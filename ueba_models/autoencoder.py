"""
ueba_models/autoencoder.py
───────────────────────────
Layer 2 — Autoencoder inference wrapper.

Loads per-user models lazily (on first encounter).
Falls back to global model for unknown/rare users.
Uses LRU cache to keep only the most recently used models in memory.
"""

import json
import logging
from collections import OrderedDict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

log = logging.getLogger("ueba.autoencoder")


# ── Train/serve skew guard ────────────────────────────────────────────────────

def _zero_variance_cols(scaler, tag: str) -> np.ndarray:
    """Indices of features that were CONSTANT in the training set.

    StandardScaler stores scale_=1.0 (var_=0) for a zero-variance column, so it
    does not normalise it. If the live feed later starts populating that field
    (e.g. an upstream enricher adds host_5m / rule.level AFTER the model was
    trained), the raw value passes through unscaled and detonates the
    autoencoder reconstruction error — pinning every event to highly_anomalous.
    Such columns carry no learned signal anyway (the model trained on a
    constant), so callers zero them post-scale to keep the model on the
    distribution it was actually trained on. Remove once the model is retrained
    on representative data (the scaler will then have real variance here).
    """
    var = getattr(scaler, "var_", None)
    if var is None:
        return np.array([], dtype=int)
    cols = np.where(var == 0)[0]
    if len(cols):
        log.warning("%s skew-guard: masking %d zero-variance feature(s) the "
                    "model never learned (indices %s)", tag, len(cols), list(cols))
    return cols


# ── Autoencoder Architecture (must match ueba_trainer.py) ─────────────────────

try:
    import ueba_model_tiers
except ImportError:          # pragma: no cover - keeps the scorer importable
    ueba_model_tiers = None  #              from a bare models/ checkout


class Autoencoder(nn.Module):
    def __init__(self, input_dim: int = 35,
                 hidden_dims: list[int] | None = None,
                 dropout: float = 0.1):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [24, 12]

        encoder_layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
            ])
            prev_dim = h_dim
        self.encoder = nn.Sequential(*encoder_layers)

        decoder_layers = []
        for h_dim in reversed(hidden_dims[:-1]):
            decoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.ReLU(),
                nn.Dropout(dropout),
            ])
            prev_dim = h_dim
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    def reconstruction_error(self, x: torch.Tensor) -> float:
        with torch.no_grad():
            recon = self.forward(x)
            return float(torch.mean((x - recon) ** 2).item())


# ── Autoencoder Scorer ────────────────────────────────────────────────────────

class AutoencoderScorer:
    """
    Manages per-user and global autoencoders for real-time inference.

    Design:
    - Models are loaded lazily (only when that user is seen)
    - LRU cache keeps max_loaded_models in RAM
    - Falls back to global model when user model doesn't exist
    - Uses GPU (CUDA) for inference when available
    """

    def __init__(self, autoencoder_dir: str, scaler,
                 thresholds_path: str, config: dict):
        self.ae_dir     = Path(autoencoder_dir)
        self.scaler     = scaler
        self._dead_cols = _zero_variance_cols(scaler, "AE")
        self.ae_config  = config["autoencoder"]
        self.arch_cfg   = self.ae_config["architecture"]
        self.max_cached = config["streaming"]["max_loaded_user_models"]

        # `inference_device` overrides `device` for streaming inference only,
        # so the trainer keeps using GPU while the engine can run on CPU.
        # Tiny per-user AEs (~3K params) are memory-bound on GPU and pinning
        # them there starves co-tenant GPU workloads (ollama, etc.).
        dev_name = self.ae_config.get("inference_device") \
                   or self.ae_config.get("device", "cuda")
        if dev_name == "cuda" and torch.cuda.is_available():
            self.device = torch.device("cuda")
            log.info("Autoencoder inference on GPU: %s", torch.cuda.get_device_name(0))
        else:
            self.device = torch.device("cpu")
            log.info("Autoencoder inference on CPU")

        # Load anomaly thresholds for each user model
        if not Path(thresholds_path).exists():
            raise FileNotFoundError(
                f"Thresholds file not found: {thresholds_path}\n"
                f"Run ueba_trainer.py first."
            )
        with open(thresholds_path) as f:
            self.thresholds: dict[str, float] = json.load(f)

        # LRU cache: {model name: model}. Keyed by MODEL name, not by entity:
        # a cohort model is shared by every member, so keying on the entity
        # would hold one copy of the same weights per member and evict the
        # per-entity models that actually differ.
        self._cache: OrderedDict[str, Autoencoder] = OrderedDict()

        # ── the cohort tier (RFP SN 18) ──
        # Quiet entities used to fall straight to global.pt. They are now
        # judged against the people they behave like, which is strictly more
        # specific. Absent or unreadable, everything behaves exactly as before.
        tier_cfg = config.get("model_tiers") or {}
        self.cohort_tier_enabled = bool(tier_cfg.get("enabled", True))
        self._assignment: dict = {}
        if self.cohort_tier_enabled and ueba_model_tiers is not None:
            groups_path = ((config.get("paths") or {}).get("peer_groups_file")
                           or tier_cfg.get("peer_groups_file") or "")
            if groups_path:
                try:
                    import ueba_peers
                    self._assignment = ueba_peers.load(groups_path) or {}
                except Exception as e:
                    # A missing or broken assignment costs the cohort tier, not
                    # the engine. Said out loud because silently scoring the
                    # whole estate against one model is the bug SN 18 names.
                    log.warning("cohort tier unavailable (%s): quiet entities "
                                "will fall back to the global model", e)
                    self._assignment = {}
            members = len((self._assignment or {}).get("members") or {})
            if members:
                log.info("Cohort tier active: %d entities placed in %d cohorts",
                         members,
                         len((self._assignment or {}).get("cohorts") or {}))
            else:
                log.info("Cohort tier enabled but no entities are placed; "
                         "quiet entities fall back to the global model")

        # Load global model at startup (always needed as fallback)
        self.global_model = self._load_model("global")
        if self.global_model is None:
            raise FileNotFoundError(
                f"Global autoencoder not found in {self.ae_dir}\n"
                f"Run ueba_trainer.py first."
            )
        log.info("Global autoencoder loaded from %s", self.ae_dir / "global.pt")

    def _load_model(self, username: str) -> Autoencoder | None:
        """Load autoencoder weights from disk for a specific user."""
        # The sanitiser lives in ueba_model_tiers now. It used to be written
        # out here and twice more in ueba_trainer.py; if the trainer's copy and
        # this one ever disagreed the scorer would silently serve the global
        # model to everyone and nothing would report it.
        if ueba_model_tiers is not None:
            safe_name = ueba_model_tiers.safe_model_name(username)
        else:
            safe_name = "".join(c if c.isalnum() or c in "-_" else "_"
                                for c in username)
        model_path = self.ae_dir / f"{safe_name}.pt"

        if not model_path.exists():
            return None

        model = Autoencoder(
            input_dim=self.arch_cfg["input_dim"],
            hidden_dims=self.arch_cfg["hidden_dims"],
            dropout=0.0,    # disable dropout at inference
        ).to(self.device)
        model.load_state_dict(
            torch.load(str(model_path), map_location=self.device)
        )
        model.eval()
        return model

    def _remember(self, name: str, model: "Autoencoder") -> None:
        """Put a loaded model in the LRU cache."""
        if len(self._cache) >= self.max_cached:
            evicted = next(iter(self._cache))
            del self._cache[evicted]
            log.debug("LRU evicted model: %s", evicted)
        self._cache[name] = model

    def _try(self, name: str) -> "Autoencoder | None":
        """The model for this NAME, from cache or disk, or None."""
        if not name:
            return None
        if name in self._cache:
            self._cache.move_to_end(name)
            return self._cache[name]
        model = self._load_model(name)
        if model is not None:
            self._remember(name, model)
            log.debug("Loaded model: %s", name)
        return model

    def _get_model(self, username: str) -> tuple[Autoencoder, str]:
        """
        Get the best available model for a user.
        Returns (model, model_name_used).
        Manages LRU cache automatically.

        THREE tiers now (RFP SN 18), narrowest first:

            own model  ->  cohort model  ->  global.pt

        The middle one is the point. `min_events_per_user` is 2000 here, so on
        the 2026-11-03 training run only 42 named entities cleared it and
        everyone else was judged by one model built from the whole estate. A
        quiet account is not an account with nothing to learn, it is one with
        too little history to learn from alone — so it is measured against the
        entities it behaves like instead.

        Each step is a real file on disk. A cohort that was planned but never
        built (too few pooled rows to be worth it) falls through to global
        rather than failing, because a model that is not there cannot judge.
        """
        model = self._try(username)
        if model is not None:
            return model, username

        if self.cohort_tier_enabled and ueba_model_tiers is not None \
                and self._assignment:
            key = ueba_model_tiers.cohort_model_key(
                ueba_model_tiers.cohort_for(self._assignment, username))
            if key:
                model = self._try(key)
                if model is not None:
                    return model, key

        # Fall back to global model
        return self.global_model, "global"

    def score(self, feature_vec: np.ndarray, username: str) -> dict:
        """
        Compute behavioral anomaly score for one feature vector.

        Args:
            feature_vec: numpy array shape (35,)
            username:    the user associated with this log event

        Returns dict with:
            reconstruction_error  — raw MSE
            deviation_score       — normalized 0-1 (1 = most anomalous)
            threshold             — threshold used for this user
            is_anomalous          — bool
            model_used            — username, 'cohort:<id>' or 'global'
            model_tier            — 'entity', 'cohort' or 'global'
        """
        # Scale feature vector
        vec_scaled = self.scaler.transform(
            feature_vec.reshape(1, -1)
        ).astype(np.float32)
        # Neutralise features the model never learned (see _zero_variance_cols).
        if len(self._dead_cols):
            vec_scaled[:, self._dead_cols] = 0.0
        tensor = torch.from_numpy(vec_scaled).to(self.device)

        # Get best model for this user
        model, model_used = self._get_model(username)

        # Compute reconstruction error
        recon_error = model.reconstruction_error(tensor)

        # Threshold of the MODEL THAT PRODUCED THE ERROR, not of the entity
        # that happened to be scored. Those are the same thing whenever an
        # entity has its own model, and different in the two cases that
        # matter: a cohort model needs its cohort's threshold, and an entity
        # whose model no longer exists must not be judged against a threshold
        # left behind by a previous training run. Today thresholds.json holds
        # 453 keys for 453 model files so nothing is stale, but the staged run
        # of 2026-11-03 produced 261 models — promoting it would have left 192
        # thresholds with no model, each of them silently applied to the
        # global model's reconstruction error.
        threshold = self.thresholds.get(
            model_used,
            self.thresholds.get("global", 0.1)
        )

        # Normalize deviation score to 0-1
        # At threshold: score = 0.5
        # At 2x threshold: score ≈ 0.75 etc.
        # This gives smooth gradient rather than hard 0/1
        deviation_score = float(
            np.clip(recon_error / (2.0 * threshold + 1e-8), 0.0, 1.0)
        )
        is_anomalous = recon_error > threshold

        return {
            "reconstruction_error": float(recon_error),
            "deviation_score":      deviation_score,
            "threshold":            float(threshold),
            "is_anomalous":         is_anomalous,
            "model_used":           model_used,
            # Named explicitly rather than left to be inferred from the shape
            # of `model_used`. SN 18 asks for the model that judged each alert
            # to be recorded so the coverage reporting stays truthful, and
            # "entity / cohort / global" is the answer to that question in the
            # form a report wants it.
            "model_tier":           (ueba_model_tiers.tier_of(model_used)
                                     if ueba_model_tiers is not None
                                     else ("global" if model_used == "global"
                                           else "entity")),
        }

    @property
    def cache_size(self) -> int:
        return len(self._cache)
