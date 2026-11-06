#!/usr/bin/env python3
"""
ueba_trainer.py
───────────────
CyberSentinel UEBA — Model Training

Reads the HDF5 feature matrix produced by ueba_preprocessor.py and trains:
  Layer 1 — Isolation Forest      (global, per-event anomaly scoring)
  Layer 2 — Autoencoder(s)        (per-user behavioral anomaly)
              └─ global.pt        (fallback for users with < 500 events)
              └─ {username}.pt    (personal model for each heavy user)
  Layer 3 — FAISS index           (for RAG semantic retrieval at runtime)

Also saves:
  scaler.pkl                      (StandardScaler, must be applied at inference)
  thresholds.json                 (per-user autoencoder reconstruction thresholds)

Run once offline on your historical data. All models are saved to models/.
At runtime, ueba_engine.py loads these saved models — no retraining needed.

Usage:
  python3 ueba_trainer.py \
      --features  data/features.h5 \
      --config    ueba_config.yaml

  # Skip layers you've already trained (e.g. resume after crash)
  python3 ueba_trainer.py --features data/features.h5 --skip-if L2
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import h5py
import joblib
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import yaml

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logging.warning("faiss not installed — skipping FAISS index build. "
                    "Install with: pip install faiss-gpu or faiss-cpu")

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)-20s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/ueba_trainer.log"),
    ],
)
log = logging.getLogger("ueba.trainer")


# ── Config ────────────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── HDF5 Dataset (PyTorch) ────────────────────────────────────────────────────

try:
    import ueba_model_tiers
except ImportError:          # pragma: no cover
    ueba_model_tiers = None


def _safe_model_name(name: str) -> str:
    """One sanitiser, shared with the scorer.

    This expression used to be written out twice here and once in
    ueba_models/autoencoder.py. The trainer decides which model files to
    CREATE and the scorer decides which to LOAD; if the two copies ever
    disagreed about a name, the scorer would quietly serve the global model to
    everyone and nothing would say so.
    """
    if ueba_model_tiers is not None:
        return ueba_model_tiers.safe_model_name(name)
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in str(name or ""))


def feature_matrix_bytes(h5_path: str) -> int:
    """How much RAM the whole feature matrix needs as float32."""
    with h5py.File(h5_path, "r") as f:
        n, dim = f["features"].shape
        return n * dim * 4


def load_feature_matrix(h5_path: str, chunk_rows: int = 2_000_000):
    """The whole feature matrix, float32, read ONCE.

    WHY THIS EXISTS

    HDF5Dataset used to read the ENTIRE features dataset on every
    construction and then slice the rows it wanted — the comment said
    "reading 1.7 GB sequentially takes ~3s", which was true of the file it
    was written against. The features dataset is **gzip-compressed**, so a
    full read decompresses every chunk: on a 28,888,489-row file that is
    ~2,890 chunks and about a minute, no matter how few rows the caller
    actually wanted.

    Per-user training constructs one Dataset per user. Measured on 2026-11-06:
    1,003 eligible users, ~118 seconds each, of which almost all was this
    decompression — roughly 19.5 TB of reads and an estimated **32 hours** for
    a job whose own documentation says 30-90 minutes. A 1 MB user cost the
    same minute as a 3 MB one, which is the tell: the cost tracked the FILE,
    not the request.

    Read once here, reuse for every user, and the whole per-user phase pays
    that minute a single time.

    Chunked rather than `f["features"][:]` so peak memory is the result plus
    one chunk (~280 MB) instead of a float64 read plus a float32 copy. h5py
    converts dtype on assignment into the pre-allocated output.
    """
    with h5py.File(h5_path, "r") as f:
        d = f["features"]
        n, dim = d.shape
        out = np.empty((n, dim), dtype=np.float32)
        log.info("  Reading feature matrix once: %d rows x %d (%.2f GB float32)",
                 n, dim, out.nbytes / 1024**3)
        t0 = time.time()
        for start in range(0, n, chunk_rows):
            end = min(start + chunk_rows, n)
            out[start:end] = d[start:end]
        log.info("  Feature matrix in RAM: %.2f GB in %.1f min",
                 out.nbytes / 1024**3, (time.time() - t0) / 60)
        return out


class HDF5Dataset(Dataset):
    """
    PyTorch Dataset that serves feature vectors for training.

    `source` is a feature matrix already in RAM (see load_feature_matrix).
    Pass it whenever more than one Dataset is built from the same file —
    without it, each construction re-reads and re-decompresses the whole
    features dataset, which is what made per-user training take 32 hours.

    Without `source` the old behaviour is kept, so a single-shot caller and
    any out-of-tree user still work.
    """

    def __init__(self, h5_path: str, indices: np.ndarray | None = None,
                 scaler: StandardScaler | None = None,
                 source: "np.ndarray | None" = None):
        self.h5_path = h5_path
        self.scaler  = scaler

        if source is not None:
            self.indices = (indices if indices is not None
                            else np.arange(source.shape[0]))
            # A slice COPIES only the rows asked for; the full-matrix case
            # takes a view, so the global model does not duplicate 4 GB.
            data = source if indices is None else source[self.indices]
        else:
            with h5py.File(h5_path, "r") as f:
                total = f["features"].shape[0]
                feat_dim = f["features"].shape[1]
                self.indices = (indices if indices is not None
                                else np.arange(total))
                n = len(self.indices)
                log.info("  Preloading %d rows into RAM (%.0f MB)...",
                         n, n * feat_dim * 4 / 1024**2)
                full = f["features"][:].astype(np.float32)
                data = full if indices is None else full[self.indices]
                if indices is not None:
                    del full
                log.info("  Preload complete: %.0f MB in RAM",
                         data.nbytes / 1024**2)

        if scaler is not None:
            data = scaler.transform(data).astype(np.float32)

        self.data = torch.from_numpy(np.ascontiguousarray(data))

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        return self.data[idx]


# ── Autoencoder Architecture ──────────────────────────────────────────────────

class Autoencoder(nn.Module):
    """
    Encoder-decoder network for learning normal behavioral patterns.

    Architecture (default, feature_dim=35):
        Encoder: 35 → 24 → 12
        Decoder: 12 → 24 → 35

    High reconstruction error = event doesn't match learned normal behavior.

    The dropout layer prevents overfitting — forces the network to learn
    robust representations rather than memorizing exact values.
    """

    def __init__(self, input_dim: int = 35,
                 hidden_dims: list[int] | None = None,
                 dropout: float = 0.1):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [24, 12]

        # Build encoder layers
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

        # Build decoder layers (mirror of encoder)
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
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Per-sample MSE reconstruction error."""
        with torch.no_grad():
            recon = self.forward(x)
            # Mean across feature dimensions → one error value per sample
            return torch.mean((x - recon) ** 2, dim=1)


# ── Autoencoder Trainer ───────────────────────────────────────────────────────

class AutoencoderTrainer:
    """Trains a single autoencoder and computes its anomaly threshold."""

    def __init__(self, config: dict, device: torch.device):
        self.config = config["autoencoder"]
        self.device = device

    def train(self, dataset: HDF5Dataset,
              model_name: str = "global",
              floor: float = 0.0) -> tuple[Autoencoder, float]:
        """
        Train an autoencoder on the given dataset.
        Returns (trained_model, threshold).
        threshold = Nth percentile of HELD-OUT (validation) reconstruction
        errors, floored at `floor`. See _compute_threshold_tensor caller below
        for why held-out (not in-sample) is required to avoid serve-time floods.
        """
        arch_cfg  = self.config["architecture"]
        train_cfg = self.config["training"]

        # Train/val split — split the already-loaded tensor directly
        # No re-reading from HDF5, no index masking, instant
        n = len(dataset)
        val_size   = int(n * train_cfg["val_split"])
        # Need at least 1 train sample AND 1 val sample; otherwise either the
        # train loop or the val loop divides by zero. Force val_size>=1 when
        # there is enough data, else skip validation entirely.
        if n >= 2 and val_size == 0:
            val_size = 1
        train_size = n - val_size

        perm       = torch.randperm(n)
        train_data = dataset.data[perm[:train_size]].to(self.device)
        val_data   = dataset.data[perm[train_size:]].to(self.device)
        bs = train_cfg["batch_size"]

        # Model
        model = Autoencoder(
            input_dim=arch_cfg["input_dim"],
            hidden_dims=arch_cfg["hidden_dims"],
            dropout=arch_cfg.get("dropout", 0.1),
        ).to(self.device)

        optimizer = torch.optim.Adam(
            model.parameters(),
            lr=train_cfg["learning_rate"],
            weight_decay=train_cfg["weight_decay"],
        )
        scheduler = torch.optim.lr_scheduler.StepLR(
            optimizer,
            step_size=train_cfg["scheduler_step"],
            gamma=train_cfg["scheduler_gamma"],
        )
        criterion = nn.MSELoss()

        # Training loop — data lives on GPU, no CPU→GPU transfer per batch
        best_val_loss = float("inf")
        patience_counter = 0
        best_state = None

        log.info("[%s] Training autoencoder | samples: %d | device: %s",
                 model_name, train_size, self.device)

        for epoch in range(1, train_cfg["epochs"] + 1):
            # Shuffle training indices on GPU
            idx = torch.randperm(train_size, device=self.device)

            # Train — accumulate loss on GPU to avoid per-batch CPU sync
            model.train()
            gpu_train_loss = torch.tensor(0.0, device=self.device)
            for i in range(0, train_size, bs):
                batch = train_data[idx[i:i + bs]]
                optimizer.zero_grad()
                output = model(batch)
                loss = criterion(output, batch)
                loss.backward()
                optimizer.step()
                gpu_train_loss += loss.detach() * len(batch)
            train_loss = gpu_train_loss.item() / train_size

            # Validate
            model.eval()
            if val_size > 0:
                gpu_val_loss = torch.tensor(0.0, device=self.device)
                with torch.no_grad():
                    for i in range(0, val_size, bs):
                        batch = val_data[i:i + bs]
                        output = model(batch)
                        gpu_val_loss += criterion(output, batch) * len(batch)
                val_loss = gpu_val_loss.item() / val_size
            else:
                # Tiny dataset — no holdout possible; gate early-stopping on
                # train_loss instead.
                val_loss = train_loss

            scheduler.step()

            if epoch % 10 == 0 or epoch == 1:
                log.info("[%s] Epoch %d/%d | train_loss: %.6f | val_loss: %.6f",
                         model_name, epoch, train_cfg["epochs"],
                         train_loss, val_loss)

            # Early stopping
            if val_loss < best_val_loss - 1e-6:
                best_val_loss = val_loss
                patience_counter = 0
                best_state = {k: v.cpu().clone()
                              for k, v in model.state_dict().items()}
            else:
                patience_counter += 1
                if patience_counter >= train_cfg["early_stopping_patience"]:
                    log.info("[%s] Early stopping at epoch %d", model_name, epoch)
                    break

        # Restore best weights
        if best_state:
            model.load_state_dict(best_state)

        # Compute the anomaly threshold on the HELD-OUT validation split, NOT the
        # training data. In-sample recon error is optimistically low (the model
        # has already seen those rows), so a p95 taken on train_data collapses
        # toward ~0 for a well-fit or sparse model — and at serve time
        # deviation_score = recon/(2*threshold) then pins to 1.0, flooding every
        # event to highly_anomalous (this is exactly what sank every prior weekly
        # retrain: thresholds ~0.001–0.04 vs a serve recon median ~0.25). Held-out
        # recon reflects generalisation, i.e. what the live feed actually looks
        # like, so the threshold stays calibrated run-to-run instead of depending
        # on how tightly this particular fit memorised its own training set.
        # Fall back to train_data only when the set is too small to hold out a
        # validation split (val_size == 0).
        calib_data = val_data if val_size > 0 else train_data
        threshold = self._compute_threshold_tensor(model, calib_data)
        # Floor: a homogeneous entity (few, near-identical events) can be
        # reconstructed so well that even its held-out recon ≈ 0 → it would still
        # flood. Never let a threshold collapse below the floor the caller sets.
        threshold = max(threshold, floor)
        log.info("[%s] Threshold (p%d, %s): %.6f",
                 model_name,
                 self.config["threshold_percentile"],
                 "held-out" if val_size > 0 else "in-sample/tiny-set",
                 threshold)

        return model, threshold

    def _compute_threshold_tensor(self, model: Autoencoder,
                                  data: torch.Tensor) -> float:
        """Compute threshold directly from a GPU tensor."""
        model.eval()
        bs = 8192
        if data.device.type != "cuda" and self.device.type == "cuda":
            data = data.to(self.device)
        all_errors = []
        with torch.no_grad():
            for i in range(0, len(data), bs):
                errors = model.reconstruction_error(data[i:i + bs])
                all_errors.append(errors)
        all_errors = torch.cat(all_errors).cpu().numpy()
        percentile = self.config["threshold_percentile"]
        return float(np.percentile(all_errors, percentile))

    def _compute_threshold(self, model: Autoencoder,
                           dataset: HDF5Dataset) -> float:
        """Compute threshold from dataset tensor on GPU."""
        model.eval()
        data = dataset.data.to(self.device)
        return self._compute_threshold_tensor(model, data)


# ── Main Trainer ──────────────────────────────────────────────────────────────

class UEBATrainer:

    def __init__(self, config: dict):
        self.config = config

        # Paths
        self.models_dir       = Path(config["paths"]["models_dir"])
        self.autoencoder_dir  = Path(config["paths"]["autoencoder_dir"])
        self.if_path          = Path(config["paths"]["isolation_forest"])
        self.scaler_path      = Path(config["paths"]["scaler"])
        self.faiss_index_path = Path(config["paths"]["faiss_index"])
        self.faiss_meta_path  = Path(config["paths"]["faiss_metadata"])
        self.profile_db       = Path(config["paths"]["profile_db"])

        # Create directories
        for d in [self.models_dir, self.autoencoder_dir,
                  self.faiss_index_path.parent, Path("logs")]:
            d.mkdir(parents=True, exist_ok=True)

        # Device
        ae_cfg = config["autoencoder"]
        requested = ae_cfg.get("device", "cuda")
        if requested == "cuda" and torch.cuda.is_available():
            self.device = torch.device("cuda")
            log.info("GPU detected: %s", torch.cuda.get_device_name(0))
            # Co-tenant safety: the L40S is shared with a production vLLM/Vaani
            # process. Hard-cap THIS process's GPU memory (env UEBA_GPU_MEM_FRACTION,
            # fraction of total device memory) so a training spike can never starve
            # the co-tenant — if we exceed the cap, OUR process OOMs, not theirs.
            _frac = os.environ.get("UEBA_GPU_MEM_FRACTION")
            if _frac:
                try:
                    torch.cuda.set_per_process_memory_fraction(float(_frac), 0)
                    log.info("GPU memory capped at %.0f%% of device for co-tenant safety",
                             float(_frac) * 100)
                except Exception as e:
                    log.warning("Could not set GPU memory fraction (%s) — continuing", e)
        else:
            self.device = torch.device("cpu")
            if requested == "cuda":
                log.warning("CUDA requested but not available — using CPU")
            log.info("Using device: CPU")

        # Thresholds store (saved to disk after training)
        self.thresholds: dict[str, float] = {}

    # ── Step 1: Fit StandardScaler ────────────────────────────────────────────

    def fit_scaler(self, h5_path: str) -> StandardScaler:
        """
        Fit StandardScaler on a sample of features.
        Reads sequentially for 10-20x faster HDF5 I/O on compressed files.
        Sequential reads are fine for scaling statistics.
        """
        sample_size = min(
            self.config["isolation_forest"]["training_sample_size"],
            500_000,
        )
        log.info("Fitting StandardScaler on %d rows (sequential read)...", sample_size)

        with h5py.File(h5_path, "r") as f:
            total = f["features"].shape[0]
            actual = min(sample_size, total)
            stride = max(1, total // actual)
            X_sample = f["features"][::stride].astype(np.float32)

        log.info("  Read %d rows (stride=%d, covers all 17 days)", len(X_sample), stride)
        scaler = StandardScaler()
        scaler.fit(X_sample)
        del X_sample

        joblib.dump(scaler, str(self.scaler_path))
        log.info("Scaler saved → %s", self.scaler_path)
        return scaler

    # ── Step 2: Train Isolation Forest ────────────────────────────────────────

    def train_isolation_forest(self, h5_path: str, scaler: StandardScaler):
        """
        Train global Isolation Forest on a representative sample.
        1M samples is statistically sufficient for anomaly boundary learning.
        """
        if_cfg = self.config["isolation_forest"]
        sample_size = if_cfg["training_sample_size"]

        log.info("Loading %d samples for Isolation Forest training (stride read)...", sample_size)

        with h5py.File(h5_path, "r") as f:
            total = f["features"].shape[0]
            actual_sample = min(sample_size, total)
            stride = max(1, total // actual_sample)
            X = f["features"][::stride].astype(np.float32)

        log.info("  Read %d rows (stride=%d, covers all 17 days)", len(X), stride)

        # Scale features
        X_scaled = scaler.transform(X)
        del X   # free RAM immediately

        log.info("Training Isolation Forest | samples: %d | estimators: %d",
                 actual_sample, if_cfg["n_estimators"])
        t0 = time.time()

        model = IsolationForest(
            n_estimators=if_cfg["n_estimators"],
            contamination=if_cfg["contamination"],
            max_samples=if_cfg["max_samples"],
            random_state=if_cfg["random_state"],
            n_jobs=if_cfg["n_jobs"],
        )
        model.fit(X_scaled)

        elapsed = time.time() - t0
        log.info("Isolation Forest trained in %.1f minutes", elapsed / 60)

        joblib.dump(model, str(self.if_path))
        log.info("Isolation Forest saved → %s", self.if_path)

        # Quick sanity check — what % of training data is flagged?
        labels = model.predict(X_scaled)
        anomaly_rate = (labels == -1).sum() / len(labels) * 100
        log.info("Training anomaly rate: %.2f%% (target: %.1f%%)",
                 anomaly_rate, if_cfg["contamination"] * 100)

        del X_scaled

    # ── Step 3: Train Autoencoders ────────────────────────────────────────────

    def train_autoencoders(self, h5_path: str, scaler: StandardScaler):
        """
        Train per-user autoencoders for users with enough data,
        plus a global autoencoder as fallback.
        """
        import sqlite3

        min_events = self.config["preprocessing"]["min_events_per_user"]
        ae_trainer = AutoencoderTrainer(self.config, self.device)

        # Threshold floors (see AutoencoderTrainer.train). `threshold_floor` is an
        # absolute minimum; `peruser_floor_frac` keeps every per-user threshold
        # at >= that fraction of the global threshold so a memorised sparse-entity
        # model can never collapse to ~0 and flood. Defaults are conservative and
        # can be tuned in ueba_config.yaml → autoencoder.*.
        ae_cfg     = self.config["autoencoder"]
        abs_floor  = float(ae_cfg.get("threshold_floor", 0.05))
        floor_frac = float(ae_cfg.get("peruser_floor_frac", 0.5))

        # ── read the features ONCE and share them ─────────────────────────────
        #
        # Every HDF5Dataset used to re-read and re-decompress the whole
        # features dataset. With 1,003 eligible users that was ~19.5 TB of
        # reads and an estimated 32 hours (measured 2026-11-06) for a job
        # documented as 30-90 minutes. One read, reused by the global model,
        # every per-user model and every cohort model.
        #
        # Guarded rather than assumed: the class docstring used to say "with
        # 178 GB RAM available this is always safe", and this box has 125 GB
        # with 11 GB free and swap exhausted. If the matrix will not fit in a
        # safe fraction of what is actually free, fall back to the old
        # per-call read — slow, but it completes instead of being OOM-killed.
        shared = None
        try:
            need = feature_matrix_bytes(h5_path)
            avail = None
            try:
                with open("/proc/meminfo") as mf:
                    for line in mf:
                        if line.startswith("MemAvailable:"):
                            avail = int(line.split()[1]) * 1024
                            break
            except Exception:
                avail = None
            budget = int(avail * 0.6) if avail else None
            if budget is None:
                log.warning("  Cannot read MemAvailable — loading the feature "
                            "matrix without a memory guard")
                shared = load_feature_matrix(h5_path)
            elif need <= budget:
                log.info("  Feature matrix %.2f GB fits the budget %.2f GB "
                         "(60%% of %.2f GB available)",
                         need / 1024**3, budget / 1024**3, avail / 1024**3)
                shared = load_feature_matrix(h5_path)
            else:
                log.warning("  Feature matrix needs %.2f GB but only %.2f GB "
                            "of the %.2f GB available is budgeted — falling "
                            "back to per-call reads. Per-user training will be "
                            "SLOW; free memory or shrink the corpus window.",
                            need / 1024**3, budget / 1024**3, avail / 1024**3)
        except Exception as e:
            log.warning("  Could not pre-load the feature matrix (%s) — "
                        "falling back to per-call reads", e)
            shared = None

        # ── Global autoencoder (all data) ─────────────────────────────────────
        log.info("Training global autoencoder...")
        global_ds = HDF5Dataset(h5_path, scaler=scaler, source=shared)
        global_model, global_threshold = ae_trainer.train(global_ds, "global",
                                                          floor=abs_floor)

        global_path = self.autoencoder_dir / "global.pt"
        torch.save(global_model.state_dict(), str(global_path))
        self.thresholds["global"] = global_threshold
        log.info("Global autoencoder saved → %s", global_path)

        # Per-user threshold floor, derived from the (calibrated) global threshold.
        peruser_floor = max(abs_floor, floor_frac * global_threshold)
        log.info("Per-user threshold floor: %.6f (abs %.4f | %.2f x global %.4f)",
                 peruser_floor, abs_floor, floor_frac, global_threshold)

        # ── Per-user autoencoders ─────────────────────────────────────────────
        # Get list of users with enough events from profile store
        db_path = str(self.profile_db)
        if not Path(db_path).exists():
            log.warning("Profile store not found at %s — skipping per-user models",
                        db_path)
            self._save_thresholds()
            return

        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT username, total_events FROM users WHERE total_events >= ?",
            (min_events,)
        ).fetchall()
        conn.close()

        eligible_users = [(r[0], r[1]) for r in rows]
        log.info("Users eligible for personal autoencoder: %d (>= %d events)",
                 len(eligible_users), min_events)

        if not eligible_users:
            log.info("No users meet the threshold — only global model will be used")
            self._save_thresholds()
            return

        # Load user → row mapping from HDF5 metadata
        log.info("Building user → row index map from HDF5 metadata...")
        user_indices: dict[str, list[int]] = {}

        with h5py.File(h5_path, "r") as f:
            meta_ds = f["metadata"]
            chunk = 100_000
            total = len(meta_ds)
            for start in range(0, total, chunk):
                end = min(start + chunk, total)
                batch_meta = meta_ds[start:end]
                for local_i, m_str in enumerate(batch_meta):
                    try:
                        m = json.loads(m_str)
                        user = m.get("user", "unknown")
                        if user not in user_indices:
                            user_indices[user] = []
                        user_indices[user].append(start + local_i)
                    except Exception:
                        pass

                if start % 1_000_000 == 0:
                    log.info("  Indexed %d / %d rows...", start, total)

        log.info("Unique users in dataset: %d", len(user_indices))

        # Train per-user models
        eligible_set = {u for u, _ in eligible_users}
        trained = 0
        skipped_sparse = 0
        for user, event_count in eligible_users:
            if user not in user_indices:
                log.debug("User %s in profile store but not in features — skipping",
                          user)
                continue

            # Resume support — skip if model already saved
            safe_name = _safe_model_name(user)
            model_path = self.autoencoder_dir / f"{safe_name}.pt"
            if model_path.exists():
                log.info("Skipping user '%s' — model already exists at %s", user, model_path)
                trained += 1
                continue

            indices = np.array(user_indices[user])
            # Profile DB has cumulative total_events, but the H5 window may
            # contain far fewer rows for this user. Re-check against actual
            # rows so we don't try to train on a handful of samples.
            if len(indices) < min_events:
                log.info("Skipping user '%s' — only %d rows in current H5 (< %d)",
                         user, len(indices), min_events)
                skipped_sparse += 1
                continue

            log.info("Training autoencoder for user '%s' | events: %d",
                     user, len(indices))

            user_ds = HDF5Dataset(h5_path, indices=indices, scaler=scaler,
                                  source=shared)
            user_model, user_threshold = ae_trainer.train(user_ds, user,
                                                          floor=peruser_floor)

            # Save model — sanitize username for filename
            safe_name = _safe_model_name(user)
            model_path = self.autoencoder_dir / f"{safe_name}.pt"
            torch.save(user_model.state_dict(), str(model_path))
            self.thresholds[user] = user_threshold
            trained += 1
            log.info("Saved user model → %s (threshold: %.6f)",
                     model_path, user_threshold)

            # Free GPU memory between users
            del user_model
            if self.device.type == "cuda":
                torch.cuda.empty_cache()

        log.info("Per-user autoencoders trained: %d (skipped %d users with sparse data)",
                 trained, skipped_sparse)

        # ── Cohort autoencoders (RFP SN 18) ───────────────────────────────────
        self._train_cohort_models(h5_path, scaler, ae_trainer, user_indices,
                                  min_events, peruser_floor, shared=shared)
        # Release the matrix before the FAISS build, which has its own
        # allocations and no need for this one.
        del shared
        self._save_thresholds()

    def _train_cohort_models(self, h5_path, scaler, ae_trainer, user_indices,
                             min_events, peruser_floor, shared=None):
        """One model per behavioural cohort, for entities too quiet to learn alone.

        THE GAP THIS CLOSES. Everything above trains a model only for an
        entity that clears min_events_per_user — 2000 here. Everyone else was
        counted into `skipped_sparse` and dropped, so they were judged by
        global.pt, a model built from the whole estate. On the 2026-11-03 run
        that left 42 named entities with a model of their own and every other
        account sharing one. SN 18 is written against exactly that.

        The cohorts come from ueba_peers — the SAME assignment that drives
        peer-group deviation (SN 42), not a second grouping that could
        disagree with the first. Members are grouped by how they actually
        behave (Jensen-Shannon divergence over access distributions), which is
        why a cohort model is more specific than the global one.

        Two guards, both of which exist to avoid building something worse than
        what it replaces:

          * a cohort needs >= cohort_min_members, because a "cohort" of one is
            a per-entity model with none of the generalisation that justifies
            the tier;
          * it needs >= cohort_min_rows of POOLED data, because a model fitted
            on a handful of rows memorises them — the same failure mode that
            `peruser_floor_frac` exists to contain for sparse per-entity
            models. Below that the members fall through to global, which is
            honest rather than falsely specific.
        """
        tier_cfg = self.config.get("model_tiers") or {}
        if not bool(tier_cfg.get("enabled", True)):
            log.info("Cohort tier disabled in config — sparse entities will use "
                     "the global model")
            return
        if ueba_model_tiers is None:
            log.warning("ueba_model_tiers unavailable — no cohort models")
            return

        min_members = int(tier_cfg.get("cohort_min_members",
                                       ueba_model_tiers.DEFAULT_COHORT_MIN_MEMBERS))
        min_rows = int(tier_cfg.get("cohort_min_rows",
                                    ueba_model_tiers.DEFAULT_COHORT_MIN_ROWS))

        groups_path = ((self.config.get("paths") or {}).get("peer_groups_file")
                       or tier_cfg.get("peer_groups_file") or "")
        assignment = {}
        if groups_path and Path(groups_path).exists():
            try:
                import ueba_peers
                assignment = ueba_peers.load(groups_path) or {}
            except Exception as e:
                log.warning("peer groups unreadable (%s) — no cohort models", e)
                assignment = {}
        if not (assignment.get("members") or {}):
            log.warning("No peer-group assignment at %r — every sparse entity "
                        "falls back to the global model. Run "
                        "build_peer_groups.py to enable the cohort tier.",
                        groups_path or "<unset>")
            return

        # Pool the row indices of every entity that did NOT earn its own model.
        # Measured against rows actually present in this H5, not the profile
        # store's cumulative total — the window is usually much smaller, and
        # that mismatch is already guarded above for per-entity models.
        pooled: dict = {}
        members: dict = {}
        for user, indices in user_indices.items():
            if len(indices) >= min_events:
                continue        # has, or will have, its own model
            plan = ueba_model_tiers.plan_training(
                user, len(indices), assignment, min_events=min_events,
                cohort_min_rows=min_rows)
            if plan["tier"] != "cohort":
                continue
            key = plan["model"]
            pooled.setdefault(key, []).extend(indices)
            members.setdefault(key, []).append(user)

        if not pooled:
            log.info("No sparse entity was placed in a cohort — nothing to train")
            return

        log.info("Cohort tier: %d candidate cohort(s) from %d sparse entities",
                 len(pooled), sum(len(v) for v in members.values()))

        built = 0
        for key in sorted(pooled):
            idx = pooled[key]
            who = members[key]
            if len(who) < min_members:
                log.info("Cohort %s: only %d member(s) (< %d) — members fall "
                         "back to the global model", key, len(who), min_members)
                continue
            if len(idx) < min_rows:
                log.info("Cohort %s: %d member(s) but only %d pooled rows "
                         "(< %d) — members fall back to the global model",
                         key, len(who), len(idx), min_rows)
                continue

            safe_name = _safe_model_name(key)
            model_path = self.autoencoder_dir / f"{safe_name}.pt"
            if model_path.exists():
                log.info("Skipping cohort %s — model already exists at %s",
                         key, model_path)
                built += 1
                continue

            log.info("Training cohort autoencoder %s | members: %d | rows: %d",
                     key, len(who), len(idx))
            ds = HDF5Dataset(h5_path, indices=np.array(sorted(set(idx))),
                             scaler=scaler, source=shared)
            model, threshold = ae_trainer.train(ds, key, floor=peruser_floor)
            torch.save(model.state_dict(), str(model_path))
            # Keyed by the MODEL name, which is what the scorer now looks up —
            # a cohort's threshold belongs to the cohort, not to any member.
            self.thresholds[key] = threshold
            built += 1
            log.info("Saved cohort model → %s (threshold: %.6f, members: %s%s)",
                     model_path, threshold, ", ".join(who[:5]),
                     "..." if len(who) > 5 else "")
            del model
            if self.device.type == "cuda":
                torch.cuda.empty_cache()

        log.info("Cohort autoencoders trained: %d of %d candidate cohort(s)",
                 built, len(pooled))

    def _save_thresholds(self):
        """Save all autoencoder thresholds to JSON."""
        path = self.models_dir / "thresholds.json"
        with open(path, "w") as f:
            json.dump(self.thresholds, f, indent=2)
        log.info("Thresholds saved → %s", path)

    # ── Step 4: Build FAISS Index ─────────────────────────────────────────────

    def build_faiss_index(self, h5_path: str, scaler: StandardScaler):
        """
        Build FAISS vector index from all training feature vectors.
        Used at runtime for RAG — retrieve similar past anomalies.
        At inference time: embed new anomaly → search index → top-K similar.
        """
        if not FAISS_AVAILABLE:
            log.warning("FAISS not available — skipping index build")
            return

        feature_dim = self.config["preprocessing"]["feature_dim"]
        max_size    = self.config["rag"]["max_index_size"]
        # Build to a fraction of the runtime ceiling, not all the way to it, so
        # the engine's add_to_index() has headroom to append fresh anomalies
        # between retrains. Building to exactly max_size makes the index "born
        # full": add_to_index then refuses every new vector and logs "index
        # full" forever, so the RAG layer never learns anything post-training.
        build_frac   = float(self.config["rag"].get("index_build_fraction", 0.8))
        build_target = max(1, int(max_size * build_frac))

        log.info("Building FAISS index | max_size: %d | build_target: %d (%.0f%%)",
                 max_size, build_target, build_frac * 100)

        with h5py.File(h5_path, "r") as f:
            total = f["features"].shape[0]
            actual = min(build_target, total)
            stride = max(1, total // actual)
            # f["features"][::stride] yields ceil(total/stride) rows, which can
            # exceed `actual`; truncate to `actual` so the vector count exactly
            # matches `metas`. Without the [:actual] slice the index ends up with
            # MORE vectors than metadata entries, and every surplus vector is
            # silently unretrievable (retrieve() drops idx >= len(metadata)).
            stride_indices = list(range(0, total, stride))[:actual]
            X = f["features"][::stride][:actual].astype(np.float32)
            metas = [json.loads(f["metadata"][i]) for i in stride_indices]

        log.info("  Read %d rows for FAISS (stride=%d)", len(X), stride)

        X_scaled = scaler.transform(X).astype(np.float32)
        del X

        # L2-normalize for cosine similarity (inner product search)
        faiss.normalize_L2(X_scaled)

        # IndexFlatIP = exact inner product search (cosine after L2 norm)
        index = faiss.IndexFlatIP(feature_dim)
        index.add(X_scaled)

        faiss.write_index(index, str(self.faiss_index_path))
        log.info("FAISS index saved → %s | vectors: %d",
                 self.faiss_index_path, index.ntotal)

        # Save metadata (needed to return human-readable similar events)
        with open(self.faiss_meta_path, "w") as f:
            for m in metas:
                f.write(json.dumps(m) + "\n")
        log.info("FAISS metadata saved → %s", self.faiss_meta_path)

        del X_scaled

    # ── Main Training Pipeline ────────────────────────────────────────────────

    def run(self, h5_path: str, skip_layers: list[str] | None = None):
        """Run the full training pipeline."""
        skip = set(skip_layers or [])
        start = time.time()

        log.info("=" * 60)
        log.info("UEBA TRAINER STARTING")
        log.info("  Features : %s", h5_path)
        log.info("  Device   : %s", self.device)
        log.info("=" * 60)

        # Verify HDF5 exists
        if not Path(h5_path).exists():
            log.error("Features file not found: %s", h5_path)
            log.error("Run ueba_preprocessor.py first.")
            sys.exit(1)

        with h5py.File(h5_path, "r") as f:
            total_rows = f["features"].shape[0]
            feature_dim = f["features"].shape[1]
        log.info("Feature matrix: %d rows × %d features", total_rows, feature_dim)

        # Step 1: Scaler (always needed)
        if "scaler" not in skip:
            scaler = self.fit_scaler(h5_path)
        else:
            log.info("Loading existing scaler...")
            scaler = joblib.load(str(self.scaler_path))

        # Step 2: Isolation Forest
        if "L1" not in skip:
            log.info("\n── Layer 1: Isolation Forest ─────────────────────────")
            self.train_isolation_forest(h5_path, scaler)
        else:
            log.info("Skipping L1 (Isolation Forest)")

        # Step 3: Autoencoders
        if "L2" not in skip:
            log.info("\n── Layer 2: Autoencoders ─────────────────────────────")
            self.train_autoencoders(h5_path, scaler)
        else:
            log.info("Skipping L2 (Autoencoders)")

        # Step 4: FAISS index
        if "L3" not in skip:
            log.info("\n── Layer 3: FAISS Index (RAG) ────────────────────────")
            self.build_faiss_index(h5_path, scaler)
        else:
            log.info("Skipping L3 (FAISS Index)")

        elapsed = time.time() - start
        log.info("=" * 60)
        log.info("TRAINING COMPLETE")
        log.info("  Total time : %.1f minutes", elapsed / 60)
        log.info("  Models dir : %s", self.models_dir)
        log.info("")
        log.info("  Files saved:")
        for p in sorted(Path(self.models_dir).rglob("*")):
            if p.is_file():
                size_mb = p.stat().st_size / (1024 * 1024)
                log.info("    %-50s  %.1f MB", str(p), size_mb)
        log.info("")
        log.info("  Next step:")
        log.info("    python3 ueba_engine.py --config ueba_config.yaml")
        log.info("=" * 60)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="UEBA Model Trainer — trains Isolation Forest, "
                    "Autoencoders, and FAISS index",
    )
    parser.add_argument("--features", default=None,
                        help="HDF5 feature matrix (default from config)")
    parser.add_argument("--config", default="ueba_config.yaml")
    parser.add_argument("--skip-if", nargs="+",
                        choices=["scaler", "L1", "L2", "L3"],
                        help="Skip specific layers (use to resume after crash)")
    args = parser.parse_args()

    os.makedirs("logs", exist_ok=True)
    config = load_config(args.config)

    h5_path = args.features or config["paths"]["features_h5"]

    trainer = UEBATrainer(config)
    trainer.run(h5_path, skip_layers=args.skip_if)


if __name__ == "__main__":
    main()
