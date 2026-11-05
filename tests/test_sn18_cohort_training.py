#!/usr/bin/env python3
"""RFP SN 18 — the TRAINER half: cohort models actually get built.

tests/test_sn18_tiers.py proves the scorer picks a cohort model when one
exists. It cannot prove one ever gets created, because it writes the .pt files
itself. This runs the real UEBATrainer._train_cohort_models against a real
(small) features.h5 and checks what lands on disk.

Worth testing separately because the two halves fail independently and the
failure is silent either way: if the trainer never writes cohort_*.pt the
scorer falls through to global for everybody and nothing errors.

Isolated: synthetic HDF5, temp model directory, temp config. Nothing reads
production.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

import h5py  # noqa: E402
import numpy as np  # noqa: E402
import yaml  # noqa: E402

import ueba_model_tiers as T  # noqa: E402
import ueba_peers as P  # noqa: E402
import ueba_trainer as TR  # noqa: E402

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


def build_h5(path: Path, dim: int, per_entity: dict, seed=0):
    """A features.h5 with `per_entity` rows attributed to each entity."""
    rng = np.random.default_rng(seed)
    feats = []
    meta = []
    for entity, n in per_entity.items():
        # Each entity gets its own centre so the data is not pure noise.
        centre = rng.normal(0, 1, dim)
        for _ in range(n):
            feats.append(centre + rng.normal(0, 0.1, dim))
            meta.append(json.dumps({"user": entity}))
    arr = np.asarray(feats, dtype=np.float32)
    with h5py.File(path, "w") as f:
        f.create_dataset("features", data=arr)
        f.create_dataset("metadata", data=np.array(meta, dtype=object),
                         dtype=h5py.string_dtype())
    return arr


class _Scaler:
    def __init__(self, dim):
        self.n_features_in_ = dim
        self.scale_ = np.ones(dim)
        self.mean_ = np.zeros(dim)
        self.var_ = np.ones(dim)

    def transform(self, X):
        return np.asarray(X, dtype=np.float64)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="sn18train-"))
    cfg = yaml.safe_load((ROOT / "ueba_config.yaml").read_text())
    dim = cfg["autoencoder"]["architecture"]["input_dim"]

    # Deliberately small so training finishes quickly, and the epoch count is
    # cut for the same reason — this test is about WHICH models are written,
    # not about convergence.
    cfg["autoencoder"]["training"] = dict(cfg["autoencoder"].get("training") or {})
    cfg["autoencoder"]["training"]["epochs"] = 2
    cfg["autoencoder"]["training"]["batch_size"] = 32
    cfg["autoencoder"]["device"] = "cpu"

    # MIN_EVENTS of 400 with the row counts below means: busy.one earns its
    # own model; the four quiet ones do not and must be pooled.
    MIN_EVENTS = 400
    per_entity = {
        "busy.one":  450,
        "quiet.a":    60,
        "quiet.b":    70,
        "quiet.c":    80,
        "lonely.z":   50,
    }
    h5_path = work / "features.h5"
    build_h5(h5_path, dim, per_entity)

    # Cohort c1 holds three quiet entities; lonely.z sits alone in c9, which
    # must therefore NOT get a model (below cohort_min_members).
    assignment = {
        "members": {
            "quiet.a":  {"cohort": "c1", "source": "behaviour"},
            "quiet.b":  {"cohort": "c1", "source": "behaviour"},
            "quiet.c":  {"cohort": "c1", "source": "behaviour"},
            "lonely.z": {"cohort": "c9", "source": "behaviour"},
        },
        "cohorts": {"c1": {"size": 3}, "c9": {"size": 1}},
    }
    groups = work / "peer_groups.json"
    P.save(groups, assignment)

    models = work / "models"
    ae_dir = models / "autoencoders"
    cfg["paths"] = dict(cfg["paths"])
    cfg["paths"].update({
        "models_dir": str(models),
        "autoencoder_dir": str(ae_dir),
        "isolation_forest": str(models / "if.pkl"),
        "scaler": str(models / "scaler.pkl"),
        "faiss_index": str(work / "vdb" / "faiss.index"),
        "faiss_metadata": str(work / "vdb" / "meta.jsonl"),
        "profile_db": str(work / "profiles.db"),
        "peer_groups_file": str(groups),
    })
    cfg["model_tiers"] = {"enabled": True, "cohort_min_members": 2,
                          "cohort_min_rows": 150}

    trainer = TR.UEBATrainer(cfg)
    ae_trainer = TR.AutoencoderTrainer(cfg, trainer.device)
    scaler = _Scaler(dim)

    # The row index map the real flow builds from HDF5 metadata.
    user_indices: dict = {}
    with h5py.File(h5_path, "r") as f:
        for i, m in enumerate(f["metadata"]):
            u = json.loads(m)["user"]
            user_indices.setdefault(u, []).append(i)
    ok("the row map covers every entity", len(user_indices) == len(per_entity))

    trainer.thresholds = {"global": 0.5}
    trainer._train_cohort_models(str(h5_path), scaler, ae_trainer,
                                 user_indices, MIN_EVENTS, peruser_floor=0.05)

    written = sorted(p.name for p in ae_dir.glob("*.pt")) if ae_dir.exists() else []

    # ── c1 must exist ──
    c1_key = T.cohort_model_key("c1")
    c1_file = T.safe_model_name(c1_key) + ".pt"
    ok("a cohort model was written for c1", c1_file in written,
       "wrote %s" % written)
    ok("and it is named cohort_c1.pt", c1_file == "cohort_c1.pt", c1_file)
    ok("a threshold was recorded under the MODEL key",
       c1_key in trainer.thresholds, sorted(trainer.thresholds))
    if c1_key in trainer.thresholds:
        ok("and it is a real positive number",
           isinstance(trainer.thresholds[c1_key], float)
           and trainer.thresholds[c1_key] > 0,
           repr(trainer.thresholds[c1_key]))
        ok("and respects the floor it was given",
           trainer.thresholds[c1_key] >= 0.05,
           repr(trainer.thresholds[c1_key]))

    # ── c9 must NOT: one member is below cohort_min_members ──
    c9_file = T.safe_model_name(T.cohort_model_key("c9")) + ".pt"
    ok("a single-member cohort gets NO model", c9_file not in written,
       "wrote %s" % written)
    ok("and no threshold either",
       T.cohort_model_key("c9") not in trainer.thresholds)

    # ── the busy entity is not swept into a cohort ──
    # It clears MIN_EVENTS, so the per-entity loop owns it. A cohort that also
    # trained on its rows would both waste the work and pollute the cohort's
    # profile with an entity that has its own model.
    ok("the busy entity is left to the per-entity loop",
       "busy_one.pt" not in written, "wrote %s" % written)
    ok("only the one cohort model was written", len(written) == 1,
       "wrote %s" % written)

    # ── the tier switched off writes nothing ──
    cfg_off = dict(cfg, model_tiers={"enabled": False})
    t2 = TR.UEBATrainer(cfg_off)
    ae2 = work / "models2" / "autoencoders"
    cfg_off["paths"] = dict(cfg["paths"])
    cfg_off["paths"]["autoencoder_dir"] = str(ae2)
    t2 = TR.UEBATrainer(cfg_off)
    t2.thresholds = {"global": 0.5}
    t2._train_cohort_models(str(h5_path), scaler,
                            TR.AutoencoderTrainer(cfg_off, t2.device),
                            user_indices, MIN_EVENTS, peruser_floor=0.05)
    ok("with the tier disabled nothing is written",
       not list(ae2.glob("cohort_*.pt")) if ae2.exists() else True)

    # ── no assignment file: inert, not fatal ──
    cfg_none = dict(cfg)
    cfg_none["paths"] = dict(cfg["paths"])
    ae3 = work / "models3" / "autoencoders"
    cfg_none["paths"]["autoencoder_dir"] = str(ae3)
    cfg_none["paths"]["peer_groups_file"] = str(work / "absent.json")
    t3 = TR.UEBATrainer(cfg_none)
    t3.thresholds = {"global": 0.5}
    t3._train_cohort_models(str(h5_path), scaler,
                            TR.AutoencoderTrainer(cfg_none, t3.device),
                            user_indices, MIN_EVENTS, peruser_floor=0.05)
    ok("a missing assignment writes nothing and does not raise",
       not list(ae3.glob("cohort_*.pt")) if ae3.exists() else True)

    # ── pooled-rows guard ──
    # c1 has 210 pooled rows. Raise the floor above that and it must be
    # refused rather than trained on too little data.
    cfg_hi = dict(cfg)
    cfg_hi["paths"] = dict(cfg["paths"])
    ae4 = work / "models4" / "autoencoders"
    cfg_hi["paths"]["autoencoder_dir"] = str(ae4)
    cfg_hi["model_tiers"] = {"enabled": True, "cohort_min_members": 2,
                             "cohort_min_rows": 5000}
    t4 = TR.UEBATrainer(cfg_hi)
    t4.thresholds = {"global": 0.5}
    t4._train_cohort_models(str(h5_path), scaler,
                            TR.AutoencoderTrainer(cfg_hi, t4.device),
                            user_indices, MIN_EVENTS, peruser_floor=0.05)
    ok("a cohort with too few pooled rows is refused",
       not list(ae4.glob("cohort_*.pt")) if ae4.exists() else True)

    total = len(_checks)
    if _failures:
        print("SN 18 cohort training: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("SN 18 cohort training: all %d checks passed" % total)
    print("workdir (safe to delete): %s" % work)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
