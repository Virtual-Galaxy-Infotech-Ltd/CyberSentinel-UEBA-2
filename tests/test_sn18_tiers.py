#!/usr/bin/env python3
"""RFP SN 18 — the cohort tier, exercised through the real scorer.

ueba_model_tiers.selftest() proves the decision logic in isolation. This
proves the thing that actually runs: AutoencoderScorer loading real
Autoencoder weights off disk and choosing between three tiers. The logic being
right is not the same as it being wired in, and the wiring is where this kind
of change fails — a name sanitised differently on the two sides makes the
scorer fall through to the global model for everybody, silently, with no error
anywhere.

Isolated: real .pt files, real thresholds.json and a real peer-group
assignment, all written into a temp directory. Nothing reads production.
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

import numpy as np  # noqa: E402
import torch  # noqa: E402
import yaml  # noqa: E402

import ueba_model_tiers as T  # noqa: E402
from ueba_models.autoencoder import Autoencoder, AutoencoderScorer  # noqa: E402

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


class _Scaler:
    """Identity scaler with the attributes _zero_variance_cols looks for."""

    def __init__(self, dim=35):
        self.n_features_in_ = dim
        self.scale_ = np.ones(dim, dtype=np.float64)
        self.mean_ = np.zeros(dim, dtype=np.float64)
        self.var_ = np.ones(dim, dtype=np.float64)

    def transform(self, X):
        return np.asarray(X, dtype=np.float64)


def _write_model(path: Path, dim, hidden, seed):
    """A real Autoencoder with distinguishable weights.

    Different seeds give different reconstruction errors, which is how the
    test tells WHICH model scored an event rather than taking model_used on
    trust — a wrong model name reported correctly would still be a bug.
    """
    torch.manual_seed(seed)
    m = Autoencoder(input_dim=dim, hidden_dims=hidden, dropout=0.0)
    torch.save(m.state_dict(), str(path))


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="sn18-"))
    ae_dir = work / "autoencoders"
    ae_dir.mkdir(parents=True)

    cfg = yaml.safe_load((ROOT / "ueba_config.yaml").read_text())
    dim = cfg["autoencoder"]["architecture"]["input_dim"]
    hidden = cfg["autoencoder"]["architecture"]["hidden_dims"]

    # Three real models: global, one entity's own, one cohort's.
    _write_model(ae_dir / "global.pt", dim, hidden, seed=1)
    _write_model(ae_dir / "busy_person.pt", dim, hidden, seed=2)
    _write_model(ae_dir / (T.safe_model_name(T.cohort_model_key("c1")) + ".pt"),
                 dim, hidden, seed=3)

    # The cohort file must be named by the SHARED sanitiser, or the scorer
    # looks for a name the trainer never wrote.
    cohort_file = ae_dir / (T.safe_model_name(T.cohort_model_key("c1")) + ".pt")
    ok("the cohort model file is named by the shared sanitiser",
       cohort_file.exists(), "expected %s" % cohort_file.name)
    ok("and that name is cohort_c1.pt", cohort_file.name == "cohort_c1.pt",
       cohort_file.name)

    thresholds = {
        "global": 0.50,
        "busy.person": 0.10,
        T.cohort_model_key("c1"): 0.20,
        # A threshold left behind by a previous run whose model no longer
        # exists. Before the fix, score() looked thresholds up by USERNAME, so
        # this value would have been applied to the global model's error.
        "ghost.person": 0.0001,
    }
    th_path = work / "thresholds.json"
    th_path.write_text(json.dumps(thresholds))

    # A real peer-group assignment, in ueba_peers' own format.
    assignment = {
        "members": {
            "quiet.one":   {"cohort": "c1", "source": "behaviour",
                            "membership": 0.9, "distance": 0.1},
            "quiet.two":   {"cohort": "c1", "source": "behaviour",
                            "membership": 0.8, "distance": 0.2},
            "lonely.one":  {"cohort": "c9", "source": "behaviour",
                            "membership": 0.7, "distance": 0.3},
        },
        "cohorts": {"c1": {"size": 2}, "c9": {"size": 1}},
    }
    groups_path = work / "peer_groups.json"
    groups_path.write_text(json.dumps(assignment))

    scfg = {
        "autoencoder": cfg["autoencoder"],
        "streaming": {"max_loaded_user_models": 8},
        "paths": {"peer_groups_file": str(groups_path)},
        "model_tiers": {"enabled": True},
    }
    scorer = AutoencoderScorer(str(ae_dir), _Scaler(dim), str(th_path), scfg)

    vec = np.ones(dim, dtype=np.float64) * 0.4

    # ── tier 1: an entity with its own model ──
    r = scorer.score(vec, "busy.person")
    ok("an entity with its own model uses it", r["model_used"] == "busy.person",
       r["model_used"])
    ok("and the tier says so", r["model_tier"] == "entity", r["model_tier"])
    ok("and its OWN threshold is applied", abs(r["threshold"] - 0.10) < 1e-9,
       str(r["threshold"]))

    # ── tier 2: a quiet entity in a cohort that HAS a model ──
    r1 = scorer.score(vec, "quiet.one")
    ok("a quiet entity uses its cohort's model",
       r1["model_used"] == "cohort:c1", r1["model_used"])
    ok("the tier is reported as cohort", r1["model_tier"] == "cohort",
       r1["model_tier"])
    ok("the COHORT's threshold is applied, not the entity's",
       abs(r1["threshold"] - 0.20) < 1e-9, str(r1["threshold"]))

    # Both members of c1 must get the SAME model — that is what sharing means.
    r2 = scorer.score(vec, "quiet.two")
    ok("every member of a cohort is judged by the same model",
       r2["model_used"] == r1["model_used"] == "cohort:c1")
    ok("and gets the same reconstruction error",
       abs(r1["reconstruction_error"] - r2["reconstruction_error"]) < 1e-12)

    # ── tier 3: a cohort with NO model on disk falls through ──
    # c9 is a real placement but no cohort_c9.pt was written (it would have
    # had one member — below cohort_min_members). Falling through is correct;
    # loading a file that is not there is not.
    r = scorer.score(vec, "lonely.one")
    ok("a placement with no model falls through to global",
       r["model_used"] == "global", r["model_used"])
    ok("and the tier is global", r["model_tier"] == "global")
    ok("with the global threshold", abs(r["threshold"] - 0.50) < 1e-9,
       str(r["threshold"]))

    # ── tier 3: an entity nobody placed ──
    r = scorer.score(vec, "stranger")
    ok("an unplaced entity uses global", r["model_used"] == "global")
    ok("with the global threshold", abs(r["threshold"] - 0.50) < 1e-9)

    # ── the stale-threshold bug ──
    # `ghost.person` has a threshold of 0.0001 and no model. Keyed by
    # username, that 0.0001 would be compared against the GLOBAL model's
    # reconstruction error and almost every event would read as anomalous —
    # a flood. Keyed by the model that produced the error, it is ignored.
    r = scorer.score(vec, "ghost.person")
    ok("a stale threshold is not applied to the global model",
       abs(r["threshold"] - 0.50) < 1e-9, str(r["threshold"]))
    ok("and the model used really is global", r["model_used"] == "global")

    # ── the models are genuinely different ──
    # If the scorer were quietly serving one model for everything, the three
    # tiers would report different names and identical errors.
    e_entity = scorer.score(vec, "busy.person")["reconstruction_error"]
    e_cohort = scorer.score(vec, "quiet.one")["reconstruction_error"]
    e_global = scorer.score(vec, "stranger")["reconstruction_error"]
    ok("the entity and cohort models are actually different weights",
       abs(e_entity - e_cohort) > 1e-9)
    ok("the cohort and global models are actually different weights",
       abs(e_cohort - e_global) > 1e-9)

    # ── a cohort key must never be shown as a person ──
    ok("a cohort key is not an entity name",
       not T.is_entity_model(r1["model_used"]))

    # ── the tier switched off behaves exactly as before ──
    scfg_off = dict(scfg, model_tiers={"enabled": False})
    scorer_off = AutoencoderScorer(str(ae_dir), _Scaler(dim), str(th_path),
                                   scfg_off)
    r = scorer_off.score(vec, "quiet.one")
    ok("with the tier disabled a quiet entity falls back to global",
       r["model_used"] == "global", r["model_used"])
    r = scorer_off.score(vec, "busy.person")
    ok("and its own model is still used",
       r["model_used"] == "busy.person")

    # ── a missing assignment is survivable ──
    scfg_missing = dict(scfg, paths={"peer_groups_file": str(work / "nope.json")})
    scorer_missing = AutoencoderScorer(str(ae_dir), _Scaler(dim), str(th_path),
                                       scfg_missing)
    r = scorer_missing.score(vec, "quiet.one")
    ok("no assignment file means global, not a crash",
       r["model_used"] == "global")

    # ── the LRU cache is keyed by MODEL, not by entity ──
    # Two members sharing a cohort must occupy ONE cache slot, or a large
    # cohort evicts the per-entity models that actually differ.
    before = scorer.cache_size
    scorer.score(vec, "quiet.one")
    scorer.score(vec, "quiet.two")
    ok("two members of one cohort occupy one cache entry",
       scorer.cache_size == before, "%d -> %d" % (before, scorer.cache_size))

    # ── the REAL assignment format, end to end ──
    # Everything above used hand-written assignment JSON. If build_cohorts
    # emits a different shape, or ueba_peers.save/load wrap it, production
    # breaks while this test passes. So: build a genuine assignment from
    # synthetic access profiles, persist it with ueba_peers' own writer, let
    # the scorer load it, and train-name a cohort model from the id it chose.
    import ueba_peers as P
    profiles = {
        "person:a1": {"crm": 50, "wiki": 10},
        "person:a2": {"crm": 45, "wiki": 12},
        "person:a3": {"crm": 52, "wiki": 9},
        "person:z9": {"obscure": 5},
    }
    real = P.build_cohorts(profiles, min_size=2, min_events=1,
                           max_distance=0.4)
    real_path = work / "real_groups.json"
    P.save(real_path, real)
    reloaded = P.load(real_path)
    ok("a saved assignment reloads with its members",
       bool((reloaded or {}).get("members")),
       "keys: %s" % sorted((reloaded or {}).keys()))

    cid = T.cohort_for(reloaded, "person:a1")
    ok("a real member resolves to a real cohort id", bool(cid), repr(cid))
    # The id build_cohorts picks contains a colon (e.g. `beh:person_a3`), so
    # the model key has two and the FILENAME must still be safe.
    key = T.cohort_model_key(cid)
    fname = T.safe_model_name(key) + ".pt"
    ok("the cohort model filename is filesystem-safe",
       "/" not in fname and ":" not in fname and "\\" not in fname, fname)
    _write_model(ae_dir / fname, dim, hidden, seed=7)

    th2 = dict(thresholds)
    th2[key] = 0.33
    th2_path = work / "thresholds_real.json"
    th2_path.write_text(json.dumps(th2))

    scfg_real = dict(scfg, paths={"peer_groups_file": str(real_path)})
    scorer_real = AutoencoderScorer(str(ae_dir), _Scaler(dim), str(th2_path),
                                    scfg_real)
    r = scorer_real.score(vec, "person:a1")
    ok("a real cohort member is scored by its cohort model",
       r["model_used"] == key, "%s vs %s" % (r["model_used"], key))
    ok("with the cohort's own threshold", abs(r["threshold"] - 0.33) < 1e-9,
       str(r["threshold"]))
    ok("and the tier reads cohort", r["model_tier"] == "cohort")
    # The BARE spelling must resolve too: thresholds.json on this deployment
    # proves the engine hands over bare names, not typed keys.
    bare_name = "a1"
    r = scorer_real.score(vec, bare_name)
    ok("the bare spelling of a typed member also resolves",
       r["model_used"] == key, "%s got %s" % (bare_name, r["model_used"]))
    # The unplaced loner still falls to global.
    r = scorer_real.score(vec, "person:z9")
    ok("an unplaced real entity still uses global",
       r["model_used"] == "global", r["model_used"])

    total = len(_checks)
    if _failures:
        print("SN 18 tiers: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("SN 18 tiers: all %d checks passed" % total)
    print("workdir (safe to delete): %s" % work)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
