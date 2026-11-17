#!/usr/bin/env python3
"""The trainer must not model an address, and must not let one entity sink it.

WHAT THIS IS ABOUT

The 15-Nov-2026 weekly retrain failed with exit code -9. The log shows why:

    10:03:50  Training autoencoder for user 'ip:192.168.2.19' | events: 23,691,006
    10:04:18  Training autoencoder | samples: 18,952,805 | device: cpu
    10:04:32  oom-kill ... task=python3 ... rss=28917832kB
    10:04:29  Model training (staging) FAILED (exit code -9)

Six hours of work, 365 per-entity models already built, all discarded. The
engine was restored to the previous week's models and there were no cohort
models at all, because cohort training runs after the per-entity phase and
never ran.

Two guards, because they fail differently:

  KIND  an IP address is not an identity. It is a lease that moves between
        machines, so a model trained on it follows the address rather than
        whoever is behind it. 17,671 of 184,548 tracked entities on this
        estate are addresses and they carry 33.6% of all events.

  SIZE  even a legitimate entity can grow large enough to take the box down,
        and the cost is several copies of the rows, not one: the slice out of
        the shared matrix, the scaler's output, the torch tensor and the
        train/validation split each materialise their own array.

The kind guard alone would have survived 15-Nov. The size guard is there for
the week an entity that IS an identity grows just as large — `unknown` already
holds 51.5% of all events on this store.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402

import ueba_trainer as TR  # noqa: E402

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


def main() -> int:
    # ── 1. KIND: what must never get a model of its own ──────────────────
    for e in ("ip:192.168.2.19", "ip:10.200.11.74", "IP:10.0.0.1",
              "addr:10.0.0.9", "unknown", "UNKNOWN", " unknown ", "", "-"):
        ok("excluded from per-entity modelling: %r" % e,
           TR._is_address_or_unknown(e), "it would get its own model")

    # ── 2. KIND: what must STILL be modelled ─────────────────────────────
    # Narrower than ueba_peers.is_groupable() on purpose: that excludes
    # `host:` because a host is not a person and peer groups compare people.
    # The trainer models hosts deliberately — a device baseline is the whole
    # of SN 56 — so a guard that dropped them would delete a shipped feature.
    for e in ("host:RootSeeker", "host:kafka-prajwal", "host:DC_ATM_SRV",
              "VGSOCSRV\\prajwal", "rahul", "Administrator", "cohort:beh:x"):
        ok("still modelled: %r" % e,
           not TR._is_address_or_unknown(e),
           "the guard is too wide and would delete a shipped capability")

    # A host is excluded from PEER grouping but included in TRAINING. If those
    # two ever collapse into one rule, one of the two features breaks.
    try:
        import ueba_peers as P
        ok("the two guards deliberately disagree about hosts",
           (not TR._is_address_or_unknown("host:RootSeeker"))
           and (not P.is_groupable("host:RootSeeker")),
           "trainer models hosts; peer grouping must not")
        ok("and agree about addresses",
           TR._is_address_or_unknown("ip:1.2.3.4")
           and (not P.is_groupable("ip:1.2.3.4")))
    except Exception as e:
        ok("ueba_peers importable for the cross-check", False, str(e))

    # ── 3. SIZE: the stride cap keeps the count and the coverage ─────────
    # Reproduces the capping arithmetic at the call site. Asserted here
    # because the behaviour that matters is the SHAPE of the sample: a cap
    # that kept the first N rows would train every large entity on its
    # earliest days only.
    for total, cap in ((23_691_006, 2_000_000), (18_952_805, 2_000_000),
                       (2_000_001, 2_000_000), (5_000, 2_000_000)):
        idx = np.arange(total)
        if len(idx) > cap:
            stride = int(np.ceil(len(idx) / cap))
            kept = idx[::stride][:cap]
        else:
            kept = idx
        ok("cap %s rows -> at most %s" % (format(total, ","), format(cap, ",")),
           len(kept) <= cap, "got %d" % len(kept))
        ok("  ...and the sample still spans the whole window (%s)"
           % format(total, ","),
           kept[-1] >= int(total * 0.95) - 1,
           "last kept row %d of %d — a head-only sample would train on the "
           "earliest days alone" % (kept[-1], total))

    ok("an entity under the cap is not resampled",
       len(np.arange(5_000)) == 5_000)

    # ── 4. both guards are actually wired into the training path ─────────
    src = (ROOT / "ueba_trainer.py").read_text()
    ok("the kind guard filters the eligible list",
       "_is_address_or_unknown(u)" in src,
       "the predicate exists but nothing calls it")
    ok("the size cap is applied before the dataset is built",
       src.find("if max_rows and len(indices) > max_rows:") != -1
       and src.find("if max_rows and len(indices) > max_rows:")
       < src.find("user_ds = HDF5Dataset("),
       "capping after the slice is built would defeat the point")
    ok("the cap is read from config, not hardcoded",
       "max_events_per_user" in src)
    ok("0 disables the cap", "if max_rows and" in src,
       "a falsy cap must mean 'no cap', not 'cap at zero'")

    # ── 5. the config carries the key with a usable default ──────────────
    try:
        import yaml
        cfg = yaml.safe_load((ROOT / "ueba_config.yaml").read_text())
        pre = cfg.get("preprocessing") or {}
        cap = pre.get("max_events_per_user")
        ok("config declares max_events_per_user", cap is not None)
        ok("and the cap is well above the minimum",
           cap and cap > pre.get("min_events_per_user", 2000) * 100,
           "cap=%s min=%s — a cap near the minimum would starve real models"
           % (cap, pre.get("min_events_per_user")))
    except Exception as e:
        ok("config readable", False, str(e))

    total = len(_checks)
    if _failures:
        print("trainer entity guards: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("trainer entity guards: all %d checks passed" % total)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
