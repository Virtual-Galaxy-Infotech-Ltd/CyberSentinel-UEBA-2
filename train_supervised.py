#!/usr/bin/env python3
"""
train_supervised.py
───────────────────
Train and publish the supervised model for RFP SN 20.

Runs offline beside the weekly retrain. Labels come from the analyst console,
not from outside the team:

    false_positives.json   an analyst marked the alert wrong   -> BENIGN
    risk_history.db        an analyst confirmed an incident    -> MALICIOUS

Feature vectors come from the SAME FeatureExtractor the unsupervised models
use, over the alerts those labels point at. A second feature space would mean
two definitions of what an event is, and the first time they drifted apart the
supervised verdict would be scoring something the engine had stopped making.

Nothing is published unless it clears the gates in ueba_supervised: enough
labels of each class, measurable recall on the malicious class, and a
positive-class F1 that beats a majority-class predictor by a margin. With the
label set dominated by false positives, a model answering "benign" to
everything would score over 99% accuracy, so accuracy is never the test.

Usage
─────
    python3 train_supervised.py --config ueba_config.yaml
    python3 train_supervised.py --config ueba_config.yaml --dry-run
    python3 train_supervised.py --config ueba_config.yaml --supply-only
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ueba_supervised as SUP  # noqa: E402


def resolve(base: Path, p) -> Path:
    q = Path(str(p))
    return q if q.is_absolute() else (base / q)


def alert_lines(alerts_file: Path, archive_dir: Path):
    """Every full alert we hold: the live file, then the archived zips.

    The .slimN projections are deliberately not read: fields the feature
    extractor needs are dropped from them, so a vector built from a slim record
    would silently differ from the one the engine produced for the same event.
    """
    if alerts_file.exists():
        with open(alerts_file, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield line
    if archive_dir.exists():
        for z in sorted(archive_dir.glob("*.jsonl.zip")):
            try:
                with zipfile.ZipFile(z) as zf:
                    for name in zf.namelist():
                        with zf.open(name) as fh:
                            for raw in fh:
                                line = raw.decode("utf-8", "replace").strip()
                                if line:
                                    yield line
            except Exception as e:
                print("  ! could not read %s: %s" % (z.name, e))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--dry-run", action="store_true",
                    help="train and report, but publish nothing")
    ap.add_argument("--supply-only", action="store_true",
                    help="report the label supply and stop")
    args = ap.parse_args()

    import yaml
    cfg_path = Path(args.config).resolve()
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    base = cfg_path.parent
    paths = cfg.get("paths") or {}
    scfg = (cfg.get("detection") or {}).get("supervised") or {}

    # The dashboard owns this file and writes it whenever an analyst marks an
    # alert, so its own config key is the authoritative one. paths.fp_file is
    # accepted as an override for a split deployment.
    fp_file = resolve(base, paths.get("fp_file")
                      or (cfg.get("dashboard") or {}).get("false_positives_file")
                      or "false_positives.json")
    rh_db = paths.get("risk_history_db") or ""
    rh_path = (resolve(base, rh_db) if rh_db else
               resolve(base, paths.get("profile_db")
                       or "profiles/user_profiles.db").parent / "risk_history.db")
    alerts = resolve(base, paths.get("alerts_file") or "ueba_alerts.jsonl")
    archive = resolve(base, paths.get("archive_dir") or "archive")
    models_dir = resolve(base, paths.get("models_dir") or "models")
    model_path = models_dir / "supervised.pkl"
    card_path = models_dir / "supervised_card.json"

    min_per_class = int(scfg.get("min_per_class") or SUP.DEFAULT_MIN_PER_CLASS)

    print("supervised training (RFP SN 20)")
    print("  benign labels    <- %s" % fp_file)
    print("  malicious labels <- %s" % rh_path)
    print("  model            -> %s" % model_path)

    fps = SUP.read_false_positives(fp_file)
    conf = SUP.read_confirmed(rh_path)
    counts = SUP.label_counts(conf, fps)
    print()
    for k in ("malicious", "benign", "conflicting", "total"):
        print("  %-14s %s" % (k, counts[k]))
    if counts["conflicting"]:
        print("  note: %d alert(s) are both confirmed and FP-marked; the "
              "confirmation is taken as the later verdict" % counts["conflicting"])

    supply = SUP.check_supply(counts, min_per_class)
    print("\n  supply gate: %s" % ("ready" if supply["ready"] else "NOT READY"))
    if not supply["ready"]:
        print("  %s" % supply["reason"])
        # Write the card anyway, so /api/supervised and the evidence pack can
        # report the real position instead of an empty silence.
        if not args.dry_run and not args.supply_only:
            models_dir.mkdir(parents=True, exist_ok=True)
            card_path.write_text(json.dumps(
                {"trained_at": None, "labels": counts, "supply": supply,
                 "published": False,
                 "headline": "No model published: " + supply["reason"]},
                indent=1), encoding="utf-8")
            print("  wrote the supply report to %s" % card_path)
        return 0
    if args.supply_only:
        return 0

    # ── vectors, from the engine's own extractor ──
    try:
        from ueba_preprocessor import FeatureExtractor, UserProfileStore
    except Exception as e:
        print("  ! cannot import the feature pipeline: %s" % e)
        return 1
    feature_dim = int((cfg.get("preprocessing") or {}).get("feature_dim") or 35)
    store = UserProfileStore(str(resolve(base, paths.get("profile_db")
                                         or "profiles/user_profiles.db")))
    extractor = FeatureExtractor(cfg, store)

    wanted = {}
    for eid in conf:
        wanted[eid] = SUP.LABEL_MALICIOUS
    for eid in fps:
        wanted.setdefault(eid, SUP.LABEL_BENIGN)

    vectors, labels, seen = [], [], set()
    scanned = unusable = 0
    for line in alert_lines(alerts, archive):
        try:
            a = json.loads(line)
        except Exception:
            continue
        eid = str(a.get("event_id") or "")
        if eid not in wanted or eid in seen:
            continue
        scanned += 1
        try:
            v = extractor.extract(a)
            if v is None or len(v) != feature_dim:
                unusable += 1
                continue
            vectors.append([float(x) for x in v])
            labels.append(wanted[eid])
            seen.add(eid)
        except Exception:
            unusable += 1

    found = {"malicious": sum(1 for y in labels if y == SUP.LABEL_MALICIOUS),
             "benign": sum(1 for y in labels if y == SUP.LABEL_BENIGN)}
    print("\n  labelled alerts matched in the alert history: %d" % scanned)
    print("  vectors built: %d  (malicious %d, benign %d)"
          % (len(vectors), found["malicious"], found["benign"]))
    if unusable:
        print("  unusable: %d" % unusable)

    # The labels exist but the alerts they point at may have aged out of the
    # retained history, which is a different problem and worth saying.
    recheck = SUP.check_supply(found, min_per_class)
    if not recheck["ready"]:
        print("  ! the labels exist but too few of the alerts they point at are "
              "still in the retained history to train on.")
        print("  %s" % recheck["reason"])
        return 0

    res = SUP.train(
        vectors, labels, feature_dim=feature_dim,
        min_per_class=min_per_class,
        min_recall=float(scfg.get("min_recall") or SUP.DEFAULT_MIN_RECALL),
        min_f1_margin=float(scfg.get("min_f1_margin")
                            or SUP.DEFAULT_MIN_F1_MARGIN),
        test_fraction=float(scfg.get("test_fraction")
                            or SUP.DEFAULT_TEST_FRACTION),
        label_sources={"benign": str(fp_file), "malicious": str(rh_path)})

    card = res["card"]
    m = card.get("metrics_heldout") or {}
    b = card.get("metrics_baseline_majority") or {}
    print("\n  held-out, MALICIOUS class:")
    print("    precision %.3f  recall %.3f  f1 %.3f"
          % (m.get("precision", 0), m.get("recall", 0), m.get("f1", 0)))
    print("  majority-class baseline:")
    print("    accuracy  %.3f  f1 %.3f   (model accuracy %.3f)"
          % (b.get("accuracy", 0), b.get("f1", 0), m.get("accuracy", 0)))
    print("  gate: %s" % ("PUBLISH" if res["ok"] else "REFUSED"))
    if not res["ok"]:
        print("  %s" % res["reason"])
        if not args.dry_run:
            models_dir.mkdir(parents=True, exist_ok=True)
            card["published"] = False
            card_path.write_text(json.dumps(card, indent=1), encoding="utf-8")
            print("  wrote the refused model's card to %s" % card_path)
        return 0

    if args.dry_run:
        print("\n  dry run: nothing written")
        return 0

    card["published"] = True
    SUP.save_model(res["model"], card, model_path, card_path)
    print("\n  published %s and %s" % (model_path.name, card_path.name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
