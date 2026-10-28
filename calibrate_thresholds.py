#!/usr/bin/env python3
"""
calibrate_thresholds.py
───────────────────────
CyberSentinel UEBA — fit the Isolation Forest score mapping to THIS estate.

WHY
───
The IF layer converts sklearn's raw `score_samples` output into a 0-1 anomaly
score with a hardcoded range:

    anomaly_score = clip(-raw_score / 0.5, 0.0, 1.0)

That assumes raw scores span roughly 0.0 (normal) to -0.5 (anomalous), which
held for the estate the model was trained on. It does not transfer. Measured on
the deployment at Virtual Galaxy on 2026-10-28, raw scores over real traffic
span only:

    min -0.6187   p25 -0.6020   median -0.6015   p75 -0.5788   max -0.5729

Every one of those is below -0.5, so `-raw/0.5` is at least 1.146 and the clip
returns exactly 1.0 for everything. The Isolation Forest contributed a flat 1.0
to 100% of alerts — half the fused score, carrying no information. 54% of
alerts came out "highly_anomalous", which is the alert-fatigue failure mode:
if everything is critical, the severity column is noise.

The verdict tiers in `isolation_forest.thresholds` are mis-calibrated the same
way (all local scores sit past the "anomalous" line), but those only label the
IF sub-score. The saturation that matters comes from the normalisation range.

WHAT THIS DOES
──────────────
Scores a sample of real enriched events — ALL events, not just the ones that
became alerts, because alerts are a biased high slice and calibrating on them
would bake the bias in — then reports the percentiles and the config to apply.

It writes nothing. Review the output, then edit ueba_config.yaml.

USAGE
─────
    ./venv/bin/python3 calibrate_thresholds.py \
        --config ueba_config.yaml \
        --sample-dir /home/vgipl/CyberSentinel-Event-Correlation-Kafka/data/enriched \
        --limit 150000
"""

import argparse
import glob
import gzip
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")


def iter_events(sample_dir, limit):
    """Newest files first — calibrate on current traffic, not last month's."""
    paths = sorted(glob.glob(os.path.join(sample_dir, "enriched_*.jsonl*")),
                   key=os.path.getmtime, reverse=True)
    n = 0
    for p in paths:
        opener = gzip.open if p.endswith(".gz") else open
        try:
            with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except ValueError:
                        continue
                    n += 1
                    if limit and n >= limit:
                        return
        except OSError:
            continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--sample-dir", required=True)
    ap.add_argument("--limit", type=int, default=150000)
    args = ap.parse_args()

    import numpy as np
    import joblib
    import ueba_preprocessor as pp

    cfg = pp.load_config(args.config)
    scaler = joblib.load(cfg["paths"]["scaler"])
    forest = joblib.load(cfg["paths"]["isolation_forest"])
    fx = pp.FeatureExtractor(cfg)

    print("sampling %s (newest first, limit %d)" % (args.sample_dir, args.limit))
    vecs = []
    for ev in iter_events(args.sample_dir, args.limit):
        try:
            vecs.append(fx.extract(ev))
        except Exception:
            continue
    if not vecs:
        sys.exit("no events could be featurised — wrong directory?")

    X = np.asarray(vecs, dtype=np.float32)
    print("featurised %d events" % len(X))
    raw = forest.score_samples(scaler.transform(X))

    def pct(p):
        return float(np.percentile(raw, p))

    print()
    print("RAW isolation-forest score distribution over ALL sampled events")
    print("  (sklearn score_samples: higher = more normal, lower = more anomalous)")
    for p in (0.1, 1, 5, 25, 50, 75, 95, 99, 99.9):
        print("    p%-5s %+.4f" % (p, pct(p)))
    print("    min   %+.4f" % raw.min())
    print("    max   %+.4f" % raw.max())

    # What the CURRENT hardcoded mapping does to this distribution.
    cur = np.clip(-raw / 0.5, 0.0, 1.0)
    print()
    print("CURRENT mapping  anomaly = clip(-raw/0.5, 0, 1)")
    print("    saturated at 1.0 : %.1f%% of events" % (100.0 * (cur >= 0.999).mean()))
    print("    distinct values  : %d" % len(np.unique(np.round(cur, 3))))

    # Proposed: stretch the observed body of the distribution across 0..1.
    # p99 is the "normal" anchor and p0.1 the "anomalous" anchor — not min/max,
    # which would let a single outlier set the whole scale.
    normal_at = pct(99)
    anom_at = pct(0.1)
    span = normal_at - anom_at
    if span <= 0:
        sys.exit("degenerate distribution (span %.6f) — cannot calibrate" % span)

    prop = np.clip((normal_at - raw) / span, 0.0, 1.0)
    print()
    print("PROPOSED mapping  anomaly = clip((normal_at - raw) / (normal_at - anom_at), 0, 1)")
    print("    normal_at (p99)   %+.4f  -> anomaly 0.0" % normal_at)
    print("    anom_at   (p0.1)  %+.4f  -> anomaly 1.0" % anom_at)
    print("    saturated at 1.0 : %.2f%% of events" % (100.0 * (prop >= 0.999).mean()))
    print("    distinct values  : %d" % len(np.unique(np.round(prop, 3))))
    print("    resulting anomaly percentiles:")
    for p in (50, 75, 95, 99, 99.9):
        print("      p%-5s %.3f" % (p, float(np.percentile(prop, p))))

    # Verdict tiers, as raw-score cutoffs at sensible rarities.
    t_susp = pct(5)
    t_anom = pct(1)
    t_high = pct(0.1)

    print()
    print("─" * 70)
    print("APPLY TO ueba_config.yaml under isolation_forest:")
    print("─" * 70)
    print("""
  # Calibrated against %d real events from this estate on this host.
  # The previous values came from a different estate; every local raw score
  # sat below the old -0.5 normalisation floor, so the anomaly score clipped
  # to 1.0 for 100%% of alerts and the layer stopped discriminating.
  score_range:
    normal_at:    %+.4f    # p99  of local raw scores -> anomaly 0.0
    anomalous_at: %+.4f    # p0.1 of local raw scores -> anomaly 1.0

  thresholds:
    suspicious:       %+.4f   # rarest 5%%
    anomalous:        %+.4f   # rarest 1%%
    highly_anomalous: %+.4f   # rarest 0.1%%
""" % (len(X), normal_at, anom_at, t_susp, t_anom, t_high))
    print("Then: systemctl restart ueba-engine")
    print()
    print("NOTE: this changes every score, so it changes which events become")
    print("alerts. Expect the alert count to FALL — that is the point. Re-check")
    print("the verdict mix afterwards; a healthy one is mostly 'suspicious'")
    print("with 'highly_anomalous' rare.")


if __name__ == "__main__":
    main()
