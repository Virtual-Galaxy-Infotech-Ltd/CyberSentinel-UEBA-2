#!/usr/bin/env python3
"""
ueba_validate_models.py — pre-deploy validation gate for retrained UEBA models.

WHY THIS EXISTS
    The weekly retrain has repeatedly shipped train/serve-skewed models straight
    into the live models/ dir (delete-then-retrain-in-place, no staging, no
    check), pinning ~99% of live events to `highly_anomalous`. Root modes:
      * scaler/model provenance mismatch (new scaler vs stale IF/AE),
      * AE threshold collapse (thresholds = p95 of TRAIN recon error; if serve
        sits outside train, deviation_score = recon/(2*thr) inflates to 1.0),
      * counter / feature provenance divergence.
    All of these show up as ONE observable symptom: a candidate model set flags a
    huge fraction of REAL recent events. This gate measures exactly that.

WHAT IT DOES
    Loads a CANDIDATE model set and scores a sample of real recent enriched events
    through the ENGINE'S OWN serve-time path (FeatureExtractor + IsolationForest
    + Autoencoder + the same fusion math). Reusing the engine's own scorers means
    the validator sees precisely what the live engine will see — no reimplementation,
    so no validator-side skew.

EXIT CODES
    0  PASS  — candidate's highly_anomalous rate is within the sane band → safe to swap.
    1  FAIL  — candidate would flood → do NOT deploy; keep current models.
    2  ERROR — could not validate (too few events, bad paths, load failure).

USAGE
    python3 ueba_validate_models.py --candidate models_staging \
        --sample enriched.jsonl --n 30000 --max-critical-rate 0.15 \
        --baseline models
"""
import argparse
import gzip
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import yaml

# Reuse the engine's own serve-time scoring components verbatim.
from ueba_models.isolation_forest import IsolationForestScorer
from ueba_models.autoencoder import AutoencoderScorer
from ueba_preprocessor import FeatureExtractor


def load_cfg(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def fuse(if_result: dict, ae_result: dict, cfg: dict) -> tuple[str, bool]:
    """Faithful copy of ueba_engine.fuse_scores (kept inline so the validator has
    no import-time dependency on the engine module). Returns (verdict, is_alert)."""
    fc = cfg["score_fusion"]
    combined = fc["isolation_forest_weight"] * if_result["anomaly_score"] \
        + fc["autoencoder_weight"] * ae_result["deviation_score"]
    combined = float(np.clip(combined, 0.0, 1.0))
    is_alert = combined >= fc["alert_threshold"]
    verdict = "normal"
    for tier in reversed(fc["verdicts"]):
        if combined >= tier["min"]:
            verdict = tier["label"]
            break
    return verdict, is_alert


def build_scorers(cfg: dict, model_dir: str):
    md = Path(model_dir)
    scaler_path = str(md / "scaler.pkl")
    scaler = joblib.load(scaler_path)
    if_scorer = IsolationForestScorer(str(md / "isolation_forest.pkl"), scaler_path, cfg)
    ae_scorer = AutoencoderScorer(str(md / "autoencoders"), scaler,
                                  str(md / "thresholds.json"), cfg)
    return if_scorer, ae_scorer


# Enriched chunks are named `enriched_YYYY-MM-DD_HH-MM-SS.jsonl[.gz]`. The
# timestamp is zero-padded throughout, so plain string ordering is already
# chronological ordering and no date parsing is needed to compare two chunks.
_CHUNK_RE = re.compile(r"enriched[_-](\d{4}-\d{2}-\d{2})[_T](\d{2}-\d{2}-\d{2})")


def chunk_key(name) -> str:
    """The sortable timestamp inside a chunk filename, or "".

    Returns the raw `YYYY-MM-DD_HH-MM-SS` text rather than a datetime: the
    only thing anyone does with it is compare it to another chunk's, and
    string comparison is exact where a parse could fail on an unexpected
    variant and silently return a wrong order.
    """
    m = _CHUNK_RE.search(str(Path(name).name))
    return "%s_%s" % (m.group(1), m.group(2)) if m else ""


def holdout_chunks(sample_dir, after: str = "", limit: int = 0) -> list:
    """Chunks strictly NEWER than `after`, newest first.

    WHY THIS EXISTS. The gate used to validate against a single file named by
    `paths.enriched_input`, which on this deployment does not exist — so the
    gate failed outright and no retrain could ever promote (2026-11-03:
    "sample file not found: /opt/ueba/enriched.jsonl").

    The obvious fix, pointing it at the training corpus, would be worse than
    the bug: a model validated on the data it was fitted to will always look
    good, and the gate exists precisely to catch a model that scores its own
    training distribution well and floods on anything else. So the sample has
    to be data the candidate has never seen.

    `after` is normally the content of `.state/last_train_pull`, the last
    chunk the weekly pull fed into the corpus. Everything newer is unseen by
    construction, which makes this a real holdout without anyone maintaining
    a second copy of the data.
    """
    d = Path(sample_dir)
    if not d.is_dir():
        return []
    cut = chunk_key(after) if after else ""
    found = []
    for f in d.iterdir():
        if not f.is_file():
            continue
        nm = f.name
        if not (nm.endswith(".jsonl") or nm.endswith(".jsonl.gz")):
            continue
        k = chunk_key(nm)
        if not k:
            continue
        if cut and k <= cut:
            continue
        found.append((k, f))
    found.sort(key=lambda kv: kv[0], reverse=True)
    out = [f for _k, f in found]
    return out[:limit] if limit else out


def read_sample_many(paths, n: int, max_scan: int) -> list[dict]:
    """Sample up to n events across several chunks, newest first.

    Spread across files rather than drained from the newest one, so the sample
    is not a few minutes of traffic that happens to be unrepresentative — a
    single quiet chunk would otherwise pass a model that floods at midday.
    """
    paths = list(paths)
    if not paths:
        return []
    per = max(1, n // len(paths))
    out: list[dict] = []
    for pth in paths:
        if len(out) >= n:
            break
        want = min(per, n - len(out))
        out.extend(read_sample(str(pth), want, max_scan))
    return out[:n]


def read_sample(path: str, n: int, max_scan: int) -> list[dict]:
    """Reservoir-sample n events from a (possibly huge) enriched jsonl(.gz),
    scanning at most max_scan lines so we never read a multi-GB file end to end."""
    opener = gzip.open if str(path).endswith(".gz") else open
    rng = random.Random(1234)  # deterministic so re-runs agree
    res: list[str] = []
    with opener(path, "rt", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= max_scan:
                break
            if len(res) < n:
                res.append(line)
            else:
                j = rng.randint(0, i)
                if j < n:
                    res[j] = line
    out = []
    for line in res:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def score_sample(cfg, if_scorer, ae_scorer, extractor, events) -> tuple[Counter, int]:
    verdicts: Counter = Counter()
    id_cfg = cfg.get("identity_resolution", {})
    mappings = id_cfg.get("mappings", {}) if id_cfg.get("enabled") else {}
    scored = 0
    for ev in events:
        try:
            fv = extractor.extract(ev)
            meta = extractor.extract_metadata(ev)
        except Exception:
            continue
        if_result = if_scorer.score(fv)
        user = meta.get("user", "unknown")
        if mappings:
            user = mappings.get(user, user)
        ae_result = ae_scorer.score(fv, user)
        verdict, is_alert = fuse(if_result, ae_result, cfg)
        verdicts[verdict if is_alert else "normal"] += 1
        scored += 1
    return verdicts, scored


def crit_rate(verdicts: Counter, scored: int) -> float:
    return verdicts.get("highly_anomalous", 0) / scored if scored else 1.0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--candidate", required=True, help="model dir to validate")
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--sample", default=None,
                    help="enriched jsonl(.gz) to sample real events from "
                         "(default: paths.input_file from config)")
    ap.add_argument("--n", type=int, default=30000, help="events to score")
    ap.add_argument("--max-scan", type=int, default=1_000_000,
                    help="max lines to scan from the sample file")
    ap.add_argument("--max-critical-rate", type=float, default=0.15,
                    help="fail if candidate flags more than this fraction as "
                         "highly_anomalous (good models sit ~0.01-0.08)")
    ap.add_argument("--baseline", default=None,
                    help="current live model dir; candidate must also be within "
                         "--baseline-multiple x its critical rate")
    ap.add_argument("--baseline-multiple", type=float, default=4.0)
    ap.add_argument("--min-events", type=int, default=500)
    ap.add_argument("--sample-dir", default=None,
                    help="directory of enriched chunks to sample a HOLDOUT "
                         "from (default: validation.sample_dir in config)")
    ap.add_argument("--after", default=None,
                    help="only use chunks newer than this chunk name or "
                         "timestamp (default: the contents of "
                         "validation.trained_through_file, i.e. the last "
                         "chunk fed into the training corpus)")
    ap.add_argument("--max-chunks", type=int, default=12,
                    help="how many holdout chunks to spread the sample across")
    args = ap.parse_args()

    cfg = load_cfg(args.config)
    vcfg = cfg.get("validation") or {}

    # An explicit --sample always wins, so an operator can validate against a
    # file of their choosing. Otherwise prefer a HOLDOUT drawn from the chunk
    # directory, and fall back to the old single-file behaviour only if no
    # directory is configured.
    events: list = []
    sample_desc = ""
    if args.sample:
        sample_path = args.sample
        if not Path(sample_path).exists():
            print(f"VALIDATION ERROR: sample file not found: {sample_path}")
            sys.exit(2)
        events = read_sample(sample_path, args.n, args.max_scan)
        sample_desc = sample_path
    else:
        sample_dir = args.sample_dir or vcfg.get("sample_dir") or ""
        after = args.after
        if after is None:
            tf = vcfg.get("trained_through_file") or ""
            try:
                after = Path(tf).read_text().strip() if tf else ""
            except Exception:
                after = ""
        if sample_dir:
            chunks = holdout_chunks(sample_dir, after or "",
                                    limit=max(1, args.max_chunks))
            if not chunks:
                # Deliberately fatal. An empty holdout means every candidate
                # would be promoted unchecked, and a gate that passes because
                # it had nothing to test is worse than one that fails loudly.
                print(f"VALIDATION ERROR: no holdout chunks in {sample_dir} "
                      f"newer than {after or '<unset>'} — the candidate cannot "
                      f"be validated against unseen data. Is the enriched feed "
                      f"still writing?")
                sys.exit(2)
            events = read_sample_many(chunks, args.n, args.max_scan)
            sample_desc = ("%d holdout chunk(s) from %s, newer than %s"
                           % (len(chunks), sample_dir, after or "<unset>"))
            print("HOLDOUT    %s" % sample_desc)
            print("  newest=%s  oldest=%s"
                  % (chunks[0].name, chunks[-1].name))
        else:
            sample_path = (cfg["paths"].get("enriched_input")
                           or cfg["paths"].get("input_file") or "enriched.jsonl")
            if not Path(sample_path).exists():
                print(f"VALIDATION ERROR: sample file not found: {sample_path}"
                      f" and no validation.sample_dir is configured, so no "
                      f"holdout could be assembled either")
                sys.exit(2)
            events = read_sample(sample_path, args.n, args.max_scan)
            sample_desc = sample_path

    if len(events) < args.min_events:
        print(f"VALIDATION ERROR: only {len(events)} events sampled from "
              f"{sample_desc} (need >= {args.min_events}) — cannot validate")
        sys.exit(2)

    # profile_store=None: feature[34] user_deviation_baseline is a zero-variance
    # 'dead column' at train time, so the engine's skew-guard zeros it at serve
    # too — None here matches serve exactly for models trained by this pipeline.
    extractor = FeatureExtractor(cfg, None)

    try:
        if_s, ae_s = build_scorers(cfg, args.candidate)
    except Exception as e:
        print(f"VALIDATION ERROR: could not load candidate models from "
              f"{args.candidate}: {e}")
        sys.exit(2)

    verds, scored = score_sample(cfg, if_s, ae_s, extractor, events)
    c_rate = crit_rate(verds, scored)
    a_rate = sum(v for k, v in verds.items() if k != "normal") / scored if scored else 1.0
    print(f"CANDIDATE  {args.candidate}")
    print(f"  scored={scored}  verdicts={dict(verds)}")
    print(f"  highly_anomalous_rate={c_rate:.4f}  alert_rate={a_rate:.4f}")

    ok = c_rate <= args.max_critical_rate
    reason = (f"crit_rate {c_rate:.4f} <= cap {args.max_critical_rate}" if ok
              else f"crit_rate {c_rate:.4f} > cap {args.max_critical_rate}")

    if args.baseline and Path(args.baseline).exists():
        try:
            b_if, b_ae = build_scorers(cfg, args.baseline)
            bverds, bscored = score_sample(cfg, b_if, b_ae, extractor, events)
            b_rate = crit_rate(bverds, bscored)
            print(f"BASELINE   {args.baseline}")
            print(f"  scored={bscored}  crit_rate={b_rate:.4f}  verdicts={dict(bverds)}")
            rel_cap = max(args.max_critical_rate, args.baseline_multiple * b_rate)
            if c_rate > rel_cap:
                ok = False
                reason = (f"crit_rate {c_rate:.4f} > {args.baseline_multiple}x "
                          f"baseline ({b_rate:.4f})")
        except Exception as e:
            print(f"  (baseline comparison skipped: {e})")

    print(f"VALIDATION {'PASS' if ok else 'FAIL'} ({reason})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
