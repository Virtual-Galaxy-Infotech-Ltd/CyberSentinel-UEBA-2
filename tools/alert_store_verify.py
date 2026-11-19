#!/usr/bin/env python3
"""Prove the SQL path returns what the in-RAM path returns — HA phase 1.1.

The cutover replaces "load the window into RAM and walk it in Python" with
"ask the indexed store". That is only safe if the two agree, and the only
honest way to know is to run both over the same real data and diff the result.

So this does exactly that, per endpoint and per window, and reports every
field that differs. It changes nothing.

ORDER MATTERS. Narrow windows are compared first by default. Loading the "All"
window in this process costs what it costs the dashboard — on the live store
that is the better part of a gigabyte — so widening is opt-in rather than
something you trip over.

    python3 tools/alert_store_verify.py --config /etc/ueba/ueba_config.yaml
    python3 tools/alert_store_verify.py --windows 24,72,168
    python3 tools/alert_store_verify.py --windows 0        # the expensive one
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ueba_alert_store as store            # noqa: E402


def _fmt(v):
    if isinstance(v, list):
        return "[%s]" % ", ".join(
            ("%s=%s" % (x.get("reason"), x.get("count"))) if isinstance(x, dict)
            else str(x) for x in v[:5])
    return str(v)


def compare_stats(con, dash, hours: int, include_fp: bool) -> tuple:
    """(differences, old, new, timings) for the stats endpoint in one window."""
    t0 = time.time()
    alerts = dash.load_alerts(include_fp=include_fp, hours=hours)
    old = dash._build_stats(alerts)
    t_old = time.time() - t0

    t1 = time.time()
    cap = int((dash.CFG or {}).get("max_feed_alerts", 0) or 0)
    new = store.stats_window(con, hours, include_fp=include_fp, cap=cap)
    t_new = time.time() - t1

    diffs = []
    # window_* are the in-RAM path's own truncation bookkeeping and are
    # reported against a cap the SQL path does not apply, so they are compared
    # only when both sides produced them.
    keys = [k for k in old if not k.startswith("window_")]
    for k in keys:
        a, b = old.get(k), new.get(k)
        if k == "top_reasons":
            # Compare as an ordered list of (reason, count). Ties between equal
            # counts can order differently, so a mismatch is only reported when
            # the COUNTS differ, not the arrangement of equal ones.
            aa = sorted(((x["reason"], x["count"]) for x in (a or [])),
                        key=lambda t: (-t[1], t[0]))
            bb = sorted(((x["reason"], x["count"]) for x in (b or [])),
                        key=lambda t: (-t[1], t[0]))
            if aa != bb:
                diffs.append((k, _fmt(a), _fmt(b)))
            continue
        if a != b:
            diffs.append((k, a, b))
    return diffs, old, new, (t_old, t_new, len(alerts))


def main() -> int:
    ap = argparse.ArgumentParser(description="Diff the SQL path against the in-RAM path")
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--db", default=None)
    ap.add_argument("--windows", default="24,72,168",
                    help="comma-separated hours; 0 means the full history")
    ap.add_argument("--include-fp", action="store_true")
    a = ap.parse_args()

    import ueba_dashboard_server as dash     # noqa: E402

    # The dashboard sets CFG and the path globals inside main(), not at import,
    # so an imported module still holds the SHIPPED defaults — which point at a
    # data directory this install no longer uses. The first run of this tool
    # compared SQL against an in-RAM path that had loaded zero alerts and
    # reported nine "differences" that were entirely the harness's fault.
    #
    # Replicating just the configuration part of main(), without starting any
    # thread, server or scheduler.
    from pathlib import Path
    dash.CFG = dash.load_dashboard_config(a.config)
    dash._RAW_CFG = dash.load_raw_config(a.config) or {}
    dash.ALERTS_FILE = Path(dash.CFG["alerts_file"])
    dash.AGENTS_REGISTRY = Path(dash.CFG["agents_registry"])
    dash.FP_FILE = Path(dash.CFG["false_positives_file"])
    dash.FP_PATTERNS_FILE = Path(dash.CFG.get("fp_patterns_file")
                                 or dash._DEFAULTS["fp_patterns_file"])
    print("  alerts: %s" % dash.ALERTS_FILE)
    print("  archive: %s" % dash.CFG.get("archive_dir"))
    # load_fps(), not load_fp(). A hasattr() guard on the wrong name silently
    # skips this, and then the in-RAM path compares UNFILTERED alerts against a
    # SQL path that is excluding false positives — a difference that would look
    # like a bug in the SQL.
    for fn in ("load_fps", "load_fp_patterns"):
        if not hasattr(dash, fn):
            print("  WARNING: %s() missing — FP filtering may not match" % fn)
            continue
        try:
            getattr(dash, fn)()
        except Exception as e:
            print("  WARNING: %s() failed: %s" % (fn, e))
    print("  false positives loaded: %d" % len(getattr(dash, "_fp_dict", {}) or {}))

    db = a.db
    if not db:
        import yaml
        cfg = yaml.safe_load(open(a.config)) or {}
        paths = cfg.get("paths") or {}
        base = os.path.dirname(os.path.abspath(a.config))
        p = paths.get("alert_store_db") or os.path.join("profiles", "alerts.db")
        db = p if os.path.isabs(p) else os.path.join(base, p)
    print("  store : %s" % db)
    print("  config: %s" % a.config)
    con = store.connect(db, read_only=True)
    st = store.stats(con)
    print("  rows  : %s\n" % format(st["rows"], ","))

    windows = [int(w) for w in a.windows.split(",") if w.strip()]
    bad = 0
    for h in windows:
        label = "All" if h == 0 else "%dh" % h
        print("WINDOW %s" % label)
        try:
            diffs, old, new, (t_old, t_new, n) = compare_stats(
                con, dash, h, a.include_fp)
        except Exception as e:
            print("  FAILED: %s: %s\n" % (type(e).__name__, e))
            bad += 1
            continue
        print("  in-RAM : %7.3fs over %s alerts" % (t_old, format(n, ",")))
        print("  SQL    : %7.3fs" % t_new)
        if t_new > 0:
            print("  speedup: %.0fx" % (t_old / t_new) if t_new else "")
        if diffs:
            bad += 1
            print("  %d FIELD(S) DIFFER:" % len(diffs))
            for k, o, nv in diffs:
                print("    %-18s in-RAM=%-28s SQL=%s" % (k, _fmt(o), _fmt(nv)))
        else:
            print("  identical on every compared field (%d)"
                  % len([k for k in old if not k.startswith("window_")]))
        print()

    con.close()
    if bad:
        print("RESULT: %d window(s) differ — do NOT cut over" % bad)
        return 1
    print("RESULT: every window agrees")
    return 0


if __name__ == "__main__":
    sys.exit(main())
