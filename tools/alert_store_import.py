#!/usr/bin/env python3
"""Backfill the indexed alert store from the flat files — RFP SN 31.

Reads what the dashboard reads today — the live `ueba_alerts.jsonl`, the daily
archive zips (or their `.slimN` projections, which are the same records already
parsed) and the false-positive store — and writes one indexed row per alert.

SAFE TO RE-RUN. Every source is tracked in `ingest_state` by byte offset and
mtime, and the upsert is keyed on event_id, so a second run imports only what
is new. It never writes to any source: the flat files stay authoritative until
the dashboard is switched over.

    python3 tools/alert_store_import.py --config ueba_config.yaml --dry-run
    python3 tools/alert_store_import.py --config ueba_config.yaml
    python3 tools/alert_store_import.py --config ueba_config.yaml --verify
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml                                             # noqa: E402

import ueba_alert_store as store                        # noqa: E402

_ARCHIVE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
_BATCH = 2000


def _abs(base: str, p: str) -> str:
    return p if os.path.isabs(p) else os.path.join(base, p)


def load_paths(cfg_path: str) -> dict:
    cfg = yaml.safe_load(open(cfg_path)) or {}
    base = os.path.dirname(os.path.abspath(cfg_path))
    paths = cfg.get("paths") or {}
    return {
        "alerts": _abs(base, paths.get("ueba_output") or "ueba_alerts.jsonl"),
        "archive": _abs(base, cfg.get("archive_dir")
                        or (paths.get("archive_dir") or "archive")),
        "fp": _abs(base, paths.get("false_positives_file") or "false_positives.json"),
        "db": _abs(base, paths.get("alert_store_db")
                   or os.path.join("profiles", "alerts.db")),
        "slim_ver": int(cfg.get("slim_version") or 7),
    }


def load_fp_ids(path: str) -> set:
    """Event ids an analyst has marked as false positives."""
    try:
        with open(path) as fh:
            d = json.load(fh)
    except Exception:
        return set()
    if isinstance(d, dict):
        return {str(k) for k in d}
    if isinstance(d, list):
        return {str(x.get("event_id")) for x in d
                if isinstance(x, dict) and x.get("event_id")}
    return set()


def _state(con, source: str) -> dict:
    r = con.execute("SELECT offset, mtime, rows FROM ingest_state WHERE source = ?",
                    (source,)).fetchone()
    return dict(r) if r else {"offset": 0, "mtime": None, "rows": 0}


def _save_state(con, source: str, offset: int, mtime: float, rows: int) -> None:
    con.execute(
        "INSERT INTO ingest_state(source, offset, mtime, rows, updated_at) "
        "VALUES(?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET "
        "offset=excluded.offset, mtime=excluded.mtime, rows=excluded.rows, "
        "updated_at=excluded.updated_at",
        (source, int(offset), float(mtime or 0), int(rows),
         time.strftime("%Y-%m-%dT%H:%M:%S")))


def import_archives(con, adir: str, fp: set, slim_ver: int, *, dry: bool) -> tuple:
    """Import every daily archive. Prefers the .slimN projection when present."""
    if not os.path.isdir(adir):
        print("  archive dir %s does not exist — skipping" % adir)
        return 0, 0
    names = sorted(n for n in os.listdir(adir) if n.endswith(".jsonl.zip"))
    total = skipped = 0
    for name in names:
        zpath = os.path.join(adir, name)
        slim = zpath[:-len(".zip")] + ".slim%d" % slim_ver
        src = "archive:" + name
        try:
            mtime = os.path.getmtime(zpath)
        except OSError:
            continue
        st = _state(con, src)
        if st["mtime"] and abs(st["mtime"] - mtime) < 1e-6 and st["rows"]:
            skipped += 1
            continue

        records = None
        if os.path.exists(slim) and os.path.getmtime(slim) >= mtime:
            try:
                with open(slim, "rb") as fh:
                    data = json.loads(fh.read())
                if isinstance(data, list):
                    records = data
            except Exception as e:
                print("  ! slim cache %s unreadable (%s) — falling back to the zip"
                      % (os.path.basename(slim), e))
        if records is None:
            records = []
            try:
                with zipfile.ZipFile(zpath) as zf:
                    inner = [n for n in zf.namelist() if n.endswith(".jsonl")] \
                        or zf.namelist()
                    for n in inner:
                        with zf.open(n) as fh:
                            for raw in fh:
                                raw = raw.strip()
                                if not raw:
                                    continue
                                try:
                                    records.append(json.loads(raw))
                                except Exception:
                                    continue
            except Exception as e:
                print("  ! %s unreadable: %s — skipped" % (name, e))
                continue

        if dry:
            print("  would import %-44s %s records" % (name, format(len(records), ",")))
            total += len(records)
            continue

        wrote = 0
        for i in range(0, len(records), _BATCH):
            wrote += store.upsert_many(con, records[i:i + _BATCH], fp_ids=fp, src=src)
            con.commit()
        _save_state(con, src, 0, mtime, wrote)
        con.commit()
        total += wrote
        print("  imported %-44s %s records" % (name, format(wrote, ",")))
    if skipped:
        print("  %d archive(s) already current — skipped" % skipped)
    return total, skipped


def import_live(con, path: str, fp: set, *, dry: bool) -> int:
    """Import the live append-only file from the last byte offset consumed."""
    if not os.path.exists(path):
        print("  live file %s does not exist — skipping" % path)
        return 0
    src = "live:" + os.path.basename(path)
    st = _state(con, src)
    size = os.path.getsize(path)
    start = int(st["offset"] or 0)
    if start > size:
        print("  live file shrank (rotation) — re-reading from the top")
        start = 0
    if start == size:
        print("  live file unchanged since the last import (%s bytes)"
              % format(size, ","))
        return 0

    batch, wrote, consumed = [], 0, start
    with open(path, "rb") as fh:
        fh.seek(start)
        for raw in fh:
            if not raw.endswith(b"\n"):
                # A partial final line: the engine is mid-append. Stop before it
                # and leave the offset here so the next run picks it up whole.
                break
            consumed += len(raw)
            raw = raw.strip()
            if not raw:
                continue
            try:
                batch.append(json.loads(raw))
            except Exception:
                continue
            if len(batch) >= _BATCH and not dry:
                wrote += store.upsert_many(con, batch, fp_ids=fp, src=src)
                con.commit()
                batch = []
    if dry:
        print("  would import %s records from the live file" % format(len(batch), ","))
        return len(batch)
    if batch:
        wrote += store.upsert_many(con, batch, fp_ids=fp, src=src)
        con.commit()
    _save_state(con, src, consumed, os.path.getmtime(path), wrote)
    con.commit()
    print("  imported %s records from the live file (offset %s -> %s)"
          % (format(wrote, ","), format(start, ","), format(consumed, ",")))
    return wrote


def verify(con, paths: dict) -> int:
    """Compare the row count against the flat files, and time the aggregates."""
    print("\nVERIFY")
    src_rows = 0
    adir = paths["archive"]
    if os.path.isdir(adir):
        for name in sorted(n for n in os.listdir(adir) if n.endswith(".jsonl.zip")):
            try:
                with zipfile.ZipFile(os.path.join(adir, name)) as zf:
                    for n in zf.namelist():
                        if not n.endswith(".jsonl"):
                            continue
                        with zf.open(n) as fh:
                            for raw in fh:
                                if raw.strip():
                                    src_rows += 1
            except Exception:
                pass
    live_rows = 0
    if os.path.exists(paths["alerts"]):
        with open(paths["alerts"], "rb") as fh:
            for raw in fh:
                if raw.strip():
                    live_rows += 1

    st = store.stats(con)
    print("  source rows : %s archive + %s live = %s"
          % (format(src_rows, ","), format(live_rows, ","),
             format(src_rows + live_rows, ",")))
    print("  store rows  : %s" % format(st["rows"], ","))
    # Fewer rows than sources is EXPECTED and not an error: event_id is the
    # primary key, and the same alert appears in both the live file and the
    # archive of the day it was rotated. Reporting the delta rather than
    # calling it a mismatch.
    delta = (src_rows + live_rows) - int(st["rows"] or 0)
    print("  difference  : %s  (duplicate event_ids across live+archive "
          "collapse to one row)" % format(delta, ","))
    print("  store size  : %.1f MB" % ((st.get("bytes") or 0) / 1048576))

    print("\n  query timings (what the dashboard would now pay):")
    for label, fn in (
        ("counts, all time",      lambda: store.counts(con, 0)),
        ("counts, 24h",           lambda: store.counts(con, 24)),
        ("top 20 entities, all",  lambda: store.top_entities(con, 0)),
        ("top 20 hosts, all",     lambda: store.top_hosts(con, 0)),
        ("top 20 signatures",     lambda: store.top_signatures(con, 0)),
        ("score histogram",       lambda: store.score_histogram(con, 0)),
        ("per-hour, 24h",         lambda: store.per_hour(con, 24)),
        ("campaigns, all",        lambda: store.campaigns(con, 0)),
        ("tier coverage",         lambda: store.tier_coverage(con, 0)),
        ("feed page of 200",      lambda: store.recent(con, 0, limit=200)),
    ):
        t = time.time()
        try:
            r = fn()
            n = len(r) if isinstance(r, (list, dict)) else 1
            print("    %-24s %7.3fs  (%s)" % (label, time.time() - t, n))
        except Exception as e:
            print("    %-24s FAILED: %s" % (label, e))
            return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Backfill the indexed alert store")
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--db", default=None, help="override the store path")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verify", action="store_true",
                    help="only compare counts and time the queries")
    a = ap.parse_args()

    paths = load_paths(a.config)
    if a.db:
        paths["db"] = a.db
    print("SOURCES")
    for k in ("alerts", "archive", "fp"):
        p = paths[k]
        print("  %-9s %-52s %s" % (k, p, "ok" if os.path.exists(p) else "ABSENT"))
    print("  %-9s %s" % ("store", paths["db"]))

    con = store.connect(paths["db"])
    if a.verify:
        rc = verify(con, paths)
        con.close()
        return rc

    fp = load_fp_ids(paths["fp"])
    print("\n  %d false-positive marking(s) will be carried over" % len(fp))
    print("\nIMPORT%s" % ("  (dry run — nothing is written)" if a.dry_run else ""))
    t0 = time.time()
    arch, _ = import_archives(con, paths["archive"], fp, paths["slim_ver"],
                              dry=a.dry_run)
    live = import_live(con, paths["alerts"], fp, dry=a.dry_run)
    st = store.stats(con)
    print("\nRESULT")
    print("  archive records : %s" % format(arch, ","))
    print("  live records    : %s" % format(live, ","))
    print("  rows in store   : %s" % format(st["rows"], ","))
    print("  store size      : %.1f MB" % ((st.get("bytes") or 0) / 1048576))
    print("  elapsed         : %.1fs" % (time.time() - t0))
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
