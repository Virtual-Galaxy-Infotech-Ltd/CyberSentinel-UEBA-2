#!/usr/bin/env python3
"""
Disk housekeeping for the UEBA tree — archive, compress, prune.

    ./ueba_housekeeping.py            # dry run, writes nothing
    ./ueba_housekeeping.py --apply    # perform the work

WHAT IT CLEANS, AND WHY EACH IS SAFE
------------------------------------
1. Orphaned archive caches (.slim1 with no matching .zip)
   `<archive>.slimN` is a LIVE performance cache, not waste: _parse_archive_zip
   writes it beside each daily zip so a cold start does not have to re-unzip and
   re-project every archive. An earlier version of this script deleted the ones
   that had a matching zip, on the mistaken reading that they were leftovers
   from a superseded implementation — they are not, they regenerate, and
   deleting them only forces the dashboard to rebuild the lot. DO NOT re-add
   that behaviour.

   What IS dead is a .slim1 whose .zip has been removed by the retention sweep:
   the cache can never be used again, because the reader finds caches only by
   globbing zips. Those are compressed into cold storage rather than deleted,
   since for that day they are the only surviving copy.

   (The retention sweep matches `ueba_alerts_*.jsonl.zip` only, which is how
   these orphans come to exist at all.)

3. Rotated logs
   `*.log.N` are closed generations that nothing appends to. Gzipped in place.

4. Development cruft
   `*.bak-*`, `*.stale-*`, `dist.bak-*`, `__pycache__` — editing artefacts.

WHAT IT WILL NOT TOUCH
----------------------
The live alert feed, the enriched feed (the daily rotate job already flushes
it), the training corpus, `training_zips/` (that is pending retrain input, not
waste), models, profiles or the vector index. This box is shared with other
teams, so nothing outside the UEBA tree is considered at all.
"""
import argparse
import gzip
import json
import os
import re
import shutil
import sys
import zipfile
from pathlib import Path

BASE = Path("/root/NEW_DRIVE/aditya_ueba")
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
LOG_ROTATED_RE = re.compile(r"\.log\.\d+$")

# Never consider these, whatever else the rules say.
PROTECTED = {
    "ueba_alerts.jsonl", "enriched.jsonl", "combined_training.jsonl",
    "features.h5", "training_zips", "models", "profiles", "vector_db",
    "venv", "archive", ".state", "dashboard",
}


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}"
        n /= 1024


def zip_record_count(path):
    """Records in a daily archive zip, or None if unreadable."""
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if not names:
                return 0
            with z.open(names[0]) as f:
                return sum(1 for line in f if line.strip())
    except Exception:
        return None


def slim_record_count(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        return len(data) if isinstance(data, list) else None
    except Exception:
        return None


def task_archive(apply_it, report):
    """Cold-store .slim1 caches whose .zip is gone. Live caches are left alone."""
    adir = BASE / "archive"
    if not adir.is_dir():
        return
    cold = BASE / "archive_cold"
    slims = sorted(adir.glob("*.slim1"))
    if not slims:
        report("archive", "no .slim1 caches present", 0)
        return

    zips = {}
    for p in adir.glob("*.zip"):
        m = DATE_RE.search(p.name)
        if m:
            zips[m.group(1)] = p

    orphan_bytes = 0
    orphan_n = live_n = 0
    for p in slims:
        m = DATE_RE.search(p.name)
        if not m:
            continue
        if zips.get(m.group(1)) is not None:
            # A zip still exists for this day, so this cache is live. Leave it.
            live_n += 1
            continue
        size = p.stat().st_size
        orphan_n += 1
        orphan_bytes += size
        if apply_it:
            cold.mkdir(parents=True, exist_ok=True)
            out = cold / (p.name + ".gz")
            with open(p, "rb") as src, gzip.open(out, "wb", compresslevel=9) as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            if out.stat().st_size > 0:
                p.unlink()

    report("archive", f"{orphan_n} orphaned cache(s) compressed to "
                      f"archive_cold/ ({human(orphan_bytes)}); "
                      f"{live_n} live cache(s) left in place", orphan_bytes)


def task_logs(apply_it, report):
    """Gzip closed log generations."""
    ldir = BASE / "logs"
    if not ldir.is_dir():
        return
    total = n = 0
    for p in sorted(ldir.iterdir()):
        if not p.is_file() or not LOG_ROTATED_RE.search(p.name):
            continue
        if p.suffix == ".gz":
            continue
        size = p.stat().st_size
        if size < 1024:
            continue
        n += 1
        total += size
        if apply_it:
            out = p.with_suffix(p.suffix + ".gz")
            with open(p, "rb") as src, gzip.open(out, "wb", compresslevel=6) as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            if out.stat().st_size > 0:
                p.unlink()
    report("logs", f"{n} rotated log(s) gzipped ({human(total)} before compression)",
           int(total * 0.9))


def task_cruft(apply_it, report):
    """Editing artefacts: .bak-*, .stale-*, dist.bak-*, __pycache__.

    The NEWEST backup of each distinct file is kept. This tree is not under
    version control, so those backups are the only way to roll a production file
    back; they total a few megabytes against a gigabyte of real waste elsewhere,
    which makes deleting the last one a bad trade at any size.
    """
    total = n = kept = 0
    targets = []
    for pat in ("*.bak-*", "*.bak.*", "*.stale-*"):
        targets.extend(p for p in BASE.glob(pat) if p.is_file())

    # Group by the file they back up: "ueba_config.yaml.bak-reports" -> that yaml.
    newest = {}
    for p in targets:
        stem = re.split(r"\.(?:bak|stale)[-.]", p.name, maxsplit=1)[0]
        cur = newest.get(stem)
        if cur is None or p.stat().st_mtime > cur.stat().st_mtime:
            newest[stem] = p
    survivors = set(newest.values())

    prunable = [p for p in targets if p not in survivors]
    kept = len(survivors)

    for d in list(BASE.glob("dist.bak-*")) + list(BASE.rglob("__pycache__")):
        if d.is_dir() and "venv" not in d.parts:
            prunable.append(d)

    for p in prunable:
        if p.name in PROTECTED:
            continue
        size = (p.stat().st_size if p.is_file()
                else sum(f.stat().st_size for f in p.rglob("*") if f.is_file()))
        n += 1
        total += size
        if apply_it:
            shutil.rmtree(p) if p.is_dir() else p.unlink()
    report("cruft", f"{n} superseded artefact(s) removed ({human(total)}); "
                    f"{kept} most-recent backup(s) kept as rollback points", total)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true",
                    help="perform the work (default is a dry run)")
    args = ap.parse_args()

    st = os.statvfs(BASE)
    before = st.f_bavail * st.f_frsize
    mode = "APPLYING" if args.apply else "DRY RUN — nothing will be written"
    print(f"\n  UEBA housekeeping — {mode}")
    print(f"  base       : {BASE}")
    print(f"  free before: {human(before)}\n")

    freed = [0]

    def report(task, msg, bytes_freed):
        print(f"  [{task:8}] {msg}")
        freed[0] += bytes_freed

    task_archive(args.apply, report)
    task_logs(args.apply, report)
    task_cruft(args.apply, report)

    st = os.statvfs(BASE)
    after = st.f_bavail * st.f_frsize
    print(f"\n  estimated reclaim : {human(freed[0])}")
    if args.apply:
        print(f"  free after        : {human(after)}  "
              f"(actual change {human(after - before)})")
    else:
        print("\n  Re-run with --apply to perform the work.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
