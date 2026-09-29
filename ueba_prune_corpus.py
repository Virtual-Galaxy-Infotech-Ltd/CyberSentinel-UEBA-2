#!/usr/bin/env python3
"""
In-place rolling-window prune for combined_training.jsonl.

WHY THIS EXISTS
---------------
ueba_weekly_retrain.sh already has a prune. Its design is the safe one: stream
the kept portion to a temp file, verify it, then swap. But it needs free space
equal to what it KEEPS — ~250 GB here — and this box has 0 bytes free. So on a
full disk that prune can never run, which is precisely how the pipeline
deadlocks: disk fills -> retrain dies -> prune never runs -> disk stays full.

This does the same job at zero free space, using two properties of the file:

  1. It is append-ordered, so event_time increases monotonically down the file.
     The cutoff can therefore be BINARY SEARCHED — a few hundred reads instead
     of streaming 529 GB.
  2. We only ever drop from the FRONT. On ext4, fallocate(COLLAPSE_RANGE)
     removes a leading byte range in place, instantly, with no copy and no
     temp space.

WHAT IT COSTS
-------------
COLLAPSE_RANGE requires the range to be filesystem-block aligned, so the cut is
rounded DOWN to a 4096 boundary. Rounding down is the safe direction: it keeps
slightly MORE than asked for, never less. The consequence is one truncated line
at the head of the file, which is harmless — every consumer wraps json.loads in
`except Exception: pass` (verified in ueba_prepare_training_data.py:160-168).

THIS IS NOT REVERSIBLE. The dropped bytes are gone. Run without --apply first
and read the plan.

    ./ueba_prune_corpus.py <file> <days>           # dry run, writes nothing
    ./ueba_prune_corpus.py <file> <days> --apply   # perform the collapse
"""
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

KEY = b'"event_time":"'
BLOCK = 4096          # ext4 filesystem block; COLLAPSE_RANGE needs alignment
DATELEN = 10          # YYYY-MM-DD — ISO-8601 dates sort correctly as bytes
SCAN_LINES = 400      # how far to look for a line carrying a timestamp


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.2f} {unit}"
        n /= 1024


def first_date_at(fh, off):
    """Date of the first COMPLETE line at or after `off`, plus that line's start.

    Seeking to an arbitrary offset usually lands mid-line, so the first partial
    line is discarded before reading. Returns (None, off) if no timestamped line
    is found within SCAN_LINES.
    """
    fh.seek(off)
    if off:
        fh.readline()
    for _ in range(SCAN_LINES):
        pos = fh.tell()
        line = fh.readline()
        if not line:
            return None, pos
        i = line.find(KEY)
        if i != -1:
            return line[i + len(KEY): i + len(KEY) + DATELEN], pos
    return None, off


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    path, days = sys.argv[1], int(sys.argv[2])
    apply_it = "--apply" in sys.argv

    if not os.path.isfile(path):
        print(f"  no such file: {path}")
        return 1
    size = os.path.getsize(path)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d").encode()

    st = os.statvfs(path)
    print("\n  in-place corpus prune")
    print(f"  file        : {path}")
    print(f"  size        : {human(size)}")
    print(f"  free on fs  : {human(st.f_bavail * st.f_frsize)}")
    print(f"  keep window : {days} days  (events on/after {cutoff.decode()})")

    with open(path, "rb") as fh:
        head, _ = first_date_at(fh, 0)
        tail, _ = first_date_at(fh, max(0, size - 4 * 1024 * 1024))
        print(f"  spans       : {head.decode() if head else '?'} -> {tail.decode() if tail else '?'}")

        if head is None:
            print("\n  could not read a timestamp at the head — refusing to guess. Nothing done.")
            return 1
        if head >= cutoff:
            print("\n  head is already inside the window — nothing to drop.")
            return 0

        # Binary search for the first line whose date >= cutoff. Relies on the
        # file being append-ordered, which is how retrain.py writes it.
        lo, hi, found = 0, size, size
        probes = 0
        while lo < hi:
            mid = (lo + hi) // 2
            date, pos = first_date_at(fh, mid)
            probes += 1
            if date is None or date >= cutoff:
                found = min(found, pos)
                hi = mid
            else:
                lo = mid + 1
        cut = (found // BLOCK) * BLOCK        # round DOWN — keeps a little extra

        # Report what actually survives, read back from the real offset.
        kept_date, _ = first_date_at(fh, cut)

    print(f"  probes      : {probes} reads (binary search, not a full scan)")
    print(f"\n  cut at      : {cut:,} bytes  (4096-aligned)")
    print(f"  would free  : {human(cut)}")
    print(f"  remaining   : {human(size - cut)}  starting {kept_date.decode() if kept_date else '?'}")

    # ── Safety gates ────────────────────────────────────────────────────────
    if cut <= 0:
        print("\n  computed cut is 0 — nothing to do.")
        return 0
    if cut >= size:
        print("\n  REFUSING: cut covers the whole file. That would empty the corpus.")
        return 1
    if (size - cut) < 1024 * 1024:
        print("\n  REFUSING: fewer than 1 MB would remain — that cannot be right.")
        return 1
    if kept_date is not None and kept_date < cutoff:
        # Expected: rounding down keeps a bit more than the window. Only flag it
        # if it kept absurdly more, which would mean the search misbehaved.
        drift = (datetime.strptime(cutoff.decode(), "%Y-%m-%d")
                 - datetime.strptime(kept_date.decode(), "%Y-%m-%d")).days
        if drift > 1:
            print(f"\n  REFUSING: kept data starts {drift} days before the window — "
                  "the offset looks wrong.")
            return 1

    if not apply_it:
        print("\n  DRY RUN — nothing was written.")
        print("  Re-run with --apply to perform the collapse.\n")
        return 0

    print("\n  applying fallocate --collapse-range ...")
    r = subprocess.run(["fallocate", "-c", "-o", "0", "-l", str(cut), path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  FAILED: {(r.stderr or '').strip()}")
        print("  The file is unchanged — COLLAPSE_RANGE is atomic on ext4.")
        return 1

    new = os.path.getsize(path)
    with open(path, "rb") as fh:
        now_head, _ = first_date_at(fh, 0)
    st = os.statvfs(path)
    print(f"  done        : {human(size)} -> {human(new)}   (freed {human(size - new)})")
    print(f"  now spans   : {now_head.decode() if now_head else '?'} -> {tail.decode() if tail else '?'}")
    print(f"  free on fs  : {human(st.f_bavail * st.f_frsize)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
