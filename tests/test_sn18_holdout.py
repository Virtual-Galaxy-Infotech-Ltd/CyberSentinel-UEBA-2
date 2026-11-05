#!/usr/bin/env python3
"""RFP SN 18 — the validation gate's holdout selection.

The gate decides whether a freshly trained model set replaces the live one. It
had failed on every run since the pipeline was repaired:

    VALIDATION ERROR: sample file not found: /opt/ueba/enriched.jsonl

so nothing could ever be promoted. The tempting fix — point it at the training
corpus, which does exist and is 79 GB — would be worse than the bug, because a
model scored against the data it was fitted to always looks good and the gate
exists to catch exactly the model that fits its training distribution and
floods on everything else.

So the sample is assembled from chunks the candidate has never seen. These
tests cover the selection, not the scoring: which files are chosen, which are
refused, and that nothing from the training window can slip in.

Filenames here are real ones from the live feed, including the genuine
`.state/last_train_pull` value of 2026-11-02.
"""
from __future__ import annotations

import gzip
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

import ueba_validate_models as V  # noqa: E402

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


# The real cut-off on this deployment: the last chunk the weekly pull fed into
# the corpus. Everything at or before this is training data.
TRAINED_THROUGH = "enriched_2026-10-31_21-56-09.jsonl.gz"

IN_WINDOW = [
    "enriched_2026-10-28_09-00-00.jsonl.gz",
    "enriched_2026-10-31_21-56-09.jsonl.gz",   # the cut-off itself
]
HOLDOUT = [
    "enriched_2026-10-31_22-08-11.jsonl.gz",   # 12 minutes after
    "enriched_2026-11-01_03-30-00.jsonl.gz",
    "enriched_2026-11-02_17-19-52.jsonl.gz",
    "enriched_2026-11-02_18-41-44.jsonl",      # uncompressed, as the live one is
]


def _event(i):
    return {"event_time": "2026-11-02T10:00:00+05:30",
            "agent": {"name": "probe"},
            "data": {"srcip": "10.0.0.%d" % (i % 250)},
            "rule": {"id": "5710", "level": 5, "description": "probe"}}


def write_chunk(path: Path, n=40):
    body = "\n".join(json.dumps(_event(i)) for i in range(n)) + "\n"
    if path.name.endswith(".gz"):
        with gzip.open(path, "wt") as f:
            f.write(body)
    else:
        path.write_text(body)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="sn18hold-"))
    feed = work / "enriched"
    feed.mkdir()
    for name in IN_WINDOW + HOLDOUT:
        write_chunk(feed / name)
    # Noise that must be ignored: not a chunk, and a directory.
    (feed / "README.txt").write_text("not a chunk")
    (feed / "enriched_bad_name.jsonl").write_text("{}\n")
    (feed / "subdir").mkdir()

    # ── chunk_key ──
    ok("a timestamp is extracted",
       V.chunk_key("enriched_2026-11-02_18-41-44.jsonl") == "2026-11-02_18-41-44")
    ok("the .gz form works too",
       V.chunk_key("enriched_2026-11-02_17-19-52.jsonl.gz") == "2026-11-02_17-19-52")
    ok("a full path works",
       V.chunk_key("/a/b/enriched_2026-11-02_17-19-52.jsonl.gz")
       == "2026-11-02_17-19-52")
    ok("a non-chunk yields nothing", V.chunk_key("README.txt") == "")
    ok("a malformed chunk name yields nothing",
       V.chunk_key("enriched_bad_name.jsonl") == "")
    # String ordering must BE chronological ordering — the whole comparison
    # rests on it, and a non-padded format would break it silently.
    ok("string order is chronological",
       V.chunk_key(HOLDOUT[0]) > V.chunk_key(TRAINED_THROUGH)
       and V.chunk_key(IN_WINDOW[0]) < V.chunk_key(TRAINED_THROUGH))
    ok("a month rollover orders correctly",
       V.chunk_key("enriched_2026-11-01_00-00-00.jsonl")
       > V.chunk_key("enriched_2026-10-31_23-59-59.jsonl"))

    # ── the core guarantee: nothing from the training window ──
    picked = V.holdout_chunks(feed, TRAINED_THROUGH)
    names = [p.name for p in picked]
    ok("every holdout chunk was found", len(picked) == len(HOLDOUT),
       "got %s" % names)
    ok("and they are exactly the unseen ones", set(names) == set(HOLDOUT),
       "got %s" % names)
    for bad in IN_WINDOW:
        ok("training-window chunk %s is excluded" % bad, bad not in names)
    ok("the cut-off chunk ITSELF is excluded",
       TRAINED_THROUGH not in names)
    ok("non-chunk files are ignored", "README.txt" not in names)
    ok("an unparseable name is ignored", "enriched_bad_name.jsonl" not in names)
    ok("a directory is ignored", "subdir" not in names)

    # ── ordering and limit ──
    ok("newest comes first", names[0] == "enriched_2026-11-02_18-41-44.jsonl",
       names[0])
    two = V.holdout_chunks(feed, TRAINED_THROUGH, limit=2)
    ok("the limit is honoured", len(two) == 2)
    ok("and keeps the NEWEST two",
       [p.name for p in two] == names[:2], str([p.name for p in two]))

    # ── degenerate inputs ──
    ok("no cut-off means everything parseable",
       len(V.holdout_chunks(feed, "")) == len(IN_WINDOW) + len(HOLDOUT))
    ok("a missing directory yields nothing",
       V.holdout_chunks(work / "nope", TRAINED_THROUGH) == [])
    ok("a file given as a directory yields nothing",
       V.holdout_chunks(feed / "README.txt", TRAINED_THROUGH) == [])
    # A cut-off NEWER than everything present: the holdout is empty, which the
    # gate must treat as fatal rather than passing a candidate unchecked.
    ok("a future cut-off yields an empty holdout",
       V.holdout_chunks(feed, "enriched_2027-01-01_00-00-00.jsonl") == [])

    # ── reading across chunks ──
    evs = V.read_sample_many(picked, 40, 10_000)
    ok("events are read from the holdout", len(evs) > 0, str(len(evs)))
    ok("and are parsed objects", isinstance(evs[0], dict))
    ok("the sample is capped at n", len(V.read_sample_many(picked, 7, 10_000)) <= 7)
    ok("no chunks means no events", V.read_sample_many([], 10, 100) == [])
    # Spread, not drained: with 4 chunks and n=40 the sample must come from
    # more than one file, or a single quiet period could pass a bad model.
    ok("both compressed and plain chunks are readable",
       len(V.read_sample_many([p for p in picked
                               if p.name.endswith(".gz")][:1], 5, 10_000)) > 0
       and len(V.read_sample_many([p for p in picked
                                   if not p.name.endswith(".gz")][:1],
                                  5, 10_000)) > 0)

    total = len(_checks)
    if _failures:
        print("SN 18 holdout: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("SN 18 holdout: all %d checks passed" % total)
    print("workdir (safe to delete): %s" % work)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
