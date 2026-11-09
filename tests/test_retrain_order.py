#!/usr/bin/env python3
"""The weekly retrain's steps have to happen in an order, and one pair matters.

WHAT THIS IS ABOUT

Cohort training (RFP SN 18) reads profiles/peer_groups.json to decide which
quiet entities share a model. build_peer_groups.py writes that file. If the
builder runs AFTER the trainer, the trainer reads last week's assignment — or,
the first time, none at all — and silently trains no cohort models.

That is what happened. On the 08-Nov-2026 run the trainer looked at 05:37:28
and logged "No peer-group assignment — every sparse entity falls back to the
global model"; the builder wrote the file at 06:21:40. Forty-four minutes, one
line in a log that reads like information rather than failure, and zero cohort
models on disk for as long as the pipeline had existed.

Nothing could have caught that from the Python side: both programs were
correct. The defect lived in the order two lines of shell invoked them. So
this test reads the shell.

It also pins the surrounding order, because the reason the builder sat late
was a real one — it was placed after the engine restart so the engine would
reload the assignment without a second restart. The fix keeps that property
by moving the builder to just before the trainer, while the engine is already
stopped. If someone later moves it back out of the stop/restart window to
"fix" something, these checks say why they should not.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()

SCRIPT = ROOT / "ueba_weekly_retrain.sh"

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


def first_line(text: str, pattern: str):
    """1-based line number of the first match, or None."""
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(pattern, line):
            return i
    return None


def main() -> int:
    if not SCRIPT.exists():
        print("retrain order: SKIP — %s not found" % SCRIPT)
        return 0
    s = SCRIPT.read_text()

    peers   = first_line(s, r'build_peer_groups\.py"?\s*$|"\$PEER_TOOL"')
    # The INVOCATION, not the first mention: this file's header paragraph
    # names retrain.py on line 8, and matching that put the trainer "before"
    # everything and made the real assertion unfalsifiable.
    trainer = first_line(s, r'"\$VENV_PY"\s+retrain\.py')
    stop    = first_line(s, r'systemctl stop "\$\{ENGINE_UNIT\}"')
    start   = first_line(s, r'systemctl start "\$\{ENGINE_UNIT\}"|# ── 5\. Restart engine')

    ok("the script invokes build_peer_groups.py", peers is not None)
    ok("the script invokes retrain.py", trainer is not None)
    ok("the script stops the engine", stop is not None)
    ok("the script restarts the engine", start is not None)

    if peers and trainer:
        ok("peer groups are rebuilt BEFORE the trainer runs",
           peers < trainer,
           "build_peer_groups at line %s, retrain.py at line %s — the trainer "
           "will read a stale or absent assignment and train no cohort models"
           % (peers, trainer))

    # The builder reads entity_presence, which the engine writes. Running it
    # while the engine is down means it is not clustering a moving target.
    if peers and stop and start:
        ok("peer groups are rebuilt while the engine is stopped",
           stop < peers < start,
           "stop=%s peers=%s start=%s" % (stop, peers, start))

    # The original placement's benefit, kept: the engine restart comes after
    # the rebuild, so it loads the new assignment without a second restart.
    if peers and start:
        ok("the engine restart still follows the rebuild, so no second "
           "restart is needed to load the assignment",
           peers < start, "peers=%s start=%s" % (peers, start))

    # A failure here must not fail the retrain or leave the engine down.
    block = ""
    m = re.search(r'PEER_TOOL="\$BASE/build_peer_groups\.py".*?\nfi\n', s, re.S)
    if m:
        block = m.group(0)
    ok("the peer-group step is non-fatal", bool(block) and "WARNING" in block,
       "a clustering failure must not mark the retrain failed")
    ok("the peer-group step does not exit on failure",
       bool(block) and not re.search(r'\bexit\s+[1-9]', block))

    # The comment has to carry the reason, or the next person moves it back.
    ok("the step records why the order matters",
       "cohort" in s.lower() and "05:37" in s,
       "the measured evidence should stay next to the code it explains")

    total = len(_checks)
    if _failures:
        print("retrain order: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("retrain order: all %d checks passed" % total)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
