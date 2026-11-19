#!/usr/bin/env python3
"""The engine must refuse to be the second engine (HA phase 1.3).

WHY THIS MATTERS MORE THAN IT LOOKS

Nothing stopped two engines running. The failure is not a noisy log — it is
silent: two engines update the same entity's profile, risk history and device
trail, and the loser's writes are simply lost. Nobody notices until a baseline
is wrong.

Kafka does not prevent it, which is the counter-intuitive part. Partition
assignment means each EVENT is handled by exactly one consumer, so two engines
would not double-score a single event. But the enriched topic is partitioned
by SOURCE IP, not by entity, and about 12% of its messages carry no key at all
and spread round-robin — so one entity's events land on several partitions and
two engines race on that entity's state.

The tests below exercise the lock across REAL PROCESSES. A same-process second
acquire succeeds by design (flock is per open-file-description), so a test that
called the function twice in one process would pass while proving nothing.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))


_CHILD = textwrap.dedent('''
    import sys, importlib.util
    sys.path.insert(0, {root!r})
    spec = importlib.util.spec_from_file_location("eng", {mod!r})
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    ok, holder = m.acquire_single_instance({lock!r})
    print("OK=%s" % ok, flush=True)
    print("HOLDER=%s" % holder.replace("\\n", " "), flush=True)
    {extra}
''')


def _run_child(lock, extra="", keep=False):
    """Acquire the lock in a separate process and report what it saw."""
    code = _CHILD.format(root=str(ROOT), mod=str(ROOT / "ueba_engine.py"),
                         lock=lock, extra=extra)
    return subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True, timeout=120)


def main() -> int:
    import ueba_engine as E

    ok("the guard exists", hasattr(E, "acquire_single_instance"))
    if not hasattr(E, "acquire_single_instance"):
        print("single instance: guard missing")
        return 1

    with tempfile.TemporaryDirectory() as td:
        lock = os.path.join(td, "sub", "engine.lock")

        # ── 1. the first engine wins, and the directory is created ─────────
        got, _ = E.acquire_single_instance(lock)
        ok("the first engine acquires the lock", got)
        ok("the lock directory is created if absent", os.path.exists(lock))

        # ── 2. a SECOND PROCESS is refused ─────────────────────────────────
        r = _run_child(lock)
        out = r.stdout
        ok("a second process is refused", "OK=False" in out,
           "stdout=%r stderr=%r" % (out[:200], r.stderr[-200:]))
        ok("and it is told who holds the lock",
           "pid=" in out and "host=" in out,
           "an operator needs to know which process to look at; got %r"
           % out[:160])
        ok("the holder record names this process",
           ("pid=%d" % os.getpid()) in out,
           "got %r" % out[:160])

        # ── 3. the refusal does NOT damage the holder's record ─────────────
        # Opened "a+" rather than "w" precisely so a refused start cannot
        # truncate the running engine's details before discovering it is not
        # allowed to have the lock.
        with open(lock) as fh:
            body = fh.read()
        ok("a refused attempt leaves the holder's record intact",
           ("pid=%d" % os.getpid()) in body, "lock file now reads %r" % body)

        # ── 4. the lock is released when the holder DIES, not just exits ───
        # This is the whole reason for flock over a pidfile. The engine was
        # SIGKILLed on 15-Nov (OOM, exit -9); a pidfile would have been left
        # behind claiming a pid that no longer existed, and the next start
        # would have had to guess whether it was stale.
        lock2 = os.path.join(td, "k.lock")
        holder = subprocess.Popen(
            [sys.executable, "-c", _CHILD.format(
                root=str(ROOT), mod=str(ROOT / "ueba_engine.py"), lock=lock2,
                extra="import time; time.sleep(60)")],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        # Read until the marker. The first line on stdout is an import-time
        # logging warning about an optional dependency, not our output, and a
        # bare readline() picks that up and reports a false failure.
        line = ""
        for _ in range(40):
            line = holder.stdout.readline()
            if not line or line.startswith("OK="):
                break
        ok("a child process can take the lock", "OK=True" in line, repr(line))

        r2 = _run_child(lock2)
        ok("while that child lives, a third process is refused",
           "OK=False" in r2.stdout, r2.stdout[:160])

        holder.kill()               # SIGKILL — no cleanup runs
        holder.wait(timeout=30)

        r3 = _run_child(lock2)
        ok("after the holder is SIGKILLed the lock is free again",
           "OK=True" in r3.stdout,
           "a pidfile would have been left stale here; got %r" % r3.stdout[:160])

    # ── 5. the guard is wired into startup, not merely defined ─────────────
    src = (ROOT / "ueba_engine.py").read_text()
    ok("main() calls the guard", "acquire_single_instance(lock_path)" in src,
       "the predicate exists but nothing calls it")
    i_guard = src.find("ok, holder = acquire_single_instance")
    i_engine = src.find("engine = UEBAEngine(")
    ok("the guard runs BEFORE the engine is constructed",
       i_guard != -1 and i_engine != -1 and i_guard < i_engine,
       "a rejected start must not have opened any store first")
    ok("a refused start exits non-zero",
       "sys.exit(3)" in src,
       "systemd must see a failure, not a clean exit it will not retry")

    total = len(_checks)
    if _failures:
        print("single instance: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
        return 1
    print("single instance: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
