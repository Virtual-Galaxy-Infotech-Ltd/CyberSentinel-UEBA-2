#!/usr/bin/env python3
"""One host, one role — whichever code path asks.

WHAT THIS IS ABOUT

classify_host() decides whether a machine is a server or an endpoint. Its
owner rule — "named after the person who signs in to it" — needs the ACCOUNTS
seen on the host. Pass only the count and a product token decides alone.

Three call paths asked the same question and two of them left the accounts
out, so on 09-Nov-2026 the live console said:

    device page            -> endpoint  ("named after prajwal, who signs in")
    /api/entities/classify -> server    ("name contains 'kafka'")
    entity profiles        -> server    ("name contains 'kafka'")

The existing suites all passed, because every one of them called
classify_host DIRECTLY with the full argument list. Nothing tested the
callers. That is the hole this file closes: it asserts on the call paths, and
it asserts they agree with each other rather than each being separately
"correct" against its own expectation.
"""
from __future__ import annotations

import inspect
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

import ueba_entities as EN  # noqa: E402

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


# The real estate, with the accounts actually observed on each host. Same
# fixtures the ueba_entities selftest pins, reused deliberately: if these
# drift apart the two files stop describing the same machine.
PRAJWAL = ["virtu", "virtualprajwal2025@example.invalid"]

CASES = [
    # (host,            accounts,  os_family, expected_role, note)
    ("kafka-prajwal",   PRAJWAL,   "windows", "endpoint",
     "product token loses to the owner's name"),
    ("kafka_prajwal",   PRAJWAL,   "windows", "endpoint",
     "underscore spelling is the same machine"),
    ("MDM_ServerAnsh",  ["ansh"],  "windows", "endpoint",
     "spelled-out 'server' is a weak token, not proof"),
    ("FixedWindows_VM", ["asus"],  "windows", "endpoint",
     "'vm' is not a role"),
    ("DC_ATM_SRV",      [],        "windows", "server",
     "strong tokens still decide on their own"),
    ("Access-SRV-2.140", [],       "windows", "server",
     "'srv' is strong"),
]


def main() -> int:
    # ── 1. the reference: classify_host with everything it needs ──────────
    for host, accounts, fam, want, note in CASES:
        got = EN.classify_host(host, None, len(accounts), fam, 0.93,
                               accounts, ())["role"]
        ok("classify_host: %s -> %s (%s)" % (host, want, note),
           got == want, "got %r" % got)

    # ── 2. extract() must reach the SAME verdict ──────────────────────────
    # This is the path that was wrong. extract() is what the engine and the
    # entity profiles use, so if it disagrees with classify_host the console
    # contradicts itself.
    for host, accounts, fam, want, note in CASES:
        ents = EN.extract({"host": {"name": host}}, None, len(accounts),
                          None, accounts, (), fam, 0.93)
        hosts = [e for e in ents if e.get("field") == "host.name"]
        got = hosts[0]["kind"] if hosts else None
        ok("extract(): %s -> %s" % (host, want), got == want, "got %r" % got)

    # ── 3. the two paths agree, host by host ──────────────────────────────
    # Asserted as EQUALITY rather than against a literal, so a future change
    # to the classifier cannot quietly move one path without the other.
    for host, accounts, fam, _want, _note in CASES:
        ref = EN.classify_host(host, None, len(accounts), fam, 0.93,
                               accounts, ())["role"]
        ents = EN.extract({"host": {"name": host}}, None, len(accounts),
                          None, accounts, (), fam, 0.93)
        hosts = [e for e in ents if e.get("field") == "host.name"]
        got = hosts[0]["kind"] if hosts else None
        ok("classify_host and extract() agree on %s" % host, got == ref,
           "extract=%r classify_host=%r" % (got, ref))

    # ── 4. the signature actually accepts them ────────────────────────────
    sig = inspect.signature(EN.extract).parameters
    for p in ("accounts", "roster", "os_family", "os_share"):
        ok("extract() takes %s" % p, p in sig)
    ok("extract() keeps its old positional order",
       list(sig)[:4] == ["log", "reg", "accounts_seen", "guard"],
       str(list(sig)[:4]))

    # ── 5. the defaults must not change behaviour for callers that have
    #      nothing to pass — a third-party caller should not start seeing
    #      different roles because this signature grew.
    noacct = EN.extract({"host": {"name": "DC_ATM_SRV"}})
    hosts = [e for e in noacct if e.get("field") == "host.name"]
    ok("a caller passing no accounts still classifies strong tokens",
       hosts and hosts[0]["kind"] == "server",
       str(hosts[:1]))

    # ── 6. source-level pin: the dashboard must not re-ask with less ──────
    # The classify endpoint used to call classify_host itself, with fewer
    # arguments, two lines after _device_role had already answered properly.
    # A behavioural test cannot see that without a live database, so this
    # pins the structure instead.
    dash = (ROOT / "ueba_dashboard_server.py").read_text()
    direct = re.findall(r"ueba_entities\.classify_host\(", dash)
    ok("dashboard calls classify_host in exactly one place",
       len(direct) == 1,
       "%d call sites — every caller should go through _device_verdict()"
       % len(direct))
    ok("the single verdict helper exists", "def _device_verdict(" in dash)
    ok("the classify endpoint uses it", "_device_verdict(host, fam, share)" in dash)

    # ── 7. the engine and the profile builder both supply accounts ────────
    eng = (ROOT / "ueba_engine.py").read_text()
    ok("engine passes accounts to extract()",
       "accounts=_accts" in eng,
       "engine still passes only the count")
    ok("engine sources them from the profile store",
       "accounts_on(host_name)" in eng)
    ok("entity profiles pass accounts to extract()",
       "_acct_map.get(" in dash and "reg, seen, None, accounts" in dash)

    pre = (ROOT / "ueba_preprocessor.py").read_text()
    ok("the profile store can return account NAMES, not just a count",
       "def accounts_on(" in pre)

    total = len(_checks)
    if _failures:
        print("host role consistency: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("host role consistency: all %d checks passed" % total)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
