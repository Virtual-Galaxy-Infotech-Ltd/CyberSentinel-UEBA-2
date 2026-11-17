#!/usr/bin/env python3
"""An address is not a person, whichever address it was seen from (SN 42).

WHAT THIS IS ABOUT

ueba_peers has carried an EXCLUDED_PREFIXES list since it was written, and
"ip:" has always been in it. is_groupable() implements it correctly. But the
call site put that check in an `elif`:

    cls = classes.get(key)
    if cls:
        if cls != "person": ...exclude...
    elif not is_groupable(ent):        # only when cls is EMPTY
        ...exclude...

classify_from_alerts() calls anything seen from a private address a "person",
and every internal address is private. So an entity literally named
`ip:192.168.2.19` was classified person, took the first branch, and never
reached is_groupable() at all. The exclusion list was unreachable for exactly
the entities it names.

Measured on the live store: 4,656 of 4,965 cohort members were IP addresses,
and ONE behavioural cohort held 3,166 of them. SN 42 warns about this
directly — a cohort drawn that wide over addresses makes every attacker a
behavioural peer of every other.

It also cost a retrain. On 15-Nov-2026 the trainer reached
`ip:192.168.2.19 | events: 23,691,006`, loaded 18,952,805 samples, and the
kernel killed it at 28.9 GB. Six hours of work lost, exit code -9.

The tests below assert on the OUTCOME — who ends up in a cohort — rather than
on is_groupable() in isolation, because is_groupable() was never wrong. Only
its caller was.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

import ueba_peers as P  # noqa: E402

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


def profile(n: int) -> dict:
    """An access profile with enough spread to be clusterable."""
    return {"agent:host-a": n, "agent:host-b": n // 2,
            "application:chrome.exe": n // 3, "asset:share-1": n // 4}


def build(entities, classes=None, **kw):
    profiles = {e: profile(120) for e in entities}
    return P.build_cohorts(profiles, classes=classes or {}, operator={},
                           min_size=kw.get("min_size", 2),
                           min_events=kw.get("min_events", 20),
                           max_distance=kw.get("max_distance", 0.9),
                           max_entities=kw.get("max_entities", 10000),
                           use_directory=kw.get("use_directory", False))


def main() -> int:
    PEOPLE = ["rahul", "priya", "arjun", "meera", "vikram", "anita"]
    ADDRS = ["ip:192.168.2.19", "ip:10.200.11.74", "ip:103.252.168.197"]
    HOSTS = ["host:kafka-prajwal", "host:RootSeeker"]

    # ── 1. the defect itself: the classifier must not rescue an address ──
    # This is the exact shape that was live. Every entity is classified
    # "person" because every one of them was seen from a private address.
    classes = {e.casefold(): "person" for e in PEOPLE + ADDRS + HOSTS}
    asg = build(PEOPLE + ADDRS + HOSTS, classes=classes)
    members = set(asg.get("members") or {})

    for a in ADDRS:
        ok("an address classified 'person' is still excluded: %s" % a,
           a not in members,
           "%s reached a cohort; the classifier overrode its kind" % a)
    for h in HOSTS:
        ok("a host classified 'person' is still excluded: %s" % h,
           h not in members, "%s reached a cohort" % h)

    ok("real people are still grouped",
       len([m for m in members if m in PEOPLE]) >= 2,
       "members=%s — the fix must not empty the cohorts it exists to build"
       % sorted(members))

    ok("no cohort member is address-shaped",
       not [m for m in members if str(m).startswith(("ip:", "host:"))],
       "leaked %s" % sorted(m for m in members
                            if str(m).startswith(("ip:", "host:"))))

    # ── 2. the classifier can still EXCLUDE, it just cannot promote ──
    # An account seen only from public addresses is an external actor. That
    # judgement still has to hold: the fix narrows what the classifier can
    # rescue, not what it can reject.
    classes2 = {e.casefold(): "person" for e in PEOPLE}
    classes2["rahul"] = "external"
    asg2 = build(PEOPLE, classes=classes2)
    m2 = set(asg2.get("members") or {})
    ok("an account classified external is excluded", "rahul" not in m2)
    ok("and the others are unaffected", len(m2) >= 2, sorted(m2))

    # ── 3. unclassified entities keep the old behaviour ──
    # is_groupable() returns True for an untyped key on purpose — the caller
    # adjudicates. A bare name with no classification must still be grouped,
    # or this fix would quietly empty every cohort at a site whose alert file
    # cannot be read.
    asg3 = build(PEOPLE, classes={})
    ok("bare names with no classification are still grouped",
       len(set(asg3.get("members") or {})) >= 2,
       "members=%s" % sorted(asg3.get("members") or {}))

    # ── 4. the reason is recorded, not silently dropped ──
    unplaced = asg.get("unplaced") or {}
    ok("an excluded address says why",
       "not groupable" in str(unplaced.get("ip:192.168.2.19", "")).lower(),
       "unplaced reason: %r" % unplaced.get("ip:192.168.2.19"))
    ok("the exclusion is counted in stats",
       int((asg.get("stats") or {}).get("excluded_not_person", 0)) >= len(ADDRS),
       "stats=%s" % (asg.get("stats") or {}))

    # ── 5. structural pin: kind is checked BEFORE the classifier ──
    # A behavioural test cannot see ordering if both checks happen to exclude
    # the same entity. This pins the order itself, because the defect was the
    # order and nothing else.
    src = (ROOT / "ueba_peers.py").read_text()
    i_kind = src.find("if not is_groupable(ent):")
    i_cls = src.find("cls = classes.get(key)")
    ok("is_groupable is consulted before the classifier",
       i_kind != -1 and i_cls != -1 and i_kind < i_cls,
       "is_groupable at %d, classes lookup at %d" % (i_kind, i_cls))
    ok("the kind check is no longer an elif branch",
       "elif not is_groupable(ent):" not in src,
       "the check is reachable only when the classifier is silent")

    # ── 5b. a point is not a distribution ────────────────────────────────
    # Entities that touched exactly ONE thing sit at distance 0 from every
    # other entity that touched that same thing, so they cluster perfectly
    # and say nothing. On the live store this produced a 567-member cohort at
    # mean 0.000, sd 0.000 — "everyone who appeared on host X", which is a
    # fact about the host and not a peer group.
    flatprof = {("flat%d" % i): {"agent:host-a": 300} for i in range(8)}
    rich = {("rich%d" % i): {"agent:host-a": 300, "agent:host-b": 150,
                             "application:chrome.exe": 90} for i in range(4)}
    both = dict(flatprof); both.update(rich)
    asg5 = P.build_cohorts(both, classes={}, operator={}, min_size=2,
                           min_events=20, max_distance=0.9,
                           max_entities=10000, use_directory=False)
    m5 = set(asg5.get("members") or {})
    ok("single-dimension entities are not clustered",
       not [x for x in m5 if str(x).startswith("flat")],
       "clustered %s — a point mass has nothing to compare"
       % sorted(x for x in m5 if str(x).startswith("flat")))
    ok("entities with a real distribution still are",
       len([x for x in m5 if str(x).startswith("rich")]) >= 2,
       "members=%s — the guard must not empty the cohorts it exists to build"
       % sorted(m5))
    ok("and the exclusion is counted separately from sparse",
       int((asg5.get("stats") or {}).get("excluded_flat", 0)) >= 8,
       "stats=%s" % (asg5.get("stats") or {}))
    ok("the reason names the dimension count",
       "distinct access" in str((asg5.get("unplaced") or {}).get("flat0", "")),
       "unplaced=%r" % (asg5.get("unplaced") or {}).get("flat0"))

    # Opt-out must work: a site whose feed is genuinely one-dimensional can
    # set it to 1 and get the old behaviour rather than empty cohorts.
    asg6 = P.build_cohorts(flatprof, classes={}, operator={}, min_size=2,
                           min_events=20, max_distance=0.9, max_entities=10000,
                           use_directory=False, min_dimensions=1)
    ok("min_dimensions=1 restores the old behaviour",
       len(set(asg6.get("members") or {})) >= 2,
       "the guard must be switchable, not absolute")

    # ── 6. the prefixes that make the guard mean anything ──
    for pfx in ("ip:", "host:", "external:", "service:"):
        ok("EXCLUDED_PREFIXES still contains %r" % pfx,
           pfx in P.EXCLUDED_PREFIXES)

    total = len(_checks)
    if _failures:
        print("peer entity kinds: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("peer entity kinds: all %d checks passed" % total)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
