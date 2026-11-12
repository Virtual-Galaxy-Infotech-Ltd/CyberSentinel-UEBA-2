#!/usr/bin/env python3
"""Model coverage, measured — RFP SN 18, sprint story 2.1 sub-points 4 and 9.

Sub-point 4 asks for a coverage baseline and sub-point 9 for the figure
ACHIEVED, "not the figure intended". So this measures what is on disk against
what is tracked, and reports two numbers rather than one:

  by entity count   — how many of the tracked entities have a model of their
                      own. Dominated by the long tail, most of which will
                      never qualify and should not.
  by event volume   — how much of the actual traffic is judged by a dedicated
                      model. This is the number that describes detection
                      quality; the entity count flatters or damns it depending
                      only on how many one-event entities the store holds.

Reporting only the first would have said 0.22% on the day the second said
34.69%, and neither alone is the answer.

Run it after every retrain. It takes a config so it can be pointed at a
staging install rather than only the live one.
"""
from __future__ import annotations

import argparse
import collections
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

try:
    import ueba_model_tiers as T
except Exception:
    T = None
try:
    import ueba_peers
except Exception:
    ueba_peers = None


def _abs(base: str, p: str) -> str:
    return p if os.path.isabs(p) else os.path.join(base, p)


def measure(cfg_path: str) -> dict:
    cfg = yaml.safe_load(open(cfg_path))
    base = os.path.dirname(os.path.abspath(cfg_path))
    paths = cfg.get("paths") or {}
    ae_dir = _abs(base, paths.get("autoencoder_dir") or "models/autoencoders/")
    db = _abs(base, paths.get("profile_db") or "profiles/user_profiles.db")
    groups = _abs(base, paths.get("peer_groups_file") or "profiles/peer_groups.json")
    min_ev = int((cfg.get("preprocessing") or {}).get("min_events_per_user", 2000))

    names = {f[:-3] for f in os.listdir(ae_dir) if f.endswith(".pt")}
    entity_models = {n for n in names if n != "global" and not n.startswith("cohort_")}
    cohort_models = {n for n in names if n.startswith("cohort_")}

    assignment = {}
    if ueba_peers is not None and os.path.exists(groups):
        try:
            assignment = ueba_peers.load(groups) or {}
        except Exception:
            assignment = {}
    members = assignment.get("members") or {}

    # Match the way the SCORER matches, not the way a dict does.
    #
    # ueba_peers.cohort_of() falls back to a CASE-INSENSITIVE scan when the
    # exact key misses, because the assignment is built from store keys and
    # the caller may hold a differently-cased spelling. ueba_model_tiers
    # .cohort_for() additionally tries the bare half of a typed key
    # (`person:jane` -> `jane`) and the typed forms of a bare one.
    #
    # A plain `name in members` test misses both. Measured here: it reported
    # `Rahul` as uncovered when the scorer places it in a cohort, because the
    # assignment spells it `rahul`.
    #
    # Replicated as a casefolded set rather than by calling cohort_for() per
    # entity: that function rescans all members on every miss, so across
    # 184k entities it is quadratic and had to be backgrounded. Same answer,
    # one pass.
    member_keys = set()
    for k in members:
        ks = str(k)
        member_keys.add(ks.casefold())
        if ":" in ks:
            prefix, bare = ks.split(":", 1)
            if prefix in ("person", "user", "entity") and bare:
                member_keys.add(bare.casefold())

    # Read-only, with a busy timeout: the engine writes to this store and it is
    # not in WAL mode, so a plain connect loses the race under load and would
    # report a coverage of zero rather than failing.
    cx = sqlite3.connect("file:%s?mode=ro" % db, uri=True, timeout=30)

    tier = collections.Counter()
    events = collections.Counter()
    eligible = 0
    for name, n in cx.execute("SELECT username, total_events FROM users"):
        n = int(n or 0)
        if n >= min_ev:
            eligible += 1
        safe = T.safe_model_name(name) if T is not None else name
        if safe in entity_models:
            t = "entity"
        elif str(name).casefold() in member_keys and cohort_models:
            t = "cohort"
        else:
            t = "global"
        tier[t] += 1
        events[t] += n

    # What the NEXT retrain should deliver, assuming it builds a model for
    # every cohort that has one. Reported separately and labelled, because
    # sub-point 9 is explicit that the achieved figure is the one that counts.
    proj = collections.Counter()
    proj_ev = collections.Counter()
    for name, n in cx.execute("SELECT username, total_events FROM users"):
        n = int(n or 0)
        safe = T.safe_model_name(name) if T is not None else name
        if safe in entity_models:
            t = "entity"
        elif str(name).casefold() in member_keys:
            t = "cohort"
        else:
            t = "global"
        proj[t] += 1
        proj_ev[t] += n

    tracked = sum(tier.values())
    # The name set is built ONCE. Written as a comprehension inside the
    # membership test it re-ran the whole 184k-row query per cohort member,
    # which turned a two-second report into minutes.
    known = {r[0] for r in cx.execute("SELECT username FROM users")}
    known_cf = {str(x).casefold() for x in known}
    unmatched = [k for k in members if str(k).casefold() not in known_cf]

    return {
        "entity_models": len(entity_models),
        "cohort_models": len(cohort_models),
        "has_global": "global" in names,
        "tracked": tracked,
        "eligible": eligible,
        "min_events": min_ev,
        "members": len(members),
        "cohorts": len(assignment.get("cohorts") or {}),
        "unmatched_members": len(unmatched),
        "unmatched_sample": [str(x)[:40] for x in unmatched[:5]],
        "tier": dict(tier),
        "events": dict(events),
        "proj": dict(proj),
        "proj_events": dict(proj_ev),
    }


def report(m: dict) -> str:
    tot = max(m["tracked"], 1)
    tote = max(sum(m["events"].values()), 1)
    out = []
    w = out.append
    w("MODELS ON DISK")
    w("  per-entity : %s" % format(m["entity_models"], ","))
    w("  cohort     : %s" % format(m["cohort_models"], ","))
    w("  global     : %s" % ("present" if m["has_global"] else "MISSING"))
    w("")
    w("ENTITIES")
    w("  tracked                  : %s" % format(m["tracked"], ","))
    w("  eligible (>= %s events)  : %s" % (format(m["min_events"], ","),
                                           format(m["eligible"], ",")))
    w("  placed in a cohort       : %s in %s cohorts" % (format(m["members"], ","),
                                                         format(m["cohorts"], ",")))
    w("")
    w("COVERAGE ACHIEVED — by entity count")
    for k in ("entity", "cohort", "global"):
        n = m["tier"].get(k, 0)
        w("  %-7s %10s  %6.2f%%" % (k, format(n, ","), 100.0 * n / tot))
    w("")
    w("COVERAGE ACHIEVED — by event volume (the number that describes detection)")
    for k in ("entity", "cohort", "global"):
        n = m["events"].get(k, 0)
        w("  %-7s %14s  %6.2f%%" % (k, format(n, ","), 100.0 * n / tote))
    w("")
    w("PROJECTED after a retrain that builds every cohort model")
    pt = max(sum(m["proj"].values()), 1)
    pe = max(sum(m["proj_events"].values()), 1)
    for k in ("entity", "cohort", "global"):
        w("  %-7s %10s entities %6.2f%%  |  %14s events %6.2f%%" % (
            k, format(m["proj"].get(k, 0), ","), 100.0 * m["proj"].get(k, 0) / pt,
            format(m["proj_events"].get(k, 0), ","),
            100.0 * m["proj_events"].get(k, 0) / pe))
    if m["unmatched_members"]:
        w("")
        w("WARNING: %s of %s cohort members are not in the profile store at all."
          % (format(m["unmatched_members"], ","), format(m["members"], ",")))
        w("  examples: %s" % ", ".join(m["unmatched_sample"]))
        w("  Those cohort slots can never be filled by a tracked entity. If they")
        w("  are address-shaped, peer grouping is clustering over addresses")
        w("  rather than people, which SN 42 warns against: a wide enough")
        w("  address cohort makes every attacker a peer of every other.")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure UEBA model coverage (SN 18)")
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--out", default=None, help="also write the report here")
    a = ap.parse_args()
    text = report(measure(a.config))
    print(text)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(text + "\n")
        print("\nwritten to %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
