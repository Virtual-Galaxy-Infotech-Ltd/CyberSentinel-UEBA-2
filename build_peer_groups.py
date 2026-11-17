#!/usr/bin/env python3
"""
build_peer_groups.py
────────────────────
Publish the peer-group assignment for RFP SN 42.

Runs offline, beside the weekly retrain, because clustering is O(n·k) over
every entity's profile and has no business on the event path. The engine only
reads the file this writes, mtime-reloaded, so a rebuild takes effect without a
restart.

Where the profiles come from
────────────────────────────
entity_presence, which is built from ALL traffic rather than from alerts. That
distinction matters here more than anywhere else: a peer group drawn from
alerts would describe how accounts MISBEHAVE, not what they normally do, and at
a 0.03% alert rate most accounts would have no profile at all. The rows used
are the ones that describe what an entity touches:

    kind='agent'        the hosts it has been seen on
    kind='application'  the programs it has run
    kind='asset'        the tagged assets it has accessed

Why the alert file is also read
───────────────────────────────
To tell an employee from an attacker. Measured on the local sample, 103 of 135
accounts with any activity are SSH brute-force username guesses, and they
behave identically to one another — clustered naively they form one cohort of
over a hundred "peers", none of them a person. The decisive signal is the
source address: an account seen only from public addresses is an external
actor whatever name it presents, which is the same rule ueba_preprocessor's
typed-entity classifier uses. With identity_resolution.typed_keys ON the entity
key already carries the class and this scan is skipped.

Usage
─────
    python3 build_peer_groups.py --config ueba_config.yaml
    python3 build_peer_groups.py --config ueba_config.yaml --dry-run
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ueba_peers  # noqa: E402

# The presence kinds that describe what an entity touches. country and privop
# are deliberately excluded: the first describes where it was, not what it did,
# and the second is a count rather than a distribution over assets.
PROFILE_KINDS = ("agent", "application", "asset")


def resolve(base: Path, p) -> Path:
    q = Path(str(p))
    return q if q.is_absolute() else (base / q)


def load_profiles(db_path) -> dict:
    """{entity: {asset: count}} from entity_presence."""
    prof: dict = collections.defaultdict(dict)
    if not Path(db_path).exists():
        return {}
    conn = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True, timeout=20.0)
    try:
        marks = ",".join("?" * len(PROFILE_KINDS))
        for user, kind, value, events in conn.execute(
                "SELECT username, kind, value, events FROM entity_presence "
                "WHERE kind IN (%s)" % marks, PROFILE_KINDS):
            if not user or not value:
                continue
            # Namespaced by kind so a host and an application that happen to
            # share a name stay distinct dimensions of the profile.
            prof[user]["%s:%s" % (kind, str(value).casefold())] = int(events or 0)
    except sqlite3.Error as e:
        print("  ! could not read entity_presence: %s" % e)
        return {}
    finally:
        conn.close()
    return dict(prof)


def _public(addr) -> bool:
    try:
        return not ipaddress.ip_address(str(addr).strip()).is_private
    except ValueError:
        return False


def _get(d, path):
    cur = d
    for k in str(path).split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def classify_from_alerts(alerts_path, entities) -> dict:
    """{entity: class} for the entities we hold, from the alert file.

    Only the source address is used, because it is the only signal in this feed
    that separates an employee from an attacker presenting a username. An
    account seen exclusively from public addresses is external; one seen from
    any private address is treated as a person, because a genuine employee's
    traffic always carries one.
    """
    out: dict = {}
    p = Path(alerts_path)
    if not p.exists():
        return out

    wanted = {str(e).casefold() for e in entities}
    srcs: dict = collections.defaultdict(set)
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    a = json.loads(line)
                except Exception:
                    continue
                u = (_get(a, "subject.name") or _get(a, "data.srcuser")
                     or _get(a, "data.dstuser"))
                if not u:
                    continue
                key = str(u).strip().casefold()
                if key not in wanted:
                    continue
                ip = _get(a, "subject.ip") or _get(a, "data.srcip")
                if ip:
                    srcs[key].add(str(ip))
    except OSError as e:
        print("  ! could not read the alert file: %s" % e)
        return out

    for ent in entities:
        key = str(ent).casefold()
        ips = srcs.get(key) or set()
        low = key
        if ips and all(_public(i) for i in ips):
            out[ent] = "external"
        elif (low.endswith("$") or low.startswith(("nt authority", "nt service"))
              or low in ("system", "local service", "network service",
                         "local system", "localsystem")):
            out[ent] = "service"
        elif low in ("root", "admin", "administrator", "guest"):
            out[ent] = "shared"
        else:
            out[ent] = "person"
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be published and write nothing")
    args = ap.parse_args()

    import yaml
    cfg_path = Path(args.config).resolve()
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    base = cfg_path.parent
    paths = cfg.get("paths") or {}
    pcfg = (cfg.get("detection") or {}).get("peers") or {}

    db = resolve(base, paths.get("profile_db") or "profiles/user_profiles.db")
    out_path = resolve(base, paths.get("peer_groups_file")
                       or "profiles/peer_groups.json")
    reg_path = paths.get("peer_cohorts_file") or ""
    alerts = resolve(base, paths.get("alerts_file") or "ueba_alerts.jsonl")
    typed = bool(((cfg.get("identity_resolution") or {}).get("typed_keys")))

    print("peer group build")
    print("  profiles  <- %s" % db)
    print("  assignment-> %s" % out_path)
    print("  typed keys : %s" % ("on" if typed else "off"))

    profiles = load_profiles(db)
    if not profiles:
        print("  ! no profiles found. entity_presence is empty or the database "
              "is missing, so there is nothing to cluster. This is expected "
              "before the engine has processed traffic.")
        return 1
    print("  entities with a profile: %d" % len(profiles))

    classes: dict = {}
    if typed:
        print("  classification: from the typed entity key")
    else:
        classes = classify_from_alerts(alerts, list(profiles))
        tally = collections.Counter(classes.values())
        print("  classification: from alert source addresses %s" % dict(tally))
        if not classes:
            print("  ! WARNING: typed_keys is off AND the alert file could not "
                  "be read, so external actors cannot be told from employees. "
                  "Clustering would group attack usernames as peers. Refusing "
                  "to publish — enable identity_resolution.typed_keys or make "
                  "the alert file readable.")
            return 1

    operator = {}
    if reg_path:
        rp = resolve(base, reg_path)
        try:
            raw = json.loads(Path(rp).read_text(encoding="utf-8") or "{}")
            operator = (raw.get("cohorts") if isinstance(raw, dict)
                        and "cohorts" in raw else raw) or {}
            print("  operator cohorts: %d from %s" % (len(operator), rp))
        except Exception:
            print("  operator cohorts: none (%s not readable)" % rp)

    asg = ueba_peers.build_cohorts(
        profiles, classes=classes, operator=operator,
        min_size=int(pcfg.get("min_size") or ueba_peers.DEFAULT_MIN_SIZE),
        min_events=int(pcfg.get("min_events") or ueba_peers.DEFAULT_MIN_EVENTS),
        max_distance=float(pcfg.get("max_distance")
                           or ueba_peers.DEFAULT_MAX_DISTANCE),
        max_entities=int(pcfg.get("max_entities")
                         or ueba_peers.DEFAULT_MAX_ENTITIES),
        use_directory=bool(pcfg.get("use_directory", True)))

    st = asg["stats"]
    print()
    for k in ("entities_seen", "eligible", "excluded_not_person",
              "excluded_sparse", "excluded_flat", "truncated", "placed",
              "unplaced", "cohorts"):
        print("  %-22s %s" % (k, st.get(k)))
    print("  %-22s %s" % ("by_source", st.get("by_source")))
    print()
    for name, c in sorted(asg["cohorts"].items(), key=lambda kv: -kv[1]["size"]):
        print("  %-30s size=%-4d src=%-10s mean=%.3f sd=%.3f"
              % (name[:30], c["size"], c["source"], c["mean_distance"],
                 c["distance_sd"]))

    # A build that places nobody is not an error, but it must not silently
    # replace a good assignment with an empty one.
    if not asg["cohorts"]:
        print("\n  ! no cohort met the minimum size. Nothing is published, so "
              "the previous assignment stays in place.")
        return 0

    placed = [m for m in asg["members"]
              if classes.get(m, "person") != "person"]
    if placed:
        print("\n  ! REFUSING TO PUBLISH: %d non-person entities were placed "
              "in a cohort (%s). That is the guard this build exists for."
              % (len(placed), placed[:5]))
        return 1

    if args.dry_run:
        print("\n  dry run: nothing written")
        return 0

    # A feed whose entities each touched one thing cannot support peer
    # grouping, and that is worth saying out loud rather than publishing a
    # handful of cohorts that look like a result. Measured 17-Nov-2026: 613 of
    # 674 entities had a single-key profile, 571 of them the same key.
    _flat = int(st.get("excluded_flat") or 0)
    _seen = max(int(st.get("entities_seen") or 0), 1)
    if _flat and _flat * 100 // _seen >= 50:
        print()
        print("  ! %d of %d entities (%d%%) touched too few distinct things to "
              "have a comparable profile." % (_flat, _seen, _flat * 100 // _seen))
        print("    Peer grouping needs BREADTH, not volume: an entity seen only "
              "on one host is at distance 0 from")
        print("    every other entity seen only on that host, which is a fact "
              "about the host and not a peer group.")
        print("    Widening what the feed records per entity — applications, "
              "assets, not just the agent — is what")
        print("    makes SN 42 meaningful here. The cohorts below are built "
              "from the %d entities that remain." % int(st.get("eligible") or 0))

    ueba_peers.save(out_path, asg)
    print("\n  wrote %s (%d cohorts, %d members)"
          % (out_path, len(asg["cohorts"]), len(asg["members"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
