#!/usr/bin/env python3
"""
ueba_peers.py
─────────────
CyberSentinel UEBA — peer groups built from observed behaviour (RFP SN 42).

  SN 42  Usage deviates from peer group: a user's pattern of activity starts
         deviating from the peer group.

Why this does not need HR data
──────────────────────────────
The tracking sheet had this blocked on department, role and business-unit
attributes from HR or Active Directory. Those make ONE kind of peer group. They
are not the only kind, and they are not the kind this serial most needs.

Splunk UBA builds four kinds — HR groups from AD, organisational-unit groups
from the AD OU tree, BEHAVIOURAL groups formed by clustering similar activity,
and device groups from network activity. Exabeam's dynamic peer analysis is
explicitly behavioural: it computes "distance between user i and user j based
on their historical behaviour data, for example a divergence metric over access
frequency distribution of accessed assets", and a "degree of membership" from
those pairwise distances. Neither vendor treats an HR feed as a prerequisite;
both treat it as one signal among several, and both point out that behavioural
groups find real groupings that AD does not know about.

So this module builds the behavioural kind now and leaves the attribute kind as
a plug: an operator register takes precedence over everything, and the moment
department or role attributes arrive they land there and immediately outrank
the inferred grouping. Nothing else has to change.

Four sources, highest precedence first:

  operator   an explicit cohort in the register — always wins. This is where
             an HR or AD feed lands when one exists.
  directory  the account's own domain or host prefix (DOMAIN\\user), which is a
             weak organisational signal but a real one, and free.
  behaviour  clustered on the access-frequency distribution over the assets the
             entity actually touches. The main source.
  unplaced   too little history, or nothing close enough. Reported as unplaced
             rather than forced into a group — see below.

Three guards, each one earned from measurement
──────────────────────────────────────────────
Measured on 3,412 local alerts, over 134 accounts. Account and domain names in
this file are stand-ins with the same shapes as the real ones; the figures are
from the real sample, the names are not, because this file is committed.

  1. ONLY PERSON-CLASS ENTITIES ARE GROUPED. The SSH brute-force usernames in
     this estate (a long list of plausible first names)
     sit at distance 0.000 from each other, because they are all the same
     attack replayed with different names. Clustered naively they form one
     enormous "peer group" of 100+ members, every one of them an attacker
     rather than an employee, and a real user drifting would then be measured
     against that. External, service and shared entities are excluded.

  2. IDENTITIES MUST BE CANONICALISED FIRST. The same person appears as
     `CORPDOM\\rlal` and `CORPDOM\\\\rlal` — the doubled-backslash spelling —
     and as a bare name elsewhere. Grouping over raw spellings puts a person in
     a cohort with themselves and makes their own behaviour their peer
     baseline, which can never deviate.

  3. A COHORT OF ONE IS NOT A PEER GROUP. Nor is a cohort of two much of one.
     Below min_size an entity is reported unplaced; a confident deviation
     verdict against one other person is not a verdict worth acting on.

Why deviation is scored against the cohort's own spread
───────────────────────────────────────────────────────
A fixed threshold on "distance from the group" would fire constantly for a
genuinely diverse group and never for a tight one. Both are wrong. The score
here is how far out the entity sits RELATIVE TO how spread its own cohort
normally is: the mean and spread of member-to-cohort distances are computed
when the cohort is built, and an entity is deviating when it sits well beyond
that spread.

This also keeps the module clear of the failure that has cost this project two
alert floods — a flat constant applied to a condition that is almost always
true. A deviation here is by construction rare within its own cohort.

Build and read are separate on purpose
──────────────────────────────────────
Building cohorts is O(n·k) over every entity's profile and belongs in a
scheduled job beside the retrain. The engine only READS the published
assignment and does one cheap divergence per event. The assignment is a JSON
register with the same mtime contract as the watch list, so a rebuild takes
effect without a restart.
"""

# Annotations as strings so this imports on 3.9 as well as the server's 3.12.
from __future__ import annotations

import json
import math
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

SOURCES = ("operator", "directory", "behaviour", "unplaced")

# Entity classes this module will group. Anything else is excluded, for the
# reason in guard 1 above.
GROUPABLE_PREFIXES = ("person:",)
EXCLUDED_PREFIXES = ("external:", "service:", "shared:", "endpoint:", "device:",
                     "addr:", "agent:", "name:", "ip:", "host:")

# A cohort smaller than this is not a peer group, and an entity in one is
# reported unplaced instead.
DEFAULT_MIN_SIZE = 4

# An entity with fewer than this many recorded accesses has no profile worth
# clustering: its distribution is dominated by whichever one or two assets it
# happened to touch.
DEFAULT_MIN_EVENTS = 20

# Distinct things an entity must have touched before its profile is a
# DISTRIBUTION rather than a point.
#
# Divergence between two identical point masses is zero whatever they are, so
# entities that touched exactly one thing cluster perfectly with every other
# entity that touched that same one thing — at distance 0.000, sd 0.000. The
# result is not a peer group. It is "everyone who appeared on host X", which
# is a fact about the host, not a behavioural similarity between people.
#
# Measured on the live store, 17-Nov-2026: of 674 entities reaching the
# clusterer, 613 (90.9%) had exactly one key, and 571 of those shared the SAME
# key. That produced a 567-member cohort whose members were indistinguishable
# from one another by construction.
DEFAULT_MIN_DIMENSIONS = 2

# Maximum divergence at which two entities are still considered peers. 0 is
# identical behaviour, 1 is no overlap at all. 0.45 was chosen against the
# local sample: the real users pair at 0.001-0.166 while unrelated accounts sit
# at 1.000, so anything in the middle is a wide margin either way.
DEFAULT_MAX_DISTANCE = 0.45

# How many standard deviations beyond its cohort's normal spread an entity must
# sit before its behaviour is reported as deviating.
DEFAULT_DEVIATION_SIGMA = 2.5

# Hard cap on how many entities one build will cluster. The distance work is
# quadratic in the worst case, and a build that never finishes is worse than a
# build that says it was truncated.
DEFAULT_MAX_ENTITIES = 5000

_lock = threading.Lock()
_cache: dict = {}


# ── profiles and distance ────────────────────────────────────────────────────

def normalise_profile(counts: dict) -> dict:
    """A frequency distribution from raw counts. Empty stays empty."""
    clean = {}
    for k, v in (counts or {}).items():
        key = str(k or "").strip().casefold()
        try:
            n = float(v)
        except (TypeError, ValueError):
            continue
        if key and n > 0:
            clean[key] = clean.get(key, 0.0) + n
    total = sum(clean.values())
    if not total:
        return {}
    return {k: v / total for k, v in clean.items()}


def profile_distance(p: dict, q: dict) -> float:
    """Jensen-Shannon divergence between two distributions, base 2.

    Bounded [0,1] and symmetric, which is what makes a single threshold
    meaningful in both directions — plain KL divergence is neither, and cosine
    over counts lets a busy entity and a quiet one with identical habits look
    far apart.

    Two entities with no asset in common score exactly 1.0.
    """
    if not p or not q:
        return 1.0
    keys = set(p) | set(q)
    m = {k: (p.get(k, 0.0) + q.get(k, 0.0)) / 2.0 for k in keys}

    def kl(x):
        tot = 0.0
        for k in keys:
            xv = x.get(k, 0.0)
            if xv > 0 and m[k] > 0:
                tot += xv * math.log2(xv / m[k])
        return tot

    d = 0.5 * kl(p) + 0.5 * kl(q)
    return max(0.0, min(1.0, d))


def pool(profiles: list) -> dict:
    """The cohort's own distribution: the mean of its members'.

    Averaging the normalised profiles, not summing raw counts, so one very
    busy member cannot become the definition of the group.
    """
    if not profiles:
        return {}
    keys: set = set()
    for p in profiles:
        keys |= set(p)
    n = float(len(profiles))
    return {k: sum(p.get(k, 0.0) for p in profiles) / n for k in keys}


# ── entity eligibility ───────────────────────────────────────────────────────

def is_groupable(entity: str) -> bool:
    """Whether this entity may be placed in a peer group at all.

    Guard 1. With typed keys on, a person is `person:<name>` and everything
    else is explicitly another namespace. With typed keys OFF the key is a bare
    account name, which cannot be told apart from an attacker's guessed
    username — so in that case the caller must supply the class itself, via
    `classes` on build_cohorts.
    """
    e = str(entity or "").strip().casefold()
    if not e or e == "unknown":
        return False
    if any(e.startswith(x) for x in EXCLUDED_PREFIXES):
        return False
    if ":" in e:
        return any(e.startswith(x) for x in GROUPABLE_PREFIXES)
    # Untyped key: cannot be adjudicated here. The caller decides.
    return True


def directory_of(entity: str) -> str:
    """The DOMAIN or HOST prefix of an account, lowercased, or "".

    `CORPDOM\\rlal` -> `corpdom`. A weak organisational signal, but a free one:
    accounts qualified by the same domain are more likely to be colleagues
    than two accounts picked at random.
    """
    e = str(entity or "").strip()
    for pfx in GROUPABLE_PREFIXES:
        if e.casefold().startswith(pfx):
            e = e[len(pfx):]
            break
    # Collapse doubled escapes first — guard 2. Without this, CORPDOM\\rlal and
    # CORPDOM\rlal produce different prefixes for one person.
    while "\\\\" in e:
        e = e.replace("\\\\", "\\")
    head, sep, _ = e.rpartition("\\")
    return head.strip().casefold() if sep else ""


# ── building ────────────────────────────────────────────────────────────────

def build_cohorts(profiles: dict, classes: "dict | None" = None,
                  operator: "dict | None" = None,
                  min_size: int = DEFAULT_MIN_SIZE,
                  min_events: int = DEFAULT_MIN_EVENTS,
                  min_dimensions: int = DEFAULT_MIN_DIMENSIONS,
                  max_distance: float = DEFAULT_MAX_DISTANCE,
                  max_entities: int = DEFAULT_MAX_ENTITIES,
                  use_directory: bool = True) -> dict:
    """Group entities by observed behaviour.

    profiles  {entity: {asset: count}} — raw access counts, from all traffic.
    classes   {entity: "person"|"service"|...} when keys are untyped, so the
              caller's own classification decides eligibility. Guard 1.
    operator  {entity: cohort_name} — explicit assignment, highest precedence.

    Returns the publishable assignment:

      {"built_at", "params", "cohorts": {name: {...}},
       "members": {entity: {"cohort", "source", "membership", "distance"}},
       "unplaced": {entity: reason}, "stats": {...}}

    Leader clustering, not connected components: entities are taken in
    descending activity order, each unassigned one becomes a leader, and other
    unassigned entities within max_distance of THAT LEADER join it. Components
    would chain — A near B, B near C, A nothing like C — and produce a cohort
    whose members are not peers of each other, which is exactly what a peer
    group must not be.
    """
    params = {"min_size": int(min_size), "min_events": int(min_events),
              "min_dimensions": int(min_dimensions),
              "max_distance": float(max_distance),
              "deviation_sigma": DEFAULT_DEVIATION_SIGMA,
              "use_directory": bool(use_directory)}
    out = {"built_at": datetime.now(timezone.utc).isoformat(),
           "params": params, "cohorts": {}, "members": {}, "unplaced": {},
           "stats": {}}

    operator = {str(k).strip().casefold(): str(v).strip()
                for k, v in (operator or {}).items()
                if str(k).strip() and str(v).strip()}
    classes = {str(k).strip().casefold(): str(v or "").strip().casefold()
               for k, v in (classes or {}).items()}

    # ── eligibility ──
    eligible: dict = {}
    excluded = truncated = sparse = flat = 0
    for entity, counts in (profiles or {}).items():
        ent = str(entity or "").strip()
        if not ent:
            continue
        key = ent.casefold()
        # KIND FIRST, and it is not negotiable.
        #
        # This check used to sit in the `elif` below, so it only ran when the
        # classifier had no opinion. classify_from_alerts() calls anything seen
        # from a private address a "person" — which is every internal address —
        # so an entity literally named `ip:192.168.2.19` was classified person,
        # took the first branch, and never reached is_groupable() at all. The
        # EXCLUDED_PREFIXES list has carried "ip:" since it was written; it was
        # simply unreachable for exactly the entities it names.
        #
        # Measured on the live store before this change: 4,656 of 4,965 cohort
        # members were IP addresses, and one behavioural cohort held 3,166 of
        # them. That is the failure SN 42 warns about directly — a cohort drawn
        # wide over addresses makes every attacker a behavioural peer of every
        # other, which is the opposite of what peer deviation is for.
        #
        # The classifier may still EXCLUDE (an account seen only from public
        # addresses is external), but it may never promote something whose kind
        # already disqualifies it. An address is not a person whichever address
        # it was seen from.
        if not is_groupable(ent):
            excluded += 1
            out["unplaced"][ent] = "entity class is not groupable"
            continue
        cls = classes.get(key)
        if cls and cls != "person":
            excluded += 1
            out["unplaced"][ent] = "not a person (%s)" % cls
            continue
        total = sum(float(v) for v in (counts or {}).values()
                    if isinstance(v, (int, float)))
        if total < min_events:
            sparse += 1
            out["unplaced"][ent] = ("only %d recorded accesses, below the %d "
                                    "needed for a profile" % (int(total), min_events))
            continue
        prof = normalise_profile(counts)
        if not prof:
            out["unplaced"][ent] = "no usable access profile"
            continue
        eligible[ent] = {"profile": prof, "events": total}

    order = sorted(eligible, key=lambda e: -eligible[e]["events"])
    if len(order) > max_entities:
        truncated = len(order) - max_entities
        for e in order[max_entities:]:
            out["unplaced"][e] = "build truncated at %d entities" % max_entities
        order = order[:max_entities]

    # ── 1. operator assignment wins ──
    assigned: dict = {}
    groups: dict = {}
    for ent in list(order):
        name = operator.get(ent.casefold())
        if name:
            assigned[ent] = {"cohort": name, "source": "operator"}
            groups.setdefault(name, []).append(ent)

    # ── 2. directory prefix, where there is one and it is big enough ──
    if use_directory:
        by_dir: dict = {}
        for ent in order:
            if ent in assigned:
                continue
            d = directory_of(ent)
            if d:
                by_dir.setdefault(d, []).append(ent)
        for d, members in by_dir.items():
            if len(members) >= min_size:
                name = "dir:%s" % d
                for ent in members:
                    assigned[ent] = {"cohort": name, "source": "directory"}
                    groups.setdefault(name, []).append(ent)

    # ── 3. behavioural leader clustering ──
    #
    # A POINT IS NOT A DISTRIBUTION, and this is the only stage that cares.
    #
    # Divergence between two identical point masses is zero whatever they are,
    # so an entity that touched exactly one thing sits at distance 0.000 from
    # every other entity that touched that same thing. They cluster perfectly
    # and the cohort says nothing: it is "everyone who appeared on host X",
    # which is a fact about the host, not a behavioural similarity.
    #
    # Measured on the live store, 17-Nov-2026: 613 of 674 entities reaching
    # the clusterer had a single-key profile and 571 of those shared the SAME
    # key, producing a 567-member cohort at mean 0.000, sd 0.000.
    #
    # Applied HERE and not at eligibility, because the operator and directory
    # stages above do not use profile distance at all. An operator naming a
    # cohort, or colleagues sharing a domain prefix, is a claim about who they
    # ARE; it does not become wrong because the feed records one thing about
    # them. Excluding them earlier removed the two cohorts on this estate that
    # were actually sound — caught by the directory selftest, which builds its
    # fixture from single-key profiles for exactly that reason.
    flat_members = {e for e in order
                    if len(eligible[e]["profile"]) < min_dimensions}
    flat = len(flat_members)
    for e in flat_members:
        if e not in assigned:
            out["unplaced"][e] = (
                "profile has only %d distinct access(es); %d needed before it "
                "is a distribution rather than a point"
                % (len(eligible[e]["profile"]), int(min_dimensions)))

    for leader in order:
        if leader in assigned or leader in flat_members:
            continue
        lp = eligible[leader]["profile"]
        members = [leader]
        for other in order:
            if other == leader or other in assigned or other in flat_members:
                continue
            if profile_distance(lp, eligible[other]["profile"]) <= max_distance:
                members.append(other)
        if len(members) < min_size:
            continue                      # leave them for the unplaced pass
        name = "beh:%s" % re.sub(r"[^a-z0-9]+", "_",
                                 leader.casefold()).strip("_")[:40]
        for ent in members:
            assigned[ent] = {"cohort": name, "source": "behaviour"}
        groups[name] = members

    # ── 4. finalise each cohort: its pooled profile and its own spread ──
    for name, members in groups.items():
        members = [m for m in members if m in eligible]
        if len(members) < min_size:
            for m in members:
                assigned.pop(m, None)
                out["unplaced"][m] = ("cohort %s had only %d members, below the "
                                      "minimum of %d" % (name, len(members), min_size))
            continue
        profs = [eligible[m]["profile"] for m in members]
        centre = pool(profs)
        dists = [profile_distance(p, centre) for p in profs]
        mean = sum(dists) / len(dists)
        var = sum((d - mean) ** 2 for d in dists) / len(dists)
        sd = math.sqrt(var)
        out["cohorts"][name] = {
            "name": name,
            "source": assigned[members[0]]["source"],
            "size": len(members),
            "members": sorted(members),
            "profile": {k: round(v, 6) for k, v in sorted(
                centre.items(), key=lambda kv: -kv[1])[:100]},
            "mean_distance": round(mean, 6),
            "distance_sd": round(sd, 6),
        }
        for m, d in zip(members, dists):
            out["members"][m] = {
                "cohort": name,
                "source": assigned[m]["source"],
                # Exabeam's "degree of membership": how central this entity is
                # to its own group. A member at the edge should not produce a
                # confident verdict, and this is what lets a caller tell.
                "membership": round(max(0.0, 1.0 - d), 6),
                "distance": round(d, 6),
            }

    for ent in order:
        if ent not in out["members"] and ent not in out["unplaced"]:
            out["unplaced"][ent] = "no cohort of at least %d comparable entities" % min_size

    out["stats"] = {
        "entities_seen": len(profiles or {}),
        "eligible": len(eligible),
        "excluded_not_person": excluded,
        "excluded_sparse": sparse,
        "excluded_flat": flat,
        "truncated": truncated,
        "placed": len(out["members"]),
        "unplaced": len(out["unplaced"]),
        "cohorts": len(out["cohorts"]),
        "by_source": {s: sum(1 for v in out["members"].values()
                             if v["source"] == s)
                      for s in ("operator", "directory", "behaviour")},
    }
    return out


# ── the published assignment ─────────────────────────────────────────────────

def save(path, assignment: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(assignment, indent=1, ensure_ascii=False),
                   encoding="utf-8")
    os.replace(tmp, p)
    with _lock:
        _cache.pop(str(p), None)


def load(path) -> dict:
    """The published assignment, re-read only when the file changes."""
    p = Path(path)
    try:
        st = p.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None
    key = str(p)
    with _lock:
        hit = _cache.get(key)
        if hit and hit["stamp"] == stamp:
            return hit["data"]
    data = {"cohorts": {}, "members": {}, "unplaced": {}, "params": {},
            "stats": {}, "built_at": ""}
    if stamp is not None:
        try:
            raw = json.loads(p.read_text(encoding="utf-8") or "{}")
            if isinstance(raw, dict):
                for k in data:
                    if k in raw:
                        data[k] = raw[k]
        except Exception as ex:
            print("[peers] failed to read %s: %s" % (p, ex))
    with _lock:
        _cache[key] = {"stamp": stamp, "data": data}
    return data


def cohort_of(assignment: dict, entity: str) -> dict:
    """{"cohort", "source", "membership", "size"} or {} when unplaced."""
    m = ((assignment or {}).get("members") or {}).get(entity)
    if not m:
        # Case-insensitive retry: the assignment is built from store keys and
        # the caller may hold a differently-cased spelling of the same entity.
        low = str(entity or "").casefold()
        for k, v in ((assignment or {}).get("members") or {}).items():
            if k.casefold() == low:
                m = v
                entity = k
                break
    if not m:
        return {}
    c = ((assignment or {}).get("cohorts") or {}).get(m["cohort"]) or {}
    return {"cohort": m["cohort"], "source": m["source"],
            "membership": m.get("membership", 0.0),
            "distance": m.get("distance", 0.0),
            "size": c.get("size", 0)}


# ── deviation ───────────────────────────────────────────────────────────────

def deviation(assignment: dict, entity: str, recent_counts: dict,
              sigma: float = DEFAULT_DEVIATION_SIGMA,
              min_events: int = DEFAULT_MIN_EVENTS) -> dict:
    """Is this entity's recent behaviour drifting from its peer group?

    {"deviating", "distance", "cohort", "z", "reason", ...}

    Scored against the cohort's OWN spread, not a fixed threshold: an entity is
    deviating when it sits more than `sigma` standard deviations beyond the
    mean member-to-cohort distance recorded when the cohort was built. For a
    tight cohort that is a small absolute move; for a diverse one it is a large
    one. A fixed number would be wrong for both.

    Never raises, and never claims a verdict it cannot support — an unplaced
    entity, a cohort of one, or too little recent activity each return
    deviating=False with the reason stated.
    """
    out = {"deviating": False, "cohort": "", "source": "", "distance": 0.0,
           "z": 0.0, "membership": 0.0, "size": 0, "reason": ""}
    try:
        info = cohort_of(assignment, entity)
        if not info:
            unp = ((assignment or {}).get("unplaced") or {})
            out["reason"] = unp.get(entity) or "entity is not in a peer group"
            return out
        out.update(cohort=info["cohort"], source=info["source"],
                   membership=info["membership"], size=info["size"])

        c = ((assignment or {}).get("cohorts") or {}).get(info["cohort"]) or {}
        centre = c.get("profile") or {}
        if not centre:
            out["reason"] = "cohort has no profile recorded"
            return out

        total = sum(float(v) for v in (recent_counts or {}).values()
                    if isinstance(v, (int, float)))
        if total < min_events:
            out["reason"] = ("only %d recent accesses, below the %d needed to "
                             "judge a drift" % (int(total), min_events))
            return out

        recent = normalise_profile(recent_counts)
        d = profile_distance(recent, centre)
        out["distance"] = round(d, 6)

        mean = float(c.get("mean_distance") or 0.0)
        sd = float(c.get("distance_sd") or 0.0)
        if sd <= 1e-9:
            # A cohort whose members are identical has no spread to measure
            # against. Falling back to the build-time ceiling is the honest
            # move: anything past what would have excluded it from the cohort
            # is a drift, and nothing tighter can be claimed.
            ceiling = float(((assignment or {}).get("params") or {})
                            .get("max_distance") or DEFAULT_MAX_DISTANCE)
            out["z"] = 0.0
            if d > ceiling:
                out.update(deviating=True,
                           reason=("behaviour has moved %.3f from the %s peer "
                                   "group, past the %.2f at which it would no "
                                   "longer join that group; the group is too "
                                   "uniform to measure a spread"
                                   % (d, info["cohort"], ceiling)))
            else:
                out["reason"] = ("within the peer group's behaviour (%.3f, "
                                 "group has no measurable spread)" % d)
            return out

        z = (d - mean) / sd
        out["z"] = round(z, 4)
        if z >= sigma:
            out.update(deviating=True,
                       reason=("behaviour is %.1f standard deviations beyond "
                               "the %s peer group's normal spread (distance "
                               "%.3f against a group mean of %.3f)"
                               % (z, info["cohort"], d, mean)))
        else:
            out["reason"] = ("within the peer group's normal spread (%.1f sd)"
                             % z)
        return out
    except Exception as e:                                   # pragma: no cover
        out["reason"] = "not assessed: %s" % e
        return out


class RecentProfiles:
    """Each entity's access distribution over a rolling window.

    The serial says a user's pattern "STARTS deviating", which is a statement
    about change, not about being unusual. Comparing an entity's all-time
    profile to its cohort answers the wrong question: an entity that has always
    been unlike its peers would be reported every day, and one that changed
    yesterday would not stand out for weeks.

    So the recent window is kept here and compared against the cohort centre.
    Bounded on both axes, the same way ueba_assets.AccessRates is: a rolling
    counter per entity is a memory leak unless something evicts it.
    """

    def __init__(self, window_secs: float = 86400.0, max_keys: int = 20000,
                 max_assets: int = 200):
        self.window = float(window_secs)
        self.max_keys = int(max_keys)
        self.max_assets = int(max_assets)
        self._seen: dict = {}      # entity -> {asset: [timestamps]}
        self._touched: dict = {}   # entity -> last touch, for eviction

    def record(self, entity: str, asset: str, now: float) -> int:
        """Note one access and return how many this entity has in the window."""
        ent = str(entity or "").strip()
        ass = str(asset or "").strip().casefold()
        if not ent or not ass:
            return 0
        if ent not in self._seen and len(self._seen) >= self.max_keys:
            # Evict the least recently touched entity rather than refusing to
            # track the new one: a long-idle entity's window is stale anyway.
            oldest = min(self._touched, key=self._touched.get, default=None)
            if oldest is not None:
                self._seen.pop(oldest, None)
                self._touched.pop(oldest, None)
        buckets = self._seen.setdefault(ent, {})
        self._touched[ent] = now
        if ass not in buckets and len(buckets) >= self.max_assets:
            # This entity is touching more distinct assets than a profile can
            # usefully describe. Drop the least recently used one.
            lru = min(buckets, key=lambda k: (buckets[k][-1] if buckets[k] else 0))
            buckets.pop(lru, None)
        ts = buckets.setdefault(ass, [])
        ts.append(now)
        cutoff = now - self.window
        total = 0
        for k in list(buckets):
            kept = [t for t in buckets[k] if t >= cutoff]
            if kept:
                buckets[k] = kept
                total += len(kept)
            else:
                buckets.pop(k, None)
        return total

    def profile(self, entity: str, now: float) -> dict:
        """{asset: count} for this entity inside the window."""
        buckets = self._seen.get(str(entity or "").strip()) or {}
        cutoff = now - self.window
        out = {}
        for k, ts in buckets.items():
            c = sum(1 for t in ts if t >= cutoff)
            if c:
                out[k] = c
        return out

    def stats(self) -> dict:
        return {"entities": len(self._seen), "window_secs": self.window,
                "max_keys": self.max_keys, "max_assets": self.max_assets}


def status(path=None) -> dict:
    a = load(path) if path else {}
    return {
        "sources": list(SOURCES),
        "built_at": a.get("built_at", ""),
        "params": a.get("params", {}),
        "stats": a.get("stats", {}),
        "cohorts": [{"name": c.get("name"), "size": c.get("size"),
                     "source": c.get("source"),
                     "mean_distance": c.get("mean_distance"),
                     "distance_sd": c.get("distance_sd")}
                    for c in (a.get("cohorts") or {}).values()],
        "hr_note": (
            "Peer groups are built from observed behaviour, so no HR or "
            "Active Directory feed is required. If department, role or "
            "business-unit attributes do arrive, they are written into the "
            "operator register and immediately outrank the inferred grouping "
            "— the precedence is operator, then directory prefix, then "
            "behaviour. Only person-class entities are grouped: the brute-force "
            "usernames in this estate behave identically to one another and "
            "would otherwise form one large cohort of attackers."),
    }


# ── selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    import tempfile

    failures = []
    checked = []

    def ok(label, cond):
        # Counted, not a literal. A hardcoded total means every check added
        # after it runs and is never reported.
        checked.append(label)
        if not cond:
            failures.append(label)

    # ── distance ──
    A = normalise_profile({"h1": 8, "h2": 2})
    B = normalise_profile({"h1": 8, "h2": 2})
    C = normalise_profile({"h9": 10})
    ok("identical profiles are distance 0", profile_distance(A, B) == 0.0)
    ok("disjoint profiles are distance 1", profile_distance(A, C) == 1.0)
    ok("distance is symmetric",
       profile_distance(A, C) == profile_distance(C, A))
    ok("distance is bounded above", profile_distance(A, C) <= 1.0)
    ok("an empty profile is maximally distant", profile_distance({}, A) == 1.0)
    ok("two empties are maximally distant", profile_distance({}, {}) == 1.0)
    part = profile_distance(normalise_profile({"h1": 9, "h2": 1}),
                            normalise_profile({"h1": 1, "h2": 9}))
    ok("partial overlap sits strictly between", 0.0 < part < 1.0)
    # scale invariance: the same habits at ten times the volume are the same
    ok("volume does not affect distance",
       profile_distance(normalise_profile({"h1": 8, "h2": 2}),
                        normalise_profile({"h1": 80, "h2": 20})) == 0.0)

    # ── normalise_profile ──
    ok("profile sums to one", abs(sum(normalise_profile({"a": 1, "b": 3}).values()) - 1.0) < 1e-9)
    ok("zero counts are dropped", "b" not in normalise_profile({"a": 1, "b": 0}))
    ok("negative counts are dropped", "b" not in normalise_profile({"a": 1, "b": -5}))
    ok("non-numeric counts are dropped", normalise_profile({"a": "x"}) == {})
    ok("keys are folded and merged",
       normalise_profile({"H1": 1, "h1": 1}) == {"h1": 1.0})
    ok("an empty input gives an empty profile", normalise_profile({}) == {})
    ok("pool of nothing is empty", pool([]) == {})
    ok("pool averages rather than sums",
       abs(sum(pool([A, C]).values()) - 1.0) < 1e-9)

    # ── eligibility, guard 1 ──
    ok("a person is groupable", is_groupable("person:asha"))
    for e in ("external:1.2.3.4", "service:system@h", "shared:root@h",
              "endpoint:10.0.0.1", "device:dc_srv", "addr:10.0.0.1",
              "agent:070", "ip:10.0.0.1", "host:dc"):
        ok("not groupable: %s" % e, not is_groupable(e))
    ok("unknown is not groupable", not is_groupable("unknown"))
    ok("empty is not groupable", not is_groupable(""))
    ok("an untyped name is left to the caller", is_groupable("asha"))

    # ── directory prefix, guard 2 ──
    ok("domain prefix is extracted", directory_of("person:CORPDOM\\rlal") == "corpdom")
    ok("doubled escapes collapse first",
       directory_of("person:CORPDOM\\\\rlal") == "corpdom")
    ok("both spellings give the same directory",
       directory_of("CORPDOM\\rlal") == directory_of("CORPDOM\\\\rlal"))
    ok("an unqualified name has no directory", directory_of("person:asha") == "")
    ok("an empty entity has no directory", directory_of("") == "")

    # ── build: the brute-force trap, guard 1 ──
    # 100 attackers with identical behaviour, plus 5 real users. Grouped
    # naively the attackers dominate; they must be excluded entirely.
    profiles = {}
    for i in range(100):
        profiles["external:198.51.100.%d" % i] = {"app-srv-01": 30}
    for i in range(5):
        profiles["person:user%d" % i] = {"lap-%d" % i: 20 + i, "fileshare": 30}
    a = build_cohorts(profiles, min_size=3, min_events=10)
    ok("no attacker is placed in a cohort",
       not any(m.startswith("external:") for m in a["members"]))
    ok("the attackers are counted as excluded",
       a["stats"]["excluded_not_person"] == 100)
    ok("the real users are still grouped", len(a["members"]) == 5)
    ok("they form one cohort", len(a["cohorts"]) == 1)
    ok("and it is a behavioural one",
       list(a["cohorts"].values())[0]["source"] == "behaviour")

    # the same trap with untyped keys, where the caller supplies the class
    untyped = {}
    for i in range(50):
        untyped["guess%d" % i] = {"app-srv-01": 30}
    for i in range(5):
        # Mostly shared activity, so these five genuinely are peers under the
        # default ceiling. See the half-and-half check below for why the split
        # matters.
        untyped["real%d" % i] = {"lap-%d" % i: 10, "fileshare": 40}
    classes = {("guess%d" % i): "external" for i in range(50)}
    classes.update({("real%d" % i): "person" for i in range(5)})
    b = build_cohorts(untyped, classes=classes, min_size=3, min_events=10)
    ok("the caller's classification is honoured",
       all(not m.startswith("guess") for m in b["members"]))
    ok("and the real accounts are placed", len(b["members"]) == 5)
    ok("an excluded entity says why",
       "not a person" in b["unplaced"]["guess0"])

    # What the default ceiling means in practice, pinned because it is not
    # obvious from the number: two entities whose activity is split evenly
    # between one shared asset and one private asset each sit at exactly 0.5,
    # so they are NOT peers at 0.45. Sharing four fifths puts them at 0.2 and
    # they are. In short, peers must have more than half their activity in
    # common.
    half = profile_distance(normalise_profile({"shared": 50, "mine": 50}),
                            normalise_profile({"shared": 50, "yours": 50}))
    ok("an even split with a private half is distance 0.5",
       abs(half - 0.5) < 1e-9)
    ok("and is therefore not a peer at the default ceiling",
       half > DEFAULT_MAX_DISTANCE)
    most = profile_distance(normalise_profile({"shared": 80, "mine": 20}),
                            normalise_profile({"shared": 80, "yours": 20}))
    ok("sharing four fifths is well inside the ceiling",
       most < DEFAULT_MAX_DISTANCE)

    # ── build: guards 2 and 3 ──
    sparse = {"person:a": {"h": 3}, "person:b": {"h": 3}, "person:c": {"h": 3},
              "person:d": {"h": 3}}
    c2 = build_cohorts(sparse, min_size=2, min_events=20)
    ok("sparse entities are unplaced", c2["members"] == {})
    ok("and are counted", c2["stats"]["excluded_sparse"] == 4)
    ok("and each says why", "below the 20 needed" in c2["unplaced"]["person:a"])

    # Two dimensions on purpose: a single-key profile is now rejected by the
    # min_dimensions guard, and this case is about min_SIZE. A fixture that
    # trips two guards cannot show which one it is testing.
    two = {"person:a": {"h": 50, "h2": 25}, "person:b": {"h": 50, "h2": 25}}
    c3 = build_cohorts(two, min_size=4, min_events=10)
    ok("a cohort below min_size is not published", c3["cohorts"] == {})
    ok("its would-be members are unplaced", len(c3["unplaced"]) == 2)
    ok("and the reason names the minimum",
       "at least 4" in list(c3["unplaced"].values())[0])

    # ── build: no chaining ──
    # a~b and b~c, but a is nothing like c. Leader clustering must not put all
    # three in one cohort on the strength of b.
    # Each carries a small second dimension so the min_dimensions guard does
    # not remove a, c and d before the chaining geometry can be tested. The
    # shape is unchanged: a and d are alike, b sits between, c is the far end.
    chain = {
        "person:a": {"x": 100, "w": 1},
        "person:b": {"x": 50, "y": 50},
        "person:c": {"y": 100, "w": 1},
        "person:d": {"x": 100, "w": 1},
    }
    ch = build_cohorts(chain, min_size=2, min_events=10, max_distance=0.6,
                       use_directory=False)
    for name, co in ch["cohorts"].items():
        members = co["members"]
        far = [(i, j) for i in members for j in members
               if i < j and profile_distance(normalise_profile(chain[i]),
                                             normalise_profile(chain[j])) > 0.6]
        ok("cohort %s has no member pair beyond the ceiling" % name, not far)

    # ── build: operator precedence ──
    op = {"person:user0": "finance", "person:user1": "finance",
          "person:user2": "finance", "person:user3": "finance"}
    d = build_cohorts(profiles, operator=op, min_size=3, min_events=10)
    ok("the operator cohort is used",
       d["members"]["person:user0"]["cohort"] == "finance")
    ok("and is attributed to the operator",
       d["members"]["person:user0"]["source"] == "operator")
    ok("operator cohorts are counted by source",
       d["stats"]["by_source"]["operator"] == 4)
    ok("an entity the operator did not name is still grouped behaviourally",
       d["members"].get("person:user4", {}).get("source") in
       ("behaviour", None))

    # ── build: directory precedence over behaviour ──
    dirp = {"person:ACME\\u%d" % i: {"h%d" % i: 40} for i in range(5)}
    e = build_cohorts(dirp, min_size=4, min_events=10)
    ok("a directory cohort forms", any(c.startswith("dir:")
                                       for c in e["cohorts"]))
    ok("and is attributed to the directory",
       list(e["members"].values())[0]["source"] == "directory")
    ok("the cohort is named for the domain", "dir:acme" in e["cohorts"])
    # too few to form one
    f = build_cohorts({"person:ACME\\u1": {"h": 40}}, min_size=4, min_events=10)
    ok("a directory with too few members forms no cohort", f["cohorts"] == {})

    # ── build: metadata ──
    ok("membership is recorded", all("membership" in m
                                      for m in a["members"].values()))
    ok("membership is between 0 and 1",
       all(0.0 <= m["membership"] <= 1.0 for m in a["members"].values()))
    ok("every cohort records its spread",
       all("distance_sd" in c for c in a["cohorts"].values()))
    ok("every cohort records its size",
       all(c["size"] == len(c["members"]) for c in a["cohorts"].values()))
    ok("params are published", a["params"]["min_size"] == 3)
    ok("built_at is recorded", a["built_at"].startswith("20"))
    ok("stats add up",
       a["stats"]["placed"] + a["stats"]["unplaced"] >= a["stats"]["eligible"])

    # ── build: truncation ──
    many = {"person:p%d" % i: {"h%d" % (i % 3): 50} for i in range(30)}
    t = build_cohorts(many, min_size=2, min_events=10, max_entities=10)
    ok("a build truncates rather than running away",
       t["stats"]["truncated"] == 20)
    ok("truncated entities say so",
       any("truncated" in r for r in t["unplaced"].values()))

    # ── build: empty and junk input ──
    ok("no profiles gives an empty assignment",
       build_cohorts({})["cohorts"] == {})
    ok("junk entities are skipped", build_cohorts({"": {"h": 99}})["members"] == {})
    ok("a None profile is skipped",
       build_cohorts({"person:a": None})["members"] == {})

    # ── cohort_of ──
    ok("cohort_of finds a member", cohort_of(a, "person:user0")["cohort"])
    ok("cohort_of reports the size", cohort_of(a, "person:user0")["size"] == 5)
    ok("cohort_of is case-insensitive",
       cohort_of(a, "PERSON:USER0")["cohort"] == cohort_of(a, "person:user0")["cohort"])
    ok("cohort_of on an unknown entity is empty", cohort_of(a, "person:nope") == {})
    ok("cohort_of on an empty assignment is empty", cohort_of({}, "x") == {})

    # ── deviation ──
    # A cohort of five users who all split their time the same way.
    base = {"person:c%d" % i: {"share": 50, "mail": 50} for i in range(5)}
    asg = build_cohorts(base, min_size=4, min_events=10, use_directory=False)
    ok("the uniform cohort is built", len(asg["cohorts"]) == 1)

    same = deviation(asg, "person:c0", {"share": 50, "mail": 50})
    ok("behaving like the group is not deviating", same["deviating"] is False)
    ok("and the reason says so", "within the peer group" in same["reason"])

    drift = deviation(asg, "person:c0", {"crown-jewels": 200})
    ok("behaviour unlike the whole group IS deviating", drift["deviating"] is True)
    ok("the drift reason names the group", drift["cohort"] in drift["reason"])
    ok("the drift reports a distance", drift["distance"] > 0.5)

    thin = deviation(asg, "person:c0", {"share": 2})
    ok("too little recent activity is not a verdict", thin["deviating"] is False)
    ok("and it says why", "below the" in thin["reason"])

    gone = deviation(asg, "person:nobody", {"share": 99})
    ok("an unplaced entity gets no verdict", gone["deviating"] is False)
    ok("and the reason explains", "not in a peer group" in gone["reason"])

    ok("deviation on an empty assignment is safe",
       deviation({}, "x", {"a": 99})["deviating"] is False)
    ok("deviation with no recent counts is safe",
       deviation(asg, "person:c0", {})["deviating"] is False)
    ok("deviation never raises on junk",
       deviation(asg, "person:c0", {"a": "x"})["deviating"] is False)

    # A cohort with real internal spread: the sigma test must scale to it.
    varied = {}
    for i in range(6):
        varied["person:v%d" % i] = {"share": 50 + i * 8, "mail": 50 - i * 8}
    va = build_cohorts(varied, min_size=4, min_events=10, use_directory=False)
    if va["cohorts"]:
        co = list(va["cohorts"].values())[0]
        ok("a varied cohort records a non-zero spread", co["distance_sd"] > 0)
        mild = deviation(va, "person:v0", {"share": 58, "mail": 42})
        ok("a move inside a varied group's spread is not flagged",
           mild["deviating"] is False)
        wild = deviation(va, "person:v0", {"unrelated": 300})
        ok("a move far outside it is flagged", wild["deviating"] is True)
        ok("the z score is reported", wild["z"] != 0.0)

    # ── the rolling window ──
    rp = RecentProfiles(window_secs=100.0, max_keys=3, max_assets=3)
    ok("recording returns the window total", rp.record("e1", "a", 1000.0) == 1)
    rp.record("e1", "a", 1001.0)
    rp.record("e1", "b", 1002.0)
    ok("the profile counts per asset",
       rp.profile("e1", 1003.0) == {"a": 2, "b": 1})
    ok("an unknown entity has an empty profile", rp.profile("zz", 1003.0) == {})
    ok("an empty entity records nothing", rp.record("", "a", 1000.0) == 0)
    ok("an empty asset records nothing", rp.record("e1", "", 1000.0) == 0)
    # ageing out
    ok("accesses age out of the window",
       rp.profile("e1", 1200.0) == {})
    rp.record("e1", "c", 2000.0)
    ok("only in-window accesses remain",
       rp.profile("e1", 2001.0) == {"c": 1})
    # entity eviction
    for i in range(5):
        rp.record("ent%d" % i, "a", 3000.0 + i)
    ok("the entity map stays bounded", rp.stats()["entities"] <= 3)
    ok("the most recent entity survived eviction",
       rp.profile("ent4", 3005.0) == {"a": 1})
    # asset eviction
    rp2 = RecentProfiles(window_secs=1000.0, max_keys=10, max_assets=2)
    for i in range(5):
        rp2.record("e", "asset%d" % i, 4000.0 + i)
    ok("the per-entity asset map stays bounded",
       len(rp2.profile("e", 4005.0)) <= 2)
    # the window feeds deviation end to end
    rp3 = RecentProfiles(window_secs=1000.0)
    for _ in range(30):
        rp3.record("person:c0", "crown-jewels", 5000.0)
    dev = deviation(asg, "person:c0", rp3.profile("person:c0", 5001.0))
    ok("a drift measured through the rolling window is flagged",
       dev["deviating"] is True)
    rp4 = RecentProfiles(window_secs=1000.0)
    for _ in range(15):
        rp4.record("person:c0", "share", 5000.0)
        rp4.record("person:c0", "mail", 5000.0)
    ok("normal behaviour through the rolling window is not flagged",
       deviation(asg, "person:c0", rp4.profile("person:c0", 5001.0))["deviating"] is False)

    # ── persistence ──
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "peers.json"
        ok("a missing assignment loads empty", load(path)["cohorts"] == {})
        save(path, asg)
        back = load(path)
        ok("the assignment round-trips", len(back["cohorts"]) == len(asg["cohorts"]))
        ok("members survive the round trip",
           cohort_of(back, "person:c0")["cohort"] == cohort_of(asg, "person:c0")["cohort"])
        ok("deviation works off the loaded copy",
           deviation(back, "person:c0", {"crown-jewels": 200})["deviating"] is True)
        save(path, build_cohorts({}))
        ok("a rebuild is picked up immediately", load(path)["cohorts"] == {})
        path.write_text("{not json", encoding="utf-8")
        ok("a corrupt assignment loads empty rather than raising",
           load(path)["cohorts"] == {})
        st = status(path)
        ok("status lists the sources", st["sources"] == list(SOURCES))
        ok("status states the HR position", "no HR" in st["hr_note"])

    total = len(checked)
    if failures:
        print("ueba_peers selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_peers selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
