#!/usr/bin/env python3
"""Behavioural profiling and anomaly detection for ANY entity kind — RFP SN 30 / SN 67.

THE GAP THIS CLOSES

An operator can already nominate any field in the incoming events and have its
values tracked as entities (`ueba_entities` mappings, hot-reloaded, with a
cardinality refusal). What happened next was the problem: those entities were
RECORDED in `entity_presence` — value, how many accounts touched it, first and
last seen — and never ANALYSED. `/api/entities/kind/<kind>` returned counts.

So an administrator could map `application_id`, see a list of application ids
with event totals, and learn nothing about whether any of them was behaving
unusually. The requirement asks for the entity's behaviour to be analysed, not
inventoried.

WHY THIS IS NOT DONE WITH AN AUTOENCODER

`ueba_preprocessor.resolve_entity()` returns the PRIMARY key, and that key
names the per-entity autoencoder file on disk and buckets the training data.
Promoting a secondary entity into it would strand every existing model until a
full retrain — the same constraint that keeps `typed_keys` off. So nothing here
touches it. A secondary entity gets a STATISTICAL baseline instead, which also
means a newly mapped field starts producing findings on the next event rather
than after the next training run.

TWO QUESTIONS, ASKED SEPARATELY

  self-drift   Is this entity behaving unlike ITSELF? The window is split in
               two and the later half is compared with the earlier one. This
               is what catches an application that was used by two people
               during office hours and is now used by nine at 3am.

  peer-outlier Is this entity behaving unlike OTHERS OF ITS KIND? The entity
               is compared with the pooled profile of every other value under
               the same kind. This is what catches the one database that is
               accessed in a way no other database is.

They are reported separately on purpose. An entity can be stable but unlike
its peers (a special-purpose server), or ordinary for its kind but changing
fast (a laptop being compromised), and collapsing those into one number loses
the distinction an analyst acts on.

FOUR DIMENSIONS, and `actors` is the one that earns its place

`signatures`, `hours` and `verdicts` are the same axes `ueba_device_compare`
uses. `actors` — WHICH primary entities touched this thing — is added here
because for a non-host entity it is usually the most informative axis there
is: a shared application being reached by a set of accounts that has changed
is the shape of both credential sharing and lateral movement, and no
signature-based axis sees it.

Distances are Jensen-Shannon via `ueba_peers.profile_distance`, the same
measure used for peer cohorts (SN 42) and device comparison (SN 56), so
"behaves alike" means one thing across the product.
"""
from __future__ import annotations

try:
    import ueba_peers
except Exception:          # pragma: no cover
    ueba_peers = None

# (key, weight, what it measures)
DIMENSIONS = (
    ("actors",     0.35, "which accounts touch it"),
    ("signatures", 0.30, "which detections fire on it"),
    ("hours",      0.20, "when it is active"),
    ("verdicts",   0.15, "how its risk verdicts distribute"),
)

# An entity seen a handful of times has no baseline worth comparing against —
# scoring it produces confident nonsense. Below this it is profiled (so it
# appears, with its counts) but carries no score.
MIN_EVENTS_FOR_SCORE = 20

# Both halves of a split need enough events to be a baseline, or the drift
# score is measuring the split rather than the entity.
MIN_EVENTS_PER_HALF = 8

# Peer comparison needs peers. One value under a kind has nothing to be an
# outlier against.
MIN_PEERS = 2

# Kinds whose values are naturally unbounded get capped, so one mapping of a
# high-cardinality field cannot turn this into a scan of the whole corpus.
# The cardinality guard in ueba_entities refuses such a field at mapping time;
# this is the second line, for a field that was bounded when it was mapped.
MAX_VALUES_PER_KIND = 500

# Kind names the product RECOGNISES, beyond the three it classifies by itself.
# Naming them matters: without this an operator inventing a kind gets
# `custom:db` on one install and `custom:database` on the next, and no report
# can speak about "databases" across customers. The candidate fields are where
# such a value is USUALLY found — they are hints for the operator, not a
# promise that this feed carries them. See feed_support().
RECOGNISED_KINDS = {
    "database": (
        "a database, schema or instance",
        ("data.db", "data.database", "data.dbname", "data.schema",
         "data.instance", "context.raw_event.data.db",
         "context.raw_event.data.database"),
    ),
    "business_unit": (
        "a department, team or cost centre",
        ("data.department", "data.dept", "data.business_unit", "data.org",
         "data.orgunit", "data.team", "subject.department"),
    ),
    "data_store": (
        "a file share, bucket or repository",
        ("data.share", "data.bucket", "data.repo", "data.path",
         "object.path", "context.raw_event.data.share"),
    ),
    "service": (
        "a named service or daemon",
        ("data.service", "data.svc", "context.raw_event.data.win.system.channel"),
    ),
}


def _norm(counts) -> dict:
    """L1-normalise a histogram, dropping non-positive entries."""
    clean = {str(k): float(v) for k, v in (counts or {}).items()
             if isinstance(v, (int, float)) and v > 0}
    total = sum(clean.values())
    if not total:
        return {}
    return {k: v / total for k, v in clean.items()}


def _distance(a: dict, b: dict) -> float:
    """Jensen-Shannon distance between normalised histograms, 0..1."""
    if ueba_peers is not None:
        try:
            return float(ueba_peers.profile_distance(a, b))
        except Exception:
            pass
    keys = set(a) | set(b)
    return min(1.0, 0.5 * sum(abs(a.get(k, 0.0) - b.get(k, 0.0)) for k in keys))


def _drivers(a: dict, b: dict, limit: int = 4) -> list:
    both = set(a) & set(b)
    ranked = sorted(both, key=lambda k: -min(a[k], b[k]))
    return [{"key": k, "before": round(b[k], 4), "after": round(a[k], 4)}
            for k in ranked[:limit]]


def _changes(a: dict, b: dict, limit: int = 4) -> list:
    """Keys that moved most between two profiles, with direction.

    `a` is the later/subject profile, `b` the earlier/comparison one, so
    `appeared` means "present now and not before".
    """
    keys = set(a) | set(b)
    ranked = sorted(keys, key=lambda k: -abs(a.get(k, 0.0) - b.get(k, 0.0)))
    out = []
    for k in ranked[:limit]:
        now, was = a.get(k, 0.0), b.get(k, 0.0)
        out.append({"key": k, "now": round(now, 4), "was": round(was, 4),
                    "gap": round(abs(now - was), 4),
                    "appeared": was == 0.0, "stopped": now == 0.0})
    return out


def feed_support(field_coverage: "dict | None" = None) -> dict:
    """Which recognised kinds this feed can actually populate.

    `field_coverage` is {field_path: events_seen} measured from the real
    corpus. Returns a per-kind verdict, so `status()` can state what is
    supported HERE rather than asserting a capability the data cannot back.

    Measured on this deployment 2026-11-05 over the live alert tail: no field
    matching any `database`, `business_unit` or `data_store` candidate exists
    (`object.type` carries only `process` and `user`; `object.name` carries
    executable paths, which the built-in `application` kind already covers).
    The mapping MECHANISM is generic, so the kind works the day such a field
    appears — which is the honest version of "supported".
    """
    cov = {str(k): int(v or 0) for k, v in (field_coverage or {}).items()}
    out = {}
    for kind, (what, candidates) in sorted(RECOGNISED_KINDS.items()):
        present = [f for f in candidates if cov.get(f, 0) > 0]
        out[kind] = {
            "kind": kind, "describes": what,
            "candidate_fields": list(candidates),
            "fields_present": present,
            "supported_by_feed": bool(present),
            "why": ("%d candidate field(s) carry values in this feed: %s"
                    % (len(present), ", ".join(present[:3]))) if present else
                   ("no candidate field for this kind carries values in this "
                    "feed, so nothing can be tracked under it yet; map any "
                    "field that does carry one and it is tracked from the "
                    "next event"),
        }
    return out


def _bucket(ts: str) -> str:
    """Hour-of-day from an ISO timestamp, or ""."""
    t = str(ts or "")
    if len(t) >= 13 and t[10] in ("T", " ") and t[11:13].isdigit():
        return str(int(t[11:13]))
    return ""


def build_profiles(alerts, extract_fn, split_at: str = "",
                   kinds=None, max_values: int = MAX_VALUES_PER_KIND) -> dict:
    """{kind: {value: profile}} from an alert iterable.

    `extract_fn(alert) -> [{'kind','value',...}]` is injected rather than
    imported so this module can be tested without a register on disk, and so
    the caller controls which extractor (and therefore which operator
    mappings) is in force.

    `split_at` is an ISO timestamp: alerts at or after it count as `recent`,
    everything before as `baseline`. Empty means the midpoint of the observed
    range, which is the only split available when the caller has no opinion.

    Each profile carries the four dimensions twice — once for each half — plus
    totals. Counts are kept rather than normalised so the halves can be
    re-split or merged by a caller without re-reading the corpus.
    """
    alerts = list(alerts)
    if not alerts:
        return {}

    def _ts(a):
        u = a.get("ueba") or {}
        return str(u.get("processed_at") or a.get("event_time") or "")

    if not split_at:
        stamps = sorted(t for t in (_ts(a) for a in alerts) if t)
        split_at = stamps[len(stamps) // 2] if stamps else ""

    want = set(kinds) if kinds else None
    out: dict = {}

    for a in alerts:
        try:
            found = extract_fn(a) or []
        except Exception:
            continue
        if not found:
            continue
        ts = _ts(a)
        half = "recent" if (split_at and ts >= split_at) else "baseline"
        ueba = (a.get("ueba") or {})
        sec = (a.get("security") or {})
        actor = str((a.get("user") or {}).get("name")
                    or (a.get("subject") or {}).get("name") or "") or "unknown"
        sig = str(sec.get("signature_id") or "") or "unknown"
        verdict = str(ueba.get("risk_verdict") or "") or "unknown"
        hour = _bucket(ts)
        try:
            score = float(ueba.get("combined_score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0

        for ent in found:
            kind = str(ent.get("kind") or "")
            value = str(ent.get("value") or "")
            if not kind or not value:
                continue
            if want is not None and kind not in want:
                continue
            bucket = out.setdefault(kind, {})
            if value not in bucket and len(bucket) >= max_values:
                # Capped rather than grown without bound. Reported by
                # profile_kind so the truncation is visible, not silent.
                continue
            p = bucket.setdefault(value, {
                "kind": kind, "value": value, "events": 0,
                "max_score": 0.0, "first_seen": ts, "last_seen": ts,
                "actors_all": {},
                "baseline": {"events": 0, "actors": {}, "signatures": {},
                             "hours": {}, "verdicts": {}},
                "recent": {"events": 0, "actors": {}, "signatures": {},
                           "hours": {}, "verdicts": {}},
            })
            p["events"] += 1
            p["max_score"] = max(p["max_score"], score)
            if ts:
                if not p["first_seen"] or ts < p["first_seen"]:
                    p["first_seen"] = ts
                if ts > p["last_seen"]:
                    p["last_seen"] = ts
            p["actors_all"][actor] = p["actors_all"].get(actor, 0) + 1
            h = p[half]
            h["events"] += 1
            h["actors"][actor] = h["actors"].get(actor, 0) + 1
            h["signatures"][sig] = h["signatures"].get(sig, 0) + 1
            h["verdicts"][verdict] = h["verdicts"].get(verdict, 0) + 1
            if hour:
                h["hours"][hour] = h["hours"].get(hour, 0) + 1

    for bucket in out.values():
        for p in bucket.values():
            p["split_at"] = split_at
            p["actor_count"] = len(p["actors_all"])
            # The cap ACTUALLY applied, carried on the profile. profile_kind
            # used to compare the bucket size against MAX_VALUES_PER_KIND,
            # the module default — so a caller passing a smaller cap got
            # `truncated: false` while values were being dropped. A silent
            # truncation in an anomaly list is the worst kind: the entity that
            # mattered is simply absent and nothing says so.
            p["_cap"] = int(max_values)
    return out


def self_drift(profile: dict) -> dict:
    """Is this entity behaving unlike ITSELF? {'score','comparable',...}

    Dimensions with no data on either side of the split are SKIPPED and the
    weights renormalised, never scored as maximally different — the same rule
    as ueba_device_compare, and for the same reason: an entity must not be
    marked anomalous for an axis it never had.
    """
    base = (profile or {}).get("baseline") or {}
    rec = (profile or {}).get("recent") or {}
    if (base.get("events", 0) < MIN_EVENTS_PER_HALF
            or rec.get("events", 0) < MIN_EVENTS_PER_HALF):
        return {"score": None, "comparable": False, "dimensions": [],
                "why": "not enough history on both sides of the window "
                       "(%d before, %d after; %d needed each) to say whether "
                       "it changed"
                       % (base.get("events", 0), rec.get("events", 0),
                          MIN_EVENTS_PER_HALF)}

    dims, skipped, usable = [], [], 0.0
    for key, weight, what in DIMENSIONS:
        b, r = _norm(base.get(key)), _norm(rec.get(key))
        if not b or not r:
            skipped.append(key)
            continue
        d = _distance(r, b)
        usable += weight
        dims.append({"dimension": key, "measures": what, "weight": weight,
                     "drift": round(max(0.0, min(1.0, d)), 4),
                     "stable": _drivers(r, b), "changed": _changes(r, b)})
    if not dims:
        return {"score": None, "comparable": False, "dimensions": [],
                "why": "no dimension carries data on both sides of the window"}

    total = 0.0
    for d in dims:
        share = d["weight"] / usable
        d["weight_used"] = round(share, 4)
        d["contribution"] = round(share * d["drift"], 4)
        total += share * d["drift"]
    total = round(max(0.0, min(1.0, total)), 4)
    lead = max(dims, key=lambda d: d["contribution"])
    top = (lead["changed"] or [{}])[0]
    detail = ""
    if top.get("key"):
        detail = (" — %s %s" % (top["key"],
                  "appeared" if top.get("appeared") else
                  "stopped" if top.get("stopped") else "shifted"))
    return {"score": total, "comparable": True, "dimensions": dims,
            "skipped": skipped,
            "why": "%.0f%% changed between the two halves of the window; most "
                   "of it in %s%s"
                   % (total * 100, lead["dimension"], detail)}


def peer_outlier(profile: dict, siblings) -> dict:
    """Is this entity behaving unlike OTHERS OF ITS KIND?

    Compared against the POOLED profile of its siblings rather than against
    each one: an entity that is unlike every sibling individually but sits in
    the middle of them collectively is not an outlier, and pairwise minimum
    distance would call it one.
    """
    others = [s for s in (siblings or [])
              if s is not profile and s.get("value") != (profile or {}).get("value")]
    if len(others) < MIN_PEERS:
        return {"score": None, "comparable": False, "dimensions": [],
                "why": "only %d other value(s) under this kind; %d needed "
                       "before 'unlike its peers' means anything"
                       % (len(others), MIN_PEERS)}

    def merged(p, key):
        out = {}
        for half in ("baseline", "recent"):
            for k, v in ((p.get(half) or {}).get(key) or {}).items():
                out[k] = out.get(k, 0) + v
        return out

    dims, skipped, usable = [], [], 0.0
    for key, weight, what in DIMENSIONS:
        mine = _norm(merged(profile, key))
        pool_counts: dict = {}
        for s in others:
            for k, v in merged(s, key).items():
                pool_counts[k] = pool_counts.get(k, 0) + v
        theirs = _norm(pool_counts)
        if not mine or not theirs:
            skipped.append(key)
            continue
        d = _distance(mine, theirs)
        usable += weight
        dims.append({"dimension": key, "measures": what, "weight": weight,
                     "distance": round(max(0.0, min(1.0, d)), 4),
                     "shared": _drivers(mine, theirs),
                     "unlike": _changes(mine, theirs)})
    if not dims:
        return {"score": None, "comparable": False, "dimensions": [],
                "why": "no dimension carries data for both this entity and "
                       "its peers"}

    total = 0.0
    for d in dims:
        share = d["weight"] / usable
        d["weight_used"] = round(share, 4)
        d["contribution"] = round(share * d["distance"], 4)
        total += share * d["distance"]
    total = round(max(0.0, min(1.0, total)), 4)
    lead = max(dims, key=lambda d: d["contribution"])
    return {"score": total, "comparable": True, "dimensions": dims,
            "skipped": skipped, "peers": len(others),
            "why": "%.0f%% unlike the other %d value(s) of this kind; most "
                   "of it in %s"
                   % (total * 100, len(others), lead["dimension"])}


def assess(profile: dict, siblings=None) -> dict:
    """Both scores for one entity, plus a one-line verdict.

    The two are NOT averaged. They answer different questions and an analyst
    acts differently on each, so collapsing them would throw away the
    distinction. The verdict names whichever is higher and says which it is.
    """
    p = profile or {}
    if p.get("events", 0) < MIN_EVENTS_FOR_SCORE:
        return {"value": p.get("value"), "kind": p.get("kind"),
                "events": p.get("events", 0), "scored": False,
                "self_drift": None, "peer_outlier": None,
                "why": "seen %d time(s); %d needed before a baseline means "
                       "anything" % (p.get("events", 0), MIN_EVENTS_FOR_SCORE)}

    drift = self_drift(p)
    peer = peer_outlier(p, siblings or [])
    ds, ps = drift.get("score"), peer.get("score")

    parts = []
    if ds is not None:
        parts.append(("changed", ds, drift["why"]))
    if ps is not None:
        parts.append(("unlike its peers", ps, peer["why"]))
    if not parts:
        why = "profiled, but neither comparison could be made: %s; %s" % (
            drift.get("why", ""), peer.get("why", ""))
    else:
        label, val, detail = max(parts, key=lambda x: x[1])
        why = "%s (%.0f%%): %s" % (label, val * 100, detail)

    return {"value": p.get("value"), "kind": p.get("kind"),
            "events": p.get("events", 0), "actor_count": p.get("actor_count", 0),
            "max_score": round(p.get("max_score", 0.0), 4),
            "first_seen": p.get("first_seen"), "last_seen": p.get("last_seen"),
            "scored": True, "self_drift": drift, "peer_outlier": peer,
            "why": why}


def profile_kind(profiles: dict, kind: str, limit: int = 50) -> dict:
    """Every value under one kind, assessed, worst first."""
    bucket = (profiles or {}).get(kind) or {}
    sibs = list(bucket.values())
    rows = [assess(p, sibs) for p in sibs]
    cap = max((p.get("_cap") or MAX_VALUES_PER_KIND) for p in sibs) \
        if sibs else MAX_VALUES_PER_KIND

    def rank(r):
        vals = [v for v in (
            (r.get("self_drift") or {}).get("score"),
            (r.get("peer_outlier") or {}).get("score")) if v is not None]
        return -(max(vals) if vals else -1.0)

    rows.sort(key=rank)
    scored = [r for r in rows if r.get("scored")]
    return {"kind": kind, "values": len(bucket), "scored": len(scored),
            "truncated": len(bucket) >= cap, "cap": cap,
            "shown": min(limit, len(rows)),
            "rows": rows[:limit]}


def selftest() -> int:
    failures, checked = [], []

    def ok(label, cond):
        checked.append(label)
        if not cond:
            failures.append(label)

    def alert(ts, actor, sig, verdict="suspicious", score=0.8, app="erp.exe"):
        return {"event_time": ts,
                "ueba": {"processed_at": ts, "risk_verdict": verdict,
                         "combined_score": score},
                "security": {"signature_id": sig},
                "user": {"name": actor},
                "_app": app}

    def extract(a):
        return [{"kind": "application", "value": a["_app"]}]

    # ── a steady entity ──
    steady = [alert("2026-11-0%d T10:00:00".replace(" ", "")[:19] % d,
                    "alice" if i % 2 else "bob", "5710")
              for d in range(1, 5) for i in range(6)]
    profs = build_profiles(steady, extract)
    ok("a profile is built", "application" in profs)
    p = profs["application"]["erp.exe"]
    ok("every event is counted", p["events"] == len(steady))
    ok("actors are counted", p["actor_count"] == 2)
    ok("both halves have events",
       p["baseline"]["events"] > 0 and p["recent"]["events"] > 0)
    d = self_drift(p)
    ok("a steady entity has not drifted", d["comparable"] and d["score"] < 0.1)
    ok("and the reason says so", "changed between" in d["why"])

    # ── an entity that changes hands and hours ──
    early = [alert("2026-11-01T10:00:00", "alice", "5710") for _ in range(12)]
    late = [alert("2026-11-09T03:00:00", "mallory", "9999",
                  verdict="highly_anomalous", score=0.99) for _ in range(12)]
    profs2 = build_profiles(early + late, extract, split_at="2026-11-05T00:00:00")
    p2 = profs2["application"]["erp.exe"]
    d2 = self_drift(p2)
    ok("a changed entity drifts", d2["comparable"] and d2["score"] > 0.8)
    ok("drift is ordered correctly", d2["score"] > d["score"])
    actors = [x for x in d2["dimensions"] if x["dimension"] == "actors"]
    ok("the actors dimension is compared", len(actors) == 1)
    ok("and it is maximally changed", actors[0]["drift"] > 0.9)
    ch = {x["key"]: x for x in actors[0]["changed"]}
    ok("the new account is marked as appeared", ch["mallory"]["appeared"])
    ok("and the old one as stopped", ch["alice"]["stopped"])
    ok("the explanation names the dimension", "actors" in d2["why"])

    # ── too little history ──
    thin = build_profiles([alert("2026-11-01T10:00:00", "a", "1")] * 3, extract)
    tp = thin["application"]["erp.exe"]
    ok("a thin entity is not scored", assess(tp)["scored"] is False)
    ok("and says how many it needs", "needed" in assess(tp)["why"])
    ok("self_drift refuses it too", self_drift(tp)["comparable"] is False)
    ok("with the counts in the reason", "before" in self_drift(tp)["why"])

    # ── peer outlier ──
    def extract_multi(a):
        return [{"kind": "database", "value": a["_app"]}]
    normal = []
    for name in ("db-a", "db-b", "db-c"):
        normal += [dict(alert("2026-11-01T10:00:00", "svc", "5710"), _app=name)
                   for _ in range(20)]
    odd = [dict(alert("2026-11-01T23:00:00", "mallory", "9999"), _app="db-x")
           for _ in range(20)]
    pk = build_profiles(normal + odd, extract_multi)
    bucket = pk["database"]
    sibs = list(bucket.values())
    ok("four values are profiled", len(bucket) == 4)
    out_x = peer_outlier(bucket["db-x"], sibs)
    out_a = peer_outlier(bucket["db-a"], sibs)
    ok("the odd one out is flagged", out_x["comparable"] and out_x["score"] > 0.8)
    ok("a normal sibling is not", out_a["score"] < 0.3)
    ok("the outlier scores higher than the sibling", out_x["score"] > out_a["score"])
    ok("the peer count is reported", out_x["peers"] == 3)
    ok("and the reason names it", "unlike the other 3" in out_x["why"])
    ok("an entity is never its own peer",
       peer_outlier(bucket["db-a"], [bucket["db-a"]])["comparable"] is False)
    # Deterministic: db-a plus ONE other leaves a single peer, below MIN_PEERS.
    one_peer = peer_outlier(bucket["db-a"], [bucket["db-a"], bucket["db-b"]])
    ok("a single peer is refused, not scored", one_peer["score"] is None)
    ok("and it is not marked comparable", one_peer["comparable"] is False)
    ok("and the reason gives both numbers",
       "1 other" in one_peer["why"] and str(MIN_PEERS) in one_peer["why"])

    # ── assess keeps the two apart ──
    a_x = assess(bucket["db-x"], sibs)
    ok("both scores are present", a_x["self_drift"] is not None
       and a_x["peer_outlier"] is not None)
    # Deliberately NOT averaged: the two answer different questions. Asserted
    # by checking no single combined score is published at all.
    ok("no combined score is published", a_x.get("score") is None)
    # db-x's events all share one timestamp, so every one lands on the same
    # side of the split and self-drift CORRECTLY refuses — an entity seen in a
    # single instant has no two halves to compare. The peer comparison still
    # works, which is the point of keeping the two questions apart: one being
    # unanswerable does not silence the other.
    ok("self-drift is unanswerable for a single-instant entity",
       a_x["self_drift"]["score"] is None)
    ok("and says why", "not enough history" in a_x["self_drift"]["why"])
    ok("peer-outlier still carries its own score",
       isinstance(a_x["peer_outlier"]["score"], float))
    ok("and the verdict reports the answerable one",
       "unlike its peers" in a_x["why"])
    # The reverse case: an entity that drifts but has too few peers.
    a_steady = assess(p2, [p2])
    ok("self-drift answers when peers cannot",
       isinstance(a_steady["self_drift"]["score"], float)
       and a_steady["peer_outlier"]["score"] is None)
    ok("and the verdict reports that one instead",
       "changed" in a_steady["why"])
    ok("the verdict names which one is higher",
       "unlike its peers" in a_x["why"] or "changed" in a_x["why"])

    # ── ranking ──
    pkk = profile_kind(pk, "database")
    ok("the kind reports its value count", pkk["values"] == 4)
    ok("and how many were scored", pkk["scored"] == 4)
    ok("the outlier ranks first", pkk["rows"][0]["value"] == "db-x")
    ok("nothing is truncated here", pkk["truncated"] is False)
    ok("an unknown kind is empty, not an error",
       profile_kind(pk, "nope")["values"] == 0)

    # ── the value cap ──
    many = []
    for i in range(30):
        many += [dict(alert("2026-11-01T10:00:00", "a", "1"), _app="v%d" % i)]
    capped = build_profiles(many, extract, max_values=10)
    ok("the number of values per kind is capped",
       len(capped["application"]) == 10)
    pc = profile_kind(capped, "application", limit=5)
    ok("truncation is reported against the cap ACTUALLY used",
       pc["truncated"] is True)
    ok("and the cap is named", pc["cap"] == 10)
    ok("and how many rows were returned", pc["shown"] == 5)
    # The uncapped case must NOT claim truncation.
    ok("an uncapped kind is not marked truncated",
       profile_kind(pk, "database")["truncated"] is False)

    # ── robustness ──
    ok("no alerts yields nothing", build_profiles([], extract) == {})
    ok("an extractor that raises is survived",
       build_profiles(steady, lambda a: (_ for _ in ()).throw(ValueError())) == {})
    ok("an entity with no kind is skipped",
       build_profiles(steady, lambda a: [{"kind": "", "value": "x"}]) == {})
    ok("an entity with no value is skipped",
       build_profiles(steady, lambda a: [{"kind": "k", "value": ""}]) == {})
    ok("assess survives an empty profile", assess({})["scored"] is False)
    ok("self_drift survives None", self_drift(None)["comparable"] is False)
    ok("peer_outlier survives None",
       peer_outlier(None, [])["comparable"] is False)
    ok("a kind filter is honoured",
       build_profiles(steady, extract, kinds=["nope"]) == {})

    # ── feed_support: honest about what the data carries ──
    fs = feed_support({})
    ok("every recognised kind is reported", set(fs) == set(RECOGNISED_KINDS))
    ok("with no fields present nothing is supported",
       all(not v["supported_by_feed"] for v in fs.values()))
    ok("and it says the mechanism still works",
       "from the next event" in fs["database"]["why"])
    fs2 = feed_support({"data.db": 400})
    ok("a present field makes the kind supported",
       fs2["database"]["supported_by_feed"] is True)
    ok("and names the field", "data.db" in fs2["database"]["fields_present"])
    ok("an unrelated kind is still unsupported",
       fs2["business_unit"]["supported_by_feed"] is False)
    ok("candidate fields are always listed",
       len(fs["business_unit"]["candidate_fields"]) > 0)

    total = len(checked)
    if failures:
        print("ueba_entity_profiles selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_entity_profiles selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
