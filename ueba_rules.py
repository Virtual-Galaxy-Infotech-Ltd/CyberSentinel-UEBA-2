#!/usr/bin/env python3
"""
ueba_rules.py
─────────────
CyberSentinel UEBA — rules that switch themselves off (RFP SN 45).

  SN 45  UEBA should activate rules for a set of users until a specified
         condition or specified time window.

What this adds over the watch list, and why it is a separate thing
──────────────────────────────────────────────────────────────────
ueba_watchlist already raises an entity's score a little so its borderline
activity surfaces. It is permanent and it is per-entity: one row, one name, no
end date. SN 45 asks for two things it deliberately does not do.

  A SET of subjects.  "Watch the contractors" is one decision, not nineteen
                      rows an analyst has to remember to remove nineteen times.
  AN ENDING.          "...until Friday", "...until they are cleared", "...until
                      this has fired five times". A rule with no ending is the
                      thing an analyst forgets, and a forgotten rule is a
                      permanent score distortion nobody remembers choosing.

So a rule is a set of subjects, an effect, and a STOP CONDITION, and the stop
condition is mandatory. There is no way to express an endless rule here: that
is what the watch list is for, and making the distinction structural rather
than advisory is the point of a separate module.

The four endings, and why only four
───────────────────────────────────
A condition language is where this kind of feature goes wrong — it grows an
expression parser, then operator precedence, then a debugger. These four cover
what the requirement names and what an analyst actually asks for, and each one
is a fact the platform already knows:

  at_time       a wall-clock instant. "Until Friday 18:00."
  after_hits    the rule has matched this many events. "Until it fires five
                times" — an analyst sampling a suspicion, not monitoring it.
  on_confirmed  an analyst confirmed an incident for a subject. The rule was
                a question and it has been answered.
  on_cleared    an analyst cleared it by hand. The explicit ending.

Anything more expressive belongs in the detection config, not in a rule an
analyst writes at 2am.

Expiry is evaluated, never scheduled
────────────────────────────────────
There is no timer and no sweeper thread. `evaluate()` is called on the hot
path anyway and decides there and then whether the rule is still live, so a
rule cannot outlive its condition because a background job failed to run.
The cost is one comparison per rule per event, and the rule count is capped.

A rule that has ended STAYS in the register, marked, with the reason and the
timestamp. Deleting it would erase the fact that the decision was ever made,
which is the thing an audit asks about.

The effect is bounded, deliberately
───────────────────────────────────
Same ceiling as the watch list, and for the same reason: a boost of 1.0 forces
every event from the subject to maximum severity, which is a firehose rather
than a rule. Boosts do not stack with the watch list either — the strongest
applies — because two ordinary 0.10 decisions silently producing a 0.20
escalation is an escalation nobody chose.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

# What a rule does while it is live. Deliberately short: a rule that can do
# anything is a rule nobody can review.
ACTIONS = ("watch", "suppress")

# How a rule ends. One is mandatory.
CONDITIONS = ("at_time", "after_hits", "on_confirmed", "on_cleared")

# Why a rule is not live, when it is not.
INACTIVE_REASONS = ("disabled", "not_started", "expired_time", "expired_hits",
                    "expired_confirmed", "cleared")

DEFAULT_BOOST = 0.10
# Matches ueba_watchlist.MAX_BOOST on purpose. A rule is a smaller decision
# than a watch-list entry, not a bigger one, so it may not reach further.
MAX_BOOST = 0.50

# A suppression cannot zero a score outright: an analyst silencing an entity
# for a week should lower its noise, not blind the platform to a real incident
# on it. The floor is what stops "suppress" becoming "ignore".
MAX_SUPPRESS = 0.50

MAX_RULES = 500
MAX_SUBJECTS = 1000
# A rule nobody ever ends is the failure this module exists to prevent, so
# at_time is capped: an analyst who wants longer is describing a watch-list
# entry or a config change, and should say so.
MAX_WINDOW_DAYS = 365

_lock = threading.Lock()
_cache: dict = {}


def _norm(v) -> str:
    return str(v or "").strip().casefold()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(v) -> "datetime | None":
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    s = str(v or "").strip()
    if not s:
        return None
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def rule_id(name: str, subjects) -> str:
    """Deterministic, so re-creating the same rule updates it."""
    basis = "%s|%s" % (_norm(name), ",".join(sorted(_norm(s) for s in subjects)))
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]


# ── construction and validation ─────────────────────────────────────────────

def build(name: str, subjects, condition: str, *,
          action: str = "watch", boost=None, until=None, hits=None,
          starts_at=None, reason: str = "", created_by=None) -> tuple:
    """(rule, errors). A rule with no valid ending is refused, not defaulted.

    Refused rather than given a default ending, because a default ending is a
    guess about how long an analyst meant to watch someone — and the whole
    requirement is that the ending is SPECIFIED.
    """
    errors = []
    nm = str(name or "").strip()
    if not nm:
        errors.append("a rule needs a name")
    if len(nm) > 120:
        errors.append("the name is too long")

    subs = []
    seen = set()
    for s in (subjects or []):
        v = _norm(s)
        if not v or v in seen:
            continue
        if v in ("*", "**"):
            errors.append("%r matches every entity, which is not a rule for a "
                          "set of users" % v)
            continue
        seen.add(v)
        subs.append(v)
    if not subs:
        errors.append("a rule needs at least one subject")
    if len(subs) > MAX_SUBJECTS:
        errors.append("a rule may not name more than %d subjects" % MAX_SUBJECTS)
        subs = subs[:MAX_SUBJECTS]

    act = _norm(action) or "watch"
    if act not in ACTIONS:
        errors.append("action must be one of %s" % list(ACTIONS))

    cond = _norm(condition)
    if cond not in CONDITIONS:
        errors.append("condition must be one of %s" % list(CONDITIONS))

    expires_at = None
    hit_limit = None
    if cond == "at_time":
        expires_at = parse_time(until)
        if expires_at is None:
            errors.append("condition at_time needs `until` as an ISO timestamp")
        else:
            start = parse_time(starts_at) or now_utc()
            if expires_at <= start:
                errors.append("`until` is not after the start, so the rule "
                              "would never be live")
            elif expires_at - start > timedelta(days=MAX_WINDOW_DAYS):
                errors.append("a window longer than %d days is not a "
                              "time-bound rule — use a watch-list entry"
                              % MAX_WINDOW_DAYS)
    elif cond == "after_hits":
        try:
            hit_limit = int(hits)
        except (TypeError, ValueError):
            hit_limit = 0
        if hit_limit < 1:
            errors.append("condition after_hits needs `hits` as a positive "
                          "integer")

    try:
        b = float(boost if boost is not None else DEFAULT_BOOST)
    except (TypeError, ValueError):
        b = DEFAULT_BOOST
    ceiling = MAX_SUPPRESS if act == "suppress" else MAX_BOOST
    b = max(0.0, min(abs(b), ceiling))

    rule = {
        "id": rule_id(nm, subs),
        "name": nm,
        "subjects": subs,
        "action": act,
        "boost": round(b, 4),
        "condition": cond,
        "starts_at": (parse_time(starts_at) or now_utc()).isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "hit_limit": hit_limit,
        "hits": 0,
        "enabled": True,
        "ended_at": None,
        "ended_reason": "",
        "reason": str(reason or "")[:500],
        "created_at": now_utc().isoformat(),
        "created_by": created_by or None,
    }
    return (None if errors else rule), errors


def _clean(raw) -> "dict | None":
    """One stored rule, normalised, or None if unusable."""
    if not isinstance(raw, dict):
        return None
    r, errs = build(
        raw.get("name") or "", raw.get("subjects") or [],
        raw.get("condition") or "", action=raw.get("action") or "watch",
        boost=raw.get("boost"), until=raw.get("expires_at"),
        hits=raw.get("hit_limit"), starts_at=raw.get("starts_at"),
        reason=raw.get("reason") or "", created_by=raw.get("created_by"))
    if r is None:
        return None
    # Runtime state survives the round trip; build() only validates shape.
    r["id"] = raw.get("id") or r["id"]
    try:
        r["hits"] = max(0, int(raw.get("hits") or 0))
    except (TypeError, ValueError):
        r["hits"] = 0
    r["enabled"] = bool(raw.get("enabled", True))
    r["ended_at"] = raw.get("ended_at") or None
    r["ended_reason"] = str(raw.get("ended_reason") or "")[:200]
    r["created_at"] = raw.get("created_at") or r["created_at"]
    return r


# ── the register, same contract as the watch list ───────────────────────────

def _read(path) -> list:
    p = Path(path)
    try:
        st = p.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None
    key = str(p)
    hit = _cache.get(key)
    if hit and hit["stamp"] == stamp:
        return hit["rules"]

    rules = []
    if stamp is not None:
        try:
            raw = json.loads(p.read_text(encoding="utf-8") or "[]")
            if isinstance(raw, dict):
                raw = raw.get("rules") or list(raw.values())
            for item in (raw or [])[:MAX_RULES]:
                c = _clean(item)
                if c:
                    rules.append(c)
        except Exception as ex:
            print("[rules] failed to read %s: %s" % (p, ex))
            rules = []
    _cache[key] = {"stamp": stamp, "rules": rules}
    return rules


def rules(path) -> list:
    with _lock:
        return [dict(r) for r in _read(path)]


def save(path, items) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(list(items or [])[:MAX_RULES], indent=2,
                              ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)
    with _lock:
        _cache.pop(str(p), None)


def add(path, rule: dict) -> tuple:
    """(rule, error). Re-adding an identical rule replaces it."""
    with _lock:
        current = [dict(r) for r in _read(path)]
    if len(current) >= MAX_RULES:
        return None, "the register is full (%d rules)" % MAX_RULES
    kept = [r for r in current if r["id"] != rule["id"]]
    kept.append(rule)
    save(path, kept)
    return rule, ""


def remove(path, rid: str) -> bool:
    with _lock:
        current = [dict(r) for r in _read(path)]
    kept = [r for r in current if r["id"] != str(rid)]
    if len(kept) == len(current):
        return False
    save(path, kept)
    return True


def end(path, rid: str, reason: str = "cleared", when=None) -> bool:
    """Mark a rule ended. Kept in the register, not deleted.

    Kept because deleting it would erase the fact that the decision was ever
    made, which is what an audit asks about.
    """
    with _lock:
        current = [dict(r) for r in _read(path)]
    touched = False
    for r in current:
        if r["id"] == str(rid) and not r["ended_at"]:
            r["ended_at"] = (parse_time(when) or now_utc()).isoformat()
            r["ended_reason"] = str(reason or "cleared")[:200]
            touched = True
    if touched:
        save(path, current)
    return touched


def bump(path, rid: str, by: int = 1) -> int:
    """Record that a rule matched. Returns its new hit count.

    Persisted rather than held in memory: `after_hits` has to survive a
    restart or a rule set to end after five hits would end after five hits
    *since the last restart*, which is not the same rule.
    """
    with _lock:
        current = [dict(r) for r in _read(path)]
    out = 0
    for r in current:
        if r["id"] == str(rid):
            r["hits"] = max(0, int(r.get("hits") or 0)) + max(1, int(by))
            out = r["hits"]
    if out:
        save(path, current)
    return out


# ── matching and evaluation ─────────────────────────────────────────────────

def matches_subject(rule: dict, entity: str) -> str:
    """The subject pattern this entity matches, or "".

    fnmatch, so "the contractors" can be `contractor-*` rather than a list
    somebody has to maintain. Typed entity keys are tested whole and with the
    namespace stripped, so a rule written as `jane.doe` still matches
    `person:jane.doe` — an analyst names a person, not an internal key format.
    """
    e = _norm(entity)
    if not e:
        return ""
    probes = [e]
    if ":" in e:
        probes.append(e.split(":", 1)[1])
    for pat in (rule.get("subjects") or []):
        for probe in probes:
            if pat == probe or fnmatch.fnmatchcase(probe, pat):
                return pat
    return ""


def evaluate(rule: dict, now=None, confirmed=False) -> dict:
    """{"active", "reason", "ends"} — is this rule live at this instant?

    Evaluated, not scheduled. There is no sweeper thread, so a rule cannot
    outlive its condition because a background job failed to run.
    """
    ts = parse_time(now) or now_utc()
    out = {"active": False, "reason": "", "ends": ""}

    if not rule.get("enabled", True):
        out["reason"] = "disabled"
        return out
    if rule.get("ended_at"):
        out["reason"] = rule.get("ended_reason") or "cleared"
        return out

    start = parse_time(rule.get("starts_at"))
    if start and ts < start:
        out["reason"] = "not_started"
        out["ends"] = "starts %s" % start.isoformat()
        return out

    cond = rule.get("condition")
    if cond == "at_time":
        exp = parse_time(rule.get("expires_at"))
        if exp is None:
            # A time-bound rule with no parseable expiry is not live. The
            # conservative direction: the alternative is a rule that runs
            # forever because its own ending could not be read.
            out["reason"] = "expired_time"
            return out
        if ts >= exp:
            out["reason"] = "expired_time"
            out["ends"] = exp.isoformat()
            return out
        out.update(active=True, reason="live", ends=exp.isoformat())
        return out

    if cond == "after_hits":
        limit = int(rule.get("hit_limit") or 0)
        hits = int(rule.get("hits") or 0)
        if limit and hits >= limit:
            out["reason"] = "expired_hits"
            out["ends"] = "%d of %d hits" % (hits, limit)
            return out
        out.update(active=True, reason="live",
                   ends="%d of %d hits" % (hits, limit))
        return out

    if cond == "on_confirmed":
        if confirmed:
            out["reason"] = "expired_confirmed"
            out["ends"] = "an incident was confirmed"
            return out
        out.update(active=True, reason="live",
                   ends="until an incident is confirmed")
        return out

    # on_cleared — live until somebody ends it, which end() records.
    out.update(active=True, reason="live", ends="until cleared by hand")
    return out


def apply(path, entity: str, now=None, confirmed=False,
          record=True) -> "dict | None":
    """The strongest live rule affecting this entity, or None.

    STRONGEST, not the sum. Two ordinary 0.10 rules must not silently produce
    a 0.20 escalation that no analyst chose — the same reason the watch list
    takes the highest entry rather than stacking.

    A `suppress` rule wins over a `watch` rule of equal weight: an analyst who
    has said "this is expected until Friday" has made the more specific and
    more recent statement about the entity.
    """
    live = []
    for r in rules(path):
        pat = matches_subject(r, entity)
        if not pat:
            continue
        verdict = evaluate(r, now, confirmed)
        if verdict["active"]:
            live.append((r, pat, verdict))

    if not live:
        return None

    # suppress first, then by boost
    live.sort(key=lambda x: (x[0]["action"] != "suppress", -x[0]["boost"]))
    rule, pat, verdict = live[0]

    if record:
        try:
            new_hits = bump(path, rule["id"])
            # Ending it the moment the condition is met, rather than on the
            # NEXT event: a rule set to end after five hits must not apply on
            # its sixth.
            limit = int(rule.get("hit_limit") or 0)
            if rule.get("condition") == "after_hits" and limit and new_hits >= limit:
                end(path, rule["id"], "expired_hits", now)
        except Exception:
            pass

    signed = -rule["boost"] if rule["action"] == "suppress" else rule["boost"]
    return {
        "id": rule["id"],
        "name": rule["name"],
        "action": rule["action"],
        "boost": round(signed, 4),
        "matched": pat,
        "condition": rule["condition"],
        "ends": verdict["ends"],
        "reason": rule.get("reason") or "",
    }


def sweep(path, now=None, confirmed_subjects=None) -> dict:
    """Mark every rule whose condition has been met. Housekeeping, not required.

    Expiry is already decided at evaluation time, so this changes no verdict.
    What it does is make the register honest for a human reading it, instead of
    showing rules as live that evaluate() would refuse.
    """
    ts = parse_time(now) or now_utc()
    conf = {_norm(s) for s in (confirmed_subjects or [])}
    out = {"ended": [], "live": 0, "already_ended": 0}
    with _lock:
        current = [dict(r) for r in _read(path)]
    changed = False
    for r in current:
        if r.get("ended_at"):
            out["already_ended"] += 1
            continue
        hit = any(matches_subject(r, s) for s in conf) if conf else False
        v = evaluate(r, ts, confirmed=hit)
        if not v["active"] and v["reason"] not in ("not_started", "disabled"):
            r["ended_at"] = ts.isoformat()
            r["ended_reason"] = v["reason"]
            out["ended"].append({"id": r["id"], "name": r["name"],
                                 "reason": v["reason"]})
            changed = True
        elif v["active"]:
            out["live"] += 1
    if changed:
        save(path, current)
    return out


def status(path=None) -> dict:
    items = rules(path) if path else []
    ts = now_utc()
    live = [r for r in items if evaluate(r, ts)["active"]]
    return {
        "actions": list(ACTIONS),
        "conditions": list(CONDITIONS),
        "max_boost": MAX_BOOST,
        "max_suppress": MAX_SUPPRESS,
        "max_window_days": MAX_WINDOW_DAYS,
        "total": len(items),
        "live": len(live),
        "ended": len([r for r in items if r.get("ended_at")]),
        "design_note": (
            "Every rule MUST carry a stop condition — there is no way to "
            "express an endless one here, which is what the watch list is "
            "for. The ending is evaluated on each event rather than swept by "
            "a timer, so a rule cannot outlive its condition because a "
            "background job failed. An ended rule stays in the register, "
            "marked with the reason, because deleting it would erase the fact "
            "that the decision was made."),
        "effect_note": (
            "Effects are bounded at the same ceiling as the watch list and do "
            "not stack: the strongest live rule applies, because two ordinary "
            "0.10 decisions silently producing a 0.20 escalation is an "
            "escalation nobody chose. A suppression cannot zero a score "
            "either — silencing an entity should lower its noise, not blind "
            "the platform to a real incident on it."),
    }


# ── selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    import tempfile

    failures = []
    checked = []

    def ok(label, cond):
        # Counted, not compared against a literal — the same trap
        # ueba_entities had: checks added after a hardcoded total ran but were
        # never reported.
        checked.append(label)
        if not cond:
            failures.append(label)

    T0 = datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)

    # FREEZE THE CLOCK for the duration of the suite.
    #
    # T0 is a fixed instant, and the fixtures evaluate rules at fixed offsets
    # from it — but build() defaults a rule's `starts_at` to the REAL now, and
    # evaluate() treats a rule as `not_started` before that. So whether a
    # check passed depended on the wall clock: the suite was only valid while
    # real UTC sat inside the hour straddling T0. Two separate checks failed
    # as the day moved past it, at different times, which read like two
    # unrelated bugs.
    #
    # Pinning `starts_at=T0` at each call site would need 27 edits and would
    # go stale the moment someone added a 28th. Freezing the clock fixes every
    # one of them at once and makes the suite deterministic.
    global now_utc
    _real_now_utc = now_utc
    now_utc = lambda: T0

    def at(h):
        return T0 + timedelta(hours=h)

    # ── build: the ending is mandatory ──
    r, e = build("no ending", ["alice"], "")
    ok("a rule with no condition is refused", r is None and e)
    ok("and the refusal names the options", "condition must be one of" in e[0])
    r, e = build("bad ending", ["alice"], "whenever")
    ok("an unknown condition is refused", r is None)

    r, e = build("no subjects", [], "on_cleared")
    ok("a rule with no subjects is refused", r is None)
    ok("and says so", any("at least one subject" in x for x in e))
    r, e = build("everyone", ["*"], "on_cleared")
    ok("a match-everything subject is refused", r is None)
    ok("and explains it is not a set of users",
       any("not a rule for a set of users" in x for x in e))
    r, e = build("", ["alice"], "on_cleared")
    ok("a nameless rule is refused", r is None)

    # at_time
    r, e = build("until friday", ["alice"], "at_time", until=at(48),
                 starts_at=T0)
    ok("a time-bound rule builds", r is not None and not e)
    ok("the expiry is stored", r["expires_at"] == at(48).isoformat())
    r, e = build("no until", ["alice"], "at_time")
    ok("at_time without `until` is refused", r is None)
    ok("and says what is missing", any("needs `until`" in x for x in e))
    r, e = build("backwards", ["alice"], "at_time", until=at(-1), starts_at=T0)
    ok("an expiry before the start is refused", r is None)
    ok("and says it would never be live",
       any("never be live" in x for x in e))
    r, e = build("forever", ["alice"], "at_time",
                 until=T0 + timedelta(days=400), starts_at=T0)
    ok("a window longer than a year is refused", r is None)
    ok("and points at the watch list", any("watch-list" in x for x in e))

    # after_hits
    r, e = build("sample", ["alice"], "after_hits", hits=3)
    ok("a hit-bound rule builds", r is not None)
    ok("the limit is stored", r["hit_limit"] == 3)
    ok("hits start at zero", r["hits"] == 0)
    for bad in (0, -1, None, "x"):
        rr, ee = build("x", ["a"], "after_hits", hits=bad)
        ok("after_hits rejects hits=%r" % bad, rr is None)

    # boost ceilings
    r, _ = build("loud", ["alice"], "on_cleared", boost=99)
    ok("a boost is capped at the ceiling", r["boost"] == MAX_BOOST)
    r, _ = build("quiet", ["alice"], "on_cleared", action="suppress", boost=99)
    ok("a suppression is capped too", r["boost"] == MAX_SUPPRESS)
    r, _ = build("neg", ["alice"], "on_cleared", boost=-0.2)
    ok("a negative boost is read as its magnitude", r["boost"] == 0.2)
    r, _ = build("default", ["alice"], "on_cleared")
    ok("the default boost applies", r["boost"] == DEFAULT_BOOST)
    r, _ = build("junk", ["alice"], "on_cleared", boost="abc")
    ok("a junk boost falls back to the default", r["boost"] == DEFAULT_BOOST)

    # id determinism
    a, _ = build("same", ["x", "y"], "on_cleared")
    b, _ = build("same", ["y", "x"], "on_cleared")
    ok("the id ignores subject order", a["id"] == b["id"])
    c, _ = build("other", ["x", "y"], "on_cleared")
    ok("a different name is a different rule", c["id"] != a["id"])
    ok("subjects are folded and deduplicated",
       build("d", ["A", "a", "b"], "on_cleared")[0]["subjects"] == ["a", "b"])

    # ── subject matching ──
    rule, _ = build("contractors", ["contractor-*", "jane.doe"], "on_cleared")
    ok("an exact subject matches", matches_subject(rule, "jane.doe") == "jane.doe")
    ok("case does not matter", matches_subject(rule, "JANE.DOE") == "jane.doe")
    ok("a wildcard subject matches",
       matches_subject(rule, "contractor-17") == "contractor-*")
    ok("an unlisted entity does not match", matches_subject(rule, "bob") == "")
    ok("a typed key matches on the bare name",
       matches_subject(rule, "person:jane.doe") == "jane.doe")
    ok("a typed wildcard matches too",
       matches_subject(rule, "person:contractor-3") == "contractor-*")
    ok("an empty entity matches nothing", matches_subject(rule, "") == "")
    ok("a partial name does not match", matches_subject(rule, "jane") == "")

    # ── evaluate ──
    tr, _ = build("window", ["alice"], "at_time", until=at(24), starts_at=T0)
    ok("a time rule is live inside its window", evaluate(tr, at(1))["active"])
    ok("and reports when it ends", evaluate(tr, at(1))["ends"] == at(24).isoformat())
    ok("it is not live after its window", not evaluate(tr, at(25))["active"])
    ok("and says why", evaluate(tr, at(25))["reason"] == "expired_time")
    ok("it is not live before its start", not evaluate(tr, at(-1))["active"])
    ok("and says that too", evaluate(tr, at(-1))["reason"] == "not_started")
    ok("exactly at the expiry it is over", not evaluate(tr, at(24))["active"])

    broken = dict(tr, expires_at="not a date")
    ok("a time rule whose expiry cannot be read is NOT live",
       not evaluate(broken, at(1))["active"])

    hr, _ = build("sample", ["alice"], "after_hits", hits=2)
    ok("a hit rule starts live", evaluate(hr)["active"])
    ok("and reports progress", "0 of 2 hits" in evaluate(hr)["ends"])
    ok("it is over at the limit", not evaluate(dict(hr, hits=2))["active"])
    ok("and past it", not evaluate(dict(hr, hits=9))["active"])
    ok("and says why", evaluate(dict(hr, hits=2))["reason"] == "expired_hits")

    cr, _ = build("question", ["alice"], "on_confirmed")
    ok("a confirm rule is live until confirmed", evaluate(cr)["active"])
    ok("and ends on confirmation", not evaluate(cr, confirmed=True)["active"])
    ok("and says why",
       evaluate(cr, confirmed=True)["reason"] == "expired_confirmed")

    mr, _ = build("manual", ["alice"], "on_cleared")
    ok("a manual rule is live", evaluate(mr)["active"])
    ok("a disabled rule is not live",
       not evaluate(dict(mr, enabled=False))["active"])
    ok("an ended rule is not live",
       not evaluate(dict(mr, ended_at=T0.isoformat(),
                         ended_reason="cleared"))["active"])
    ok("and reports the recorded reason",
       evaluate(dict(mr, ended_at=T0.isoformat(),
                     ended_reason="cleared"))["reason"] == "cleared")

    # ── the register and apply() ──
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "rules.json"
        ok("a missing register is empty", rules(path) == [])
        ok("apply on nothing is None", apply(path, "alice") is None)

        r1, _ = build("watch contractors", ["contractor-*"], "at_time",
                      until=at(24), starts_at=T0, boost=0.2,
                      reason="onboarding review")
        got, err = add(path, r1)
        ok("a rule is added", got and not err)
        ok("and read back", len(rules(path)) == 1)

        hit = apply(path, "contractor-4", now=at(1), record=False)
        ok("a subject is matched", hit and hit["name"] == "watch contractors")
        ok("the boost is positive for a watch", hit["boost"] == 0.2)
        ok("the matched pattern is reported", hit["matched"] == "contractor-*")
        ok("the ending is reported", hit["ends"] == at(24).isoformat())
        ok("the analyst's reason is carried", hit["reason"] == "onboarding review")
        ok("a non-subject is unaffected",
           apply(path, "bob", now=at(1), record=False) is None)
        ok("outside the window nothing applies",
           apply(path, "contractor-4", now=at(25), record=False) is None)

        # strongest wins, no stacking
        r2, _ = build("also watch", ["contractor-4"], "on_cleared", boost=0.35)
        add(path, r2)
        hit = apply(path, "contractor-4", now=at(1), record=False)
        ok("the strongest rule applies, not the sum", hit["boost"] == 0.35)

        # suppression beats an equal watch
        r3, _ = build("expected", ["contractor-4"], "at_time", until=at(24),
                      starts_at=T0, action="suppress", boost=0.35)
        add(path, r3)
        hit = apply(path, "contractor-4", now=at(1), record=False)
        ok("a suppression wins over a watch of equal weight",
           hit["action"] == "suppress")
        ok("and its boost is negative", hit["boost"] == -0.35)

        # hit counting and self-ending
        path2 = Path(td) / "r2.json"
        # Explicit, though the frozen clock above now makes it redundant:
        # this is the check whose failure led to the clock being frozen.
        hr2, _ = build("three strikes", ["alice"], "after_hits", hits=3,
                       starts_at=T0)
        add(path2, hr2)
        seen = []
        for i in range(5):
            seen.append(apply(path2, "alice", now=at(i)) is not None)
        ok("a hit rule applies exactly its limit of times",
           seen == [True, True, True, False, False], )
        stored = rules(path2)[0]
        ok("the hits are persisted", stored["hits"] >= 3)
        ok("and the rule ended itself", stored["ended_at"] is not None)
        ok("with the right reason", stored["ended_reason"] == "expired_hits")

        # end / remove
        path3 = Path(td) / "r3.json"
        mr3, _ = build("manual", ["alice"], "on_cleared")
        add(path3, mr3)
        ok("it applies before being cleared",
           apply(path3, "alice", record=False) is not None)
        ok("ending it reports success", end(path3, mr3["id"], "cleared"))
        ok("it no longer applies", apply(path3, "alice", record=False) is None)
        ok("but it is still in the register", len(rules(path3)) == 1)
        ok("ending it twice is False", not end(path3, mr3["id"]))
        ok("ending an unknown rule is False", not end(path3, "nope"))
        ok("removing it works", remove(path3, mr3["id"]))
        ok("and it is gone", rules(path3) == [])
        ok("removing nothing is False", not remove(path3, "nope"))

        # re-adding the same rule replaces rather than duplicates
        path4 = Path(td) / "r4.json"
        x1, _ = build("dup", ["alice"], "on_cleared", boost=0.1)
        x2, _ = build("dup", ["alice"], "on_cleared", boost=0.4)
        add(path4, x1)
        add(path4, x2)
        ok("re-adding an identical rule replaces it", len(rules(path4)) == 1)
        ok("with the newer values", rules(path4)[0]["boost"] == 0.4)

        # sweep
        path5 = Path(td) / "r5.json"
        s1, _ = build("gone", ["alice"], "at_time", until=at(1), starts_at=T0)
        s2, _ = build("still", ["bob"], "on_cleared")
        s3, _ = build("asked", ["carol"], "on_confirmed")
        add(path5, s1); add(path5, s2); add(path5, s3)
        res = sweep(path5, now=at(9))
        ok("sweep ends an expired rule", len(res["ended"]) == 1)
        ok("and names it", res["ended"][0]["name"] == "gone")
        ok("and leaves the live ones", res["live"] == 2)
        ok("the ending is persisted",
           any(r["ended_reason"] == "expired_time" for r in rules(path5)))
        res = sweep(path5, now=at(10))
        ok("sweeping again ends nothing new", res["ended"] == [])
        ok("and counts the already-ended", res["already_ended"] == 1)
        res = sweep(path5, now=at(11), confirmed_subjects=["carol"])
        ok("a confirmation ends an on_confirmed rule",
           any(x["reason"] == "expired_confirmed" for x in res["ended"]))

        # corrupt and junk input
        path6 = Path(td) / "r6.json"
        path6.write_text("{not json", encoding="utf-8")
        ok("a corrupt register reads empty", rules(path6) == [])
        path6.write_text(json.dumps([{"name": "x"}, "junk", None,
                                     {"name": "ok", "subjects": ["a"],
                                      "condition": "on_cleared"}]),
                         encoding="utf-8")
        ok("only the usable rule survives",
           [r["name"] for r in rules(path6)] == ["ok"])
        path6.write_text(json.dumps({"rules": [
            {"name": "wrapped", "subjects": ["a"],
             "condition": "on_cleared"}]}), encoding="utf-8")
        ok("a wrapped register is tolerated", len(rules(path6)) == 1)

        st = status(path5)
        ok("status counts the rules", st["total"] == 3)
        ok("status counts the live ones", st["live"] >= 1)
        ok("status lists the conditions", st["conditions"] == list(CONDITIONS))
        ok("status explains the mandatory ending",
           "no way to express an endless one" in st["design_note"])
        ok("status explains the no-stacking rule",
           "escalation nobody chose" in st["effect_note"])

    # Clock restored before the summary, which both return paths share.
    now_utc = _real_now_utc

    total = len(checked)
    if failures:
        print("ueba_rules selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_rules selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
