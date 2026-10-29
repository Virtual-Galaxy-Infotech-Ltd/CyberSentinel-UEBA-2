#!/usr/bin/env python3
"""
ueba_risk_history.py
────────────────────
CyberSentinel UEBA — a standing risk record per entity (RFP SN 48).

SN 48 asks that a user or device previously involved in malicious behaviour
stays flagged. Nothing in the platform could answer that. The only verdict an
analyst could record was the negative one — marking an alert a false positive —
so "this account was involved in a confirmed incident last month" existed
nowhere except in the analyst's memory, and the next alert on that account
looked exactly like the first.

Two halves, both here:

  1. A confirmed-incident ledger. The positive counterpart to false-positive
     marking: an analyst confirms an alert as genuinely malicious and it is
     recorded against the entity, with who confirmed it and when. Retraction is
     a soft delete, because analysts revise verdicts and a risk record that
     cannot be corrected will stop being trusted and then stop being used.

  2. A standing risk derived from that ledger, which the engine reads on every
     event. It contributes an additive boost in exactly the way a watch-list
     hit does (see ueba_watchlist and fuse_scores): it lowers the bar at which
     that entity's behaviour becomes visible, rather than relabelling alerts
     that would have fired anyway.

Why risk decays, and why it never reaches zero
──────────────────────────────────────────────
An incident from eighteen months ago should not weigh the same as one from
Tuesday, or every entity that has ever had a bad day ends up permanently at the
top of the queue and the ranking stops meaning anything. Each incident's
contribution therefore halves every `half_life_days`.

But "stays flagged" is the actual requirement, so decay governs the BOOST only.
As long as an entity has one unretracted incident it keeps a prior: the reason
string is always produced, so an analyst looking at the entity always learns it
has history, even when the numerical contribution has decayed to nothing. The
two are deliberately separate — how much we amplify, and whether we disclose.

Storage
───────
Its own SQLite file, in WAL mode, because two processes use it: the dashboard
writes confirmations and the engine reads standing risk on the hot path. It is
NOT in the profile store, which holds one connection and one entity row per
username and whose rows are read positionally.

Reads are served from an in-memory rollup refreshed only when the file's mtime
or size changes — the same approach ueba_watchlist takes, for the same reason:
the engine asks about every event and confirmed incidents are rare, so the
whole ledger fits in memory many times over.
"""

# Annotations as strings, so this module imports on the 3.9 that the dev boxes
# still run as well as the 3.12 on the server. The `X | None` style matches the
# rest of the codebase; without this it is a runtime error before 3.10.
from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

SEVERITIES = ("low", "medium", "high", "critical")

# What each severity contributes to standing risk before decay.
SEVERITY_WEIGHT = {"low": 0.15, "medium": 0.35, "high": 0.65, "critical": 1.0}

DEFAULT_HALF_LIFE_DAYS = 90.0
DEFAULT_MAX_BOOST = 0.25
# Hard ceiling, matching ueba_watchlist.MAX_BOOST's reasoning: an operator
# should not be able to configure the detector into calling everything an alert.
MAX_BOOST = 0.50

_lock = threading.Lock()
_cache: dict = {}        # path -> {"sig": (mtime, size), "roll": {...}}


# ── helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(v) -> str:
    return str(v or "").strip().lower()


def _parse(ts) -> datetime | None:
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _connect(path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    con = sqlite3.connect(path, timeout=10.0)
    con.row_factory = sqlite3.Row
    # WAL so the engine's reads are never blocked by a dashboard write.
    try:
        con.execute("PRAGMA journal_mode=WAL")
    except sqlite3.DatabaseError:
        pass
    con.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id           TEXT PRIMARY KEY,
            entity       TEXT NOT NULL,
            entity_type  TEXT NOT NULL DEFAULT 'user',
            event_id     TEXT,
            campaign_id  TEXT,
            severity     TEXT NOT NULL,
            score        REAL,
            summary      TEXT,
            confirmed_by TEXT,
            confirmed_at TEXT NOT NULL,
            retracted_at TEXT,
            retracted_by TEXT
        )
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_inc_entity "
                "ON incidents(entity, retracted_at)")
    # One confirmation per alert. Without this, double-clicking Confirm books
    # the same incident twice and doubles that entity's standing risk.
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_inc_event "
                "ON incidents(entity, event_id) WHERE event_id IS NOT NULL")
    con.commit()
    return con


def _sig(path):
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


# ── writes ───────────────────────────────────────────────────────────────────

def confirm(path, entity: str, severity: str = "high", event_id: str = "",
            campaign_id: str = "", score=None, summary: str = "",
            confirmed_by: str = "", entity_type: str = "user") -> dict:
    """Record an entity as involved in confirmed malicious behaviour.

    Idempotent per (entity, event_id): confirming the same alert twice updates
    the existing record rather than inflating the entity's history.
    """
    entity = _norm(entity)
    if not entity or entity == "unknown":
        raise ValueError("an incident needs an entity")
    severity = _norm(severity) or "high"
    if severity not in SEVERITIES:
        raise ValueError("severity must be one of %s" % (SEVERITIES,))
    entity_type = _norm(entity_type) or "user"

    rec = {
        "id":           "inc-" + uuid.uuid4().hex[:12],
        "entity":       entity,
        "entity_type":  entity_type,
        "event_id":     str(event_id or "") or None,
        "campaign_id":  str(campaign_id or "") or None,
        "severity":     severity,
        "score":        None if score in (None, "") else float(score),
        "summary":      str(summary or "")[:1000],
        "confirmed_by": str(confirmed_by or ""),
        "confirmed_at": _now(),
    }
    con = _connect(path)
    try:
        existing = None
        if rec["event_id"]:
            existing = con.execute(
                "SELECT id FROM incidents WHERE entity = ? AND event_id = ?",
                (entity, rec["event_id"])).fetchone()
        if existing:
            rec["id"] = existing["id"]
            con.execute("""UPDATE incidents SET severity=?, score=?, summary=?,
                             confirmed_by=?, confirmed_at=?, campaign_id=?,
                             entity_type=?, retracted_at=NULL, retracted_by=NULL
                           WHERE id=?""",
                        (rec["severity"], rec["score"], rec["summary"],
                         rec["confirmed_by"], rec["confirmed_at"],
                         rec["campaign_id"], rec["entity_type"], rec["id"]))
        else:
            con.execute("""INSERT INTO incidents
                (id, entity, entity_type, event_id, campaign_id, severity,
                 score, summary, confirmed_by, confirmed_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (rec["id"], rec["entity"], rec["entity_type"], rec["event_id"],
                 rec["campaign_id"], rec["severity"], rec["score"],
                 rec["summary"], rec["confirmed_by"], rec["confirmed_at"]))
        con.commit()
    finally:
        con.close()
    _invalidate(path)
    return rec


def retract(path, incident_id: str, retracted_by: str = "") -> bool:
    """Withdraw a confirmation. Soft delete — the record and who changed it stay."""
    con = _connect(path)
    try:
        n = con.execute(
            "UPDATE incidents SET retracted_at=?, retracted_by=? "
            "WHERE id=? AND retracted_at IS NULL",
            (_now(), str(retracted_by or ""), str(incident_id))).rowcount
        con.commit()
    finally:
        con.close()
    if n:
        _invalidate(path)
    return bool(n)


# ── reads ────────────────────────────────────────────────────────────────────

def incidents(path, entity: str = "", include_retracted: bool = False) -> list:
    """Incident records, newest first. All entities if `entity` is empty."""
    if not os.path.exists(path):
        return []
    con = _connect(path)
    try:
        sql = "SELECT * FROM incidents WHERE 1=1"
        args: list = []
        if entity:
            sql += " AND entity = ?"
            args.append(_norm(entity))
        if not include_retracted:
            sql += " AND retracted_at IS NULL"
        sql += " ORDER BY confirmed_at DESC"
        return [dict(r) for r in con.execute(sql, args)]
    finally:
        con.close()


def _invalidate(path):
    with _lock:
        _cache.pop(str(path), None)


def _rollup(path) -> dict:
    """entity -> {count, worst, last_at, weight_sum}, cached on file signature."""
    key = str(path)
    sig = _sig(path)
    with _lock:
        hit = _cache.get(key)
        if hit and hit["sig"] == sig:
            return hit["roll"]

    roll: dict = {}
    if sig is not None:
        con = _connect(path)
        try:
            for r in con.execute(
                    "SELECT entity, entity_type, severity, confirmed_at "
                    "FROM incidents WHERE retracted_at IS NULL"):
                e = roll.setdefault(r["entity"], {
                    "entity": r["entity"], "entity_type": r["entity_type"],
                    "count": 0, "worst": "low", "last_at": "", "items": []})
                e["count"] += 1
                if (SEVERITY_WEIGHT.get(r["severity"], 0)
                        > SEVERITY_WEIGHT.get(e["worst"], 0)):
                    e["worst"] = r["severity"]
                if str(r["confirmed_at"]) > e["last_at"]:
                    e["last_at"] = str(r["confirmed_at"])
                e["items"].append((r["severity"], str(r["confirmed_at"])))
        finally:
            con.close()

    with _lock:
        _cache[key] = {"sig": sig, "roll": roll}
    return roll


def standing(path, entity: str, cfg: dict | None = None) -> dict:
    """This entity's standing risk from confirmed history.

    Returns zeros for an entity with no history, so callers need no special
    case. `boost` decays; `reason` does not — see the module docstring.
    """
    cfg = cfg or {}
    out = {"incidents": 0, "risk": 0.0, "boost": 0.0, "worst_severity": None,
           "last_incident_at": None, "reason": None}
    e = _rollup(path).get(_norm(entity))
    if not e:
        return out

    half_life = float(cfg.get("half_life_days") or DEFAULT_HALF_LIFE_DAYS)
    half_life = max(1.0, half_life)
    max_boost = min(float(cfg.get("max_boost") or DEFAULT_MAX_BOOST), MAX_BOOST)

    now = datetime.now(timezone.utc)
    total = 0.0
    for severity, confirmed_at in e["items"]:
        d = _parse(confirmed_at)
        age_days = max(0.0, (now - d).total_seconds() / 86400.0) if d else 0.0
        total += SEVERITY_WEIGHT.get(severity, 0.0) * (0.5 ** (age_days / half_life))

    risk = min(total, 1.0)
    out.update({
        "incidents":        e["count"],
        "risk":             round(risk, 4),
        "boost":            round(risk * max_boost, 4),
        "worst_severity":   e["worst"],
        "last_incident_at": e["last_at"] or None,
    })

    when = _parse(e["last_at"])
    ago = ""
    if when:
        days = int((now - when).total_seconds() // 86400)
        ago = (" today" if days <= 0 else
               " yesterday" if days == 1 else
               " %d days ago" % days)
    out["reason"] = (
        "This entity has %d confirmed malicious incident%s on record (most "
        "recent%s, worst severity %s)"
        % (e["count"], "" if e["count"] == 1 else "s", ago, e["worst"]))
    return out


def summary(path, cfg: dict | None = None, limit: int = 100) -> list:
    """Every entity with history, riskiest first. For the UI and reports."""
    out = []
    for ent in _rollup(path):
        s = standing(path, ent, cfg)
        s["entity"] = ent
        out.append(s)
    out.sort(key=lambda r: (-r["risk"], -r["incidents"]))
    return out[:limit]


# ── selftest ──────────────────────────────────────────────────────────────────

def selftest() -> int:
    import tempfile
    failures = []

    def ok(label, cond):
        if not cond:
            failures.append(label)

    db = os.path.join(tempfile.mkdtemp(), "risk.db")

    # empty store
    ok("no history -> zeros", standing(db, "nobody")["incidents"] == 0)
    ok("no history -> no reason", standing(db, "nobody")["reason"] is None)
    ok("no history -> no boost", standing(db, "nobody")["boost"] == 0.0)
    ok("empty list", incidents(db) == [])
    ok("empty summary", summary(db) == [])

    # confirm
    r = confirm(db, "Alice", severity="high", event_id="ev-1",
                confirmed_by="analyst1", summary="exfil to external host")
    ok("confirm returns an id", r["id"].startswith("inc-"))
    ok("entity normalised", r["entity"] == "alice")
    s = standing(db, "alice")
    ok("one incident recorded", s["incidents"] == 1)
    ok("worst severity tracked", s["worst_severity"] == "high")
    ok("fresh incident carries risk", s["risk"] > 0.6)
    ok("boost is bounded by max_boost", s["boost"] <= DEFAULT_MAX_BOOST + 1e-9)
    ok("reason is produced", "1 confirmed malicious incident" in (s["reason"] or ""))
    ok("reason says today", "today" in (s["reason"] or ""))
    ok("lookup is case-insensitive", standing(db, "ALICE")["incidents"] == 1)

    # idempotent per event
    confirm(db, "alice", severity="high", event_id="ev-1", confirmed_by="analyst2")
    ok("same alert does not double-count", standing(db, "alice")["incidents"] == 1)
    ok("re-confirm updates the confirmer",
       incidents(db, "alice")[0]["confirmed_by"] == "analyst2")

    # a second, distinct alert does count
    confirm(db, "alice", severity="critical", event_id="ev-2")
    s = standing(db, "alice")
    ok("second incident counts", s["incidents"] == 2)
    ok("worst severity upgrades", s["worst_severity"] == "critical")
    ok("reason pluralises", "2 confirmed malicious incidents" in (s["reason"] or ""))
    ok("risk is capped at 1.0", s["risk"] <= 1.0)

    # events with no id are always distinct
    confirm(db, "bob", severity="low")
    confirm(db, "bob", severity="low")
    ok("id-less confirmations both count", standing(db, "bob")["incidents"] == 2)

    # retract
    inc = incidents(db, "alice")
    ok("retract works", retract(db, inc[0]["id"], retracted_by="lead"))
    ok("retracted incident drops out", standing(db, "alice")["incidents"] == 1)
    ok("retracting twice is a no-op", not retract(db, inc[0]["id"]))
    ok("retracted row is retained",
       len(incidents(db, "alice", include_retracted=True)) == 2)
    ok("unknown id retracts nothing", not retract(db, "inc-doesnotexist"))

    # decay, and the floor that keeps an entity flagged
    old = os.path.join(tempfile.mkdtemp(), "old.db")
    con = _connect(old)
    from datetime import timedelta
    long_ago = (datetime.now(timezone.utc) - timedelta(days=900)).isoformat()
    con.execute("""INSERT INTO incidents (id, entity, entity_type, severity,
                   confirmed_at) VALUES ('inc-old','ghost','user','critical',?)""",
                (long_ago,))
    con.commit(); con.close()
    _invalidate(old)
    s = standing(old, "ghost")
    ok("old incident still counted", s["incidents"] == 1)
    ok("old incident's risk has decayed", s["risk"] < 0.05)
    ok("old incident's boost is negligible", s["boost"] < 0.02)
    ok("but the entity is still flagged", s["reason"] is not None)
    ok("reason states the age", "days ago" in (s["reason"] or ""))

    # a shorter half-life decays faster
    fast = standing(old, "ghost", {"half_life_days": 10})
    slow = standing(old, "ghost", {"half_life_days": 3650})
    ok("half_life shortens risk", fast["risk"] < slow["risk"])

    # boost configuration is honoured and capped
    fresh = os.path.join(tempfile.mkdtemp(), "f.db")
    confirm(fresh, "carol", severity="critical")
    ok("max_boost honoured",
       standing(fresh, "carol", {"max_boost": 0.1})["boost"] <= 0.1 + 1e-9)
    ok("max_boost cannot exceed the hard cap",
       standing(fresh, "carol", {"max_boost": 99})["boost"] <= MAX_BOOST + 1e-9)

    # validation
    for bad, label in ((("", "high"), "empty entity refused"),
                       (("unknown", "high"), "unknown entity refused"),
                       (("dave", "sideways"), "bad severity refused")):
        try:
            confirm(fresh, bad[0], severity=bad[1])
            failures.append(label)
        except ValueError:
            pass

    # summary ordering
    confirm(fresh, "eve", severity="low")
    rows = summary(fresh)
    ok("summary lists both entities", len(rows) == 2)
    ok("summary is riskiest first", rows[0]["entity"] == "carol")
    ok("summary carries the entity key", "entity" in rows[0])

    # cache invalidation
    before = standing(fresh, "eve")["incidents"]
    confirm(fresh, "eve", severity="high")
    ok("cache invalidated after a write",
       standing(fresh, "eve")["incidents"] == before + 1)

    total = 42
    if failures:
        print("ueba_risk_history selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_risk_history selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
