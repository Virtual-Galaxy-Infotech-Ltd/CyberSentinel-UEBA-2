#!/usr/bin/env python3
"""
ueba_alert_store.py
───────────────────
CyberSentinel UEBA — alerts in an indexed table instead of flat files.

WHY THIS EXISTS

The dashboard answers every question by loading a time window into RAM and
walking it in Python. Measured on the live install: 232,373 archived alerts
held as slim dicts cost 922 MB, the process sat at 2.84 GB against a 3 GB
cgroup limit, and it was OOM-killed on 17-Nov-2026. Worse, the cost grows with
retention — `history_days` is 95 and the archive held 22, so the same cache
projects to 3.23 GB once the window fills, which is larger than the entire
limit. No amount of cache trimming fixes an approach whose working set is the
whole corpus.

Almost nothing the dashboard shows needs the records. "Top users by risk",
"alerts per hour", "score distribution", "signatures by count", "campaign
sizes" are all aggregates — GROUP BY over an indexed column. Only the feed
needs rows, and only the most recent page of them. So the fix is not a smaller
cache; it is to stop loading the corpus to count it.

SQLITE, DELIBERATELY, AND THE PATH TO POSTGRES

The SN 31 design (docs/HA_DESIGN_SN31.md) calls for PostgreSQL, and for the
clustered store it is the right answer. It is not the right answer *today*: the
host has ~850 MB of free RAM and no free swap, and adding a database server to
it risks the search cluster and the correlation engine that share the box. The
memory win here comes from indexes and aggregation, not from being
client-server, so it is available from SQLite at no infrastructure cost — and
SQLite is already a dependency carrying six other stores in this product.

So the SQL is written to port: no SQLite-only syntax in the query layer, epoch
integers rather than `strftime`, explicit column lists, and `INSERT ... ON
CONFLICT DO UPDATE`, which PostgreSQL spells the same way. The schema moves to
PostgreSQL by changing the connect call and the one DDL string.

WHAT IS STORED

One row per alert: the columns the aggregates group and filter by, extracted
once at write time, plus the slim JSON record for the feed. Extracting at write
time rather than query time is the point — it is what makes an index possible.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone

log = logging.getLogger("ueba.alert_store")

try:
    import orjson
    def _loads(b):
        return orjson.loads(b)
    def _dumps(o) -> str:
        return orjson.dumps(o).decode("utf-8")
except ImportError:                                   # pragma: no cover
    def _loads(b):
        return json.loads(b)
    def _dumps(o) -> str:
        return json.dumps(o, separators=(",", ":"))


SCHEMA_VERSION = 2

# Epoch INTEGER for `ts`, not an ISO string. Every window query is a range scan
# on it, and comparing integers needs no per-row parsing or collation — which is
# precisely what the in-memory version was paying for on 232k records per build.
_DDL = """
CREATE TABLE IF NOT EXISTS alerts (
    event_id         TEXT PRIMARY KEY,
    ts               INTEGER NOT NULL,
    entity           TEXT,
    host_name        TEXT,
    host_ip          TEXT,
    os_family        TEXT,
    signature        TEXT,
    signature_id     TEXT,
    severity         TEXT,
    verdict          TEXT,
    score            REAL,
    campaign_id      TEXT,
    model_used       TEXT,
    model_type       TEXT,
    bytes_xfer       INTEGER,
    first_seen       TEXT,
    watchlist        TEXT,
    is_fp            INTEGER NOT NULL DEFAULT 0,
    mitre_tactic     TEXT,
    mitre_techniques TEXT,
    slim             TEXT NOT NULL,
    src              TEXT
);
CREATE INDEX IF NOT EXISTS ix_alerts_ts         ON alerts(ts);
CREATE INDEX IF NOT EXISTS ix_alerts_fp_ts      ON alerts(is_fp, ts);
CREATE INDEX IF NOT EXISTS ix_alerts_entity_ts  ON alerts(entity, ts);
CREATE INDEX IF NOT EXISTS ix_alerts_host_ts    ON alerts(host_name, ts);
CREATE INDEX IF NOT EXISTS ix_alerts_sig_ts     ON alerts(signature, ts);
CREATE INDEX IF NOT EXISTS ix_alerts_verdict_ts ON alerts(verdict, ts);
CREATE INDEX IF NOT EXISTS ix_alerts_campaign   ON alerts(campaign_id);

-- One row per (alert, reason). A child table rather than a JSON column so the
-- "top reasons in this window" aggregate is an indexed GROUP BY rather than a
-- scan with per-row JSON parsing, and so it ports to PostgreSQL unchanged —
-- json_each is SQLite-only and jsonb_array_elements is its Postgres spelling,
-- whereas a join is a join.
CREATE TABLE IF NOT EXISTS alert_reasons (
    event_id TEXT NOT NULL,
    reason   TEXT NOT NULL,
    PRIMARY KEY (event_id, reason)
);
CREATE INDEX IF NOT EXISTS ix_reasons_reason ON alert_reasons(reason);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Import bookkeeping, so a re-import is incremental rather than a full
-- re-parse: one row per source file with the byte offset consumed and the
-- mtime it was consumed at.
CREATE TABLE IF NOT EXISTS ingest_state (
    source     TEXT PRIMARY KEY,
    offset     INTEGER NOT NULL DEFAULT 0,
    mtime      REAL,
    rows       INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT
);
"""

_MIN_TS = 0


def connect(path: str, *, read_only: bool = False) -> sqlite3.Connection:
    """Open the store, creating it if needed.

    WAL because the engine writes while the console reads, which is the same
    reason risk_history.db and device_trail.db use it. A busy_timeout rather
    than the default instant failure: a reader that loses the race should wait,
    not report zero alerts, which is how a plain connect fails here.
    """
    if read_only:
        con = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=30,
                              check_same_thread=False)
    else:
        d = os.path.dirname(os.path.abspath(path))
        if d:
            os.makedirs(d, exist_ok=True)
        con = sqlite3.connect(path, timeout=30, check_same_thread=False)
        con.executescript(_DDL)
        con.execute("PRAGMA journal_mode=WAL")
        # NORMAL, not FULL: an alert already exists durably in the engine's
        # jsonl, so a lost transaction on power failure costs a re-import of the
        # tail rather than data. FULL would fsync per commit and make the
        # backfill several times slower for no gain we need.
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(SCHEMA_VERSION),))
        con.commit()
    con.row_factory = sqlite3.Row
    return con


# ── record extraction ───────────────────────────────────────────────────────

def _ts_of(a: dict) -> int:
    """Epoch seconds from the engine's processed_at, else the source event_time.

    Mirrors the dashboard's _alert_ts so a window selects the same rows it
    always did. An unparseable timestamp sorts oldest rather than being dropped
    — the in-memory version kept those records too, and silently losing alerts
    to a bad clock would be worse than showing them early.
    """
    ueba = a.get("ueba") or {}
    for raw in (ueba.get("processed_at"), a.get("event_time")):
        if not raw:
            continue
        s = str(raw).strip()
        if not s:
            continue
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            d = datetime.fromisoformat(s)
        except ValueError:
            continue
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return int(d.timestamp())
    return _MIN_TS


def _first(*vals):
    for v in vals:
        if v not in (None, ""):
            return v
    return None


def row_from_alert(a: dict, *, is_fp: bool = False, src: str = "") -> tuple:
    """Flatten one alert (fat engine record or slim projection) into a row.

    Accepts both shapes on purpose: the engine appends fat records to the live
    file, while the archive slim caches hold the projection. The columns below
    exist in both, and `__user`/`__bytes` are read when present so a slim
    record does not have to be re-resolved.
    """
    ueba = a.get("ueba") or {}
    sec = a.get("security") or {}
    host = a.get("host") or {}
    ev = a.get("evidence") or {}
    rev = (a.get("context") or {}).get("raw_event") or {}
    ae = ((ueba.get("raw_scores") or {}).get("autoencoder") or {})

    tactic = a.get("__mitre_tactic")
    if tactic is None:
        tactic = ((rev.get("rule") or {}).get("mitre") or {}).get("tactic") or []
    techniques = a.get("__mitre_techniques")
    if techniques is None:
        techniques = (ev.get("signature") or {}).get("mitre_techniques") or []

    return (
        str(a.get("event_id") or ""),
        _ts_of(a),
        a.get("__user") or None,
        (host.get("name") or None),
        (host.get("ip") or None),
        ((host.get("os") or {}).get("family") or None),
        sec.get("signature") or None,
        (str(sec.get("signature_id")) if sec.get("signature_id") is not None else None),
        sec.get("severity") or None,
        ueba.get("risk_verdict") or None,
        (float(ueba["combined_score"])
         if isinstance(ueba.get("combined_score"), (int, float)) else None),
        ueba.get("campaign_id") or None,
        ae.get("model_used") or None,
        ae.get("model_type") or None,
        (int(a["__bytes"]) if isinstance(a.get("__bytes"), (int, float)) else None),
        ((ev.get("history") or {}).get("first_seen") or None),
        (_dumps(ueba.get("watchlist")) if ueba.get("watchlist") else None),
        1 if is_fp else 0,
        _dumps(tactic) if tactic else None,
        _dumps(techniques) if techniques else None,
        _dumps(a),
        src or None,
    )


_COLS = ("event_id, ts, entity, host_name, host_ip, os_family, signature, "
         "signature_id, severity, verdict, score, campaign_id, model_used, "
         "model_type, bytes_xfer, first_seen, watchlist, is_fp, mitre_tactic, "
         "mitre_techniques, slim, src")
_PLACEHOLDERS = ", ".join("?" * 22)

# ON CONFLICT DO UPDATE rather than INSERT OR REPLACE: the latter is SQLite-only
# and it DELETEs then INSERTs, which would renumber nothing here but does fire
# delete triggers and churn the indexes. This form is also what PostgreSQL
# accepts verbatim.
_UPSERT = (
    "INSERT INTO alerts (%s) VALUES (%s) "
    "ON CONFLICT(event_id) DO UPDATE SET "
    "ts=excluded.ts, entity=excluded.entity, host_name=excluded.host_name, "
    "host_ip=excluded.host_ip, os_family=excluded.os_family, "
    "signature=excluded.signature, signature_id=excluded.signature_id, "
    "severity=excluded.severity, verdict=excluded.verdict, "
    "score=excluded.score, campaign_id=excluded.campaign_id, "
    "model_used=excluded.model_used, model_type=excluded.model_type, "
    "bytes_xfer=excluded.bytes_xfer, first_seen=excluded.first_seen, "
    "watchlist=excluded.watchlist, mitre_tactic=excluded.mitre_tactic, "
    "mitre_techniques=excluded.mitre_techniques, slim=excluded.slim, "
    "src=excluded.src" % (_COLS, _PLACEHOLDERS)
)


def upsert_many(con: sqlite3.Connection, alerts, *, fp_ids=(), src: str = "") -> int:
    """Insert or refresh a batch. Returns the number of rows written.

    is_fp is NOT overwritten on conflict: an analyst's false-positive marking
    lives in its own store and is applied by mark_false_positive(). Re-importing
    the same alert must not quietly un-mark it.
    """
    fp = set(fp_ids or ())
    rows = []
    for a in alerts:
        if not isinstance(a, dict) or not a.get("event_id"):
            continue
        rows.append(row_from_alert(a, is_fp=str(a.get("event_id")) in fp, src=src))
    if not rows:
        return 0
    con.executemany(_UPSERT, rows)

    # Reasons are rewritten per alert rather than merged: a re-import carries
    # the current truth, and leaving a reason behind that the engine no longer
    # emits would quietly inflate every "top reasons" aggregate afterwards.
    ids = [r[0] for r in rows]
    con.executemany("DELETE FROM alert_reasons WHERE event_id = ?",
                    [(i,) for i in ids])
    pairs = []
    for a in alerts:
        if not isinstance(a, dict):
            continue
        eid = str(a.get("event_id") or "")
        if not eid:
            continue
        for r in ((a.get("ueba") or {}).get("anomaly_reasons") or []):
            r = str(r).strip()
            if r:
                pairs.append((eid, r))
    if pairs:
        con.executemany(
            "INSERT INTO alert_reasons (event_id, reason) VALUES (?, ?) "
            "ON CONFLICT(event_id, reason) DO NOTHING", pairs)
    return len(rows)


def mark_false_positive(con: sqlite3.Connection, event_ids, value: bool = True) -> int:
    ids = [str(e) for e in (event_ids or []) if e]
    if not ids:
        return 0
    con.executemany("UPDATE alerts SET is_fp=? WHERE event_id=?",
                    [(1 if value else 0, i) for i in ids])
    return len(ids)


# ── queries: aggregate in SQL, never in Python ─────────────────────────────

def _window(hours: int, now: float | None = None) -> int:
    """Lower bound for a window. hours<=0 means everything in the table."""
    if not hours or hours <= 0:
        return _MIN_TS
    return int((now if now is not None else time.time()) - hours * 3600)


def _fp_clause(include_fp: bool) -> str:
    return "" if include_fp else " AND is_fp = 0"


def counts(con, hours: int = 0, *, include_fp: bool = False, now=None) -> dict:
    """Headline numbers. One pass, no rows returned to Python."""
    lo = _window(hours, now)
    r = con.execute(
        "SELECT COUNT(*) AS total, COUNT(DISTINCT entity) AS entities, "
        "COUNT(DISTINCT host_name) AS hosts, "
        "COUNT(DISTINCT campaign_id) AS campaigns, "
        "AVG(score) AS avg_score, MAX(score) AS max_score, "
        "MIN(ts) AS first_ts, MAX(ts) AS last_ts "
        "FROM alerts WHERE ts >= ?" + _fp_clause(include_fp), (lo,)).fetchone()
    return dict(r) if r else {}


def verdict_counts(con, hours: int = 0, *, include_fp: bool = False, now=None) -> dict:
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT verdict, COUNT(*) AS n FROM alerts WHERE ts >= ?"
        + _fp_clause(include_fp) + " GROUP BY verdict", (lo,)).fetchall()
    return {(r["verdict"] or "unknown"): r["n"] for r in rows}


def top_entities(con, hours: int = 0, *, limit: int = 20, include_fp: bool = False,
                 now=None) -> list:
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT entity, COUNT(*) AS alerts, MAX(score) AS max_score, "
        "AVG(score) AS avg_score, MAX(ts) AS last_ts "
        "FROM alerts WHERE ts >= ? AND entity IS NOT NULL"
        + _fp_clause(include_fp) +
        " GROUP BY entity ORDER BY max_score DESC, alerts DESC LIMIT ?",
        (lo, int(limit))).fetchall()
    return [dict(r) for r in rows]


def top_hosts(con, hours: int = 0, *, limit: int = 20, include_fp: bool = False,
              now=None) -> list:
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT host_name, COUNT(*) AS alerts, MAX(score) AS max_score, "
        "COUNT(DISTINCT entity) AS entities, MAX(ts) AS last_ts "
        "FROM alerts WHERE ts >= ? AND host_name IS NOT NULL"
        + _fp_clause(include_fp) +
        " GROUP BY host_name ORDER BY alerts DESC LIMIT ?",
        (lo, int(limit))).fetchall()
    return [dict(r) for r in rows]


def top_signatures(con, hours: int = 0, *, limit: int = 20, include_fp: bool = False,
                   now=None) -> list:
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT signature, COUNT(*) AS n, MAX(score) AS max_score "
        "FROM alerts WHERE ts >= ? AND signature IS NOT NULL"
        + _fp_clause(include_fp) +
        " GROUP BY signature ORDER BY n DESC LIMIT ?",
        (lo, int(limit))).fetchall()
    return [dict(r) for r in rows]


def campaigns(con, hours: int = 0, *, limit: int = 50, include_fp: bool = False,
              now=None) -> list:
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT campaign_id, COUNT(*) AS alerts, COUNT(DISTINCT entity) AS entities, "
        "MAX(score) AS max_score, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
        "FROM alerts WHERE ts >= ? AND campaign_id IS NOT NULL AND campaign_id <> ''"
        + _fp_clause(include_fp) +
        " GROUP BY campaign_id ORDER BY max_score DESC, alerts DESC LIMIT ?",
        (lo, int(limit))).fetchall()
    return [dict(r) for r in rows]


def score_histogram(con, hours: int = 0, *, buckets: int = 10,
                    include_fp: bool = False, now=None) -> list:
    """Score distribution, bucketed in SQL.

    CAST(score*buckets) rather than a CASE ladder so the bucket count is a
    parameter and the expression stays portable. Scores are 0..1; a score of
    exactly 1.0 would land in bucket `buckets`, so it is clamped into the last.
    """
    lo = _window(hours, now)
    b = max(int(buckets), 1)
    rows = con.execute(
        "SELECT MIN(CAST(score * ? AS INTEGER), ? ) AS bucket, COUNT(*) AS n "
        "FROM alerts WHERE ts >= ? AND score IS NOT NULL"
        + _fp_clause(include_fp) +
        " GROUP BY bucket ORDER BY bucket", (b, b - 1, lo)).fetchall()
    out = [{"bucket": i, "lo": i / b, "hi": (i + 1) / b, "n": 0} for i in range(b)]
    for r in rows:
        i = int(r["bucket"] or 0)
        if 0 <= i < b:
            out[i]["n"] = r["n"]
    return out


def per_hour(con, hours: int = 24, *, include_fp: bool = False, now=None) -> list:
    """Alerts per hour over the window — the timeline, without loading rows."""
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT (ts / 3600) * 3600 AS hour_ts, COUNT(*) AS n "
        "FROM alerts WHERE ts >= ?" + _fp_clause(include_fp) +
        " GROUP BY hour_ts ORDER BY hour_ts", (lo,)).fetchall()
    return [{"ts": r["hour_ts"], "n": r["n"]} for r in rows]


def tier_coverage(con, hours: int = 0, *, include_fp: bool = False, now=None) -> dict:
    """Which model tier judged the alerts in this window (RFP SN 18)."""
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT COALESCE(model_type, 'unknown') AS tier, COUNT(*) AS n "
        "FROM alerts WHERE ts >= ?" + _fp_clause(include_fp) +
        " GROUP BY tier ORDER BY n DESC", (lo,)).fetchall()
    return {r["tier"]: r["n"] for r in rows}


def backfill_reasons(con, *, batch: int = 5000) -> int:
    """Populate alert_reasons for rows imported before schema v2.

    Reads the reasons back out of each row's stored slim record rather than
    re-reading the source files: the data is already here, and a re-import
    would re-parse 400 MB to recover something we kept.
    """
    done = 0
    while True:
        rows = con.execute(
            "SELECT a.event_id, a.slim FROM alerts a "
            "WHERE NOT EXISTS (SELECT 1 FROM alert_reasons r "
            "                  WHERE r.event_id = a.event_id) "
            "LIMIT ?", (int(batch),)).fetchall()
        if not rows:
            break
        pairs = []
        marks = []
        for r in rows:
            try:
                rec = _loads(r["slim"])
            except Exception:
                rec = {}
            rs = ((rec.get("ueba") or {}).get("anomaly_reasons") or [])
            got = False
            for x in rs:
                x = str(x).strip()
                if x:
                    pairs.append((r["event_id"], x))
                    got = True
            if not got:
                # An alert with no reasons would be re-selected forever by the
                # NOT EXISTS above, so it gets a sentinel row that the queries
                # ignore. Without this the loop never terminates.
                marks.append((r["event_id"], ""))
        if pairs:
            con.executemany(
                "INSERT INTO alert_reasons (event_id, reason) VALUES (?, ?) "
                "ON CONFLICT(event_id, reason) DO NOTHING", pairs)
        if marks:
            con.executemany(
                "INSERT INTO alert_reasons (event_id, reason) VALUES (?, ?) "
                "ON CONFLICT(event_id, reason) DO NOTHING", marks)
        con.commit()
        done += len(rows)
    # The sentinel must never reach an aggregate.
    con.execute("DELETE FROM alert_reasons WHERE reason = ''")
    con.commit()
    return done


def top_reasons(con, hours: int = 0, *, limit: int = 5,
                include_fp: bool = False, now=None) -> list:
    """Most common anomaly reasons in the window."""
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT r.reason AS reason, COUNT(*) AS n "
        "FROM alert_reasons r JOIN alerts a ON a.event_id = r.event_id "
        "WHERE a.ts >= ?" + (" AND a.is_fp = 0" if not include_fp else "") +
        " GROUP BY r.reason ORDER BY n DESC, r.reason ASC LIMIT ?",
        (lo, int(limit))).fetchall()
    return [{"reason": r["reason"], "count": r["n"]} for r in rows]


def stats_window(con, hours: int = 0, *, include_fp: bool = False,
                 now=None, cap: int = 0) -> dict:
    """The /api/stats payload, computed in SQL.

    Reproduces _build_stats exactly, including two behaviours that a naive
    translation gets wrong:

      unique_users counts a bucket for alerts with NO user. The in-memory
      version does `users_seen.add(get_user(a))`, and get_user returns None
      for an unattributed alert — so None is a member of that set.
      COUNT(DISTINCT entity) excludes NULLs, which would report one fewer.

      alert_rate_1h is relative to NOW, not to the window. A 24-hour window
      and a 90-day window report the same last-hour count.
    """
    lo = _window(hours, now)
    fp = _fp_clause(include_fp)
    t_now = now if now is not None else time.time()

    r = con.execute(
        "SELECT COUNT(*) AS total, "
        "COUNT(DISTINCT entity) AS named_users, "
        "SUM(CASE WHEN entity IS NULL OR entity = '' THEN 1 ELSE 0 END) AS unnamed, "
        "COUNT(DISTINCT CASE WHEN campaign_id IS NOT NULL AND campaign_id <> '' "
        "                    THEN campaign_id END) AS campaigns, "
        "SUM(CASE WHEN verdict = 'highly_anomalous' THEN 1 ELSE 0 END) AS highly, "
        "SUM(CASE WHEN verdict = 'anomalous' THEN 1 ELSE 0 END) AS anomalous, "
        "SUM(CASE WHEN verdict = 'suspicious' THEN 1 ELSE 0 END) AS suspicious, "
        "SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS rate_1h "
        "FROM alerts WHERE ts >= ?" + fp,
        (int(t_now - 3600), lo)).fetchone()

    total = int(r["total"] or 0)
    if not total:
        return {"total_alerts": 0, "highly_anomalous": 0, "anomalous": 0,
                "suspicious": 0, "campaigns": 0, "suppressed_noise": 0,
                "unique_users": 0, "alert_rate_1h": 0, "top_reasons": []}

    unique_users = int(r["named_users"] or 0) + (1 if int(r["unnamed"] or 0) else 0)
    out = {
        "total_alerts":     total,
        "highly_anomalous": int(r["highly"] or 0),
        "anomalous":        int(r["anomalous"] or 0),
        "suspicious":       int(r["suspicious"] or 0),
        "campaigns":        int(r["campaigns"] or 0),
        "unique_users":     unique_users,
        "alert_rate_1h":    int(r["rate_1h"] or 0),
        "top_reasons":      top_reasons(con, hours, limit=5,
                                        include_fp=include_fp, now=now),
    }
    if cap:
        out["window_total"] = total
        out["window_cap"] = int(cap)
        out["window_capped"] = total > int(cap)
    return out


def recent(con, hours: int = 0, *, limit: int = 200, offset: int = 0,
           include_fp: bool = False, now=None) -> list:
    """The feed: the newest `limit` records, as the dashboard's slim dicts.

    The only query that returns records rather than counts, and it returns a
    page of them. This is what replaces holding the window in RAM: the feed
    never needed more than a screenful.
    """
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT slim FROM alerts WHERE ts >= ?" + _fp_clause(include_fp) +
        " ORDER BY ts DESC LIMIT ? OFFSET ?",
        (lo, int(limit), int(offset))).fetchall()
    out = []
    for r in rows:
        try:
            out.append(_loads(r["slim"]))
        except Exception:
            continue
    out.reverse()        # oldest-first, matching the in-memory contract
    return out


def by_entity(con, entity: str, *, hours: int = 0, limit: int = 200,
              include_fp: bool = False, now=None) -> list:
    lo = _window(hours, now)
    rows = con.execute(
        "SELECT slim FROM alerts WHERE entity = ? AND ts >= ?"
        + _fp_clause(include_fp) + " ORDER BY ts DESC LIMIT ?",
        (entity, lo, int(limit))).fetchall()
    out = []
    for r in rows:
        try:
            out.append(_loads(r["slim"]))
        except Exception:
            continue
    out.reverse()
    return out


def stats(con) -> dict:
    """Store-level facts: row count, span, file size."""
    r = con.execute("SELECT COUNT(*) AS rows, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
                    "FROM alerts").fetchone()
    out = dict(r) if r else {}
    try:
        page = con.execute("PRAGMA page_count").fetchone()[0]
        size = con.execute("PRAGMA page_size").fetchone()[0]
        out["bytes"] = int(page) * int(size)
    except Exception:
        out["bytes"] = None
    return out


# ── selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    import tempfile

    failures: list = []
    checked: list = []

    def ok(label, cond, detail=""):
        checked.append(label)
        if not cond:
            failures.append("%s%s" % (label, (" — " + detail) if detail else ""))

    T0 = 1_762_000_000          # fixed instant; never datetime.now()

    def alert(i, *, entity="person:a", host="srv-1", sig="Sig A", score=0.5,
              verdict="anomalous", campaign=None, ts_off=0, mtype="entity",
              nbytes=None):
        return {
            "event_id": "e%d" % i,
            "event_time": datetime.fromtimestamp(T0 + ts_off, timezone.utc).isoformat(),
            "ueba": {"risk_verdict": verdict, "combined_score": score,
                     "campaign_id": campaign,
                     "processed_at": datetime.fromtimestamp(
                         T0 + ts_off, timezone.utc).isoformat(),
                     "raw_scores": {"autoencoder": {"model_used": "m",
                                                    "model_type": mtype}}},
            "security": {"signature": sig, "signature_id": 100 + i,
                         "severity": "high"},
            "host": {"name": host, "ip": "10.0.0.%d" % (i % 250),
                     "os": {"family": "windows"}},
            "__user": entity,
            "__bytes": nbytes,
            "evidence": {"history": {"first_seen": "2026-01-01"}},
        }

    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "alerts.db")
        con = connect(db)

        # ── 1. schema and idempotence ───────────────────────────────────────
        n = upsert_many(con, [alert(i) for i in range(10)], src="test")
        con.commit()
        ok("a batch inserts", n == 10, "wrote %d" % n)
        ok("row count matches", stats(con)["rows"] == 10)

        # Re-importing the SAME alerts must not duplicate them. The archive is
        # re-read on every restart, so a non-idempotent import would multiply
        # the corpus on each boot.
        upsert_many(con, [alert(i) for i in range(10)], src="test")
        con.commit()
        ok("re-importing the same ids does not duplicate",
           stats(con)["rows"] == 10, "rows=%d" % stats(con)["rows"])

        # ── 2. a false-positive marking survives re-import ──────────────────
        mark_false_positive(con, ["e3"])
        con.commit()
        ok("marking an fp takes effect",
           counts(con, include_fp=False)["total"] == 9)
        upsert_many(con, [alert(3)], src="test")
        con.commit()
        ok("re-importing does NOT un-mark a false positive",
           counts(con, include_fp=False)["total"] == 9,
           "an analyst's decision must outlive a backfill")
        ok("include_fp still sees it",
           counts(con, include_fp=True)["total"] == 10)

        # ── 3. windows select by time, and 0 means everything ───────────────
        con.execute("DELETE FROM alerts")
        rows = [alert(100 + i, ts_off=-i * 3600) for i in range(48)]
        upsert_many(con, rows)
        con.commit()
        now = T0 + 1
        ok("a 24h window selects 24 rows",
           counts(con, 24, now=now)["total"] == 24,
           "got %d" % counts(con, 24, now=now)["total"])
        ok("hours=0 selects everything",
           counts(con, 0, now=now)["total"] == 48)
        ok("a wider window than the data is not an error",
           counts(con, 9999, now=now)["total"] == 48)

        # ── 4. the aggregates ───────────────────────────────────────────────
        con.execute("DELETE FROM alerts")
        upsert_many(con, [
            alert(1, entity="person:a", host="srv-1", sig="S1", score=0.9,
                  verdict="highly_anomalous", campaign="c1"),
            alert(2, entity="person:a", host="srv-1", sig="S1", score=0.4,
                  verdict="anomalous", campaign="c1"),
            alert(3, entity="person:b", host="srv-2", sig="S2", score=0.7,
                  verdict="anomalous", campaign="c1"),
            alert(4, entity="person:c", host="srv-2", sig="S2", score=0.1,
                  verdict="suspicious", mtype="global"),
        ])
        con.commit()

        te = top_entities(con, 0, now=now)
        ok("top_entities groups and orders by max score",
           te and te[0]["entity"] == "person:a" and te[0]["alerts"] == 2,
           "got %s" % te[:2])
        ok("top_entities counts distinct entities", len(te) == 3)

        th = top_hosts(con, 0, now=now)
        ok("top_hosts aggregates per host", len(th) == 2, "got %s" % th)
        ok("and counts entities per host",
           {h["host_name"]: h["entities"] for h in th} == {"srv-1": 1, "srv-2": 2},
           "got %s" % th)

        ts_ = top_signatures(con, 0, now=now)
        ok("top_signatures counts per signature",
           {s["signature"]: s["n"] for s in ts_} == {"S1": 2, "S2": 2},
           "got %s" % ts_)

        vc = verdict_counts(con, 0, now=now)
        ok("verdict_counts buckets by verdict",
           vc == {"highly_anomalous": 1, "anomalous": 2, "suspicious": 1},
           "got %s" % vc)

        cm = campaigns(con, 0, now=now)
        ok("campaigns groups by campaign and counts entities",
           len(cm) == 1 and cm[0]["alerts"] == 3 and cm[0]["entities"] == 2,
           "got %s" % cm)
        ok("an alert with no campaign is excluded from campaigns",
           sum(c["alerts"] for c in cm) == 3)

        tier = tier_coverage(con, 0, now=now)
        ok("tier_coverage reports the model tier (SN 18)",
           tier == {"entity": 3, "global": 1}, "got %s" % tier)

        # ── 5. the histogram, including the 1.0 edge ────────────────────────
        con.execute("DELETE FROM alerts")
        upsert_many(con, [alert(i, score=s) for i, s in
                          enumerate([0.0, 0.05, 0.5, 0.99, 1.0])])
        con.commit()
        h = score_histogram(con, 0, buckets=10, now=now)
        ok("the histogram has one entry per bucket", len(h) == 10)
        ok("bucket 0 holds the two lowest scores",
           h[0]["n"] == 2, "got %s" % h[0])
        ok("a score of exactly 1.0 lands in the LAST bucket, not an 11th",
           h[9]["n"] == 2 and sum(x["n"] for x in h) == 5,
           "1.0 must clamp; got %s" % [x["n"] for x in h])

        # ── 6. per_hour ─────────────────────────────────────────────────────
        con.execute("DELETE FROM alerts")
        upsert_many(con, [alert(200 + i, ts_off=-(i // 2) * 3600) for i in range(6)])
        con.commit()
        ph = per_hour(con, 24, now=now)
        ok("per_hour buckets to the hour", len(ph) == 3, "got %s" % ph)
        ok("and counts within each", all(p["n"] == 2 for p in ph), "got %s" % ph)
        ok("hour bucket boundaries are aligned",
           all(p["ts"] % 3600 == 0 for p in ph), "got %s" % ph)

        # ── 7. the feed returns records, oldest-first, paged ────────────────
        con.execute("DELETE FROM alerts")
        upsert_many(con, [alert(300 + i, ts_off=i) for i in range(50)])
        con.commit()
        page = recent(con, 0, limit=10, now=now)
        ok("recent() returns records, not counts",
           len(page) == 10 and isinstance(page[0], dict))
        ok("recent() returns the NEWEST page",
           page[-1]["event_id"] == "e349", "got %s" % page[-1].get("event_id"))
        ok("recent() is oldest-first within the page",
           page[0]["event_id"] == "e340", "got %s" % page[0].get("event_id"))
        ok("recent() honours offset",
           recent(con, 0, limit=10, offset=10, now=now)[-1]["event_id"] == "e339")
        ok("the stored record round-trips",
           page[0].get("security", {}).get("signature") == "Sig A")

        be = by_entity(con, "person:a", hours=0, limit=5, now=now)
        ok("by_entity filters to one entity", len(be) == 5)

        # ── 8. an unparseable timestamp is kept, not dropped ────────────────
        con.execute("DELETE FROM alerts")
        bad = alert(900)
        bad["ueba"]["processed_at"] = "not-a-date"
        bad["event_time"] = ""
        upsert_many(con, [bad])
        con.commit()
        ok("an alert with no usable timestamp is still stored",
           stats(con)["rows"] == 1,
           "losing alerts to a bad clock is worse than sorting them early")
        ok("and it sorts oldest", con.execute(
            "SELECT ts FROM alerts").fetchone()[0] == _MIN_TS)

        # ── 9. a slim record imports as well as a fat one ───────────────────
        con.execute("DELETE FROM alerts")
        slim = {"event_id": "s1", "event_time": "2026-11-01T00:00:00+00:00",
                "ueba": {"risk_verdict": "anomalous", "combined_score": 0.6,
                         "processed_at": "2026-11-01T00:00:00+00:00",
                         "raw_scores": {"autoencoder": {"model_type": "cohort"}}},
                "security": {"signature": "S"}, "host": {"name": "h"},
                "__user": "person:z", "__mitre_tactic": ["Execution"]}
        upsert_many(con, [slim])
        con.commit()
        r = con.execute("SELECT entity, verdict, model_type, mitre_tactic "
                        "FROM alerts WHERE event_id='s1'").fetchone()
        ok("a slim archive record populates the same columns",
           r["entity"] == "person:z" and r["verdict"] == "anomalous"
           and r["model_type"] == "cohort", "got %s" % dict(r))
        ok("mitre lists are stored as json",
           json.loads(r["mitre_tactic"]) == ["Execution"])

        # ── 10. a record with no event_id is skipped, not crashed on ────────
        before = stats(con)["rows"]
        upsert_many(con, [{"no": "id"}, None, "not a dict"])
        con.commit()
        ok("junk records are skipped rather than raising",
           stats(con)["rows"] == before)

        # ── 11. the indexes are actually used by the window query ───────────
        # The whole point is that a window does not scan the table. If the
        # planner stops using ix_alerts_fp_ts this silently becomes the thing
        # it replaced.
        plan = con.execute(
            "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM alerts "
            "WHERE ts >= 1 AND is_fp = 0").fetchall()
        text = " ".join(str(tuple(p)) for p in plan)
        ok("the window query uses an index, not a full scan",
           "USING INDEX" in text.upper() or "USING COVERING INDEX" in text.upper(),
           "plan was: %s" % text)

        plan2 = con.execute(
            "EXPLAIN QUERY PLAN SELECT entity, COUNT(*) FROM alerts "
            "WHERE ts >= 1 GROUP BY entity").fetchall()
        ok("the per-entity rollup has an index available",
           "INDEX" in " ".join(str(tuple(p)) for p in plan2).upper(),
           "plan was: %s" % plan2)

        con.close()

        # ── 12. read-only open works and cannot write ──────────────────────
        ro = connect(db, read_only=True)
        ok("a read-only connection can query", stats(ro)["rows"] >= 0)
        try:
            ro.execute("DELETE FROM alerts")
            ro.commit()
            ok("a read-only connection refuses writes", False,
               "the console should not be able to delete the corpus")
        except sqlite3.OperationalError:
            ok("a read-only connection refuses writes", True)
        ro.close()

    total = len(checked)
    if failures:
        print("ueba_alert_store selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_alert_store selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
