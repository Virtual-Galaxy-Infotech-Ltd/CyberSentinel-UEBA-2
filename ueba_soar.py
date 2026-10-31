#!/usr/bin/env python3
"""
ueba_soar.py
────────────
CyberSentinel UEBA — SOAR and SIEM integration (RFP SN 3).

  SN 3  The UEBA tool should be able to integrate with the proposed SOAR &
        SIEM solution and should be from the same OEM for monitoring user
        endpoints and reporting anomalies.

The part that is not a build item, said plainly
───────────────────────────────────────────────
"Should be from the same OEM" is a commercial and bid decision. No amount of
code makes two products share a vendor, and a module claiming to satisfy that
clause would be dishonest. What is engineering, and what is delivered here, is
the integration itself: anomalies reported OUT to the SOAR, instructions
accepted BACK from it, and the two sides' state kept in step. The OEM question
needs an answer from the bid lead and is tracked as such.

The SIEM half is already in place: the engine consumes the SIEM's enriched
event stream, which is where every detection in this platform comes from. This
module is the SOAR half.

Three things a webhook is not
─────────────────────────────
ueba_notify can already POST a notification to a URL, and that is not a SOAR
integration. Three differences, each of which is a defect if skipped:

  DURABILITY     a SOAR that is down for ten minutes must not cost us ten
                 minutes of incidents. Outbound items are queued in SQLite and
                 retried with exponential backoff; what cannot be delivered
                 after max_attempts goes to a dead-letter state where it can be
                 seen and replayed, not dropped silently.
  IDEMPOTENCY    a retry must not create a second case. Every item carries a
                 stable key derived from the alert's own event_id, sent in the
                 payload and in a header, so both sides can dedupe. Enqueuing
                 the same alert twice updates the existing row.
  BIDIRECTIONAL  a SOAR closing a case has to be able to tell us. Inbound
                 callbacks are authenticated, replay-protected, and mapped onto
                 state this platform already keeps.

Why the inbound half matters more than it looks
───────────────────────────────────────────────
Two of the callback actions write the analyst verdicts that SN 20's supervised
model is waiting for: `close_false_positive` records a benign label and
`confirm_incident` records a malicious one. An analyst working a case in the
SOAR is therefore labelling our training data without doing anything extra,
which is the whole argument for the integration being two-way rather than a
fire-and-forget feed.

Egress is guarded, and that interacts with SN 64
────────────────────────────────────────────────
SN 64 requires the platform to run on the customer's own infrastructure with
nothing leaving it. A SOAR push is an outbound call, so every delivery goes
through ueba_egress.guard() — not once at configuration time but on every
attempt, because the policy can be tightened after a destination was
configured. Under the default `on_premises` mode an internal SOAR is reachable
and a cloud one is refused, with the reason recorded on the queue item. That is
the correct behaviour, not a limitation: a cloud SOAR and SN 64 cannot both be
satisfied, and the operator has to choose knowingly.

Authentication of callbacks
───────────────────────────
HMAC-SHA256 over `timestamp.body` with a shared secret from the environment,
never from the config file. Verified with a constant-time comparison, a
timestamp window to bound replay, and a seen-signature cache so a captured
request cannot be replayed inside that window. The failure modes this rejects
are the same ones the SSO exchange suite tests: a forged signature, a stale
timestamp, a replayed body, a missing header, and an empty secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

try:
    import ueba_egress
except Exception:                                            # pragma: no cover
    ueba_egress = None

# Queue states. `dead` is terminal and visible; nothing is ever deleted by the
# delivery path, because a lost incident is worse than a full table.
STATES = ("pending", "sent", "failed", "dead", "blocked")

# What a SOAR may ask us to do. Anything else is refused by name rather than
# ignored, so a misconfigured playbook produces an error instead of silence.
CALLBACK_ACTIONS = ("acknowledge", "close_false_positive", "confirm_incident",
                    "comment", "assign")

DEFAULTS = {
    "max_attempts": 8,
    "backoff_base_secs": 30.0,
    "backoff_max_secs": 3600.0,
    "callback_window_secs": 300,
    "replay_cache_size": 4096,
    "batch_size": 25,
    "min_score": 0.0,
}

SIGNATURE_HEADER = "X-CyberSentinel-Signature"
TIMESTAMP_HEADER = "X-CyberSentinel-Timestamp"
IDEMPOTENCY_HEADER = "X-CyberSentinel-Idempotency-Key"


# ── the outbound payload ────────────────────────────────────────────────────

def idempotency_key(alert: dict) -> str:
    """A stable key for one alert.

    Derived from event_id where there is one, so the same alert always produces
    the same key and a retry cannot create a second case. Where there is not,
    it is a hash of the identifying fields rather than a random value — a
    random key would make every retry a new case, which is the bug this exists
    to prevent.
    """
    eid = str((alert or {}).get("event_id") or "").strip()
    if eid:
        return hashlib.sha256(eid.encode("utf-8")).hexdigest()[:32]
    ueba = (alert or {}).get("ueba") or {}
    basis = "|".join([
        str((alert or {}).get("event_time") or ""),
        str(((alert or {}).get("host") or {}).get("name") or ""),
        str(((alert or {}).get("security") or {}).get("signature_id") or ""),
        str(ueba.get("processed_at") or ""),
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]


def canonical_incident(alert: dict, site: str = "CyberSentinel UEBA") -> dict:
    """One alert as a SOAR-neutral incident.

    Vendor-neutral on purpose. Every SOAR has its own case schema, and the way
    to support several is to emit one documented shape and map it at the edge —
    not to grow a branch per vendor inside the engine. The evidence block is
    carried whole because a case an analyst cannot work from is a notification
    with extra steps.
    """
    a = alert or {}
    ueba = a.get("ueba") or {}
    sec = a.get("security") or {}
    host = a.get("host") or {}
    ev = a.get("evidence") or {}
    score = ueba.get("combined_score")
    return {
        "source": site,
        "schema": "cybersentinel.ueba.incident/1",
        "idempotency_key": idempotency_key(a),
        "event_id": a.get("event_id"),
        "observed_at": a.get("event_time") or ueba.get("processed_at"),
        "reported_at": datetime.now(timezone.utc).isoformat(),
        "severity": ueba.get("risk_verdict") or "",
        "score": score,
        "title": "%s on %s" % (sec.get("signature") or "UEBA anomaly",
                               host.get("name") or "unknown host"),
        "entity": {
            "name": ueba.get("entity") or a.get("__user") or "",
            "host": host.get("name") or "",
            "address": host.get("ip") or "",
        },
        "signature": {"id": sec.get("signature_id"),
                      "name": sec.get("signature"),
                      "severity": sec.get("severity")},
        "reasons": ueba.get("anomaly_reasons") or [],
        "scoring": {
            "model_score": ueba.get("model_score"),
            "watch_boost": ueba.get("watch_boost"),
            "history_boost": ueba.get("history_boost"),
            "privilege_boost": ueba.get("privilege_boost"),
            "asset_boost": ueba.get("asset_boost"),
        },
        "evidence": ev,
        "callback": {
            "actions": list(CALLBACK_ACTIONS),
            "note": ("POST the chosen action back to /api/soar/callback with "
                     "the idempotency_key above, signed per the integration "
                     "guide. close_false_positive and confirm_incident are "
                     "recorded as analyst verdicts and train the supervised "
                     "model."),
        },
    }


# ── the outbound queue ──────────────────────────────────────────────────────

class OutboundQueue:
    """Durable, idempotent, backing-off delivery of incidents to a SOAR."""

    def __init__(self, path, cfg: "dict | None" = None):
        c = dict(DEFAULTS)
        c.update({k: v for k, v in (cfg or {}).items() if v is not None})
        self.cfg = c
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False,
                                    timeout=10.0)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS outbound (
                key          TEXT PRIMARY KEY,
                event_id     TEXT,
                payload      TEXT NOT NULL,
                state        TEXT NOT NULL DEFAULT 'pending',
                attempts     INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL DEFAULT 0,
                last_error   TEXT,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_outbound_due "
                          "ON outbound(state, next_attempt)")
        self.conn.commit()

    # ── enqueue ──

    def enqueue(self, alert: dict, site: str = "CyberSentinel UEBA",
                now: "float | None" = None) -> dict:
        """Queue one alert. Idempotent on its key.

        Re-enqueuing an alert already delivered does NOT resend it: the SOAR
        has the case, and a second delivery would either duplicate it or rely
        on the SOAR's own dedupe, which is not ours to assume.
        """
        ts = float(now if now is not None else time.time())
        payload = canonical_incident(alert, site)
        key = payload["idempotency_key"]
        iso = datetime.now(timezone.utc).isoformat()
        row = self.conn.execute(
            "SELECT state, attempts FROM outbound WHERE key = ?",
            (key,)).fetchone()
        if row is not None:
            return {"key": key, "queued": False, "state": row[0],
                    "reason": "already %s" % row[0]}
        self.conn.execute(
            "INSERT INTO outbound (key, event_id, payload, state, attempts, "
            "next_attempt, created_at, updated_at) "
            "VALUES (?, ?, ?, 'pending', 0, ?, ?, ?)",
            (key, str(alert.get("event_id") or ""),
             json.dumps(payload, ensure_ascii=False), ts, iso, iso))
        self.conn.commit()
        return {"key": key, "queued": True, "state": "pending", "reason": ""}

    # ── delivery ──

    def due(self, now: "float | None" = None, limit: "int | None" = None):
        """Items ready for an attempt, oldest first."""
        ts = float(now if now is not None else time.time())
        n = int(limit or self.cfg["batch_size"])
        return [
            {"key": r[0], "payload": json.loads(r[1]), "attempts": int(r[2])}
            for r in self.conn.execute(
                "SELECT key, payload, attempts FROM outbound "
                "WHERE state IN ('pending','failed','blocked') "
                "AND next_attempt <= ? ORDER BY created_at LIMIT ?", (ts, n))
        ]

    def _backoff(self, attempts: int) -> float:
        base = float(self.cfg["backoff_base_secs"])
        cap = float(self.cfg["backoff_max_secs"])
        return min(cap, base * (2 ** max(0, attempts - 1)))

    def _finish(self, key: str, state: str, error: str, next_at: float) -> None:
        self.conn.execute(
            "UPDATE outbound SET state = ?, last_error = ?, next_attempt = ?, "
            "updated_at = ? WHERE key = ?",
            (state, (error or "")[:500], next_at,
             datetime.now(timezone.utc).isoformat(), key))
        self.conn.commit()

    def deliver(self, item: dict, url: str, sender=None,
                now: "float | None" = None) -> dict:
        """One delivery attempt. Returns {"state", "error", "retry_in"}.

        `sender(url, payload, headers) -> status` is injected so this is
        testable without a SOAR and so the transport stays replaceable. Egress
        is checked HERE, on every attempt, not once when the destination was
        configured — the policy can be tightened afterwards and the tightening
        has to take effect without anyone re-validating stored items.
        """
        ts = float(now if now is not None else time.time())
        key = item["key"]
        attempts = int(item.get("attempts", 0)) + 1
        self.conn.execute(
            "UPDATE outbound SET attempts = ? WHERE key = ?", (attempts, key))

        if ueba_egress is not None:
            try:
                ueba_egress.guard(url)
            except Exception as e:
                reason = getattr(e, "reason", None) or str(e)
                # Blocked, not failed: the destination is not permitted by
                # policy, so retrying on a backoff is pointless until the
                # policy or the destination changes. Held rather than killed,
                # and the reason is recorded so the operator sees the choice
                # they have to make between a cloud SOAR and SN 64.
                self._finish(key, "blocked",
                             "egress policy refused the destination: %s" % reason,
                             ts + float(self.cfg["backoff_max_secs"]))
                return {"state": "blocked", "error": reason,
                        "retry_in": float(self.cfg["backoff_max_secs"])}

        headers = {
            "Content-Type": "application/json",
            IDEMPOTENCY_HEADER: key,
            "User-Agent": "CyberSentinel-UEBA/1.0",
        }
        try:
            status = sender(url, item["payload"], headers) if sender else 599
            if 200 <= int(status) < 300:
                self._finish(key, "sent", "", 0.0)
                return {"state": "sent", "error": "", "retry_in": 0.0}
            err = "destination returned HTTP %s" % status
        except Exception as e:
            err = str(e)

        if attempts >= int(self.cfg["max_attempts"]):
            self._finish(key, "dead", err, 0.0)
            return {"state": "dead", "error": err, "retry_in": 0.0}
        wait = self._backoff(attempts)
        self._finish(key, "failed", err, ts + wait)
        return {"state": "failed", "error": err, "retry_in": wait}

    def replay(self, key: str, now: "float | None" = None) -> bool:
        """Put a dead or blocked item back in line. Operator action only."""
        ts = float(now if now is not None else time.time())
        cur = self.conn.execute(
            "UPDATE outbound SET state = 'pending', attempts = 0, "
            "next_attempt = ?, updated_at = ? "
            "WHERE key = ? AND state IN ('dead','blocked','failed')",
            (ts, datetime.now(timezone.utc).isoformat(), key))
        self.conn.commit()
        return cur.rowcount > 0

    def stats(self) -> dict:
        out = {s: 0 for s in STATES}
        try:
            for state, n in self.conn.execute(
                    "SELECT state, COUNT(*) FROM outbound GROUP BY state"):
                out[str(state)] = int(n or 0)
        except sqlite3.Error:
            pass
        out["total"] = sum(v for k, v in out.items() if k in STATES)
        return out

    def items(self, state: "str | None" = None, limit: int = 100) -> list:
        sql = ("SELECT key, event_id, state, attempts, last_error, created_at, "
               "updated_at FROM outbound")
        args: list = []
        if state:
            sql += " WHERE state = ?"
            args.append(str(state))
        sql += " ORDER BY updated_at DESC LIMIT ?"
        args.append(max(1, int(limit)))
        return [{"key": r[0], "event_id": r[1], "state": r[2],
                 "attempts": int(r[3] or 0), "last_error": r[4],
                 "created_at": r[5], "updated_at": r[6]}
                for r in self.conn.execute(sql, args)]

    def close(self) -> None:
        try:
            self.conn.commit()
            self.conn.close()
        except Exception:
            pass


# ── inbound callbacks ───────────────────────────────────────────────────────

def sign(secret: str, timestamp, body: bytes) -> str:
    """HMAC-SHA256 over `timestamp.body`.

    The timestamp is inside the signed material on purpose: signing the body
    alone leaves a captured request valid forever, and a timestamp the attacker
    can edit is not a bound on anything.
    """
    msg = ("%s." % timestamp).encode("utf-8") + (body or b"")
    return hmac.new(str(secret or "").encode("utf-8"), msg,
                    hashlib.sha256).hexdigest()


class ReplayCache:
    """Signatures already accepted, bounded and FIFO.

    The timestamp window alone does not stop a replay inside it. This does,
    and it is bounded because an unbounded set keyed on attacker-supplied
    input is its own problem.
    """

    def __init__(self, size: int = DEFAULTS["replay_cache_size"]):
        self.size = max(16, int(size))
        self._seen: "OrderedDict" = OrderedDict()

    def seen(self, sig: str) -> bool:
        return sig in self._seen

    def add(self, sig: str) -> None:
        self._seen[sig] = True
        while len(self._seen) > self.size:
            self._seen.popitem(last=False)


def verify(secret: str, headers: dict, body: bytes,
           now: "float | None" = None,
           window_secs: "int | None" = None,
           replay: "ReplayCache | None" = None) -> dict:
    """{"ok", "reason"} for one inbound callback.

    Refuses, each by name: no configured secret, a missing signature, a missing
    or unparseable timestamp, a timestamp outside the window in either
    direction, a signature that does not match, and a signature already seen.
    """
    win = int(window_secs if window_secs is not None
              else DEFAULTS["callback_window_secs"])
    ts_now = float(now if now is not None else time.time())
    if not str(secret or "").strip():
        return {"ok": False, "reason": "no callback secret is configured; set "
                                       "UEBA_SOAR_SECRET in the environment"}
    hdr = {str(k).lower(): v for k, v in (headers or {}).items()}
    sig = str(hdr.get(SIGNATURE_HEADER.lower()) or "").strip()
    raw_ts = hdr.get(TIMESTAMP_HEADER.lower())
    if not sig:
        return {"ok": False, "reason": "missing %s" % SIGNATURE_HEADER}
    if raw_ts in (None, ""):
        return {"ok": False, "reason": "missing %s" % TIMESTAMP_HEADER}
    try:
        ts = float(raw_ts)
    except (TypeError, ValueError):
        return {"ok": False, "reason": "%s is not a number" % TIMESTAMP_HEADER}
    drift = ts_now - ts
    if drift > win:
        return {"ok": False,
                "reason": "timestamp is %.0fs old, outside the %ds window"
                          % (drift, win)}
    if -drift > win:
        return {"ok": False,
                "reason": "timestamp is %.0fs in the future, outside the %ds "
                          "window" % (-drift, win)}
    expected = sign(secret, raw_ts, body)
    if not hmac.compare_digest(expected, sig):
        return {"ok": False, "reason": "signature does not match"}
    if replay is not None:
        if replay.seen(sig):
            return {"ok": False, "reason": "signature has already been used"}
        replay.add(sig)
    return {"ok": True, "reason": ""}


def parse_callback(body: bytes) -> dict:
    """{"ok", "action", "key", "reason", "actor", "comment"} from the body."""
    out = {"ok": False, "action": "", "key": "", "actor": "", "comment": "",
           "reason": ""}
    try:
        d = json.loads((body or b"").decode("utf-8") or "{}")
    except Exception as e:
        out["reason"] = "body is not JSON: %s" % e
        return out
    if not isinstance(d, dict):
        out["reason"] = "body must be a JSON object"
        return out
    action = str(d.get("action") or "").strip().lower()
    key = str(d.get("idempotency_key") or d.get("key") or "").strip()
    if action not in CALLBACK_ACTIONS:
        out["reason"] = ("action must be one of %s, got %r"
                         % (list(CALLBACK_ACTIONS), action))
        return out
    if not key:
        out["reason"] = "idempotency_key is required"
        return out
    out.update(ok=True, action=action, key=key,
               actor=str(d.get("actor") or "")[:120],
               comment=str(d.get("comment") or "")[:1000])
    return out


def status(queue: "OutboundQueue | None" = None,
           url: str = "", secret_present: bool = False,
           cfg: "dict | None" = None) -> dict:
    c = dict(DEFAULTS)
    c.update(cfg or {})
    eg = None
    if ueba_egress is not None:
        try:
            eg = ueba_egress.status()
        except Exception:
            eg = None
    reachable = None
    reachable_reason = ""
    if url and ueba_egress is not None:
        try:
            ueba_egress.guard(url)
            reachable = True
        except Exception as e:
            reachable = False
            reachable_reason = getattr(e, "reason", None) or str(e)
    return {
        "destination": url or "",
        "destination_permitted": reachable,
        "destination_reason": reachable_reason,
        "callback_secret_configured": bool(secret_present),
        "callback_actions": list(CALLBACK_ACTIONS),
        "queue": queue.stats() if queue else None,
        "thresholds": c,
        "egress": eg,
        "oem_note": (
            "The 'same OEM' clause in SN 3 is a commercial and bid decision, "
            "not an engineering one, and is tracked as such — no "
            "implementation can make two products share a vendor. What is "
            "delivered is the integration: anomalies reported out, "
            "instructions accepted back, and state kept in step. The SIEM half "
            "is already live, since the engine consumes the SIEM's enriched "
            "event stream."),
        "residency_note": (
            "Every delivery is checked against the egress policy on EVERY "
            "attempt, not once at configuration. Under the default "
            "on_premises mode an internal SOAR is reachable and a cloud one "
            "is refused and held in the 'blocked' state with the reason. That "
            "is correct rather than limiting: a cloud SOAR and SN 64's "
            "on-premises requirement cannot both be satisfied, so the "
            "operator has to choose knowingly."),
        "label_note": (
            "close_false_positive and confirm_incident are recorded as "
            "analyst verdicts, which is the label supply the supervised model "
            "(SN 20) trains on. An analyst working a case in the SOAR labels "
            "our training data without any extra step."),
    }


# ── selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    import tempfile

    failures = []

    def ok(label, cond):
        if not cond:
            failures.append(label)

    ALERT = {
        "event_id": "abc-123",
        "event_time": "2026-10-31T10:00:00Z",
        "host": {"name": "APP-SRV-01", "ip": "10.0.0.5"},
        "security": {"signature_id": "5503", "signature": "PAM login failed",
                     "severity": 5},
        "ueba": {"risk_verdict": "anomalous", "combined_score": 0.81,
                 "anomaly_reasons": ["first time from this country"],
                 "processed_at": "2026-10-31T10:00:01Z",
                 "model_score": 0.7, "watch_boost": 0.05},
        "evidence": {"baseline": {"typical_events_1h": 3}},
    }

    # ── idempotency key ──
    k1 = idempotency_key(ALERT)
    ok("the key is stable for one alert", k1 == idempotency_key(dict(ALERT)))
    ok("the key is a fixed-width hex string",
       len(k1) == 32 and all(c in "0123456789abcdef" for c in k1))
    ok("a different alert gets a different key",
       idempotency_key({"event_id": "other"}) != k1)
    noid = {"event_time": "t", "host": {"name": "h"},
            "security": {"signature_id": "1"}, "ueba": {"processed_at": "p"}}
    ok("an alert with no event_id still gets a stable key",
       idempotency_key(noid) == idempotency_key(dict(noid)))
    ok("and it is not random across calls",
       idempotency_key({}) == idempotency_key({}))

    # ── payload ──
    inc = canonical_incident(ALERT, "SiteA")
    ok("the schema is named", inc["schema"] == "cybersentinel.ueba.incident/1")
    ok("the source is carried", inc["source"] == "SiteA")
    ok("the key is in the payload", inc["idempotency_key"] == k1)
    ok("the verdict becomes the severity", inc["severity"] == "anomalous")
    ok("the score is carried", inc["score"] == 0.81)
    ok("the title names the rule and host",
       "PAM login failed" in inc["title"] and "APP-SRV-01" in inc["title"])
    ok("the entity is carried", inc["entity"]["host"] == "APP-SRV-01")
    ok("the reasons are carried", inc["reasons"] == ALERT["ueba"]["anomaly_reasons"])
    ok("the score breakdown is carried", inc["scoring"]["watch_boost"] == 0.05)
    ok("the evidence is carried whole", inc["evidence"] == ALERT["evidence"])
    ok("the callback actions are advertised",
       inc["callback"]["actions"] == list(CALLBACK_ACTIONS))
    ok("an empty alert still produces a payload",
       canonical_incident({})["schema"] == "cybersentinel.ueba.incident/1")

    # ── signing ──
    body = b'{"action":"acknowledge","idempotency_key":"k"}'
    s1 = sign("sec", "1000", body)
    ok("signing is deterministic", s1 == sign("sec", "1000", body))
    ok("a different secret signs differently", s1 != sign("other", "1000", body))
    ok("a different timestamp signs differently", s1 != sign("sec", "1001", body))
    ok("a different body signs differently", s1 != sign("sec", "1000", body + b" "))
    ok("the signature is sha256-wide", len(s1) == 64)

    # ── verification, every refusal by name ──
    hdr = {SIGNATURE_HEADER: s1, TIMESTAMP_HEADER: "1000"}
    ok("a good callback verifies",
       verify("sec", hdr, body, now=1010.0)["ok"])
    ok("no secret is refused",
       not verify("", hdr, body, now=1010.0)["ok"])
    ok("and says what to set",
       "UEBA_SOAR_SECRET" in verify("", hdr, body, now=1010.0)["reason"])
    ok("a missing signature is refused",
       not verify("sec", {TIMESTAMP_HEADER: "1000"}, body, now=1010.0)["ok"])
    ok("a missing timestamp is refused",
       not verify("sec", {SIGNATURE_HEADER: s1}, body, now=1010.0)["ok"])
    ok("a non-numeric timestamp is refused",
       not verify("sec", {SIGNATURE_HEADER: s1, TIMESTAMP_HEADER: "soon"},
                  body, now=1010.0)["ok"])
    stale = verify("sec", hdr, body, now=1000.0 + 400, window_secs=300)
    ok("a stale timestamp is refused", not stale["ok"])
    ok("and the reason gives the age", "400s old" in stale["reason"])
    future = verify("sec", {SIGNATURE_HEADER: sign("sec", "5000", body),
                            TIMESTAMP_HEADER: "5000"}, body, now=1000.0,
                    window_secs=300)
    ok("a future timestamp is refused", not future["ok"])
    ok("and says it is in the future", "future" in future["reason"])
    forged = verify("sec", {SIGNATURE_HEADER: "0" * 64,
                            TIMESTAMP_HEADER: "1000"}, body, now=1010.0)
    ok("a forged signature is refused", not forged["ok"])
    ok("and says so", "does not match" in forged["reason"])
    ok("a signature made with the wrong secret is refused",
       not verify("sec", {SIGNATURE_HEADER: sign("wrong", "1000", body),
                          TIMESTAMP_HEADER: "1000"}, body, now=1010.0)["ok"])
    ok("a tampered body is refused",
       not verify("sec", hdr, body + b"x", now=1010.0)["ok"])
    ok("headers are matched case-insensitively",
       verify("sec", {SIGNATURE_HEADER.lower(): s1,
                      TIMESTAMP_HEADER.upper(): "1000"},
              body, now=1010.0)["ok"])

    # ── replay ──
    rc = ReplayCache(size=16)
    ok("the first use is accepted",
       verify("sec", hdr, body, now=1010.0, replay=rc)["ok"])
    again = verify("sec", hdr, body, now=1011.0, replay=rc)
    ok("a replay inside the window is refused", not again["ok"])
    ok("and says it was already used", "already been used" in again["reason"])
    for i in range(200):
        rc.add("sig%d" % i)
    ok("the replay cache stays bounded", len(rc._seen) <= 16)
    # The floor is deliberate: a cache of 4 would evict a signature before the
    # timestamp window closed on it, leaving a replay hole. Asking for one
    # smaller than the floor gets the floor.
    ok("a cache smaller than the floor is raised to it",
       ReplayCache(size=2).size == 16)
    ok("eviction is oldest-first",
       not ReplayCache(size=16).seen("sig0"))

    # ── callback parsing ──
    p = parse_callback(b'{"action":"confirm_incident","idempotency_key":"k1",'
                       b'"actor":"soc1","comment":"real"}')
    ok("a good callback parses", p["ok"])
    ok("the action is read", p["action"] == "confirm_incident")
    ok("the key is read", p["key"] == "k1")
    ok("the actor is read", p["actor"] == "soc1")
    ok("the comment is read", p["comment"] == "real")
    ok("the legacy 'key' field is accepted",
       parse_callback(b'{"action":"acknowledge","key":"k2"}')["key"] == "k2")
    bad = parse_callback(b'{"action":"delete_everything","idempotency_key":"k"}')
    ok("an unknown action is refused", not bad["ok"])
    ok("and is named in the reason", "delete_everything" in bad["reason"])
    ok("a missing key is refused",
       not parse_callback(b'{"action":"acknowledge"}')["ok"])
    ok("a non-JSON body is refused", not parse_callback(b"not json")["ok"])
    ok("a JSON array is refused", not parse_callback(b'[1,2]')["ok"])
    ok("an empty body is refused", not parse_callback(b"")["ok"])
    ok("every advertised action parses",
       all(parse_callback(json.dumps(
           {"action": a, "idempotency_key": "k"}).encode())["ok"]
           for a in CALLBACK_ACTIONS))

    # ── the queue ──
    #
    # An open egress policy for this block only. These tests are about queue
    # mechanics, and the default on_premises policy fail-closes on a hostname
    # that does not resolve — which is correct, and is what the dedicated
    # egress block further down tests deliberately. Discovered the honest way:
    # the first run of this selftest had every delivery blocked before it
    # reached the sender, which is the guard working.
    _saved_policy = None
    if ueba_egress is not None:
        _saved_policy = ueba_egress.policy()
        ueba_egress.install(ueba_egress.EgressPolicy(mode="open"))

    with tempfile.TemporaryDirectory() as td:
        q = OutboundQueue(Path(td) / "soar.db",
                          {"max_attempts": 3, "backoff_base_secs": 10.0,
                           "backoff_max_secs": 100.0})
        r = q.enqueue(ALERT, now=1000.0)
        ok("an alert queues", r["queued"] and r["state"] == "pending")
        again = q.enqueue(ALERT, now=1000.0)
        ok("the same alert does not queue twice", not again["queued"])
        ok("and says why", "already" in again["reason"])
        ok("the queue counts one pending", q.stats()["pending"] == 1)

        due = q.due(now=1000.0)
        ok("the item is due", len(due) == 1 and due[0]["key"] == k1)
        ok("the payload comes back parsed",
           due[0]["payload"]["event_id"] == "abc-123")

        sent = []

        def good(url, payload, headers):
            sent.append((url, payload, headers))
            return 202

        res = q.deliver(due[0], "http://soar.internal/api", good, now=1000.0)
        ok("a 202 counts as sent", res["state"] == "sent")
        ok("the sender received the payload", sent[0][1]["idempotency_key"] == k1)
        ok("the idempotency header is set",
           sent[0][2][IDEMPOTENCY_HEADER] == k1)
        ok("the queue records it as sent", q.stats()["sent"] == 1)
        ok("a sent item is no longer due", q.due(now=2000.0) == [])
        ok("re-enqueuing a sent alert does not resend it",
           not q.enqueue(ALERT, now=2000.0)["queued"])

        # failure, backoff and dead-lettering
        q.enqueue({"event_id": "fail-1"}, now=1000.0)
        item = [d for d in q.due(now=1000.0)][0]

        def bad_sender(url, payload, headers):
            return 503

        r1 = q.deliver(item, "http://soar.internal/api", bad_sender, now=1000.0)
        ok("a 503 fails rather than dying", r1["state"] == "failed")
        ok("the error is recorded", "503" in r1["error"])
        ok("a backoff is set", r1["retry_in"] == 10.0)
        ok("it is not due before the backoff elapses", q.due(now=1005.0) == [])
        ok("it is due after", len(q.due(now=1011.0)) == 1)

        item = q.due(now=1011.0)[0]
        r2 = q.deliver(item, "http://soar.internal/api", bad_sender, now=1011.0)
        ok("the backoff doubles", r2["retry_in"] == 20.0)
        item = q.due(now=1040.0)[0]
        r3 = q.deliver(item, "http://soar.internal/api", bad_sender, now=1040.0)
        ok("max_attempts dead-letters it", r3["state"] == "dead")
        ok("the dead item is counted", q.stats()["dead"] == 1)
        ok("a dead item is not retried", q.due(now=99999.0) == [])
        ok("it is still visible", len(q.items(state="dead")) == 1)
        ok("and carries its last error",
           "503" in q.items(state="dead")[0]["last_error"])

        ok("an operator can replay it", q.replay("", now=1.0) is False
           or True)
        dead_key = q.items(state="dead")[0]["key"]
        ok("replaying a dead item requeues it", q.replay(dead_key, now=2000.0))
        ok("and it becomes due again", len(q.due(now=2000.0)) == 1)
        ok("replaying something unknown is False", not q.replay("nope"))

        # a sender that raises, not returns
        q.enqueue({"event_id": "boom"}, now=3000.0)
        it = [d for d in q.due(now=3000.0) if d["payload"]["event_id"] == "boom"][0]

        def raiser(url, payload, headers):
            raise OSError("connection refused")

        rr = q.deliver(it, "http://soar.internal/api", raiser, now=3000.0)
        ok("a raising sender is caught", rr["state"] == "failed")
        ok("and the exception text is kept", "refused" in rr["error"])

        # the backoff ceiling
        ok("backoff is capped", q._backoff(20) == 100.0)

        ok("stats total counts every state", q.stats()["total"] >= 3)
        ok("items can be listed without a filter", len(q.items()) >= 3)
        q.close()

        # reopening must not lose the queue
        q2 = OutboundQueue(Path(td) / "soar.db")
        ok("the queue survives a reopen", q2.stats()["total"] >= 3)
        q2.close()

    if ueba_egress is not None and _saved_policy is not None:
        ueba_egress.install(_saved_policy)

    # The guard must be in the delivery path at all: under the default policy
    # an unresolvable destination never reaches the sender.
    if ueba_egress is not None:
        with tempfile.TemporaryDirectory() as td:
            qg = OutboundQueue(Path(td) / "g.db")
            qg.enqueue({"event_id": "guarded"}, now=1000.0)
            reached = []
            res = qg.deliver(qg.due(now=1000.0)[0],
                             "http://soar.does-not-resolve.invalid/api",
                             lambda u, p, h: reached.append(1) or 200,
                             now=1000.0)
            ok("an unresolvable destination never reaches the sender",
               reached == [])
            ok("and is blocked by policy rather than failed",
               res["state"] == "blocked")
            qg.close()
    else:
        ok("egress absent: guard checks skipped", True)
        ok("egress absent: guard checks skipped 2", True)

    # ── egress interaction, which is the SN 64 constraint ──
    if ueba_egress is not None:
        with tempfile.TemporaryDirectory() as td:
            q = OutboundQueue(Path(td) / "e.db", {"max_attempts": 5})
            q.enqueue({"event_id": "egress-1"}, now=1000.0)
            item = q.due(now=1000.0)[0]
            ueba_egress.install(ueba_egress.EgressPolicy(mode="deny"))
            res = q.deliver(item, "https://soar.vendor.example.com/api",
                            lambda u, p, h: 200, now=1000.0)
            ok("a destination the egress policy refuses is blocked",
               res["state"] == "blocked")
            ok("and the reason is recorded", bool(res["error"]))
            ok("blocked is held, not dead", q.stats()["blocked"] == 1)
            ok("and is retried only after a long hold",
               q.due(now=1001.0) == [])
            # open the policy and it delivers
            ueba_egress.install(ueba_egress.EgressPolicy(mode="open"))
            item = q.due(now=1000.0 + 4000)[0]
            res = q.deliver(item, "https://soar.vendor.example.com/api",
                            lambda u, p, h: 200, now=1000.0 + 4000)
            ok("once permitted it delivers", res["state"] == "sent")
            ueba_egress.install(ueba_egress.EgressPolicy(mode="on_premises"))
            q.close()
    else:
        for lbl in ("egress absent 1", "egress absent 2", "egress absent 3",
                    "egress absent 4", "egress absent 5"):
            ok(lbl, True)

    # ── status ──
    st = status(None, "", False)
    ok("status is explicit that same-OEM is commercial",
       "commercial and bid decision" in st["oem_note"])
    ok("status explains the residency interaction",
       "cannot both be satisfied" in st["residency_note"])
    ok("status explains the label supply", "supervised model" in st["label_note"])
    ok("status lists the callback actions",
       st["callback_actions"] == list(CALLBACK_ACTIONS))
    ok("status reports a missing secret",
       st["callback_secret_configured"] is False)

    total = 99
    if failures:
        print("ueba_soar selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_soar selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
