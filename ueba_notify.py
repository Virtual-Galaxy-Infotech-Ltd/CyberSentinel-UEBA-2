#!/usr/bin/env python3
"""
Device registry and proactive alerting (RFP points 10 and 15).

    10  device label, device priority, alert by priority, alert by score
    15  proactive and actionable alerting for anomalous behaviour and risk scores

Two stores and one dispatcher:

    devices.json       label, priority and owner per monitored device
    notify_rules.json  conditions -> channels, with throttling
    Dispatcher         tails the alert file and fires matching rules

WHY THIS LIVES IN THE DASHBOARD AND NOT THE ENGINE
--------------------------------------------------
The engine's job is to decide what is anomalous. Deciding who should be told,
through which channel, and how often, is an operational policy that changes far
more frequently than detection does — and it needs the SMTP configuration and
the device registry, both of which already live on the dashboard side. Keeping
it here means notification policy can be edited, and a broken webhook can fail,
without touching the detection path.

THROTTLING IS NOT OPTIONAL
--------------------------
This platform raises tens of thousands of alerts a week. A rule with no ceiling
is an outage of somebody's inbox, and the first thing an operator does with a
noisy alert channel is mute it — at which point the feature has negative value.
Every rule therefore carries a per-hour ceiling and a repeat-suppression window,
and both have conservative defaults.
"""
import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid

import ueba_egress
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ordered: index is the comparison rank.
PRIORITIES = ("low", "medium", "high", "critical")
VERDICTS = ("suspicious", "anomalous", "highly_anomalous")

DEFAULT_MAX_PER_HOUR = 20
DEFAULT_THROTTLE_MIN = 15
WEBHOOK_TIMEOUT = 10

_lock = threading.RLock()


# ── storage ─────────────────────────────────────────────────────────────────

def _read(path, default):
    try:
        p = Path(path)
        if not p.exists():
            return default
        return json.loads(p.read_text(encoding="utf-8") or "null") or default
    except Exception as e:
        print(f"[notify] failed to read {path}: {e}")
        return default


def _write(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)


def _now():
    return datetime.now(timezone.utc)


def _norm(v):
    return str(v or "").strip().lower()


# ── Device registry (RFP 10) ────────────────────────────────────────────────

def devices(path):
    return _read(path, [])


def device_index(path):
    """{normalised device name: record} for O(1) lookup on the alert path."""
    return {_norm(d.get("name")): d for d in devices(path) if d.get("name")}


def save_device(path, *, name, label="", priority="medium", owner="",
                notes="", updated_by=None):
    name = str(name or "").strip()
    if not name:
        raise ValueError("device name is required")
    priority = _norm(priority) or "medium"
    if priority not in PRIORITIES:
        raise ValueError(f"priority must be one of {list(PRIORITIES)}")
    rec = {
        "name":       name,
        "label":      str(label or "")[:80],
        "priority":   priority,
        "owner":      str(owner or "")[:80],
        "notes":      str(notes or "")[:300],
        "updated_by": updated_by,
        "updated_at": _now().isoformat(),
    }
    with _lock:
        items = devices(path)
        at = next((i for i, d in enumerate(items)
                   if _norm(d.get("name")) == _norm(name)), None)
        if at is None:
            items.append(rec)
            created = True
        else:
            rec["created_at"] = items[at].get("created_at") or rec["updated_at"]
            items[at] = rec
            created = False
        _write(path, items)
    return rec, created


def delete_device(path, name):
    with _lock:
        items = devices(path)
        kept = [d for d in items if _norm(d.get("name")) != _norm(name)]
        if len(kept) == len(items):
            return False
        _write(path, kept)
    return True


# ── Notification rules (RFP 15) ─────────────────────────────────────────────

def rules(path):
    return _read(path, [])


def save_rule(path, *, name, min_score=None, verdicts=None, priorities=None,
              labels=None, tactics=None, watchlisted_only=False,
              emails=None, webhook=None, throttle_minutes=None,
              max_per_hour=None, enabled=True, rid=None, created_by=None):
    name = str(name or "").strip()
    if not name:
        raise ValueError("rule name is required")

    def _clean_list(v, allowed=None, lower=True):
        out = []
        for x in (v or []):
            s = _norm(x) if lower else str(x).strip()
            if not s:
                continue
            if allowed and s not in allowed:
                raise ValueError(f"{s!r} is not one of {list(allowed)}")
            out.append(s)
        return out

    emails = [e.strip() for e in (emails or []) if e and e.strip()]
    webhook = (webhook or "").strip()
    if webhook and not webhook.lower().startswith(("http://", "https://")):
        raise ValueError("webhook must be an http(s) URL")
    if webhook:
        # Refuse the rule now rather than letting it fail silently every time it
        # fires. An operator who typed an off-premises destination needs to hear
        # about it while the form is still open.
        try:
            ueba_egress.guard(webhook)
        except ueba_egress.EgressBlocked as e:
            raise ValueError("webhook destination is not permitted: %s" % e.reason)
    if not emails and not webhook:
        raise ValueError("a rule needs at least one channel: email or webhook")

    try:
        ms = None if min_score in (None, "") else float(min_score)
    except (TypeError, ValueError):
        raise ValueError("min_score must be a number between 0 and 1")
    if ms is not None and not (0.0 <= ms <= 1.0):
        raise ValueError("min_score must be between 0 and 1")

    rec = {
        "id":               rid or ("ntf-" + uuid.uuid4().hex[:10]),
        "name":             name[:120],
        "enabled":          bool(enabled),
        "min_score":        ms,
        "verdicts":         _clean_list(verdicts, VERDICTS),
        "priorities":       _clean_list(priorities, PRIORITIES),
        "labels":           _clean_list(labels),
        "tactics":          _clean_list(tactics, lower=False),
        "watchlisted_only": bool(watchlisted_only),
        "emails":           emails,
        "webhook":          webhook,
        "throttle_minutes": int(throttle_minutes if throttle_minutes is not None
                                else DEFAULT_THROTTLE_MIN),
        "max_per_hour":     int(max_per_hour if max_per_hour is not None
                                else DEFAULT_MAX_PER_HOUR),
        "created_by":       created_by,
        "created_at":       _now().isoformat(),
        "last_fired":       None,
        "fired_count":      0,
        "suppressed_count": 0,
    }
    with _lock:
        items = rules(path)
        at = next((i for i, r in enumerate(items) if r.get("id") == rec["id"]), None)
        if at is None:
            items.append(rec)
            created = True
        else:
            for k in ("created_at", "created_by", "last_fired", "fired_count",
                      "suppressed_count"):
                rec[k] = items[at].get(k, rec[k])
            items[at] = rec
            created = False
        _write(path, items)
    return rec, created


def delete_rule(path, rid):
    with _lock:
        items = rules(path)
        kept = [r for r in items if r.get("id") != rid]
        if len(kept) == len(items):
            return False
        _write(path, kept)
    return True


# ── Matching ────────────────────────────────────────────────────────────────

def summarise(alert):
    """The flat view of an alert that rules match against and channels send."""
    ueba = alert.get("ueba") or {}
    sec = alert.get("security") or {}
    host = alert.get("host") or {}
    subj = alert.get("subject") or {}
    tactic = alert.get("__mitre_tactic")
    if tactic is None:
        rule = ((alert.get("context") or {}).get("raw_event") or {}).get("rule") or {}
        tactic = (rule.get("mitre") or {}).get("tactic") or []
    try:
        score = float(ueba.get("combined_score") or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    return {
        "event_id":    alert.get("event_id"),
        "event_time":  alert.get("event_time"),
        "user":        alert.get("__user") or subj.get("name") or "unknown",
        "host":        host.get("name") or "",
        "host_ip":     host.get("ip") or "",
        "score":       score,
        "verdict":     ueba.get("risk_verdict") or "",
        "signature":   (sec.get("signature") or "")[:160],
        "severity":    sec.get("severity"),
        "campaign_id": ueba.get("campaign_id"),
        "reasons":     ueba.get("anomaly_reasons") or [],
        "tactics":     tactic if isinstance(tactic, list) else [tactic],
        "watchlist":   ueba.get("watchlist"),
    }


def matches(rule, s, device):
    """Does this alert satisfy every condition the rule specifies?

    An unset condition means "don't care" rather than "match nothing" — a rule
    with only a score floor should fire on score alone.
    """
    if rule.get("min_score") is not None and s["score"] < rule["min_score"]:
        return False
    if rule.get("verdicts") and _norm(s["verdict"]) not in rule["verdicts"]:
        return False
    if rule.get("watchlisted_only") and not s.get("watchlist"):
        return False
    if rule.get("priorities"):
        prio = _norm((device or {}).get("priority"))
        if prio not in rule["priorities"]:
            return False
    if rule.get("labels"):
        label = _norm((device or {}).get("label"))
        if label not in rule["labels"]:
            return False
    if rule.get("tactics"):
        want = {_norm(t) for t in rule["tactics"]}
        have = {_norm(t) for t in s.get("tactics") or []}
        if not (want & have):
            return False
    return True


# ── Channels ────────────────────────────────────────────────────────────────

def _subject(s):
    return (f"[UEBA {s['verdict'].replace('_', ' ').title()}] "
            f"{s['user']} on {s['host'] or 'unknown host'} "
            f"(score {s['score']:.3f})")


def _body(s, device, rule_name, site):
    lines = [
        f"{site} raised a {s['verdict'].replace('_', ' ')} alert.",
        "",
        f"  Rule matched : {rule_name}",
        f"  Entity       : {s['user']}",
        f"  Host         : {s['host'] or '—'}  {s['host_ip'] or ''}".rstrip(),
    ]
    if device:
        lines.append(f"  Device       : {device.get('label') or '—'} "
                     f"(priority {device.get('priority', '—')})")
        if device.get("owner"):
            lines.append(f"  Owner        : {device['owner']}")
    lines += [
        f"  Score        : {s['score']:.4f}",
        f"  Signature    : {s['signature'] or '—'}",
        f"  Time         : {s['event_time'] or '—'}",
        f"  Event id     : {s['event_id'] or '—'}",
    ]
    if s.get("campaign_id"):
        lines.append(f"  Campaign     : {s['campaign_id']}")
    if s.get("tactics"):
        lines.append(f"  MITRE        : {', '.join(str(t) for t in s['tactics'])}")
    if s.get("reasons"):
        lines.append(f"  Reasons      : {', '.join(str(r) for r in s['reasons'][:6])}")
    if s.get("watchlist"):
        w = s["watchlist"]
        lines.append(f"  Watch list   : {w.get('type')}:{w.get('value')} "
                     f"— {w.get('reason') or 'no reason recorded'}")
    lines += ["", "This notification was generated automatically. Open the UEBA "
              "console to investigate."]
    return "\n".join(lines)


def post_webhook(url, payload):
    # Checked again here, not only at rule-creation time: the egress policy can
    # be tightened after a rule was saved, and the tightening must take effect
    # without anyone having to remember to re-validate every stored rule.
    ueba_egress.guard(url)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "CyberSentinel-UEBA/1.0"})
    with urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT) as r:
        return r.status


# ── Dispatcher ──────────────────────────────────────────────────────────────

class Dispatcher:
    """Tails the alert file and fires matching notification rules.

    `send_email(to, subject, body)` is injected so this module does not need to
    know the SMTP configuration; the dashboard already resolves it.
    """

    def __init__(self, alerts_file, rules_path, devices_path, state_path,
                 send_email=None, site="CyberSentinel UEBA", poll_secs=15):
        self.alerts_file = Path(alerts_file)
        self.rules_path = rules_path
        self.devices_path = devices_path
        self.state_path = Path(state_path)
        self.send_email = send_email
        self.site = site
        self.poll = poll_secs
        self._thread = None
        self._stop = threading.Event()
        # (rule_id, entity) -> last sent, for repeat suppression.
        self._last_sent = {}
        # rule_id -> deque of send timestamps, for the hourly ceiling.
        self._recent = {}

    # ── position, persisted so a restart neither replays nor skips ──────────
    def _load_pos(self):
        try:
            return int(json.loads(self.state_path.read_text())["position"])
        except Exception:
            try:
                return self.alerts_file.stat().st_size
            except OSError:
                return 0

    def _save_pos(self, pos):
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"position": pos}))
            os.replace(tmp, self.state_path)
        except Exception as e:
            print(f"[notify] could not persist position: {e}")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, name="notify-dispatch",
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        pos = self._load_pos()
        while not self._stop.wait(self.poll):
            try:
                pos = self._tick(pos)
            except Exception as e:
                print(f"[notify] dispatch tick failed: {e}")

    def _tick(self, pos):
        if not self.alerts_file.exists():
            return pos
        try:
            size = self.alerts_file.stat().st_size
        except OSError:
            return pos
        if size < pos:
            pos = 0                      # rotated
        if size == pos:
            return pos

        active = [r for r in rules(self.rules_path) if r.get("enabled")]
        if not active:
            # Nothing to evaluate, but still advance so enabling a rule later
            # does not replay the whole backlog into somebody's inbox.
            self._save_pos(size)
            return size

        devidx = device_index(self.devices_path)
        with open(self.alerts_file, "r", encoding="utf-8", errors="replace") as f:
            f.seek(pos)
            chunk = f.read()
            pos = f.tell()
        for line in chunk.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except Exception:
                continue
            s = summarise(alert)
            device = devidx.get(_norm(s["host"]))
            for rule in active:
                try:
                    if matches(rule, s, device):
                        self._fire(rule, s, device)
                except Exception as e:
                    print(f"[notify] rule {rule.get('id')} failed: {e}")
        self._save_pos(pos)
        return pos

    def _allowed(self, rule, entity):
        """Throttle: repeat suppression per entity, plus an hourly ceiling."""
        now = time.time()
        rid = rule.get("id")
        window = int(rule.get("throttle_minutes") or 0) * 60
        if window:
            key = (rid, entity)
            last = self._last_sent.get(key)
            if last and (now - last) < window:
                return False, "throttled"
        cap = int(rule.get("max_per_hour") or 0)
        if cap:
            dq = self._recent.setdefault(rid, deque())
            while dq and now - dq[0] > 3600:
                dq.popleft()
            if len(dq) >= cap:
                return False, "hourly cap"
        return True, None

    def _fire(self, rule, s, device):
        ok, why = self._allowed(rule, s["user"])
        if not ok:
            self._bump(rule["id"], suppressed=True)
            return
        sent_any = False
        if rule.get("emails") and self.send_email:
            try:
                self.send_email(rule["emails"], _subject(s),
                                _body(s, device, rule.get("name"), self.site))
                sent_any = True
            except Exception as e:
                print(f"[notify] email for rule {rule['id']} failed: {e}")
        if rule.get("webhook"):
            try:
                post_webhook(rule["webhook"], {
                    "source": "cybersentinel-ueba",
                    "rule": {"id": rule["id"], "name": rule.get("name")},
                    "alert": s,
                    "device": device,
                    "generated_at": _now().isoformat(),
                })
                sent_any = True
            except Exception as e:
                print(f"[notify] webhook for rule {rule['id']} failed: {e}")
        if sent_any:
            now = time.time()
            self._last_sent[(rule["id"], s["user"])] = now
            self._recent.setdefault(rule["id"], deque()).append(now)
            self._bump(rule["id"], suppressed=False)

    def _bump(self, rid, suppressed):
        with _lock:
            items = rules(self.rules_path)
            for r in items:
                if r.get("id") == rid:
                    if suppressed:
                        r["suppressed_count"] = int(r.get("suppressed_count") or 0) + 1
                    else:
                        r["fired_count"] = int(r.get("fired_count") or 0) + 1
                        r["last_fired"] = _now().isoformat()
                    break
            _write(self.rules_path, items)
