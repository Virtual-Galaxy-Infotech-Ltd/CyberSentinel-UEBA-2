#!/usr/bin/env python3
"""
Report persistence, scheduling and delivery (RFP 38, 39, 40).

Three small JSON stores plus an output directory:

    report_definitions.json  saved custom reports        (38)
    report_schedules.json    periodic schedules          (38, 40)
    report_history.json      index of generated files    (audit trail)
    reports/                 the generated artifacts

The scheduler is a daemon thread that wakes once a minute, asks each enabled
schedule whether it is due, and generates + delivers the ones that are. It is
deliberately dumb: `next_run` is computed and stored, so a restart cannot cause
a double-send, and a schedule that was missed while the service was down runs
once on the next tick rather than firing N times to "catch up".

Generation itself is injected as a callback, because building a report needs the
dashboard's loaded alert window. That keeps this module testable on its own and
keeps the dashboard free of scheduling logic.

SCHEDULE TIMES ARE SERVER-LOCAL. An administrator setting "daily at 08:00" means
08:00 where the box sits, not UTC, and silently shifting that by the machine's
offset is the kind of surprise that gets noticed only after a missed report.
"""
import json
import os
import re
import smtplib
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

INTERVALS = ("hourly", "daily", "weekly", "monthly")
WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday",
            "saturday", "sunday")

# Generated reports are capped so a daily schedule cannot quietly fill the disk.
# This box has run out of root space twice; a reporting feature must not be the
# third cause.
MAX_STORED_REPORTS = 200
MAX_STORED_BYTES = 2 * 1024 * 1024 * 1024      # 2 GB

_lock = threading.RLock()
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ── Generic JSON store ──────────────────────────────────────────────────────

def _read(path, default):
    try:
        p = Path(path)
        if not p.exists():
            return default
        return json.loads(p.read_text(encoding="utf-8") or "null") or default
    except Exception as e:
        print(f"[reports] failed to read {path}: {e}")
        return default


def _write(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)


# ── Custom report definitions (38) ──────────────────────────────────────────

def definitions(path):
    return _read(path, [])


def save_definition(path, *, name, sections, hours, fmt="pdf",
                    base=None, did=None, created_by=None, description=""):
    if not name or not str(name).strip():
        raise ValueError("name is required")
    sections = [s for s in (sections or []) if s]
    if not sections:
        raise ValueError("a report needs at least one section")
    with _lock:
        items = definitions(path)
        now = datetime.now(timezone.utc).isoformat()
        rec = {
            "id":          did or ("rpt-" + uuid.uuid4().hex[:10]),
            "name":        str(name).strip()[:120],
            "description": str(description or "")[:400],
            "base":        base,                    # optional built-in it derives from
            "sections":    sections,
            "hours":       int(hours or 24),
            "format":      fmt or "pdf",
            "created_by":  created_by,
            "created_at":  now,
            "updated_at":  now,
        }
        existing = next((i for i, d in enumerate(items) if d.get("id") == rec["id"]), None)
        if existing is None:
            items.append(rec)
            created = True
        else:
            rec["created_at"] = items[existing].get("created_at") or now
            rec["created_by"] = items[existing].get("created_by") or created_by
            items[existing] = rec
            created = False
        _write(path, items)
    return rec, created


def delete_definition(path, did):
    with _lock:
        items = definitions(path)
        kept = [d for d in items if d.get("id") != did]
        if len(kept) == len(items):
            return False
        _write(path, kept)
    return True


# ── Schedules (40) ──────────────────────────────────────────────────────────

def schedules(path):
    return _read(path, [])


def _local_now():
    return datetime.now().astimezone()


def local_tz_label():
    n = _local_now()
    off = n.utcoffset() or timedelta(0)
    mins = int(off.total_seconds() // 60)
    sign = "+" if mins >= 0 else "-"
    return f"{n.tzname() or 'local'} (UTC{sign}{abs(mins) // 60:02d}:{abs(mins) % 60:02d})"


def compute_next_run(sched, after=None):
    """The next local datetime this schedule should fire, strictly after `after`."""
    now = after or _local_now()
    interval = (sched.get("interval") or "daily").lower()
    hh, mm = _parse_at(sched.get("at") or "08:00")

    if interval == "hourly":
        nxt = now.replace(minute=mm % 60, second=0, microsecond=0)
        if nxt <= now:
            nxt += timedelta(hours=1)
        return nxt

    base = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if interval == "daily":
        return base if base > now else base + timedelta(days=1)

    if interval == "weekly":
        want = sched.get("weekday")
        want = WEEKDAYS.index(want) if isinstance(want, str) and want in WEEKDAYS else int(want or 0)
        delta = (want - base.weekday()) % 7
        nxt = base + timedelta(days=delta)
        return nxt if nxt > now else nxt + timedelta(days=7)

    if interval == "monthly":
        # Clamped to 28 so every month has the day — a schedule set for the 31st
        # that silently skips February is worse than one that runs on the 28th.
        day = max(1, min(int(sched.get("day") or 1), 28))
        nxt = base.replace(day=day)
        if nxt <= now:
            nxt = (nxt.replace(day=1) + timedelta(days=32)).replace(day=day, hour=hh,
                                                                    minute=mm, second=0,
                                                                    microsecond=0)
        return nxt

    return base + timedelta(days=1)


def _parse_at(s):
    try:
        hh, mm = str(s).split(":")[:2]
        return max(0, min(int(hh), 23)), max(0, min(int(mm), 59))
    except Exception:
        return 8, 0


def save_schedule(path, *, report_id, interval, at="08:00", hours=24, fmt="pdf",
                  recipients=None, name=None, weekday=None, day=None,
                  enabled=True, sid=None, created_by=None):
    if (interval or "").lower() not in INTERVALS:
        raise ValueError(f"interval must be one of {list(INTERVALS)}")
    recipients = [r.strip() for r in (recipients or []) if r and r.strip()]
    bad = [r for r in recipients if not _EMAIL_RE.match(r)]
    if bad:
        raise ValueError(f"not a valid email address: {bad[0]}")
    with _lock:
        items = schedules(path)
        rec = {
            "id":         sid or ("sch-" + uuid.uuid4().hex[:10]),
            "name":       (name or "").strip()[:120] or None,
            "report_id":  report_id,
            "interval":   interval.lower(),
            "at":         f"{_parse_at(at)[0]:02d}:{_parse_at(at)[1]:02d}",
            "weekday":    weekday,
            "day":        day,
            "hours":      int(hours or 24),
            "format":     fmt or "pdf",
            "recipients": recipients,
            "enabled":    bool(enabled),
            "created_by": created_by,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_run":   None,
            "last_status": None,
        }
        existing = next((i for i, s in enumerate(items) if s.get("id") == rec["id"]), None)
        if existing is not None:
            old = items[existing]
            for k in ("created_at", "created_by", "last_run", "last_status"):
                rec[k] = old.get(k)
            items[existing] = rec
            created = False
        else:
            items.append(rec)
            created = True
        rec["next_run"] = compute_next_run(rec).isoformat()
        _write(path, items)
    return rec, created


def delete_schedule(path, sid):
    with _lock:
        items = schedules(path)
        kept = [s for s in items if s.get("id") != sid]
        if len(kept) == len(items):
            return False
        _write(path, kept)
    return True


# ── History + artifacts ─────────────────────────────────────────────────────

def history(path, limit=100):
    items = _read(path, [])
    return items[-limit:][::-1]


def _doc_name(fname):
    """Sidecar path for an artifact's source document."""
    return f"{fname}.doc.json"


def record_artifact(hist_path, out_dir, *, report_id, title, fmt, data,
                    hours, generated_by=None, schedule_id=None, delivery=None,
                    document=None):
    """Persist a generated report and index it. Returns the history record.

    `document` is the renderer-agnostic report that produced `data`. Storing it
    is what lets an analyst later pull the SAME report as PDF or Excel: without
    it the only way to satisfy "give me this one as a spreadsheet" would be to
    re-run the report, which silently covers a different period — the same
    report id over [now-hours, now] instead of the window it originally
    described. A file that claims to be last Tuesday's report but contains this
    Tuesday's numbers is worse than no button at all.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(report_id))[:40] or "report"
    rid = uuid.uuid4().hex[:8]
    fname = f"{safe}-{stamp}-{rid}.{fmt}"
    (out / fname).write_bytes(data)

    doc_bytes = 0
    if document is not None:
        try:
            blob = json.dumps(document, ensure_ascii=False).encode("utf-8")
            (out / _doc_name(fname)).write_bytes(blob)
            doc_bytes = len(blob)
        except Exception as e:
            # Losing the sidecar costs format conversion, not the report.
            print(f"[reports] could not store source document for {fname}: {e}")

    rec = {
        "id":           rid,
        "file":         fname,
        "report_id":    report_id,
        "title":        title,
        "format":       fmt,
        "hours":        hours,
        "bytes":        len(data),
        "doc_bytes":    doc_bytes,
        "has_document": doc_bytes > 0,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": generated_by,
        "schedule_id":  schedule_id,
        "delivery":     delivery,
    }
    with _lock:
        items = _read(hist_path, [])
        items.append(rec)
        items = _prune(items, out)
        _write(hist_path, items)
    return rec


def _prune(items, out_dir):
    """Drop the oldest artifacts once either cap is exceeded."""
    total = sum(int(i.get("bytes") or 0) + int(i.get("doc_bytes") or 0) for i in items)
    while items and (len(items) > MAX_STORED_REPORTS or total > MAX_STORED_BYTES):
        old = items.pop(0)
        total -= int(old.get("bytes") or 0) + int(old.get("doc_bytes") or 0)
        _unlink_artifact(out_dir, old)
    return items


def _unlink_artifact(out_dir, rec):
    """Remove an artifact and its source-document sidecar."""
    name = str(rec.get("file") or "")
    if not name:
        return
    for candidate in (name, _doc_name(name)):
        try:
            f = Path(out_dir) / candidate
            if f.is_file():
                f.unlink()
        except Exception as e:
            print(f"[reports] could not remove {candidate}: {e}")


def artifact_document(out_dir, hist_path, art_id):
    """(document, record) for a stored report, or (None, record) if the
    sidecar is absent — which is the case for anything generated before source
    documents were kept."""
    rec = next((r for r in _read(hist_path, []) if r.get("id") == art_id), None)
    if rec is None:
        return None, None
    out = Path(out_dir).resolve()
    try:
        p = (out / _doc_name(str(rec.get("file") or ""))).resolve()
        if out in p.parents and p.is_file():
            return json.loads(p.read_text(encoding="utf-8")), rec
    except Exception as e:
        print(f"[reports] could not read source document for {rec.get('file')}: {e}")
    return None, rec


def delete_artifact(hist_path, out_dir, art_id):
    """Remove one generated report and its history entry. Returns the record, or
    None if the id is unknown.

    The file is deleted first and a failure there is tolerated: if the artifact
    is already gone from disk, the analyst still wants the dangling history row
    to disappear rather than being stuck with a row whose Delete button never
    works.
    """
    with _lock:
        items = _read(hist_path, [])
        rec = next((r for r in items if r.get("id") == art_id), None)
        if rec is None:
            return None
        _unlink_artifact(out_dir, rec)
        _write(hist_path, [r for r in items if r.get("id") != art_id])
    return rec


def artifact_path(out_dir, hist_path, art_id):
    """Resolve a history id to a file, refusing anything outside the output dir."""
    rec = next((r for r in _read(hist_path, []) if r.get("id") == art_id), None)
    if not rec:
        return None, None
    out = Path(out_dir).resolve()
    p = (out / str(rec.get("file") or "")).resolve()
    # The filename comes from our own store, but resolving and re-checking costs
    # nothing and means a tampered history file cannot read /etc/shadow.
    if out not in p.parents or not p.is_file():
        return None, rec
    return p, rec


# ── Email delivery (39) ─────────────────────────────────────────────────────

def smtp_configured(cfg):
    return bool((cfg or {}).get("host"))


def send_email(cfg, *, to, subject, body, attachment=None, filename=None,
               mime="application/octet-stream"):
    """Send one report. Raises on failure; the caller records that in history."""
    cfg = cfg or {}
    host = cfg.get("host")
    if not host:
        raise RuntimeError("SMTP is not configured (reporting.smtp.host is empty)")
    port = int(cfg.get("port") or 587)
    sender = cfg.get("from_addr") or cfg.get("username") or "ueba@localhost"

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)
    if attachment is not None:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(attachment, maintype=maintype or "application",
                           subtype=(subtype or "octet-stream").split(";")[0].strip(),
                           filename=filename or "report")

    timeout = int(cfg.get("timeout_secs") or 30)
    if cfg.get("ssl"):
        smtp = smtplib.SMTP_SSL(host, port, timeout=timeout)
    else:
        smtp = smtplib.SMTP(host, port, timeout=timeout)
    try:
        if cfg.get("starttls") and not cfg.get("ssl"):
            smtp.starttls()
        if cfg.get("username"):
            smtp.login(cfg["username"], cfg.get("password") or "")
        smtp.send_message(msg)
    finally:
        try:
            smtp.quit()
        except Exception:
            pass


# ── Scheduler (40) ──────────────────────────────────────────────────────────

class Scheduler:
    """Fires due schedules. `runner(sched)` does the actual generation+delivery
    and returns a short status string; anything it raises is caught, recorded on
    the schedule, and does not stop the loop."""

    def __init__(self, sched_path, runner, tick_secs=60):
        self.path = sched_path
        self.runner = runner
        self.tick = tick_secs
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._seed_next_runs()
        self._thread = threading.Thread(target=self._loop, name="report-scheduler",
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _seed_next_runs(self):
        """Give every schedule a next_run at startup. A schedule whose time
        passed while the service was down is scheduled forward, not run N times
        to catch up — nobody wants 40 identical reports after an outage."""
        with _lock:
            items = schedules(self.path)
            changed = False
            for s in items:
                if not s.get("next_run"):
                    s["next_run"] = compute_next_run(s).isoformat()
                    changed = True
            if changed:
                _write(self.path, items)

    def _loop(self):
        while not self._stop.wait(self.tick):
            try:
                self._tick()
            except Exception:
                print("[reports] scheduler tick failed:\n" + traceback.format_exc())

    def _tick(self):
        now = _local_now()
        with _lock:
            items = schedules(self.path)
        due = []
        for s in items:
            if not s.get("enabled"):
                continue
            nxt = _parse_local(s.get("next_run"))
            if nxt is None or nxt <= now:
                due.append(s)
        for s in due:
            status = "ok"
            try:
                status = self.runner(s) or "ok"
            except Exception as e:
                status = f"failed: {e}"
                print(f"[reports] schedule {s.get('id')} failed: {e}")
            self._mark_ran(s.get("id"), status, now)

    def _mark_ran(self, sid, status, when):
        with _lock:
            items = schedules(self.path)
            for s in items:
                if s.get("id") == sid:
                    s["last_run"] = when.astimezone(timezone.utc).isoformat()
                    s["last_status"] = str(status)[:300]
                    s["next_run"] = compute_next_run(s, after=when).isoformat()
                    break
            _write(self.path, items)


def _parse_local(v):
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v))
        return d if d.tzinfo else d.astimezone()
    except (ValueError, TypeError):
        return None
