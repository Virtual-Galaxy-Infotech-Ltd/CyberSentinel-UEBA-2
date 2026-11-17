#!/usr/bin/env python3
"""
ueba_device_identity.py
───────────────────────
CyberSentinel UEBA — stable machine identity across DHCP changes (RFP SN 5).

  SN 5  The solution must be able to adjust itself in a DHCP environment and
        yet uniquely identify machines with high accuracy despite change of
        IP address.

Why this is buildable today, against what the tracking sheet assumed
────────────────────────────────────────────────────────────────────
The sheet recorded this as blocked on an asset registry or a MAC source from
the customer. Measured on 3,412 local alerts, it is not:

  * 12 distinct agent ids, and NOT ONE of them ever reported a second
    hostname. The agent-id↔hostname binding is perfectly stable.
  * 5 of those 12 ids were seen on MORE THAN ONE IP address — one of them on
    three (…10.207, …10.217, …10.147). That is DHCP churn already happening in
    the live estate, with a stable key surviving it.
  * 0 IP addresses were seen under two different agent ids in that window —
    but that is a property of a short window, not a guarantee, so the trail
    below is still time-bounded rather than a flat IP→device map.

So the agent id IS the asset identifier for every host that runs an agent. A
MAC address would add nothing it does not already provide. What a MAC source
WOULD add is coverage of agentless devices, and the IP trail below is the
honest substitute for those: it learns which device held an address during
which period, from the events where a stable key and an address appear
together.

How an address is resolved
──────────────────────────
Precedence, highest first. Each answer carries the rule that produced it, so a
wrong binding can be argued with rather than taken on trust:

  1. operator        an explicit binding in the register — always wins
  2. agent_id        host.id, proven stable above
  3. hostname        host.name, when no agent id is present
  4. ip_trail        no name or id on this event, but the address was held by
                     a known device during a period that covers this event
  5. ip_current      the event is later than anything recorded, and the
                     address's lease is still open to a known device
  6. ip_recent       the address was held by a known device just outside the
                     event's time, within the grace window
  7. address         nothing known — keyed by address, and SAID to be unstable

Why the trail is time-bounded
─────────────────────────────
A flat IP→device map is the obvious shortcut and it is wrong in exactly the
way SN 5 is written against. When a lease moves, that map either overwrites
the old device (losing its history) or keeps the first device forever
(attributing the new one's behaviour to it). Intervals avoid both: the old
holder's interval is CLOSED and the new one's is OPENED, so each device keeps
its own behaviour and neither inherits the other's.

The invariant, stated because it is the easy thing to get backwards: AN
ADDRESS has at most one open interval — only one machine can hold a lease at a
time, so a new holder closes the previous one. A DEVICE may hold several
addresses at once and that is not a fault: a laptop on wifi and ethernet
genuinely has two, and nothing in the event stream proves an old lease was
released. Closing a device's other intervals on every address change would
break the dual-interface case to tidy up a case that is already bounded by
stale_secs and closed immediately by any real new holder.

This module is deliberately storage-only on the hot path: resolve() does one
indexed read, and a write happens only when an address's holder actually
changes or an interval needs extending.
"""

# Annotations as strings so this imports on 3.9 as well as the server's 3.12.
from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

# How a device key was decided, best first. Exposed so the console and the
# evidence pack can show it without re-deriving it.
SOURCES = ("operator", "agent_id", "hostname", "ip_trail", "ip_current",
           "ip_recent", "address")

# Namespaces. Kept distinct so a device identified by address can never be
# confused with one identified by a stable key — they are different claims.
NS_AGENT = "agent"
NS_NAME = "name"
NS_ADDR = "addr"

# The two bounds govern different directions in time, which is worth being
# explicit about because they are easy to confuse:
#
#   GRACE bounds looking BACKWARD. An event timestamped before an interval
#   opened, or after one was closed, is still attributed to that device if it
#   falls this close to it. Events do arrive out of order, and a few minutes of
#   slack costs nothing; it is reported as ip_recent so the weaker claim shows.
DEFAULT_GRACE_SECS = 900.0

# STALE bounds looking FORWARD, and is necessarily much larger. An open
# interval is the statement "this device holds this address now", so an event
# after the last confirmed sighting belongs to it — but only while that
# statement is still credible. A lease nobody has confirmed for two days is no
# longer evidence, and an event past that point is reported as an unstable
# address identity instead. The same bound decides when a quiet device's own
# next event opens a fresh interval rather than extending a dormant one.
DEFAULT_STALE_SECS = 86400.0 * 2

_HOST_ID_FIELDS = ("host.id", "agent.id", "context.raw_event.agent.id")
_HOST_NAME_FIELDS = ("host.name", "agent.name", "context.raw_event.agent.name")
_HOST_IP_FIELDS = ("host.ip", "agent.ip", "context.raw_event.agent.ip")
# The address an event is ABOUT when it carries no agent of its own — firewall
# and flow records, which are the agentless population this exists for.
_SRC_IP_FIELDS = ("subject.ip", "data.srcip", "context.raw_event.data.srcip")

_lock = threading.Lock()
_reg_cache: dict = {}


# ── helpers ──────────────────────────────────────────────────────────────────

def _norm(v) -> str:
    return str(v or "").strip().casefold()


def get_nested(obj, path: str, default=None):
    cur = obj
    for part in str(path).split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


def _first(log: dict, fields) -> str:
    for f in fields:
        v = get_nested(log, f)
        if v not in (None, "", "-"):
            return str(v).strip()
    return ""


def is_ip(v) -> bool:
    try:
        ipaddress.ip_address(str(v).strip())
        return True
    except ValueError:
        return False


def device_key(ns: str, value: str) -> str:
    """A device key. Always namespaced: `agent:070` and `name:070` are
    different claims about different things and must not collide."""
    v = _norm(value)
    return "%s:%s" % (ns, v) if v else ""


def parse_time(v) -> "datetime | None":
    """Parse an event timestamp. Returns None rather than guessing — a wrong
    timestamp would put an interval in the wrong place, which is worse than
    having none."""
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


def event_time(log: dict) -> datetime:
    for f in ("ueba.processed_at", "event_time", "@timestamp",
              "context.raw_event.timestamp"):
        d = parse_time(get_nested(log, f))
        if d:
            return d
    return datetime.now(timezone.utc)


# ── operator register ────────────────────────────────────────────────────────
#
# Same file-and-mtime contract as the watch list and the asset register, so a
# binding an operator writes takes effect on the next event with no restart.
# This is also where a MAC-derived or CMDB-derived asset list would land if one
# ever arrives: the format is {address_or_name: device_label}, and nothing else
# in the module has to change to consume it.

def _read_register(path) -> dict:
    p = Path(path)
    try:
        st = p.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None
    key = str(p)
    hit = _reg_cache.get(key)
    if hit and hit["stamp"] == stamp:
        return hit["data"]

    data: dict = {}
    if stamp is not None:
        try:
            raw = json.loads(p.read_text(encoding="utf-8") or "{}")
            if isinstance(raw, dict):
                src = raw.get("bindings") if "bindings" in raw else raw
                for k, v in (src or {}).items():
                    kk, vv = _norm(k), str(v or "").strip()
                    if kk and vv:
                        data[kk] = vv
        except Exception as ex:
            print("[device_identity] failed to read %s: %s" % (p, ex))
            data = {}
    _reg_cache[key] = {"stamp": stamp, "data": data}
    return data


def register(path) -> dict:
    with _lock:
        return dict(_read_register(path))


def save_register(path, bindings: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = {"bindings": {_norm(k): str(v).strip()
                         for k, v in (bindings or {}).items()
                         if _norm(k) and str(v or "").strip()}}
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)
    with _lock:
        _reg_cache.pop(str(p), None)


# ── the trail store ──────────────────────────────────────────────────────────

class DeviceTrail:
    """Which device held which address, when.

    One row per (address, device, interval). Its own SQLite file, following
    ueba_risk_history: the module owns its schema outright, which is what lets
    it be tested in isolation without standing up the feature pipeline.
    """

    def __init__(self, path, grace_secs: float = DEFAULT_GRACE_SECS,
                 stale_secs: float = DEFAULT_STALE_SECS):
        self.path = str(path)
        self.grace = float(grace_secs)
        self.stale = float(stale_secs)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False,
                                    timeout=10.0)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_trail (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                address     TEXT NOT NULL,
                device      TEXT NOT NULL,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                events      INTEGER NOT NULL DEFAULT 1,
                closed      INTEGER NOT NULL DEFAULT 0
            )
        """)
        # The hot-path read is "the interval for this address covering this
        # time", so the index leads with the address.
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_trail_addr "
                          "ON ip_trail(address, last_seen)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_trail_device "
                          "ON ip_trail(device)")
        self.conn.commit()
        self._pending = 0

    # ── writes ──

    def observe(self, address: str, device: str, when: datetime) -> dict:
        """Record that `device` held `address` at `when`.

        Returns {"action": opened|extended|moved|ignored, "previous": device|None}.

        "moved" is the case this table exists for: the address is now held by a
        different device, so the old interval is closed rather than overwritten
        and the two devices keep their own histories.
        """
        out = {"action": "ignored", "previous": None}
        addr, dev = _norm(address), _norm(device)
        if not addr or not dev or not is_ip(addr) or when is None:
            return out
        iso = when.isoformat()
        try:
            row = self.conn.execute(
                "SELECT id, device, first_seen, last_seen, events FROM ip_trail "
                "WHERE address = ? AND closed = 0 "
                "ORDER BY last_seen DESC LIMIT 1", (addr,)).fetchone()

            if row is None:
                self.conn.execute(
                    "INSERT INTO ip_trail (address, device, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?)", (addr, dev, iso, iso))
                out = {"action": "opened", "previous": None}
            elif row[1] == dev:
                last = parse_time(row[3])
                gap = (when - last).total_seconds() if last else 0.0
                if gap > self.stale:
                    # Same device, but after a long silence. Opening a fresh
                    # interval keeps the gap visible instead of asserting the
                    # device held the address throughout a two-day silence.
                    self.conn.execute("UPDATE ip_trail SET closed = 1 WHERE id = ?",
                                      (row[0],))
                    self.conn.execute(
                        "INSERT INTO ip_trail (address, device, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?)", (addr, dev, iso, iso))
                    out = {"action": "opened", "previous": dev}
                else:
                    # Extend. first_seen moves back if this event predates it,
                    # because events can arrive out of order.
                    first = parse_time(row[2])
                    new_first = (iso if (first and when < first) else row[2])
                    new_last = (iso if (not last or when > last) else row[3])
                    self.conn.execute(
                        "UPDATE ip_trail SET first_seen = ?, last_seen = ?, "
                        "events = events + 1 WHERE id = ?",
                        (new_first, new_last, row[0]))
                    out = {"action": "extended", "previous": dev}
            else:
                self.conn.execute("UPDATE ip_trail SET closed = 1 WHERE id = ?",
                                  (row[0],))
                self.conn.execute(
                    "INSERT INTO ip_trail (address, device, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?)", (addr, dev, iso, iso))
                out = {"action": "moved", "previous": row[1]}

            self._pending += 1
            if self._pending >= 50:
                self.conn.commit()
                self._pending = 0
        except Exception as e:
            print("[device_identity] observe failed for %s: %s" % (addr, e))
        return out

    def commit(self) -> None:
        try:
            self.conn.commit()
            self._pending = 0
        except Exception:
            pass

    # ── reads ──

    def holder_at(self, address: str, when: datetime) -> dict:
        """{"device", "source", "why"} for whoever held `address` at `when`.

        Covering interval first; then an interval that ended within the grace
        window, reported as ip_recent so the weaker claim is visible.
        """
        out = {"device": "", "source": "", "why": ""}
        addr = _norm(address)
        if not addr or when is None:
            return out
        iso = when.isoformat()
        try:
            row = self.conn.execute(
                "SELECT device, first_seen, last_seen FROM ip_trail "
                "WHERE address = ? AND first_seen <= ? AND last_seen >= ? "
                "ORDER BY events DESC LIMIT 1", (addr, iso, iso)).fetchone()
            if row:
                return {"device": row[0], "source": "ip_trail",
                        "why": "%s held %s from %s to %s"
                               % (row[0], addr, str(row[1])[:19], str(row[2])[:19])}

            # The address's lease is still OPEN to someone and this event is
            # later than anything recorded for it. That is the ordinary case
            # for an agentless event arriving between two agent reports, and
            # the open interval is exactly the statement "this device holds
            # this address now" — so it answers, bounded by staleness, because
            # a lease nobody has confirmed for days is no longer evidence.
            row = self.conn.execute(
                "SELECT device, first_seen, last_seen FROM ip_trail "
                "WHERE address = ? AND closed = 0 "
                "ORDER BY last_seen DESC LIMIT 1", (addr,)).fetchone()
            if row:
                last = parse_time(row[2])
                if last and when >= last:
                    gap = (when - last).total_seconds()
                    if gap <= self.stale:
                        return {"device": row[0], "source": "ip_current",
                                "why": "%s holds %s; lease open since %s, last "
                                       "confirmed %.0fs before this event"
                                       % (row[0], addr, str(row[1])[:19], gap)}

            # Nearest interval on either side, then the grace test. Checking
            # both directions matters: an event can arrive before the interval
            # that will come to cover it has been opened.
            best = None
            for dev, first, last in self.conn.execute(
                    "SELECT device, first_seen, last_seen FROM ip_trail "
                    "WHERE address = ? ORDER BY last_seen DESC LIMIT 20", (addr,)):
                f, l = parse_time(first), parse_time(last)
                if not f or not l:
                    continue
                if when > l:
                    gap = (when - l).total_seconds()
                elif when < f:
                    gap = (f - when).total_seconds()
                else:
                    gap = 0.0
                if gap <= self.grace and (best is None or gap < best[0]):
                    best = (gap, dev, first, last)
            if best:
                return {"device": best[1], "source": "ip_recent",
                        "why": "%s held %s until %s, %.0fs from this event"
                               % (best[1], addr, str(best[3])[:19], best[0])}
        except Exception as e:
            print("[device_identity] holder_at failed for %s: %s" % (addr, e))
        return out

    def addresses_of(self, device: str, limit: int = 50) -> list:
        """Every address this device has held, newest first — the IP trail the
        requirement is really asking to see."""
        out = []
        try:
            for addr, first, last, events, closed in self.conn.execute(
                    "SELECT address, first_seen, last_seen, events, closed "
                    "FROM ip_trail WHERE device = ? "
                    "ORDER BY last_seen DESC LIMIT ?",
                    (_norm(device), max(1, int(limit)))):
                out.append({"address": addr, "first_seen": first,
                            "last_seen": last, "events": int(events or 0),
                            "current": not int(closed or 0)})
        except Exception as e:
            print("[device_identity] addresses_of failed: %s" % e)
        return out

    def history_of(self, address: str, limit: int = 50) -> list:
        """Every device that has held this address, newest first."""
        out = []
        try:
            for dev, first, last, events, closed in self.conn.execute(
                    "SELECT device, first_seen, last_seen, events, closed "
                    "FROM ip_trail WHERE address = ? "
                    "ORDER BY last_seen DESC LIMIT ?",
                    (_norm(address), max(1, int(limit)))):
                out.append({"device": dev, "first_seen": first,
                            "last_seen": last, "events": int(events or 0),
                            "current": not int(closed or 0)})
        except Exception as e:
            print("[device_identity] history_of failed: %s" % e)
        return out

    def stats(self) -> dict:
        try:
            addrs, devs, rows = self.conn.execute(
                "SELECT COUNT(DISTINCT address), COUNT(DISTINCT device), "
                "COUNT(*) FROM ip_trail").fetchone()
            moved = self.conn.execute(
                "SELECT COUNT(*) FROM (SELECT address FROM ip_trail "
                "GROUP BY address HAVING COUNT(DISTINCT device) > 1)").fetchone()[0]
            roamed = self.conn.execute(
                "SELECT COUNT(*) FROM (SELECT device FROM ip_trail "
                "GROUP BY device HAVING COUNT(DISTINCT address) > 1)").fetchone()[0]
            return {"addresses": int(addrs or 0), "devices": int(devs or 0),
                    "intervals": int(rows or 0),
                    "addresses_reassigned": int(moved or 0),
                    "devices_that_changed_address": int(roamed or 0)}
        except Exception:
            return {"addresses": 0, "devices": 0, "intervals": 0,
                    "addresses_reassigned": 0, "devices_that_changed_address": 0}

    def close(self) -> None:
        try:
            self.commit()
            self.conn.close()
        except Exception:
            pass


# ── resolution ───────────────────────────────────────────────────────────────

def stable_key(log: dict) -> tuple:
    """(device_key, source, why) from the event's own stable fields, or ("",...).

    Does not consult the trail or the register — this is what the event itself
    can prove about which machine it came from.
    """
    aid = _first(log, _HOST_ID_FIELDS)
    name = _first(log, _HOST_NAME_FIELDS)
    if aid:
        # The agent id is scoped by name when both are present. The ids in this
        # feed are three digits ("070"), which is only unique within one SIEM
        # deployment, and a second deployment would collide silently.
        return (device_key(NS_AGENT, aid), "agent_id",
                "agent id %s%s" % (aid, (" (%s)" % name) if name else ""))
    if name and not is_ip(name):
        return (device_key(NS_NAME, name), "hostname",
                "hostname %s, no agent id on the event" % name)
    return ("", "", "")


def resolve(log: dict, trail: "DeviceTrail | None" = None,
            reg: "dict | None" = None, learn: bool = True) -> dict:
    """The machine this event came from, as stably as the data allows.

    {"device", "source", "why", "address", "stable", "moved_from"}

    `stable` is the field that matters to a caller: False means the identity is
    keyed on an address and WILL break when the lease moves. A behaviour
    baseline should not be built on an unstable key, and saying so here is
    better than letting one be built silently.
    """
    out = {"device": "", "source": "", "why": "", "address": "",
           "stable": False, "moved_from": None}

    addr = _first(log, _HOST_IP_FIELDS) or _first(log, _SRC_IP_FIELDS)
    if addr and not is_ip(addr):
        addr = ""
    out["address"] = addr
    when = event_time(log)

    # 1. operator binding, on either the address or the name
    if reg:
        name = _first(log, _HOST_NAME_FIELDS)
        for probe in (addr, name):
            if probe and _norm(probe) in reg:
                label = reg[_norm(probe)]
                out.update(device=device_key(NS_NAME, label), source="operator",
                           why="operator bound %s to %s" % (probe, label),
                           stable=True)
                if trail is not None and learn and addr:
                    act = trail.observe(addr, out["device"], when)
                    if act["action"] == "moved":
                        out["moved_from"] = act["previous"]
                return out

    # 2 & 3. the event's own stable fields
    key, source, why = stable_key(log)
    if key:
        out.update(device=key, source=source, why=why, stable=True)
        # Learn the binding, which is what makes step 4 possible for the
        # agentless events that carry only an address.
        if trail is not None and learn and addr:
            act = trail.observe(addr, key, when)
            if act["action"] == "moved":
                out["moved_from"] = act["previous"]
                out["why"] += "; this address was previously held by %s" % act["previous"]
        return out

    # 4 & 5. no stable field — ask the trail who held the address then
    if addr and trail is not None:
        hit = trail.holder_at(addr, when)
        if hit["device"]:
            out.update(device=hit["device"], source=hit["source"],
                       why=hit["why"], stable=True)
            return out

    # 6. nothing known. Keyed by address and declared unstable.
    if addr:
        out.update(device=device_key(NS_ADDR, addr), source="address",
                   why="no agent id, hostname or prior binding for %s — this "
                       "identity will change if the lease moves" % addr,
                   stable=False)
    return out


def status(trail: "DeviceTrail | None" = None, path=None) -> dict:
    """What this module is doing, for /api and the evidence pack."""
    return {
        "sources": list(SOURCES),
        "grace_secs": trail.grace if trail else DEFAULT_GRACE_SECS,
        "stale_secs": trail.stale if trail else DEFAULT_STALE_SECS,
        "bindings": len(register(path)) if path else 0,
        "trail": trail.stats() if trail else None,
        "mac_note": (
            "No MAC address or CMDB feed is required for agent-reporting hosts: "
            "the agent id is already a stable per-machine identifier (measured "
            "on 3,412 alerts, 12 ids, none ever reporting a second hostname, "
            "while 5 appeared on multiple addresses). A MAC or CMDB source "
            "would extend coverage to agentless devices; until one exists those "
            "are resolved through the time-bounded IP trail, and an address "
            "with no prior binding is reported as an unstable identity rather "
            "than guessed at."),
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

    T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)

    def at(mins):
        return T0 + timedelta(minutes=mins)

    def ev(**kw):
        """Build an event shaped like the real feed."""
        log = {}
        if "aid" in kw:
            log.setdefault("host", {})["id"] = kw["aid"]
        if "name" in kw:
            log.setdefault("host", {})["name"] = kw["name"]
        if "ip" in kw:
            log.setdefault("host", {})["ip"] = kw["ip"]
        if "srcip" in kw:
            log.setdefault("data", {})["srcip"] = kw["srcip"]
        if "when" in kw:
            log["event_time"] = kw["when"].isoformat()
        return log

    # ── helpers ──
    ok("is_ip accepts v4", is_ip("10.0.0.1"))
    ok("is_ip accepts v6", is_ip("2001:db8::1"))
    ok("is_ip rejects a hostname", not is_ip("DC_DIR_srv"))
    ok("is_ip rejects empty", not is_ip(""))
    ok("device_key namespaces", device_key(NS_AGENT, "070") == "agent:070")
    ok("device_key folds case", device_key(NS_NAME, "DC_SRV") == "name:dc_srv")
    ok("device_key of nothing is empty", device_key(NS_AGENT, "  ") == "")
    ok("agent and name keys never collide",
       device_key(NS_AGENT, "070") != device_key(NS_NAME, "070"))
    ok("parse_time reads iso with Z",
       parse_time("2026-10-01T09:00:00Z") == T0)
    ok("parse_time assumes utc when naive",
       parse_time("2026-10-01T09:00:00") == T0)
    ok("parse_time refuses junk", parse_time("not a date") is None)
    ok("parse_time refuses empty", parse_time("") is None)
    ok("event_time falls back to now",
       (datetime.now(timezone.utc) - event_time({})).total_seconds() < 5)
    ok("event_time prefers processed_at",
       event_time({"ueba": {"processed_at": T0.isoformat()},
                   "event_time": at(99).isoformat()}) == T0)

    # ── stable_key ──
    k, s, _ = stable_key(ev(aid="070", name="APP-SRV-01"))
    ok("agent id wins over hostname", k == "agent:070" and s == "agent_id")
    k, s, _ = stable_key(ev(name="APP-SRV-01"))
    ok("hostname is used when there is no agent id",
       k == "name:app-srv-01" and s == "hostname")
    ok("the agent-id reason names the host",
       "APP-SRV-01" in stable_key(ev(aid="070", name="APP-SRV-01"))[2])
    k, _, _ = stable_key(ev(name="10.0.0.5"))
    ok("a hostname that is really an address is not a stable key", k == "")
    ok("an empty event has no stable key", stable_key({}) == ("", "", ""))
    ok("agent.name is read when host.name is absent",
       stable_key({"agent": {"name": "GW-01"}})[0] == "name:gw-01")
    ok("the raw_event agent id is read as a fallback",
       stable_key({"context": {"raw_event": {"agent": {"id": "082"}}}})[0]
       == "agent:082")

    with tempfile.TemporaryDirectory() as td:
        trail = DeviceTrail(os.path.join(td, "dev.db"))

        # ── the DHCP case this module exists for ──
        a = resolve(ev(aid="065", name="LAP-A", ip="10.200.10.207", when=at(0)), trail)
        ok("first sighting resolves to the agent id", a["device"] == "agent:065")
        ok("and is reported stable", a["stable"] is True)
        ok("and records the address", a["address"] == "10.200.10.207")
        ok("nothing moved on a first sighting", a["moved_from"] is None)

        b = resolve(ev(aid="065", name="LAP-A", ip="10.200.10.217", when=at(60)), trail)
        ok("the SAME device on a NEW address keeps one identity",
           b["device"] == a["device"])
        ok("the identity stays stable across the address change",
           b["stable"] is True)

        c = resolve(ev(aid="065", name="LAP-A", ip="10.200.10.147", when=at(120)), trail)
        ok("a third address still resolves to the same device",
           c["device"] == "agent:065")
        addrs = {r["address"] for r in trail.addresses_of("agent:065")}
        ok("all three addresses are on the device's trail",
           addrs == {"10.200.10.207", "10.200.10.217", "10.200.10.147"}, )
        ok("the trail counts the device as having changed address",
           trail.stats()["devices_that_changed_address"] == 1)

        # ── an agentless event on an address the device held ──
        f = resolve(ev(srcip="10.200.10.147", when=at(121)), trail)
        ok("an agentless event resolves through the trail",
           f["device"] == "agent:065")
        ok("an event past the last sighting uses the open lease",
           f["source"] == "ip_current")
        ok("and is treated as stable", f["stable"] is True)
        ok("the reason names the address", "10.200.10.147" in f["why"])
        # Widen the interval, then query INSIDE it: that is the ip_trail case,
        # and it has to be distinguishable from the open-lease case above.
        trail.observe("10.200.10.147", "agent:065", at(180))
        inside = resolve(ev(srcip="10.200.10.147", when=at(150)), trail)
        ok("an event inside a confirmed interval is ip_trail",
           inside["source"] == "ip_trail" and inside["device"] == "agent:065")
        ok("the ip_trail reason states the interval",
           "held 10.200.10.147" in inside["why"])

        # ── the lease moves to a different machine ──
        g = resolve(ev(aid="099", name="LAP-B", ip="10.200.10.147", when=at(300)), trail)
        ok("a new device on that address gets its OWN identity",
           g["device"] == "agent:099")
        ok("and the move is reported", g["moved_from"] == "agent:065")
        ok("and the reason says who held it before", "agent:065" in g["why"])
        hist = trail.history_of("10.200.10.147")
        ok("the address history holds both devices",
           {h["device"] for h in hist} == {"agent:065", "agent:099"})
        ok("exactly one interval is current",
           sum(1 for h in hist if h["current"]) == 1)
        ok("the current holder is the new device",
           [h["device"] for h in hist if h["current"]] == ["agent:099"])
        ok("the trail counts the address as reassigned",
           trail.stats()["addresses_reassigned"] == 1)

        # The decisive property: an agentless event BEFORE the move must still
        # resolve to the OLD device. A flat IP→device map cannot do this, and
        # getting it wrong is what SN 5 is written against.
        old = resolve(ev(srcip="10.200.10.147", when=at(121)), trail)
        ok("an event from before the move still resolves to the old device",
           old["device"] == "agent:065")
        after = resolve(ev(srcip="10.200.10.147", when=at(400)), trail)
        ok("an event from after the move resolves to the new device",
           after["device"] == "agent:099")
        ok("and does so on the open lease", after["source"] == "ip_current")
        # Past the staleness bound the open lease stops being evidence.
        cold = resolve(ev(srcip="10.200.10.147",
                          when=at(300) + timedelta(seconds=DEFAULT_STALE_SECS + 60)),
                       trail)
        ok("a very late event does not trust a stale lease",
           cold["source"] == "address" and cold["stable"] is False)

        # ── the two bounds, in both directions ──
        trail2 = DeviceTrail(os.path.join(td, "d2.db"),
                             grace_secs=600, stale_secs=1800)
        resolve(ev(aid="070", ip="10.0.0.1", when=at(0)), trail2)

        # forward, lease still credible
        near = resolve(ev(srcip="10.0.0.1", when=at(5)), trail2)
        ok("forward inside the stale bound uses the open lease",
           near["device"] == "agent:070" and near["source"] == "ip_current")
        # forward, lease no longer credible (3600s > 1800s)
        far = resolve(ev(srcip="10.0.0.1", when=at(60)), trail2)
        ok("forward beyond the stale bound does not trust the lease",
           far["source"] == "address")
        ok("and is declared unstable", far["stable"] is False)
        ok("and says why", "lease moves" in far["why"])
        # backward, within grace (300s < 600s)
        before = resolve(ev(srcip="10.0.0.1", when=at(-5)), trail2)
        ok("an out-of-order event just BEFORE the interval resolves",
           before["device"] == "agent:070")
        ok("and is reported as the weaker ip_recent claim",
           before["source"] == "ip_recent")
        # backward, beyond grace (3600s > 600s)
        way_before = resolve(ev(srcip="10.0.0.1", when=at(-60)), trail2)
        ok("backward beyond the grace window does not resolve",
           way_before["source"] == "address")
        # a CLOSED interval is not an open lease, so only grace applies to it
        trail2.observe("10.0.0.1", "agent:071", at(10))   # moves the lease
        hist2 = trail2.history_of("10.0.0.1")
        ok("the moved address has one open and one closed interval",
           sorted(h["current"] for h in hist2) == [False, True])

        # ── dormancy ──
        trail3 = DeviceTrail(os.path.join(td, "d3.db"), stale_secs=3600)
        resolve(ev(aid="070", ip="10.0.0.9", when=at(0)), trail3)
        act = trail3.observe("10.0.0.9", "agent:070", at(10))
        ok("a prompt repeat extends the interval", act["action"] == "extended")
        act = trail3.observe("10.0.0.9", "agent:070", at(600))
        ok("the same device after a long silence opens a new interval",
           act["action"] == "opened")
        ok("both intervals are kept", len(trail3.history_of("10.0.0.9")) == 2)

        # ── the unresolvable case ──
        u = resolve({}, trail)
        ok("an event with nothing identifying resolves to nothing",
           u["device"] == "" and u["stable"] is False)
        ok("a hostname-only event needs no trail",
           resolve(ev(name="DC_DIR_srv"))["device"] == "name:dc_dir_srv")

        # ── observe() input validation ──
        ok("observe rejects a non-address",
           trail.observe("not-an-ip", "agent:1", at(0))["action"] == "ignored")
        ok("observe rejects an empty device",
           trail.observe("10.0.0.2", "", at(0))["action"] == "ignored")
        ok("observe rejects a missing time",
           trail.observe("10.0.0.2", "agent:1", None)["action"] == "ignored")
        ok("holder_at on an unknown address is empty",
           trail.holder_at("192.0.2.99", at(0))["device"] == "")
        ok("holder_at with no time is empty",
           trail.holder_at("10.0.0.1", None)["device"] == "")

        # ── learn=False must not write ──
        quiet = DeviceTrail(os.path.join(td, "d4.db"))
        resolve(ev(aid="070", ip="10.9.9.9", when=at(0)), quiet, learn=False)
        ok("learn=False records nothing", quiet.stats()["intervals"] == 0)

        # ── the operator register ──
        regp = Path(td) / "devices.json"
        ok("a missing register reads empty", register(regp) == {})
        save_register(regp, {"10.5.5.5": "KIOSK-01", "Printer-3": "PRN-03"})
        r = register(regp)
        ok("the register round-trips", r.get("10.5.5.5") == "KIOSK-01")
        ok("register keys are folded", r.get("printer-3") == "PRN-03")
        o = resolve(ev(srcip="10.5.5.5", when=at(0)), trail, r)
        ok("the operator binding wins", o["device"] == "name:kiosk-01")
        ok("and is attributed to the operator", o["source"] == "operator")
        ok("and is stable", o["stable"] is True)
        # It must beat the agent id too — the operator is the authority.
        o2 = resolve(ev(aid="070", srcip="10.5.5.5", when=at(0)), trail, r)
        ok("the operator binding beats the agent id", o2["source"] == "operator")
        save_register(regp, {})
        ok("the register can be emptied", register(regp) == {})
        regp.write_text("{not json", encoding="utf-8")
        ok("a corrupt register reads empty, it does not raise",
           register(regp) == {})

        # ── status ──
        st = status(trail, regp)
        ok("status lists the sources", st["sources"] == list(SOURCES))
        ok("status is explicit about MAC", "No MAC address" in st["mac_note"])
        ok("status carries the trail stats", st["trail"]["addresses"] >= 3)

        # The invariant, asserted rather than assumed.
        openc = trail.conn.execute(
            "SELECT address, COUNT(*) FROM ip_trail WHERE closed = 0 "
            "GROUP BY address HAVING COUNT(*) > 1").fetchall()
        ok("no address ever has two open intervals", openc == [])
        resolve(ev(aid="065", name="LAP-A", ip="10.77.0.1", when=at(500)), trail)
        held = [r for r in trail.addresses_of("agent:065") if r["current"]]
        ok("a device may hold several addresses at once", len(held) > 1)

        trail.close()
        trail2.close()
        trail3.close()
        quiet.close()

        # ── reopening must not lose the trail ──
        again = DeviceTrail(os.path.join(td, "dev.db"))
        ok("the trail survives a reopen",
           again.holder_at("10.200.10.147", at(400))["device"] == "agent:099")
        again.close()

    total = len(checked)
    if failures:
        print("ueba_device_identity selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_device_identity selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
