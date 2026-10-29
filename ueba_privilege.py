#!/usr/bin/env python3
"""
ueba_privilege.py
─────────────────
CyberSentinel UEBA — privilege as an entity attribute (RFP SN 15).

SN 15 asks for high-privilege access anomaly detection covering misuse, sharing
and takeover. Nothing in the platform knew which accounts were privileged, so
an administrator's anomaly scored exactly like a contractor's, and the three
behaviours the serial names could not be distinguished from each other.

Where the privilege level comes from
────────────────────────────────────
Group membership would be the right source and it is not available: the SIEM
forwards no account-management events, so there is no 4728/4732/4756 to read a
"Domain Admins" membership from (the same gap that blocks SN 43). Three sources
are available, and they are consulted in this order:

  1. An operator-maintained list, which is authoritative. A SOC that knows its
     own privileged accounts can simply say so, and nothing inferred overrides
     it. Same file-and-mtime contract as ueba_watchlist.
  2. Observed privileged activity. An account that repeatedly performs
     privileged operations is treated as elevated even if nobody listed it.
  3. Name shape, as the weakest signal and last resort.

Service accounts are classified, not just levelled
──────────────────────────────────────────────────
This is the part that decides whether the feature is usable. Measured on the
live stream, `NT AUTHORITY\\SYSTEM` alone produced 101 privileged operations
across 3 hosts in 150 seconds. It is genuinely high-privilege and it is
genuinely on every host, so a naive "privileged account seen on many hosts"
rule reports it forever and the alert becomes furniture.

So every entity carries a CLASS as well as a level. A service or machine
account is high-privilege for misuse scoring and exempt from credential
sharing, because being on many hosts is its job. Sharing is a statement about
a person, and only human accounts can make it.

The three detections
────────────────────
  takeover  a privileged account appears on a host or in a country it has
            never been seen in. Reuses the all-traffic presence record built
            for SN 19 — novelty is only meaningful measured against ALL of an
            entity's traffic, not against its past alerts.
  sharing   one human privileged account seen on several hosts inside the
            window. Service accounts exempt, as above.
  misuse    a privileged operation by a privileged account outside business
            hours, or at a rate well above that account's own norm.

Privilege also contributes an additive scoring prior, the same mechanism as a
watch-list hit or confirmed history: an administrator's unusual behaviour
should become visible sooner than a standard user's. That is what "privilege
level scored as an entity attribute" means in practice.
"""

# Annotations as strings, so this imports on the 3.9 the dev boxes still run
# as well as the 3.12 on the server.
from __future__ import annotations

import json
import re
import threading
from pathlib import Path

LEVELS = ("standard", "elevated", "high")
_LEVEL_RANK = {"standard": 0, "elevated": 1, "high": 2}
CLASSES = ("human", "service")

# Windows events that ARE a privileged operation, measured present on the live
# stream. 4672 is the canonical "special privileges assigned to this logon".
PRIV_EVENT_IDS = {"4672", "4673", "4674", "4985"}

# SIEM rule groups that mean the same thing. Both of these carry real volume
# (privilege_escalation 206 and elevated_process 103 per 150s when sampled),
# so they, not the raw event IDs, are the main signal in this deployment.
PRIV_RULE_GROUPS = ("privilege_escalation", "privilege_enum", "elevated_process")

# Machine, system and service accounts. High-privilege, but their presence on
# many hosts is normal operation and must never read as credential sharing.
_SERVICE_PATTERNS = (
    r"^nt\s+authority\\",          # NT AUTHORITY\SYSTEM, \LOCAL SERVICE, ...
    r"^nt\s+service\\",
    r"^iis\s+apppool\\",
    r"^window\s+manager\\",
    r"^font\s?driver\s?host\\",
    r"\$$",                        # COMPUTERNAME$ — machine accounts
    r"^(local|network)\s+service$",
    r"^system$",
    r"^svc[-_.]",
    r"[-_.]svc$",
    r"^(systemd|daemon|nobody|_apt|messagebus|syslog)$",
)

# Name shapes that suggest administrative privilege. Weakest signal, used only
# when the operator list and observed activity both say nothing.
_ADMIN_PATTERNS = (
    r"^administrator$",
    r"\\administrator$",
    r"^admin$",
    r"^root$",
    r"^sa$",
    r"^.*[-_.]admin$",
    r"^admin[-_.].*$",
    r"^da[-_.].*$",                # da-xxx, a common domain-admin convention
)

# Entities that are not accounts at all. The profile store also tracks IP and
# host pseudo-entities ("ip:192.168.2.140", "host:CPU-SRV-208") and bare address
# literals, because behaviour is worth baselining for them too. But SN 15 is
# about ACCOUNTS: "this privileged account is a shared credential" is a category
# error said about an IP address, and "privileged operation by this host" says
# nothing an analyst can act on. They are excluded from the serial entirely
# rather than classified within it.
_PSEUDO_PATTERNS = (
    r"^ip:",
    r"^host:",
    r"^mac:",
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",   # a bare IPv4 literal
    r"^[0-9a-f]{0,4}:[0-9a-f:]{2,}$",                # a bare IPv6 literal
)

_lock = threading.Lock()
_cache: dict = {}


# ── helpers ──────────────────────────────────────────────────────────────────

def _norm(v) -> str:
    """Lower-case, trimmed, and with escaped backslashes collapsed.

    The de-escaping is not cosmetic. Entity names reach the profile store with
    inconsistent escaping — measured on the live deployment, 91 of the 181
    domain-qualified entities carry a DOUBLED backslash ("NT AUTHORITY\\\\SYSTEM")
    and the rest a single one. Without collapsing them, an operator who
    declares "DOMAIN\\user" privileged silently fails to match the stored
    "DOMAIN\\\\user", and the declaration does nothing with no error anywhere.
    This matches what canonical_identity does in the preprocessor.
    """
    s = str(v or "").strip().lower()
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return s


def _matches_any(name: str, patterns) -> bool:
    for p in patterns:
        if re.search(p, name):
            return True
    return False


def _clean_entry(e) -> dict | None:
    """Validate one operator-list entry, or None if unusable."""
    if not isinstance(e, dict):
        return None
    value = _norm(e.get("value") or e.get("entity") or e.get("user"))
    if not value:
        return None
    level = _norm(e.get("level")) or "high"
    if level not in LEVELS:
        level = "high"
    klass = _norm(e.get("class") or e.get("kind"))
    if klass not in CLASSES:
        # An operator listing an account without saying which it is almost
        # always means a person; service accounts get listed deliberately.
        klass = "human"
    return {"value": value, "level": level, "class": klass,
            "note": str(e.get("note") or "")[:300]}


def _read(path) -> dict:
    """{normalised value: entry} for `path`, re-parsed only when it changes."""
    p = Path(str(path))
    try:
        st = p.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None

    key = str(p)
    hit = _cache.get(key)
    if hit and hit["stamp"] == stamp:
        return hit["index"]

    index = {}
    if stamp is not None:
        try:
            raw = json.loads(p.read_text(encoding="utf-8") or "[]")
            if isinstance(raw, dict):
                raw = list(raw.values())
            for e in raw or []:
                c = _clean_entry(e)
                if c:
                    index[c["value"]] = c
        except Exception as ex:
            print("[privilege] failed to read %s: %s" % (p, ex))
            index = {}

    _cache[key] = {"stamp": stamp, "index": index}
    return index


def normalise(value) -> str:
    """The stored form of an entity name.

    Public because callers have to match on it. `entries()` returns normalised
    values, so comparing a raw name against them fails whenever the escaping
    differs — which it does for half the domain-qualified names on this estate.
    A console delete that got this wrong would 404 on a declaration that plainly
    exists, and a re-declaration would duplicate instead of replace.
    """
    return _norm(value)


def entries(path) -> list:
    """The operator list, for the console."""
    with _lock:
        return list(_read(path).values())


def save(path, items: list) -> None:
    """Atomically replace the operator list."""
    p = Path(str(path))
    clean = [c for c in (_clean_entry(e) for e in (items or [])) if c]
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(clean, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)
    with _lock:
        _cache.pop(str(p), None)


# ── event inspection ─────────────────────────────────────────────────────────

def is_privileged_event(log: dict, get_nested) -> bool:
    """True if this event IS a privileged operation.

    `get_nested` is injected rather than imported so this module stays free of
    a dependency on the preprocessor, which imports heavy numeric libraries.
    """
    eid = str(get_nested(log, "context.raw_event.data.win.system.eventID", "") or "")
    if eid in PRIV_EVENT_IDS:
        return True
    groups = get_nested(log, "context.raw_event.rule.groups", None) or []
    if isinstance(groups, (list, tuple)):
        for g in groups:
            if _norm(g) in PRIV_RULE_GROUPS:
                return True
    return False


# ── classification ───────────────────────────────────────────────────────────

def classify(entity: str, path: str = "", priv_events: int = 0,
             cfg: dict | None = None) -> dict:
    """This entity's privilege level and class.

    Returns {"level", "class", "source"} — `source` names which of the three
    signals decided it, so an analyst questioning a verdict can see why rather
    than having to trust it.
    """
    cfg = cfg or {}
    name = _norm(entity)
    out = {"level": "standard", "class": "human", "source": "default"}
    if not name or name == "unknown":
        return out

    # 1. the operator list wins outright, including over the pseudo-entity
    #    check below — a SOC may legitimately want a named jump host treated as
    #    a privileged entity.
    if path:
        with _lock:
            listed = _read(path).get(name)
        if listed:
            return {"level": listed["level"], "class": listed["class"],
                    "source": "operator list"}

    # Not an account: out of scope for this serial. Left at standard so the
    # applies_from floor keeps it out, and classed non-human so the sharing
    # check could not reach it even if an operator lowered that floor.
    if _matches_any(name, _PSEUDO_PATTERNS):
        return {"level": "standard", "class": "service",
                "source": "not an account"}

    # Class before level: it is independent of level, and a service account
    # stays a service account however it was levelled.
    if _matches_any(name, _SERVICE_PATTERNS):
        out["class"] = "service"

    # 2. observed privileged activity
    min_obs = int(cfg.get("min_privileged_events") or 5)
    if priv_events >= min_obs:
        out["level"] = "elevated"
        out["source"] = "observed (%d privileged operations)" % priv_events

    # 3. name shape, weakest
    if _matches_any(name, _ADMIN_PATTERNS):
        out["level"] = "high"
        out["source"] = "administrative account name"
    elif out["class"] == "service" and out["level"] == "standard":
        # A service account with no observed privileged activity is still more
        # than a standard user; it is just not evidenced as high.
        out["level"] = "elevated"
        out["source"] = "service account name"

    return out


def is_privileged(verdict: dict, cfg: dict | None = None) -> bool:
    """True if this verdict clears the level at which SN 15 applies."""
    floor = _norm((cfg or {}).get("applies_from")) or "elevated"
    if floor not in LEVELS:
        floor = "elevated"
    return _LEVEL_RANK.get(verdict.get("level"), 0) >= _LEVEL_RANK[floor]


# ── the three detections ─────────────────────────────────────────────────────

def assess(verdict: dict, presence: dict | None, host_count: int,
           privileged_event: bool, business_hours, cfg: dict | None = None) -> dict:
    """Misuse, sharing and takeover for one event.

    `presence`    this event's novelty verdict from record_presence (SN 19)
    `host_count`  how many distinct hosts this entity has been used on

    A count, not the host list: this runs before score fusion on every event,
    because the prior it returns has to be able to change whether the event
    alerts at all. The profile store keeps that count in memory, so asking is
    free, whereas reading the host list would add a query to the hot loop. The
    names are not lost — the alert's evidence block carries them under
    seen_locations, which is where an analyst reads them anyway.

    Returns {"reasons": [...], "boost": float, "findings": [...]}.
    """
    cfg = cfg or {}
    out: dict = {"reasons": [], "boost": 0.0, "findings": []}
    if not is_privileged(verdict, cfg):
        return out

    level = verdict.get("level")
    klass = verdict.get("class")
    label = "high-privilege" if level == "high" else "elevated-privilege"

    # ── takeover ──
    # A privileged account turning up somewhere it has never been is the
    # strongest of the three, which is why it is stated first.
    pres = presence or {}
    for kind, word in (("agent", "host"), ("country", "country")):
        bit = pres.get(kind) or {}
        if bit.get("first_time"):
            out["findings"].append("takeover")
            out["reasons"].append(
                "Possible account takeover: this %s account has never been seen "
                "on this %s before (%s)" % (label, word, bit.get("value")))
            break

    # ── sharing ──
    # Only ever asked of a human account. See the module docstring: a service
    # account on many hosts is normal operation, and reporting it would make
    # this reason worthless within a day.
    if klass == "human":
        min_hosts = int(cfg.get("sharing_min_hosts") or 4)
        if int(host_count or 0) >= min_hosts:
            out["findings"].append("sharing")
            out["reasons"].append(
                "Possible shared credential: this %s account has been used on %d "
                "different hosts" % (label, int(host_count)))

    # ── misuse ──
    # Three conditions, and each one removes a different false positive.
    #
    # The event must BE a privileged operation, or this fires on an
    # administrator reading their email at 21:00.
    #
    # It must be out of hours, which is what makes it worth saying at all.
    #
    # And the account must be human, for the same reason sharing is human-only:
    # a service account runs at 03:00 because that is when its job runs. Without
    # this condition the single account NT AUTHORITY\\SYSTEM produces a finding
    # on every one of its privileged operations — 43 of them per 75 seconds when
    # measured on this estate — and the reason is worthless by the first morning.
    if privileged_event and business_hours is False and klass == "human":
        out["findings"].append("misuse")
        out["reasons"].append(
            "Privileged operation by a %s account outside business hours" % label)

    # The prior. Applied whether or not one of the three fired: a privileged
    # account's unusual behaviour should surface sooner than a standard user's,
    # which is the attribute half of the serial.
    max_boost = float(cfg.get("max_boost") or 0.15)
    max_boost = min(max_boost, 0.40)
    share = {"high": 1.0, "elevated": 0.6}.get(level, 0.0)
    bump = 1.0 if out["findings"] else 0.5
    out["boost"] = round(max_boost * share * bump, 4)
    return out


# ── selftest ──────────────────────────────────────────────────────────────────

def selftest() -> int:
    import os
    import tempfile
    failures = []

    def ok(label, cond):
        if not cond:
            failures.append(label)

    def gn(d, path, default=None):
        """Minimal stand-in for the preprocessor's get_nested."""
        cur = d
        for part in path.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur if cur not in (None, "") else default

    # ── class detection ──
    for n in ("NT AUTHORITY\\SYSTEM", "nt authority\\local service",
              "WIN-SRV-01$", "svc-backup", "backup_svc", "SYSTEM",
              "IIS APPPOOL\\DefaultAppPool", "systemd"):
        ok("service: %s" % n, classify(n)["class"] == "service")
    for n in ("aditya.umathe", "VGSOC\\rohan", "jinu", "Administrator"):
        ok("human: %s" % n, classify(n)["class"] == "human")

    # ── level from name shape ──
    for n in ("Administrator", "VGSOCSRV\\Administrator", "admin", "root", "sa",
              "db-admin", "admin.tools", "da-aditya"):
        ok("high by name: %s" % n, classify(n)["level"] == "high")
    ok("ordinary user is standard", classify("aditya.umathe")["level"] == "standard")
    ok("ordinary user source", classify("aditya.umathe")["source"] == "default")
    ok("service with no activity is elevated",
       classify("svc-backup")["level"] == "elevated")
    ok("empty entity is standard", classify("")["level"] == "standard")
    ok("unknown entity is standard", classify("unknown")["level"] == "standard")

    # ── level from observed activity ──
    ok("observed activity elevates", classify("jinu", priv_events=9)["level"] == "elevated")
    ok("observed source is named", "9 privileged" in classify("jinu", priv_events=9)["source"])
    ok("below the floor stays standard", classify("jinu", priv_events=2)["level"] == "standard")
    ok("observed threshold configurable",
       classify("jinu", priv_events=3, cfg={"min_privileged_events": 3})["level"] == "elevated")
    ok("name beats observation",
       classify("Administrator", priv_events=1)["level"] == "high")

    # ── the operator list is authoritative ──
    d = tempfile.mkdtemp()
    lst = os.path.join(d, "privileged.json")
    save(lst, [
        {"value": "jinu", "level": "high", "note": "domain admin"},
        {"value": "NT AUTHORITY\\SYSTEM", "level": "high", "class": "service"},
        {"value": "Administrator", "level": "standard", "note": "decommissioned"},
        {"value": "", "level": "high"},                       # unusable, dropped
        "not-a-dict",                                          # unusable, dropped
    ])
    ok("list persisted 3 usable entries", len(entries(lst)) == 3)
    ok("listed entity is high", classify("jinu", lst)["level"] == "high")
    ok("listed source is named", classify("jinu", lst)["source"] == "operator list")
    ok("list overrides name shape", classify("Administrator", lst)["level"] == "standard")
    ok("list overrides observation",
       classify("Administrator", lst, priv_events=99)["level"] == "standard")
    ok("list sets class", classify("NT AUTHORITY\\SYSTEM", lst)["class"] == "service")
    ok("unlisted falls through to inference", classify("root", lst)["level"] == "high")
    bare = os.path.join(d, "bare.json")
    save(bare, [{"value": "x"}])
    ok("list default level is high", classify("x", bare)["level"] == "high")
    ok("list default class is human", classify("x", bare)["class"] == "human")
    ok("missing list file is tolerated",
       classify("jinu", os.path.join(d, "nope.json"))["level"] == "standard")
    lst3 = os.path.join(d, "jump.json")
    save(lst3, [{"value": "host:jump-01", "level": "high"}])

    # ── escaping: half the real estate carries doubled backslashes ──
    ok("normalise is the public name for it",
       normalise("NT AUTHORITY\\\\SYSTEM") == _norm("NT AUTHORITY\\\\SYSTEM"))
    ok("doubled backslash collapses", _norm("NT AUTHORITY\\\\SYSTEM") == "nt authority\\system")
    ok("single backslash preserved", _norm("NT AUTHORITY\\SYSTEM") == "nt authority\\system")
    ok("triple collapses too", _norm("A\\\\\\user") == "a\\user")
    ok("doubled form classes as service",
       classify("NT AUTHORITY\\\\SYSTEM")["class"] == "service")
    ok("doubled domain admin is high",
       classify("VGSOCSRV\\\\Administrator")["level"] == "high")
    lst4 = os.path.join(d, "esc.json")
    save(lst4, [{"value": "NT AUTHORITY\\SYSTEM", "level": "high", "class": "human"}])
    ok("a single-backslash declaration matches the doubled stored name",
       classify("NT AUTHORITY\\\\SYSTEM", lst4)["source"] == "operator list")
    ok("and overrides the inferred class",
       classify("NT AUTHORITY\\\\SYSTEM", lst4)["class"] == "human")
    save(lst4, [{"value": "NT AUTHORITY\\\\SYSTEM", "level": "high"}])
    ok("a doubled declaration matches the single stored name",
       classify("NT AUTHORITY\\SYSTEM", lst4)["source"] == "operator list")

    # ── pseudo-entities are not accounts and are out of scope ──
    for n in ("ip:192.168.2.140", "host:CPU-SRV-208", "10.200.10.186",
              "103.127.29.167", "mac:00:11:22:33:44:55"):
        v = classify(n)
        ok("pseudo is standard: %s" % n, v["level"] == "standard")
        ok("pseudo is non-human: %s" % n, v["class"] == "service")
        ok("pseudo source named: %s" % n, v["source"] == "not an account")
    ok("a pseudo-entity on many hosts reports no sharing",
       "sharing" not in assess(
           {"level": "high", "class": classify("ip:10.0.0.5")["class"]},
           None, 20, False, True)["findings"])
    ok("an operator listing still beats the pseudo check",
       classify("host:jump-01", lst3)["level"] == "high")
    ok("a real username is unaffected", classify("rohan")["class"] == "human")
    ok("an employee-id username stays human", classify("0869015")["class"] == "human")

    # ── is_privileged floor ──
    hi = {"level": "high", "class": "human"}
    el = {"level": "elevated", "class": "human"}
    st = {"level": "standard", "class": "human"}
    ok("high clears default floor", is_privileged(hi))
    ok("elevated clears default floor", is_privileged(el))
    ok("standard does not", not is_privileged(st))
    ok("floor can be raised", not is_privileged(el, {"applies_from": "high"}))
    ok("bad floor falls back", is_privileged(el, {"applies_from": "nonsense"}))

    # ── privileged event detection ──
    ok("4672 is privileged", is_privileged_event(
        {"context": {"raw_event": {"data": {"win": {"system": {"eventID": "4672"}}}}}}, gn))
    ok("4673 is privileged", is_privileged_event(
        {"context": {"raw_event": {"data": {"win": {"system": {"eventID": 4673}}}}}}, gn))
    ok("privilege_escalation group is privileged", is_privileged_event(
        {"context": {"raw_event": {"rule": {"groups": ["windows", "privilege_escalation"]}}}}, gn))
    ok("elevated_process group is privileged", is_privileged_event(
        {"context": {"raw_event": {"rule": {"groups": ["elevated_process"]}}}}, gn))
    ok("ordinary logon is not privileged", not is_privileged_event(
        {"context": {"raw_event": {"data": {"win": {"system": {"eventID": "4624"}}}}}}, gn))
    ok("empty event is not privileged", not is_privileged_event({}, gn))
    ok("non-list groups tolerated", not is_privileged_event(
        {"context": {"raw_event": {"rule": {"groups": "privilege_escalation"}}}}, gn))

    # ── assess: standard users are out of scope entirely ──
    a = assess(st, {"agent": {"first_time": True, "value": "H9"}}, 9, True, False)
    ok("standard user yields nothing", a["reasons"] == [] and a["boost"] == 0.0)

    # ── takeover ──
    a = assess(hi, {"agent": {"first_time": True, "value": "FIN-SRV"}}, 0, False, True)
    ok("takeover detected", "takeover" in a["findings"])
    ok("takeover names the host", "FIN-SRV" in a["reasons"][0])
    ok("takeover says high-privilege", "high-privilege" in a["reasons"][0])
    a = assess(el, {"country": {"first_time": True, "value": "Russia"}}, 0, False, True)
    ok("takeover on country too", "takeover" in a["findings"])
    ok("elevated wording differs", "elevated-privilege" in a["reasons"][0])
    a = assess(hi, {"agent": {"first_time": False, "value": "H1"}}, 0, False, True)
    ok("no novelty, no takeover", "takeover" not in a["findings"])

    # ── sharing, and the service-account exemption that makes it usable ──
    a = assess(hi, None, 6, False, True)
    ok("sharing detected for a human", "sharing" in a["findings"])
    ok("sharing names the count", "6 different hosts" in a["reasons"][0])
    svc = {"level": "high", "class": "service"}
    a = assess(svc, None, 6, False, True)
    ok("service account is exempt from sharing", "sharing" not in a["findings"])
    a = assess(hi, None, 2, False, True)
    ok("two hosts is not sharing", "sharing" not in a["findings"])
    a = assess(hi, None, 2, False, True, {"sharing_min_hosts": 2})
    ok("sharing threshold configurable", "sharing" in a["findings"])

    # ── misuse ──
    a = assess(hi, None, 0, True, False)
    ok("out-of-hours privileged op is misuse", "misuse" in a["findings"])
    a = assess(svc, None, 0, True, False)
    ok("service account is exempt from misuse", "misuse" not in a["findings"])
    ok("a service account still gets a prior", a["boost"] > 0)
    a = assess(hi, None, 0, True, True)
    ok("in-hours privileged op is not misuse", "misuse" not in a["findings"])
    a = assess(hi, None, 0, False, False)
    ok("out of hours alone is not misuse", "misuse" not in a["findings"])
    a = assess(hi, None, 0, True, None)
    ok("unknown business hours is not misuse", "misuse" not in a["findings"])

    # ── the prior ──
    ok("high gets a prior with no finding", assess(hi, None, 0, False, True)["boost"] > 0)
    ok("elevated prior is smaller than high",
       assess(el, None, 0, False, True)["boost"] <
       assess(hi, None, 0, False, True)["boost"])
    ok("a finding raises the prior",
       assess(hi, {"agent": {"first_time": True, "value": "X"}}, 0, False, True)["boost"] >
       assess(hi, None, 0, False, True)["boost"])
    ok("prior respects max_boost",
       assess(hi, None, 0, False, True, {"max_boost": 0.05})["boost"] <= 0.05)
    ok("prior is hard-capped",
       assess(hi, {"agent": {"first_time": True, "value": "X"}}, 0, True, False,
              {"max_boost": 99})["boost"] <= 0.40)
    ok("standard user gets no prior", assess(st, None, 0, True, False)["boost"] == 0.0)

    # all three at once
    a = assess(hi, {"agent": {"first_time": True, "value": "NEW"}}, 6, True, False)
    ok("all three can fire together", len(a["findings"]) == 3)
    ok("three reasons produced", len(a["reasons"]) == 3)

    total = 104
    if failures:
        print("ueba_privilege selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_privilege selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
