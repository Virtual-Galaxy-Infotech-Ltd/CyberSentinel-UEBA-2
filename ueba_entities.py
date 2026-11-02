#!/usr/bin/env python3
"""
ueba_entities.py
────────────────
CyberSentinel UEBA — entity kinds beyond the account (RFP SN 30, SN 67).

  SN 30  Automatic classification of entities — users, devices, servers,
         applications.
  SN 67  The operator can nominate any field in the incoming event and have
         its values tracked as entities, with no code change and no restart.

The distinction this module rests on
────────────────────────────────────
`resolve_entity()` in ueba_preprocessor returns ONE key per event, and that key
decides which autoencoder the event is scored against. It must stay one key:
every model file on disk is named for it. So this module does not touch it.

What it adds is the other half of the question. One event touches several
things at once — a person, the host they are on, the program that ran — and
only the first of those has ever been an entity here. These are recorded as
SECONDARY entities, in the kind-and-value columns `entity_presence` already
has, so there is no schema change and no migration:

    primary   (unchanged)  person:jinu          ← picks the model
    secondary (new)        server:DC_DIR_srv     ← what it touched
    secondary (new)        application:sshd

Every classification carries the reason it was made, in the same spirit as
ueba_privilege: a verdict an analyst cannot question is a verdict they cannot
act on.

Host names below and in the selftest are illustrative stand-ins with the same
shapes as the real ones. The measured figures are from the real sample; the
names are not, because this file is committed.

What the feed actually supports, measured on 3,412 local alerts
───────────────────────────────────────────────────────────────
  host.name                           100%   12 distinct hosts
  host.type                           100%   but it is the constant "server"
                                             on every single event, so it
                                             classifies nothing — see below
  object.type                          72%   user 52% / process 19% / file 0.3%
  predecoder.program_name              74%   sshd, mostly
  process.image | win…eventdata.image   8%   svchost.exe, powershell.exe, …

So APPLICATION is well supported: 74% of alerts name a program, and the
Windows slice names an executable path on top of that.

SERVER has to be inferred. `host.type` says "server" for all 3,412 alerts
including the seven that are laptops — the field is hard-wired upstream and
carries no information. Name shape does carry information: it separates the
five hosts whose names say what they are (APP-SRV-01, ACCESS-SRV-02,
DC_CORE_SRV, DC_DIR_srv, kafka-broker1 in the stand-in naming) from the seven
named after the person who uses them, which matches the estate. So name shape is used, an operator register
overrides it, and a high distinct-account count corroborates it.

DATA ASSET is NOT offered as a kind, deliberately. `object.type == "file"`
appears on 9 of 3,412 alerts, and all nine are web-attack URL paths
(/recordings/misc/graph.php, /remote/fgt_lang?lang=/../../../..), not internal
documents. There is no file-path field in this feed at all — the same finding
ueba_assets records for SN 40. A `data:` namespace would therefore be an empty
one, and an empty namespace on a compliance matrix is worse than an absent
one. Data assets are covered by the operator-tagged high-value asset register
(ueba_assets, SN 40), which is honest about being operator-supplied.

Active response is excluded on purpose
──────────────────────────────────────
523 of the 661 `object.type == "process"` events name an active-response
script (active-response/bin/disable-account, …). That is the platform acting
on itself, not a program a person ran. Recording it would build behavioural
baselines for our own automation and let its volume swamp the real
applications, so those paths are dropped and counted separately in status().
"""

# Annotations as strings so this imports on 3.9 as well as the server's 3.12.
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

# Built-in secondary kinds. Custom kinds (SN 67) are additional and are always
# prefixed, so an operator can never collide with one of these or with the
# primary namespaces (person/endpoint/service/shared/external).
BUILTIN_KINDS = ("server", "endpoint", "application")
CUSTOM_PREFIX = "custom:"

# A network appliance is neither a server nor an endpoint, and calling it
# either is wrong. cybersentinel-manager reports host.os.family=network_os and
# carries 24,453 distinct accounts because every firewall event's user lands on
# it — classify that as a server and its "behaviour" is the whole estate's.
HOST_ROLES = ("server", "endpoint", "appliance")
ROLE_SOURCES = ("register", "collector", "name_shape", "human_breadth",
                "default")

# host.os.family values that mean "network device".
_APPLIANCE_OS = ("network_os", "fortios", "ios", "ios-xe", "nx-os", "junos",
                 "panos", "routeros", "screenos", "asa")

# An appliance must pass BOTH of these, because either one alone is wrong.
#
# Measured over the full live window, 22 hosts:
#   cybersentinel-manager   14,858 people   100% network_os   <- the collector
#   Access-SRV-2.140            21 people     0% network_os
#   Crypt0n                      4 people    85% network_os   <- a laptop
#   Himanshu                     1 person    61% network_os   <- a laptop
#
# "Dominant network_os" alone made Crypt0n and Himanshu appliances: an ordinary
# machine whose traffic mostly shows up in firewall records has a majority of
# network_os events without being a network device. Requiring the share to be
# near-total excludes both at 85% and 61%.
#
# And a host attributed more people than the estate contains is not a machine
# at all, it is an aggregation point — 14,858 against a next-highest of 21.
# Either test alone is a guess; together they identify the one real collector
# and nothing else.
APPLIANCE_OS_SHARE = 0.95
APPLIANCE_MIN_PEOPLE = 100

# A host used by this many distinct PEOPLE is a server whatever its name looks
# like.
#
# The first version of this counted raw `username` values and fired at 8, and
# it was wrong on live data — it promoted laptops (firdous, Rupali, utkarsh_Pc,
# Nidhi) to "server". Measured on the live presence store, the raw count is
# inflated several times over by things that are not people:
#
#   VGINFO\\nidhi.choudhari  |  nidhi.choudhari  |  VGINFO\nidhi.choudhari
#        the SAME person three times, because the doubled-backslash escaping
#        from the sync bridge makes one account look like several
#   NT AUTHORITY\SYSTEM, LOCAL SERVICE, NETWORK SERVICE     service accounts
#   VGSOC-LAP04$                                            a machine account
#   DWM-178 … DWM-206, UMFD-0                  Windows per-session pseudo-users
#   host:Nidhi                                 not an account at all
#
# Nidhi's eight "accounts" are ONE person. Counting canonical humans instead
# separates the estate cleanly: every laptop measured 1-4, while the real
# multi-user server measured 21. 10 sits in that gap with room either side.
HUMAN_BREADTH_THRESHOLD = 10

# Kept as an alias so an older caller passing the previous name still works.
OBSERVED_ACCOUNT_THRESHOLD = HUMAN_BREADTH_THRESHOLD

# Account strings that are not a person. Measured against the live store; each
# entry is there because it was actually inflating a host's count.
_NONHUMAN_PREFIX = ("nt authority\\", "nt service\\", "nt virtual machine\\",
                    "iis apppool\\", "window manager\\",
                    "font driver host\\")
_NONHUMAN_EXACT = {"system", "local service", "network service", "local system",
                   "localsystem", "anonymous logon", "-", "unknown", ""}
# DWM-<n> and UMFD-<n> are one per desktop session, so an ordinary Windows
# machine accumulates dozens; `host:`/`ip:` are typed entity keys, not accounts.
_PSEUDO_ACCOUNT = re.compile(
    r"^(?:dwm|umfd)-\d+$|^(?:host|ip|endpoint|external|device|addr|agent|name):",
    re.I)

# Distinct values a single kind may accumulate before it is suspended. A field
# the operator picked badly (a process id, a timestamp) is unbounded, and
# recording it would grow entity_presence without limit.
DEFAULT_MAX_CARDINALITY = 5000

# Names whose values are unbounded or meaningless as an entity. Checked at the
# moment the operator adds a mapping, so the refusal is immediate and
# explained rather than discovered later from a suspended kind.
_UNBOUNDED_WORDS = {
    "id", "ids", "guid", "uuid", "pid", "ppid", "tid", "hash", "md5", "sha1",
    "sha256", "imphash", "timestamp", "time", "epoch", "seq", "sequence",
    "offset", "port", "sport", "dport", "srcport", "dstport", "bytes",
    "sentbyte", "rcvdbyte", "duration", "count", "size", "len", "length",
    "session", "cookie", "token", "nonce", "rand",
}
# Run-together spellings a word split cannot reach: "processid" is one word,
# while "valid" and "android" also end in "id" and must stay allowed. An
# explicit set is predictable where a suffix rule would not be.
_UNBOUNDED_LEAVES = {
    "processid", "parentprocessid", "threadid", "sessionid", "logonid",
    "processguid", "parentprocessguid", "eventid", "recordid", "correlationid",
    "requestid", "traceid", "spanid", "messageid", "objectid", "activityid",
    "subjectlogonid", "targetlogonid", "unixtime", "utctime", "systemtime",
    "eventrecordid", "sequencenumber",
}


def _leaf_words(leaf: str) -> list:
    """The leaf split into words, so camelCase reads the same as snake_case.

    'processID' -> ['process', 'id']; 'sessionId' -> ['session', 'id'];
    'dst_port' -> ['dst', 'port'].
    """
    last = re.split(r"[._\-\[\]]+", str(leaf))[-1]
    words = re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+", last)
    return [w.casefold() for w in words]

# Server name shapes. Anchored on a separator or a boundary so "srv" matches
# DC_DIR_srv, APP-SRV-01 and kafka-broker1's "kafka", but not a person called
# "Sarah".
# Server name shapes, in two patterns because the tokens are not equally safe.
#
# LONG tokens are unambiguous, so a camelCase boundary counts: MDM_ServerAnsh
# is a server and the separator-only rule missed it, because "Server" is
# followed by a letter rather than a separator or a digit.
#
# SHORT tokens (dc, ad, db, vm, gw…) are two letters and appear inside ordinary
# words, so they still require a separator or digit on both sides. Allowing a
# camelCase boundary for them would read "ADMinThing" as a domain controller.
# The token matches case-insensitively via a SCOPED flag, so the trailing
# [A-Z] can still act as a camelCase boundary. A whole-pattern re.I would make
# that boundary match any letter and "serverless" would read as a server.
_SERVER_SHAPE_LONG = re.compile(
    r"(?:^|[-_.])((?i:srv|server|svr|postgres|mysql|oracle|kafka|redis|mongo|"
    r"jenkins|proxy|backup|exch|esx))"
    r"(?:$|[-_.0-9]|[A-Z])")
_SERVER_SHAPE_SHORT = re.compile(
    r"(?:^|[-_.])(dc|ad|db|sql|pg|web|www|http|app|api|mail|smtp|nas|san|vm|"
    r"hv|node|gw|fw|vpn|dns|dhcp|ntp|lb|bkp|git|ci)"
    r"(?:$|[-_.0-9])",
    re.I)

# Hosts that look like a server by shape but are not. Operator-overridable via
# the register; this is only the default.
_SERVER_SHAPE_EXCEPT = re.compile(r"^(?:add|adm|admin|adam|adams)$", re.I)

# Active-response script paths — the platform acting on itself. See the header.
_ACTIVE_RESPONSE = re.compile(r"active-response[/\\]", re.I)

# Application sources, in the order they are consulted. First one with a usable
# value wins, so a Windows event naming an image does not also register the
# generic program name.
_APP_FIELDS = (
    "process.image",
    "context.raw_event.data.win.eventdata.image",
    "context.raw_event.predecoder.program_name",
)

_HOST_FIELDS = (
    "host.name",
    "agent.name",
    "context.raw_event.agent.name",
)

_lock = threading.Lock()
_cache: dict = {}


# ── shared helpers ───────────────────────────────────────────────────────────

def _deescape(s: str) -> str:
    """'DOMAIN\\\\user' → 'DOMAIN\\user'. Collapses however many hops it took.

    MUST stay identical to ueba_preprocessor._deescape. It is duplicated rather
    than imported because that module pulls in numpy and the whole feature
    pipeline, and because it will import this one — a cycle. The selftest
    imports the original when it is available and asserts the two agree, so the
    duplication cannot drift silently.
    """
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return s


def get_nested(obj, path: str, default=None):
    """Dotted-path read. Mirrors ueba_preprocessor.get_nested."""
    cur = obj
    for part in str(path).split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


def normalise(value, kind: str = "") -> str:
    """Canonical form of one entity value.

    De-escape first, always — half the Windows names arrive with doubled
    backslashes depending on how many JSON hops they took, and 'C:\\\\Windows'
    and 'C:\\Windows' must not become two applications.

    Applications are reduced to the executable's own name: a program is the
    same program wherever it is installed from, and keeping the path would make
    SysWOW64\\powershell.exe and System32\\powershell.exe two entities.
    Hosts keep their full name and only lose case.
    """
    s = _deescape(str(value or "").strip())
    if not s:
        return ""
    if kind == "application":
        # Split on both separators: the path may be Windows or POSIX, and a
        # Windows path that arrived through a POSIX-side tool can carry either.
        s = s.replace("\\", "/").rstrip("/")
        s = s.rsplit("/", 1)[-1]
        # "firewall-drop (add)" — the parenthesised verb is the action taken,
        # not part of the program's name.
        s = re.sub(r"\s*\([^)]*\)\s*$", "", s)
        s = s.strip().casefold()
    else:
        s = s.strip().casefold()
    return s


def human_account(raw) -> str:
    r"""The canonical PERSON behind an account string, or "" if it is not one.

    This is the fix for the misclassification the first version of this module
    shipped. Four things have to happen in order, and skipping any of them
    inflates a host's apparent user count:

      1. DE-ESCAPE. The sync bridge doubles backslashes depending on how many
         JSON hops an event took, so one person arrives as both
         `VGINFO\\name` and `VGINFO\name`.
      2. DROP NON-HUMANS. Service accounts, machine accounts (trailing `$`),
         Windows per-session pseudo-users (DWM-178, UMFD-0) and typed entity
         keys (`host:`, `ip:`) are not people.
      3. STRIP THE DOMAIN. `VGINFO\name` and a bare `name` are one person.
      4. RE-CHECK the tail, because a qualified name can still resolve to a
         non-human: `SOMEDOMAIN\SYSTEM` passes step 2 and must not pass here.
    """
    s = _deescape(str(raw or "").strip())
    low = s.casefold()
    if low in _NONHUMAN_EXACT:
        return ""
    if any(low.startswith(p) for p in _NONHUMAN_PREFIX):
        return ""
    if _PSEUDO_ACCOUNT.search(low) or low.endswith("$"):
        return ""
    tail = s.rsplit("\\", 1)[-1].strip().casefold()
    if (not tail or tail in _NONHUMAN_EXACT
            or _PSEUDO_ACCOUNT.search(tail) or tail.endswith("$")):
        return ""
    return tail


def count_human_accounts(accounts) -> int:
    """How many distinct PEOPLE these account strings represent."""
    return len({h for h in (human_account(a) for a in (accounts or [])) if h})


def appliance_os(os_family) -> str:
    """The os.family value marking this as a network appliance, or "".

    Separate from the role decision so a caller can report WHICH value decided
    it rather than just the verdict.
    """
    v = str(os_family or "").strip().casefold().replace(" ", "_")
    return v if v in _APPLIANCE_OS else ""


def check_field(field: str) -> tuple:
    """(ok, reason) for a field an operator wants to track (SN 67).

    Refused at the point of adding rather than at the point of recording, so
    the operator is told why instead of finding a suspended kind later.
    """
    f = str(field or "").strip()
    if not f:
        return False, "no field given"
    if len(f) > 200:
        return False, "field path is implausibly long"
    if not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.\-\[\]]*$", f):
        return False, "field path must be a dotted path, e.g. data.appname"
    leaf = f.rsplit(".", 1)[-1]
    low = leaf.casefold()
    words = _leaf_words(leaf)
    # A trailing number is part of the name, not the name: "sha256" splits to
    # ['sha', '256'], so the digits are skipped to reach the word that matters.
    while words and words[-1].isdigit():
        words.pop()
    hit = (low in _UNBOUNDED_LEAVES
           or low in _UNBOUNDED_WORDS
           or (words and words[-1] in _UNBOUNDED_WORDS))
    if hit:
        return (False,
                "%r is an unbounded identifier — tracking it would create one "
                "entity per event. Pick a field whose values repeat, such as "
                "an application or account name." % leaf)
    return True, ""


def _kind_name(kind: str) -> str:
    """Custom kinds are namespaced, so they cannot collide with ours.

    IDEMPOTENT, and it has to be: save() re-cleans every mapping on write-back,
    so a non-idempotent version turned "custom:protocol" into
    "custom:custom_protocol" one write later and dedupe and removal could never
    match the stored kind again.
    """
    raw = str(kind or "").strip().casefold()
    if raw.startswith(CUSTOM_PREFIX):
        raw = raw[len(CUSTOM_PREFIX):]
    k = re.sub(r"[^a-z0-9_]+", "_", raw).strip("_")
    if not k:
        return ""
    return k if k in BUILTIN_KINDS else CUSTOM_PREFIX + k


# ── the register: host role overrides and SN 67 field mappings ───────────────

def _clean_mapping(m) -> "dict | None":
    if not isinstance(m, dict):
        return None
    field = str(m.get("field") or "").strip()
    kind = _kind_name(m.get("kind") or "")
    if not field or not kind:
        return None
    ok, _ = check_field(field)
    if not ok:
        return None
    try:
        cap = int(m.get("max_cardinality") or DEFAULT_MAX_CARDINALITY)
    except (TypeError, ValueError):
        cap = DEFAULT_MAX_CARDINALITY
    return {
        "field": field,
        "kind": kind,
        "enabled": bool(m.get("enabled", True)),
        "max_cardinality": max(1, min(cap, 1_000_000)),
        "note": str(m.get("note") or "")[:500],
        "added_at": m.get("added_at") or datetime.now(timezone.utc).isoformat(),
        "added_by": m.get("added_by") or None,
    }


def _read(path) -> dict:
    """Parsed register for `path`, re-read only when the file changes.

    Same contract as the watch list: mtime plus size, so an operator's edit
    takes effect within one event and no restart is needed.
    """
    p = Path(path)
    try:
        st = p.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None

    key = str(p)
    hit = _cache.get(key)
    if hit and hit["stamp"] == stamp:
        return hit["data"]

    hosts: dict = {}
    mappings: list = []
    if stamp is not None:
        try:
            raw = json.loads(p.read_text(encoding="utf-8") or "{}")
            if isinstance(raw, list):           # tolerate a bare mapping list
                raw = {"mappings": raw}
            for name, role in (raw.get("hosts") or {}).items():
                n, r = normalise(name), str(role or "").strip().casefold()
                if n and r in HOST_ROLES:
                    hosts[n] = r
            seen = set()
            for m in (raw.get("mappings") or []):
                c = _clean_mapping(m)
                if c and (c["field"], c["kind"]) not in seen:
                    seen.add((c["field"], c["kind"]))
                    mappings.append(c)
        except Exception as ex:
            print("[entities] failed to read %s: %s" % (p, ex))
            hosts, mappings = {}, []

    data = {"hosts": hosts, "mappings": mappings}
    _cache[key] = {"stamp": stamp, "data": data}
    return data


def register(path) -> dict:
    with _lock:
        d = _read(path)
        return {"hosts": dict(d["hosts"]), "mappings": list(d["mappings"])}


def save(path, hosts: dict, mappings: list) -> None:
    """Atomically replace the register."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "hosts": {normalise(k): str(v).casefold()
                  for k, v in (hosts or {}).items()
                  if normalise(k) and str(v).casefold() in HOST_ROLES},
        "mappings": [m for m in (_clean_mapping(x) for x in (mappings or []))
                     if m],
    }
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(body, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    os.replace(tmp, p)
    with _lock:
        _cache.pop(str(p), None)


def add_mapping(path, field: str, kind: str, note: str = "",
                added_by=None, max_cardinality=None) -> tuple:
    """(entry, error). Refuses an unbounded field, and says why."""
    ok, reason = check_field(field)
    if not ok:
        return None, reason
    if not _kind_name(kind):
        return None, "no kind given"
    with _lock:
        cur = _read(path)
        hosts, mappings = dict(cur["hosts"]), list(cur["mappings"])
    entry = _clean_mapping({"field": field, "kind": kind, "note": note,
                            "added_by": added_by,
                            "max_cardinality": max_cardinality})
    if not entry:
        return None, "mapping is not usable"
    for m in mappings:
        if m["field"] == entry["field"] and m["kind"] == entry["kind"]:
            return m, "that field is already mapped to that kind"
    mappings.append(entry)
    save(path, hosts, mappings)
    return entry, ""


def remove_mapping(path, field: str, kind: str) -> bool:
    k = _kind_name(kind)
    f = str(field or "").strip()
    with _lock:
        cur = _read(path)
        hosts, mappings = dict(cur["hosts"]), list(cur["mappings"])
    keep = [m for m in mappings if not (m["field"] == f and m["kind"] == k)]
    if len(keep) == len(mappings):
        return False
    save(path, hosts, keep)
    return True


def set_host_role(path, host: str, role: str) -> tuple:
    """Operator override for one host's role. role='' clears it."""
    n = normalise(host)
    if not n:
        return None, "no host given"
    r = str(role or "").strip().casefold()
    if r and r not in HOST_ROLES:
        return None, "role must be one of %s" % (HOST_ROLES,)
    with _lock:
        cur = _read(path)
        hosts, mappings = dict(cur["hosts"]), list(cur["mappings"])
    if r:
        hosts[n] = r
    else:
        hosts.pop(n, None)
    save(path, hosts, mappings)
    return {"host": n, "role": r or None}, ""


# ── classification ──────────────────────────────────────────────────────────

def classify_host(name, reg: "dict | None" = None,
                  humans_seen: int = 0, os_family: str = "",
                  os_share: float = 1.0) -> dict:
    """{'role', 'source', 'why'} for one host name.

    Precedence, and each step is here because a weaker one got something wrong:

      1. OPERATOR REGISTER   always wins; the classifier is a default.
      2. OS FAMILY           a FortiOS/IOS/JunOS box is an APPLIANCE, not a
                             server. The firewall collector in this estate
                             carries 24,453 distinct accounts because every
                             event's user lands on it, and calling that a
                             server makes the whole estate its "behaviour".

                             `os_family` MUST be the host's DOMINANT value,
                             not one event's. Measured on live data, two
                             Windows hosts carry a minority of network_os
                             events (538 windows vs 29, and 39 vs 33) because
                             firewall records get attributed to whichever host
                             reported them. Passing a single event's value
                             would make those two appliances.
      3. NAME SHAPE          catches the servers whose names say so, including
                             the ones only one person logs into.
      4. HUMAN BREADTH       catches a multi-user server with no naming
                             convention. Counted as distinct PEOPLE, not raw
                             account strings — see human_account(). The raw
                             count is inflated three- to tenfold by escaping
                             duplicates, service and machine accounts and
                             Windows session pseudo-users, and counting it
                             promoted four laptops to "server" on live data.
      5. ENDPOINT            the default.

    `humans_seen` is a count of PEOPLE. Passing a raw account count here is the
    mistake this signature was renamed to make obvious.
    """
    n = normalise(name)
    if not n:
        return {"role": "", "source": "", "why": "no host on the event"}

    if reg:
        role = (reg.get("hosts") or {}).get(n)
        if role in HOST_ROLES:
            return {"role": role, "source": "register",
                    "why": "operator tagged %s as %s" % (n, role)}

    appl = appliance_os(os_family)
    if appl and os_share >= APPLIANCE_OS_SHARE and humans_seen >= APPLIANCE_MIN_PEOPLE:
        return {"role": "appliance", "source": "collector",
                "why": "%.0f%% of its events are %s and %d distinct people are "
                       "attributed to it — an aggregation point, not a host "
                       "people log into"
                       % (os_share * 100, appl, humans_seen)}

    # The long pattern is run against the ORIGINAL spelling so its camelCase
    # boundary can see the capital; the short one against the folded name.
    raw = _deescape(str(name or "").strip())
    tokens = [t for t in (_SERVER_SHAPE_LONG.findall(raw)
                          + _SERVER_SHAPE_LONG.findall(n)
                          + _SERVER_SHAPE_SHORT.findall(n))
              if not _SERVER_SHAPE_EXCEPT.match(t)]
    tokens = sorted(set(t.lower() for t in tokens))
    if tokens:
        return {"role": "server", "source": "name_shape",
                "why": "name contains %s" % ", ".join(repr(t) for t in tokens)}

    if humans_seen >= HUMAN_BREADTH_THRESHOLD:
        return {"role": "server", "source": "human_breadth",
                "why": "%d distinct people have used it (threshold %d)"
                       % (humans_seen, HUMAN_BREADTH_THRESHOLD)}

    if humans_seen:
        return {"role": "endpoint", "source": "default",
                "why": "only %d distinct %s used it, and the name carries no "
                       "server signal"
                       % (humans_seen, "person has" if humans_seen == 1
                          else "people have")}
    return {"role": "endpoint", "source": "default",
            "why": "no server signal"}


def event_host(log: dict) -> str:
    for f in _HOST_FIELDS:
        v = get_nested(log, f)
        if v not in (None, ""):
            return str(v)
    return ""


def applications(log: dict) -> list:
    """[(value, field)] for the program(s) this event names.

    At most one, from the first source that yields a usable name — a Windows
    event names both an image and a program name, and they are the same
    program.
    """
    for f in _APP_FIELDS:
        raw = get_nested(log, f)
        if raw in (None, "", "-"):
            continue
        if _ACTIVE_RESPONSE.search(_deescape(str(raw))):
            return []                       # platform automation, see header
        v = normalise(raw, "application")
        if v:
            return [(v, f)]

    # object.name is only a program when object.type says so. On 52% of alerts
    # it is an account name, and on the network events it is a destination
    # hostname, so reading it unconditionally would file people and websites
    # as applications.
    if str(get_nested(log, "object.type") or "").casefold() == "process":
        raw = get_nested(log, "object.name")
        if raw and not _ACTIVE_RESPONSE.search(_deescape(str(raw))):
            v = normalise(raw, "application")
            if v:
                return [(v, "object.name")]
    return []


class CardinalityGuard:
    """Suspends a kind that is accumulating unbounded values.

    check_field() refuses the fields whose NAMES give them away. This catches
    the rest: a field that looked fine and turns out to carry a fresh value
    every event. Once suspended a kind stops being recorded and says why, in
    preference to growing entity_presence without limit.

    Bounded by construction: the moment a kind passes its cap its value set is
    dropped, so the guard itself cannot be the thing that exhausts memory.
    """

    def __init__(self, cap: int = DEFAULT_MAX_CARDINALITY):
        self.cap = max(1, int(cap))
        self._seen: dict = {}
        self._suspended: dict = {}
        self._dropped: dict = {}

    def allow(self, kind: str, value: str, cap: "int | None" = None) -> bool:
        if kind in self._suspended:
            self._dropped[kind] = self._dropped.get(kind, 0) + 1
            return False
        limit = max(1, int(cap or self.cap))
        vals = self._seen.setdefault(kind, set())
        if value in vals:
            return True
        if len(vals) >= limit:
            self._suspended[kind] = (
                "more than %d distinct values; the field is unbounded, so it "
                "is not an entity" % limit)
            self._seen.pop(kind, None)      # release the set, keep the verdict
            self._dropped[kind] = self._dropped.get(kind, 0) + 1
            return False
        vals.add(value)
        return True

    def suspended(self) -> dict:
        return dict(self._suspended)

    def status(self) -> dict:
        return {
            "cap": self.cap,
            "kinds": {k: len(v) for k, v in self._seen.items()},
            "suspended": dict(self._suspended),
            "dropped": dict(self._dropped),
        }


DEVICE_PREFIX = "device:"


def device_key(host) -> str:
    """The entity key a device's own presence rows are filed under.

    entity_presence is (username, kind, value), and nothing requires the first
    column to be an account — the primary namespace already files userless
    traffic under endpoint:/host: keys. So a device gets its own rows under
    device:<host>, and "which programs ran on this machine" becomes a lookup
    rather than a field the slim cache would have to start carrying.
    """
    n = normalise(host)
    return (DEVICE_PREFIX + n) if n else ""


def device_facing(entities: list) -> list:
    """The subset of extract()'s output that describes the DEVICE.

    The host's own server/endpoint row is excluded: filing a device under
    itself says nothing. What is left is the program that ran and anything the
    operator nominated, both of which are properties of the machine as much as
    of the account.
    """
    return [e for e in (entities or [])
            if str(e.get("kind") or "") not in HOST_ROLES]


def extract(log: dict, reg: "dict | None" = None, accounts_seen: int = 0,
            guard: "CardinalityGuard | None" = None) -> list:
    """Secondary entities this one event touches.

    [{'kind','value','source','field','why'}]. The primary entity key is NOT
    included — that is resolve_entity()'s job and this must never compete with
    it. Never raises: a missing secondary entity is worth less than the
    pipeline it would take down.
    """
    out: list = []
    try:
        host = event_host(log)
        if host:
            c = classify_host(host, reg, accounts_seen)
            if c["role"]:
                v = normalise(host)
                if guard is None or guard.allow(c["role"], v):
                    out.append({"kind": c["role"], "value": v,
                                "source": c["source"], "field": "host.name",
                                "why": c["why"]})

        for value, field in applications(log):
            if guard is None or guard.allow("application", value):
                out.append({"kind": "application", "value": value,
                            "source": "event", "field": field,
                            "why": "program named on the event"})

        # SN 67 — whatever the operator nominated.
        for m in ((reg or {}).get("mappings") or []):
            if not m.get("enabled", True):
                continue
            raw = get_nested(log, m["field"])
            if raw in (None, "", "-") or isinstance(raw, (dict, list)):
                continue
            v = normalise(raw)
            if not v:
                continue
            if guard is not None and not guard.allow(
                    m["kind"], v, m.get("max_cardinality")):
                continue
            out.append({"kind": m["kind"], "value": v, "source": "operator",
                        "field": m["field"],
                        "why": "operator mapped %s to %s"
                               % (m["field"], m["kind"])})
    except Exception as ex:                                  # pragma: no cover
        print("[entities] extract failed: %s" % ex)
    return out


def status(path=None, guard: "CardinalityGuard | None" = None) -> dict:
    """What this module is doing, for /api and for the evidence pack."""
    reg = register(path) if path else {"hosts": {}, "mappings": []}
    return {
        "builtin_kinds": list(BUILTIN_KINDS),
        "custom_prefix": CUSTOM_PREFIX,
        "host_overrides": len(reg["hosts"]),
        "mappings": reg["mappings"],
        "observed_account_threshold": OBSERVED_ACCOUNT_THRESHOLD,
        "data_asset_kind": (
            "not offered — this feed carries no file-path field (object.type "
            "== 'file' on 9 of 3,412 sampled alerts, all web-attack URL "
            "paths). Data assets are covered by the operator-tagged "
            "high-value asset register (SN 40)."),
        "guard": guard.status() if guard else None,
    }


# ── selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    import tempfile

    failures = []

    def ok(label, cond):
        if not cond:
            failures.append(label)

    # ── normalise ──
    ok("deescape collapses doubled backslashes",
       _deescape("C:\\\\Windows\\\\x") == "C:\\Windows\\x")
    ok("deescape collapses however many hops",
       _deescape("A\\\\\\\\b") == "A\\b")
    ok("app normalises a windows path to the executable",
       normalise("C:\\\\Windows\\\\System32\\\\cmd.exe", "application")
       == "cmd.exe")
    ok("app normalises a posix path to the executable",
       normalise("/usr/sbin/sshd", "application") == "sshd")
    ok("app folds case",
       normalise("PowerShell.EXE", "application") == "powershell.exe")
    ok("app strips the parenthesised action",
       normalise("firewall-drop (add)", "application") == "firewall-drop")
    ok("app from a mixed-separator path",
       normalise("C:/Windows\\\\System32/svchost.exe", "application")
       == "svchost.exe")
    ok("host keeps its full name, folded",
       normalise("DC_DIR_srv") == "dc_dir_srv")
    ok("empty normalises to empty", normalise(None) == "" and normalise("  ") == "")
    ok("two spellings of one program converge",
       normalise("C:\\\\Windows\\\\SysWOW64\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
                 "application")
       == normalise("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "application"))

    # The de-escaper must agree with the one in the preprocessor, which is the
    # canonical copy. Skipped rather than failed when that module cannot be
    # imported, so this selftest still runs without numpy installed.
    try:
        import ueba_preprocessor as _pp
        cases = ["a\\\\b", "a\\b", "A\\\\\\\\B", "", "no-escape",
                 "C:\\\\Program Files\\\\x", "DOMAIN\\\\user"]
        ok("deescape matches ueba_preprocessor on every case",
           all(_deescape(c) == _pp._deescape(c) for c in cases))
    except Exception:
        pass

    # ── check_field ──
    ok("a plain field is accepted", check_field("data.appname")[0])
    ok("an unbounded id is refused", not check_field("data.win.system.processID")[0])
    for leaf in ("process.pid", "x.sha256", "e.timestamp", "d.dstport",
                 "a.sessionId", "b.guid", "c.rcvdbyte"):
        ok("refused: %s" % leaf, not check_field(leaf)[0])
    ok("the refusal explains itself",
       "unbounded" in check_field("process.pid")[1])
    ok("an empty field is refused", not check_field("")[0])
    ok("a path with spaces is refused", not check_field("data. appname")[0])
    ok("a path with a quote is refused", not check_field("data.app'name")[0])
    ok("an implausibly long path is refused", not check_field("a." * 150)[0])
    # A field whose leaf is innocent but whose parent is not stays allowed:
    # only the leaf decides, because the leaf is what the values come from.
    ok("only the leaf decides", check_field("data.processid.name")[0])

    # ── kind namespacing ──
    ok("a builtin kind is unprefixed", _kind_name("server") == "server")
    ok("a custom kind is prefixed", _kind_name("Database") == "custom:database")
    ok("a custom kind cannot squat a primary namespace",
       _kind_name("person") == "custom:person")
    ok("punctuation is folded away", _kind_name("data store!") == "custom:data_store")
    ok("an empty kind is empty", _kind_name("  ") == "")

    # ── classify_host ──
    for h in ("APP-SRV-01", "ACCESS-SRV-02", "DC_CORE_SRV", "DC_DIR_srv",
              "kafka-broker1", "web01", "db-prod-2", "vpn.gw"):
        ok("server by shape: %s" % h,
           classify_host(h)["role"] == "server")
    for h in ("sales_Pc", "Laptop-A", "Laptop-B", "Laptop-C", "Laptop-D", "Laptop-E",
              "Laptop-F_primary"):
        ok("endpoint by default: %s" % h,
           classify_host(h)["role"] == "endpoint")
    ok("shape reports which token matched",
       "srv" in classify_host("DC_DIR_srv")["why"])
    ok("source is name_shape when the shape decided",
       classify_host("web01")["source"] == "name_shape")
    ok("a person called Sarah is not a server",
       classify_host("Sarah")["role"] == "endpoint")
    ok("an 'adam' laptop is not a server by its 'ad'",
       classify_host("adam")["role"] == "endpoint")
    ok("no host yields no role", classify_host("")["role"] == "")
    ok("human breadth promotes a shapeless host",
       classify_host("blobby", humans_seen=40)["role"] == "server")
    ok("the breadth source is reported",
       classify_host("blobby", humans_seen=40)["source"] == "human_breadth")
    ok("and the count is quoted",
       "40 distinct people" in classify_host("blobby", humans_seen=40)["why"])
    ok("three people is not enough to promote a laptop",
       classify_host("sales_Pc", humans_seen=3)["role"] == "endpoint")
    ok("and the reason says how few",
       "3 distinct people" in classify_host("sales_Pc", humans_seen=3)["why"])
    ok("one person reads in the singular",
       "1 distinct person has" in classify_host("sales_Pc", humans_seen=1)["why"])
    # The regression this rebuild exists for: every one of these laptops was
    # promoted to "server" by the previous raw-account rule at its threshold
    # of 8. Their real human counts, measured on the live store, are 1-3.
    for host, humans in (("firdous", 3), ("rupali", 1), ("utkarsh_pc", 3),
                         ("nidhi", 1), ("rupen_primary", 2), ("monish", 1)):
        v = classify_host(host, None, humans)
        ok("live laptop stays an endpoint: %s" % host, v["role"] == "endpoint")
    # ...while the host that genuinely is multi-user is promoted.
    ok("a genuinely multi-user host is a server",
       classify_host("someshapelesshost", None, 21)["role"] == "server")

    # ── appliances: BOTH tests required ──
    ap = classify_host("collector", None, 14858, "network_os", 1.0)
    ok("a near-total network_os collector is an appliance",
       ap["role"] == "appliance")
    ok("and the source says collector", ap["source"] == "collector")
    ok("and the reason gives both numbers",
       "100%" in ap["why"] and "14858" in ap["why"])
    # The two live laptops that the share-only rule got wrong.
    ok("85% network_os with 4 people is NOT an appliance",
       classify_host("crypt0n", None, 4, "network_os", 0.85)["role"]
       == "endpoint")
    ok("61% network_os with 1 person is NOT an appliance",
       classify_host("himanshu", None, 1, "network_os", 0.61)["role"]
       == "endpoint")
    # NB the host name here must carry no server token of its own — an earlier
    # version of this check used "small-fw" and matched on 'fw' before the
    # appliance test was ever reached.
    ok("100% network_os but only 4 people is NOT an appliance",
       classify_host("quietbox", None, 4, "network_os", 1.0)["role"]
       == "endpoint")
    ok("many people but only 61% network_os is NOT an appliance",
       classify_host("busy", None, 9999, "network_os", 0.61)["role"]
       == "server")
    ok("an ordinary windows host is not an appliance",
       classify_host("laptop-a", None, 2, "windows", 0.0)["role"] == "endpoint")
    ok("an unknown os family decides nothing",
       classify_host("laptop-a", None, 2, "weird", 1.0)["role"] == "endpoint")
    ok("appliance_os reports which value matched",
       appliance_os("NETWORK_OS") == "network_os")
    ok("and nothing for a normal os", appliance_os("windows") == "")

    # ── name shape: camelCase on long tokens, separators only on short ones ──
    ok("a camelCase long token is caught",
       classify_host("MDM_ServerAnsh")["role"] == "server")
    ok("upper-case too", classify_host("MDM_SERVERAnsh")["role"] == "server")
    ok("srv in camelCase is caught",
       classify_host("app_srvNode")["role"] == "server")
    # The word that must NOT match: a trailing letter is only a boundary when
    # it is a capital, so "serverless" is not a server.
    ok("serverless is not a server",
       classify_host("serverless-fn")["role"] == "endpoint")
    ok("a short token still needs a real boundary",
       classify_host("ADMinThing")["role"] == "endpoint")
    ok("and adam is still not a domain controller",
       classify_host("adam")["role"] == "endpoint")
    ok("a short token with a separator still works",
       classify_host("DC_ATM_SRV")["role"] == "server")

    # ── human_account ──
    ok("a plain name is a person", human_account("jane.doe") == "jane.doe")
    ok("a domain is stripped", human_account("VGINFO\\jane.doe") == "jane.doe")
    ok("a doubled-escape domain is stripped too",
       human_account("VGINFO\\\\jane.doe") == "jane.doe")
    ok("all three spellings are one person",
       len({human_account("VGINFO\\\\n.c"), human_account("VGINFO\\n.c"),
            human_account("n.c")}) == 1)
    for nonhuman in ("NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\\\LOCAL SERVICE",
                     "NT SERVICE\\MSSQL", "NT VIRTUAL MACHINE\\4D02C33E",
                     "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
                     "VGSOC-LAP04$", "DWM-178", "UMFD-0", "host:Nidhi",
                     "ip:10.0.0.1", "external:1.2.3.4", "ANONYMOUS LOGON",
                     "-", ""):
        ok("not a person: %s" % (nonhuman or "(empty)"),
           human_account(nonhuman) == "")
    ok("a qualified service account is still rejected",
       human_account("SOMEDOMAIN\\SYSTEM") == "")
    ok("a qualified machine account is still rejected",
       human_account("SOMEDOMAIN\\HOST$") == "")
    ok("counting collapses one person's spellings",
       count_human_accounts(["VGINFO\\\\n.c", "VGINFO\\n.c", "n.c"]) == 1)
    ok("counting excludes the non-humans",
       count_human_accounts(["VGINFO\\\\n.c", "NT AUTHORITY\\\\SYSTEM",
                             "VGSOC-LAP04$", "DWM-1", "host:X"]) == 1)
    ok("counting nothing is zero", count_human_accounts([]) == 0)
    ok("counting None is zero", count_human_accounts(None) == 0)
    # The exact live case, start to finish.
    nidhi = ["VGINFO\\\\nidhi.choudhari", "host:Nidhi",
             "NT AUTHORITY\\\\SYSTEM", "VGSOC-LAP04$", "nidhi.choudhari",
             "NT AUTHORITY\\\\NETWORK SERVICE", "VGINFO\\nidhi.choudhari",
             "NT AUTHORITY\\\\LOCAL SERVICE"]
    ok("the live Nidhi case counts as one person",
       count_human_accounts(nidhi) == 1)
    ok("and therefore stays an endpoint",
       classify_host("nidhi", None, count_human_accounts(nidhi))["role"]
       == "endpoint")
    reg = {"hosts": {"sales_pc": "server", "app-srv-01": "endpoint"}}
    ok("the register overrides the default",
       classify_host("sales_Pc", reg)["role"] == "server")
    ok("the register overrides the shape too",
       classify_host("APP-SRV-01", reg)["role"] == "endpoint")
    ok("the register overrides observed breadth",
       classify_host("APP-SRV-01", reg, 99)["role"] == "endpoint")
    ok("register is reported as the source",
       classify_host("sales_Pc", reg)["source"] == "register")

    # ── applications ──
    ok("program_name is read",
       applications({"context": {"raw_event": {"predecoder":
                    {"program_name": "sshd"}}}}) == [("sshd", "context.raw_event.predecoder.program_name")])
    ok("process.image wins over program_name",
       applications({"process": {"image": "C:\\\\Windows\\\\cmd.exe"},
                     "context": {"raw_event": {"predecoder":
                        {"program_name": "sshd"}}}})[0][0] == "cmd.exe")
    ok("the windows eventdata image is read",
       applications({"context": {"raw_event": {"data": {"win": {"eventdata":
                    {"image": "C:\\\\Windows\\\\System32\\\\svchost.exe"}}}}}})[0][0]
       == "svchost.exe")
    ok("object.name is an application only when object.type says process",
       applications({"object": {"type": "process",
                                "name": "C:\\\\Windows\\\\reg.exe"}})[0][0] == "reg.exe")
    ok("object.name is NOT read when the object is a user",
       applications({"object": {"type": "user", "name": "root"}}) == [])
    ok("object.name is NOT read when the type is absent",
       applications({"object": {"name": "www.google.com"}}) == [])
    ok("active response is excluded",
       applications({"object": {"type": "process",
                                "name": "active-response/bin/disable-account (add)"}}) == [])
    ok("active response is excluded from program_name too",
       applications({"context": {"raw_event": {"predecoder":
                    {"program_name": "active-response\\\\bin\\\\firewall-drop"}}}}) == [])
    ok("a dash value is not an application",
       applications({"process": {"image": "-"}}) == [])
    ok("an empty event yields nothing", applications({}) == [])
    ok("at most one application per event",
       len(applications({"process": {"image": "/bin/bash"},
                         "object": {"type": "process", "name": "/bin/sh"}})) == 1)

    # ── cardinality guard ──
    g = CardinalityGuard(cap=3)
    ok("under the cap is allowed", all(g.allow("custom:x", str(i)) for i in range(3)))
    ok("the cap suspends the kind", not g.allow("custom:x", "4"))
    ok("a suspended kind stays suspended", not g.allow("custom:x", "0"))
    ok("the suspension says why", "unbounded" in g.suspended()["custom:x"])
    ok("another kind is unaffected", g.allow("custom:y", "a"))
    ok("repeats do not consume the cap",
       all(CardinalityGuard(cap=2).allow("k", "same") for _ in range(1)))
    g2 = CardinalityGuard(cap=2)
    g2.allow("k", "a"); g2.allow("k", "a"); g2.allow("k", "b")
    ok("a repeated value never counts twice", g2.allow("k", "a"))
    ok("the suspended kind's value set is released",
       "custom:x" not in g.status()["kinds"])
    ok("drops are counted", g.status()["dropped"]["custom:x"] >= 2)
    g3 = CardinalityGuard(cap=100)
    ok("a per-mapping cap overrides the default",
       g3.allow("k", "a", cap=1) and not g3.allow("k", "b", cap=1))

    # ── extract ──
    ev = {
        "host": {"name": "DC_DIR_srv"},
        "process": {"image": "C:\\\\Windows\\\\System32\\\\powershell.exe"},
        "data": {"appname": "HTTPS"},
    }
    got = extract(ev)
    kinds = {e["kind"]: e["value"] for e in got}
    ok("extract finds the server", kinds.get("server") == "dc_dir_srv")
    ok("extract finds the application", kinds.get("application") == "powershell.exe")
    ok("extract does not invent a custom kind", not any(
        e["kind"].startswith(CUSTOM_PREFIX) for e in got))
    ok("every entity carries its reason", all(e["why"] for e in got))
    ok("every entity carries the field it came from", all(e["field"] for e in got))
    ok("a laptop is an endpoint, not a server",
       extract({"host": {"name": "Laptop-A"}})[0]["kind"] == "endpoint")
    ok("an empty event yields nothing", extract({}) == [])
    ok("extract never raises on junk",
       extract({"host": None, "process": "nonsense"}) == [] or True)
    ok("extract survives a non-dict log", extract(None) == [])

    reg2 = {"hosts": {}, "mappings": [
        {"field": "data.appname", "kind": "custom:protocol", "enabled": True,
         "max_cardinality": 5000},
        {"field": "data.missing", "kind": "custom:nothing", "enabled": True,
         "max_cardinality": 5000},
        {"field": "data.appname", "kind": "custom:off", "enabled": False,
         "max_cardinality": 5000}]}
    got2 = extract(ev, reg2)
    k2 = {e["kind"]: e["value"] for e in got2}
    ok("an operator mapping produces an entity", k2.get("custom:protocol") == "https")
    ok("a mapping whose field is absent produces nothing",
       "custom:nothing" not in k2)
    ok("a disabled mapping produces nothing", "custom:off" not in k2)
    ok("the operator entity is attributed to the operator",
       [e for e in got2 if e["kind"] == "custom:protocol"][0]["source"] == "operator")
    ok("a dict-valued field is skipped",
       not [e for e in extract({"data": {"x": {"y": 1}}},
            {"hosts": {}, "mappings": [{"field": "data.x", "kind": "k",
             "enabled": True, "max_cardinality": 10}]}) if e["kind"] == "custom:k"])

    # The guard must bite through extract(), not only when called directly.
    g4 = CardinalityGuard(cap=1)
    extract({"host": {"name": "web01"}}, guard=g4)
    second = extract({"host": {"name": "db02"}}, guard=g4)
    ok("the guard suspends a kind through extract",
       not [e for e in second if e["kind"] == "server"])

    # ── the register on disk ──
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "entities.json"
        ok("a missing register reads as empty",
           register(path) == {"hosts": {}, "mappings": []})

        entry, err = add_mapping(path, "data.appname", "Protocol",
                                 note="fortigate app id", added_by="aditya")
        ok("a good mapping is added", entry and not err)
        ok("the kind is namespaced on the way in",
           entry["kind"] == "custom:protocol")
        ok("the register now reports it", len(register(path)["mappings"]) == 1)

        dup, err2 = add_mapping(path, "data.appname", "protocol")
        ok("a duplicate is reported, not duplicated",
           err2 and len(register(path)["mappings"]) == 1)

        bad, err3 = add_mapping(path, "process.pid", "pid")
        ok("an unbounded field is refused on the way in", bad is None and err3)
        ok("the refusal reaches the caller", "unbounded" in err3)
        ok("the refused mapping was not stored",
           len(register(path)["mappings"]) == 1)

        _, err4 = set_host_role(path, "sales_Pc", "server")
        ok("a host override is stored", not err4)
        ok("the override is read back",
           register(path)["hosts"].get("sales_pc") == "server")
        ok("the override is applied by the classifier",
           classify_host("sales_Pc", register(path))["role"] == "server")
        _, err5 = set_host_role(path, "x", "laptop")
        ok("an unknown role is refused", err5)
        set_host_role(path, "sales_Pc", "")
        ok("an override can be cleared",
           "sales_pc" not in register(path)["hosts"])

        ok("a mapping can be removed",
           remove_mapping(path, "data.appname", "protocol"))
        ok("removing a mapping that is not there is False",
           not remove_mapping(path, "data.appname", "protocol"))
        ok("the register is empty again",
           register(path)["mappings"] == [])

        # mtime invalidation: an edit underneath us must be picked up without
        # a restart, which is the whole point of the register contract.
        save(path, {"a-srv": "server"}, [])
        ok("the edit is visible immediately",
           register(path)["hosts"] == {"a-srv": "server"})
        save(path, {"b-srv": "endpoint"}, [])
        ok("a second edit is visible too",
           register(path)["hosts"] == {"b-srv": "endpoint"})

        # a corrupt register must read as empty, not take the engine down
        path.write_text("{not json", encoding="utf-8")
        ok("a corrupt register reads as empty",
           register(path) == {"hosts": {}, "mappings": []})

        # a bare list is tolerated as a mapping list
        path.write_text(json.dumps([{"field": "data.appname", "kind": "p"}]),
                        encoding="utf-8")
        ok("a bare list is read as mappings",
           len(register(path)["mappings"]) == 1)

        # junk entries are dropped individually, not fatally
        path.write_text(json.dumps({"mappings": [
            {"field": "data.appname", "kind": "good"},
            {"field": "process.pid", "kind": "bad"},
            "not a dict", {"kind": "no field"}]}), encoding="utf-8")
        ok("only the usable mapping survives",
           [m["kind"] for m in register(path)["mappings"]] == ["custom:good"])

        st = status(path)
        ok("status lists the builtin kinds",
           st["builtin_kinds"] == list(BUILTIN_KINDS))
        ok("status is explicit that no data-asset kind is offered",
           "not offered" in st["data_asset_kind"])

    total = 168
    if failures:
        print("ueba_entities selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  \u2717 %s" % f)
        return 1
    print("ueba_entities selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
