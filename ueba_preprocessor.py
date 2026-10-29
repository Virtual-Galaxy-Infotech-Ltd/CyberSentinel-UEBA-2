#!/usr/bin/env python3
"""
ueba_preprocessor.py
────────────────────
CyberSentinel UEBA — Feature Extraction & Preprocessing

Reads enriched.jsonl (output of L2 enrich_json.py), extracts numerical
feature vectors from each log, and writes them to an HDF5 file for
efficient training. Also maintains per-user behavioral profiles in SQLite.

This is the FOUNDATION of the entire UEBA pipeline. Every other component
depends on the feature vectors produced here.

Key design decisions:
  - Processes in chunks (never loads full file into RAM)
  - Uses plain Python dicts (no Pandas) for single-log inference at runtime
  - HDF5 output supports random access slicing for training
  - Handles missing/null fields gracefully (fills with 0.0)
  - Categorical fields are integer-encoded using config mappings

Usage:
  # Offline — preprocess training data
  python3 ueba_preprocessor.py \
      --input  combined_training.jsonl \
      --output data/features.h5 \
      --config ueba_config.yaml \
      --mode   batch

  # Check what features look like for a single log
  python3 ueba_preprocessor.py --demo --config ueba_config.yaml
"""

import argparse
import ipaddress
import json
import math
import logging
import multiprocessing as mp
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import h5py
import numpy as np
import yaml

try:
    import orjson
    _json_loads = orjson.loads
except ImportError:
    _json_loads = json.loads

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)-20s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("ueba.preprocessor")

# Alias for code where a local parameter shadows `log` — several methods here
# take the event dict as `log`, so the module logger is unreachable by name
# inside them (see UserProfileStore.update).
_log = log

# Transfer-volume writes are committed in batches: roughly ten events a second
# report bytes, so a commit per row would fsync constantly for a statistic that
# tolerates losing a few seconds of history on a crash.
_XFER_COMMIT_EVERY = 50
# Presence observations run on every event, same as transfer volume, so they
# commit on the same cadence and for the same reason: update() only runs after
# the alert gate, so nothing else would flush these writes.
_PRESENCE_COMMIT_EVERY = 50
# How many distinct values an entity may accumulate per kind before novelty
# stops being meaningful. A laptop that has legitimately been in 40 countries
# has no "unusual country"; past this point the signal is suppressed rather
# than reported, because at that spread it is noise.
_PRESENCE_NOVELTY_CAP = 40

# Where the host and the source country actually live in an enriched event.
#
# Ordered, and tried in order. `agent.name` was the only path the profile store
# ever looked at for the host, and no event carries it: the agent appears under
# context.raw_event, and the normalised host under host.name. The consequence
# was measurable — seen_agents was empty on all 155,160 profile rows while
# seen_countries was populated on 125,947 of them. The column was not sparse,
# it was dead. Keep `agent.name` last so an event that does carry it still
# works.
_HOST_FIELDS = (
    "host.name",
    "context.raw_event.agent.name",
    "context.raw_event.data.win.system.computer",
    "agent.name",
)
_COUNTRY_FIELDS = (
    "enrich.geo.src.country",
    "enrich.geo.src_country",
)


def _first_field(log: dict, fields) -> str:
    """First of `fields` that this event actually carries, as a string."""
    for path in fields:
        v = get_nested(log, path, "")
        if v not in (None, "", [], {}):
            return str(v).strip()
    return ""


def event_host(log: dict) -> str:
    """The host an event came from, whichever field this source populates."""
    return _first_field(log, _HOST_FIELDS)


def event_country(log: dict) -> str:
    """The source country an event came from, if it was geo-enriched."""
    return _first_field(log, _COUNTRY_FIELDS)


# ── Config Loader ─────────────────────────────────────────────────────────────

def load_config(config_path: str) -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


# ── Nested Field Getter ───────────────────────────────────────────────────────

def get_nested(d: dict, key_path: str, default=None) -> Any:
    """
    Safely get a nested dict value using dot notation.
    Example: get_nested(log, 'enrich.temporal.hour', 0)
    Returns default if any key in the path is missing or None.
    """
    keys = key_path.split(".")
    val = d
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k)
        if val is None:
            return default
    return val


def safe_float(val, default: float = 0.0) -> float:
    """Convert any value to float safely."""
    if val is None:
        return default
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def safe_bool(val, default: float = 0.0) -> float:
    """Convert boolean/truthy value to 0.0 or 1.0."""
    if val is None:
        return default
    if isinstance(val, bool):
        return 1.0 if val else 0.0
    if isinstance(val, (int, float)):
        return 1.0 if val else 0.0
    if isinstance(val, str):
        return 1.0 if val.lower() in ("true", "yes", "1") else 0.0
    return default


# URL-encoded query strings / paths occasionally leak into subject.name or
# data.srcuser and would otherwise become junk "user" entities. Real usernames
# and hosts never contain these characters (DOMAIN\\user, user@dom, host$ are fine).
_ENTITY_JUNK_CHARS = ("/", "%", "&", "=", "~", "?")
def _is_url_junk(s: str) -> bool:
    if not s:
        return False
    if len(s) > 64:
        return True
    low = s.lower()
    if "://" in low or low.startswith("www.") or ".php" in low or ".html" in low or ".aspx" in low:
        return True
    return any(c in s for c in _ENTITY_JUNK_CHARS)


# ── Identity Canonicalisation ─────────────────────────────────────────────────
#
# One person arrives under several spellings, so one person gets several
# baselines and each one is trained on a fraction of their history. Measured on
# a 3,412-alert production sample: 10 of 135 identities (7.4%) were duplicates
# of another identity, and 5 of the per-entity autoencoders on disk were second
# or third copies of a person who already had one.
#
#   jinu   <- 'VGSOC-LAP11\\JINU'(24), 'jinu'(20), 'VGSOC-LAP11\JINU'(6)
#   sujal  <- 'VGSOC-LAP16\Sujal',      'VGSOCSRV\sujal'
#
# Three separate defects produce that:
#   1. escaping — the same event is 'DOMAIN\user' or 'DOMAIN\\user' depending
#      on how many JSON encode/decode hops it took through the sync bridge
#   2. qualification — 'VGSOC-LAP11\JINU' and 'jinu' are never related
#   3. case — 'JINU' vs 'jinu', 'User' vs 'user'
#
# This normalisation is deliberately applied INSIDE resolve_entity() rather than
# at the engine. The pre-existing `identity_resolution.mappings` block was
# applied in ueba_engine.py only, so the trainer bucketed by the raw name while
# the engine looked up the canonical one — and 3 of the 5 configured mappings
# therefore resolved to a model file that training had never produced, silently
# falling back to the global autoencoder. resolve_entity() is the one place both
# sides already share, which is what its own docstring promises.
#
# TYPE-AWARE ON PURPOSE. Only account names are canonicalised; `ip:` and `host:`
# keys are returned untouched. A normaliser that also treats "_" as a separator
# over-merges: it collapses host_DC_ATM_SRV and host_GPU_SRV onto "srv", two
# unrelated servers. Only the backslash is a domain separator here.

_IDENTITY_CANONICALIZE = False      # off ⇒ resolve_entity() behaves as before
_IDENTITY_CASEFOLD     = True
_IDENTITY_STRIP_DOMAIN = True
_IDENTITY_ALIASES      = {}         # operator overrides: spelling → canonical
_IDENTITY_SHARED       = set()      # keep these host-qualified (see below)


def _deescape(s: str) -> str:
    """'DOMAIN\\\\user' → 'DOMAIN\\user'. Collapses however many hops it took."""
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return s


def _account_parts(name: str) -> tuple:
    """De-escape, then split 'DOMAIN\\user' into ('DOMAIN', 'user').

    prefix is '' for an unqualified name. Only the backslash is treated as a
    separator — see the type-awareness note above for why '_' must not be.
    """
    s = _deescape(str(name).strip())
    head, sep, tail = s.rpartition("\\")
    tail = tail.strip()
    return (head.strip() if sep else ""), (tail or s)


def canonical_identity(name: str) -> str:
    """Canonical key for ONE ACCOUNT identity.

    Never call this on an `ip:` or `host:` key — see the type-awareness note
    above. Returns `name` unchanged when canonicalisation is disabled.
    """
    if not name or not _IDENTITY_CANONICALIZE:
        return name

    raw = str(name).strip()
    s = _deescape(raw)

    # Operator overrides win, and are probed on both the raw and the de-escaped
    # spelling so a mapping written either way still fires. The target is then
    # canonicalised too, so an operator may write the readable form
    # ("RootSeeker\Sujal") and still land on the key training produces.
    for probe in (raw, s):
        if probe in _IDENTITY_ALIASES:
            s = _deescape(str(_IDENTITY_ALIASES[probe]).strip())
            break

    # DOMAIN\user and HOST\user → user.
    #
    # EXCEPT for shared/local accounts. 'VGINFO\admin' and 'LAPTOP-07\admin'
    # are two different local accounts that happen to share a name, so merging
    # them would be a regression — one baseline averaging unrelated actors, the
    # exact defect that makes `root` useless today. Those keep their prefix
    # until Phase B gives them a proper (account, host) key.
    if _IDENTITY_STRIP_DOMAIN:
        prefix, tail = _account_parts(s)
        if prefix and tail.casefold() not in _IDENTITY_SHARED:
            s = tail

    if _IDENTITY_CASEFOLD:
        s = s.casefold()

    return s or raw


# ── Typed Entity Keys (Phase B) ───────────────────────────────────────────────
#
# Phase A merges spellings of the same account. It does not address the larger
# problem: the entity namespace is flat, so a person, a laptop, a service
# account and an internet stranger are all just strings competing for the same
# keyspace. Measured on the model store and a 3,412-alert sample:
#
#   * 397 of 453 per-entity autoencoders (87.6%) are keyed on an IP address
#   * 103 of 135 named accounts were seen ONLY from a public source IP — they
#     are SSH brute-force username guesses (janya, jesica, kaycie, postgres,
#     zabbix, pi, odoo ...), not employees, and each got its own autoencoder
#   * `root` was ONE baseline for 912 alerts from 16 different public IPs, so
#     sixteen unrelated attackers were averaged into a single "normal" profile
#     and none of them deviated from it
#
# Typed keys split that into five namespaces:
#
#   person:<canonical>            a human being
#   endpoint:<ip|host>            a machine, and userless internal traffic
#   service:<account>@<host>      SYSTEM, LOCAL SERVICE, machine accounts
#   shared:<account>@<host>       root/admin/guest — scoped, because `root` on
#                                 the ATM server is not `root` on the GPU box
#   external:<ip>                 an actor out on the internet
#
# THE DECISIVE RULE: anything presenting from a PUBLIC source IP is an external
# actor, whatever account name it offers, and that takes precedence over every
# other classification. Verified unambiguous on the sample — no named account
# ever appeared from a private source IP (0 of 1,458), so the rule never has to
# adjudicate a genuine employee against it.
#
# This is what keeps attack traffic out of legitimate baselines. The target
# endpoint deliberately does NOT absorb it either: keying a brute-force flood
# to endpoint:CPU-SRV-208 would merely move the poisoning from `root`'s profile
# to the server's, and teach us that being attacked is normal for that server.
# External actors have no history, so they fall through to the global Isolation
# Forest — which is the correct model for them, since it is the one that knows
# what a port scan looks like across the whole estate.

_ENTITY_TYPED = False

# Phase D — see ueba_identity.py. Off by default; populating costs one upsert
# per person: event on the profile-store path, which is why it is a flag and
# not always-on.
_BINDINGS_ENABLED = False
_BINDINGS_RETENTION = 90.0

# Windows built-ins. A trailing "$" is a machine account.
_SERVICE_PREFIXES = {"nt authority", "nt service"}
_SERVICE_TAILS    = {"system", "local service", "network service",
                     "local system", "localsystem"}
_IDENTITY_SERVICE = set()           # plus anything named in the config


def _is_public_ip(addr: str) -> bool:
    """True for a routable internet address. Malformed input is NOT public —
    an unparseable string must never be allowed to reclassify a real person
    as an external attacker."""
    try:
        return not ipaddress.ip_address(str(addr).strip()).is_private
    except ValueError:
        return False


def _is_service_account(name: str) -> bool:
    prefix, tail = _account_parts(name)
    p, t = prefix.casefold(), tail.casefold()
    return (t.endswith("$")
            or p in _SERVICE_PREFIXES
            or t in _SERVICE_TAILS
            or t in _IDENTITY_SERVICE
            or name.strip().casefold() in _IDENTITY_SERVICE)


def _typed_entity(account: str, src_ip: str, host: str) -> str:
    """Classify one event into a typed entity key. See the note above."""
    # 1. External actors first — this outranks any account name presented.
    if src_ip and _is_public_ip(src_ip):
        return f"external:{src_ip}"

    if account:
        # Shared and service accounts are scoped by host, so the host suffix is
        # what disambiguates them and the domain prefix is redundant noise.
        _, tail = _account_parts(account)
        tail = tail.casefold()
        if _is_service_account(account):
            return f"service:{tail}@{host}" if host else f"service:{tail}"
        if tail in _IDENTITY_SHARED:
            return f"shared:{tail}@{host}" if host else f"shared:{tail}"
        return f"person:{canonical_identity(account)}"

    # 2. Userless. A private source IP is one of our own machines.
    if src_ip:
        return f"endpoint:{src_ip}"
    if host:
        return f"endpoint:{host}"
    return "unknown"


def apply_identity_config(config: dict) -> bool:
    """Load `identity_resolution` from ueba_config.yaml into the module state
    above. Idempotent — safe to call from every consumer's startup, and called
    from FeatureExtractor.__init__ for the same reason apply_noise_config() is:
    so the engine, the trainer and the batch preprocessor cannot disagree about
    what an entity is. Returns whether canonicalisation is on.

    Default is OFF. Changing an entity key changes which autoencoder file is
    looked up, so switching this on strands every existing per-entity model
    until the next retrain — the entity falls back to the global model in the
    meantime. It must therefore be turned on as part of a retrain, not on a
    live deployment.
    """
    global _IDENTITY_CANONICALIZE, _IDENTITY_CASEFOLD, _IDENTITY_STRIP_DOMAIN
    global _ENTITY_TYPED, _BINDINGS_ENABLED, _BINDINGS_RETENTION

    block = config.get("identity_resolution", {}) or {}

    _IDENTITY_CANONICALIZE = bool(block.get("canonicalize", False))
    _IDENTITY_CASEFOLD     = bool(block.get("casefold", True))
    _IDENTITY_STRIP_DOMAIN = bool(block.get("strip_domain", True))

    _IDENTITY_ALIASES.clear()
    for alias, target in (block.get("mappings", {}) or {}).items():
        if str(alias).strip() and str(target).strip():
            _IDENTITY_ALIASES[str(alias).strip()] = str(target).strip()

    _IDENTITY_SHARED.clear()
    for acct in (block.get("shared_accounts", []) or []):
        if str(acct).strip():
            _IDENTITY_SHARED.add(str(acct).strip().casefold())

    _IDENTITY_SERVICE.clear()
    for acct in (block.get("service_accounts", []) or []):
        if str(acct).strip():
            _IDENTITY_SERVICE.add(str(acct).strip().casefold())

    # Typed keys imply canonicalisation: person: keys are built from
    # canonical_identity(), so leaving it off would produce person:VGINFO\JINU
    # and person:jinu as two entities and silently undo Phase A. Rather than
    # offer that half-state as a configuration, force it and say so.
    _ENTITY_TYPED = bool(block.get("typed_keys", False))
    if _ENTITY_TYPED and not _IDENTITY_CANONICALIZE:
        _IDENTITY_CANONICALIZE = True
        log.info("typed_keys is on, so canonicalize is forced on with it")

    bcfg = block.get("bindings", {}) or {}
    _BINDINGS_ENABLED = bool(bcfg.get("enabled", False))
    _BINDINGS_RETENTION = float(bcfg.get("retention_days", 90) or 90)
    if _BINDINGS_ENABLED and not _ENTITY_TYPED:
        # Bindings key on person: entities, which only exist under typed keys.
        # Without them every record() would be rejected and the table would
        # stay empty while looking enabled — worse than being off.
        _BINDINGS_ENABLED = False
        log.warning("identity bindings need typed_keys; staying off")
    elif _BINDINGS_ENABLED:
        log.info("Identity bindings ON (retention=%.0fd)", _BINDINGS_RETENTION)

    if _ENTITY_TYPED:
        log.info("Typed entity keys ON (person/endpoint/service/shared/external; "
                 "service_accounts=%d)", len(_IDENTITY_SERVICE))

    if _IDENTITY_CANONICALIZE:
        log.info("Identity canonicalisation ON (casefold=%s strip_domain=%s "
                 "aliases=%d shared_accounts=%d)",
                 _IDENTITY_CASEFOLD, _IDENTITY_STRIP_DOMAIN,
                 len(_IDENTITY_ALIASES), len(_IDENTITY_SHARED))
    return _IDENTITY_CANONICALIZE or _ENTITY_TYPED


# ── Data transfer volume (RFP SN 12 / SN 46) ─────────────────────────────────
#
# The Fortigate events already carry transfer volumes and nothing read them:
# measured on 40,000 live enriched events, context.raw_event.data.sentbyte is
# present on 8,031 and non-zero on 8,029. The RFP plan recorded this as blocked
# on "byte counts added to the events the SIEM forwards" — they are already
# being forwarded.
#
# Deliberately NOT added to the 35-feature vector. Every autoencoder and the
# Isolation Forest were fitted on that exact shape, so a 36th feature would
# invalidate the whole model store. Volume is tracked beside the vector in the
# profile instead, and read at alert time.

_BYTE_FIELDS = (
    ("data.sentbyte",                      "sent"),
    ("data.rcvdbyte",                      "received"),
    ("context.raw_event.data.sentbyte",    "sent"),
    ("context.raw_event.data.rcvdbyte",    "received"),
)


def transfer_bytes(log: dict) -> dict:
    """{'sent': int, 'received': int, 'total': int} for one event.

    Zeros where the event carries no volume, which is most non-firewall
    traffic — the caller must treat 0 as "not reported" rather than "nothing
    transferred", or every Windows logon looks like a quiet link.
    """
    out = {"sent": 0, "received": 0}
    for path, slot in _BYTE_FIELDS:
        if out[slot]:
            continue
        v = get_nested(log, path)
        if v in (None, ""):
            continue
        try:
            n = int(float(v))
        except (TypeError, ValueError):
            continue
        if n > 0:
            out[slot] = n
    out["total"] = out["sent"] + out["received"]
    return out


def resolve_entity(log: dict) -> str:
    """Single source of truth for the UEBA entity (user/host/IP) key.

    Real user identities take priority. Userless network/firewall events are
    keyed by their source IP (``ip:<addr>``) so each internal endpoint becomes
    its own behavioral entity instead of collapsing into one meaningless
    ``"unknown"`` mega-bucket (it previously absorbed ~74% of all events and
    produced a per-user autoencoder that modelled the average of all traffic).
    Falls back to the reporting host, then literal ``"unknown"`` (≈0 events).

    Used by BOTH feature extraction and the profile store so that training-time
    bucketing and runtime AE selection can never diverge. Identity
    canonicalisation and typed classification therefore happen HERE and nowhere
    else — see canonical_identity() and _typed_entity().

    With ``identity_resolution.typed_keys`` on, returns a typed key instead
    (``person:`` / ``endpoint:`` / ``service:`` / ``shared:`` / ``external:``);
    the flat scheme described above is what you get with it off.

    NOTE: object.name on network events is a destination hostname
    (e.g. www.google.com), so it is only accepted as a username for auth events.
    """
    is_auth = (
        get_nested(log, "event_category") == "auth"
        or safe_bool(get_nested(log, "enrich.flags.is_auth_event"))
    )
    user = (
        get_nested(log, "subject.name")
        or get_nested(log, "data.srcuser")
        or get_nested(log, "data.dstuser")
        or get_nested(log, "context.raw_event.data.srcuser")
        or get_nested(log, "context.raw_event.data.dstuser")
        or (get_nested(log, "object.name") if is_auth else None)
    )
    if user and _is_url_junk(user):
        user = None

    # Hoisted above the account branch because typed classification needs all
    # three fields together: the source IP decides whether an account name
    # belongs to a person or to an internet stranger presenting that name.
    src_ip = (
        get_nested(log, "subject.ip")
        or get_nested(log, "data.srcip")
        or get_nested(log, "context.raw_event.data.srcip")
    )
    host = (
        get_nested(log, "host.name")
        or get_nested(log, "agent.name")
        or get_nested(log, "context.raw_event.agent.name")
    )

    if _ENTITY_TYPED:
        return _typed_entity(user or "", src_ip or "", host or "")

    if user:
        # Account names only. The ip:/host: fallbacks below are returned as-is.
        return canonical_identity(user)
    if src_ip:
        return f"ip:{src_ip}"
    return f"host:{host}" if host else "unknown"


# ── Noise Filter ──────────────────────────────────────────────────────────────

# Fortigate rule IDs that represent normal policy enforcement — not behavioral anomalies.
# These fire thousands of times per day on any corporate network and have no
# investigative value for UEBA. Suppress them from alert generation entirely.
_NOISE_SIGNATURE_IDS = {
    "92653",   # RDP logon on SocSRV_15 — normal teammate access
    "67022",   # Non-network local logon — machine account scheduled task noise
    "67028",   # Special privileges assigned to new logon — RDP false positive on SocSRV_15
    "120052",   # Sysmon event1: Process spawned with elevated privileges (SYSTEM — normal Windows behavior)
    "130001",   # Sysmon event3: Termius/mDNS multicast discovery — false positive
    "60107",   # Failed privileged operation (SocSRV_15 chrome.exe noise)
    "81621",   # Fortigate: Multiple high traffic events to same port
    "81620",   # Fortigate: Multiple high traffic events from same destination
    "81619",   # Fortigate: Multiple high traffic events from same source
    "113202",   # MikroTik: L2TP tunnel authenticated
    "81633",   # Fortigate: App passed by firewall
    "81634",   # Fortigate: App blocked by firewall
    "81644",   # Fortigate: Blocked URL (denied category)
}

# Fortigate rule IDs that are low-value but should still be scored
# (kept in training, suppressed from alerts unless score >= 0.95)
_LOW_VALUE_SIGNATURE_IDS = {
    "81612",   # Fortigate: Firewall configuration changes (low severity)
    "81631",   # Fortigate: Firewall pass (low level)
}

_SUPPRESS_SOURCE_IPS = {
    "164.52.194.98",   # engine server — reverse tunnel + rsync traffic
}


def apply_noise_config(config: dict) -> int:
    """Merge operator-managed suppression IDs from ueba_config.yaml
    (`noise_suppression.signature_ids`) into the module-level
    `_NOISE_SIGNATURE_IDS` set, so the YAML is authoritative without a code
    edit. Idempotent — safe to call from every consumer's startup. Returns
    the number of IDs newly added (those not already hard-coded above).

    Without this, the YAML block is documentary only: `is_noise` checks the
    hard-coded set, so IDs added to config never actually suppress anything.
    """
    block = config.get("noise_suppression", {}) or {}

    cfg_ids = block.get("signature_ids", []) or []
    cfg_ids = {str(s).strip() for s in cfg_ids if str(s).strip()}
    new_ids = cfg_ids - _NOISE_SIGNATURE_IDS
    if new_ids:
        _NOISE_SIGNATURE_IDS.update(new_ids)
        log.info("Noise config merged: +%d signature_ids from config (%s)",
                 len(new_ids), ", ".join(sorted(new_ids)))

    # `suppress_source_ips` and `suppress_hostnames_as_users` were documented in
    # ueba_config.yaml but never read — only the hard-coded sets above applied.
    # That is a per-deployment correctness bug, not just untidiness: the baked-in
    # value is the LAB engine's IP, so at a customer site the wrong address was
    # suppressed while the local UEBA server's own sync/SSH traffic scored as
    # alerts against its own estate. Merging them here makes the YAML
    # authoritative, so install_ueba.sh can set the right IP per site.
    cfg_ips = block.get("suppress_source_ips", []) or []
    cfg_ips = {str(v).strip() for v in cfg_ips if str(v).strip()}
    new_ips = cfg_ips - _SUPPRESS_SOURCE_IPS
    if new_ips:
        _SUPPRESS_SOURCE_IPS.update(new_ips)
        log.info("Noise config merged: +%d suppress_source_ips (%s)",
                 len(new_ips), ", ".join(sorted(new_ips)))

    cfg_hosts = block.get("suppress_hostnames_as_users", []) or []
    cfg_hosts = {str(v).strip() for v in cfg_hosts if str(v).strip()}
    new_hosts = cfg_hosts - _SUPPRESS_AGENT_NAMES
    if new_hosts:
        _SUPPRESS_AGENT_NAMES.update(new_hosts)
        log.info("Noise config merged: +%d suppress_hostnames_as_users (%s)",
                 len(new_hosts), ", ".join(sorted(new_hosts)))

    return len(new_ids) + len(new_ips) + len(new_hosts)

# Known internal agents/hostnames that should never appear as alert subjects.
_SUPPRESS_AGENT_NAMES = {
    "DESKTOP-QO9VL7M$",   # Windows machine account
    "NT AUTHORITY\\NETWOR",   # Windows NETWORK SERVICE account
    "NT AUTHORITY\\SYSTEM",   # Windows SYSTEM account — Defender/scheduler noise
    "cybersentinel-manager",
    "cybersentinel-manage",
    "Centos7Trial",
    "164.52.194.98",
}

def is_noise(log: dict) -> bool:
    """
    Returns True if this event should be completely skipped for alert generation.
    These are high-volume, low-value firewall policy events that are normal
    behaviour on any corporate network and should not trigger UEBA alerts.

    Note: These events are still used during TRAINING so the model learns
    what normal network traffic looks like. They are only filtered at the
    alert output stage.
    """
    sig_id = str(get_nested(log, "security.signature_id") or "")
    if sig_id in _NOISE_SIGNATURE_IDS:
        return True

    # Suppress self-monitoring web access-log noise: health-check / probe
    # requests against the platform's own internal API endpoints (paths under
    # "/api/", e.g. /api/stats, /api/health, /api/stream). These fire the web
    # access-log rules (31101 "Web server 400 error code", 31151 "Multiple 400
    # errors from same source") in huge volume — the URL path gets parsed as the
    # "user" and the sheer frequency trips high_frequency/highly_anomalous — but
    # they carry no security signal (it's the monitoring talking to itself).
    # Scoped to /api/ paths only, so real web-attack 4xx on app routes (login,
    # admin, wp-admin, …) is still detected.
    if sig_id in ("31101", "31151"):
        req_path = str(get_nested(log, "object.name") or
                       get_nested(log, "object.id") or "").lower()
        if req_path.startswith("/api/"):
            return True

    # Also suppress if no anomaly flags are set AND event is pure Fortigate
    # network allow/pass with anomaly_count == 0
    source = str(get_nested(log, "context.source") or "")
    if "fortigate" in source.lower():
        action = str(get_nested(log, "event_action") or "").lower()
        anomaly_count = get_nested(log, "enrich.anomalies.anomaly_count") or 0
        if action in ("allow", "connect") and int(anomaly_count) == 0:
            return True

    # Suppress Windows machine accounts (name ending in $) — never real users
    user_name = str(get_nested(log, "subject.name") or "")
    if user_name.endswith("$"):
        return True

    # Suppress mDNS multicast traffic (224.x.x.x) — Termius, printers, etc.
    subject_ip = str(get_nested(log, "subject.ip") or "")
    if subject_ip.startswith("224."):
        return True
    # Suppress port 5353 (mDNS) — never security relevant
    subject_port = str(get_nested(log, "subject.port") or "")
    object_port  = str(get_nested(log, "object.port") or "")
    if subject_port == "5353" and object_port == "5353":
        return True

    # Suppress engine server's own IP — tunnel/rsync traffic
    src_ip = str(get_nested(log, "enrich.geo.src_ip") or
                 get_nested(log, "context.raw_event.data.srcip") or
                 get_nested(log, "source.ip") or "")
    if src_ip in _SUPPRESS_SOURCE_IPS:
        return True

    dst_ip = str(get_nested(log, "context.raw_event.data.dstip") or
                 get_nested(log, "destination.ip") or "")
    if dst_ip in _SUPPRESS_SOURCE_IPS:
        return True

    # Suppress events with no resolvable user identity
    user = str(get_nested(log, "subject.name") or "")
    if not user or user.lower() in ("none", "null", ""):
        anomaly_count = int(get_nested(log, "enrich.anomalies.anomaly_count") or 0)
        if anomaly_count == 0:
            return True

    candidate_names = {
        str(get_nested(log, "subject.name") or ""),
        str(get_nested(log, "subject.ip") or ""),
        str(get_nested(log, "object.name") or ""),
        str(get_nested(log, "host.name") or ""),
        str(get_nested(log, "host.ip") or ""),
        str(get_nested(log, "context.raw_event.data.dstuser") or ""),
        str(get_nested(log, "context.raw_event.data.srcuser") or ""),
    }
    if candidate_names & _SUPPRESS_AGENT_NAMES:
        return True

    # Suppress Windows machine accounts (name ending in $) — never real users
    user_name = str(get_nested(log, "subject.name") or "")
    if user_name.endswith("$"):
        return True

    # Suppress mDNS multicast traffic (224.x.x.x) — Termius, printers, etc.
    subject_ip = str(get_nested(log, "subject.ip") or "")
    if subject_ip.startswith("224."):
        return True
    # Suppress port 5353 (mDNS) — never security relevant
    subject_port = str(get_nested(log, "subject.port") or "")
    object_port  = str(get_nested(log, "object.port") or "")
    if subject_port == "5353" and object_port == "5353":
        return True

    # Suppress engine server's own IP — tunnel/rsync traffic
    src_ip = str(get_nested(log, "enrich.geo.src_ip") or
                 get_nested(log, "context.raw_event.data.srcip") or
                 get_nested(log, "source.ip") or "")
    if src_ip in _SUPPRESS_SOURCE_IPS:
        return True

    dst_ip = str(get_nested(log, "context.raw_event.data.dstip") or
                 get_nested(log, "destination.ip") or "")
    if dst_ip in _SUPPRESS_SOURCE_IPS:
        return True

    # Suppress events with no resolvable user identity
    user = str(get_nested(log, "subject.name") or "")
    if not user or user.lower() in ("none", "null", ""):
        anomaly_count = int(get_nested(log, "enrich.anomalies.anomaly_count") or 0)
        if anomaly_count == 0:
            return True

    return False


# ── Feature Extractor ─────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Converts a single enriched log (Python dict) into a fixed-size
    numpy feature vector of shape (feature_dim,).

    This class is used both:
      - During offline batch preprocessing (training data)
      - During real-time streaming (one log at a time)

    The feature ordering is FIXED and documented below.
    If you add new features, append them at the end and update feature_dim
    in ueba_config.yaml.

    Feature index map (35 features total):
    ─────────────────────────────────────
    [0]  temporal.hour              0-23
    [1]  temporal.day_of_week       0-6
    [2]  temporal.is_weekend        0/1
    [3]  temporal.is_business_hours 0/1
    [4]  temporal.is_night_shift    0/1
    [5]  flags.is_auth_event        0/1
    [6]  flags.is_network_event     0/1
    [7]  flags.is_file_event        0/1
    [8]  flags.is_process_event     0/1
    [9]  anomalies.is_brute_force          0/1
    [10] anomalies.is_port_scan            0/1
    [11] anomalies.is_tor                  0/1
    [12] anomalies.is_malicious_ip         0/1
    [13] anomalies.is_impossible_travel    0/1
    [14] anomalies.is_lateral_movement     0/1
    [15] anomalies.is_data_exfiltration    0/1
    [16] anomalies.is_after_hours          0/1
    [17] anomalies.is_high_frequency       0/1
    [18] counters.src_ip_5m         integer
    [19] counters.src_ip_1h         integer
    [20] counters.user_1h           integer
    [21] counters.host_1h           integer
    [22] behavioral.unique_destinations_1h integer
    [23] behavioral.unique_ports_1h        integer
    [24] behavioral.recent_failures_5m     integer
    [25] geo.distance_km            float (0 if unknown)
    [26] geo.cross_border           0/1
    [27] geo.cross_continent        0/1
    [28] risk_score                 0-100
    [29] rule.level                 0-15
    [30] network_intel.is_cloud     0/1
    [31] event_category             0-10 (encoded)
    [32] event_outcome              0-2  (encoded)
    [33] traffic_direction          0-3  (encoded)
    [34] user_deviation_baseline    float (from profile store, 0 if new user)
    """

    FEATURE_DIM = 35

    # Category encodings (must match ueba_config.yaml)
    EVENT_CATEGORY_MAP = {
        "auth": 0, "network": 1, "process": 2, "file": 3,
        "dns": 4, "web": 5, "malware": 6, "cloud": 7,
        "policy": 8, "system": 9, "unknown": 10,
    }
    EVENT_OUTCOME_MAP = {
        "success": 0, "failure": 1, "unknown": 2,
    }
    TRAFFIC_DIRECTION_MAP = {
        "inbound": 0, "outbound": 1, "internal": 2, "unknown": 3,
    }

    def __init__(self, config: dict, profile_store=None):
        self.config = config
        self.profile_store = profile_store  # optional, used for feature [34]
        self.null_fill = config["preprocessing"].get("null_fill_value", 0.0)
        # Honor operator-managed suppression IDs from the YAML config. Runs
        # here so every consumer (engine, trainer, batch preprocessor) that
        # builds a FeatureExtractor picks them up — no per-call config plumbing.
        apply_noise_config(config)
        # Same reasoning, same place: the entity key must be identical in the
        # trainer and at runtime or the AE lookup misses. See
        # apply_identity_config() for why this defaults to off.
        apply_identity_config(config)

    def extract(self, log: dict) -> np.ndarray:
        """
        Extract feature vector from one enriched log dict.
        Returns numpy array of shape (FEATURE_DIM,) with dtype float32.
        Never raises — missing fields become null_fill_value (0.0).
        """
        vec = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # ── [0-4] Temporal ────────────────────────────────────────────────────
        # Support both schema versions: hour vs hour_of_day, day_of_week (int) vs day name
        hour = get_nested(log, "enrich.temporal.hour") or get_nested(log, "enrich.temporal.hour_of_day")
        vec[0]  = safe_float(hour, 0.0)
        dow = get_nested(log, "enrich.temporal.day_of_week")
        if isinstance(dow, str):
            dow_map = {"Monday":0,"Tuesday":1,"Wednesday":2,"Thursday":3,"Friday":4,"Saturday":5,"Sunday":6}
            dow = dow_map.get(dow, 0)
        vec[1]  = safe_float(dow, 0.0)
        vec[2]  = safe_bool(get_nested(log,  "enrich.temporal.is_weekend"))
        vec[3]  = safe_bool(get_nested(log,  "enrich.temporal.is_business_hours"))
        # is_night_shift (old schema) or is_night (new schema)
        vec[4]  = safe_bool(get_nested(log, "enrich.temporal.is_night_shift") or get_nested(log, "enrich.temporal.is_night"))

        # ── [5-8] Event flags ─────────────────────────────────────────────────
        vec[5]  = safe_bool(get_nested(log, "enrich.flags.is_auth_event"))
        vec[6]  = safe_bool(get_nested(log, "enrich.flags.is_network_event"))
        vec[7]  = safe_bool(get_nested(log, "enrich.flags.is_file_event"))
        vec[8]  = safe_bool(get_nested(log, "enrich.flags.is_process_event"))

        # ── [9-17] Anomaly flags ──────────────────────────────────────────────
        vec[9]  = safe_bool(get_nested(log, "enrich.anomalies.is_brute_force"))
        vec[10] = safe_bool(get_nested(log, "enrich.anomalies.is_port_scan"))
        # is_tor (old schema) or is_tor_traffic (new schema)
        vec[11] = safe_bool(get_nested(log, "enrich.anomalies.is_tor") or get_nested(log, "enrich.anomalies.is_tor_traffic"))
        # is_malicious_ip (old) — check threat_detected in new schema
        vec[12] = safe_bool(get_nested(log, "enrich.anomalies.is_malicious_ip") or get_nested(log, "enrich.network_intel.threat_detected"))
        vec[13] = safe_bool(get_nested(log, "enrich.anomalies.is_impossible_travel"))
        vec[14] = safe_bool(get_nested(log, "enrich.anomalies.is_lateral_movement"))
        # is_data_exfiltration (old) or is_data_exfil (new)
        vec[15] = safe_bool(get_nested(log, "enrich.anomalies.is_data_exfiltration") or get_nested(log, "enrich.anomalies.is_data_exfil"))
        vec[16] = safe_bool(get_nested(log, "enrich.anomalies.is_after_hours"))
        vec[17] = safe_bool(get_nested(log, "enrich.anomalies.is_high_frequency") or get_nested(log, "enrich.anomalies.is_high_frequency"))

        # ── [18-21] Rolling counters ──────────────────────────────────────────
        # New schema only has 5m counters; estimate 1h as 5m * 12 if 1h missing
        src_ip_5m  = safe_float(get_nested(log, "enrich.counters.src_ip_5m"))
        src_ip_1h  = get_nested(log, "enrich.counters.src_ip_1h")
        vec[18] = src_ip_5m
        vec[19] = safe_float(src_ip_1h) if src_ip_1h is not None else src_ip_5m * 12
        user_1h    = get_nested(log, "enrich.counters.user_1h")
        vec[20] = safe_float(user_1h) if user_1h is not None else 0.0
        host_5m    = safe_float(get_nested(log, "enrich.counters.host_5m"))
        host_1h    = get_nested(log, "enrich.counters.host_1h")
        vec[21] = safe_float(host_1h) if host_1h is not None else host_5m * 12

        # ── [22-24] Behavioral ────────────────────────────────────────────────
        vec[22] = safe_float(get_nested(log, "enrich.behavioral.unique_destinations_1h"))
        vec[23] = safe_float(get_nested(log, "enrich.behavioral.unique_ports_1h"))
        vec[24] = safe_float(get_nested(log, "enrich.behavioral.recent_failures_5m"))

        # ── [25-27] Geo ───────────────────────────────────────────────────────
        vec[25] = safe_float(get_nested(log, "enrich.geo.distance_km"))  # 0 if missing
        # cross_border/cross_continent: old schema top-level, new schema in anomalies
        vec[26] = safe_bool(get_nested(log, "enrich.geo.cross_border") or get_nested(log, "enrich.anomalies.cross_border"))
        vec[27] = safe_bool(get_nested(log, "enrich.geo.cross_continent") or get_nested(log, "enrich.anomalies.cross_continent"))

        # ── [28-29] Risk ──────────────────────────────────────────────────────
        vec[28] = safe_float(get_nested(log, "enrich.risk_score"))
        # rule.level: old schema top-level, new schema in context.raw_event.rule.level
        rule_level = (
            get_nested(log, "rule.level")
            or get_nested(log, "security.severity")
            or get_nested(log, "context.raw_event.rule.level")
        )
        vec[29] = safe_float(rule_level)

        # ── [30] Network intel ────────────────────────────────────────────────
        is_cloud = get_nested(log, "enrich.network_intel.cloud_provider")
        vec[30] = 0.0 if (is_cloud is None or is_cloud == "") else 1.0

        # ── [31] Event category (encoded) ─────────────────────────────────────
        cat = str(get_nested(log, "event_category", "unknown")).lower()
        vec[31] = float(self.EVENT_CATEGORY_MAP.get(cat, 10))

        # ── [32] Event outcome (encoded) ──────────────────────────────────────
        outcome = str(get_nested(log, "event_outcome", "unknown")).lower()
        vec[32] = float(self.EVENT_OUTCOME_MAP.get(outcome, 2))

        # ── [33] Traffic direction (encoded) ──────────────────────────────────
        # Old schema: enrich.classification.traffic_direction
        # New schema: enrich.normalization.direction (inbound/outbound) or network.direction
        direction = str(
            get_nested(log, "enrich.classification.traffic_direction")
            or get_nested(log, "enrich.normalization.direction")
            or get_nested(log, "network.direction")
            or "unknown"
        ).lower()
        # Normalize new schema values to old schema encoding
        direction = direction.replace("outgoing", "outbound").replace("incoming", "inbound")
        vec[33] = float(self.TRAFFIC_DIRECTION_MAP.get(direction, 3))

        # ── [34] User baseline deviation ──────────────────────────────────────
        # How different is this event from this user's historical average?
        # 0.0 if user is new / profile store not available
        if self.profile_store:
            user = (
                get_nested(log, "subject.name")
                or get_nested(log, "data.dstuser")
                or get_nested(log, "agent.name")
                or "unknown"
            )
            vec[34] = self.profile_store.get_baseline_deviation(user, vec)
        else:
            vec[34] = 0.0

        return vec

    def extract_metadata(self, log: dict) -> dict:
        """
        Extract non-numeric metadata from a log for storing alongside
        the feature vector (used by FAISS metadata store and output writer).
        Supports both the CyberSentinel SIEM schema (subject/object) and the legacy
        schema (data.srcuser).
        """
        # Entity (user / host / source-IP) key — single source of truth.
        # Userless firewall/network events resolve to ip:<src> rather than the
        # old "unknown" mega-bucket. See resolve_entity() for the full policy.
        user = resolve_entity(log)

        # Source IP: try all known locations
        src_ip = (
            get_nested(log, "subject.ip")
            or get_nested(log, "data.srcip")
            or get_nested(log, "context.raw_event.data.srcip")
            or ""
        )

        # Destination IP
        dst_ip = (
            get_nested(log, "object.ip")
            or get_nested(log, "data.dstip")
            or get_nested(log, "context.raw_event.data.dstip")
            or ""
        )

        # Destination port
        dst_port = (
            get_nested(log, "object.port")
            or get_nested(log, "data.dstport")
            or get_nested(log, "context.raw_event.data.dstport")
            or ""
        )

        # Agent info: try both schema versions
        agent_name = (
            get_nested(log, "host.name")
            or get_nested(log, "agent.name")
            or get_nested(log, "context.raw_event.agent.name")
            or ""
        )
        agent_ip = (
            get_nested(log, "host.ip")
            or get_nested(log, "agent.ip")
            or get_nested(log, "context.raw_event.agent.ip")
            or ""
        )

        # Rule info
        rule_id   = get_nested(log, "security.signature_id") or get_nested(log, "rule.id", "")
        rule_desc = get_nested(log, "security.signature")    or get_nested(log, "rule.description", "")
        rule_level = (
            get_nested(log, "security.severity")
            or get_nested(log, "rule.level")
            or get_nested(log, "context.raw_event.rule.level")
            or 0
        )

        # Country
        country_src = (
            get_nested(log, "enrich.geo.src.country")
            or get_nested(log, "enrich.geo.src_country")
            or ""
        )

        # Protocol and direction
        protocol  = get_nested(log, "network.protocol") or get_nested(log, "enrich.normalization.protocol") or ""
        direction = (
            get_nested(log, "network.direction")
            or get_nested(log, "enrich.classification.traffic_direction")
            or get_nested(log, "context.raw_event.data.action")
            or ""
        )

        return {
            "event_id":       get_nested(log, "event_id", ""),
            "event_time":     get_nested(log, "event_time", ""),
            "user":           user,
            "src_ip":         src_ip,
            "dst_ip":         dst_ip,
            "dst_port":       str(dst_port) if dst_port else "",
            "agent_name":     agent_name,
            "agent_ip":       agent_ip,
            "agent_role":     get_nested(log, "host.type") or get_nested(log, "context.raw_event.agent.role", ""),
            "event_category": get_nested(log, "event_category", "unknown"),
            "event_action":   get_nested(log, "event_action", ""),
            "event_outcome":  get_nested(log, "event_outcome", "unknown"),
            "rule_id":        rule_id,
            "rule_desc":      rule_desc,
            "rule_level":     int(rule_level) if rule_level else 0,
            "risk_score":     get_nested(log, "enrich.risk_score", 0),
            "country_src":    country_src,
            "protocol":       protocol.upper() if protocol else "",
            "direction":      direction,
            "is_internal":    get_nested(log, "enrich.classification.is_internal_traffic") or False,
            "anomaly_count":  get_nested(log, "enrich.anomalies.anomaly_count", 0),
            "schema_version": get_nested(log, "schema_version", ""),
            "fingerprint":    get_nested(log, "enrich.fingerprint", ""),
            # Noise flag — engine should suppress alert output for these events.
            # They are still scored and used for FAISS/profile updates.
            "is_noise":       is_noise(log),
        }


# ── User Profile Store (SQLite) ───────────────────────────────────────────────

class UserProfileStore:
    """
    Maintains per-user behavioral baselines in SQLite.
    Used to compute feature [34] — how much does this event deviate
    from this user's historical norm?

    Schema:
        users table:
            username        TEXT PRIMARY KEY
            avg_hour        REAL    (average login hour)
            avg_risk        REAL    (average risk score)
            avg_events_1h   REAL    (average events per hour)
            seen_countries  TEXT    (JSON list)
            seen_agents     TEXT    (JSON list)
            total_events    INTEGER
            first_seen      TEXT
            last_seen       TEXT
    """

    # ── Baseline windowing (RFP 22) ──────────────────────────────────────────
    # "events" is the original behaviour: a fixed-alpha EWMA. Its window is
    # measured in EVENTS, not time — a busy entity's baseline turns over in
    # minutes while a quiet entity's spans months, and `baseline_window_days`
    # had no effect on either because nothing read it.
    #
    # "time" makes the window a real, configurable period. Statistics are
    # decayed by ELAPSED TIME before each new event is folded in, so the
    # effective window is `baseline_window_days` of wall clock regardless of how
    # active the entity is, and categorical values (countries, agents) age out
    # instead of being remembered forever.
    #
    # The default stays "events" deliberately. Switching changes the
    # distribution of feature [34], which the Isolation Forest and the
    # autoencoders were fitted against — so it must be followed by a retrain,
    # and flipping it silently mid-week would score live traffic against models
    # trained on a differently-computed feature.
    MODE_EVENTS = "events"
    MODE_TIME = "time"

    def __init__(self, db_path: str, window_days: float = 21.0,
                 mode: str = MODE_EVENTS, legacy_alpha: float = 0.01):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.db_path = db_path
        self._bindings_store = None
        self.window_days = max(0.5, float(window_days or 21.0))
        self.mode = mode if mode in (self.MODE_EVENTS, self.MODE_TIME) else self.MODE_EVENTS
        self.legacy_alpha = float(legacy_alpha or 0.01)
        self._init_schema()
        self._migrate()
        log.info("Profile store opened: %s (baseline mode=%s, window=%.1fd)",
                 db_path, self.mode, self.window_days)

    def _migrate(self):
        """Add the decayed-weight column if this database predates it.

        Rows keep weight 0 here and are seeded lazily by _seed_weight() on their
        first time-mode update. Seeding at migration would be wrong: "events"
        mode never maintains the column afterwards, so a value written now would
        be stale by the time the mode actually changed.
        """
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(users)")}
        if "weight" not in cols:
            self.conn.execute(
                "ALTER TABLE users ADD COLUMN weight REAL DEFAULT 0.0")
            self.conn.commit()
            log.info("Profile store migrated: added decayed-weight column")

        # Transfer-volume baseline (SN 12 / SN 46).
        #
        # Added ONLY here, never in CREATE TABLE, and only after the weight
        # column above. This method reads the users row positionally
        # (existing[8] is last_seen, existing[9] is weight), so a column added
        # to CREATE TABLE lands at a different index on a fresh database than
        # on a migrated one and every positional read silently returns the
        # wrong field. Appending through migration in a fixed order keeps the
        # layout identical everywhere.
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(users)")}
        for col in ("bytes_events", "bytes_total", "bytes_max"):
            if col not in cols:
                self.conn.execute(
                    "ALTER TABLE users ADD COLUMN %s INTEGER DEFAULT 0" % col)
                self.conn.commit()
                log.info("Profile store migrated: added %s", col)

        # Where each entity has actually been seen (SN 19).
        #
        # A separate table, not more columns on `users`, for two reasons. The
        # positional-read hazard above is one. The other is that this is
        # populated from ALL traffic while every column on `users` is populated
        # from alerts only — `seen_countries` and `seen_agents` there answer
        # "which countries has this entity alerted from before", which is a
        # different question and, at a 0.02% alert rate, one whose answer is
        # almost always "none". Scoring novelty off those would have reported
        # nearly every event as a first-time country.
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS entity_presence (
                username   TEXT    NOT NULL,
                kind       TEXT    NOT NULL,
                value      TEXT    NOT NULL,
                events     INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT,
                last_seen  TEXT,
                PRIMARY KEY (username, kind, value)
            )
        """)
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_presence_entity "
            "ON entity_presence(username, kind)")
        self.conn.commit()

    def _seed_weight(self, first_seen, last_seen, total_events):
        """Effective weight to credit an entity that has no decayed weight yet.

        Rows written in "events" mode never maintain `weight`, so the first
        time-mode update would otherwise see w_prev = 0 and throw the entity's
        entire accumulated baseline away — every entity in the estate would
        restart from its next single event, which is precisely the opposite of
        what a behavioural baseline is for.

        The right value is the weight this entity WOULD have reached at
        saturation: its observed event rate multiplied by the window. That
        respects the existing baseline without freezing it.
        """
        try:
            n = float(total_events or 0)
            if n <= 0:
                return 0.0
            a = datetime.fromisoformat(str(first_seen).replace("Z", "+00:00"))
            b = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
            if a.tzinfo is None:
                a = a.replace(tzinfo=timezone.utc)
            if b.tzinfo is None:
                b = b.replace(tzinfo=timezone.utc)
            span_days = max(0.5, (b - a).total_seconds() / 86400.0)
            rate_per_day = n / span_days
            return float(min(n, rate_per_day * self.window_days))
        except (ValueError, TypeError, AttributeError):
            # Unparseable timestamps: fall back to the raw count, which is the
            # legacy scheme's own notion of accumulated weight.
            return float(total_events or 0)

    def _decay(self, last_seen_iso, now_dt):
        """exp(-elapsed / window) — how much of the old statistic survives."""
        if not last_seen_iso:
            return 1.0
        try:
            prev = datetime.fromisoformat(str(last_seen_iso).replace("Z", "+00:00"))
            if prev.tzinfo is None:
                prev = prev.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return 1.0
        dt_days = max(0.0, (now_dt - prev).total_seconds() / 86400.0)
        return float(math.exp(-dt_days / self.window_days))

    def _age_categoricals(self, raw, value, now_dt, cap):
        """Keep {value: last_seen} within the window, dropping stale entries.

        Tolerates the legacy list form, so a database written by the previous
        version keeps working: its values are treated as seen now, then age out
        naturally from here.
        """
        try:
            data = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            data = {}
        if isinstance(data, list):
            data = {v: now_dt.isoformat() for v in data if v}
        if value:
            data[value] = now_dt.isoformat()
        cutoff = now_dt - timedelta(days=self.window_days)
        kept = {}
        for v, seen in data.items():
            try:
                d = datetime.fromisoformat(str(seen).replace("Z", "+00:00"))
                if d.tzinfo is None:
                    d = d.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
            if d >= cutoff:
                kept[v] = seen
        if len(kept) > cap:
            kept = dict(sorted(kept.items(), key=lambda kv: kv[1], reverse=True)[:cap])
        return kept

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username        TEXT PRIMARY KEY,
                avg_hour        REAL    DEFAULT 12.0,
                avg_risk        REAL    DEFAULT 0.0,
                avg_events_1h   REAL    DEFAULT 0.0,
                seen_countries  TEXT    DEFAULT '[]',
                seen_agents     TEXT    DEFAULT '[]',
                total_events    INTEGER DEFAULT 0,
                first_seen      TEXT    DEFAULT '',
                last_seen       TEXT    DEFAULT ''
            )
        """)
        self.conn.commit()

    def _bindings(self):
        """Lazily open the binding table in this same database. Opened on
        first use rather than in __init__ so that a deployment with the flag
        off never creates the table at all."""
        if self._bindings_store is None:
            import ueba_identity
            # Share this store's connection — a second connection to the same
            # file deadlocks mid-transaction. See IdentityBindings.__init__.
            self._bindings_store = ueba_identity.IdentityBindings(
                conn=self.conn, retention_days=_BINDINGS_RETENTION)
        return self._bindings_store

    def update(self, log: dict, feature_vec: np.ndarray):
        """Update a user's profile with data from a new log event."""
        # Same entity key as feature extraction so training-eligibility (which
        # is gated off this profile store) matches the runtime AE bucket.
        user = resolve_entity(log)

        # Phase D: note which host/address this person was seen on. Additive —
        # a separate table, read by nothing in the scoring path yet. Must never
        # be able to break profiling, so it is fully contained.
        if _BINDINGS_ENABLED:
            try:
                self._bindings().record_event(user, log, get_nested)
            except Exception as e:
                _log.debug("identity binding skipped: %s", e)

        existing = self.conn.execute(
            "SELECT * FROM users WHERE username = ?", (user,)
        ).fetchone()

        now = datetime.now(timezone.utc).isoformat()
        hour        = float(feature_vec[0])
        risk        = float(feature_vec[28])
        events_1h   = float(feature_vec[20])
        country     = event_country(log)
        agent       = event_host(log)

        if existing is None:
            # New user — insert baseline
            self.conn.execute("""
                INSERT INTO users
                    (username, avg_hour, avg_risk, avg_events_1h,
                     seen_countries, seen_agents, total_events, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
            """, (
                user, hour, risk, events_1h,
                json.dumps([country] if country else []),
                json.dumps([agent] if agent else []),
                now, now,
            ))
        elif self.mode == self.MODE_TIME:
            # ── Rolling time window (RFP 22) ────────────────────────────────
            # Decay the accumulated statistic by elapsed time, then fold the new
            # event in with unit weight. The running weight saturates at roughly
            # (event rate x window), so the effective memory is the configured
            # PERIOD rather than a fixed number of events — correct for a busy
            # server and a once-a-week account alike.
            now_dt = datetime.now(timezone.utc)
            decay = self._decay(existing[8], now_dt)        # last_seen column
            w_prev = float(existing[9] or 0.0)              # weight column
            if w_prev <= 0.0:
                # First time-mode update for a row written in "events" mode.
                w_prev = self._seed_weight(existing[7], existing[8], existing[6])
            w = w_prev * decay + 1.0

            def _blend(prev, new):
                """Time-decayed weighted mean: the surviving share of the old
                statistic, plus the new event carrying unit weight."""
                return (float(prev) * w_prev * decay + new) / w

            avg_hour      = _blend(existing[1], hour)
            avg_risk      = _blend(existing[2], risk)
            avg_events_1h = _blend(existing[3], events_1h)

            countries = self._age_categoricals(existing[4], country, now_dt, 50)
            agents    = self._age_categoricals(existing[5], agent,   now_dt, 20)

            self.conn.execute("""
                UPDATE users SET
                    avg_hour      = ?,
                    avg_risk      = ?,
                    avg_events_1h = ?,
                    seen_countries = ?,
                    seen_agents    = ?,
                    total_events   = ?,
                    last_seen      = ?,
                    weight         = ?
                WHERE username = ?
            """, (
                avg_hour, avg_risk, avg_events_1h,
                json.dumps(countries), json.dumps(agents),
                existing[6] + 1, now, w, user,
            ))
        else:
            # Existing user — exponential moving average update
            # alpha=0.01 means new events have small influence on baseline
            # (keeps baseline stable, not skewed by a single attack burst)
            alpha = self.legacy_alpha
            n = existing[6]  # total_events column
            avg_hour      = (1 - alpha) * existing[1]      + alpha * hour
            avg_risk      = (1 - alpha) * existing[2]      + alpha * risk
            avg_events_1h = (1 - alpha) * existing[3]      + alpha * events_1h

            countries = json.loads(existing[4])
            if isinstance(countries, dict):
                countries = list(countries)
            if country and country not in countries:
                countries.append(country)
                if len(countries) > 50:       # cap to 50 unique countries
                    countries = countries[-50:]

            agents = json.loads(existing[5])
            if isinstance(agents, dict):
                agents = list(agents)
            if agent and agent not in agents:
                agents.append(agent)
                if len(agents) > 20:
                    agents = agents[-20:]

            self.conn.execute("""
                UPDATE users SET
                    avg_hour      = ?,
                    avg_risk      = ?,
                    avg_events_1h = ?,
                    seen_countries = ?,
                    seen_agents    = ?,
                    total_events   = ?,
                    last_seen      = ?
                WHERE username = ?
            """, (
                avg_hour, avg_risk, avg_events_1h,
                json.dumps(countries), json.dumps(agents),
                n + 1, now, user,
            ))

        if xfer > 0:
            self.conn.execute(
                """UPDATE users
                      SET bytes_events = COALESCE(bytes_events, 0) + 1,
                          bytes_total  = COALESCE(bytes_total, 0) + ?,
                          bytes_max    = MAX(COALESCE(bytes_max, 0), ?)
                    WHERE username = ?""",
                (xfer, xfer, user))

        self.conn.commit()

    def get_baseline_deviation(self, user: str, feature_vec: np.ndarray) -> float:
        """
        Return how much this event deviates from the user's baseline.
        Returns a 0.0-1.0 float. 0 = perfectly normal, 1 = extremely unusual.
        Returns 0.0 for unknown users.
        """
        row = self.conn.execute(
            "SELECT avg_hour, avg_risk, avg_events_1h FROM users WHERE username = ?",
            (user,)
        ).fetchone()

        if row is None:
            return 0.0   # new user, no baseline yet

        avg_hour, avg_risk, avg_events_1h = row
        current_hour  = float(feature_vec[0])
        current_risk  = float(feature_vec[28])
        current_ev_1h = float(feature_vec[20])

        # Normalized absolute deviations for each dimension
        hour_dev  = abs(current_hour  - avg_hour)  / 23.0        # max range = 23
        risk_dev  = abs(current_risk  - avg_risk)  / 100.0       # max range = 100
        ev_dev    = abs(current_ev_1h - avg_events_1h) / max(avg_events_1h + 1, 10)

        # Weighted average deviation
        deviation = (0.4 * hour_dev) + (0.4 * risk_dev) + (0.2 * ev_dev)
        return float(min(deviation, 1.0))

    def record_presence(self, user: str, log: dict) -> dict:
        """Note where an entity was seen, and say whether it is somewhere new.

        Called for EVERY event, before the alert gate — the same reasoning as
        record_transfer. "This account has never logged in from this country
        before" is only a meaningful statement if the set of countries it HAS
        logged in from was built from all of its traffic. Built from alerts
        alone the claim inverts: it would announce a first-time country on
        almost every alert, because the alert-derived set is nearly empty.

        Returns a novelty verdict for this event, so the caller gets it from
        the write it is already doing rather than reading back afterwards:

            {"country": {"value": "RU", "first_time": True, "distinct": 3},
             "agent":   {"value": "...", "first_time": False, "distinct": 2}}

        Kinds with no value in this event are simply absent. Never raises: a
        novelty signal is worth less than the pipeline it would take down.
        """
        out: dict = {}
        if not user or user == "unknown":
            return out
        try:
            country = event_country(log)
            agent   = event_host(log)
            now     = datetime.now(timezone.utc).isoformat()

            for kind, value in (("country", country), ("agent", agent)):
                value = str(value).strip()
                if not value:
                    continue
                # One statement per kind. RETURNING gives us the post-increment
                # count, so events == 1 means this event is the first sighting;
                # a separate SELECT would both cost more and race.
                row = self.conn.execute(
                    """INSERT INTO entity_presence
                           (username, kind, value, events, first_seen, last_seen)
                       VALUES (?, ?, ?, 1, ?, ?)
                       ON CONFLICT(username, kind, value) DO UPDATE SET
                           events    = events + 1,
                           last_seen = excluded.last_seen
                       RETURNING events""",
                    (user, kind, value, now, now)).fetchone()
                seen = int(row[0]) if row else 1
                first_time = (seen == 1)

                # Only counted when it matters: on a first sighting, to decide
                # whether this entity's spread is still narrow enough for
                # novelty to mean anything. Every other event skips the count.
                distinct = 0
                if first_time:
                    distinct = int(self.conn.execute(
                        "SELECT COUNT(*) FROM entity_presence "
                        "WHERE username = ? AND kind = ?",
                        (user, kind)).fetchone()[0] or 0)
                    # The entity's very first event is not a novel location —
                    # everything is new to an entity with no history at all,
                    # and reporting that would flag every new account's first
                    # appearance as an anomalous one.
                    if distinct <= 1 or distinct > _PRESENCE_NOVELTY_CAP:
                        first_time = False

                # The engine asks "how many hosts has this account been used
                # on" for every event, to decide credential sharing (SN 15).
                # Updated here, where a new row is created and the count is
                # already known, so that question never costs a query.
                if kind == "agent" and distinct:
                    self._host_counts()[user] = distinct

                out[kind] = {"value": value, "first_time": first_time,
                             "distinct": distinct, "events": seen}

            self._presence_pending = getattr(self, "_presence_pending", 0) + 1
            if self._presence_pending >= _PRESENCE_COMMIT_EVERY:
                self.conn.commit()
                self._presence_pending = 0
        except Exception as e:
            log.debug("presence not recorded for %s: %s", user, e)
        return out

    def record_privilege_use(self, user: str, log: dict) -> int:
        """Count one privileged operation against an entity (SN 15).

        Stored as another kind in entity_presence rather than a new table: it
        is the same shape (how many times a value was observed for an entity)
        and inherits that table's commit cadence. presence_summary and the
        novelty reasons read only the "country" and "agent" kinds, so these
        rows are invisible to them.

        Returns the entity's running total, served from memory. The engine asks
        for an entity's privilege level on EVERY event, and a SELECT per event
        to answer it would add a read to the hot loop for a number that changes
        a few times a second at most.
        """
        if not user or user == "unknown":
            return 0
        counts = self._privop_counts()
        try:
            self.conn.execute(
                """INSERT INTO entity_presence
                       (username, kind, value, events, first_seen, last_seen)
                   VALUES (?, 'privop', 'any', 1, ?, ?)
                   ON CONFLICT(username, kind, value) DO UPDATE SET
                       events    = events + 1,
                       last_seen = excluded.last_seen""",
                (user, datetime.now(timezone.utc).isoformat(),
                 datetime.now(timezone.utc).isoformat()))
            counts[user] = counts.get(user, 0) + 1
            self._presence_pending = getattr(self, "_presence_pending", 0) + 1
            if self._presence_pending >= _PRESENCE_COMMIT_EVERY:
                self.conn.commit()
                self._presence_pending = 0
        except Exception as e:
            _log.debug("privilege use not recorded for %s: %s", user, e)
        return counts.get(user, 0)

    def privilege_use_count(self, user: str) -> int:
        """How many privileged operations this entity has been seen performing."""
        if not user:
            return 0
        return self._privop_counts().get(user, 0)

    def distinct_host_count(self, user: str) -> int:
        """How many distinct hosts this entity has been seen on (SN 15)."""
        if not user:
            return 0
        return self._host_counts().get(user, 0)

    def _host_counts(self) -> dict:
        """Entity -> distinct host count, read from disk once per process."""
        cached = getattr(self, "_host_cache", None)
        if cached is not None:
            return cached
        cached = {}
        try:
            for name, n in self.conn.execute(
                    "SELECT username, COUNT(*) FROM entity_presence "
                    "WHERE kind = 'agent' GROUP BY username"):
                cached[name] = int(n or 0)
        except Exception as e:
            _log.debug("host counts unavailable: %s", e)
        self._host_cache = cached
        return cached

    def _privop_counts(self) -> dict:
        """Entity -> privileged-operation count, read from disk once per process."""
        cached = getattr(self, "_privop_cache", None)
        if cached is not None:
            return cached
        cached = {}
        try:
            for name, n in self.conn.execute(
                    "SELECT username, events FROM entity_presence WHERE kind = 'privop'"):
                cached[name] = int(n or 0)
        except Exception as e:
            _log.debug("privileged-use counts unavailable: %s", e)
        self._privop_cache = cached
        return cached

    def presence_summary(self, user: str) -> dict:
        """Everywhere an entity has been seen, newest first. For the UI/reports."""
        out: dict = {"country": [], "agent": []}
        if not user:
            return out
        try:
            for kind, value, events, first_seen, last_seen in self.conn.execute(
                    "SELECT kind, value, events, first_seen, last_seen "
                    "FROM entity_presence WHERE username = ? "
                    "ORDER BY events DESC, last_seen DESC", (user,)):
                if kind in out:
                    out[kind].append({"value": value, "events": events,
                                      "first_seen": first_seen,
                                      "last_seen": last_seen})
        except Exception as e:
            log.debug("presence summary unavailable for %s: %s", user, e)
        return out

    def record_transfer(self, user: str, nbytes: int) -> None:
        """Fold one event's transfer volume into an entity's baseline.

        Separate from update() because update() is called ONLY for events that
        already alerted — see the call site in ueba_engine. A baseline for
        "normal transfer volume" built from anomalies alone would define normal
        as the set of things already judged abnormal, and with an alert rate of
        0.02% it would never reach min_events anyway.

        Cheap on purpose: one UPSERT, only for events that actually report
        bytes (about a fifth of traffic), so the hot loop takes a write it
        would not otherwise take roughly ten times a second.
        """
        if not user or user == "unknown" or not nbytes or nbytes <= 0:
            return
        try:
            self._xfer_pending = getattr(self, "_xfer_pending", 0) + 1
            self.conn.execute(
                """INSERT INTO users (username, bytes_events, bytes_total, bytes_max)
                   VALUES (?, 1, ?, ?)
                   ON CONFLICT(username) DO UPDATE SET
                       bytes_events = COALESCE(bytes_events, 0) + 1,
                       bytes_total  = COALESCE(bytes_total, 0) + excluded.bytes_total,
                       bytes_max    = MAX(COALESCE(bytes_max, 0), excluded.bytes_max)""",
                (user, int(nbytes), int(nbytes)))
            # Commit on a cadence, not per row. update() commits too, but it
            # runs only for events that alerted (0.02% of traffic), so without
            # this the writes sit in an open transaction indefinitely —
            # invisible to every other connection and lost on a hard stop.
            if self._xfer_pending >= _XFER_COMMIT_EVERY:
                self.conn.commit()
                self._xfer_pending = 0
        except Exception as e:
            _log.debug("transfer volume not recorded for %s: %s", user, e)

    def get_user_profile(self, user: str) -> dict | None:
        """Return full profile for a user, or None if not found."""
        cur = self.conn.execute(
            "SELECT * FROM users WHERE username = ?", (user,))
        row = cur.fetchone()
        if row is None:
            return None
        # By NAME, not position. Columns are appended by _migrate(), so a
        # positional read silently returns the wrong field the moment the
        # migration order differs between two deployments — and it returns a
        # plausible number rather than an error, which is the worst kind.
        r = dict(zip([d[0] for d in cur.description], row))

        def _int(v):
            try:
                return int(v or 0)
            except (TypeError, ValueError):
                return 0

        events = _int(r.get("bytes_events"))
        total = _int(r.get("bytes_total"))
        return {
            "username":       r.get("username"),
            "avg_hour":       r.get("avg_hour"),
            "avg_risk":       r.get("avg_risk"),
            "avg_events_1h":  r.get("avg_events_1h"),
            "seen_countries": json.loads(r.get("seen_countries") or "[]"),
            "seen_agents":    json.loads(r.get("seen_agents") or "[]"),
            "total_events":   r.get("total_events"),
            "first_seen":     r.get("first_seen"),
            "last_seen":      r.get("last_seen"),
            # Transfer-volume baseline (SN 12 / SN 46).
            "bytes_events":   events,
            "bytes_total":    total,
            "bytes_max":      _int(r.get("bytes_max")),
            "bytes_avg":      (total / events) if events else 0.0,
        }

    def get_all_users(self) -> list[str]:
        """Return list of all usernames in the profile store."""
        rows = self.conn.execute("SELECT username FROM users").fetchall()
        return [r[0] for r in rows]

    def get_user_event_count(self, user: str) -> int:
        """Return how many events we've seen for this user."""
        row = self.conn.execute(
            "SELECT total_events FROM users WHERE username = ?", (user,)
        ).fetchone()
        return row[0] if row else 0

    def close(self):
        self.conn.close()


# ── HDF5 Writer ───────────────────────────────────────────────────────────────

class HDF5Writer:
    """
    Writes feature vectors to an HDF5 file in chunks.
    Supports unlimited appending — file grows as chunks are added.
    Never loads more than one chunk into RAM.

    File structure:
        features.h5
            /features   shape: (N, 35)  dtype: float32
            /metadata   shape: (N,)     dtype: special (JSON strings)
    """

    def __init__(self, output_path: str, feature_dim: int):
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        self.path = output_path
        self.feature_dim = feature_dim
        self.total_written = 0

        # Create file with resizable datasets
        self.f = h5py.File(output_path, "w")
        self.feat_ds = self.f.create_dataset(
            "features",
            shape=(0, feature_dim),
            maxshape=(None, feature_dim),   # unlimited rows
            dtype="float32",
            chunks=(10000, feature_dim),    # read/write 10K rows at a time
            compression="gzip",             # compress to save disk space (~3x)
            compression_opts=4,
        )
        # Metadata stored as JSON strings (one per row)
        self.meta_ds = self.f.create_dataset(
            "metadata",
            shape=(0,),
            maxshape=(None,),
            dtype=h5py.special_dtype(vlen=str),
        )
        log.info("HDF5 writer opened: %s", output_path)

    def write_chunk(self, vectors: np.ndarray, metadata: list[dict]):
        """
        Append a chunk of feature vectors and their metadata to the HDF5 file.
        vectors: shape (chunk_size, feature_dim)
        metadata: list of dicts, one per row
        """
        n = len(vectors)
        current = self.total_written

        # Resize datasets to accommodate new rows
        self.feat_ds.resize(current + n, axis=0)
        self.meta_ds.resize(current + n, axis=0)

        # Write chunk
        self.feat_ds[current:current + n] = vectors
        self.meta_ds[current:current + n] = [json.dumps(m) for m in metadata]

        self.f.flush()
        self.total_written += n

    def close(self):
        self.f.close()
        log.info("HDF5 writer closed. Total rows written: %d", self.total_written)


# ── Worker function for multiprocessing ──────────────────────────────────────

def _worker_init(config: dict):
    """Initialize a per-worker FeatureExtractor (no profile store)."""
    global _worker_extractor
    _worker_extractor = FeatureExtractor(config, profile_store=None)


def _worker_process_line(line_bytes: bytes) -> tuple | None:
    """Parse one JSON line and extract features. Runs in a worker process."""
    try:
        log_entry = _json_loads(line_bytes)
    except Exception:
        return None
    try:
        vec = _worker_extractor.extract(log_entry)
        meta = _worker_extractor.extract_metadata(log_entry)
        return (vec, meta)
    except Exception:
        return None


# ── Batch Preprocessor ────────────────────────────────────────────────────────

class BatchPreprocessor:
    """
    Reads combined_training.jsonl in chunks, extracts feature vectors,
    updates user profiles, and writes to HDF5.

    Uses multiprocessing + orjson for ~5-10x speedup over single-threaded json.
    """

    def __init__(self, config: dict):
        self.config = config
        self.chunk_size = config["preprocessing"]["chunk_size"]
        self.feature_dim = config["preprocessing"]["feature_dim"]

        # Initialize profile store (main process only)
        db_path = config["paths"]["profile_db"]
        self.profile_store = UserProfileStore(db_path)

        # Initialize feature extractor for single-event use
        self.extractor = FeatureExtractor(config, self.profile_store)

        # Worker count: leave 4 cores free for OS + other services
        self.n_workers = max(1, min(mp.cpu_count() - 4, 24))

    def run(self, input_path: str, output_path: str):
        """
        Main preprocessing loop.
        Reads input JSONL in large batches, fans out to worker pool
        for parallel JSON parsing + feature extraction, then writes
        results to HDF5 and updates profiles in the main process.
        """
        writer = HDF5Writer(output_path, self.feature_dim)

        total_logs = 0
        skipped    = 0
        start_time = time.time()
        chunk_num  = 0
        batch_size = self.chunk_size

        log.info("Starting batch preprocessing (parallel)")
        log.info("  Input   : %s", input_path)
        log.info("  Output  : %s", output_path)
        log.info("  Workers : %d", self.n_workers)
        log.info("  Chunk   : %d logs", batch_size)
        log.info("  JSON    : %s", "orjson" if _json_loads.__module__ == "orjson" else "stdlib json")

        pool = mp.Pool(self.n_workers, initializer=_worker_init,
                       initargs=(self.config,))
        try:
            with open(input_path, "rb") as f:
                while True:
                    lines = []
                    for _ in range(batch_size):
                        line = f.readline()
                        if not line:
                            break
                        line = line.strip()
                        if line:
                            lines.append(line)
                    if not lines:
                        break

                    results = pool.map(_worker_process_line, lines,
                                       chunksize=2000)

                    chunk_vectors  = []
                    chunk_metadata = []
                    for r in results:
                        if r is None:
                            skipped += 1
                            continue
                        vec, meta = r
                        chunk_vectors.append(vec)
                        chunk_metadata.append(meta)

                    if chunk_vectors:
                        chunk_num += 1
                        arr = np.stack(chunk_vectors, axis=0)
                        writer.write_chunk(arr, chunk_metadata)
                        total_logs += len(chunk_vectors)

                        elapsed = time.time() - start_time
                        rate = total_logs / elapsed
                        log.info(
                            "Chunk %d written | logs: %d | rate: %.0f/sec | "
                            "skipped: %d",
                            chunk_num, total_logs, rate, skipped,
                        )
        finally:
            pool.terminate()
            pool.join()

        writer.close()
        self.profile_store.close()

        elapsed = time.time() - start_time
        log.info("=" * 60)
        log.info("PREPROCESSING COMPLETE")
        log.info("  Total logs processed : %d", total_logs)
        log.info("  Skipped (errors)     : %d", skipped)
        log.info("  Chunks written       : %d", chunk_num)
        log.info("  Time elapsed         : %.1f minutes", elapsed / 60)
        log.info("  Output               : %s", output_path)

        output_mb = Path(output_path).stat().st_size / (1024 * 1024)
        log.info("  Output size          : %.1f MB", output_mb)
        log.info("=" * 60)

        return total_logs, skipped


# ── Demo Mode ─────────────────────────────────────────────────────────────────

def run_demo(config: dict):
    """
    Show what a feature vector looks like for a sample enriched log.
    Useful for verifying the extractor works correctly with your data.
    """
    # Sample enriched log (matches the CyberSentinel SIEM + L2 output format)
    sample_log = {
        "true": 1771327039.492798,
        "timestamp": "2026-02-17T16:47:19.290+0530",
        "rule": {
            "level": 3,
            "description": "PAM: Login session closed.",
            "id": "5502",
        },
        "agent": {"id": "013", "name": "DB_3", "ip": "34.34.34.3"},
        "event_id": "evt-001",
        "event_time": "2026-02-17T11:17:34Z",
        "event_category": "auth",
        "event_outcome": "success",
        "subject": {"name": "dakshay", "ip": "34.34.34.3"},
        "object":  {"ip": "192.168.1.10"},
        "data": {"dstuser": "dakshay"},
        "enrich": {
            "temporal": {
                "hour": 11,
                "day_of_week": 1,
                "is_weekend": False,
                "is_business_hours": True,
                "is_night_shift": False,
            },
            "flags": {
                "is_auth_event": True,
                "is_network_event": False,
                "is_file_event": False,
                "is_process_event": False,
            },
            "anomalies": {
                "is_brute_force": False,
                "is_port_scan": False,
                "is_tor": False,
                "is_malicious_ip": False,
                "is_impossible_travel": False,
                "is_lateral_movement": False,
                "is_data_exfiltration": False,
                "is_after_hours": False,
                "is_high_frequency": False,
            },
            "counters": {
                "src_ip_5m": 3,
                "src_ip_1h": 47,
                "user_1h": 12,
                "host_1h": 5,
            },
            "behavioral": {
                "unique_destinations_1h": 2,
                "unique_ports_1h": 1,
                "recent_failures_5m": 0,
            },
            "geo": {
                "distance_km": 0.0,
                "cross_border": False,
                "cross_continent": False,
                "src": {"country": "India"},
            },
            "risk_score": 15,
            "network_intel": {"cloud_provider": None},
            "classification": {"traffic_direction": "internal"},
        },
    }

    extractor = FeatureExtractor(config)
    vec  = extractor.extract(sample_log)
    meta = extractor.extract_metadata(sample_log)

    feature_names = [
        "temporal.hour", "temporal.day_of_week", "temporal.is_weekend",
        "temporal.is_business_hours", "temporal.is_night_shift",
        "flags.is_auth_event", "flags.is_network_event",
        "flags.is_file_event", "flags.is_process_event",
        "anomalies.is_brute_force", "anomalies.is_port_scan",
        "anomalies.is_tor", "anomalies.is_malicious_ip",
        "anomalies.is_impossible_travel", "anomalies.is_lateral_movement",
        "anomalies.is_data_exfiltration", "anomalies.is_after_hours",
        "anomalies.is_high_frequency",
        "counters.src_ip_5m", "counters.src_ip_1h",
        "counters.user_1h", "counters.host_1h",
        "behavioral.unique_destinations_1h", "behavioral.unique_ports_1h",
        "behavioral.recent_failures_5m",
        "geo.distance_km", "geo.cross_border", "geo.cross_continent",
        "risk_score", "rule.level", "network_intel.is_cloud",
        "event_category (encoded)", "event_outcome (encoded)",
        "traffic_direction (encoded)", "user_baseline_deviation",
    ]

    print("\n" + "=" * 60)
    print("DEMO — Feature Vector for Sample Log")
    print("=" * 60)
    print(f"{'Index':<6} {'Feature':<40} {'Value'}")
    print("-" * 60)
    for i, (name, val) in enumerate(zip(feature_names, vec)):
        print(f"[{i:>2}]  {name:<40} {val:.4f}")
    print("=" * 60)
    print(f"Vector shape  : {vec.shape}")
    print(f"Vector dtype  : {vec.dtype}")
    print(f"Non-zero vals : {np.count_nonzero(vec)}")
    print("\nMetadata:")
    for k, v in meta.items():
        print(f"  {k}: {v}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="UEBA Feature Extraction — JSON enriched logs → HDF5 feature matrix",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input",  help="Input enriched JSONL file")
    parser.add_argument("--output", help="Output HDF5 file (default from config)")
    parser.add_argument("--config", default="ueba_config.yaml",
                        help="Config file path (default: ueba_config.yaml)")
    parser.add_argument("--demo", action="store_true",
                        help="Run demo mode — show feature vector for a sample log")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.demo:
        run_demo(config)
        return

    if not args.input:
        parser.error("--input is required (unless using --demo)")

    input_path  = args.input
    output_path = args.output or config["paths"]["features_h5"]

    # Create necessary directories
    for d in ["data", "profiles", "logs"]:
        os.makedirs(d, exist_ok=True)

    preprocessor = BatchPreprocessor(config)
    preprocessor.run(input_path, output_path)


if __name__ == "__main__":
    main()
