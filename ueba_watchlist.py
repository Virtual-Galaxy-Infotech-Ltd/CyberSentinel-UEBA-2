#!/usr/bin/env python3
"""
Watch lists — elevated scrutiny for named users, hosts and IPs (RFP point 1).

WHAT A WATCH LIST IS FOR
------------------------
An analyst knows things the models do not: that an employee is under notice,
that a contractor's access is being wound down, that a particular server is in
scope for an investigation. A watch list is how that knowledge reaches the
scoring pipeline.

HOW IT WORKS
------------
A watched entity gets a small additive boost to its fused anomaly score, applied
BEFORE the alert threshold and verdict tiers are evaluated. The effect is to
lower the bar for that entity — not to alert on everything it does.

With the shipped defaults (threshold 0.75, boost 0.10) a watched user's routine
activity still scores well under threshold and stays silent; what changes is
that their borderline behaviour — the 0.68 that would normally be discarded —
now surfaces, and their genuinely anomalous behaviour escalates a tier. That is
the intended trade. A boost large enough to alert on everything would make the
watch list useless within a day, because the analyst would mute it.

The store is a plain JSON file shared by the engine (read, hot-reloaded on
mtime) and the dashboard (read/write via /api/watchlist). Entry ids are derived
from type+value, so adding the same entity twice updates it rather than
producing duplicates.
"""
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

# The entity kinds a watch list can name. Matched against the metadata the
# preprocessor already extracts, so no new plumbing is needed in the engine.
TYPES = ("user", "host", "ip")

# Additive score boost when no per-entry value is given. See the module docstring
# for why this is deliberately small.
DEFAULT_BOOST = 0.10

# A boost of 1.0 would force every event from the entity to maximum severity,
# which is an alert firehose rather than a watch list. Cap it well below that.
MAX_BOOST = 0.50

_lock = threading.Lock()
# Cached parse keyed by path, invalidated on mtime/size change. The engine calls
# match() on every scored event, so re-reading the file each time is not an
# option; watching mtime means an analyst's edit still takes effect within one
# event, with no engine restart.
_cache: dict = {}


def _norm(v) -> str:
    """Entities are compared case-insensitively and whitespace-trimmed.

    Usernames arrive from Windows, Linux and firewall logs with inconsistent
    casing for what is the same account, and an analyst typing a name into the
    UI should not have to reproduce the log's capitalisation exactly.
    """
    return str(v or "").strip().lower()


def entry_id(etype: str, value: str) -> str:
    """Deterministic id, so re-adding an entity updates it instead of duplicating."""
    return hashlib.sha1(f"{_norm(etype)}|{_norm(value)}".encode()).hexdigest()[:12]


def _clean(e: dict) -> dict | None:
    """Normalise one stored record, or None if it is unusable."""
    if not isinstance(e, dict):
        return None
    etype, value = _norm(e.get("type")), str(e.get("value") or "").strip()
    if etype not in TYPES or not value:
        return None
    try:
        boost = float(e.get("boost", DEFAULT_BOOST))
    except (TypeError, ValueError):
        boost = DEFAULT_BOOST
    boost = max(0.0, min(boost, MAX_BOOST))
    return {
        "id":       e.get("id") or entry_id(etype, value),
        "type":     etype,
        "value":    value,
        "reason":   str(e.get("reason") or "")[:500],
        "boost":    round(boost, 4),
        "added_at": e.get("added_at") or datetime.now(timezone.utc).isoformat(),
        "added_by": e.get("added_by") or None,
    }


def _read(path) -> tuple:
    """(entries, index) for `path`, re-parsed only when the file changes."""
    p = Path(path)
    try:
        st = p.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None

    key = str(p)
    hit = _cache.get(key)
    if hit and hit["stamp"] == stamp:
        return hit["entries"], hit["index"]

    entries = []
    if stamp is not None:
        try:
            raw = json.loads(p.read_text(encoding="utf-8") or "[]")
            if isinstance(raw, dict):           # tolerate {id: entry} shape
                raw = list(raw.values())
            for e in raw or []:
                c = _clean(e)
                if c:
                    entries.append(c)
        except Exception as ex:
            print(f"[watchlist] failed to read {p}: {ex}")
            entries = []

    # (type, normalised value) -> entry, for O(1) lookup on the hot path.
    index = {(e["type"], _norm(e["value"])): e for e in entries}
    _cache[key] = {"stamp": stamp, "entries": entries, "index": index}
    return entries, index


def entries(path) -> list:
    with _lock:
        return list(_read(path)[0])


def save(path, items: list) -> None:
    """Atomically replace the store. Caller holds whatever lock it needs."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)
    _cache.pop(str(p), None)


def add(path, etype: str, value: str, reason: str = "",
        boost=None, added_by=None) -> tuple:
    """Add or update one entity. Returns (entry, created)."""
    cand = _clean({
        "type": etype, "value": value, "reason": reason,
        "boost": DEFAULT_BOOST if boost is None else boost,
        "added_by": added_by,
    })
    if cand is None:
        raise ValueError(f"type must be one of {TYPES} and value must be non-empty")
    with _lock:
        items = list(_read(path)[0])
        existing = next((i for i, e in enumerate(items) if e["id"] == cand["id"]), None)
        if existing is None:
            items.append(cand)
            created = True
        else:
            # Preserve original provenance; the entity was already being watched.
            cand["added_at"] = items[existing].get("added_at") or cand["added_at"]
            items[existing] = cand
            created = False
        save(path, items)
    return cand, created


def remove(path, eid: str) -> bool:
    with _lock:
        items = list(_read(path)[0])
        kept = [e for e in items if e["id"] != eid]
        if len(kept) == len(items):
            return False
        save(path, kept)
    return True


def match(path, metadata: dict) -> dict | None:
    """Highest-boost watch-list entry matching this event, or None.

    An event can hit several entries at once — a watched user logging in from a
    watched IP — in which case the strongest boost wins rather than stacking.
    Stacking would let two ordinary 0.10 entries silently produce a 0.20 escalation
    that no analyst chose.
    """
    if not metadata:
        return None
    with _lock:
        _, index = _read(path)
    if not index:
        return None

    candidates = [("user", metadata.get("user")),
                  ("host", metadata.get("agent_name"))]
    for f in ("src_ip", "dst_ip", "agent_ip"):
        candidates.append(("ip", metadata.get(f)))

    # resolve_entity() does not always yield a username. Userless events —
    # firewall and network traffic with no account attached — are keyed as
    # "ip:<addr>" or "host:<name>" instead, and that prefixed string is what
    # lands in metadata["user"]. Without unwrapping it here, an analyst watching
    # host GPU_SRV would silently fail to match the very events that host
    # generates, because they are filed under "host:GPU_SRV" rather than under
    # agent_name. The analyst types the bare name; we do the translation.
    ent = _norm(metadata.get("user"))
    if ent.startswith("ip:"):
        candidates.append(("ip", ent[3:]))
    elif ent.startswith("host:"):
        candidates.append(("host", ent[5:]))

    best = None
    for etype, raw in candidates:
        v = _norm(raw)
        if not v:
            continue
        hit = index.get((etype, v))
        if hit and (best is None or hit["boost"] > best["boost"]):
            best = hit
    return best
