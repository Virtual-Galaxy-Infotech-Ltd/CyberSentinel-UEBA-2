#!/usr/bin/env python3
"""
ueba_nicknames.py
─────────────────
CyberSentinel UEBA — operator-assigned friendly names for devices and users.

RFP SN 58 asks that a device be findable by hostname, MAC address, username,
IP address OR NICKNAME. Four of those five already work: hostname, username and
IP are indexed by /api/suggest and matched by /api/search/deep.

MAC is not in the data at all — no event carries one under any of mac,
src_mac, dst_mac, hwaddr or mac_address at any nesting depth, checked across a
40,000-event sample. It cannot be searched because it is never received, and
no amount of UI work changes that; it needs the SIEM to forward it, or a DHCP
or asset-registry feed.

Nickname is the one gap this closes. A nickname is a label a human chooses —
"Finance DC", "Rupali's laptop" — attached to an entity the platform already
knows. It is deliberately NOT derived from the data: the whole point is that
an analyst searching for "the ATM server" should find it even though no event
anywhere contains that phrase.

Storage mirrors ueba_watchlist: one JSON file, re-read only when its mtime or
size changes, written atomically. It cannot live in agents.json, which the
agent-sync poller rewrites from the SIEM registry every few minutes and would
silently discard anything added by hand.
"""

import json
import os
import tempfile
import threading
from pathlib import Path

TYPES = ("user", "host", "ip")
MAX_LEN = 60

_lock = threading.Lock()
_cache: dict = {}


def _norm(v) -> str:
    return str(v or "").strip()


def entry_id(etype: str, value: str) -> str:
    """Stable id for one entity, case-insensitive on the value.

    Case-insensitive because a host arrives as VGSOC-LAP11 in one event and
    vgsoc-lap11 in the next, and an analyst who named one would reasonably
    expect the other to carry the same label.
    """
    return "%s:%s" % (_norm(etype).lower(), _norm(value).lower())


def _clean(e: dict) -> dict | None:
    etype = _norm(e.get("type")).lower()
    value = _norm(e.get("value"))
    nick = _norm(e.get("nickname"))[:MAX_LEN]
    if etype not in TYPES or not value or not nick:
        return None
    return {"id": entry_id(etype, value), "type": etype, "value": value,
            "nickname": nick, "note": _norm(e.get("note"))[:200],
            "added_at": _norm(e.get("added_at")), "added_by": _norm(e.get("added_by"))}


def _read(path) -> tuple:
    """(entries, index) for `path`, re-parsed only when the file changes."""
    p = Path(path)
    try:
        st = p.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        return [], {}
    hit = _cache.get(str(p))
    if hit and hit["stamp"] == stamp:
        return hit["entries"], hit["index"]
    try:
        raw = json.loads(p.read_text(encoding="utf-8") or "[]")
    except Exception:
        return [], {}
    entries = [c for c in (_clean(e) for e in raw if isinstance(e, dict)) if c]
    index = {e["id"]: e for e in entries}
    _cache[str(p)] = {"stamp": stamp, "entries": entries, "index": index}
    return entries, index


def entries(path) -> list:
    return list(_read(path)[0])


def save(path, items: list) -> None:
    """Atomic replace, so a reader never sees a half-written file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    clean = [c for c in (_clean(e) for e in items) if c]
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".nick.", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(clean, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    _cache.pop(str(p), None)


def set_name(path, etype: str, value: str, nickname: str,
             note: str = "", added_by: str = "") -> dict:
    from datetime import datetime, timezone
    e = _clean({"type": etype, "value": value, "nickname": nickname,
                "note": note, "added_by": added_by,
                "added_at": datetime.now(timezone.utc).isoformat()})
    if e is None:
        raise ValueError("type must be one of %s, and value and nickname are required"
                         % (TYPES,))
    with _lock:
        items = [x for x in entries(path) if x["id"] != e["id"]]
        items.append(e)
        save(path, items)
    return e


def remove(path, eid: str) -> bool:
    with _lock:
        items = entries(path)
        kept = [x for x in items if x["id"] != _norm(eid).lower()]
        if len(kept) == len(items):
            return False
        save(path, kept)
    return True


def lookup(path, etype: str, value: str) -> str | None:
    """The nickname for one entity, or None."""
    if not value:
        return None
    return (_read(path)[1].get(entry_id(etype, value)) or {}).get("nickname")


def all_names(path) -> dict:
    """{nickname: entry} for building a search index."""
    return {e["nickname"]: e for e in _read(path)[0]}


# ── selftest ──────────────────────────────────────────────────────────────────

def selftest() -> int:
    import tempfile as tf
    fails = []

    def ck(name, got, exp):
        ok = got == exp
        if not ok:
            fails.append(name)
        print("  %-52s %s" % (name, "ok" if ok else "FAIL got=%r exp=%r" % (got, exp)))

    d = tf.mkdtemp()
    p = Path(d) / "nicknames.json"

    print("empty store")
    ck("no entries", entries(p), [])
    ck("lookup misses", lookup(p, "host", "anything"), None)

    print("\nsetting a name")
    set_name(p, "host", "DC_ATM_SRV", "ATM Server", note="finance DC", added_by="aditya")
    ck("one entry", len(entries(p)), 1)
    ck("lookup hits", lookup(p, "host", "DC_ATM_SRV"), "ATM Server")
    ck("case-insensitive on value", lookup(p, "host", "dc_atm_srv"), "ATM Server")
    ck("wrong type misses", lookup(p, "user", "DC_ATM_SRV"), None)

    print("\nre-naming replaces rather than duplicates")
    set_name(p, "host", "dc_atm_srv", "ATM Server (prod)")
    ck("still one entry", len(entries(p)), 1)
    ck("new name wins", lookup(p, "host", "DC_ATM_SRV"), "ATM Server (prod)")

    print("\nvalidation")
    for bad, label in ((("mac", "aa:bb", "x"), "unknown type refused"),
                       (("host", "", "x"), "empty value refused"),
                       (("host", "h1", ""), "empty nickname refused")):
        try:
            set_name(p, *bad); ck(label, False, True)
        except ValueError:
            ck(label, True, True)
    long_name = "n" * 200
    set_name(p, "user", "jinu", long_name)
    ck("nickname truncated to %d" % MAX_LEN, len(lookup(p, "user", "jinu")), MAX_LEN)

    print("\nremoval and the index")
    ck("remove works", remove(p, entry_id("user", "jinu")), True)
    ck("removing twice is False", remove(p, entry_id("user", "jinu")), False)
    ck("lookup gone", lookup(p, "user", "jinu"), None)
    ck("all_names maps nickname -> entry", list(all_names(p)), ["ATM Server (prod)"])

    print("\ncorrupt file is survivable, not fatal")
    p.write_text("{not json", encoding="utf-8")
    ck("entries falls back to empty", entries(p), [])

    print("\n%s - %d failure(s)" % ("PASS" if not fails else "FAIL", len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
