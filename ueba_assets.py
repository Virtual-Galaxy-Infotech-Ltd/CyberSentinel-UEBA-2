#!/usr/bin/env python3
"""
ueba_assets.py
──────────────
CyberSentinel UEBA — trusted hosts and high-value assets (RFP SN 17, SN 40).

Two serials, one register, because both are the same shape: an operator tags an
entity, and that tag changes how its events score.

  SN 17  Identifying trusted host and entity compromise instances.
         A host the SOC has declared trusted is held to a higher standard, not
         a lower one. Trust here means "this host is load-bearing", so anomalous
         behaviour ON it is more serious than the same behaviour on an unknown
         laptop — it is the premise of a compromise, not a reason to excuse it.

  SN 40  User starts accessing and downloading high-value assets with increased
         frequency. An asset is tagged with a value tier; access to it is
         measured against what that entity normally does with that asset.

What the data supports, measured on the live stream
───────────────────────────────────────────────────
  host.name           100%  — the source host, so SN 17 has what it needs
  object.id / .type    97%  — the destination, mostly kind "ip"
  object.name          46%  — the destination FQDN when it resolved
  data.dstip/dstport   84%  — destination address and service port
  rcvdbyte             16%  — and ~0 toward internal destinations in sampling

So FREQUENCY is the solid half of SN 40 and volume is the weak half. There is
no file-path field anywhere in the feed — object.path, data.file, the syscheck
path and the Windows file-share fields are all absent — so "downloaded this
document" is not expressible. Frequency of access to a tagged asset, and bytes
where the event carries them, is what can honestly be claimed. Recorded here
rather than left for someone to discover.

Why "increased" needs two numbers
─────────────────────────────────
A rate on its own says nothing. Ten connections an hour is alarming for an
account that normally makes one and unremarkable for a server that makes
hundreds. So each entity carries its own long-run rate for each asset, built
from all traffic (entity_presence, kind "asset"), and the short rolling window
is compared against that. An entity with no history for an asset is reported as
a first access instead, which is a different and simpler statement.
"""

# Annotations as strings so this imports on 3.9 as well as the server's 3.12.
from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from pathlib import Path

ROLES = ("trusted_host", "high_value_asset")
TIERS = ("normal", "high", "critical")
_TIER_RANK = {"normal": 0, "high": 1, "critical": 2}

# Tier weight, before any boost ceiling is applied.
_TIER_WEIGHT = {"normal": 0.0, "high": 0.6, "critical": 1.0}

_lock = threading.Lock()
_cache: dict = {}


# ── helpers ──────────────────────────────────────────────────────────────────

def normalise(value) -> str:
    """The stored form of an entity or asset name.

    Lower-cased, trimmed, and with escaped backslashes collapsed — the same
    treatment ueba_privilege applies, for the same measured reason: names reach
    us with inconsistent escaping and a raw comparison fails silently. Public
    because callers have to match on it.
    """
    s = str(value or "").strip().lower()
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    return s


def _clean(e) -> dict | None:
    """Validate one register entry, or None if unusable."""
    if not isinstance(e, dict):
        return None
    value = normalise(e.get("value") or e.get("entity") or e.get("asset"))
    if not value:
        return None
    role = normalise(e.get("role"))
    if role not in ROLES:
        return None                      # a tag with no role scores nothing
    tier = normalise(e.get("tier"))
    if tier not in TIERS:
        # A host someone bothered to declare trusted, or an asset someone
        # bothered to tag, is not "normal" — that is the default for everything
        # they did NOT list.
        tier = "high"
    return {
        "value": value,
        "role":  role,
        "tier":  tier,
        "label": str(e.get("label") or "")[:120],
        "note":  str(e.get("note") or "")[:300],
    }


def _read(path) -> dict:
    """{(role, value): entry}, re-parsed only when the file changes."""
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
                c = _clean(e)
                if c:
                    index[(c["role"], c["value"])] = c
        except Exception as ex:
            print("[assets] failed to read %s: %s" % (p, ex))
            index = {}

    _cache[key] = {"stamp": stamp, "index": index}
    return index


def entries(path, role: str = "") -> list:
    """Register entries, optionally for one role only."""
    with _lock:
        vals = list(_read(path).values())
    if role:
        r = normalise(role)
        vals = [v for v in vals if v["role"] == r]
    return vals


def save(path, items: list) -> None:
    """Atomically replace the register."""
    p = Path(str(path))
    clean = [c for c in (_clean(e) for e in (items or [])) if c]
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(clean, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)
    with _lock:
        _cache.pop(str(p), None)


def lookup(path, value, role: str) -> dict | None:
    """The entry tagging `value` in `role`, or None."""
    if not path or not value:
        return None
    with _lock:
        return _read(path).get((normalise(role), normalise(value)))


# ── what an event touched ────────────────────────────────────────────────────

def event_target(log: dict, get_nested) -> dict:
    """The asset this event reached: {"id", "name", "port"}, any may be "".

    Two identifiers are returned because the register may be written against
    either. An operator tags "the payroll server" by whichever of the address
    or the name they actually know, and both appear in the feed — the address on
    84% of events and the name on 46%.
    """
    oid = (get_nested(log, "object.id", "")
           or get_nested(log, "context.raw_event.data.dstip", "") or "")
    name = get_nested(log, "object.name", "") or ""
    port = (get_nested(log, "context.raw_event.data.dstport", "")
            or get_nested(log, "network.dst_port", "") or "")
    return {"id": str(oid).strip(), "name": str(name).strip(), "port": str(port).strip()}


def match_asset(path, target: dict) -> dict | None:
    """The high-value-asset entry this target matches, by address then name."""
    for key in ("id", "name"):
        v = (target or {}).get(key)
        if v:
            hit = lookup(path, v, "high_value_asset")
            if hit:
                return hit
    return None


# ── access rate, per entity and asset ────────────────────────────────────────

class AccessRates:
    """Short rolling per-(entity, asset) access counts.

    Deliberately in memory and deliberately bounded. "Increased frequency" is a
    statement about now, so it needs a window rather than the cumulative total
    the profile store already keeps; and an unbounded dict keyed on a pair this
    wide is a slow memory leak in a process that runs for weeks.
    """

    def __init__(self, window_secs: int = 3600, max_keys: int = 20000):
        self.window = max(60, int(window_secs))
        self.max_keys = max(1000, int(max_keys))
        self._hits: dict = {}

    def record(self, entity: str, asset: str, now: float | None = None) -> int:
        """Note one access. Returns the count inside the window, including this."""
        if not entity or not asset:
            return 0
        now = time.time() if now is None else now
        key = (entity, asset)
        dq = self._hits.get(key)
        if dq is None:
            if len(self._hits) >= self.max_keys:
                # Drop the coldest half rather than refuse to record. Losing the
                # quietest pairs costs a signal that was never going to fire;
                # refusing would blind the detection entirely.
                self._evict()
            dq = self._hits[key] = deque()
        dq.append(now)
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def count(self, entity: str, asset: str, now: float | None = None) -> int:
        dq = self._hits.get((entity, asset))
        if not dq:
            return 0
        now = time.time() if now is None else now
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def _evict(self) -> None:
        ranked = sorted(self._hits.items(), key=lambda kv: (len(kv[1]), kv[1][-1] if kv[1] else 0))
        for key, _ in ranked[: len(ranked) // 2 or 1]:
            self._hits.pop(key, None)

    def __len__(self) -> int:
        return len(self._hits)


# ── the detections ───────────────────────────────────────────────────────────

def assess(path, source_host: str, entity: str, target: dict,
           window_count: int, baseline_rate: float, seen_before: int,
           is_alert_anomalous: bool = True, bytes_down: int = 0,
           cfg: dict | None = None) -> dict:
    """Trusted-host compromise (SN 17) and high-value asset access (SN 40).

    `window_count`   accesses by this entity to this asset inside the window
    `baseline_rate`  that entity's long-run accesses-per-window for this asset
    `seen_before`    how many times it has EVER accessed it, before this event

    Returns {"reasons": [...], "boost": float, "findings": [...], "tier": str}.
    """
    cfg = cfg or {}
    out: dict = {"reasons": [], "boost": 0.0, "findings": [], "tier": None}
    max_boost = min(float(cfg.get("max_boost") or 0.20), 0.40)

    # ── SN 17 — a trusted host behaving anomalously ──
    trusted = lookup(path, source_host, "trusted_host") if source_host else None
    if trusted and is_alert_anomalous:
        label = trusted.get("label") or source_host
        out["findings"].append("trusted_host_compromise")
        out["reasons"].append(
            "Possible compromise of a trusted host: %s is declared %s-value and "
            "trusted, and is behaving outside its own baseline"
            % (label, trusted["tier"]))
        out["boost"] = max(out["boost"],
                           max_boost * _TIER_WEIGHT.get(trusted["tier"], 0.6))

    # ── SN 40 — access to a tagged high-value asset ──
    asset = match_asset(path, target)
    if asset:
        out["tier"] = asset["tier"]
        label = asset.get("label") or asset["value"]
        ratio_thresh = float(cfg.get("frequency_ratio") or 3.0)
        min_count = int(cfg.get("frequency_min_count") or 5)

        # == 0, not <= 0. A negative count means the store could not tell us,
        # and "we do not know" must never be reported as "never happened
        # before" — see record_asset_access.
        if seen_before == 0:
            out["findings"].append("first_asset_access")
            out["reasons"].append(
                "First recorded access by this entity to %s, a %s-value asset"
                % (label, asset["tier"]))
        elif window_count >= min_count and baseline_rate > 0 and \
                window_count >= baseline_rate * ratio_thresh:
            out["findings"].append("asset_access_surge")
            out["reasons"].append(
                "Access to %s, a %s-value asset, is running at %d in the window "
                "against a normal %.1f for this entity (%.1fx)"
                % (label, asset["tier"], window_count, baseline_rate,
                   window_count / baseline_rate))

        # Volume, only where the event actually carries it. Secondary by
        # design — see the module docstring on why frequency leads.
        min_bytes = int(cfg.get("download_min_bytes") or 10 * 1024 * 1024)
        if bytes_down and bytes_down >= min_bytes:
            out["findings"].append("asset_download_volume")
            out["reasons"].append(
                "%.1f MB downloaded from %s, a %s-value asset"
                % (bytes_down / 1048576.0, label, asset["tier"]))

        if out["findings"]:
            out["boost"] = max(out["boost"],
                               max_boost * _TIER_WEIGHT.get(asset["tier"], 0.6))

    out["boost"] = round(out["boost"], 4)
    return out


# ── selftest ──────────────────────────────────────────────────────────────────

def selftest() -> int:
    import os
    import tempfile
    failures = []

    def ok(label, cond):
        if not cond:
            failures.append(label)

    def gn(d, p, default=None):
        cur = d
        for k in p.split("."):
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur if cur not in (None, "") else default

    d = tempfile.mkdtemp()
    reg = os.path.join(d, "assets.json")

    # ── normalise ──
    ok("lower-cases", normalise("  SRV-Payroll ") == "srv-payroll")
    ok("collapses doubled backslash", normalise("DOM\\\\host") == "dom\\host")
    ok("keeps single backslash", normalise("DOM\\host") == "dom\\host")
    ok("empty is empty", normalise(None) == "")

    # ── entry validation ──
    save(reg, [
        {"value": "10.156.170.121", "role": "high_value_asset", "tier": "critical",
         "label": "Core banking gateway"},
        {"value": "SRV-PAYROLL", "role": "high_value_asset"},            # tier defaults
        {"value": "VGCBS-15.vginfo.net", "role": "trusted_host", "tier": "high"},
        {"value": "nope", "role": "not_a_role"},                          # dropped
        {"value": "", "role": "trusted_host"},                            # dropped
        "garbage",                                                         # dropped
        {"value": "weird", "role": "high_value_asset", "tier": "sideways"},  # tier fixed
    ])
    all_e = entries(reg)
    ok("three valid plus the tier-fixed one kept", len(all_e) == 4)
    ok("unknown role dropped", not any(e["value"] == "nope" for e in all_e))
    ok("declared asset defaults to high tier",
       lookup(reg, "srv-payroll", "high_value_asset")["tier"] == "high")
    ok("bad tier falls back to high",
       lookup(reg, "weird", "high_value_asset")["tier"] == "high")
    ok("label retained",
       lookup(reg, "10.156.170.121", "high_value_asset")["label"] == "Core banking gateway")
    ok("role filter works", len(entries(reg, "trusted_host")) == 1)
    ok("lookup is case-insensitive",
       lookup(reg, "VGCBS-15.VGINFO.NET", "trusted_host") is not None)
    ok("role is part of the key — asset is not a trusted host",
       lookup(reg, "srv-payroll", "trusted_host") is None)
    ok("missing file tolerated",
       lookup(os.path.join(d, "none.json"), "x", "trusted_host") is None)

    # ── event_target ──
    t = event_target({"object": {"id": "10.0.0.5", "name": "payroll.corp"},
                      "context": {"raw_event": {"data": {"dstport": "1521"}}}}, gn)
    ok("target id", t["id"] == "10.0.0.5")
    ok("target name", t["name"] == "payroll.corp")
    ok("target port", t["port"] == "1521")
    t = event_target({"context": {"raw_event": {"data": {"dstip": "10.0.0.9"}}}}, gn)
    ok("falls back to dstip", t["id"] == "10.0.0.9")
    ok("absent name is empty", event_target({}, gn)["name"] == "")

    # ── match_asset, by either identifier ──
    ok("matches by address",
       match_asset(reg, {"id": "10.156.170.121", "name": ""})["tier"] == "critical")
    ok("matches by name",
       match_asset(reg, {"id": "1.1.1.1", "name": "SRV-PAYROLL"}) is not None)
    ok("address wins when both are tagged",
       match_asset(reg, {"id": "10.156.170.121", "name": "srv-payroll"})["tier"] == "critical")
    ok("untagged target matches nothing",
       match_asset(reg, {"id": "8.8.8.8", "name": "dns.google"}) is None)
    ok("empty target matches nothing", match_asset(reg, {}) is None)

    # ── AccessRates ──
    r = AccessRates(window_secs=100)
    base = 1000.0
    ok("first access counts 1", r.record("u", "a", base) == 1)
    ok("second counts 2", r.record("u", "a", base + 1) == 2)
    ok("count agrees", r.count("u", "a", base + 2) == 2)
    ok("a different asset is separate", r.record("u", "b", base + 1) == 1)
    ok("a different entity is separate", r.record("v", "a", base + 1) == 1)
    ok("old hits leave the window", r.record("u", "a", base + 500) == 1)
    ok("empty entity records nothing", r.record("", "a", base) == 0)
    ok("empty asset records nothing", r.record("u", "", base) == 0)
    ok("unknown pair counts 0", r.count("zz", "yy", base) == 0)
    r2 = AccessRates(window_secs=100, max_keys=1000)
    for i in range(1100):
        r2.record("e%d" % i, "a", base)
    ok("eviction bounds the map", len(r2) <= 1000)

    # ── SN 17: trusted-host compromise ──
    a = assess(reg, "VGCBS-15.vginfo.net", "alice", {}, 0, 0.0, 0, True)
    ok("trusted host compromise detected", "trusted_host_compromise" in a["findings"])
    ok("reason names the host", "VGCBS-15" in a["reasons"][0])
    ok("trusted host carries a boost", a["boost"] > 0)
    a = assess(reg, "VGCBS-15.vginfo.net", "alice", {}, 0, 0.0, 0, False)
    ok("a trusted host behaving normally is not a finding",
       "trusted_host_compromise" not in a["findings"])
    a = assess(reg, "some-random-laptop", "alice", {}, 0, 0.0, 0, True)
    ok("an undeclared host is not a compromise finding", a["findings"] == [])

    # ── SN 40: first access ──
    tgt = {"id": "10.156.170.121", "name": ""}
    a = assess(reg, "x", "alice", tgt, 1, 0.0, 0)
    ok("first asset access detected", "first_asset_access" in a["findings"])
    ok("first-access reason names the label", "Core banking gateway" in a["reasons"][0])
    ok("critical tier reported", a["tier"] == "critical")

    # ── SN 40: frequency surge ──
    a = assess(reg, "x", "alice", tgt, 30, 4.0, 500)
    ok("surge detected", "asset_access_surge" in a["findings"])
    ok("surge states both numbers",
       "30" in a["reasons"][0] and "4.0" in a["reasons"][0])
    a = assess(reg, "x", "alice", tgt, 6, 4.0, 500)
    ok("a small rise is not a surge", "asset_access_surge" not in a["findings"])
    a = assess(reg, "x", "alice", tgt, 3, 0.2, 500)
    ok("below min_count is not a surge", "asset_access_surge" not in a["findings"])
    a = assess(reg, "x", "alice", tgt, 30, 4.0, 500, cfg={"frequency_ratio": 20})
    ok("ratio is configurable", "asset_access_surge" not in a["findings"])
    a = assess(reg, "x", "alice", tgt, 30, 0.0, 500)
    ok("no baseline means no surge claim", "asset_access_surge" not in a["findings"])

    # ── SN 40: volume, secondary ──
    a = assess(reg, "x", "alice", tgt, 1, 4.0, 500, bytes_down=50 * 1024 * 1024)
    ok("large download detected", "asset_download_volume" in a["findings"])
    ok("volume reason is in MB", "MB downloaded" in a["reasons"][0])
    a = assess(reg, "x", "alice", tgt, 1, 4.0, 500, bytes_down=1024)
    ok("a small download is not a finding", "asset_download_volume" not in a["findings"])
    a = assess(reg, "x", "alice", tgt, 1, 4.0, 500, bytes_down=0)
    ok("absent volume is not a finding", "asset_download_volume" not in a["findings"])

    # ── untagged asset is out of scope ──
    a = assess(reg, "x", "alice", tgt, 1, 0.0, -1)
    ok("unknown history does not claim a first access",
       "first_asset_access" not in a["findings"])
    a = assess(reg, "x", "alice", tgt, 30, 4.0, -1)
    ok("unknown history still allows a surge claim",
       "asset_access_surge" in a["findings"])

    a = assess(reg, "x", "alice", {"id": "8.8.8.8"}, 999, 0.1, 0)
    ok("untagged asset yields nothing", a["findings"] == [] and a["boost"] == 0.0)
    ok("untagged asset has no tier", a["tier"] is None)

    # ── boost shape ──
    crit = assess(reg, "x", "alice", tgt, 1, 0.0, 0)["boost"]
    high = assess(reg, "x", "alice", {"id": "srv-payroll"}, 1, 0.0, 0)["boost"]
    ok("critical boosts more than high", crit > high)
    ok("boost respects max_boost",
       assess(reg, "x", "alice", tgt, 1, 0.0, 0, cfg={"max_boost": 0.05})["boost"] <= 0.05)
    ok("boost is hard-capped",
       assess(reg, "x", "alice", tgt, 1, 0.0, 0, cfg={"max_boost": 99})["boost"] <= 0.40)

    # both serials at once
    a = assess(reg, "VGCBS-15.vginfo.net", "alice", tgt, 30, 4.0, 500, True,
               bytes_down=50 * 1024 * 1024)
    ok("both serials can fire together", len(a["findings"]) >= 3)

    total = 64
    if failures:
        print("ueba_assets selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_assets selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
