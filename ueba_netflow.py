#!/usr/bin/env python3
"""
ueba_netflow.py
───────────────
CyberSentinel UEBA — flow ingestion and network anomaly detection (RFP SN 28).

  SN 28  The solution should allow network data ingestion from log collectors
         for NetFlows to provide Network Anomaly Detections.

Two halves, and the second one is the part with a design decision in it
───────────────────────────────────────────────────────────────────────
INGESTION is a normalisation problem. Collectors emit flow records in whatever
shape their exporter uses, so this module reads the shapes collectors actually
produce — nfdump, IPFIX/NetFlow v9 JSON, Elastic Common Schema, the Logstash
netflow module, and the firewall fields this deployment already carries — and
reduces them to one canonical flow. Adding a sixth shape is a table entry.

DETECTION is where the decision is. Measured on the local alert sample:

  * records carrying BOTH a source and a destination address: 0 of 3,412.
    Destination fields, ports, protocol and byte counts are absent from alerts
    entirely — they live in the enriched event stream.
  * the Fortigate flow events that DO carry them are in the engine's noise
    suppression list (81619, 81620, 81621, 81631, 81633, 81634, 81644),
    because individually they are policy enforcement firing thousands of times
    a day with no investigative value.

Both facts point the same way: a network anomaly is NOT a property of one flow.
"Firewall passed a connection" is uninteresting; "this host opened connections
to 200 distinct ports on three machines in ninety seconds" is a port scan, and
it is only visible in the aggregate. So detection here runs over the flow
stream as a windowed aggregate and raises its OWN findings, independent of
whether the constituent flow events would individually pass the noise gate.
Inferring network anomalies from flow ALERTS would have found nothing, because
by design there are none.

What is detected, and the evidence each one rests on
────────────────────────────────────────────────────
  port_scan        many distinct destination ports across few destinations,
                   with little data moved per flow
  address_sweep    one or two ports across many distinct destinations
  data_egress      sustained outbound volume to addresses outside the estate
  beaconing        repeated contact with one destination at a regular
                   interval — measured as a low coefficient of variation over
                   the gaps, which is what separates malware check-in from a
                   human clicking around
  asymmetric_flow  many flows sending far more than they receive, the shape
                   of both exfiltration and of scanning a closed port

Every finding carries the numbers that produced it, so an analyst can disagree
with the threshold rather than with the verdict.

Thresholds are DEFAULTS, not calibrated
───────────────────────────────────────
This is stated plainly because it matters: there are no flow records in the
local sample, so none of these numbers has been fitted to this estate. They
are conventional starting points, every one is config-driven, and the first
task once the flow feed is connected is to measure the firing rate and tune
them. The module reports its own rate through stats() to make that measurement
a reading rather than an exercise.

Findings are throttled, for a reason this project has paid for twice
───────────────────────────────────────────────────────────────────
A scanning host is a standing CONDITION, not an event. Unthrottled, every flow
it emits would raise the same port_scan finding — the identical shape that
produced 4,836 misuse findings in one overnight run and then 914
privilege-only alerts. One finding per entity per detection per window.
"""

from __future__ import annotations

import ipaddress
import math
import time
from collections import deque

try:
    # Reuse the tested throttle rather than writing a second one.
    from ueba_privilege import FindingThrottle
except Exception:                                            # pragma: no cover
    FindingThrottle = None

DETECTIONS = ("port_scan", "address_sweep", "data_egress", "beaconing",
              "asymmetric_flow")

# ── field maps, one per collector shape ──────────────────────────────────────
#
# Order matters only in that the first map to yield a source AND a destination
# wins. A record is tried against every map, so a collector that emits a
# mixture (ECS envelope around netflow fields, which filebeat does) still
# resolves.
_SHAPES = (
    ("ecs", {
        "src": ("source.ip",), "dst": ("destination.ip",),
        "sport": ("source.port",), "dport": ("destination.port",),
        "proto": ("network.transport", "network.iana_number"),
        "sent": ("source.bytes", "network.bytes"),
        "rcvd": ("destination.bytes",),
        "spkts": ("source.packets",), "dpkts": ("destination.packets",),
        "dur": ("event.duration",),
        "start": ("event.start", "@timestamp"),
    }),
    ("netflow_logstash", {
        "src": ("netflow.ipv4_src_addr", "netflow.ipv6_src_addr"),
        "dst": ("netflow.ipv4_dst_addr", "netflow.ipv6_dst_addr"),
        "sport": ("netflow.l4_src_port",), "dport": ("netflow.l4_dst_port",),
        "proto": ("netflow.protocol",),
        "sent": ("netflow.in_bytes",), "rcvd": ("netflow.out_bytes",),
        "spkts": ("netflow.in_pkts",), "dpkts": ("netflow.out_pkts",),
        "dur": ("netflow.flow_duration_milliseconds",),
        "start": ("netflow.first_switched",),
    }),
    ("ipfix", {
        "src": ("sourceIPv4Address", "sourceIPv6Address"),
        "dst": ("destinationIPv4Address", "destinationIPv6Address"),
        "sport": ("sourceTransportPort",),
        "dport": ("destinationTransportPort",),
        "proto": ("protocolIdentifier",),
        "sent": ("octetDeltaCount", "octetTotalCount"),
        "rcvd": ("reverseOctetDeltaCount",),
        "spkts": ("packetDeltaCount",), "dpkts": ("reversePacketDeltaCount",),
        "dur": ("flowDurationMilliseconds",),
        "start": ("flowStartSysUpTime", "flowStartMilliseconds"),
    }),
    ("nfdump", {
        # nfdump's short names. Deliberately listed in full rather than
        # pattern-matched: `pr` and `td` are too short to guess at safely.
        "src": ("sa", "srcaddr"), "dst": ("da", "dstaddr"),
        "sport": ("sp", "srcport"), "dport": ("dp", "dstport"),
        "proto": ("pr", "proto"),
        "sent": ("ibyt", "ibytes"), "rcvd": ("obyt", "obytes"),
        "spkts": ("ipkt", "ipkts"), "dpkts": ("opkt", "opkts"),
        "dur": ("td",), "start": ("ts", "first"),
    }),
    ("firewall", {
        # What this deployment already carries. Measured coverage on the
        # enriched stream: dstip/dstport ~84%, sentbyte present on about a
        # fifth of events.
        "src": ("data.srcip", "context.raw_event.data.srcip"),
        "dst": ("data.dstip", "context.raw_event.data.dstip"),
        "sport": ("data.srcport", "context.raw_event.data.srcport"),
        "dport": ("data.dstport", "context.raw_event.data.dstport"),
        "proto": ("data.proto", "context.raw_event.data.proto"),
        "sent": ("data.sentbyte", "context.raw_event.data.sentbyte"),
        "rcvd": ("data.rcvdbyte", "context.raw_event.data.rcvdbyte"),
        "spkts": ("data.sentpkt",), "dpkts": ("data.rcvdpkt",),
        "dur": ("data.duration", "context.raw_event.data.duration"),
        "start": ("event_time", "@timestamp"),
    }),
)

# IANA numbers for the protocols worth naming.
_PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp",
                58: "ipv6-icmp"}

# ── thresholds. Defaults, not calibrated — see the header. ──────────────────
DEFAULTS = {
    "window_secs": 300.0,
    # port_scan: ports across few destinations, little data per flow.
    "scan_min_ports": 20,
    "scan_max_destinations": 3,
    "scan_max_mean_bytes": 1024.0,
    # address_sweep: many destinations across few ports.
    "sweep_min_destinations": 20,
    "sweep_max_ports": 2,
    # data_egress: outbound volume to addresses outside the estate.
    "egress_min_bytes": 100 * 1024 * 1024,
    # beaconing: repeated contact at a regular interval.
    "beacon_min_flows": 8,
    "beacon_max_cv": 0.15,
    "beacon_min_interval_secs": 5.0,
    # asymmetric_flow: sending far more than is received.
    "asym_min_flows": 20,
    "asym_min_ratio": 20.0,
    "asym_min_sent": 1024 * 1024,
    # bounds
    "max_tracked_sources": 20000,
    "max_destinations_per_source": 4096,
    "max_ports_per_source": 4096,
    "max_intervals_per_pair": 64,
    "finding_window_secs": 3600,
}


def get_nested(obj, path: str, default=None):
    cur = obj
    for part in str(path).split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


def _num(v, default=0.0) -> float:
    try:
        f = float(v)
        return f if math.isfinite(f) else default
    except (TypeError, ValueError):
        return default


def _ip(v) -> str:
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return ""


def is_external(addr: str) -> bool:
    """True for an address outside the estate.

    Private, loopback, link-local and multicast are all internal for this
    purpose. A malformed address is NOT external: treating an unparseable
    string as the internet would turn a bad field into an egress alert.

    WORTH KNOWING: Python counts the TEST-NET documentation ranges
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) as private, so those
    addresses are INTERNAL here. They are the natural choice for a test
    fixture and they will silently not trigger an egress finding — which cost
    one debugging round while writing the selftest below, hence this note.
    """
    try:
        ip = ipaddress.ip_address(str(addr).strip())
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def proto_name(v) -> str:
    """'tcp' from 6, 'tcp' from 'TCP', '' from nothing."""
    if v in (None, ""):
        return ""
    s = str(v).strip().lower()
    if s.isdigit():
        return _PROTO_NAMES.get(int(s), s)
    return s


# The shape that matched most recently, tried first on the next record. One
# deployment emits one shape, so after the first flow this turns five
# speculative shape attempts per event into one — and flows are the bulk of the
# enriched stream, so the saving is on the hot path rather than in theory.
_shape_hint = [None]


def normalise(record: dict) -> "dict | None":
    """One canonical flow from a collector record, or None if it is not a flow.

    {"src","dst","sport","dport","proto","sent","rcvd","bytes","packets",
     "duration","shape"}

    A record must yield BOTH endpoints to be a flow. Half a flow is an event,
    and the aggregates below would be wrong if a stream of half-flows were
    counted as connections.
    """
    if not isinstance(record, dict):
        return None
    hint = _shape_hint[0]
    order = _SHAPES
    if hint is not None:
        order = ([x for x in _SHAPES if x[0] == hint]
                 + [x for x in _SHAPES if x[0] != hint])
    for shape, m in order:
        src = dst = ""
        for f in m["src"]:
            src = _ip(get_nested(record, f))
            if src:
                break
        if not src:
            continue
        for f in m["dst"]:
            dst = _ip(get_nested(record, f))
            if dst:
                break
        if not dst:
            continue

        def first(key, conv=_num, default=0.0):
            for f in m.get(key, ()):
                v = get_nested(record, f)
                if v not in (None, "", "-"):
                    return conv(v, default) if conv is _num else conv(v)
            return default

        sent = first("sent")
        rcvd = first("rcvd")
        dur = first("dur")
        # Logstash and IPFIX report duration in milliseconds; a flow lasting
        # longer than a day is almost certainly ms misread as seconds.
        if shape in ("netflow_logstash", "ipfix") and dur > 0:
            dur = dur / 1000.0
        _shape_hint[0] = shape
        return {
            "src": src,
            "dst": dst,
            "sport": int(first("sport")) or 0,
            "dport": int(first("dport")) or 0,
            "proto": proto_name(first("proto", conv=lambda v: v, default="")),
            "sent": sent,
            "rcvd": rcvd,
            "bytes": sent + rcvd,
            "packets": first("spkts") + first("dpkts"),
            "duration": dur,
            "shape": shape,
        }
    return None


class FlowWindow:
    """Per-source flow aggregates over a rolling window.

    Bounded on every axis. A scanning host is precisely the case that would
    make an unbounded structure explode — it is the one touching thousands of
    ports — so the caps are not theoretical.
    """

    def __init__(self, cfg: "dict | None" = None):
        c = dict(DEFAULTS)
        c.update({k: v for k, v in (cfg or {}).items() if v is not None})
        self.cfg = c
        self.window = float(c["window_secs"])
        self._flows: dict = {}      # src -> deque of (ts, flow)
        self._pair_times: dict = {}  # (src,dst) -> deque of ts
        self._touched: dict = {}
        self._dropped = 0

    # ── ingest ──

    def record(self, flow: dict, now: "float | None" = None) -> int:
        """Add one flow. Returns how many this source has in the window."""
        if not flow or not flow.get("src") or not flow.get("dst"):
            return 0
        ts = float(now if now is not None else time.time())
        src = flow["src"]

        if src not in self._flows and len(self._flows) >= int(
                self.cfg["max_tracked_sources"]):
            oldest = min(self._touched, key=self._touched.get, default=None)
            if oldest is not None:
                self._flows.pop(oldest, None)
                self._touched.pop(oldest, None)
                self._dropped += 1
                for k in [k for k in self._pair_times if k[0] == oldest]:
                    self._pair_times.pop(k, None)
        self._touched[src] = ts

        dq = self._flows.setdefault(src, deque())
        dq.append((ts, flow))
        self._expire(src, ts)

        pair = (src, flow["dst"])
        times = self._pair_times.setdefault(pair, deque(
            maxlen=int(self.cfg["max_intervals_per_pair"])))
        times.append(ts)
        return len(dq)

    def _expire(self, src: str, now: float) -> None:
        dq = self._flows.get(src)
        if dq is None:
            return
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq:
            self._flows.pop(src, None)
            self._touched.pop(src, None)

    # ── aggregates ──

    def summary(self, src: str, now: "float | None" = None) -> dict:
        """What this source has been doing inside the window."""
        ts = float(now if now is not None else time.time())
        self._expire(src, ts)
        dq = self._flows.get(src) or deque()
        dests: set = set()
        ports: set = set()
        ext_sent = 0.0
        sent = rcvd = 0.0
        flows = 0
        max_d = int(self.cfg["max_destinations_per_source"])
        max_p = int(self.cfg["max_ports_per_source"])
        for _, f in dq:
            flows += 1
            if len(dests) < max_d:
                dests.add(f["dst"])
            if f["dport"] and len(ports) < max_p:
                ports.add(f["dport"])
            sent += f["sent"]
            rcvd += f["rcvd"]
            if is_external(f["dst"]):
                ext_sent += f["sent"]
        return {
            "source": src,
            "flows": flows,
            "destinations": len(dests),
            "ports": len(ports),
            "bytes_sent": sent,
            "bytes_received": rcvd,
            "bytes_sent_external": ext_sent,
            "mean_bytes_per_flow": (sent + rcvd) / flows if flows else 0.0,
            "window_secs": self.window,
        }

    def intervals(self, src: str, dst: str) -> list:
        """Gaps between successive contacts with one destination."""
        times = list(self._pair_times.get((src, dst)) or ())
        return [b - a for a, b in zip(times, times[1:])]

    def destinations(self, src: str, now: "float | None" = None) -> list:
        ts = float(now if now is not None else time.time())
        self._expire(src, ts)
        return sorted({f["dst"] for _, f in (self._flows.get(src) or ())})

    def stats(self) -> dict:
        return {"sources": len(self._flows),
                "pairs": len(self._pair_times),
                "evicted_sources": self._dropped,
                "window_secs": self.window}


def _cv(values) -> float:
    """Coefficient of variation: spread relative to the mean.

    The right measure for beaconing because it is scale-free — a check-in
    every 60s and one every 3600s are both regular, and a threshold on raw
    standard deviation would only catch one of them.
    """
    vals = [float(v) for v in values if _num(v, -1) >= 0]
    if len(vals) < 2:
        return 1.0
    mean = sum(vals) / len(vals)
    if mean <= 0:
        return 1.0
    var = sum((v - mean) ** 2 for v in vals) / len(vals)
    return math.sqrt(var) / mean


def assess(window: FlowWindow, src: str, now: "float | None" = None,
           cfg: "dict | None" = None,
           throttle=None) -> dict:
    """Network anomaly findings for one source.

    {"findings": [...], "summary": {...}}. Each finding carries the numbers
    that produced it. Throttled per (entity, detection) where a throttle is
    supplied — a scanning host is a standing condition and would otherwise
    raise the same finding on every flow.
    """
    c = dict(DEFAULTS)
    c.update(window.cfg)
    c.update({k: v for k, v in (cfg or {}).items() if v is not None})
    ts = float(now if now is not None else time.time())
    s = window.summary(src, ts)
    out = {"findings": [], "summary": s}

    def allow(name):
        if throttle is None:
            return True
        try:
            # (entity, finding kind) is the throttle's own key shape — passing
            # a concatenated key put the timestamp in the `finding` slot and
            # silently defeated the throttle.
            return throttle.allow(src, name, ts)
        except Exception:
            return True

    def add(name, detail, **nums):
        if allow(name):
            out["findings"].append({"detection": name, "detail": detail,
                                    "evidence": nums})

    # port scan: ports wide, destinations narrow, little data moved
    if (s["ports"] >= int(c["scan_min_ports"])
            and s["destinations"] <= int(c["scan_max_destinations"])
            and s["mean_bytes_per_flow"] <= float(c["scan_max_mean_bytes"])):
        add("port_scan",
            "contacted %d distinct ports on %d destination(s) in %.0fs, "
            "averaging %.0f bytes per flow — the shape of a port scan rather "
            "than of use"
            % (s["ports"], s["destinations"], s["window_secs"],
               s["mean_bytes_per_flow"]),
            ports=s["ports"], destinations=s["destinations"],
            mean_bytes=round(s["mean_bytes_per_flow"], 1), flows=s["flows"])

    # address sweep: destinations wide, ports narrow
    if (s["destinations"] >= int(c["sweep_min_destinations"])
            and 0 < s["ports"] <= int(c["sweep_max_ports"])):
        add("address_sweep",
            "contacted %d distinct destinations on %d port(s) in %.0fs — the "
            "shape of a sweep for one service"
            % (s["destinations"], s["ports"], s["window_secs"]),
            destinations=s["destinations"], ports=s["ports"],
            flows=s["flows"])

    # data egress: sustained outbound volume leaving the estate
    if s["bytes_sent_external"] >= float(c["egress_min_bytes"]):
        add("data_egress",
            "sent %.1f MB to addresses outside the estate in %.0fs"
            % (s["bytes_sent_external"] / 1048576.0, s["window_secs"]),
            bytes_sent_external=int(s["bytes_sent_external"]),
            flows=s["flows"])

    # asymmetric flow: many flows, sending far more than received
    if (s["flows"] >= int(c["asym_min_flows"])
            and s["bytes_sent"] >= float(c["asym_min_sent"])
            and s["bytes_received"] * float(c["asym_min_ratio"]) < s["bytes_sent"]):
        ratio = (s["bytes_sent"] / s["bytes_received"]
                 if s["bytes_received"] else float("inf"))
        add("asymmetric_flow",
            "sent %.1f MB and received %.1f MB across %d flows (%s:1) — the "
            "shape of exfiltration or of probing closed ports"
            % (s["bytes_sent"] / 1048576.0, s["bytes_received"] / 1048576.0,
               s["flows"], "inf" if math.isinf(ratio) else "%.0f" % ratio),
            bytes_sent=int(s["bytes_sent"]),
            bytes_received=int(s["bytes_received"]),
            ratio=(None if math.isinf(ratio) else round(ratio, 1)),
            flows=s["flows"])

    # beaconing: one destination, regular interval
    for dst in window.destinations(src, ts):
        gaps = window.intervals(src, dst)
        if len(gaps) + 1 < int(c["beacon_min_flows"]):
            continue
        mean_gap = sum(gaps) / len(gaps) if gaps else 0.0
        if mean_gap < float(c["beacon_min_interval_secs"]):
            # Faster than this is a burst, not a check-in; bursts are what the
            # scan and sweep tests are for.
            continue
        cv = _cv(gaps)
        if cv <= float(c["beacon_max_cv"]):
            if allow("beaconing"):
                out["findings"].append({
                    "detection": "beaconing",
                    "detail": ("contacted %s %d times at a near-constant "
                               "%.0fs interval (variation %.0f%%) — regular "
                               "enough to be an automated check-in rather "
                               "than a person"
                               % (dst, len(gaps) + 1, mean_gap, cv * 100.0)),
                    "evidence": {"destination": dst, "contacts": len(gaps) + 1,
                                 "mean_interval_secs": round(mean_gap, 2),
                                 "variation": round(cv, 4),
                                 "external": is_external(dst)},
                })
            break      # one beaconing finding per assessment is enough
    return out


def make_throttle(cfg: "dict | None" = None):
    """A throttle for these findings, or None if the shared one is absent."""
    if FindingThrottle is None:
        return None
    c = dict(DEFAULTS)
    c.update(cfg or {})
    return FindingThrottle(
        window_secs=int(c["finding_window_secs"]),
        max_keys=int(c["max_tracked_sources"]))


def status(window: "FlowWindow | None" = None,
           cfg: "dict | None" = None) -> dict:
    c = dict(DEFAULTS)
    c.update(cfg or {})
    return {
        "detections": list(DETECTIONS),
        "shapes": [name for name, _ in _SHAPES],
        "thresholds": c,
        "window": window.stats() if window else None,
        "calibration_note": (
            "These thresholds are conventional defaults, NOT fitted to this "
            "estate: the local alert sample contains no flow records at all "
            "(0 of 3,412 carry both endpoints), so there was nothing to "
            "calibrate against. Every one is config-driven. The first task "
            "once a flow feed is connected is to read the firing rate from "
            "this endpoint and tune them."),
        "ingest_note": (
            "Flow records are read from the collector shapes collectors "
            "actually emit (%s). A network anomaly is an aggregate property, "
            "so detection runs over the flow stream and raises its own "
            "findings rather than reading flow ALERTS — the per-flow firewall "
            "events are in the engine's noise list by design, because "
            "individually they are policy enforcement with no investigative "
            "value." % ", ".join(n for n, _ in _SHAPES)),
    }


# ── selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    failures = []
    checked = []

    def ok(label, cond):
        # Counted, not a literal. A hardcoded total means every check added
        # after it runs and is never reported.
        checked.append(label)
        if not cond:
            failures.append(label)

    # ── helpers ──
    ok("an iana number names a protocol", proto_name(6) == "tcp")
    ok("a numeric string names a protocol", proto_name("17") == "udp")
    ok("a name is folded", proto_name("TCP") == "tcp")
    ok("an unknown number passes through", proto_name(253) == "253")
    ok("nothing gives nothing", proto_name(None) == "" and proto_name("") == "")

    ok("a public address is external", is_external("8.8.8.8"))
    for a in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1",
              "169.254.1.1", "224.0.0.1", "0.0.0.0"):
        ok("internal: %s" % a, not is_external(a))
    ok("a malformed address is NOT treated as external",
       not is_external("not-an-ip"))
    ok("an empty address is not external", not is_external(""))
    ok("a public v6 address is external", is_external("2001:4860:4860::8888"))
    # Pinned because it is counter-intuitive and it broke a fixture here.
    for doc in ("192.0.2.1", "198.51.100.1", "203.0.113.1"):
        ok("a TEST-NET documentation address counts as internal: %s" % doc,
           not is_external(doc))
    ok("a private v6 address is internal", not is_external("fd00::1"))

    ok("cv of a constant series is zero", _cv([60, 60, 60]) == 0.0)
    ok("cv of a wild series is large", _cv([1, 100, 5, 300]) > 0.5)
    ok("cv of one value is maximal", _cv([60]) == 1.0)
    ok("cv of nothing is maximal", _cv([]) == 1.0)
    ok("cv ignores negatives rather than dividing by a bad mean",
       _cv([-5, -5]) == 1.0)

    # ── normalisation, every shape ──
    ecs = {"source": {"ip": "10.0.0.5", "port": 4444, "bytes": 1000},
           "destination": {"ip": "8.8.8.8", "port": 53, "bytes": 200},
           "network": {"transport": "udp"}}
    f = normalise(ecs)
    ok("ecs normalises", f and f["shape"] == "ecs")
    ok("ecs reads both endpoints", f["src"] == "10.0.0.5" and f["dst"] == "8.8.8.8")
    ok("ecs reads the ports", f["sport"] == 4444 and f["dport"] == 53)
    ok("ecs reads the protocol", f["proto"] == "udp")
    ok("ecs reads the bytes", f["sent"] == 1000 and f["rcvd"] == 200)
    ok("total bytes are summed", f["bytes"] == 1200)

    ls = {"netflow": {"ipv4_src_addr": "10.0.0.6", "ipv4_dst_addr": "10.0.0.7",
                      "l4_src_port": 1234, "l4_dst_port": 445,
                      "protocol": 6, "in_bytes": 500, "out_bytes": 100,
                      "flow_duration_milliseconds": 2500}}
    f = normalise(ls)
    ok("the logstash netflow shape normalises", f and f["shape"] == "netflow_logstash")
    ok("its protocol number is named", f["proto"] == "tcp")
    ok("milliseconds become seconds", abs(f["duration"] - 2.5) < 1e-9)

    ipf = {"sourceIPv4Address": "10.0.0.8", "destinationIPv4Address": "1.1.1.1",
           "destinationTransportPort": 443, "protocolIdentifier": 6,
           "octetDeltaCount": 9000, "flowDurationMilliseconds": 1000}
    f = normalise(ipf)
    ok("the ipfix shape normalises", f and f["shape"] == "ipfix")
    ok("ipfix bytes are read", f["sent"] == 9000)
    ok("ipfix duration converts", abs(f["duration"] - 1.0) < 1e-9)

    nf = {"sa": "10.0.0.9", "da": "10.0.0.10", "sp": 2000, "dp": 22,
          "pr": "TCP", "ibyt": 300, "obyt": 400, "td": 1.5}
    f = normalise(nf)
    ok("the nfdump shape normalises", f and f["shape"] == "nfdump")
    ok("nfdump seconds are not rescaled", abs(f["duration"] - 1.5) < 1e-9)

    fw = {"data": {"srcip": "10.0.0.11", "dstip": "93.184.216.34",
                   "dstport": 443, "proto": 6, "sentbyte": 2000,
                   "rcvdbyte": 50000}}
    f = normalise(fw)
    ok("the firewall shape normalises", f and f["shape"] == "firewall")
    ok("firewall bytes are read", f["sent"] == 2000 and f["rcvd"] == 50000)
    fw2 = {"context": {"raw_event": {"data": {
        "srcip": "10.0.0.12", "dstip": "10.0.0.13", "dstport": 80}}}}
    ok("the nested firewall path normalises", normalise(fw2) is not None)

    # half a flow is not a flow
    ok("a record with only a source is not a flow",
       normalise({"source": {"ip": "10.0.0.1"}}) is None)
    ok("a record with only a destination is not a flow",
       normalise({"destination": {"ip": "10.0.0.1"}}) is None)
    ok("an empty record is not a flow", normalise({}) is None)
    ok("a non-dict is not a flow", normalise("nope") is None)
    ok("a record with unparseable addresses is not a flow",
       normalise({"source": {"ip": "x"}, "destination": {"ip": "y"}}) is None)
    ok("a dash value is skipped",
       normalise({"sa": "10.0.0.1", "da": "10.0.0.2", "dp": "-"})["dport"] == 0)

    # The shape hint must not change any answer, only the order of attempts.
    _shape_hint[0] = None
    cold = [normalise(r) for r in (ecs, ls, ipf, nf, fw)]
    _shape_hint[0] = "firewall"
    warm = [normalise(r) for r in (ecs, ls, ipf, nf, fw)]
    ok("the shape hint does not change what is parsed", cold == warm)
    _shape_hint[0] = "nfdump"
    ok("a stale hint still parses an ecs record correctly",
       normalise(ecs)["shape"] == "ecs")
    _shape_hint[0] = None

    # ── the window ──
    w = FlowWindow({"window_secs": 100.0})
    ok("recording a flow counts it", w.record(normalise(fw), 1000.0) == 1)
    ok("recording junk counts nothing", w.record(None, 1000.0) == 0)
    ok("recording a flow with no source counts nothing",
       w.record({"dst": "1.1.1.1"}, 1000.0) == 0)
    s = w.summary("10.0.0.11", 1000.0)
    ok("the summary counts the flow", s["flows"] == 1)
    ok("the summary counts the destination", s["destinations"] == 1)
    ok("the summary counts external bytes sent", s["bytes_sent_external"] == 2000)
    ok("flows age out of the window", w.summary("10.0.0.11", 2000.0)["flows"] == 0)

    # ── port scan ──
    w = FlowWindow({"window_secs": 300.0})
    for port in range(1, 61):
        w.record({"src": "10.0.0.20", "dst": "10.0.0.99", "dport": port,
                  "sent": 60.0, "rcvd": 0.0, "bytes": 60.0, "proto": "tcp"},
                 1000.0 + port)
    r = assess(w, "10.0.0.20", 1100.0)
    names = {f["detection"] for f in r["findings"]}
    ok("a port scan is detected", "port_scan" in names)
    scan = [f for f in r["findings"] if f["detection"] == "port_scan"][0]
    ok("the scan finding carries the port count", scan["evidence"]["ports"] == 60)
    ok("the scan finding names the shape", "port scan" in scan["detail"])
    ok("a scan is not also reported as a sweep", "address_sweep" not in names)

    # heavy traffic on many ports is NOT a scan — the bytes test must hold
    w2 = FlowWindow({"window_secs": 300.0})
    for port in range(1, 61):
        w2.record({"src": "10.0.0.21", "dst": "10.0.0.99", "dport": port,
                   "sent": 500000.0, "rcvd": 400000.0, "bytes": 900000.0,
                   "proto": "tcp"}, 1000.0 + port)
    ok("heavy traffic across many ports is not called a scan",
       "port_scan" not in {f["detection"] for f in
                           assess(w2, "10.0.0.21", 1100.0)["findings"]})

    # ── address sweep ──
    w3 = FlowWindow({"window_secs": 300.0})
    for i in range(1, 41):
        w3.record({"src": "10.0.0.22", "dst": "10.0.1.%d" % i, "dport": 445,
                   "sent": 80.0, "rcvd": 0.0, "bytes": 80.0, "proto": "tcp"},
                  1000.0 + i)
    names = {f["detection"] for f in assess(w3, "10.0.0.22", 1100.0)["findings"]}
    ok("an address sweep is detected", "address_sweep" in names)
    ok("a sweep is not also reported as a port scan", "port_scan" not in names)

    # ── data egress ──
    w4 = FlowWindow({"window_secs": 600.0})
    for i in range(20):
        w4.record({"src": "10.0.0.23", "dst": "93.184.216.34", "dport": 443,
                   "sent": 20 * 1024 * 1024.0, "rcvd": 1000.0,
                   "bytes": 20 * 1024 * 1024.0, "proto": "tcp"}, 1000.0 + i)
    r = assess(w4, "10.0.0.23", 1100.0)
    names = {f["detection"] for f in r["findings"]}
    ok("data egress is detected", "data_egress" in names)
    eg = [f for f in r["findings"] if f["detection"] == "data_egress"][0]
    ok("the egress finding reports the volume",
       eg["evidence"]["bytes_sent_external"] > 100 * 1024 * 1024)
    ok("egress is reported in MB in the detail", "MB" in eg["detail"])
    ok("asymmetry is also detected on this traffic", "asymmetric_flow" in names)

    # the same volume to an INTERNAL destination is not egress
    w5 = FlowWindow({"window_secs": 600.0})
    for i in range(20):
        w5.record({"src": "10.0.0.24", "dst": "10.0.0.50", "dport": 445,
                   "sent": 20 * 1024 * 1024.0, "rcvd": 1000.0,
                   "bytes": 20 * 1024 * 1024.0, "proto": "tcp"}, 1000.0 + i)
    ok("volume to an internal destination is not egress",
       "data_egress" not in {f["detection"] for f in
                             assess(w5, "10.0.0.24", 1100.0)["findings"]})

    # ── beaconing ──
    w6 = FlowWindow({"window_secs": 3600.0})
    for i in range(12):
        w6.record({"src": "10.0.0.25", "dst": "8.8.8.8", "dport": 443,
                   "sent": 400.0, "rcvd": 400.0, "bytes": 800.0,
                   "proto": "tcp"}, 1000.0 + i * 60.0)
    r = assess(w6, "10.0.0.25", 1800.0)
    bc = [f for f in r["findings"] if f["detection"] == "beaconing"]
    ok("regular contact is detected as beaconing", bool(bc))
    if bc:
        ok("the beacon finding names the destination",
           bc[0]["evidence"]["destination"] == "8.8.8.8")
        ok("it reports the interval",
           abs(bc[0]["evidence"]["mean_interval_secs"] - 60.0) < 1.0)
        ok("it reports the destination as external",
           bc[0]["evidence"]["external"] is True)
        ok("it says why regularity matters", "check-in" in bc[0]["detail"])

    # irregular contact is not beaconing
    w7 = FlowWindow({"window_secs": 3600.0})
    gaps = [5, 400, 12, 900, 30, 650, 7, 1200, 15, 300, 90]
    t = 1000.0
    for g in gaps:
        t += g
        w7.record({"src": "10.0.0.26", "dst": "1.1.1.1", "dport": 443,
                   "sent": 400.0, "rcvd": 400.0, "bytes": 800.0,
                   "proto": "tcp"}, t)
    ok("irregular contact is not beaconing",
       "beaconing" not in {f["detection"] for f in
                           assess(w7, "10.0.0.26", t + 1)["findings"]})

    # a fast burst is not beaconing either
    w8 = FlowWindow({"window_secs": 3600.0})
    for i in range(12):
        w8.record({"src": "10.0.0.27", "dst": "9.9.9.9", "dport": 443,
                   "sent": 10.0, "rcvd": 0.0, "bytes": 10.0, "proto": "tcp"},
                  1000.0 + i * 1.0)
    ok("a sub-interval burst is not beaconing",
       "beaconing" not in {f["detection"] for f in
                           assess(w8, "10.0.0.27", 1100.0)["findings"]})

    # ── quiet traffic raises nothing ──
    w9 = FlowWindow({"window_secs": 300.0})
    w9.record({"src": "10.0.0.28", "dst": "10.0.0.29", "dport": 443,
               "sent": 5000.0, "rcvd": 60000.0, "bytes": 65000.0,
               "proto": "tcp"}, 1000.0)
    ok("ordinary traffic raises no finding",
       assess(w9, "10.0.0.28", 1001.0)["findings"] == [])
    ok("an unknown source raises no finding",
       assess(w9, "10.9.9.9", 1001.0)["findings"] == [])

    # ── throttling ──
    th = make_throttle({"finding_window_secs": 3600})
    if th is not None:
        w10 = FlowWindow({"window_secs": 300.0})
        for port in range(1, 61):
            w10.record({"src": "10.0.0.30", "dst": "10.0.0.99", "dport": port,
                        "sent": 60.0, "rcvd": 0.0, "bytes": 60.0,
                        "proto": "tcp"}, 1000.0 + port)
        first = assess(w10, "10.0.0.30", 1100.0, throttle=th)
        second = assess(w10, "10.0.0.30", 1101.0, throttle=th)
        ok("the first assessment reports the scan",
           "port_scan" in {f["detection"] for f in first["findings"]})
        ok("the second is throttled rather than repeating it",
           "port_scan" not in {f["detection"] for f in second["findings"]})
        ok("a different source is not throttled with it",
           assess(w10, "10.0.0.20", 1101.0, throttle=th) is not None)
    else:
        ok("throttle unavailable, skipped", True)
        ok("throttle unavailable, skipped 2", True)
        ok("throttle unavailable, skipped 3", True)

    # ── bounds ──
    wb = FlowWindow({"window_secs": 10000.0, "max_tracked_sources": 5})
    for i in range(20):
        wb.record({"src": "10.1.0.%d" % i, "dst": "10.0.0.1", "dport": 80,
                   "sent": 10.0, "rcvd": 10.0, "bytes": 20.0, "proto": "tcp"},
                  1000.0 + i)
    ok("the source map stays bounded", wb.stats()["sources"] <= 5)
    ok("evictions are counted", wb.stats()["evicted_sources"] > 0)
    wp = FlowWindow({"window_secs": 10000.0, "max_ports_per_source": 10})
    for p in range(100):
        wp.record({"src": "10.2.0.1", "dst": "10.0.0.1", "dport": p + 1,
                   "sent": 1.0, "rcvd": 0.0, "bytes": 1.0, "proto": "tcp"},
                  1000.0 + p)
    ok("the port set stays bounded",
       wp.summary("10.2.0.1", 1200.0)["ports"] <= 10)
    wi = FlowWindow({"window_secs": 10000.0, "max_intervals_per_pair": 8})
    for i in range(50):
        wi.record({"src": "10.3.0.1", "dst": "10.0.0.2", "dport": 80,
                   "sent": 1.0, "rcvd": 0.0, "bytes": 1.0, "proto": "tcp"},
                  1000.0 + i * 60)
    ok("the interval history stays bounded",
       len(wi.intervals("10.3.0.1", "10.0.0.2")) <= 8)

    # ── status ──
    st = status(w, None)
    ok("status lists the detections", st["detections"] == list(DETECTIONS))
    ok("status lists every collector shape", len(st["shapes"]) == 5)
    ok("status is explicit that thresholds are uncalibrated",
       "NOT fitted" in st["calibration_note"])
    ok("status explains why detection is an aggregate",
       "aggregate property" in st["ingest_note"])
    ok("status carries the thresholds", st["thresholds"]["scan_min_ports"] == 20)

    total = len(checked)
    if failures:
        print("ueba_netflow selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_netflow selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
