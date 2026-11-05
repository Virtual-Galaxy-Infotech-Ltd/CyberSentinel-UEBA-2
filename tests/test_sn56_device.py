#!/usr/bin/env python3
"""RFP SN 56 — device summary and peer comparison, through the real routes.

ueba_device_compare.selftest() proves the maths. This proves it is wired in:
that /api/device/<name> carries a composite risk score, that
/api/device/<name>/peers ranks on four dimensions instead of one, and that the
activity-rhythm histogram the new dimension needs is actually collected by
_build_devices rather than quietly absent (in which case `hours` would be
skipped on every comparison and nothing would say so).

The fixture is built so the dimensions DISAGREE. That is the whole point: if
every device differed on all four axes at once, a single-dimension ranking
would score the same order and this test would pass against the code it is
meant to distinguish from.

    device      signatures   active hours   so…
    desk-a      5710/5712    09-17          the subject
    desk-b      5710/5712    09-17          alike on both
    night-c     5710/5712    01-04          SAME rules, OPPOSITE clock
    other-d     9999         09-17          same clock, different rules

night-c is the case that matters. Ranked on signatures alone it is
indistinguishable from desk-b; ranked behaviourally it must fall behind.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


def _alert(device, ip, user, sig, hour, score, verdict, reason, sev=5):
    ts = "2026-11-04T%02d:15:00+05:30" % hour
    return {
        "event_time": ts,
        "host": {"name": device, "ip": ip, "os": {"family": "windows"}},
        "user": {"name": user},
        "security": {"signature_id": str(sig), "signature": "rule %s" % sig,
                     "severity": sev},
        "ueba": {"combined_score": score, "risk_verdict": verdict,
                 "anomaly_reasons": [reason], "processed_at": ts,
                 "model_used": "global"},
    }


# (device, ip, signatures, hours, users, score, verdict, reason)
PLAN = [
    ("desk-a",  "10.200.10.11", [5710, 5712], [9, 13, 17], 3, 0.80, "suspicious", "odd_process"),
    ("desk-b",  "10.200.10.12", [5710, 5712], [9, 13, 17], 3, 0.82, "suspicious", "odd_process"),
    ("night-c", "10.200.10.13", [5710, 5712], [1, 2, 4],   3, 0.81, "suspicious", "odd_process"),
    ("other-d", "10.200.10.14", [9999],       [9, 13, 17], 1, 0.95, "highly_anomalous", "data_egress"),
]


def build_site(work: Path) -> dict:
    alerts = work / "alerts.jsonl"
    with alerts.open("w") as fh:
        for dev, ip, sigs, hours, nusers, score, verdict, reason in PLAN:
            for sig in sigs:
                for hour in hours:
                    for u in range(nusers):
                        for _rep in range(4):
                            fh.write(json.dumps(_alert(
                                dev, ip, "person%d" % u, sig, hour,
                                score, verdict, reason)) + "\n")
    (work / "agents.json").write_text(json.dumps(
        [{"id": "%03d" % n, "name": d, "ip": ip}
         for n, (d, ip, *_r) in enumerate(PLAN, 1)]))
    for name in ("entities.json",):
        (work / name).write_text("{}")
    for name in ("false_positives.json", "fp_patterns.json"):
        (work / name).write_text("[]")

    base = yaml.safe_load((ROOT / "ueba_config.yaml").read_text())
    d = base.setdefault("dashboard", {})
    d["alerts_file"] = str(alerts)
    d["agents_registry"] = str(work / "agents.json")
    d["false_positives_file"] = str(work / "false_positives.json")
    archive = work / "archive"
    archive.mkdir(exist_ok=True)
    d["archive_dir"] = str(archive)
    base["archive_dir"] = str(archive)
    base["audit_file"] = str(work / "audit.jsonl")
    d["audit_file"] = str(work / "audit.jsonl")
    p = base.setdefault("paths", {})
    p["entities_file"] = str(work / "entities.json")
    p["audit_file"] = str(work / "audit.jsonl")
    a = base.setdefault("auth", {})
    a.update({"enabled": False, "enforce": False})
    cfg_path = work / "site.yaml"
    cfg_path.write_text(yaml.safe_dump(base, sort_keys=False))
    return {"cfg_path": cfg_path, "raw": base}


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="sn56-"))
    site = build_site(work)

    import ueba_dashboard_server as S
    import ueba_device_compare as DC
    S.CFG = S.load_dashboard_config(str(site["cfg_path"]))
    S.ALERTS_FILE = Path(S.CFG["alerts_file"])
    S.AGENTS_REGISTRY = Path(S.CFG["agents_registry"])
    S._RAW_CFG = site["raw"]
    client = S.app.test_client()

    ok("the compare module is wired in", S._DEVICE_COMPARE_OK)

    # ── the activity rhythm must actually be collected ──
    # If _build_devices never fills `hours`, the dimension is skipped on every
    # comparison and the feature silently degrades to the old behaviour.
    with S.app.test_request_context("/api/device?hours=0"):
        index = S._device_index()
    ok("every device is indexed", len(index) == len(PLAN), str(sorted(index)))
    rec = index.get("desk-a") or {}
    ok("the hour histogram is populated", bool(rec.get("hours")),
       str(rec.get("hours")))
    ok("and holds the hours the fixture used",
       set((rec.get("hours") or {}).keys()) == {"9", "13", "17"},
       str(rec.get("hours")))
    ok("night-c's hours are the opposite ones",
       set((index.get("night-c") or {}).get("hours", {}).keys()) == {"1", "2", "4"},
       str((index.get("night-c") or {}).get("hours")))
    est = S._device_estate(index)
    ok("estate comparators are derived", est["max_alerts"] > 0 and est["devices"] == 4,
       str(est))

    # ── the summary carries a composite risk score ──
    r = client.get("/api/device/desk-a?hours=0")
    ok("the device summary responds", r.status_code == 200, str(r.status_code))
    body = r.get_json() or {}
    risk = body.get("risk") or {}
    ok("a risk object is present", bool(risk), str(body.keys()))
    ok("with a numeric score", isinstance(risk.get("score"), (int, float)),
       repr(risk.get("score")))
    ok("and a band", risk.get("band") in ("low", "moderate", "high", "critical"),
       repr(risk.get("band")))
    ok("and components that explain it", len(risk.get("components") or []) >= 3,
       str(risk.get("components")))
    ok("the contributions sum to the score",
       abs(sum(c["contribution"] for c in risk["components"])
           - risk["score"]) < 1e-3)
    ok("and the reason is a sentence, not a number",
       isinstance(risk.get("why"), str) and len(risk["why"]) > 20,
       repr(risk.get("why")))
    ok("max_score is still present for the panels that read it",
       "max_score" in body)

    # A device with no alerts in the window must say it has no score rather
    # than report 0.00 as though it had been assessed.
    r = client.get("/api/device/ghost-host?hours=0")
    gb = r.get_json() or {}
    ok("an unknown device still answers", r.status_code == 200)
    ok("and is marked as not in the window", gb.get("in_window") is False)

    # ── peers: four dimensions, and night-c must lose ──
    r = client.get("/api/device/desk-a/peers?hours=0&limit=10")
    ok("the peers endpoint responds", r.status_code == 200, str(r.status_code))
    pb = r.get_json() or {}
    ok("it is comparable", pb.get("comparable") is True, str(pb.get("reason")))
    peers = {p["device"]: p for p in (pb.get("peers") or [])}
    ok("desk-b is a peer", "desk-b" in peers, str(sorted(peers)))

    ok("the basis names the dimensions",
       "Jensen-Shannon" in (pb.get("basis") or ""), pb.get("basis", "")[:80])
    ok("the dimension weights are published",
       len(pb.get("dimension_weights") or []) == len(DC.DIMENSIONS))

    if "desk-b" in peers:
        b = peers["desk-b"]
        ok("the per-dimension breakdown is present",
           len(b.get("dimensions") or []) >= 3, str(len(b.get("dimensions") or [])))
        ok("each dimension carries its own similarity",
           all("similarity" in d for d in b["dimensions"]))
        ok("each dimension carries drivers",
           all("drivers" in d for d in b["dimensions"]))
        ok("each dimension carries DIFFERENTIATORS",
           all("differentiators" in d for d in b["dimensions"]))
        ok("the peer has a plain-language explanation",
           isinstance(b.get("why"), str) and "alike" in b["why"], repr(b.get("why")))
        ok("the old signature-only cosine is still reported",
           isinstance(b.get("similarity_signatures"), (int, float)))
        ok("an identical twin scores very high", b["similarity"] > 0.9,
           str(b["similarity"]))
        hours_dim = [d for d in b["dimensions"] if d["dimension"] == "hours"]
        ok("the hours dimension was compared", len(hours_dim) == 1)
        if hours_dim:
            ok("and desk-b matches on it", hours_dim[0]["similarity"] > 0.9,
               str(hours_dim[0]["similarity"]))

    # THE DISCRIMINATING CASE. night-c fires exactly the same rules as desk-b,
    # so a signature-only ranking cannot separate them. Behaviourally it runs
    # at 01-04 instead of 09-17 and must rank lower.
    if "night-c" in peers and "desk-b" in peers:
        nc, db = peers["night-c"], peers["desk-b"]
        ok("night-c and desk-b are identical on signatures alone",
           abs(nc["similarity_signatures"] - db["similarity_signatures"]) < 1e-6,
           "%s vs %s" % (nc["similarity_signatures"], db["similarity_signatures"]))
        ok("but the behavioural score separates them",
           nc["similarity"] < db["similarity"],
           "night-c %s vs desk-b %s" % (nc["similarity"], db["similarity"]))
        ok("and desk-b is ranked first",
           (pb["peers"][0]["device"] == "desk-b"),
           str([p["device"] for p in pb["peers"]]))
        nh = [d for d in nc["dimensions"] if d["dimension"] == "hours"]
        ok("night-c's clock is the dimension that marks it down",
           bool(nh) and nh[0]["similarity"] < 0.3,
           str(nh[0]["similarity"]) if nh else "hours not compared")
        if nh:
            ok("and the differentiators name the hours involved",
               {x["key"] for x in nh[0]["differentiators"]} & {"1", "2", "4", "9", "13", "17"},
               str(nh[0]["differentiators"]))

    # other-d shares the clock but no rules — it must be the weakest or absent.
    if "other-d" in peers and "desk-b" in peers:
        ok("a device sharing only its clock ranks below a true twin",
           peers["other-d"]["similarity"] < peers["desk-b"]["similarity"])

    # ── ranking is monotone with the reported score ──
    sims = [p["similarity"] for p in (pb.get("peers") or [])]
    ok("peers are returned in descending similarity",
       sims == sorted(sims, reverse=True), str(sims))
    ok("nothing below the floor is returned",
       all(s >= S._DEVICE_MIN_SIMILARITY for s in sims), str(sims))

    total = len(_checks)
    if _failures:
        print("SN 56: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("SN 56: all %d checks passed" % total)
    print("workdir (safe to delete): %s" % work)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
