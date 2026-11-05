#!/usr/bin/env python3
"""RFP SN 30 / SN 67 — operator-defined entities are ANALYSED, not just listed.

ueba_entity_profiles.selftest() proves the maths. This proves the path a real
administrator takes:

  1. map a field they nominate  (POST /api/entities/mappings)
  2. the values under it get profiled from the live events
  3. /api/entities/kind/<kind> carries an assessment, not only counts
  4. /api/entities/profile/<kind>/<value> explains one entity
  5. /api/entities reports which recognised kinds this feed can populate

The fixture makes the two anomaly questions DISAGREE, which is the whole
reason they are reported separately:

    value       behaviour
    erp         steady, and typical of its kind      -> neither score high
    payroll     steady, but unlike every sibling     -> peer-outlier high
    legacy      typical of its kind, but changed     -> self-drift high

A single blended score cannot tell `payroll` from `legacy`, and an analyst
acts differently on each.

Isolated: synthetic alerts, a temp register, a temp presence DB. Nothing reads
production.
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


EARLY = "2026-11-01T%02d:00:00+05:30"
LATE = "2026-11-20T%02d:00:00+05:30"
SPLIT_SAFE = "2026-11-10T00:00:00+05:30"


def _alert(ts, actor, sig, app, verdict="suspicious", score=0.80, sev=5):
    return {
        "event_time": ts,
        "host": {"name": "Access-SRV-2.140", "ip": "10.200.10.5",
                 "os": {"family": "windows"}},
        "user": {"name": actor},
        "security": {"signature_id": str(sig), "signature": "rule %s" % sig,
                     "severity": sev},
        "data": {"appname": app},
        "ueba": {"combined_score": score, "risk_verdict": verdict,
                 "anomaly_reasons": ["synthetic"], "processed_at": ts,
                 "model_used": "global"},
    }


def build_site(work: Path) -> dict:
    rows = []
    # erp and payroll: steady across both halves. payroll is reached by a
    # different crowd at different hours, so it is unlike its siblings while
    # being perfectly stable in itself.
    for half_ts in (EARLY, LATE):
        for h in (9, 11, 14):
            for who in ("alice", "bob", "carol"):
                for _ in range(3):
                    rows.append(_alert(half_ts % h, who, 5710, "erp"))
        for h in (10, 12, 15):
            for who in ("alice", "bob", "carol"):
                for _ in range(3):
                    rows.append(_alert(half_ts % h, who, 5710, "crm"))
        # payroll: one service account, middle of the night, its own signature
        for h in (2, 3):
            for _ in range(14):
                rows.append(_alert(half_ts % h, "svc_payroll", 7777, "payroll"))
    # legacy: ordinary early (same crowd/hours as erp), then taken over
    for h in (9, 11):
        for who in ("alice", "bob"):
            for _ in range(8):
                rows.append(_alert(EARLY % h, who, 5710, "legacy"))
    for h in (3, 4):
        for _ in range(16):
            rows.append(_alert(LATE % h, "mallory", 9999, "legacy",
                               verdict="highly_anomalous", score=0.99, sev=12))

    alerts = work / "alerts.jsonl"
    with alerts.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    (work / "agents.json").write_text(json.dumps(
        [{"id": "001", "name": "Access-SRV-2.140", "ip": "10.200.10.5"}]))
    (work / "entities.json").write_text("{}")
    for n in ("false_positives.json", "fp_patterns.json"):
        (work / n).write_text("[]")

    base = yaml.safe_load((ROOT / "ueba_config.yaml").read_text())
    d = base.setdefault("dashboard", {})
    d["alerts_file"] = str(alerts)
    d["agents_registry"] = str(work / "agents.json")
    d["false_positives_file"] = str(work / "false_positives.json")
    arch = work / "archive"
    arch.mkdir(exist_ok=True)
    d["archive_dir"] = str(arch)
    base["archive_dir"] = str(arch)
    base["audit_file"] = str(work / "audit.jsonl")
    d["audit_file"] = str(work / "audit.jsonl")
    p = base.setdefault("paths", {})
    p["entities_file"] = str(work / "entities.json")
    p["audit_file"] = str(work / "audit.jsonl")
    p["profile_db"] = str(work / "profiles.db")
    base.setdefault("auth", {}).update({"enabled": False, "enforce": False})
    cfg = work / "site.yaml"
    cfg.write_text(yaml.safe_dump(base, sort_keys=False))
    return {"cfg": cfg, "raw": base, "n": len(rows)}


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="sn30-"))
    site = build_site(work)

    import ueba_dashboard_server as S
    import ueba_entity_profiles as EP
    S.CFG = S.load_dashboard_config(str(site["cfg"]))
    S.ALERTS_FILE = Path(S.CFG["alerts_file"])
    S.AGENTS_REGISTRY = Path(S.CFG["agents_registry"])
    S._RAW_CFG = site["raw"]
    c = S.app.test_client()

    ok("the profiling module is wired in", S._ENTITY_PROFILES_OK)

    # ── 1. an administrator maps a field of their own choosing ──
    r = c.post("/api/entities/mappings",
               json={"field": "data.appname", "kind": "application_id",
                     "note": "SN 67 demo"})
    ok("the operator can map any field", r.status_code == 200,
       "%d %s" % (r.status_code, r.get_data(as_text=True)[:140]))
    entry = (r.get_json() or {}).get("entry") or {}
    kind = entry.get("kind")
    ok("the kind is namespaced so it cannot collide",
       str(kind).startswith("custom:"), repr(kind))

    # ── 2. the values under it are profiled from live events ──
    r = c.get("/api/entities/kind/%s?hours=0" % kind)
    ok("the per-kind list responds", r.status_code == 200, str(r.status_code))
    body = r.get_json() or {}
    vals = {x["value"]: x for x in body.get("rows") or []}
    ok("every mapped value appears",
       {"erp", "crm", "payroll", "legacy"} <= set(vals), str(sorted(vals)))
    # Found in the stored history, not yet in entity_presence — which the
    # preprocessor only fills as NEW traffic arrives. Marked by source so an
    # operator can tell "already in the history" from "recorded live".
    ok("values found only in history are marked as such",
       all(vals[v]["source"] == "alerts" for v in ("erp", "legacy")),
       str({v: vals[v].get("source") for v in vals}))
    ok("and the two sources are counted",
       (body.get("sources") or {}).get("alerts", 0) >= 4,
       str(body.get("sources")))

    # ── 3. the list carries an ASSESSMENT, not just counts ──
    ok("an assessment block is present", bool(body.get("assessment")),
       str(body.get("assessment_error") or "")[:120])
    a = body.get("assessment") or {}
    ok("it reports how many values were scored", a.get("scored", 0) >= 3,
       str(a.get("scored")))
    ok("and it is not silently truncated", a.get("truncated") is False)
    for v in ("erp", "payroll", "legacy"):
        ok("%s row carries a reason" % v, bool(vals.get(v, {}).get("why")),
           repr(vals.get(v, {}).get("why")))

    rows = {x["value"]: x for x in a.get("rows") or []}

    # ── 4. the two questions disagree, as the fixture intends ──
    def sd(v):
        return (rows.get(v, {}).get("self_drift") or {}).get("score")

    def po(v):
        return (rows.get(v, {}).get("peer_outlier") or {}).get("score")

    ok("legacy changed in itself", sd("legacy") is not None and sd("legacy") > 0.6,
       str(sd("legacy")))
    ok("erp did not change in itself",
       sd("erp") is not None and sd("erp") < 0.2, str(sd("erp")))
    ok("legacy's drift beats erp's", sd("legacy") > sd("erp"))

    ok("payroll is unlike its siblings",
       po("payroll") is not None and po("payroll") > 0.5, str(po("payroll")))
    ok("erp is not unlike its siblings",
       po("erp") is not None and po("erp") < po("payroll"),
       "%s vs %s" % (po("erp"), po("payroll")))

    # THE POINT: payroll is stable but odd; legacy is normal-for-kind but
    # changed. A single blended score could not separate them.
    ok("payroll is stable yet an outlier",
       sd("payroll") < 0.25 and po("payroll") > 0.5,
       "drift=%s peer=%s" % (sd("payroll"), po("payroll")))
    ok("the two scores rank the two values differently",
       (sd("legacy") > sd("payroll")) and (po("payroll") > po("legacy")),
       "drift L=%s P=%s | peer L=%s P=%s"
       % (sd("legacy"), sd("payroll"), po("legacy"), po("payroll")))

    # ── 5. one entity, explained ──
    r = c.get("/api/entities/profile/%s/legacy?hours=0" % kind)
    ok("the single-entity endpoint responds", r.status_code == 200,
       str(r.status_code))
    one = r.get_json() or {}
    ok("it is profiled", one.get("profiled") is True, str(one)[:160])
    ok("both halves are reported",
       (one.get("halves") or {}).get("baseline", 0) > 0
       and (one.get("halves") or {}).get("recent", 0) > 0,
       str(one.get("halves")))
    ok("the accounts that touched it are listed",
       any(x["entity"] == "mallory" for x in one.get("actors") or []),
       str(one.get("actors"))[:140])
    asm = one.get("assessment") or {}
    ok("no single blended score is published", asm.get("score") is None)
    ok("self-drift is explained",
       isinstance((asm.get("self_drift") or {}).get("why"), str))
    dims = (asm.get("self_drift") or {}).get("dimensions") or []
    ok("per-dimension drift is reported", len(dims) >= 3, str(len(dims)))
    actors_dim = [d for d in dims if d["dimension"] == "actors"]
    ok("the actors dimension is present", len(actors_dim) == 1)
    if actors_dim:
        ch = {x["key"]: x for x in actors_dim[0].get("changed") or []}
        ok("the new account is marked as appeared",
           ch.get("mallory", {}).get("appeared") is True, str(ch)[:140])
        ok("and a departed one as stopped",
           any(v.get("stopped") for v in ch.values()), str(ch)[:140])

    # A value that is not in the window answers plainly rather than erroring.
    r = c.get("/api/entities/profile/%s/not-a-real-value?hours=0" % kind)
    ok("an absent value still answers 200", r.status_code == 200)
    nb = r.get_json() or {}
    ok("and says it has no profile", nb.get("profiled") is False)
    ok("with a reason rather than an empty page",
       "no alerts for this value" in (nb.get("note") or ""))

    # ── 6. the feed's real support for the RFP's named kinds ──
    r = c.get("/api/entities")
    ok("the status endpoint responds", r.status_code == 200, str(r.status_code))
    st = r.get_json() or {}
    rk = st.get("recognised_kinds") or {}
    ok("recognised kinds are reported", set(rk) == set(EP.RECOGNISED_KINDS),
       str(sorted(rk)))
    ok("database is named as a kind", "database" in rk)
    ok("business_unit is named as a kind", "business_unit" in rk)
    ok("and this fixture's feed supports neither",
       rk["database"]["supported_by_feed"] is False
       and rk["business_unit"]["supported_by_feed"] is False)
    ok("but candidate fields are offered to the operator",
       len(rk["database"]["candidate_fields"]) > 0)
    ok("and the reason says the mechanism still works",
       "from the next event" in rk["database"]["why"])
    ok("the kinds actually being profiled are listed",
       kind in (st.get("profiled_kinds") or []),
       str(st.get("profiled_kinds")))

    # ── 7. untracking stops it, and does not error ──
    r = c.delete("/api/entities/mappings",
                 json={"field": "data.appname", "kind": kind})
    ok("the mapping can be removed", r.status_code == 200,
       "%d %s" % (r.status_code, r.get_data(as_text=True)[:120]))

    # ── 8. THE CONSOLE CONTRACT ──
    # src/panels/entities.js reads specific key names out of these responses.
    # A renamed key does not raise anywhere: the panel just renders "—" in
    # every cell and looks like a feature that does not work. Markers being
    # present in the built bundle proves the code shipped, not that it can
    # read what the API returns. These assertions are that interface.
    r = c.get("/api/entities/kind/%s?hours=0" % kind)
    rows = (r.get_json() or {}).get("rows") or []
    asmt = (r.get_json() or {}).get("assessment") or {}
    ok("kind rows carry every key the table renders",
       all(all(k in row for k in
               ("value", "events", "entities", "self_drift",
                "peer_outlier", "source"))
           for row in rows),
       str(sorted(rows[0].keys())) if rows else "no rows")
    ok("the assessment carries the keys the header renders",
       all(k in asmt for k in ("values", "scored", "truncated", "cap")),
       str(sorted(asmt.keys())))

    r = c.get("/api/entities/profile/%s/legacy?hours=0" % kind)
    one = r.get_json() or {}
    ok("the profile carries the keys the drill-down renders",
       all(k in one for k in
           ("profiled", "events", "actor_count", "actors", "halves",
            "assessment")),
       str(sorted(one.keys())))
    ok("halves carry both sides", set(one["halves"]) == {"baseline", "recent"},
       str(one.get("halves")))
    ok("actors carry the keys the chips render",
       all(set(a) >= {"entity", "events"} for a in one["actors"]),
       str(one["actors"][:2]))
    asm = one["assessment"]
    ok("the assessment carries both scores and a why",
       all(k in asm for k in ("self_drift", "peer_outlier", "why")),
       str(sorted(asm.keys())))

    # The panel calls dimRows(drift.dimensions, "drift", "stable", "changed")
    # and dimRows(peer.dimensions, "distance", "shared", "unlike"). Those
    # four key names per side are the contract.
    drift = asm["self_drift"] or {}
    ok("self-drift reports comparability", "comparable" in drift)
    if drift.get("comparable"):
        for d in drift["dimensions"]:
            ok("drift dimension %s has the keys the UI reads" % d.get("dimension"),
               all(k in d for k in ("dimension", "measures", "drift",
                                    "stable", "changed")),
               str(sorted(d.keys())))
        ch = [x for dd in drift["dimensions"] for x in dd["changed"]]
        ok("changed entries carry direction flags",
           all(set(x) >= {"key", "appeared", "stopped"} for x in ch),
           str(ch[:1]))

    # peer_outlier for a kind WITH siblings, so the other side is exercised.
    r = c.get("/api/entities/profile/%s/payroll?hours=0" % kind)
    pj = (r.get_json() or {}).get("assessment", {}).get("peer_outlier") or {}
    ok("peer-outlier reports comparability", "comparable" in pj)
    if pj.get("comparable"):
        for d in pj["dimensions"]:
            ok("peer dimension %s has the keys the UI reads" % d.get("dimension"),
               all(k in d for k in ("dimension", "measures", "distance",
                                    "shared", "unlike")),
               str(sorted(d.keys())))

    st2 = (c.get("/api/entities").get_json() or {})
    rk2 = st2.get("recognised_kinds") or {}
    ok("recognised kinds carry the keys the support list renders",
       all(all(k in v for k in
               ("describes", "supported_by_feed", "fields_present"))
           for v in rk2.values()),
       str(sorted(next(iter(rk2.values())).keys())) if rk2 else "none")
    ok("profiled_kinds is a list the chip bar can iterate",
       isinstance(st2.get("profiled_kinds"), list))

    # ── 9. THE OTHER HALF OF THE CONTRACT ──
    # Section 8 proves the API emits the keys. If someone later edits
    # entities.js to read different ones, every assertion above still passes
    # while the panel renders "—" everywhere. So the panel's own key names are
    # read out of the source and checked against the API's. Unusual for a
    # Python test to read JavaScript, but this is precisely the seam that rots
    # silently, and there is no runtime that touches both sides.
    panel = ROOT / "dashboard" / "src" / "panels" / "entities.js"
    if not panel.exists():
        ok("the panel source is present", False, str(panel))
    else:
        src = panel.read_text(encoding="utf-8")
        ok("the panel calls the profile endpoint",
           "/api/entities/profile/" in src)
        ok("the panel calls the per-kind endpoint",
           "/api/entities/kind/" in src)
        # The two dimRows call sites carry the key names per side.
        ok("drift rows are read with the keys the API emits",
           'dimRows(drift.dimensions, "drift", "stable", "changed")' in src,
           "dimRows drift call not found as expected")
        ok("peer rows are read with the keys the API emits",
           'dimRows(peer.dimensions, "distance", "shared", "unlike")' in src,
           "dimRows peer call not found as expected")
        for key in ("self_drift", "peer_outlier", "profiled_kinds",
                    "recognised_kinds", "supported_by_feed", "actor_count",
                    "halves", "truncated"):
            ok("the panel reads %s" % key, key in src)
        ok("the panel renders into the anchor in index.html",
           "set-ent-behaviour" in src)
        idx = ROOT / "dashboard" / "index.html"
        ok("and index.html provides that anchor",
           "set-ent-behaviour" in idx.read_text(encoding="utf-8"))

    total = len(_checks)
    if _failures:
        print("SN 30/67: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("SN 30/67: all %d checks passed" % total)
    print("workdir (safe to delete): %s" % work)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
