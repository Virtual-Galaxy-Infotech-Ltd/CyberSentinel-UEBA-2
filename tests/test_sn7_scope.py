#!/usr/bin/env python3
"""RFP SN 7 — scoped administrator authority, end-to-end.

Sub-points 7-10 of story 2.4 ask for something the unit tests in ueba_scope.py
cannot give: sign in AS each role, attempt what it must not reach, and show
that lists omit out-of-scope rows rather than greying them. This drives the
REAL Flask routes with REAL server-side sessions.

Isolated by construction. Every path points into a temp directory built here:
a synthetic alert file, a synthetic agent registry, a fresh auth DB. Nothing
reads or writes production data, and the estate below is invented so the
in-scope / out-of-scope cases are clean rather than whatever the live feed
happens to contain today.

THE ESTATE, chosen to separate the two scope axes:

    device              address        in admin_dev?   in admin_net?
    DC_AD_srv           10.200.10.5    yes (DC_*)      yes (10.200.10.0/24)
    Access-SRV-2.140    10.200.11.40   yes (explicit)  NO  (wrong subnet)
    lab-box-7           10.200.10.77   NO              yes
    far-host            192.168.99.9   NO              NO

The second and third rows are the point. A device-scoped admin and a
subnet-scoped admin must each be able to reach one of them and not the other,
which a single-axis estate cannot demonstrate.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
# UEBA_ROOT lets the harness run against an installation it does not live
# inside, so a deployed box can be verified without copying test files into it.
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

ESTATE = [
    ("DC_AD_srv",        "10.200.10.5"),
    ("Access-SRV-2.140", "10.200.11.40"),
    ("lab-box-7",        "10.200.10.77"),
    ("far-host",         "192.168.99.9"),
]

SCOPES = {
    "admin_dev": {"devices": ["Access-SRV-2.140", "DC_*"], "subnets": []},
    "admin_net": {"devices": [], "subnets": ["10.200.10.0/24"]},
}

ACCOUNTS = [
    ("viewer",     "zz_viewer", "viewer",  None),
    ("analyst",    "zz_analyst", "analyst", None),
    ("admin_full", "zz_admin",   "admin",   None),
    ("admin_dev",  "zz_devadm",  "admin",   SCOPES["admin_dev"]),
    ("admin_net",  "zz_netadm",  "admin",   SCOPES["admin_net"]),
]

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


def _alert(device, ip, user, score=0.8):
    return {
        "event_time": "2026-11-04T10:00:00+05:30",
        "host": {"name": device, "ip": ip, "os": {"family": "windows"}},
        "user": {"name": user},
        "security": {"signature_id": "5710", "signature": "probe", "severity": 5},
        "ueba": {
            "combined_score": score,
            "risk_verdict": "HIGH" if score >= 0.7 else "LOW",
            "anomaly_reasons": ["synthetic"],
            "processed_at": "2026-11-04T10:00:00+05:30",
            "model_used": "global",
        },
    }


def build_site(work: Path) -> dict:
    """A complete, self-contained site config in `work`."""
    alerts = work / "alerts.jsonl"
    with alerts.open("w") as fh:
        for device, ip in ESTATE:
            for i in range(3):
                fh.write(json.dumps(_alert(device, ip, "person%d" % i)) + "\n")

    registry = work / "agents.json"
    registry.write_text(json.dumps(
        [{"id": "%03d" % n, "name": d, "ip": ip}
         for n, (d, ip) in enumerate(ESTATE, 1)]))

    devices_file = work / "devices.json"
    devices_file.write_text("[]")
    for name in ("entities.json", "rules.json", "watchlist.json",
                 "privileged.json", "assets.json", "nicknames.json",
                 "false_positives.json", "fp_patterns.json"):
        (work / name).write_text("[]" if name != "entities.json" else "{}")

    base = yaml.safe_load((ROOT / "ueba_config.yaml").read_text())
    d = base.setdefault("dashboard", {})
    d["alerts_file"] = str(alerts)
    d["agents_registry"] = str(registry)
    d["false_positives_file"] = str(work / "false_positives.json")
    d["host"], d["port"] = "127.0.0.1", 0
    # ISOLATION, and not optional. load_alerts() spans the live file AND the
    # archive, so redirecting only alerts_file leaves the archive pointing at
    # production. Run against .23 that pulled 21 real hostnames into the
    # fixture and produced six failures that looked like scope leaks and were
    # actually correct filtering of data that should never have been in the
    # test. An empty temp archive is what makes the estate above the whole
    # estate.
    archive = work / "archive"
    archive.mkdir(exist_ok=True)
    d["archive_dir"] = str(archive)
    base["archive_dir"] = str(archive)
    p = base.setdefault("paths", {})
    for key, val in (("entities_file", work / "entities.json"),
                     ("rules_file", work / "rules.json"),
                     ("watchlist_file", work / "watchlist.json"),
                     ("privileged_file", work / "privileged.json"),
                     ("assets_file", work / "assets.json"),
                     ("nicknames_file", work / "nicknames.json"),
                     ("devices_file", work / "devices.json")):
        p[key] = str(val)
    # The audit trail defaults to a production path; point it into the temp
    # directory or every write logs "Read-only file system: '/root'".
    base["audit_file"] = str(work / "audit.jsonl")
    base.setdefault("dashboard", {})["audit_file"] = str(work / "audit.jsonl")
    p["audit_file"] = str(work / "audit.jsonl")
    a = base.setdefault("auth", {})
    a.update({"enabled": True, "enforce": True, "cookie_secure": False,
              "auth_db": str(work / "auth.db")})
    n = base.setdefault("notify", {})
    n["devices_file"] = str(devices_file)
    cfg_path = work / "site.yaml"
    cfg_path.write_text(yaml.safe_dump(base, sort_keys=False))
    return {"cfg_path": cfg_path, "raw": base, "work": work}


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="sn7-"))
    site = build_site(work)
    raw = site["raw"]

    import ueba_auth

    # Accounts exist BEFORE init_auth, or enforce=True refuses to boot with
    # nobody able to log in — which is itself correct behaviour.
    store = ueba_auth.AuthStore(raw["auth"]["auth_db"])
    subs = {}
    for key, username, role, scope in ACCOUNTS:
        sub = ueba_auth.local_sub(username)
        store.upsert_user(sub, username, "%s@test.local" % username, username, role)
        if scope:
            # Seeded through parse_scope, NOT with the raw dict, because that is
            # what POST /api/scopes does before storing. Writing the raw dict
            # here produced three false failures: patterns are matched with
            # fnmatchcase against a case-folded device, so an unparsed
            # `DC_*` matches nothing and a device admin looked locked out of
            # its own scope. The product was right; the harness was lying.
            import ueba_scope as _z
            parsed = _z.parse_scope(scope)
            assert not parsed["errors"], parsed["errors"]
            store.set_scope(sub, {"devices": parsed["devices"],
                                  "subnets": parsed["subnets"]})
        subs[key] = sub
        # Every account gets a password, because init_auth REFUSES to start
        # enforcing when nobody could log in — SSO needs PyJWT, which is not a
        # hard dependency here. That guard is correct behaviour, so the harness
        # satisfies it rather than disabling it. The value is throwaway and the
        # DB is deleted with the temp directory.
        store.set_password(sub, "Harness-Only-%s-9f2" % key)
    con = sqlite3.connect(raw["auth"]["auth_db"])
    for key, username, role, scope in ACCOUNTS:
        con.execute("UPDATE users SET role=?, role_pinned=1 WHERE sub=?",
                    (role, subs[key]))
    con.commit()
    con.close()

    store2 = ueba_auth.AuthStore(raw["auth"]["auth_db"])
    tokens = {k: store2.create_session(subs[k], 3600, "127.0.0.1", "sn7")
              for k in subs}

    import ueba_dashboard_server as S
    S.CFG = S.load_dashboard_config(str(site["cfg_path"]))
    S.ALERTS_FILE = Path(S.CFG["alerts_file"])
    S.AGENTS_REGISTRY = Path(S.CFG["agents_registry"])
    S._RAW_CFG = raw
    eff = ueba_auth.init_auth(S.app, raw)
    cookie = eff.get("cookie_name", "ueba_session")
    ok("auth enforces in the harness", bool(eff.get("enforce")))

    client = S.app.test_client()

    def as_role(who):
        client.set_cookie(cookie, tokens[who], domain="localhost")

    def clear():
        client.delete_cookie(cookie, domain="localhost")

    def get(path):
        return client.get(path)

    def post(path, body):
        return client.post(path, json=body)

    def allowed(resp):
        return resp.status_code not in (401, 403)

    print("=" * 78)
    print("SN 7 — scoped administrator authority")
    print("=" * 78)

    # ── 1. the capability ladder still holds ──
    for who, may_write_config in (("viewer", False), ("analyst", False),
                                  ("admin_full", True)):
        as_role(who)
        r = post("/api/entities/hosts", {"host": "DC_AD_srv", "role": "server"})
        ok("%s %s set a host role" % (who, "may" if may_write_config else "may not"),
           allowed(r) == may_write_config, "status %d" % r.status_code)
        clear()

    # ── 2. in-scope writes are ALLOWED (the half my first pass got wrong) ──
    # A scoped admin that cannot act inside its own scope is not restricted,
    # it is broken. This is the positive case the requirement asks for.
    for who, device in (("admin_dev", "DC_AD_srv"),
                        ("admin_dev", "Access-SRV-2.140"),
                        ("admin_net", "DC_AD_srv")):
        as_role(who)
        r = post("/api/entities/hosts", {"host": device, "role": "server"})
        ok("%s may write IN scope (%s)" % (who, device), allowed(r),
           "status %d body %s" % (r.status_code, r.get_data(as_text=True)[:120]))
        clear()

    # ── 3. out-of-scope writes are REFUSED ──
    for who, device in (("admin_dev", "lab-box-7"),
                        ("admin_dev", "far-host"),
                        ("admin_net", "Access-SRV-2.140"),
                        ("admin_net", "far-host")):
        as_role(who)
        r = post("/api/entities/hosts", {"host": device, "role": "server"})
        ok("%s refused OUT of scope (%s)" % (who, device),
           r.status_code == 403, "status %d" % r.status_code)
        if r.status_code == 403:
            body = r.get_json() or {}
            ok("  ...and the refusal explains why (%s/%s)" % (who, device),
               bool(body.get("detail")), repr(body)[:120])
        clear()

    # ── 4. an unrestricted admin is unaffected ──
    as_role("admin_full")
    for device, _ip in ESTATE:
        r = post("/api/entities/hosts", {"host": device, "role": "server"})
        ok("admin_full may write anywhere (%s)" % device, allowed(r),
           "status %d" % r.status_code)
    clear()

    # ── 5. lists OMIT out-of-scope rows, they are not greyed out ──
    expected = {
        "admin_full": {d for d, _ in ESTATE},
        "admin_dev":  {"DC_AD_srv", "Access-SRV-2.140"},
        "admin_net":  {"DC_AD_srv", "lab-box-7"},
    }
    for who, want in expected.items():
        as_role(who)
        r = get("/api/device?hours=0")
        if not ok("%s can read the device list" % who, r.status_code == 200,
                  "status %d" % r.status_code):
            clear()
            continue
        got = {row["device"] for row in (r.get_json() or {}).get("devices", [])}
        ok("%s sees exactly its scope" % who, got == want,
           "got %s want %s" % (sorted(got), sorted(want)))
        ok("%s sees no out-of-scope row at all" % who, not (got - want),
           "leaked %s" % sorted(got - want))
        clear()

    # ── 6. scope administration needs an UNRESTRICTED admin (escalation guard) ──
    as_role("admin_dev")
    r = post("/api/scopes", {"sub": subs["viewer"],
                             "scope": {"devices": ["*"], "subnets": []}})
    ok("a scoped admin may NOT assign scopes", r.status_code == 403,
       "status %d" % r.status_code)
    clear()
    as_role("admin_full")
    r = get("/api/scopes")
    ok("an unrestricted admin may review scopes", r.status_code == 200,
       "status %d" % r.status_code)
    if r.status_code == 200:
        ok("and it reports who may administer them",
           (r.get_json() or {}).get("may_administer") is True)
    clear()

    # ── 7. the two admin READS that were open to everyone ──
    # Found by the first run of this harness: both served a viewer while the
    # console hid their panels behind an admin capability.
    for who, want_allowed in (("viewer", False), ("analyst", False),
                              ("admin_full", True)):
        as_role(who)
        for path in ("/api/entities", "/api/scopes"):
            r = get(path)
            ok("%s %s read %s" % (who, "may" if want_allowed else "may NOT", path),
               allowed(r) == want_allowed, "status %d" % r.status_code)
        clear()

    # ── 8. the last-administrator guard still holds ──
    # Run BEFORE the escalation probe on purpose. When the escalation ran
    # first it created a second admin, the count never reached one, and the
    # guard looked broken when it had simply never been reached — two of the
    # four failures in the first pass were that artefact, not a defect.
    as_role("admin_full")
    for who in ("admin_dev", "admin_net"):
        rr = client.patch("/api/auth/users/%s" % subs[who], json={"role": "viewer"})
        ok("an unrestricted admin may demote %s" % who, allowed(rr),
           "status %d" % rr.status_code)
    r = client.patch("/api/auth/users/%s" % subs["admin_full"], json={"role": "viewer"})
    ok("demoting the last admin is refused", r.status_code == 409,
       "status %d" % r.status_code)
    r = client.delete("/api/auth/users/%s" % subs["admin_full"])
    ok("deleting the last admin is refused", r.status_code == 409,
       "status %d" % r.status_code)
    clear()
    # restore the two scoped admins for the escalation probe
    for who in ("admin_dev", "admin_net"):
        store2.update_user(subs[who], role="admin")

    # ── 9. ESCALATION: can a scoped admin manufacture an unscoped one? ──
    # POST /api/scopes is guarded by _may_administer_scopes(), so a scoped
    # admin cannot widen its own scope directly. Account management was the
    # second door to the same room: a new account is created with NO scope,
    # and no scope means unrestricted.
    as_role("admin_dev")
    r = post("/api/auth/users", {"username": "zz_escalated", "role": "admin",
                                 "password": "Escalate-Attempt-7k2"})
    ok("a scoped admin may NOT create an admin account", r.status_code == 403,
       "status %d body %s" % (r.status_code, r.get_data(as_text=True)[:140]))
    r2 = client.patch("/api/auth/users/%s" % subs["viewer"], json={"role": "admin"})
    ok("a scoped admin may NOT promote an account", r2.status_code == 403,
       "status %d" % r2.status_code)
    r3 = client.delete("/api/auth/users/%s" % subs["analyst"])
    ok("a scoped admin may NOT delete an account", r3.status_code == 403,
       "status %d" % r3.status_code)
    if r.status_code == 403:
        ok("and the refusal names the scope that blocked it",
           "scope" in (r.get_json() or {}).get("error", "").lower()
           or "limited to" in (r.get_json() or {}).get("error", "").lower(),
           repr(r.get_json())[:140])
    clear()
    # An unrestricted admin must still be able to do all three.
    as_role("admin_full")
    r = post("/api/auth/users", {"username": "zz_ok_new", "role": "analyst",
                                 "password": "Legit-Account-5m8"})
    ok("an unrestricted admin may still create accounts", allowed(r),
       "status %d" % r.status_code)
    clear()

    # ── 10. unauthenticated gets nothing ──
    r = get("/api/device?hours=0")
    ok("no session is refused", r.status_code in (401, 403),
       "status %d" % r.status_code)

    # ── sub-point 10: the role-by-screen matrix, as an artefact ──
    rows = []
    PROBES = [
        ("read the device list",      "GET",  "/api/device?hours=0",  None),
        ("read tracked entities",     "GET",  "/api/entities",        None),
        ("review scopes",             "GET",  "/api/scopes",          None),
        ("read the audit trail",      "GET",  "/api/audit",           None),
        ("set a host role (in)",      "POST", "/api/entities/hosts",  {"host": "DC_AD_srv", "role": "server"}),
        ("set a host role (out)",     "POST", "/api/entities/hosts",  {"host": "far-host", "role": "server"}),
        ("assign a scope",            "POST", "/api/scopes",          {"sub": subs["viewer"], "scope": {"devices": ["X"], "subnets": []}}),
        ("create an account",         "POST", "/api/auth/users",      {"username": "zz_matrix", "role": "viewer", "password": "Matrix-Probe-3k9"}),
    ]
    for who in ("viewer", "analyst", "admin_dev", "admin_net", "admin_full"):
        as_role(who)
        row = {"role": who}
        for label, method, path, body in PROBES:
            rr = get(path) if method == "GET" else post(path, body)
            row[label] = "allow" if allowed(rr) else "deny (%d)" % rr.status_code
        rows.append(row)
        clear()

    out = Path(__file__).resolve().parent / "sn7_role_matrix.md"
    with out.open("w") as fh:
        fh.write("# RFP SN 7 — role-by-screen matrix\n\n")
        fh.write("Generated by `tests/test_sn7_scope.py` against the real Flask\n")
        fh.write("routes with real server-side sessions, on synthetic data.\n\n")
        fh.write("Scopes under test: `admin_dev` = devices "
                 "`Access-SRV-2.140`, `DC_*`; `admin_net` = subnet "
                 "`10.200.10.0/24`.\n")
        fh.write("`DC_AD_srv` (10.200.10.5) is inside both; `far-host` "
                 "(192.168.99.9) is inside neither.\n\n")
        heads = [p[0] for p in PROBES]
        fh.write("| role | " + " | ".join(heads) + " |\n")
        fh.write("|" + "---|" * (len(heads) + 1) + "\n")
        for row in rows:
            fh.write("| `%s` | " % row["role"]
                     + " | ".join(row[h] for h in heads) + " |\n")
        fh.write("\nEvery cell is an observed HTTP outcome, not a design "
                 "intention.\n")
    print("matrix written to %s" % out)

    total = len(_checks)
    if _failures:
        print("SN 7: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("SN 7: all %d checks passed" % total)
    print("workdir (safe to delete): %s" % work)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
