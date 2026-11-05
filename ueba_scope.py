#!/usr/bin/env python3
"""
ueba_scope.py
─────────────
CyberSentinel UEBA — scoped administrator authority (RFP SN 7).

  SN 7  The solution should have permission for device admin, subnet admin.

Why scope is ORTHOGONAL to role, and why that is the whole design
─────────────────────────────────────────────────────────────────
ueba_auth's roles are a ladder: viewer < analyst < admin, compared by index so
a route gated on "analyst" also admits "admin". The obvious reading of SN 7 is
to add `device_admin` and `subnet_admin` as rungs on that ladder. That reading
is wrong, and wrong in a way that grants more authority than the requirement
asks for:

  * put device_admin BELOW admin and it inherits every analyst capability over
    the WHOLE estate, which is not "permission for device admin"
  * put it ABOVE analyst and the same problem, one rung up
  * either way the ladder now has a rung that means "admin, but only
    sometimes", and every `role_at_least` comparison in the codebase silently
    acquires a meaning nobody checked

So role and scope are two independent axes:

    ROLE   what you may do          (unchanged: viewer / analyst / admin)
    SCOPE  what you may do it TO    (new: a device set, a subnet, or neither)

An administrator with NO scope is unrestricted, which is exactly today's
behaviour — so nothing changes for existing accounts and there is no
migration. An administrator WITH a scope is a device admin or a subnet admin,
or both at once if the operator wants.

The escalation hole this has to close
─────────────────────────────────────
A scoped admin who can edit scopes can widen their own, and then they are not
scoped at all. That is not a hypothetical: "admin" is the role that manages
users, so the naive implementation hands every device admin the key to their
own cage. Scope administration therefore requires an UNRESTRICTED admin, and
`may_administer_scopes()` is the single predicate that says so. It is tested
directly, because a comment is not an access control.

Two enforcement points, and a list is not a view
────────────────────────────────────────────────
  WRITES  refused with 403 when the target is outside scope.
  READS   out-of-scope rows are ABSENT, not greyed out. A row a scoped admin
          can see the existence of has already leaked the thing the scope was
          meant to withhold — the hostname, the address, the fact that the
          machine exists at all. Filtering in the UI would leave the data in
          the response body for anyone with developer tools.

An empty scope means unrestricted, and that is a decision
─────────────────────────────────────────────────────────
The alternative — empty means "nothing" — is defensible for a capability
system and wrong here, because the stored scope for every existing admin is
empty and flipping the meaning would lock the estate's administrators out of
their own console the moment this shipped. `is_restricted()` exists so the
distinction is always read through one function rather than re-derived from a
truthiness test at each call site.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re

# What a scope may restrict. Deliberately small: the requirement names devices
# and subnets, and a scope language nobody asked for is a liability.
SCOPE_KINDS = ("devices", "subnets")

# A device pattern this permissive matches the whole estate, which means the
# operator has written an unrestricted scope while believing they wrote a
# restricted one. Refused at the point of entry with the reason.
_WIDE_OPEN = ("*", "**", "?*", "*.*")

_MAX_ENTRIES = 512
_MAX_PATTERN_LEN = 253


def _norm_device(v) -> str:
    """A device pattern, lowercased and trimmed.

    Case-folded because the agents disagree about it — the same host arrives as
    DC_DIR_srv, dc_dir_srv and DC_DIR_SRV depending on which one reported it,
    and a scope that matched only one spelling would be a scope with holes.
    """
    return str(v or "").strip().casefold()


def parse_scope(raw) -> dict:
    """{"devices": [...], "subnets": [...], "errors": [...]} from operator input.

    Accepts a dict with either key, or a bare list treated as devices. Every
    rejected entry is reported with the reason rather than dropped, because an
    operator who typed a bad CIDR needs to know their scope is narrower than
    they think.
    """
    out = {"devices": [], "subnets": [], "errors": []}
    if raw is None:
        return out
    if isinstance(raw, (list, tuple)):
        raw = {"devices": list(raw)}
    if not isinstance(raw, dict):
        out["errors"].append("a scope must be an object with 'devices' and/or "
                             "'subnets', or a list of device patterns")
        return out

    seen_d, seen_s = set(), set()
    for v in (raw.get("devices") or []):
        d = _norm_device(v)
        if not d:
            continue
        if len(d) > _MAX_PATTERN_LEN:
            out["errors"].append("device pattern is implausibly long: %.40s…" % d)
            continue
        if d in _WIDE_OPEN:
            out["errors"].append(
                "%r matches every device, which is an unrestricted scope "
                "written as if it were a restricted one. Leave the scope empty "
                "to mean unrestricted." % d)
            continue
        if d not in seen_d:
            seen_d.add(d)
            out["devices"].append(d)

    for v in (raw.get("subnets") or []):
        s = str(v or "").strip()
        if not s:
            continue
        try:
            # strict=False so 10.0.0.5/24 is accepted as 10.0.0.0/24 rather
            # than refused; an operator naming a host inside the subnet they
            # mean is a typo worth absorbing, not worth a rejection.
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as e:
            out["errors"].append("%r is not a valid address or CIDR: %s" % (s, e))
            continue
        if net.prefixlen == 0:
            out["errors"].append(
                "%s covers the entire address space, which is an unrestricted "
                "scope. Leave the scope empty to mean unrestricted." % s)
            continue
        key = str(net)
        if key not in seen_s:
            seen_s.add(key)
            out["subnets"].append(key)

    if len(out["devices"]) + len(out["subnets"]) > _MAX_ENTRIES:
        out["errors"].append("a scope may not exceed %d entries" % _MAX_ENTRIES)
        out["devices"] = out["devices"][:_MAX_ENTRIES]
        out["subnets"] = out["subnets"][:max(0, _MAX_ENTRIES - len(out["devices"]))]
    return out


def is_restricted(scope) -> bool:
    """True when this scope actually restricts anything.

    The one place the empty-means-unrestricted decision is read. Every caller
    goes through here rather than testing truthiness, so the decision cannot
    drift between call sites.
    """
    s = scope or {}
    return bool((s.get("devices") or []) or (s.get("subnets") or []))


def may_administer_scopes(user, scope) -> bool:
    """Whether this user may create or change a scope.

    Requires an UNRESTRICTED admin. A scoped admin who could edit scopes would
    widen their own, and "admin" is precisely the role that manages users — so
    without this predicate every device admin holds the key to their own cage.
    """
    if not user:
        return False
    if str((user or {}).get("role") or "") != "admin":
        return False
    return not is_restricted(scope)


def _device_matches(patterns, device: str) -> str:
    """The pattern that admits this device, or "".

    fnmatch, so an operator can write `dc_*_srv` or `*-lap??`. Exact names are
    the common case and are tried as patterns too, which fnmatch handles.
    """
    d = _norm_device(device)
    if not d:
        return ""
    for p in (patterns or []):
        # The PATTERN is normalised here too, not just the device. It used to
        # be compared as stored, with fnmatchcase against a case-folded
        # device, so a pattern carrying any capital matched nothing at all —
        # and because the gate fails closed, the administrator was simply
        # locked out, with a message reporting the pattern count rather than
        # the mismatch. parse_scope lowercases on the way in, so every scope
        # created through the API was already safe; this closes the gap for a
        # scope written by any other path (a script, a migration, a restored
        # row) and costs one casefold per comparison.
        pn = _norm_device(p)
        if pn == d or fnmatch.fnmatchcase(d, pn):
            return p
    return ""


def _subnet_matches(subnets, address: str) -> str:
    """The subnet containing this address, or ""."""
    a = str(address or "").strip()
    if not a:
        return ""
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return ""
    for s in (subnets or []):
        try:
            if ip in ipaddress.ip_network(s):
                return s
        except ValueError:
            continue
    return ""


def covers(scope, device=None, address=None) -> dict:
    """{"allowed", "why", "matched"} — may this scope act on this target?

    An unrestricted scope allows everything. A restricted scope allows a
    target matched by EITHER axis: a device admin given a device set and a
    subnet is granted both, not their intersection, because the requirement
    names two independent kinds of administrator and an operator who lists
    both means "these machines and that range".

    A target with NEITHER a device nor an address is refused under a restricted
    scope. That is deliberate and it is the conservative direction: an object
    we cannot place in the estate is an object we cannot prove is inside the
    operator's authority, and allowing it would make every unidentifiable row
    a hole in every scope.
    """
    s = scope or {}
    if not is_restricted(s):
        return {"allowed": True, "why": "scope is unrestricted", "matched": ""}

    d = _device_matches(s.get("devices"), device)
    if d:
        return {"allowed": True, "matched": d,
                "why": "device %s matches %r in scope" % (device, d)}
    n = _subnet_matches(s.get("subnets"), address)
    if n:
        return {"allowed": True, "matched": n,
                "why": "address %s is inside %s in scope" % (address, n)}

    if not str(device or "").strip() and not str(address or "").strip():
        return {"allowed": False, "matched": "",
                "why": "the target carries neither a device nor an address, so "
                       "it cannot be placed inside this scope"}
    bits = []
    if device:
        bits.append("device %s" % device)
    if address:
        bits.append("address %s" % address)
    return {"allowed": False, "matched": "",
            "why": "%s is outside this administrator's scope (%d device "
                   "pattern(s), %d subnet(s))"
                   % (" / ".join(bits), len(s.get("devices") or []),
                      len(s.get("subnets") or []))}


def filter_rows(scope, rows, device_keys=("device", "agent", "host", "name"),
                address_keys=("ip", "address", "host_ip")) -> list:
    """The rows this scope may see. Out-of-scope rows are ABSENT.

    Absent rather than flagged: a row whose existence a scoped admin can see
    has already leaked the hostname, the address, or the fact that the machine
    exists — which is the thing the scope was meant to withhold. Filtering in
    the browser would leave it all in the response body.
    """
    if not is_restricted(scope):
        return list(rows or [])
    out = []
    for row in (rows or []):
        if not isinstance(row, dict):
            continue
        dev = next((row[k] for k in device_keys
                    if row.get(k) not in (None, "")), "")
        addr = next((row[k] for k in address_keys
                     if row.get(k) not in (None, "")), "")
        if covers(scope, dev, addr)["allowed"]:
            out.append(row)
    return out


def describe(scope) -> str:
    """One sentence an operator can check their intent against."""
    s = scope or {}
    if not is_restricted(s):
        return "unrestricted — this administrator may act on the whole estate"
    bits = []
    d, n = s.get("devices") or [], s.get("subnets") or []
    if d:
        bits.append("%d device pattern%s (%s%s)"
                    % (len(d), "" if len(d) == 1 else "s",
                       ", ".join(d[:4]), ", …" if len(d) > 4 else ""))
    if n:
        bits.append("%d subnet%s (%s%s)"
                    % (len(n), "" if len(n) == 1 else "s",
                       ", ".join(n[:4]), ", …" if len(n) > 4 else ""))
    return "restricted to " + " and ".join(bits)


def label(scope) -> str:
    """A short role label for the console: what KIND of admin this is."""
    s = scope or {}
    if not is_restricted(s):
        return "admin"
    d, n = bool(s.get("devices")), bool(s.get("subnets"))
    if d and n:
        return "device+subnet admin"
    return "device admin" if d else "subnet admin"


def status() -> dict:
    return {
        "kinds": list(SCOPE_KINDS),
        "model_note": (
            "Scope is ORTHOGONAL to role, not another rung on the "
            "viewer/analyst/admin ladder. Role says what an account may do; "
            "scope says what it may do it to. An admin with no scope is "
            "unrestricted, which is the existing behaviour, so no account "
            "changes and nothing migrates. Adding device_admin as a rung "
            "instead would have granted admin-level authority over the whole "
            "estate, which is more than the requirement asks for."),
        "escalation_note": (
            "Scope administration requires an UNRESTRICTED admin. A scoped "
            "admin who could edit scopes would widen their own, and admin is "
            "the role that manages users — so without that rule every device "
            "admin holds the key to their own cage."),
        "filtering_note": (
            "Out-of-scope rows are absent from responses, not marked. A row "
            "whose existence is visible has already leaked the hostname or "
            "address the scope was meant to withhold, and filtering in the "
            "browser would leave it in the response body."),
    }


# ── selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    failures = []
    checked = []

    def ok(label_, cond):
        # Counted, not a literal. This module kept `total = 86` while the other
        # suites were converted, so the five checks added for the pattern-case
        # trap ran and were not reported — the number stayed 86 either way.
        checked.append(label_)
        if not cond:
            failures.append(label_)

    # ── parsing ──
    s = parse_scope({"devices": ["DC_DIR_srv", "app-srv-*"],
                     "subnets": ["10.0.0.0/24", "192.168.1.5/24"]})
    ok("device patterns are folded", s["devices"][0] == "dc_dir_srv")
    ok("a wildcard pattern survives", "app-srv-*" in s["devices"])
    ok("a cidr is normalised", "10.0.0.0/24" in s["subnets"])
    ok("a host address inside a cidr is absorbed to the network",
       "192.168.1.0/24" in s["subnets"])
    ok("no errors on good input", s["errors"] == [])

    ok("a bare list is read as devices",
       parse_scope(["a", "b"])["devices"] == ["a", "b"])
    ok("None parses to an empty scope", parse_scope(None)["devices"] == [])
    ok("a string is refused with a reason",
       parse_scope("dc_srv")["errors"] != [])
    ok("duplicates collapse",
       parse_scope({"devices": ["a", "A", "a"]})["devices"] == ["a"])
    ok("blank entries are skipped",
       parse_scope({"devices": ["", "  ", "a"]})["devices"] == ["a"])

    bad = parse_scope({"subnets": ["not-a-cidr", "10.0.0.0/99"]})
    ok("a bad cidr is refused", len(bad["errors"]) == 2)
    ok("and is named in the error", "not-a-cidr" in bad["errors"][0])
    ok("and is not silently kept", bad["subnets"] == [])

    for pat in _WIDE_OPEN:
        w = parse_scope({"devices": [pat]})
        ok("a match-everything pattern is refused: %r" % pat, w["errors"] != [])
        ok("and is not stored: %r" % pat, w["devices"] == [])
    ok("the refusal explains the empty-scope convention",
       "Leave the scope empty" in parse_scope({"devices": ["*"]})["errors"][0])
    z = parse_scope({"subnets": ["0.0.0.0/0"]})
    ok("a zero-prefix subnet is refused", z["subnets"] == [] and z["errors"])
    ok("an ipv6 default route is refused too",
       parse_scope({"subnets": ["::/0"]})["subnets"] == [])
    ok("an over-long pattern is refused",
       parse_scope({"devices": ["a" * 300]})["devices"] == [])
    big = parse_scope({"devices": ["d%d" % i for i in range(600)]})
    ok("an oversized scope is capped",
       len(big["devices"]) <= _MAX_ENTRIES and big["errors"])

    # ── restricted vs unrestricted ──
    ok("an empty scope is unrestricted", not is_restricted({}))
    ok("None is unrestricted", not is_restricted(None))
    ok("empty lists are unrestricted",
       not is_restricted({"devices": [], "subnets": []}))
    ok("a device scope is restricted", is_restricted({"devices": ["a"]}))
    ok("a subnet scope is restricted", is_restricted({"subnets": ["10.0.0.0/8"]}))

    # ── covers ──
    unres = {}
    ok("unrestricted allows a device", covers(unres, "anything")["allowed"])
    ok("unrestricted allows an address", covers(unres, None, "8.8.8.8")["allowed"])
    ok("unrestricted allows an unidentifiable target",
       covers(unres)["allowed"])
    ok("and says it is unrestricted", "unrestricted" in covers(unres)["why"])

    dev = {"devices": ["dc_dir_srv", "app-srv-*"]}
    ok("an exact device is allowed", covers(dev, "DC_DIR_srv")["allowed"])
    ok("case does not matter", covers(dev, "dc_dir_SRV")["allowed"])
    ok("a wildcard device is allowed", covers(dev, "APP-SRV-07")["allowed"])
    ok("the matching pattern is reported",
       covers(dev, "app-srv-07")["matched"] == "app-srv-*")

    # ── a pattern carrying CAPITALS ──
    # The fixture above is already lowercase, which is why this went unnoticed:
    # parse_scope folds patterns on the way in, so an API-created scope was
    # always safe. A scope stored by any other path (a script, a migration, a
    # restored row) kept its capitals and matched NOTHING — and since the gate
    # fails closed, that locked the administrator out of their own devices,
    # reporting only how many patterns existed. Found by the SN 7 end-to-end
    # harness, which seeded set_scope directly.
    raw_upper = {"devices": ["Access-SRV-2.140", "DC_*"], "subnets": []}
    ok("an unparsed exact pattern still matches",
       covers(raw_upper, "Access-SRV-2.140")["allowed"])
    ok("an unparsed wildcard still matches",
       covers(raw_upper, "DC_AD_srv")["allowed"])
    ok("and the device's own case still does not matter",
       covers(raw_upper, "dc_ad_SRV")["allowed"])
    # The direction that matters: folding patterns must not widen the scope.
    ok("a non-member is still refused",
       not covers(raw_upper, "lab-box-7")["allowed"])
    ok("and so is a device from another range",
       not covers(raw_upper, "far-host")["allowed"])
    ok("the reason names the device", "app-srv-07" in covers(dev, "app-srv-07")["why"])
    out = covers(dev, "laptop-a")
    ok("an unlisted device is refused", not out["allowed"])
    ok("the refusal says it is outside scope", "outside" in out["why"])
    ok("and counts what the scope holds", "2 device pattern" in out["why"])
    ok("a partial name does not match", not covers(dev, "dc_dir")["allowed"])
    ok("a superstring does not match", not covers(dev, "xdc_dir_srvx")["allowed"])

    net = {"subnets": ["10.0.5.0/24", "2001:db8::/32"]}
    ok("an address inside the subnet is allowed",
       covers(net, None, "10.0.5.17")["allowed"])
    ok("the subnet is reported",
       covers(net, None, "10.0.5.17")["matched"] == "10.0.5.0/24")
    ok("an address outside it is refused",
       not covers(net, None, "10.0.6.17")["allowed"])
    ok("an ipv6 address inside the subnet is allowed",
       covers(net, None, "2001:db8::1")["allowed"])
    ok("a malformed address is refused rather than crashing",
       not covers(net, None, "not-an-ip")["allowed"])

    both = {"devices": ["dc_*"], "subnets": ["10.0.5.0/24"]}
    ok("either axis admits: device side", covers(both, "dc_dir")["allowed"])
    ok("either axis admits: subnet side",
       covers(both, "laptop-a", "10.0.5.1")["allowed"])
    ok("neither axis matching is refused",
       not covers(both, "laptop-a", "10.9.9.9")["allowed"])
    # The decisive conservative case.
    nowhere = covers(both)
    ok("a target with no device and no address is refused under a scope",
       not nowhere["allowed"])
    ok("and the reason says it cannot be placed",
       "cannot be placed" in nowhere["why"])

    # ── escalation guard ──
    admin = {"role": "admin"}
    analyst = {"role": "analyst"}
    viewer = {"role": "viewer"}
    ok("an unrestricted admin may administer scopes",
       may_administer_scopes(admin, {}))
    ok("a SCOPED admin may NOT administer scopes",
       not may_administer_scopes(admin, {"devices": ["dc_*"]}))
    ok("a scoped admin with only a subnet may not either",
       not may_administer_scopes(admin, {"subnets": ["10.0.0.0/8"]}))
    ok("an analyst may not", not may_administer_scopes(analyst, {}))
    ok("a viewer may not", not may_administer_scopes(viewer, {}))
    ok("no user may not", not may_administer_scopes(None, {}))
    ok("a user with no role may not", not may_administer_scopes({}, {}))

    # ── row filtering ──
    rows = [
        {"device": "dc_dir_srv", "ip": "10.0.5.1"},
        {"device": "app-srv-07", "ip": "10.0.9.1"},
        {"device": "laptop-a", "ip": "10.0.9.2"},
        {"device": "laptop-b", "ip": "10.0.5.99"},
        {"device": "", "ip": ""},
    ]
    ok("an unrestricted scope sees every row",
       len(filter_rows({}, rows)) == 5)
    seen = filter_rows({"devices": ["dc_*", "app-srv-*"]}, rows)
    ok("only matching devices survive", len(seen) == 2)
    ok("the out-of-scope rows are absent, not marked",
       all(r["device"].startswith(("dc_", "app-srv-")) for r in seen))
    seen = filter_rows({"subnets": ["10.0.5.0/24"]}, rows)
    ok("the subnet filter admits by address", len(seen) == 2)
    ok("and includes a row whose device is out of scope but address is in",
       any(r["device"] == "laptop-b" for r in seen))
    ok("a row with neither key is dropped under a scope",
       not any(r["device"] == "" for r in filter_rows({"devices": ["dc_*"]}, rows)))
    ok("alternative key names are honoured",
       len(filter_rows({"devices": ["h1"]}, [{"host": "h1"}, {"host": "h2"}])) == 1)
    ok("an address under an alternative key is honoured",
       len(filter_rows({"subnets": ["10.1.0.0/16"]},
                       [{"address": "10.1.2.3"}, {"address": "10.2.2.3"}])) == 1)
    ok("non-dict rows are dropped rather than raising",
       filter_rows({"devices": ["a"]}, ["nope", None]) == [])
    ok("an empty row list is empty", filter_rows({"devices": ["a"]}, []) == [])
    ok("None rows are empty", filter_rows({}, None) == [])

    # ── describe and label ──
    ok("unrestricted describes itself", "unrestricted" in describe({}))
    ok("a device scope describes its count",
       "1 device pattern" in describe({"devices": ["a"]}))
    ok("plurals are handled",
       "2 device patterns" in describe({"devices": ["a", "b"]}))
    ok("a long list is truncated with an ellipsis",
       "…" in describe({"devices": ["d%d" % i for i in range(9)]}))
    ok("both axes are described",
       " and " in describe({"devices": ["a"], "subnets": ["10.0.0.0/8"]}))
    ok("an unrestricted admin is labelled admin", label({}) == "admin")
    ok("a device scope is labelled device admin",
       label({"devices": ["a"]}) == "device admin")
    ok("a subnet scope is labelled subnet admin",
       label({"subnets": ["10.0.0.0/8"]}) == "subnet admin")
    ok("both is labelled both",
       label({"devices": ["a"], "subnets": ["10.0.0.0/8"]})
       == "device+subnet admin")

    # ── status ──
    st = status()
    ok("status explains the orthogonality", "ORTHOGONAL" in st["model_note"])
    ok("status explains the escalation rule",
       "key to their own cage" in st["escalation_note"])
    ok("status explains why rows are absent",
       "response body" in st["filtering_note"])
    ok("status lists the kinds", st["kinds"] == list(SCOPE_KINDS))

    total = len(checked)
    if failures:
        print("ueba_scope selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_scope selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
