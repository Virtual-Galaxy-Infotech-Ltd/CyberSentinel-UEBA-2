#!/usr/bin/env python3
"""
ueba_egress.py
──────────────
CyberSentinel UEBA — one gate that decides whether any byte may leave the box.

RFP SN 64 asks for an on-premises deployment: the customer's behavioural data,
usernames and alert contents must not reach a third party. Saying "we don't
call out" is not an answer an auditor can check, and until this module existed
it was not even true by default. Two outbound paths shipped:

  1. the AI-analyst helper, which POSTs alert context to an external LLM API.
     Its config default was `enabled: true`; the only thing standing between a
     fresh install and live egress was an unset API key. An operator exporting
     that key for an unrelated reason silently opened the path.

  2. notification webhooks, which POST alert bodies to any http(s) URL an
     operator types. The sole validation was that the string began with http.
     Nothing stopped a rule pointing at an internet host.

Both now ask this module first, and this module is deny-by-default. Four modes:

  deny         no outbound connections at all.
  on_premises  DEFAULT. Private, loopback and link-local destinations only —
               so the SOC's own SMTP relay and ticketing webhook keep working
               with no configuration — plus anything explicitly allowlisted.
  allowlist    nothing but the explicit allowlist.
  open         unrestricted. Must be set deliberately; the dashboard reports
               it as a compliance exception rather than a normal state.

A destination clears the gate only if EVERY address its hostname resolves to
clears it. Resolution failure blocks: a name that cannot be checked is not
assumed safe. Allowlisted hostnames skip the address check, because pinning a
public host is the operator's explicit decision, not an accident.

The gate is advisory in one honest respect: it governs the product's own
outbound calls, not the machine's. It is a correctness control over what this
software does, not a firewall. Site-level egress filtering stays the customer's
job and the deployment guide still says so.
"""

import ipaddress
import os
import socket
from urllib.parse import urlsplit

MODES = ("deny", "on_premises", "allowlist", "open")
DEFAULT_MODE = "on_premises"


class EgressBlocked(Exception):
    """Raised when a destination is not permitted by policy."""

    def __init__(self, url, reason):
        super().__init__(reason)
        self.url = url
        self.reason = reason


def _host_of(url):
    """Hostname from a URL, lowercased, brackets stripped from IPv6 literals."""
    parts = urlsplit(url if "//" in url else "//" + url)
    host = (parts.hostname or "").strip().lower()
    return host.strip("[]")


def _as_ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _is_internal(ip):
    """True for addresses that cannot leave the customer's own network."""
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
    )


def _resolve(host):
    """Every address a hostname resolves to. Empty list on failure."""
    ip = _as_ip(host)
    if ip is not None:
        return [ip]
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    out = []
    for info in infos:
        addr = _as_ip(info[4][0])
        if addr is not None and addr not in out:
            out.append(addr)
    return out


class EgressPolicy:
    """An immutable outbound-destination policy."""

    def __init__(self, mode=DEFAULT_MODE, allow=None):
        mode = (mode or "").strip().lower().replace("-", "_") or DEFAULT_MODE
        if mode not in MODES:
            raise ValueError(
                "egress.mode must be one of %s, got %r" % (", ".join(MODES), mode)
            )
        self.mode = mode
        self.allow = tuple(
            e.strip().lower() for e in (allow or []) if isinstance(e, str) and e.strip()
        )

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, cfg):
        """Build from the `egress:` config block. Absent block means default."""
        block = (cfg or {}).get("egress") or {}
        if not isinstance(block, dict):
            block = {}
        env_mode = os.environ.get("UEBA_EGRESS_MODE", "").strip()
        return cls(
            mode=env_mode or block.get("mode", DEFAULT_MODE),
            allow=block.get("allow") or block.get("allowlist") or [],
        )

    # ── matching ────────────────────────────────────────────────────────────

    def _allow_match(self, host, addrs):
        """The allowlist entry permitting this destination, or None.

        Entries may be an exact hostname, a `*.suffix` wildcard, a bare IP, or
        a CIDR. IP and CIDR entries are tested against the resolved addresses.
        """
        for entry in self.allow:
            if entry == host:
                return entry
            if entry.startswith("*.") and host.endswith(entry[1:]):
                return entry
            net = None
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                pass
            if net is not None and addrs:
                if all(a.version == net.version and a in net for a in addrs):
                    return entry
        return None

    def check(self, url):
        """Raise EgressBlocked unless `url` is a permitted destination.

        Returns a short string naming why it was permitted, for the audit log.
        """
        host = _host_of(url)
        if not host:
            raise EgressBlocked(url, "no hostname in destination")

        if self.mode == "open":
            return "egress.mode=open"

        if self.mode == "deny":
            raise EgressBlocked(
                url, "egress.mode=deny — this install makes no outbound connections"
            )

        addrs = _resolve(host)
        entry = self._allow_match(host, addrs)
        if entry is not None:
            return "allowlisted (%s)" % entry

        if self.mode == "allowlist":
            raise EgressBlocked(
                url, "%s is not in egress.allow (egress.mode=allowlist)" % host
            )

        # on_premises
        if not addrs:
            raise EgressBlocked(
                url,
                "%s could not be resolved, so it cannot be shown to be internal" % host,
            )
        external = [str(a) for a in addrs if not _is_internal(a)]
        if external:
            raise EgressBlocked(
                url,
                "%s resolves outside the local network (%s); on-premises policy "
                "permits internal destinations only. Add it to egress.allow to "
                "permit it deliberately." % (host, ", ".join(sorted(external))),
            )
        return "internal destination"

    def permits(self, url):
        """True if `url` is permitted. Never raises."""
        try:
            self.check(url)
            return True
        except EgressBlocked:
            return False

    # ── reporting ───────────────────────────────────────────────────────────

    def status(self):
        """Compliance summary, safe to expose over the API."""
        return {
            "mode": self.mode,
            "allow": list(self.allow),
            "sends_data_off_premises": self.mode == "open" or bool(self.allow),
            "compliant_on_premises": self.mode in ("deny", "on_premises")
            and not self.allow,
            "description": {
                "deny": "No outbound connections are permitted.",
                "on_premises": "Outbound connections are permitted to the local "
                               "network only.",
                "allowlist": "Outbound connections are permitted to explicitly "
                             "listed destinations only.",
                "open": "Outbound connections are unrestricted. This is not an "
                        "on-premises configuration.",
            }[self.mode],
        }


# ── process-wide gate ────────────────────────────────────────────────────────
#
# Call sites should not each re-read the config: a single installed policy means
# one place to audit and no chance of two components disagreeing.

_POLICY = EgressPolicy()


def install(policy):
    """Install the process-wide policy. Returns it."""
    global _POLICY
    if not isinstance(policy, EgressPolicy):
        raise TypeError("expected an EgressPolicy")
    _POLICY = policy
    return _POLICY


def install_from_config(cfg):
    return install(EgressPolicy.from_config(cfg))


def policy():
    return _POLICY


def guard(url):
    """Raise EgressBlocked unless the installed policy permits `url`."""
    return _POLICY.check(url)


def status():
    return _POLICY.status()


# ── selftest ──────────────────────────────────────────────────────────────────

def selftest() -> int:
    failures = []

    def ok(label, cond):
        if not cond:
            failures.append(label)

    def blocked(pol, url, label):
        try:
            pol.check(url)
        except EgressBlocked:
            return
        failures.append(label)

    def allowed(pol, url, label):
        try:
            pol.check(url)
        except EgressBlocked as e:
            failures.append("%s (%s)" % (label, e.reason))

    # host parsing
    ok("host from https", _host_of("https://api.example.com/v1/x") == "api.example.com")
    ok("host lowercased", _host_of("https://API.Example.COM/") == "api.example.com")
    ok("host with port", _host_of("http://10.0.0.5:8080/hook") == "10.0.0.5")
    ok("bare host", _host_of("10.0.0.5") == "10.0.0.5")
    ok("ipv6 unbracketed", _host_of("http://[::1]:9000/x") == "::1")
    ok("no host", _host_of("") == "")

    # internal classification
    ok("rfc1918 10/8 internal", _is_internal(ipaddress.ip_address("10.200.10.23")))
    ok("rfc1918 192.168 internal", _is_internal(ipaddress.ip_address("192.168.1.1")))
    ok("rfc1918 172.16 internal", _is_internal(ipaddress.ip_address("172.16.0.1")))
    ok("loopback internal", _is_internal(ipaddress.ip_address("127.0.0.1")))
    ok("link-local internal", _is_internal(ipaddress.ip_address("169.254.1.1")))
    ok("ipv6 loopback internal", _is_internal(ipaddress.ip_address("::1")))
    ok("public not internal", not _is_internal(ipaddress.ip_address("8.8.8.8")))
    ok("ipv6 public not internal",
       not _is_internal(ipaddress.ip_address("2606:4700::1111")))

    # mode validation
    try:
        EgressPolicy(mode="sideways")
        failures.append("bad mode accepted")
    except ValueError:
        pass
    ok("hyphen mode normalised", EgressPolicy(mode="on-premises").mode == "on_premises")
    ok("default is on_premises", EgressPolicy().mode == "on_premises")
    ok("empty mode falls back", EgressPolicy(mode="  ").mode == "on_premises")

    # deny
    deny = EgressPolicy(mode="deny")
    blocked(deny, "http://10.0.0.5/hook", "deny blocks internal")
    blocked(deny, "https://api.anthropic.com/v1/messages", "deny blocks external")

    # on_premises
    prem = EgressPolicy()
    allowed(prem, "http://10.200.10.23:9000/hook", "on_prem allows rfc1918")
    allowed(prem, "http://127.0.0.1:8025/hook", "on_prem allows loopback")
    blocked(prem, "https://8.8.8.8/x", "on_prem blocks public IP")
    blocked(prem, "http://host.invalid./x", "on_prem blocks unresolvable")
    blocked(prem, "not a url", "on_prem blocks hostless")

    # allowlist
    al = EgressPolicy(mode="allowlist", allow=["siem.internal", "*.soc.local",
                                               "203.0.113.0/24"])
    allowed(al, "https://siem.internal/api", "allowlist exact host")
    allowed(al, "https://tickets.soc.local/hook", "allowlist wildcard")
    allowed(al, "https://203.0.113.9/x", "allowlist CIDR")
    blocked(al, "https://evil.example.com/x", "allowlist blocks other host")
    blocked(al, "http://10.0.0.5/hook", "allowlist blocks unlisted internal")
    ok("wildcard does not match bare suffix", not al.permits("https://soc.local/x"))

    # allowlist entries also widen on_premises
    prem_plus = EgressPolicy(mode="on_premises", allow=["203.0.113.0/24"])
    allowed(prem_plus, "https://203.0.113.9/x", "on_prem honours allowlist")
    blocked(prem_plus, "https://8.8.8.8/x", "on_prem still blocks unlisted public")

    # open
    op = EgressPolicy(mode="open")
    allowed(op, "https://api.anthropic.com/v1/messages", "open allows external")
    blocked(op, "", "open still needs a hostname")

    # config
    ok("from_config default", EgressPolicy.from_config({}).mode == "on_premises")
    ok("from_config absent block", EgressPolicy.from_config(None).mode == "on_premises")
    ok("from_config mode",
       EgressPolicy.from_config({"egress": {"mode": "deny"}}).mode == "deny")
    ok("from_config allow",
       EgressPolicy.from_config(
           {"egress": {"mode": "allowlist", "allow": ["a.b"]}}).allow == ("a.b",))
    ok("from_config allowlist alias",
       EgressPolicy.from_config(
           {"egress": {"mode": "allowlist", "allowlist": ["a.b"]}}).allow == ("a.b",))
    ok("from_config ignores junk block",
       EgressPolicy.from_config({"egress": "yes"}).mode == "on_premises")
    os.environ["UEBA_EGRESS_MODE"] = "deny"
    try:
        ok("env overrides config mode",
           EgressPolicy.from_config({"egress": {"mode": "open"}}).mode == "deny")
    finally:
        del os.environ["UEBA_EGRESS_MODE"]

    # status
    ok("default status compliant", EgressPolicy().status()["compliant_on_premises"])
    ok("deny status compliant",
       EgressPolicy(mode="deny").status()["compliant_on_premises"])
    ok("open status not compliant",
       not EgressPolicy(mode="open").status()["compliant_on_premises"])
    ok("open status flags off-prem",
       EgressPolicy(mode="open").status()["sends_data_off_premises"])
    ok("allowlisted status flags off-prem",
       EgressPolicy(mode="on_premises",
                    allow=["x.y"]).status()["sends_data_off_premises"])
    ok("status has description", "on-premises" in
       EgressPolicy(mode="open").status()["description"])

    # process-wide gate
    original = policy()
    try:
        install(EgressPolicy(mode="deny"))
        ok("installed policy is returned", policy().mode == "deny")
        try:
            guard("http://10.0.0.5/x")
            failures.append("guard ignored installed policy")
        except EgressBlocked:
            pass
        ok("module status follows install", status()["mode"] == "deny")
        install_from_config({"egress": {"mode": "open"}})
        ok("install_from_config applies", policy().mode == "open")
        try:
            install("nope")
            failures.append("install accepted a non-policy")
        except TypeError:
            pass
    finally:
        install(original)
    ok("default gate restored", policy().mode == "on_premises")

    # the blocked reason must be actionable
    try:
        EgressPolicy().check("https://8.8.8.8/x")
    except EgressBlocked as e:
        ok("reason names the host", "8.8.8.8" in e.reason)
        ok("reason says how to permit", "egress.allow" in e.reason)
        ok("exception carries url", e.url == "https://8.8.8.8/x")

    total = 48
    if failures:
        print("ueba_egress selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_egress selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
