#!/usr/bin/env python3
"""
ueba_appdecode.py
─────────────────
CyberSentinel UEBA — connection detail and application-layer decoding (SN 57).

  SN 57  The solution's UI should allow using advanced search for detail
         connection information. Certain application-layer protocols are
         further decoded during this process.

What this does, and the boundary it does not cross
──────────────────────────────────────────────────
Stated first because it is the thing most likely to be over-claimed in a
review: THIS IS NOT DEEP PACKET INSPECTION. We receive logs, not packets.
Nothing here can decode a protocol from a payload, because there is no payload
to decode — and a platform claiming DPI from log input would be making a
claim it cannot support.

What it does instead is decode the application-layer information the logs
DO carry into structured, searchable fields, and label every value with where
it came from:

  observed   the log named it — an app field, a URL, a DNS question, an SNI
  inferred   the log did not, so it was derived from the port number

That distinction is the point. "Port 445, therefore SMB" is a reasonable guess
and a useless piece of evidence if an analyst cannot tell it apart from a log
that actually said SMB. Everything here carries its provenance.

Measured on the local alert sample, 3,412 alerts
────────────────────────────────────────────────
  object.name / object.type   72.0%   (file / process / user)
  url                          0.3%   9 records, all web-attack paths
  hostname, dns, http method, user agent, app category, ports:  0.0%

So almost nothing application-layer survives into ALERTS. The fields exist
upstream — destination ports are on about 84% of the enriched stream, and the
firewall events carrying app categories are noise-suppressed because
individually they are policy enforcement. This module therefore runs over the
CONNECTION stream (see ueba_netflow), where those fields live, rather than
over the alert feed where they do not.

The nine URLs that are present are worth noting, because they justify the URL
decoder on their own: every one is an attack path —
/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession and
similar. Decoding a URL into host, path, extension, depth and traversal
indicators turns those from an opaque string into something searchable.

When the SIEM starts forwarding richer decoded fields
─────────────────────────────────────────────────────
The field table is the only thing that changes. Each decoder reads a list of
candidate paths, so a SIEM that begins sending dns.question.name or
tls.client.server_name is picked up by adding the path — no new code, and the
provenance flips from inferred to observed automatically.
"""

from __future__ import annotations

import math
import re
from urllib.parse import unquote, urlsplit

# ── port → service. The inferred side of the decoder. ───────────────────────
#
# Deliberately a short, boring list of ports whose meaning is not in dispute.
# Guessing "8080 is HTTP" is fine; guessing an ephemeral high port is noise
# dressed as evidence, so anything not listed stays unnamed.
_PORT_SERVICE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmp-trap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 587: "smtp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    3128: "http-proxy", 3268: "ldap-gc", 3306: "mysql", 3389: "rdp",
    4444: "metasploit-default", 5432: "postgres", 5060: "sip",
    5061: "sip-tls", 5432: "postgres", 5900: "vnc", 5985: "winrm",
    5986: "winrm-tls", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 9092: "kafka", 11211: "memcached",
    27017: "mongodb",
}

# Protocols this module claims to decode further, and the fields each yields.
DECODERS = ("url", "dns", "http", "tls", "service")

PROVENANCE = ("observed", "inferred", "none")

# Candidate field paths per decoder. Adding a path is how a newly-forwarded
# SIEM field is adopted; nothing else changes.
_FIELDS = {
    "url": ("url.original", "url.full", "http.request.uri", "data.url",
            "context.raw_event.data.url", "http.url"),
    "dns": ("dns.question.name", "dns.query.name", "data.qname",
            "context.raw_event.data.qname", "data.dns_query"),
    "tls": ("tls.client.server_name", "tls.server_name", "data.sni",
            "context.raw_event.data.sni"),
    "http_method": ("http.request.method", "data.method",
                    "context.raw_event.data.method"),
    "user_agent": ("user_agent.original", "http.request.headers.user-agent",
                   "data.agent", "context.raw_event.data.agent"),
    "app": ("network.protocol", "network.application", "data.app",
            "data.appcat", "data.service",
            "context.raw_event.data.app", "context.raw_event.data.appcat"),
    "host": ("destination.domain", "url.domain", "data.hostname",
             "context.raw_event.data.hostname"),
}

# Path shapes worth flagging on a decoded URL. Each is a statement about the
# REQUEST, not a verdict about the event — an analyst searches on them.
_URL_FLAGS = (
    ("traversal", re.compile(r"\.\./|\.\.\\|%2e%2e", re.I)),
    ("encoded_traversal", re.compile(r"%252e|%c0%ae", re.I)),
    ("script_in_path", re.compile(r"\.(php|asp|aspx|jsp|cgi|pl|sh)\b", re.I)),
    ("sql_markers", re.compile(r"(?:union\s+select|'\s+or\s+|--\s|;\s*drop\s)", re.I)),
    ("script_markers", re.compile(r"(?:<script|javascript:|onerror\s*=)", re.I)),
    ("shell_markers", re.compile(r"(?:/bin/(?:sh|bash)|cmd\.exe|powershell)", re.I)),
    ("long_query", re.compile(r"\?.{200,}", re.S)),
)

# A hostname this long with this much randomness is the usual shape of an
# algorithmically generated domain. Reported as an indicator, never a verdict.
_DGA_MIN_LABEL = 12
_DGA_MIN_ENTROPY = 3.5


def get_nested(obj, path: str, default=None):
    cur = obj
    for part in str(path).split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
        if cur is None:
            return default
    return cur


def _first(record: dict, key: str):
    """(value, path) for the first populated candidate path of `key`."""
    for p in _FIELDS.get(key, ()):
        v = get_nested(record, p)
        if v not in (None, "", "-"):
            return v, p
    return None, ""


def entropy(s: str) -> float:
    """Shannon entropy in bits per character.

    Used only as a DGA indicator on a hostname label. A real word scores around
    3 bits; a random string of the same length scores closer to 4.
    """
    t = str(s or "")
    if not t:
        return 0.0
    counts = {}
    for ch in t:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(t))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def service_for_port(port, proto: str = "") -> dict:
    """{"service", "provenance"} from a port number.

    Always `inferred`: the port is a convention, not an observation of the
    protocol. A caller that cannot tell the difference will eventually report
    "SMB" about something that merely used 445.
    """
    try:
        p = int(port)
    except (TypeError, ValueError):
        return {"service": "", "provenance": "none"}
    if p <= 0 or p > 65535:
        return {"service": "", "provenance": "none"}
    name = _PORT_SERVICE.get(p, "")
    if not name:
        return {"service": "", "provenance": "none"}
    return {"service": name, "provenance": "inferred"}


def decode_url(raw) -> dict:
    """Split a URL or request path into searchable parts, with indicators."""
    s = str(raw or "").strip()
    if not s:
        return {}
    # A request line ("GET /path HTTP/1.1") is a common log shape.
    m = re.match(r"^([A-Z]{3,10})\s+(\S+)(?:\s+HTTP/[\d.]+)?$", s)
    method = ""
    if m:
        method, s = m.group(1), m.group(2)
    parts = urlsplit(s if "//" in s else ("//" + s if s.startswith("www.")
                                          else s))
    path = parts.path or ""
    try:
        decoded_path = unquote(path)
    except Exception:
        decoded_path = path
    segments = [x for x in decoded_path.split("/") if x]
    ext = ""
    if segments and "." in segments[-1]:
        ext = segments[-1].rsplit(".", 1)[-1].lower()[:12]
    probe = "%s?%s" % (decoded_path, parts.query or "")
    flags = [name for name, rx in _URL_FLAGS if rx.search(probe)]
    out = {
        "scheme": (parts.scheme or "").lower(),
        "host": (parts.hostname or "").lower(),
        "port": parts.port or 0,
        "path": decoded_path[:512],
        "query": (parts.query or "")[:512],
        "extension": ext,
        "depth": len(segments),
        "indicators": flags,
    }
    if method:
        out["method"] = method
    return out


def decode_dns(raw) -> dict:
    """Split a DNS question name, with a DGA indicator."""
    s = str(raw or "").strip().rstrip(".").lower()
    if not s:
        return {}
    labels = [x for x in s.split(".") if x]
    tld = labels[-1] if labels else ""
    # The registrable part, roughly — enough for grouping in a search.
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else s
    longest = max(labels, key=len) if labels else ""
    ent = entropy(longest)
    return {
        "name": s[:253],
        "labels": len(labels),
        "tld": tld,
        "registrable": registrable,
        "longest_label": longest[:63],
        "entropy": round(ent, 3),
        "dga_suspect": bool(len(longest) >= _DGA_MIN_LABEL
                            and ent >= _DGA_MIN_ENTROPY),
    }


def _agent_class(ua: str) -> str:
    """A coarse class for a user agent, which is what a search wants.

    Not a browser-version parser: the useful question in this context is
    "was this a browser, a script, or a scanner", and the long tail of version
    strings makes a field nobody can filter on.
    """
    s = str(ua or "").lower()
    if not s:
        return ""
    if any(k in s for k in ("nmap", "nikto", "sqlmap", "masscan", "zgrab",
                            "dirbuster", "gobuster", "nessus", "acunetix",
                            "metasploit")):
        return "scanner"
    if any(k in s for k in ("curl", "wget", "python-requests", "go-http",
                            "libwww", "httpie", "powershell", "winhttp",
                            "java/", "okhttp", "axios", "node-fetch")):
        return "script"
    if any(k in s for k in ("bot", "crawler", "spider", "slurp")):
        return "bot"
    if any(k in s for k in ("mozilla", "chrome", "safari", "firefox", "edge")):
        return "browser"
    return "other"


def decode(record: dict, flow: "dict | None" = None) -> dict:
    """Everything decodable about one connection record.

    {"protocol", "protocol_provenance", "app", "app_provenance",
     "decoders": [...], "url": {...}, "dns": {...}, "tls": {...},
     "http": {...}, "fields": {path: value}}

    `flow` is the canonical flow from ueba_netflow.normalise, when the caller
    already has it — the ports come from there rather than being re-read.
    """
    out = {
        "protocol": "", "protocol_provenance": "none",
        "app": "", "app_provenance": "none",
        "decoders": [], "fields": {},
    }
    if not isinstance(record, dict):
        return out

    def note(path, value):
        if path:
            out["fields"][path] = (str(value)[:256] if not isinstance(
                value, (int, float, bool)) else value)

    # ── what the log says the application is ──
    app, app_path = _first(record, "app")
    if app:
        out["app"] = str(app).strip().lower()[:64]
        out["app_provenance"] = "observed"
        note(app_path, app)

    # ── transport, from the flow where we have one ──
    dport = sport = 0
    if flow:
        out["protocol"] = flow.get("proto") or ""
        if out["protocol"]:
            out["protocol_provenance"] = "observed"
        dport = int(flow.get("dport") or 0)
        sport = int(flow.get("sport") or 0)

    # ── url ──
    raw_url, url_path = _first(record, "url")
    if raw_url:
        u = decode_url(raw_url)
        if u:
            out["url"] = u
            out["decoders"].append("url")
            note(url_path, raw_url)
            if not out["app"]:
                out["app"] = "https" if u.get("scheme") == "https" else "http"
                out["app_provenance"] = "observed"

    # ── dns ──
    raw_dns, dns_path = _first(record, "dns")
    if raw_dns:
        d = decode_dns(raw_dns)
        if d:
            out["dns"] = d
            out["decoders"].append("dns")
            note(dns_path, raw_dns)
            if not out["app"]:
                out["app"] = "dns"
                out["app_provenance"] = "observed"

    # ── tls ──
    raw_sni, sni_path = _first(record, "tls")
    if raw_sni:
        out["tls"] = {"server_name": str(raw_sni).strip().lower()[:253]}
        out["decoders"].append("tls")
        note(sni_path, raw_sni)
        if not out["app"]:
            out["app"] = "tls"
            out["app_provenance"] = "observed"

    # ── http ──
    method, m_path = _first(record, "http_method")
    ua, ua_path = _first(record, "user_agent")
    http = {}
    if method:
        http["method"] = str(method).strip().upper()[:12]
        note(m_path, method)
    elif out.get("url", {}).get("method"):
        http["method"] = out["url"]["method"]
    if ua:
        http["user_agent"] = str(ua)[:256]
        http["agent_class"] = _agent_class(ua)
        note(ua_path, ua)
    if http:
        out["http"] = http
        if "http" not in out["decoders"]:
            out["decoders"].append("http")

    # ── host ──
    host, host_path = _first(record, "host")
    if host:
        out["host"] = str(host).strip().lower()[:253]
        note(host_path, host)
    elif out.get("url", {}).get("host"):
        out["host"] = out["url"]["host"]
    elif out.get("tls", {}).get("server_name"):
        out["host"] = out["tls"]["server_name"]

    # ── service, inferred from the port, LAST and clearly labelled ──
    if not out["app"] and dport:
        svc = service_for_port(dport, out["protocol"])
        if svc["service"]:
            out["app"] = svc["service"]
            out["app_provenance"] = svc["provenance"]
            out["decoders"].append("service")
    out["port_service"] = service_for_port(dport).get("service", "")
    out["source_port_service"] = service_for_port(sport).get("service", "")
    return out


# ── structured search over connection detail ────────────────────────────────
#
# "Advanced search" with no custom query language to learn: `field:value`
# terms, optionally comparing with > < >= <= != , joined implicitly by AND.
# Free text with no field falls back to a substring match across the whole
# record. The same grammar is what SN 26's plain-language search will
# translate onto, so there is one evaluator rather than two.

_TERM = re.compile(r"""
    (?P<field>[A-Za-z_][A-Za-z0-9_.]*)
    \s*(?P<op>>=|<=|!=|[:=><])\s*
    (?P<value>"[^"]*"|'[^']*'|\S+)
""", re.X)

OPERATORS = (":", "=", "!=", ">", "<", ">=", "<=")


def parse_query(q: str) -> dict:
    """{"terms": [{field, op, value}], "text": [free words], "errors": [...]}"""
    out = {"terms": [], "text": [], "errors": []}
    s = str(q or "").strip()
    if not s:
        return out
    pos = 0
    for m in _TERM.finditer(s):
        if m.start() > pos:
            out["text"].extend(
                w for w in s[pos:m.start()].split() if w)
        val = m.group("value").strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        out["terms"].append({"field": m.group("field").lower(),
                             "op": m.group("op"), "value": val})
        pos = m.end()
    if pos < len(s):
        out["text"].extend(w for w in s[pos:].split() if w)
    return out


def _flatten(obj, prefix="", into=None, depth=0):
    """{dotted path: scalar} for one record, bounded in depth."""
    into = {} if into is None else into
    if depth > 6:
        return into
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, "%s.%s" % (prefix, k) if prefix else str(k), into,
                     depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:16]):
            _flatten(v, prefix, into, depth + 1)
    else:
        if prefix:
            cur = into.get(prefix)
            if cur is None:
                into[prefix] = obj
            elif isinstance(cur, list):
                cur.append(obj)
            else:
                into[prefix] = [cur, obj]
    return into


def _as_num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _match_one(values, op: str, want: str) -> bool:
    vals = values if isinstance(values, list) else [values]
    w_num = _as_num(want)
    for v in vals:
        if v is None:
            continue
        sv = str(v).lower()
        wl = str(want).lower()
        if op in (":", "="):
            # ':' is a substring match, which is what a search box means by
            # typing part of a name; '=' is exact.
            if (wl in sv) if op == ":" else (sv == wl):
                return True
        elif op == "!=":
            if sv == wl:
                return False
        elif w_num is not None:
            n = _as_num(v)
            if n is None:
                continue
            if ((op == ">" and n > w_num) or (op == "<" and n < w_num)
                    or (op == ">=" and n >= w_num)
                    or (op == "<=" and n <= w_num)):
                return True
    # '!=' passes when nothing matched it
    return op == "!=" and bool(vals)


def matches(flat: dict, parsed: dict) -> bool:
    """Does one flattened record satisfy every term and free-text word?"""
    for t in parsed.get("terms", []):
        field, op, want = t["field"], t["op"], t["value"]
        # A field matches on an exact path or on a trailing path segment, so
        # `dport:445` finds `connection.dport` without the analyst knowing the
        # full path.
        hits = [v for k, v in flat.items()
                if k.lower() == field or k.lower().endswith("." + field)]
        if not hits:
            if op == "!=":
                continue        # a field that is absent is not equal to it
            return False
        if not any(_match_one(h, op, want) for h in hits):
            return False
    if parsed.get("text"):
        blob = " ".join(str(v).lower() for v in flat.values())
        for w in parsed["text"]:
            if w.lower() not in blob:
                return False
    return True


def searchable(record: dict, flow: "dict | None" = None,
               decoded: "dict | None" = None) -> dict:
    """The flattened, searchable view of one connection: flow + decoded.

    Returned as its own namespaces so a query can say `app:smb` or
    `url.indicators:traversal` and mean it, rather than hoping a substring
    lands in the right place.
    """
    d = decoded if decoded is not None else decode(record, flow)
    view = {}
    if flow:
        for k, v in flow.items():
            view["connection.%s" % k] = v
    for k, v in d.items():
        if k == "fields":
            continue
        if isinstance(v, dict):
            for k2, v2 in v.items():
                view["%s.%s" % (k, k2)] = v2
        else:
            view[k] = v
    return _flatten(view)


def status() -> dict:
    return {
        "decoders": list(DECODERS),
        "operators": list(OPERATORS),
        "provenance": list(PROVENANCE),
        "known_ports": len(_PORT_SERVICE),
        "url_indicators": [n for n, _ in _URL_FLAGS],
        "dpi_note": (
            "This is NOT deep packet inspection and does not claim to be. The "
            "platform receives logs, not packets, so nothing here decodes a "
            "protocol from a payload. What it decodes is the "
            "application-layer information the logs already carry — URLs, DNS "
            "questions, TLS server names, HTTP methods and user agents, "
            "vendor app categories — into structured searchable fields, and "
            "derives the service from the port where the log does not name "
            "it. Every value is labelled 'observed' when the log said it and "
            "'inferred' when it came from the port number, because an analyst "
            "who cannot tell those apart will eventually report SMB about "
            "something that merely used port 445."),
        "coverage_note": (
            "Measured on 3,412 local alerts: object fields 72%, URLs 0.3%, "
            "and DNS, SNI, HTTP method, user agent and ports all 0%. Those "
            "fields exist UPSTREAM — destination ports are on about 84% of "
            "the enriched stream — so decoding runs over the connection "
            "stream rather than the alert feed. Adding a newly-forwarded "
            "SIEM field is a path in the field table, not new code, and the "
            "provenance flips from inferred to observed automatically."),
    }


# ── selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    failures = []

    def ok(label, cond):
        if not cond:
            failures.append(label)

    # ── entropy ──
    ok("entropy of a repeated character is zero", entropy("aaaa") == 0.0)
    ok("entropy of empty is zero", entropy("") == 0.0)
    ok("random text scores higher than a word",
       entropy("x7fq2bv9zk3m") > entropy("marketing"))

    # ── port service, and its provenance ──
    ok("445 infers smb", service_for_port(445)["service"] == "smb")
    ok("and is labelled inferred", service_for_port(445)["provenance"] == "inferred")
    ok("53 infers dns", service_for_port(53)["service"] == "dns")
    ok("3389 infers rdp", service_for_port(3389)["service"] == "rdp")
    ok("an ephemeral port infers nothing",
       service_for_port(51734)["service"] == "")
    ok("and says nothing rather than guessing",
       service_for_port(51734)["provenance"] == "none")
    ok("port 0 infers nothing", service_for_port(0)["service"] == "")
    ok("a junk port infers nothing", service_for_port("x")["provenance"] == "none")
    ok("an out-of-range port infers nothing",
       service_for_port(70000)["provenance"] == "none")

    # ── url ──
    u = decode_url("https://example.com:8443/a/b/report.php?id=1")
    ok("the scheme is decoded", u["scheme"] == "https")
    ok("the host is decoded", u["host"] == "example.com")
    ok("the port is decoded", u["port"] == 8443)
    ok("the path is decoded", u["path"] == "/a/b/report.php")
    ok("the query is decoded", u["query"] == "id=1")
    ok("the extension is decoded", u["extension"] == "php")
    ok("the depth is counted", u["depth"] == 3)
    ok("a script path is flagged", "script_in_path" in u["indicators"])

    # the real attack paths from the sample, decoded
    t = decode_url("/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession")
    ok("traversal is flagged", "traversal" in t["indicators"])
    ok("a path-only url still decodes", t["path"].startswith("/remote/"))
    ok("a path-only url has no host", t["host"] == "")
    e = decode_url("/x?q=%2e%2e%2f%2e%2e%2fetc/passwd")
    ok("encoded traversal is flagged after unquoting",
       "traversal" in e["indicators"])
    s = decode_url("/search?q=1' OR '1'='1' -- ")
    ok("sql markers are flagged", "sql_markers" in s["indicators"])
    x = decode_url("/p?next=<script>alert(1)</script>")
    ok("script markers are flagged", "script_markers" in x["indicators"])
    sh = decode_url("/cgi-bin/x?cmd=/bin/sh")
    ok("shell markers are flagged", "shell_markers" in sh["indicators"])
    lq = decode_url("/a?" + "k=v&" * 80)
    ok("a very long query is flagged", "long_query" in lq["indicators"])
    rl = decode_url("GET /index.html HTTP/1.1")
    ok("a request line yields the method", rl.get("method") == "GET")
    ok("and the path", rl["path"] == "/index.html")
    ok("an empty url decodes to nothing", decode_url("") == {})
    ok("a clean url carries no indicators",
       decode_url("https://intranet/home")["indicators"] == [])

    # ── dns ──
    d = decode_dns("mail.corp.example.com.")
    ok("the trailing dot is dropped", d["name"] == "mail.corp.example.com")
    ok("labels are counted", d["labels"] == 4)
    ok("the tld is taken", d["tld"] == "com")
    ok("the registrable part is taken", d["registrable"] == "example.com")
    ok("a normal name is not dga-suspect", d["dga_suspect"] is False)
    g = decode_dns("x7fq2bv9zk3mqp.example.net")
    ok("a long random label is dga-suspect", g["dga_suspect"] is True)
    ok("its entropy is reported", g["entropy"] > 3.0)
    ok("a short name is not dga-suspect",
       decode_dns("ns1.example.com")["dga_suspect"] is False)
    ok("an empty name decodes to nothing", decode_dns("") == {})
    ok("a single-label name still decodes",
       decode_dns("localhost")["labels"] == 1)

    # ── user agent class ──
    ok("nmap is a scanner", _agent_class("Mozilla/5.0 Nmap Scripting Engine") == "scanner")
    ok("sqlmap is a scanner", _agent_class("sqlmap/1.5") == "scanner")
    ok("curl is a script", _agent_class("curl/8.1.2") == "script")
    ok("python-requests is a script", _agent_class("python-requests/2.31") == "script")
    ok("powershell is a script", _agent_class("WindowsPowerShell/5.1") == "script")
    ok("chrome is a browser",
       _agent_class("Mozilla/5.0 (Windows NT 10.0) Chrome/120") == "browser")
    ok("a crawler is a bot", _agent_class("Googlebot/2.1") == "bot")
    ok("an empty agent has no class", _agent_class("") == "")
    ok("an unknown agent is other", _agent_class("CustomThing/1") == "other")
    # A scanner that also claims to be Mozilla must still read as a scanner.
    ok("scanner wins over a browser claim",
       _agent_class("Mozilla/5.0 (compatible; Nikto/2.1.6)") == "scanner")

    # ── decode, end to end ──
    rec = {"data": {"url": "/admin/../../etc/passwd", "method": "GET",
                    "agent": "curl/8.1.2"}}
    d = decode(rec)
    ok("the url decoder ran", "url" in d["decoders"])
    ok("traversal survives into the decode",
       "traversal" in d["url"]["indicators"])
    ok("the http decoder ran", "http" in d["decoders"])
    ok("the method is taken", d["http"]["method"] == "GET")
    ok("the agent is classed", d["http"]["agent_class"] == "script")
    ok("the app is observed, not inferred", d["app_provenance"] == "observed")
    ok("the source paths are recorded", any("url" in k for k in d["fields"]))

    dnsrec = {"dns": {"question": {"name": "x7fq2bv9zk3mqp.bad.example"}}}
    d = decode(dnsrec)
    ok("the dns decoder ran", "dns" in d["decoders"])
    ok("dns sets the app", d["app"] == "dns")
    ok("and it is observed", d["app_provenance"] == "observed")
    ok("the dga indicator survives", d["dns"]["dga_suspect"] is True)

    tlsrec = {"tls": {"client": {"server_name": "Login.Example.COM"}}}
    d = decode(tlsrec)
    ok("the tls decoder ran", "tls" in d["decoders"])
    ok("the server name is folded", d["tls"]["server_name"] == "login.example.com")
    ok("tls sets the host", d["host"] == "login.example.com")

    # inference only when the log said nothing, and labelled as such
    flow = {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": 50000,
            "dport": 445, "proto": "tcp"}
    d = decode({}, flow)
    ok("the service is inferred from the port", d["app"] == "smb")
    ok("and is labelled inferred", d["app_provenance"] == "inferred")
    ok("the transport is observed from the flow",
       d["protocol"] == "tcp" and d["protocol_provenance"] == "observed")
    ok("the service decoder is listed", "service" in d["decoders"])

    # an observed app must NOT be overwritten by the port guess
    d = decode({"data": {"app": "HTTPS-Browsing"}}, flow)
    ok("an observed app beats the port inference", d["app"] == "https-browsing")
    ok("and stays observed", d["app_provenance"] == "observed")

    d = decode({}, {"src": "a", "dst": "b", "dport": 51999, "proto": "udp",
                    "sport": 0})
    ok("an unknown port infers no app", d["app"] == "")
    ok("and says so", d["app_provenance"] == "none")
    ok("decoding a non-dict is safe", decode("nope")["app"] == "")
    ok("decoding an empty record is safe", decode({})["decoders"] == [])

    # ── query parsing ──
    p = parse_query("app:smb dport>=445 host!=intranet free text")
    ok("three terms are parsed", len(p["terms"]) == 3)
    ok("the first term is read", p["terms"][0] == {"field": "app", "op": ":",
                                                   "value": "smb"})
    ok("a >= operator is read", p["terms"][1]["op"] == ">=")
    ok("a != operator is read", p["terms"][2]["op"] == "!=")
    ok("free text is collected", p["text"] == ["free", "text"])
    q = parse_query('url.path:"/etc/passwd"')
    ok("a quoted value keeps its spaces and slashes",
       q["terms"][0]["value"] == "/etc/passwd")
    ok("an empty query parses to nothing",
       parse_query("")["terms"] == [] and parse_query("")["text"] == [])
    ok("plain words are all free text", parse_query("just words")["text"] == ["just", "words"])

    # ── matching ──
    rec = {"data": {"url": "/admin/../../etc/passwd", "app": "HTTP"}}
    flow = {"src": "10.0.0.1", "dst": "10.0.0.9", "dport": 80, "proto": "tcp",
            "sent": 400, "rcvd": 90, "sport": 40000, "bytes": 490,
            "packets": 6, "duration": 0.2, "shape": "firewall"}
    view = searchable(rec, flow)
    ok("the connection is searchable", view.get("connection.dport") == 80)
    ok("the decoded app is searchable", view.get("app") == "http")
    ok("decoded url parts are searchable",
       view.get("url.path") == "/admin/../../etc/passwd")
    ok("indicators are searchable",
       "traversal" in str(view.get("url.indicators")))

    ok("an exact field match works", matches(view, parse_query("app=http")))
    ok("a substring field match works", matches(view, parse_query("app:ht")))
    ok("a trailing-segment field match works",
       matches(view, parse_query("dport:80")))
    ok("a numeric comparison works", matches(view, parse_query("dport<=80")))
    ok("a failing numeric comparison does not match",
       not matches(view, parse_query("dport>1000")))
    ok("a wrong value does not match", not matches(view, parse_query("app=smb")))
    ok("terms are joined by AND",
       not matches(view, parse_query("app=http dport=445")))
    ok("both terms satisfied matches",
       matches(view, parse_query("app=http dport=80")))
    ok("a != on a different value matches",
       matches(view, parse_query("app!=smb")))
    ok("a != on the same value does not match",
       not matches(view, parse_query("app!=http")))
    ok("an absent field is not equal to anything",
       matches(view, parse_query("nosuchfield!=x")))
    ok("an absent field fails a positive match",
       not matches(view, parse_query("nosuchfield:x")))
    ok("free text matches across the record",
       matches(view, parse_query("passwd")))
    ok("free text that is absent does not match",
       not matches(view, parse_query("nowhere")))
    ok("searching indicators by name works",
       matches(view, parse_query("url.indicators:traversal")))
    ok("an empty query matches everything", matches(view, parse_query("")))

    # ── status ──
    st = status()
    ok("status lists the decoders", st["decoders"] == list(DECODERS))
    ok("status disclaims DPI", "NOT deep packet inspection" in st["dpi_note"])
    ok("status explains provenance", "observed" in st["dpi_note"])
    ok("status reports the measured coverage", "0.3%" in st["coverage_note"])
    ok("status lists the operators", ">=" in st["operators"])
    ok("status lists the url indicators", "traversal" in st["url_indicators"])

    total = 100
    if failures:
        print("ueba_appdecode selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_appdecode selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
