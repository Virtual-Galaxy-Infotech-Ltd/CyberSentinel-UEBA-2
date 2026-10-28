#!/usr/bin/env python3
"""
ueba_dashboard_server.py
─────────────────────────
CyberSentinel UEBA — Dashboard API Server

Serves ueba_alerts.jsonl data as JSON endpoints for the dashboard.

Run:
    python3 ueba_dashboard_server.py
    python3 ueba_dashboard_server.py --config ueba_config.yaml
    python3 ueba_dashboard_server.py --port 3026 --alerts /path/to/ueba_alerts.jsonl

Configuration is sourced (in priority order) from:
    1. CLI flags
    2. The `dashboard:` block in ueba_config.yaml
    3. Built-in defaults (matches the historical hard-coded values)

The Anthropic API key for the AI Security Analyst is taken from the
ANTHROPIC_API_KEY environment variable. If unset, the dashboard falls back to
a locally-generated summary.
"""

import argparse
import gzip
import json
import os
import re
import time
import uuid
import zipfile
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

# orjson parses JSON ~2.5x faster than the stdlib (measured on real archives:
# 6.4s -> 2.6s per day-file) and is already installed in the venv. It's the hot
# path for both live-tail and archive ingestion, so use it when present and fall
# back to stdlib json transparently otherwise. orjson returns bytes from dumps.
try:
    import orjson as _orjson

    def _jloads(b):
        return _orjson.loads(b)

    def _jdumps(o) -> bytes:
        return _orjson.dumps(o)
except Exception:  # pragma: no cover - orjson should be present, but degrade gracefully
    _orjson = None

    def _jloads(b):
        return json.loads(b)

    def _jdumps(o) -> bytes:
        return json.dumps(o).encode("utf-8")

from flask import (
    Flask, jsonify, request, send_from_directory, Response,
    stream_with_context, has_request_context,
)
from flask_cors import CORS

# SSO / session layer. Optional in the same way orjson and yaml are: if the
# module (or PyJWT under it) is missing the dashboard still serves, just with
# no authentication — which is exactly what it did before this existed.
try:
    import ueba_auth  # type: ignore
    AUTH_MODULE_AVAILABLE = True
except ImportError:
    ueba_auth = None
    AUTH_MODULE_AVAILABLE = False

# Watch lists. Optional on the same terms — an install that predates this module
# keeps serving, with the watch-list endpoints reporting themselves unavailable
# rather than 500ing.
try:
    import ueba_watchlist  # type: ignore
    WATCHLIST_AVAILABLE = True
except ImportError:
    ueba_watchlist = None
    WATCHLIST_AVAILABLE = False

# Reporting. Optional on the same terms; note that PDF and Excel have their own
# optional dependencies on top (reportlab / openpyxl) which are reported
# separately by ueba_report_render.available_formats(), so a site missing only
# reportlab still gets CSV, HTML, JSON and XML reports.
try:
    import ueba_reports        # type: ignore
    import ueba_report_render  # type: ignore
    import ueba_report_store   # type: ignore
    REPORTS_AVAILABLE = True
except ImportError:
    ueba_reports = ueba_report_render = ueba_report_store = None
    REPORTS_AVAILABLE = False

# Device registry and proactive alerting. Optional on the same terms.
try:
    import ueba_notify  # type: ignore
    NOTIFY_AVAILABLE = True
except ImportError:
    ueba_notify = None
    NOTIFY_AVAILABLE = False

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None  # config file is optional

try:
    import requests  # type: ignore
except ImportError:
    requests = None  # AI proxy will degrade gracefully


# ── Defaults (used when config file or keys are missing) ──────────────────────
_DEFAULTS = {
    "host":            "0.0.0.0",
    "port":            3026,
    "alerts_file":     "/root/NEW_DRIVE/aditya_ueba/ueba_alerts.jsonl",
    "agents_registry": "/root/NEW_DRIVE/aditya_ueba/agents.json",
    "false_positives_file": "/root/NEW_DRIVE/aditya_ueba/false_positives.json",
    "fp_patterns_file":     "/root/NEW_DRIVE/aditya_ueba/fp_patterns.json",
    # ── Audit trail (RFP 65) ────────────────────────────────────────────────
    # Append-only JSONL record of every state-changing request: who did it,
    # what they did it to, from where, and whether it worked.
    #
    # Request BODIES are deliberately NOT recorded wholesale. The SSO exchange
    # carries a bearer token in its body, and an audit log that quietly
    # accumulates credentials is a liability rather than a control. Only an
    # explicit per-route allowlist of harmless fields is kept (see
    # _AUDIT_BODY_FIELDS) — the analyst's free-text FP "reason", nothing else.
    "audit_file":      "/root/NEW_DRIVE/aditya_ueba/ueba_audit.jsonl",
    # This box has filled its root disk twice already. The audit log rotates
    # itself so it can never become the third cause.
    "audit_max_bytes": 64 * 1024 * 1024,
    "audit_enabled":   True,
    # Analyst watch lists (RFP 1). Shared with the engine — normally inherited
    # from the `paths:` block, see load_dashboard_config().
    "watchlist_file":  "/root/NEW_DRIVE/aditya_ueba/watchlist.json",
    # Device registry and proactive alerting (RFP 10, 15).
    "notify": {
        "enabled":      True,
        "devices_file": "/root/NEW_DRIVE/aditya_ueba/devices.json",
        "rules_file":   "/root/NEW_DRIVE/aditya_ueba/notify_rules.json",
        "state_file":   "/root/NEW_DRIVE/aditya_ueba/.state/notify.state",
        "poll_secs":    15,
    },
    # Reporting (RFP 34-40, 62). See the `reporting:` block in ueba_config.yaml.
    "reporting": {
        "enabled":           True,
        "output_dir":        "/root/NEW_DRIVE/aditya_ueba/reports",
        "definitions_file":  "/root/NEW_DRIVE/aditya_ueba/report_definitions.json",
        "schedules_file":    "/root/NEW_DRIVE/aditya_ueba/report_schedules.json",
        "history_file":      "/root/NEW_DRIVE/aditya_ueba/report_history.json",
        "default_hours":     168,
        "max_window_alerts": 400000,
        "scheduler_enabled": True,
        "smtp": {
            "host": "", "port": 587, "starttls": True, "ssl": False,
            "username": "", "password": "", "password_env": "UEBA_SMTP_PASSWORD",
            "from_addr": "ueba@cybersentinel.local", "timeout_secs": 30,
        },
    },
    # The engine rotates ueba_alerts.jsonl at midnight, zipping each day to
    # archive_dir as ueba_alerts_YYYY-MM-DD.jsonl.zip. The dashboard reads the
    # live file PLUS these archives so the timeline windows (24H…90D / All) have
    # history to show — without them, "All" would only ever show today.
    "archive_dir":     "/root/NEW_DRIVE/aditya_ueba/archive",
    "max_alerts":      500000,
    "cache_ttl_secs":  10,
    # Timeline-window loading. `history_days` bounds the "All"/90D lookback into
    # the archives; `max_feed_alerts` caps how many alerts a single windowed
    # request returns (most-recent kept).
    #
    # The cap is large (500k) on purpose. To keep a window that big from shipping
    # a ~1 GB firehose, the bulk /api/feed payload OMITS each alert's `evidence`
    # blob (~77% of per-alert bytes) — the dashboard lazy-loads it per row via
    # /api/evidence/<event_id> only when an analyst expands that row. So 500k
    # alerts cost ~0.5 KB each on the wire (~260 MB worst case) instead of ~2.3 KB.
    "history_days":    95,
    "max_feed_alerts": 500000,
    # /api/feed table payload cap. The feed table + client-side charts only ever
    # need the most-recent slice; on a high-volume feed a wide window can hold
    # tens of thousands of alerts, and shipping all of them (tens of MB) freezes
    # the browser parsing/aggregating them. The bulk feed returns at most this
    # many newest rows. Window TOTALS stay accurate via /api/stats (which counts
    # the full window up to max_feed_alerts), so this only bounds the table feed.
    "feed_row_cap":    5000,
    # Live threat map (firewall geoIP). The /api/geofeed endpoint tails recent
    # FIREWALL events from the enriched feed, geolocates each external source IP
    # via a local MaxMind GeoLite2 DB (fully offline, no API key), and serves
    # source→datacenter arcs to the globe.gl panel. If the GeoLite2 DB or the
    # geoip2 lib is absent the endpoint degrades to empty (geo_ok=false).
    "enriched_file": "/root/NEW_DRIVE/aditya_ueba/enriched.jsonl",
    "geoip_city_db": "",   # explicit path; empty → auto-detect from known locations
    "geoip_asn_db":  "",
    "threatmap": {
        "window_bytes": 12582912,   # tail this many bytes of enriched.jsonl (~last few min)
        "max_arcs":     400,        # cap arcs returned per poll (most-recent kept)
        "dc_ip":        "103.76.143.84",   # WAN/DC anchor IP — geolocated for the arc target
        "dc_lat":       21.1463,    # fallback DC coords (Nagpur, IN) if dc_ip won't resolve
        "dc_lng":       79.0849,
        "dc_label":     "VG Datacenter",
    },
    "ai_analyst": {
        "enabled":     True,
        "model":       "claude-sonnet-4-6",
        "max_tokens":  1000,
        "timeout_secs": 20,
    },
    # Agent auto-discovery — periodically reads the SIEM manager's
    # `client.keys` to keep agents.json in sync with the SOC inventory.
    #
    # Reading the bind-mounted client.keys requires NO permission changes
    # on the SOC server: the file is plain-text and world-readable by the
    # `soc` user. If you ever want to switch to `agent_control -l`
    # (richer: includes connection status), set remote_command to
    # `docker exec cybersentinel-manager /var/ossec/bin/agent_control -l`
    # and grant docker access. The poller auto-detects the format.
    # `mode` picks how the registry is reached:
    #   ssh   — UEBA runs on its own host and reaches the SIEM over SSH.
    #   local — UEBA runs ON the SIEM host, so the registry is reachable
    #           without a network hop. SSHing to localhost was not merely
    #           wasteful, it failed outright wherever root@localhost is not
    #           permitted, and the only symptom was endpoints displaying as
    #           bare IPs instead of names, because agents.json never got
    #           written. Nothing in the UI said why.
    #
    # In local mode `local_command` is run through a shell, which is what
    # makes `docker exec ...` usable: on a containerised SIEM the registry is
    # not on the host filesystem at all. Verified on the first co-located
    # deployment — client.keys exists only inside the manager container.
    "agent_sync": {
        "enabled":            True,
        "mode":               "ssh",
        "poll_interval_secs": 60,
        "ssh_host":           "soc@localhost",
        "ssh_port":           2222,
        "ssh_key":            "/root/.ssh/id_ueba",
        "remote_command":     "cat /var/ossec/etc/client.keys",
        "local_command":      "cat /var/ossec/etc/client.keys",
        "ssh_timeout_secs":   20,
    },
}


def load_dashboard_config(config_path: str | None) -> dict:
    """Load the `dashboard:` block from ueba_config.yaml, layered on defaults."""
    cfg = dict(_DEFAULTS)
    cfg["ai_analyst"] = dict(_DEFAULTS["ai_analyst"])
    cfg["reporting"] = dict(_DEFAULTS["reporting"])
    cfg["reporting"]["smtp"] = dict(_DEFAULTS["reporting"]["smtp"])
    if not config_path or not yaml:
        return cfg
    p = Path(config_path)
    if not p.exists():
        return cfg
    try:
        with open(p, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[dashboard] failed to read {config_path}: {e}")
        return cfg
    dash = (raw.get("dashboard") or {}) if isinstance(raw, dict) else {}
    for k, v in dash.items():
        if k == "ai_analyst" and isinstance(v, dict):
            cfg["ai_analyst"].update(v)
        elif k == "agent_sync" and isinstance(v, dict):
            cfg.setdefault("agent_sync", dict(_DEFAULTS["agent_sync"]))
            cfg["agent_sync"].update(v)
        elif k == "notify" and isinstance(v, dict):
            base = dict(_DEFAULTS["notify"])
            base.update(v)
            cfg["notify"] = base
        elif k == "reporting" and isinstance(v, dict):
            # Two levels deep because of the nested smtp block: a site that
            # overrides only smtp.host must keep the default port and timeout
            # rather than losing them to a shallow replace.
            base = dict(_DEFAULTS["reporting"])
            base["smtp"] = dict(_DEFAULTS["reporting"]["smtp"])
            for rk, rv in v.items():
                if rk == "smtp" and isinstance(rv, dict):
                    base["smtp"].update(rv)
                else:
                    base[rk] = rv
            cfg["reporting"] = base
        else:
            cfg[k] = v

    # The watch-list store is shared with the engine, which reads it from the
    # `paths:` block. Falling back to that value means the file is configured in
    # exactly one place — if the two blocks could be set independently, a site
    # that changed only one would get a dashboard writing a file the engine
    # never reads, and watch lists that silently do nothing. An explicit
    # dashboard.watchlist_file still wins, for the rare split-host deployment.
    if "watchlist_file" not in dash and isinstance(raw, dict):
        shared = (raw.get("paths") or {}).get("watchlist_file")
        if shared:
            cfg["watchlist_file"] = shared
    return cfg


def load_raw_config(config_path: str | None) -> dict:
    """Whole parsed ueba_config.yaml — the auth layer reads its own `auth:` block."""
    if not config_path or not yaml:
        return {}
    p = Path(config_path)
    if not p.exists():
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"[dashboard] failed to read {config_path}: {e}")
        return {}


_SERVER_STARTED_AT = datetime.now(timezone.utc).isoformat()


# ── App + runtime config (populated in main()) ────────────────────────────────
# The dashboard is served from one of two places, in priority order:
#   1. dashboard/dist/         — built by `cd dashboard && npm run build`
#   2. dashboard/index.html    — legacy single-file fallback
# The decision is per-request so flipping between builds doesn't need a restart.
DASHBOARD_DIR     = Path(__file__).resolve().parent / "dashboard"
DASHBOARD_DIST    = DASHBOARD_DIR / "dist"
DASHBOARD_LEGACY  = DASHBOARD_DIR / "index.html"

app = Flask(__name__, static_folder=None)


def _configure_cors(auth_cfg: dict) -> str:
    """Apply the CORS policy.

    Historically this was a bare `CORS(app)` — `Access-Control-Allow-Origin: *`
    for every route. That is preserved verbatim while the dashboard is
    unauthenticated, so nothing changes for existing deployments. Once auth is
    enabled AND an explicit origin allowlist is configured, we switch to that
    allowlist with credentials enabled, because "wildcard origin" plus "session
    cookie" is the combination that lets any page a logged-in analyst visits
    read the alert feed.
    """
    origins = list(auth_cfg.get("cors_origins") or [])
    if auth_cfg.get("enabled") and origins:
        CORS(app, origins=origins, supports_credentials=True)
        return f"restricted to {len(origins)} origin(s)"
    CORS(app)
    return "open (*) — no origin allowlist configured"


# ── Response gzip ──
# The feed/charts are rendered entirely client-side from raw /api/feed rows, so a
# wide window ships tens of MB of highly-repetitive JSON. gzip cuts that ~10x on
# the wire (28MB → ~3MB) with no behaviour change. Stdlib only (no flask-compress
# dependency); kicks in only when the client advertises gzip and the body is big
# enough to be worth it, and never double-encodes a streamed/already-encoded body.
_GZIP_MIN_BYTES = 1024
# Short cache for /api/geofeed, keyed by (window_bytes, max_arcs). 5s sits just
# under the threat map's own 6s poll, so the map never shows anything staler
# than it would anyway.
_geofeed_cache: dict = {}
_GEOFEED_TTL = 5.0
# Upper bound for materialising a static file in order to compress it. The
# dashboard's largest asset is globe.gl at ~1.2 MB, so 8 MB leaves plenty of
# headroom while making it impossible for some future large file to be pulled
# into memory on every request.
_GZIP_MAX_STATIC_BYTES = 8 * 1024 * 1024
# Compressed static assets, keyed by (path, Last-Modified, Content-Length).
#
# This was keyed on the request path alone, on the reasoning that Vite gives
# every bundle a content hash in its filename so a path's bytes never change.
# That holds for /assets/index-<hash>.js. It is false for "/" and the SPA
# routes, which all serve index.html — whose contents change on every single
# rebuild while the path stays the same.
#
# The consequence was severe and very hard to see (hit 2026-10-28): after a
# frontend rebuild the process kept serving the PREVIOUS index.html to every
# client that sent Accept-Encoding: gzip, i.e. every browser, while an
# uncompressed request read the new file correctly from disk. The stale shell
# referenced bundle filenames the rebuild had deleted, so the browser got a
# 404 for its JS and CSS and rendered an unstyled skeleton. Nothing in the
# logs named the cause, and _serve_index()'s own no-store header — added to
# prevent exactly this class of failure at the browser — was powerless against
# a stale copy held server-side.
#
# Keying on the file's Last-Modified and Content-Length (both set by
# send_from_directory from the file stat) means a changed file cannot hit a
# stale entry: the key changes with the file. No restart needed after a
# rebuild, which is what the "decision is per-request" comment above the
# DASHBOARD_DIST definition already promised.
_static_gzip_cache: dict = {}
# Entries are small (compressed bytes of static assets) but the key space grows
# with every rebuild, so bound it rather than leak across a long uptime.
_GZIP_CACHE_MAX_ENTRIES = 64


@app.after_request
def _gzip_response(resp: "Response") -> "Response":
    try:
        accept = (request.headers.get("Accept-Encoding") or "")
        if "gzip" not in accept.lower():
            return resp
        if resp.headers.get("Content-Encoding"):
            return resp
        ctype = (resp.content_type or "")
        # NEVER touch SSE. /api/stream is an infinite open stream, so asking for
        # its body would block forever. It is text/* too, so this check has to
        # come before any of the type matching below.
        if ctype.startswith("text/event-stream"):
            return resp
        # Also catch the structured-suffix JSON types (RFC 6839): the threat
        # map's country polygons are served as application/geo+json, which the
        # plain "application/json" test misses — 426 KB going over the wire
        # uncompressed on every first load of the map.
        compressible = (
            ctype.startswith("application/json")
            or ctype.startswith("text/")
            or ctype.startswith("application/javascript")
            or (ctype.startswith("application/") and "+json" in ctype.split(";")[0])
        )
        if not compressible:
            return resp

        is_static = bool(resp.direct_passthrough)
        # Last-Modified + Content-Length come from the file stat, so the key
        # follows the file's identity rather than just its URL.
        cache_key = ((request.path,
                      resp.headers.get("Last-Modified"),
                      resp.headers.get("Content-Length"))
                     if is_static else None)

        if is_static:
            # send_from_directory() sets direct_passthrough for static files, and
            # this handler used to bail on that flag — which is why globe.gl was
            # shipping at 1,217 KB instead of its 373 KB gzipped size, and
            # three.js at 717 KB instead of 190 KB. Nearly 3 s of the threat-map
            # load was uncompressed JavaScript. Unlike SSE these are ordinary
            # finite files, so materialising them is safe; cap the size so a
            # large asset can never be pulled into memory wholesale.
            hit = _static_gzip_cache.get(cache_key)
            if hit is not None:
                resp.direct_passthrough = False
                resp.set_data(hit)
                resp.headers["Content-Encoding"] = "gzip"
                resp.headers["Content-Length"] = str(len(hit))
                resp.headers["Vary"] = "Accept-Encoding"
                return resp
            try:
                if (resp.content_length or 0) > _GZIP_MAX_STATIC_BYTES:
                    return resp
                resp.direct_passthrough = False
            except Exception:
                return resp

        data = resp.get_data()
        if len(data) < _GZIP_MIN_BYTES:
            return resp
        packed = gzip.compress(data, 6)
        if cache_key is not None:
            if len(_static_gzip_cache) >= _GZIP_CACHE_MAX_ENTRIES:
                _static_gzip_cache.clear()
            _static_gzip_cache[cache_key] = packed
        resp.set_data(packed)
        resp.headers["Content-Encoding"] = "gzip"
        resp.headers["Content-Length"] = str(len(resp.get_data()))
        vary = resp.headers.get("Vary")
        if not vary:
            resp.headers["Vary"] = "Accept-Encoding"
        elif "accept-encoding" not in vary.lower():
            resp.headers["Vary"] = vary + ", Accept-Encoding"
    except Exception:
        # Compression is a best-effort optimisation — never break a response over it.
        return resp
    return resp

# ── Audit trail ─────────────────────────────────────────────────────────────
# Every request that CHANGES something is recorded here. Reads are not audited:
# the feed is queried constantly by the dashboard's own polling, so logging GETs
# would bury the handful of entries that actually matter under machine traffic.
_audit_lock = __import__("threading").Lock()

# Methods that can alter server-side state. GET/HEAD/OPTIONS are read-only.
_AUDIT_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# Per-route allowlist of body fields safe to record. Anything not listed here is
# never written — see the note in _DEFAULTS about why bodies are not logged
# wholesale. Matched by path prefix.
_AUDIT_BODY_FIELDS = {
    "/api/false-positive": ("reason",),
    # Who was put under watch, and why, is the substance of the action — an
    # audit entry saying only "POST /api/watchlist" would be near-useless.
    "/api/watchlist":      ("type", "value", "reason", "boost"),
    # Which report, over what period, in what format. "Who pulled the audit
    # report for last quarter" is itself an auditable question, and recipients
    # matter because scheduling a report is how data leaves the platform.
    "/api/reports":        ("report_id", "format", "hours", "name", "interval",
                            "recipients"),
    # Never "rows" — the export body carries the alert table itself, and copying
    # it into the audit log would duplicate the whole feed on every export.
    "/api/export":         ("format", "title"),
    # Registering a device priority, or creating a rule that mails alerts out
    # of the platform, are both attributable actions.
    "/api/devices":        ("name", "label", "priority", "owner"),
    "/api/notify":         ("name", "min_score", "emails", "webhook", "enabled"),
}
_AUDIT_FIELD_MAXLEN = 200


def _audit_actor() -> dict:
    """Identify who made this request, as well as we currently can.

    While auth.enforce is off an unauthenticated request is normal, so the IP is
    the only identity available. That is recorded honestly as user=None rather
    than being dressed up as an account — an audit trail that invents actors is
    worse than one that admits it does not know.
    """
    user = None
    role = None
    if AUTH_MODULE_AVAILABLE:
        try:
            u = ueba_auth.current_user()
            if u:
                user = u.get("username") or u.get("sub")
                role = u.get("role")
        except Exception:
            pass
    # X-Forwarded-For is only meaningful behind a trusted proxy; the left-most
    # entry is the client. Fall back to the socket peer.
    fwd = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return {"user": user, "role": role, "ip": fwd or request.remote_addr}


def _audit_body() -> dict:
    """Allowlisted body fields for this path, if any. Never the whole body."""
    fields = None
    for prefix, allowed in _AUDIT_BODY_FIELDS.items():
        if request.path.startswith(prefix):
            fields = allowed
            break
    if not fields:
        return {}
    # Flask caches the parsed JSON on the request, so this does not re-read the
    # (already consumed) stream.
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return {}
    out = {}
    for f in fields:
        v = body.get(f)
        if v not in (None, ""):
            out[f] = str(v)[:_AUDIT_FIELD_MAXLEN]
    return out


def _audit_rotate_if_needed(path: Path, cap: int) -> None:
    """Keep one previous generation. Called with _audit_lock held."""
    try:
        if cap > 0 and path.exists() and path.stat().st_size >= cap:
            path.replace(path.with_suffix(path.suffix + ".1"))
    except Exception as e:
        print(f"[dashboard] audit rotate failed: {e}")


@app.after_request
def _audit_mutations(resp: "Response") -> "Response":
    """Record state-changing requests. Never allowed to break a response."""
    try:
        if not CFG.get("audit_enabled", True):
            return resp
        if request.method not in _AUDIT_METHODS:
            return resp
        entry = {
            "ts":     datetime.now(timezone.utc).isoformat(),
            "action": f"{request.method} {request.path}",
            "status": resp.status_code,
            # 2xx/3xx only. A 400 or 403 is still worth recording — a rejected
            # attempt is exactly the kind of thing an auditor looks for.
            "ok":     200 <= resp.status_code < 400,
        }
        entry.update(_audit_actor())
        detail = _audit_body()
        if detail:
            entry["detail"] = detail
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        cap = int(CFG.get("audit_max_bytes") or 0)
        with _audit_lock:
            _audit_rotate_if_needed(AUDIT_FILE, cap)
            AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(AUDIT_FILE, "a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception as e:
        # An audit failure must never cost the user their request.
        print(f"[dashboard] audit write failed: {e}")
    return resp


CFG: dict = dict(_DEFAULTS)
CFG["ai_analyst"] = dict(_DEFAULTS["ai_analyst"])
CFG["reporting"] = dict(_DEFAULTS["reporting"])
# The whole parsed ueba_config.yaml. The dashboard normally reads only its own
# `dashboard:` block, but the compliance report must describe engine-side
# settings (profiling window, retention) accurately rather than guess.
_RAW_CFG: dict = {}
ALERTS_FILE: Path     = Path(_DEFAULTS["alerts_file"])
AGENTS_REGISTRY: Path = Path(_DEFAULTS["agents_registry"])
FP_FILE: Path         = Path(_DEFAULTS["false_positives_file"])
FP_PATTERNS_FILE: Path = Path(_DEFAULTS["fp_patterns_file"])
AUDIT_FILE: Path       = Path(_DEFAULTS["audit_file"])
WATCHLIST_FILE: Path   = Path(_DEFAULTS["watchlist_file"])

# ── Alert cache — avoids reading the full file on every API request ──
# The live alerts file is append-only and grows large (hundreds of MB). The
# engine appends every second, so an mtime-keyed cache never hits — instead we
# track the byte offset we've parsed up to and incrementally parse only the
# newly-appended lines, keeping a trimmed in-memory list. Inode + size guard a
# rotation/truncation (midnight rollover) by forcing a full re-read.
_alert_cache: list = []
_alert_cache_mtime: float = 0.0   # retained for compatibility (unused by the tail reader)
_alert_cache_off: int = 0         # byte offset parsed up to in the live file
_alert_cache_inode: int = 0       # inode of the file the offset belongs to
# Single-flight lock: during a cold window (engine rewrote the file → new inode)
# a burst of parallel API requests would otherwise each trigger a full re-parse
# of the hundreds-of-MB live file at once (thundering herd) and corrupt the shared
# cache via interleaved global mutation. Serialize the cache read/update so only
# one thread re-parses; the rest reuse the warm cache.
_alert_read_lock = __import__("threading").Lock()

# ── Archive cache — historical daily alert zips, keyed by path → (mtime, alerts).
# Daily archives are written once at the midnight rotation and never change, so
# a parsed file is cached until its mtime changes (which it never should). Only
# files inside the requested window are ever opened, so a 7-day view touches ~7
# small zips and an "All" view touches at most `history_days` of them — once.
_archive_lock = __import__("threading").Lock()
_archive_cache: dict = {}        # str(path) -> (mtime, [alerts])
_archive_warn_at: float = 0.0    # rate-limit malformed-archive warnings (epoch secs)
_last_window_total: int = 0      # pre-cap count of the most recent windowed read
# ...but "most recent" is per-THREAD, not global. The background warmer rebuilds
# several windows concurrently, so a plain global was being overwritten between
# _read_alerts_windowed() and the builder that reads it — /api/stats?hours=720
# would report window_total from whichever window the warmer happened to finish
# last (e.g. 686,106 shown against a window_total of 1,789,621). Each thread now
# keeps its own value, so the number always belongs to the window being built.
_tls = __import__("threading").local()


def _set_window_total(n: int) -> None:
    global _last_window_total
    _tls.window_total = int(n)
    _last_window_total = int(n)      # kept for any legacy reader


def _get_window_total() -> int:
    return int(getattr(_tls, "window_total", _last_window_total) or 0)
_MIN_DT = datetime.min.replace(tzinfo=timezone.utc)
_ARCHIVE_RE = re.compile(r"ueba_alerts_(\d{4}-\d{2}-\d{2})\.jsonl\.zip$")

# ── Slim projection ──────────────────────────────────────────────────────────
# Every dashboard consumer (stats/users/campaigns/incidents/agents/feed and the
# per-user/agent drilldowns) reads only a small, fixed set of fields. The full
# engine alert is a fat nested record (~8-10KB) dominated by `evidence` and
# `context.raw_event`, which exist only to (a) render the lazy evidence panel and
# (b) derive the user + MITRE tags. Retaining the full record for the whole
# history window is what pushed the dashboard to ~40GB RSS and made cold window
# builds slow. We instead project each alert to a slim record AT INGEST — keeping
# just the consumed fields and pre-resolving the user + MITRE lists — and drop
# the heavy blobs. Measured: retained memory 3.9GB -> 0.11GB per archive day
# (~3%). Evidence is no longer in RAM; /api/evidence lazy-loads it from disk by
# event_id (rare, single-row action). Bump _SLIM_VER when the kept field set
# changes so stale on-disk slim caches are rebuilt instead of served incomplete.
# v2 (2026-10-28) adds the scoring model and the entity's first-seen date, for
# RFP SN 54 (display threat BY MODEL) and SN 47 (account used for the first
# time). Both were present on the engine's alert and dropped here, so the feed
# table could never show or filter on them however the UI asked.
_SLIM_VER = 2


def _slim(a: dict) -> dict:
    """Project a full engine alert to the compact record the dashboard actually
    reads. Pre-resolves user + MITRE so subject/object/context.raw_event/evidence
    can be dropped. `_resolve_user`/get_user and `_alert_ts` still work because
    the resolved user is stored under the same `__user` memo key they check, and
    the timestamp is recomputed lazily from the retained processed_at/event_time."""
    ueba = a.get("ueba") or {}
    sec  = a.get("security") or {}
    host = a.get("host") or {}
    rev  = (a.get("context") or {}).get("raw_event") or {}
    ev   = a.get("evidence") or {}
    return {
        "event_id":   a.get("event_id"),
        "event_time": a.get("event_time"),
        "ueba": {
            "risk_verdict":    ueba.get("risk_verdict"),
            "combined_score":  ueba.get("combined_score"),
            "campaign_id":     ueba.get("campaign_id"),
            "anomaly_reasons": ueba.get("anomaly_reasons") or [],
            "processed_at":    ueba.get("processed_at"),
            # Only set on watch-listed alerts, so this costs nothing on the
            # overwhelming majority of records. It has to be carried here or the
            # badge would appear on live-streamed alerts and then vanish once
            # the alert came back from the cache as a slim record.
            "watchlist":       ueba.get("watchlist"),
            "model_score":     ueba.get("model_score"),
            "watch_boost":     ueba.get("watch_boost"),
            # Two strings, kept deliberately rather than the whole raw_scores
            # block: which autoencoder scored this row, and whether it was the
            # entity's own model or the global fallback.
            "raw_scores": {"autoencoder": {
                "model_used": ((ueba.get("raw_scores") or {})
                               .get("autoencoder") or {}).get("model_used"),
                "model_type": ((ueba.get("raw_scores") or {})
                               .get("autoencoder") or {}).get("model_type"),
            }},
        },
        # One date, not the whole evidence blob: when this entity was first
        # ever observed, which is what makes "first use" and "dormant return"
        # visible in the table instead of only in the expanded evidence pane.
        "evidence": {"history": {
            "first_seen": ((ev.get("history") or {}).get("first_seen")),
        }},
        "security": {
            "signature":    sec.get("signature"),
            "signature_id": sec.get("signature_id"),
            "severity":     sec.get("severity"),
        },
        "host": {"name": host.get("name"), "ip": host.get("ip")},
        # Pre-resolved (see get_user memo) so builders never touch the dropped
        # subject/object/raw_event blobs again.
        "__user": _resolve_user(a),
        "__mitre_tactic":     ((rev.get("rule") or {}).get("mitre") or {}).get("tactic") or [],
        "__mitre_techniques": ((ev.get("signature") or {}).get("mitre_techniques")) or [],
    }

# ── False-positive store — in-memory dict, persisted to FP_FILE atomically ──
# Maps event_id -> {"event_id": ..., "reason": "...", "marked_at": "..."}
_fp_lock = __import__("threading").Lock()
_fp_dict: dict = {}

# ── False-positive pattern store ─────────────────────────────────────────────
# Each pattern auto-suppresses any future alert whose rule description
# (security.signature) matches `rule_description`. Comparison is whitespace-
# trimmed and case-insensitive so analysts don't have to worry about minor
# string normalisation differences between the SIEM source and the alert
# stream. Persisted to FP_PATTERNS_FILE atomically.
_fp_pat_lock = __import__("threading").Lock()
_fp_patterns: list = []  # list of dicts: {id, rule_description, reason, marked_at}
# Lookup index over _fp_patterns, keyed by normalised rule_description.
#   {norm_desc: [(marked_at_dt, pattern), ...]}   (original list order preserved)
# _matching_pattern used to LINEAR-SCAN every pattern for every alert, and each
# comparison re-normalised two strings and re-parsed two ISO timestamps. On the
# "All" window that was 500k alerts x 204 patterns = ~102M comparisons, measured
# at 28.7s per load_alerts() call — and every endpoint calls it. Indexing by
# description makes the lookup O(1) and parses each pattern's marked_at once.
_fp_pat_index: dict = {}


def _norm_desc(s) -> str:
    """Normalise a rule description for matching: trim + lowercase."""
    return (str(s or "")).strip().lower()


def _parse_iso(ts) -> datetime | None:
    """Parse an ISO-8601 timestamp; return None if missing/unparseable."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None

# ── Agent sync state (populated by the background poller) ────────────────────
_agent_sync_last_at: str = ""           # ISO timestamp of last successful poll
_agent_sync_last_error: str = ""        # last error message (for /api/health)
_agent_sync_lock = __import__("threading").Lock()


def _parse_client_keys(stdout: str) -> list[dict]:
    """Parse a SIEM `client.keys` file into [{id, name, ip}].

    Format is one agent per line: `<id> <name> <ip|"any"> <key>`. Lines
    starting with `#` or `!` (revoked) are skipped. IDs `000` / `0` are
    the manager itself and are skipped too.
    """
    out: list[dict] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        agent_id, name, ip = parts[0], parts[1], parts[2]
        if agent_id in ("000", "0"):
            continue
        # `any` is the SIEM's placeholder when no fixed IP was configured.
        if ip.lower() == "any":
            ip = ""
        else:
            ip = ip.split("/")[0]   # drop /netmask if present
        out.append({
            "id":     agent_id,
            "name":   name,
            "ip":     ip,
            "status": "",            # client.keys doesn't carry status
        })
    return out


def _parse_agent_control_l(stdout: str) -> list[dict]:
    """Parse the output of `agent_control -l` into a list of {id, name, ip} dicts.

    Typical output format (the banner line is ignored; the parser keys on
    the `ID:` prefix):

        agent_control. List of available agents:
           ID: 000, Name: cybersentinel-manager (server), IP: 127.0.0.1, Active/Local
           ID: 001, Name: Sparta1, IP: 10.200.11.106/any, Active
           ID: 002, Name: KAFKA_ME_P, IP: 10.200.10.174, Disconnected
        ...

    Server-self entry (ID 000) is skipped — it isn't a real endpoint.
    """
    import re as _re
    line_re = _re.compile(
        r"ID:\s*(?P<id>\S+)\s*,\s*"
        r"Name:\s*(?P<name>.+?)(?:\s*\([^)]+\))?\s*,\s*"
        r"IP:\s*(?P<ip>[^,\s]+)\s*,\s*"
        r"(?P<status>.+?)\s*$"
    )
    out: list[dict] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or not line.lstrip().startswith("ID:"):
            continue
        m = line_re.match(line)
        if not m:
            continue
        agent_id = m.group("id").strip()
        if agent_id in ("000", "0"):
            continue                                # skip the manager itself
        ip = m.group("ip").split("/")[0]            # strip /any or /netmask
        out.append({
            "id":     agent_id,
            "name":   m.group("name").strip(),
            "ip":     ip,
            "status": m.group("status").strip().lower(),
        })
    return out


def _fetch_agents_from_soc() -> tuple[list[dict] | None, str]:
    """SSH to the SOC server and run `agent_control -l`, parse the result.

    Returns (agents, error_message). On success error_message is "".
    On failure agents is None and error_message describes the problem.
    """
    cfg = CFG.get("agent_sync") or _DEFAULTS["agent_sync"]
    timeout = int(cfg.get("ssh_timeout_secs", 20))
    mode = str(cfg.get("mode", "ssh")).strip().lower()

    if mode == "local":
        # Through a shell on purpose: the useful command on a containerised
        # SIEM is `docker exec <manager> cat /var/ossec/etc/client.keys`, and
        # that needs shell word-splitting. The command comes from our own
        # config file, not from a request, so it is operator input.
        cmd = cfg.get("local_command") or cfg.get("remote_command")
        shell = True
        what = "local command"
    else:
        cmd = [
            "ssh",
            "-p", str(cfg["ssh_port"]),
            "-i", cfg["ssh_key"],
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={timeout}",
            cfg["ssh_host"],
            cfg["remote_command"],
        ]
        shell = False
        what = "remote command"

    try:
        import subprocess
        r = subprocess.run(
            cmd, capture_output=True, text=True, shell=shell,
            timeout=timeout + 5,
        )
    except Exception as e:
        return None, f"{what} failed: {e}"
    if r.returncode != 0:
        # Surface stderr (first line) so the operator can fix permissions.
        err = (r.stderr or "").strip().splitlines()[:1]
        return None, f"{what} rc={r.returncode}: {' / '.join(err)}"
    # Auto-detect the output format. client.keys lines start with the
    # agent id followed by a space; agent_control lines start with "ID:".
    stdout = r.stdout
    agents = _parse_client_keys(stdout)
    if not agents:
        agents = _parse_agent_control_l(stdout)
    if not agents:
        return None, "remote command returned no parseable agents"
    return agents, ""


def _merge_agents(fresh: list[dict], existing_path: Path) -> list[dict]:
    """Merge `fresh` (from agent_control) with existing agents.json entries.

    Preserves fields the CLI doesn't return — most importantly `os` — by
    keying on agent id. New agents picked up from the SIEM just won't have
    those fields until the operator fills them in (or we extend the
    poller to call `agent_control -i <id>` for OS info).
    """
    by_id: dict = {}
    if existing_path.exists():
        try:
            for rec in json.loads(existing_path.read_text(encoding="utf-8") or "[]"):
                if isinstance(rec, dict) and rec.get("id"):
                    by_id[str(rec["id"])] = dict(rec)
        except Exception:
            pass
    fresh_ids: set = set()
    out: list[dict] = []
    for a in fresh:
        aid = str(a["id"])
        fresh_ids.add(aid)
        merged = dict(by_id.get(aid, {}))
        # Always trust the manager for id + name. For ip/status, only
        # overwrite when fresh has a real value — client.keys can return
        # empty strings (e.g. when an agent's IP is configured as "any"
        # or status isn't available from the file).
        merged["id"]   = aid
        merged["name"] = a["name"]
        if a.get("ip"):
            merged["ip"] = a["ip"]
        elif "ip" not in merged:
            merged["ip"] = ""
        if a.get("status"):
            merged["status"] = a["status"]
        out.append(merged)
    # Sort by numeric id for stable ordering.
    out.sort(key=lambda r: (int(r["id"]) if str(r["id"]).isdigit() else 9999, r["id"]))
    return out


def _write_agents_atomically(path: Path, agents: list[dict]) -> None:
    """Write agents.json with a tmp+rename so a reader never sees a half file."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(agents, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def _agent_sync_poll() -> None:
    """One round of the agent sync — runs in the background thread."""
    global _agent_sync_last_at, _agent_sync_last_error
    fresh, err = _fetch_agents_from_soc()
    with _agent_sync_lock:
        if err:
            _agent_sync_last_error = err
            print(f"[agent-sync] failed: {err}", flush=True)
            return
        try:
            merged = _merge_agents(fresh, AGENTS_REGISTRY)
            _write_agents_atomically(AGENTS_REGISTRY, merged)
            _agent_sync_last_at    = datetime.now(timezone.utc).isoformat()
            _agent_sync_last_error = ""
            print(f"[agent-sync] wrote {len(merged)} agents to {AGENTS_REGISTRY}", flush=True)
        except Exception as e:
            _agent_sync_last_error = f"write failed: {e}"
            print(f"[agent-sync] write failed: {e}", flush=True)


def _start_agent_sync_thread() -> None:
    """Spawn the agent-sync background thread (daemon, won't block shutdown)."""
    import threading
    cfg = CFG.get("agent_sync") or _DEFAULTS["agent_sync"]
    if not cfg.get("enabled"):
        print("[agent-sync] disabled in config")
        return
    interval = max(15, int(cfg.get("poll_interval_secs", 60)))

    def _loop():
        # Do one fetch immediately so first request after startup is fresh.
        _agent_sync_poll()
        while True:
            time.sleep(interval)
            _agent_sync_poll()

    t = threading.Thread(target=_loop, name="agent-sync", daemon=True)
    t.start()
    print(f"[agent-sync] polling every {interval}s — `{cfg['remote_command']}`")


def load_fps() -> None:
    """Load FPs from disk into _fp_dict. Safe to call multiple times."""
    global _fp_dict
    if not FP_FILE.exists():
        _fp_dict = {}
        return
    try:
        data = json.loads(FP_FILE.read_text(encoding="utf-8") or "[]")
        if isinstance(data, list):
            _fp_dict = {r["event_id"]: r for r in data if isinstance(r, dict) and r.get("event_id")}
        else:
            _fp_dict = {}
    except Exception as e:
        print(f"[dashboard] failed to load FP file {FP_FILE}: {e}")
        _fp_dict = {}


def save_fps() -> None:
    """Atomically write _fp_dict to FP_FILE."""
    tmp = FP_FILE.with_suffix(FP_FILE.suffix + ".tmp")
    try:
        FP_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(list(_fp_dict.values()), indent=2), encoding="utf-8")
        tmp.replace(FP_FILE)
    except Exception as e:
        print(f"[dashboard] failed to persist FPs to {FP_FILE}: {e}")
    # FP state changed → cached aggregations now include alerts that should be
    # filtered (or vice-versa). Drop them so the next request recomputes fresh and
    # the analyst sees their FP mark take effect immediately, not after the TTL.
    _invalidate_result_cache()


def load_fp_patterns() -> None:
    """Load FP patterns from disk into _fp_patterns.

    Accepts both the new shape (`rule_description`) and the legacy shape
    (`signature_id` + optional `user`/`agent`). Legacy entries are dropped
    with a warning since they can't be migrated without alert context — the
    analyst will need to re-mark a representative alert FP to recreate them.
    """
    global _fp_patterns
    if not FP_PATTERNS_FILE.exists():
        _fp_patterns = []
        _rebuild_fp_pattern_index()   # clear the index too, or it goes stale
        return
    try:
        data = json.loads(FP_PATTERNS_FILE.read_text(encoding="utf-8") or "[]")
        if isinstance(data, list):
            kept, dropped = [], 0
            for p in data:
                if isinstance(p, dict) and (p.get("rule_description") or "").strip():
                    kept.append(p)
                elif isinstance(p, dict) and p.get("signature_id"):
                    dropped += 1
            _fp_patterns = kept
            if dropped:
                print(f"[dashboard] dropped {dropped} legacy sig-based FP pattern(s) — re-mark to recreate")
        else:
            _fp_patterns = []
    except Exception as e:
        print(f"[dashboard] failed to load FP patterns {FP_PATTERNS_FILE}: {e}")
        _fp_patterns = []
    _rebuild_fp_pattern_index()


def save_fp_patterns() -> None:
    """Atomically write _fp_patterns to FP_PATTERNS_FILE.

    Also refreshes _fp_pat_index — every mutation path (add / bulk-replace /
    delete) calls through here, so the index can never drift from the list."""
    _rebuild_fp_pattern_index()
    tmp = FP_PATTERNS_FILE.with_suffix(FP_PATTERNS_FILE.suffix + ".tmp")
    try:
        FP_PATTERNS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(_fp_patterns, indent=2), encoding="utf-8")
        tmp.replace(FP_PATTERNS_FILE)
    except Exception as e:
        print(f"[dashboard] failed to persist FP patterns to {FP_PATTERNS_FILE}: {e}")
    _invalidate_result_cache()


def _alert_matches_pattern(alert: dict, pattern: dict) -> bool:
    """Return True iff alert's rule description matches the pattern's
    rule_description (trim + case-insensitive) AND the alert arrived after
    the pattern was created. The time guard keeps historical alerts visible
    — patterns only suppress NEW alerts going forward.
    """
    sec = alert.get("security", {}) or {}
    if _norm_desc(sec.get("signature")) != _norm_desc(pattern.get("rule_description")):
        return False
    # Time guard: pattern.marked_at must exist; alert must have been *emitted
    # by the engine* strictly later. Compare against ueba.processed_at (engine
    # time) rather than event_time (source time) — a backlog replay can produce
    # alerts whose event_time is days old but whose processed_at is "now".
    p_at = _parse_iso(pattern.get("marked_at"))
    ueba = alert.get("ueba", {}) or {}
    a_at = _parse_iso(ueba.get("processed_at") or alert.get("event_time"))
    if p_at is None or a_at is None:
        return False
    return a_at > p_at


def _rebuild_fp_pattern_index() -> None:
    """Rebuild _fp_pat_index from _fp_patterns. Call after any mutation of the
    pattern list. Patterns with an unparseable marked_at are skipped, matching
    _alert_matches_pattern's behaviour (it returns False when p_at is None)."""
    global _fp_pat_index
    idx: dict = {}
    for p in _fp_patterns:
        if not isinstance(p, dict):
            continue
        p_at = _parse_iso(p.get("marked_at"))
        if p_at is None:
            continue                      # never matches — same as the scan
        idx.setdefault(_norm_desc(p.get("rule_description")), []).append((p_at, p))
    _fp_pat_index = idx


def _matching_pattern(alert: dict):
    """Return the first FP pattern matching this alert, or None.

    Equivalent to scanning _fp_patterns with _alert_matches_pattern, but uses
    _fp_pat_index for an O(1) description lookup and reuses the memoised
    _alert_ts() parse instead of re-parsing the alert timestamp per pattern.
    Candidates keep their original list order, so the pattern returned for a
    given alert is unchanged."""
    if not _fp_pat_index:
        return None
    sec = alert.get("security", {}) or {}
    group = _fp_pat_index.get(_norm_desc(sec.get("signature")))
    if not group:
        return None
    a_at = _alert_ts(alert)               # memoised: processed_at, else event_time
    if a_at is None:
        return None
    for p_at, p in group:
        if a_at > p_at:                   # same strict time guard as before
            return p
    return None


def _pattern_from_alert(alert: dict, reason: str) -> dict | None:
    """Build an FP pattern record from an alert's rule description.

    The pattern suppresses every future alert whose rule description (the
    human-readable rule name, `security.signature`) matches — regardless of
    user, host, or even signature_id. This is the broad "this kind of activity
    is benign here" semantic.

    Returns None if the alert has no rule description.
    """
    sec = alert.get("security", {}) or {}
    desc = (str(sec.get("signature") or "")).strip()
    if not desc:
        return None
    return {
        "id":               "fpp-" + uuid.uuid4().hex[:10],
        "rule_description": desc,
        "reason":           reason or "auto-suppress from analyst FP mark",
        "marked_at":        datetime.now(timezone.utc).isoformat(),
    }


def _add_pattern_if_new(candidate: dict | None):
    """Append candidate to _fp_patterns unless an identical rule_description
    already exists. Returns (record, was_new). If candidate is None or has no
    rule_description, returns (None, False).
    """
    if not candidate or not (candidate.get("rule_description") or "").strip():
        return None, False
    cand_norm = _norm_desc(candidate["rule_description"])
    with _fp_pat_lock:
        for p in _fp_patterns:
            if _norm_desc(p.get("rule_description")) == cand_norm:
                return p, False
        _fp_patterns.append(candidate)
        save_fp_patterns()
        return candidate, True


def _remove_patterns_for_descriptions(descriptions) -> int:
    """Drop every FP pattern whose rule_description matches any in the given
    iterable (whitespace-trimmed, case-insensitive). Persists once if anything
    changed. Returns the number of patterns removed.

    Used by the FP restore flow so that un-marking an alert also tears down
    the auto-suppression pattern that was created when it was marked. Without
    this, Restore only frees the single event from the FP filter while the
    pattern keeps suppressing every other alert with the same signature —
    surprising the analyst and starving the engine of those alerts.
    """
    targets = {_norm_desc(d) for d in descriptions if d}
    if not targets:
        return 0
    removed = 0
    with _fp_pat_lock:
        keep = []
        for p in _fp_patterns:
            if _norm_desc(p.get("rule_description")) in targets:
                removed += 1
                continue
            keep.append(p)
        if removed:
            _fp_patterns[:] = keep
            save_fp_patterns()
    return removed


def _read_live_alerts(n: int | None = None) -> list:
    """Read the live ueba_alerts.jsonl (today's alerts), newest `n`, oldest-first
    (no FP filtering).

    The file is append-only and large (hundreds of MB of fat records), and the
    engine appends to it every second — so re-reading the whole file per request
    (and an mtime-keyed cache, which never hits because mtime keeps changing) made
    every API call re-parse the entire file and take minutes. Instead we keep a
    parsed cache and only read the bytes appended since the last call, tracking a
    byte offset; inode + a shrink check force a full re-read on midnight rotation.
    """
    global _alert_cache, _alert_cache_off, _alert_cache_inode
    if n is None:
        n = CFG["max_alerts"]
    if not ALERTS_FILE.exists():
        return []
    try:
        st = ALERTS_FILE.stat()
    except Exception:
        return _alert_cache[-n:] if n else _alert_cache

    # Serialize cache update so a burst of parallel requests during a cold window
    # doesn't trigger N concurrent full re-parses (thundering herd) or corrupt the
    # shared cache. One thread re-parses; the others wait then reuse the warm cache.
    with _alert_read_lock:
        # Detect rotation/truncation (midnight rollover replaces the file, or it
        # shrinks): drop the cache and re-read from the top.
        if st.st_ino != _alert_cache_inode or st.st_size < _alert_cache_off:
            _alert_cache = []
            _alert_cache_off = 0
            _alert_cache_inode = st.st_ino

        # Parse only the newly-appended bytes (if any) since the last read.
        if st.st_size > _alert_cache_off:
            try:
                with open(ALERTS_FILE, "rb") as f:
                    f.seek(_alert_cache_off)
                    chunk = f.read()
            except Exception:
                return _alert_cache[-n:] if n else _alert_cache
            # Consume up to the last complete line; a trailing partial line (engine
            # mid-append) is left for the next call.
            nl = chunk.rfind(b"\n")
            if nl != -1:
                complete = chunk[:nl + 1]
                _alert_cache_off += len(complete)
                for raw in complete.split(b"\n"):
                    if not raw.strip():
                        continue
                    try:
                        _alert_cache.append(_slim(_jloads(raw)))
                    except Exception:
                        continue
                cap = int(CFG.get("max_alerts", 500000) or 500000)
                if len(_alert_cache) > cap:
                    del _alert_cache[:len(_alert_cache) - cap]

        return _alert_cache[-n:] if n else _alert_cache


def _alert_ts(a: dict) -> datetime | None:
    """Best-effort timestamp for windowing/sorting: engine processed_at, else
    source event_time. Mirrors the client-side timeline filter.

    The parsed datetime is memoised on the alert dict under "__ts" because the
    same dicts live for a long time in the archive/live caches and were being
    re-parsed (datetime.fromisoformat) on every windowed request — hundreds of
    thousands of ISO strings per API call. Parse once, reuse forever; only newly
    appended alerts ever pay the parse. A separate sentinel distinguishes
    "not computed yet" from a legitimately unparseable timestamp (cached as None)."""
    cached = a.get("__ts", _TS_UNSET)
    # Valid memo states: a datetime, or None (a cached "unparseable" result).
    # Anything else (notably a str — which is what orjson would produce if a
    # datetime memo ever got serialized into a persisted slim cache) is treated
    # as "not computed" and recomputed, so a poisoned memo can never leak a str
    # into the datetime comparisons in the builders.
    if cached is None or isinstance(cached, datetime):
        return cached
    ueba = a.get("ueba") or {}
    ts = _parse_iso(ueba.get("processed_at") or a.get("event_time"))
    a["__ts"] = ts
    return ts


def _parse_archive_zip(path: Path) -> list | None:
    """Unzip a daily archive and parse its JSONL into a list of SLIM alert dicts
    (see _slim). Returns None on a hard failure (corrupt zip / unreadable) so the
    caller can skip it without aborting the whole window.

    Daily archives are immutable after the midnight rotation, so the first parse
    also writes a compact on-disk slim cache (`<archive>.slimN`) next to the zip;
    subsequent restarts load that directly — no unzip, no re-parse of the fat
    records, no re-projection. Measured: cold archive warm 295s -> a few seconds
    once the slim caches exist."""
    slim_path = path.with_suffix(".slim%d" % _SLIM_VER)
    # Fast path: a fresh slim cache already exists.
    try:
        if slim_path.exists() and slim_path.stat().st_mtime >= path.stat().st_mtime:
            data = _jloads(slim_path.read_bytes())
            if isinstance(data, list):
                return data
    except Exception:
        pass  # fall through to a full parse/rebuild
    try:
        alerts: list = []
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if n.endswith(".jsonl")] or zf.namelist()
            for name in names:
                with zf.open(name) as fh:
                    for raw in fh:
                        if not raw.strip():
                            continue
                        try:
                            alerts.append(_slim(_jloads(raw)))
                        except Exception:
                            continue
        # Persist the slim projection for the next restart (best-effort, atomic).
        try:
            tmp = slim_path.with_suffix(slim_path.suffix + ".tmp")
            tmp.write_bytes(_jdumps(alerts))
            tmp.replace(slim_path)
        except Exception:
            pass
        return alerts
    except Exception:
        return None


def _read_archived_alerts(cutoff: datetime) -> list:
    """Alerts from daily archive zips whose date is on/after `cutoff`'s date.
    Each archive is parsed once and cached by mtime (archives never change after
    the midnight rotation), and only files inside the window are ever opened."""
    global _archive_warn_at
    adir = Path(CFG.get("archive_dir") or "")
    if not adir.is_dir():
        return []
    cutoff_date = cutoff.date()
    out: list = []
    try:
        entries = sorted(adir.glob("ueba_alerts_*.jsonl.zip"))
    except Exception:
        return []
    for path in entries:
        m = _ARCHIVE_RE.search(path.name)
        if not m:
            continue
        try:
            fdate = datetime.strptime(m.group(1), "%Y-%m-%d").date()
        except ValueError:
            continue
        if fdate < cutoff_date:
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        with _archive_lock:
            cached = _archive_cache.get(str(path))
            if cached and cached[0] == mtime:
                out.extend(cached[1])
                continue
        # Parse outside the lock (unzip can be slow); store under the lock after.
        alerts = _parse_archive_zip(path)
        if alerts is None:
            now = time.time()
            if now - _archive_warn_at > 300:
                _archive_warn_at = now
                print(f"[dashboard] WARNING: could not read archive {path.name}; skipping")
            continue
        with _archive_lock:
            _archive_cache[str(path)] = (mtime, alerts)
        out.extend(alerts)
    return out


# Sentinel for the per-alert timestamp memo in _alert_ts (None is a valid,
# cached "unparseable" result, so it can't double as "not computed yet").
_TS_UNSET = object()

# ── Windowed snapshot cache (with thundering-herd protection) ────────────────
# Building a window (merge archives+live, decorate, sort, cap) is the single
# hottest path in the dashboard: every boot fires 5+ endpoints (stats/feed/users/
# campaigns/agents/health) that each call load_alerts() for the SAME window, and
# the 30s auto-refresh repeats it. Without coordination those requests rebuild
# the same multi-hundred-thousand-row list *concurrently* — saturating every core
# AND allocating N copies of the decorated list at once (which is exactly how a
# restart-time burst ballooned RSS toward OOM). Two-part fix:
#   1. Memoise the built window keyed by `hours` for a short TTL.
#   2. Serialise the *build* behind the lock so a cold-cache burst does ONE build
#      and every other caller waits for it and reuses the snapshot — never N
#      parallel builds. The lock is held during the build; that's intentional
#      (callers should wait, not pile up). TTL is well under the 30s refresh and
#      the live SSE stream still pushes new alerts in real time, so the brief
#      staleness is invisible.
_window_cache: dict = {}        # hours -> (built_at, list, window_total)
_window_cache_lock = __import__("threading").RLock()
_WINDOW_TTL = 5.0               # base TTL for cheap windows (seconds)
# Measured build cost per window, used to scale that TTL: hours -> seconds.
#
# A fixed 5s TTL was pathological for wide windows. The "All" window takes ~16s
# to build, so its snapshot was ALWAYS expired before anyone could use it: every
# request re-entered the build, took the global lock for ~16s, and queued all
# other endpoints behind it — which is what made single endpoints take 13-60s.
# Scaling the TTL by the observed build cost means an expensive window is reused
# for a while instead of being rebuilt continuously. Freshness is unaffected in
# practice: the SSE stream pushes new alerts to the client in real time.
_window_build_secs: dict = {}
_WINDOW_TTL_MAX = 300.0         # never hold a snapshot longer than this


def _window_ttl(hours: int) -> float:
    """TTL for a window's snapshot: at least _WINDOW_TTL, and at least ~6x what
    the window last cost to build, capped at _WINDOW_TTL_MAX."""
    built = _window_build_secs.get(hours, 0.0)
    return min(max(_WINDOW_TTL, built * 6.0), _WINDOW_TTL_MAX)


def _read_alerts_windowed(hours: int, n: int | None = None) -> list:
    """Live + archived alerts within the requested window, oldest-first, capped
    at `max_feed_alerts` (most-recent kept). hours==0 → full `history_days`.

    Records with an unparseable timestamp are kept (never silently dropped) and
    sorted as oldest. The pre-cap in-window total is stashed in
    `_last_window_total` so /api/stats can tell the analyst when a wide window
    was truncated.

    Results are memoised for `_WINDOW_TTL` seconds keyed by `hours`, and the build
    is serialised (see the herd note above) so a burst of concurrent endpoints
    reuses one snapshot instead of each rebuilding it. `n` is not part of the key:
    every API caller uses the default (max_alerts), so it never varies."""
    global _last_window_total

    def _fresh():
        hit = _window_cache.get(hours)
        if hit is not None and (time.time() - hit[0]) < _window_ttl(hours):
            return hit
        return None

    # Fast path: a fresh snapshot already exists — return it without building.
    with _window_cache_lock:
        hit = _fresh()
        if hit is not None:
            _set_window_total(hit[2])
            return hit[1]

        # Cold/stale. Build while holding the lock so concurrent callers block
        # here and then fall through to reuse what we store — one build, not N.
        # (Re-check first in case we raced another builder that just finished.)
        hit = _fresh()
        if hit is not None:
            _set_window_total(hit[2])
            return hit[1]

        _build_started = time.time()
        history_days = int(CFG.get("history_days", 95) or 95)
        cap = int(CFG.get("max_feed_alerts", 10000) or 10000)
        now = datetime.now(timezone.utc)
        cutoff = now - (timedelta(hours=hours) if hours and hours > 0
                        else timedelta(days=history_days))

        combined = _read_archived_alerts(cutoff) + _read_live_alerts(n)
        decorated = []
        for a in combined:
            ts = _alert_ts(a)
            if ts is None or ts >= cutoff:
                decorated.append((ts or _MIN_DT, a))
        decorated.sort(key=lambda t: t[0])
        window_total = len(decorated)
        if len(decorated) > cap:
            decorated = decorated[-cap:]
        result = [a for _, a in decorated]

        _set_window_total(window_total)
        _window_build_secs[hours] = time.time() - _build_started
        _window_cache[hours] = (time.time(), result, window_total)
        return result


def _read_all_alerts_for_lookup() -> list:
    """Live + ALL archived alerts within history_days, UNCAPPED. Used only by the
    FP mutators to resolve an alert (or campaign) by id — they must find any
    alert the analyst can currently see, including ones loaded from archives."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(CFG.get("history_days", 95) or 95))
    return _read_archived_alerts(cutoff) + _read_live_alerts()


def _window_hours() -> int:
    """Timeline window (hours) requested via ?hours=N. 0 / absent / invalid → 0
    ('All', bounded server-side to history_days), matching the default view."""
    if not has_request_context():
        return 0
    v = (request.args.get("hours") or "").strip()
    if not v:
        return 0
    try:
        h = int(v)
        return h if h > 0 else 0
    except (TypeError, ValueError):
        return 0


def load_alerts(n: int | None = None, include_fp: bool = False,
                hours: int | None = None) -> list:
    """Load alerts for the current timeline window. By default filters out any
    alert that is FP-marked, either by event_id (per-instance) or by a stored
    fingerprint pattern (signature_id + user + agent). Pass include_fp=True to
    opt out (used by the "show FPs" feed view and by /api/false-positives).

    The window comes from the request's ?hours=N (0 = All) unless `hours` is
    passed explicitly. Spans live + archived alerts so the timeline filters
    actually have history to show.
    """
    if hours is None:
        hours = _window_hours()
    raw = _read_alerts_windowed(hours, n)
    if include_fp:
        return raw
    if not _fp_dict and not _fp_patterns:
        return raw
    out = []
    for a in raw:
        if a.get("event_id") in _fp_dict:
            continue
        if _matching_pattern(a) is not None:
            continue
        out.append(a)
    return out


def _wants_include_fp() -> bool:
    """Read ?include_fp=1 from the current request."""
    v = (request.args.get("include_fp") or "").strip().lower()
    return v in ("1", "true", "yes", "y")


# ── Endpoint result cache + background warmer ────────────────────────────────
# The window snapshot cache (above) makes *loading* a window cheap, but each
# heavy endpoint (stats/users/campaigns/agents/feed) still iterates the whole
# window to AGGREGATE its answer — and for the wide "All" window that's 300k+
# alerts per endpoint. Python's GIL serialises those CPU-bound aggregations, so a
# boot burst of 5 endpoints runs them back-to-back (~13s on "All"). Two parts:
#   1. Cache each endpoint's computed JSON value keyed by (name, hours, include_fp)
#      so a refresh / extra browser tab / multi-analyst fleet returns instantly.
#   2. A background warmer recomputes the cache for *actively-viewed* windows every
#      few seconds, so a window someone is watching is always pre-aggregated and
#      its next load is instant — the heavy aggregation happens off the request
#      path. Idle windows stop being refreshed and age out, so we never burn CPU
#      aggregating a window nobody is looking at.
# Staleness is bounded by the warm interval (seconds) and is invisible: the feed
# table auto-refreshes every 30s and the live SSE stream pushes new alerts in
# real time regardless.
# Reads of _result_cache never block: dict get/set are atomic under the GIL, and
# readers serve the last cached value while the warmer refreshes it in the
# background. Builds are coordinated by *per-key* locks so (a) two threads never
# build the same key at once and (b) one slow endpoint's build never blocks a
# different endpoint or window. The big shared alert list is built once by the
# window cache (with its own herd lock), so concurrent per-endpoint aggregations
# operate on that shared list and don't each duplicate it — memory stays bounded.
_result_cache: dict = {}            # (name, hours, include_fp) -> (built_at, value)
_active_windows: dict = {}          # (hours, include_fp) -> last_requested (epoch)
_result_build_locks: dict = {}      # key -> Lock (one builder per key)
_result_locks_guard = __import__("threading").Lock()
_RESULT_TTL = 45.0                  # a value newer than this is served as-is
_STALE_SERVE_MAX = 600.0            # serve an older value rather than block, up to this
_RESULT_REFRESH_AGE = 60.0          # warmer rebuilds an entry only once it's older than this
# Was 18s. Raised to 60s when max_feed_alerts went 500k -> 2M: aggregating a wide
# window costs ~14s, so an 18s cadence on the window an analyst is watching would
# have spent ~78% of a core rebuilding it continuously. 60s keeps that near 23%.
# Freshness is unaffected in practice — the browser only re-polls every 60s, and
# the SSE stream pushes new alerts to the feed in real time regardless.
# Refresh age for a STANDARD window that nobody is currently viewing. Keeping all
# seven windows at the 18s cadence cost ~89% of a core continuously, which then
# contended with live requests. Idle windows only need to be warm *enough* that
# clicking them is instant; once clicked the window becomes active and drops back
# to the 18s cadence, so the analyst sees current numbers within one tick.
# 150s here still cost ~71% of a core: refreshing a wide window re-reads and
# re-sorts the whole retained archive (~1M records), and 720/1440/2160/0
# currently return identical data (retained history is under 30 days), so most
# of that work is duplicated. 600s keeps window-switching instant for a fraction
# of the CPU; a just-clicked window is at most this stale for one 18s tick.
_IDLE_REFRESH_AGE = 600.0
_WARM_TICK = 5.0                    # how often the warmer wakes to check freshness
_ACTIVE_WINDOW_TTL = 180.0          # keep warming a window seen within this long
# The seven windows the timeline selector offers, most-used first. These are kept
# permanently warm rather than only while "recently viewed": a window nobody had
# touched for 3 minutes fell out of _active_windows and went cold, so the next
# click on it paid a full cold aggregation — measured at 6.7s (3D), 11.9s (60D)
# and 9.1s (90D). Seven windows is a small, fixed set, so just hold them all.
_STANDARD_WINDOWS = (24, 168, 0, 72, 720, 1440, 2160)
_ENDPOINT_BUILDERS: dict = {}       # name -> builder(alerts) -> JSON value


def _build_lock_for(key):
    """Per-key build lock so only one thread (re)builds a given cache entry, while
    other keys build freely in parallel."""
    with _result_locks_guard:
        lk = _result_build_locks.get(key)
        if lk is None:
            lk = __import__("threading").Lock()
            _result_build_locks[key] = lk
        return lk


def _invalidate_result_cache() -> None:
    """Drop all cached endpoint results (e.g. after a false-positive change) so the
    next request recomputes against the new FP state instead of serving a stale
    aggregation. Safe to call from any thread / request handler."""
    _result_cache.clear()


def _build_and_store(name: str, builder, hours: int, include_fp: bool):
    """(Re)build one cache entry under its per-key lock and store it. Returns the
    fresh value. If another thread built it while we waited for the lock, reuse
    that instead of rebuilding."""
    key = (name, hours, include_fp)
    with _build_lock_for(key):
        hit = _result_cache.get(key)
        if hit is not None and (time.time() - hit[0]) < _RESULT_TTL:
            return hit[1]
        alerts = load_alerts(include_fp=include_fp, hours=hours)
        value = builder(alerts)
        _result_cache[key] = (time.time(), value)
        return value


def _endpoint_result(name: str, builder, hours: int, include_fp: bool):
    """Return the cached value for (name, hours, include_fp). Fresh hits return
    instantly with no lock. A slightly-stale value is also returned immediately
    (the warmer keeps active windows fresh in the background); we only block to
    build when there is no usable cached value at all (first-ever request for the
    window, or right after a cache invalidation)."""
    key = (name, hours, include_fp)
    now = time.time()
    _active_windows[(hours, include_fp)] = now
    hit = _result_cache.get(key)
    if hit is not None:
        age = now - hit[0]
        if age < _RESULT_TTL:
            return hit[1]                       # fresh — instant
        if age < _STALE_SERVE_MAX:
            return hit[1]                       # serve stale now; warmer will refresh
    # No usable cached value → build it (per-key lock; concurrent callers for the
    # same key wait once and then reuse).
    return _build_and_store(name, builder, hours, include_fp)


def _cached_endpoint(name: str, builder):
    """Request-context entry point: resolve the window from the request, register
    it as active (so the warmer keeps it hot), and return the cached/built value."""
    return _endpoint_result(name, builder, _window_hours(), _wants_include_fp())


def _warm_results_loop() -> None:
    """Daemon: keep the result cache hot for windows analysts are actively viewing
    so their loads stay instant. The heavy aggregation runs here, off the request
    path; each (endpoint, window) is rebuilt under its own per-key lock so it never
    blocks a live request for a different endpoint/window."""
    while True:
        try:
            time.sleep(_WARM_TICK)
            now = time.time()
            active = {w for w, seen in list(_active_windows.items())
                      if (now - seen) < _ACTIVE_WINDOW_TTL}
            windows = list(active)
            # Always keep the fixed timeline windows hot, even when idle, so
            # switching between them never pays a cold build — but refresh the
            # idle ones far less often (see _IDLE_REFRESH_AGE).
            for _h in _STANDARD_WINDOWS:
                if (_h, False) not in windows:
                    windows.append((_h, False))
            for (hours, include_fp) in windows:
                # Only rebuild entries that are getting stale — skip ones still
                # fresh so the warmer doesn't peg a core recomputing the heavy
                # "All" window every tick for no benefit.
                max_age = (_RESULT_REFRESH_AGE if (hours, include_fp) in active
                           else _IDLE_REFRESH_AGE)
                stale = []
                for name, builder in list(_ENDPOINT_BUILDERS.items()):
                    hit = _result_cache.get((name, hours, include_fp))
                    if hit is not None and (now - hit[0]) < max_age:
                        continue
                    stale.append((name, builder))
                if not stale:
                    continue
                # Load the window ONCE and share it across every builder that
                # needs it. This used to sit inside the endpoint loop, so a tick
                # that refreshed 6 endpoints paid the window read (and the FP
                # filter) 6 times over.
                try:
                    alerts = load_alerts(include_fp=include_fp, hours=hours)
                except Exception:
                    continue
                for name, builder in stale:
                    try:
                        key = (name, hours, include_fp)
                        with _build_lock_for(key):
                            _result_cache[key] = (time.time(), builder(alerts))
                    except Exception:
                        pass  # never let one bad build kill the warmer
        except Exception:
            time.sleep(_WARM_TICK)


def _looks_like_request(v) -> bool:
    """True if a string looks like an HTTP request path / URL / query rather than
    a username. Web-attack decoders (SQLi/XSS scans on /search.php?q=...) put the
    raw request in object.name, which must NEVER be shown as a 'user' — otherwise
    every unique attack payload becomes its own bogus user in the risk view.
    Real usernames (incl. DOMAIN\\user) never start with '/' or contain '?'/'%2'."""
    if not isinstance(v, str):
        return False
    s = v.strip()
    if not s:
        return False
    return (s.startswith("/") or s.startswith("http://") or s.startswith("https://")
            or "?" in s or "%2" in s or "../" in s or "<" in s)


def get_user(alert: dict) -> str:
    """Resolve the most meaningful username from an alert, memoised on the dict.

    The resolution (below) is non-trivial — many nested lookups plus a regex
    request-shape check at every step — and it's called once per alert by stats,
    users, campaigns, agents AND the per-user/agent drilldowns, which each scan
    the whole window. Caching the result on the dict (`__user`) makes a repeat
    scan a dict.get instead of re-resolving 300k+ times. Same dicts live in the
    alert caches, so the memo persists; only new alerts pay the resolution."""
    cached = alert.get("__user", _TS_UNSET)
    if cached is not _TS_UNSET:
        return cached
    u = _resolve_user(alert)
    alert["__user"] = u
    return u


def _resolve_user(alert: dict) -> str:
    """Resolve the most meaningful username from an alert.
    Priority: subject.name > raw_event user fields > object.name (if not a URL)
              > host/agent name > subject.ip > ae model (if personal) > 'unknown'

    Request-like values (URLs/paths/queries from web-attack events) are rejected
    at every step, and user-less events fall back to the AGENT name rather than a
    raw IP — so web scans group under their target agent (e.g. 'Agent-70') instead
    of flooding the view with one 'user' per attack payload.
    """
    sub  = alert.get("subject", {}) or {}
    obj  = alert.get("object", {}) or {}
    ueba = alert.get("ueba", {}) or {}
    host = alert.get("host", {}) or {}
    raw  = (alert.get("context", {}) or {}).get("raw_event", {}) or {}
    win  = (raw.get("data", {}) or {}).get("win", {}) or {}
    wed  = (win.get("eventdata", {}) or {})
    raw_data = raw.get("data", {}) or {}

    def _ok(v):
        return v and v not in ("", "-", None) and not _looks_like_request(v)

    if _ok(sub.get("name")):
        return sub["name"]

    for field in ("subjectUserName", "targetUserName", "subjectDomainName"):
        if _ok(wed.get(field)):
            return wed[field]

    for field in ("srcuser", "dstuser", "user", "username", "accountName"):
        if _ok(raw_data.get(field)):
            return raw_data[field]

    if _ok(obj.get("name")):
        return obj["name"]

    # No real username — prefer the AGENT/host name over a bare IP so web-attack
    # scans and other user-less events group under their agent instead of a
    # request URL or a raw IP.
    hname = host.get("name")
    if hname and hname not in ("", None):
        return hname

    ip = sub.get("ip")
    if ip and ip not in ("", None):
        return ip

    model = ueba.get("raw_scores", {}).get("autoencoder", {}).get("model_used", "")
    if model and model not in ("global", "unknown", "", None):
        return model

    return "unknown"


@app.route("/api/stats")
def stats():
    """Overall stats for the stats overview panel."""
    return jsonify(_cached_endpoint("stats", _build_stats))


def _build_stats(alerts):
    if not alerts:
        return {
            "total_alerts": 0, "highly_anomalous": 0, "anomalous": 0,
            "suspicious": 0, "campaigns": 0, "suppressed_noise": 0,
            "unique_users": 0, "alert_rate_1h": 0, "top_reasons": []
        }

    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)

    # Single pass over the window (was 7 separate passes) — for the wide "All"
    # window that's 300k+ alerts, so collapsing the passes makes this ~7x cheaper
    # and keeps the background warmer light.
    total = len(alerts)
    highly = anomalous = suspicious = alert_rate_1h = 0
    campaign_ids: set = set()
    users_seen: set = set()
    reason_counts: dict = defaultdict(int)
    for a in alerts:
        ueba = a.get("ueba", {}) or {}
        verdict = ueba.get("risk_verdict")
        if verdict == "highly_anomalous": highly += 1
        elif verdict == "anomalous":      anomalous += 1
        elif verdict == "suspicious":     suspicious += 1
        cid = ueba.get("campaign_id")
        if cid:
            campaign_ids.add(cid)
        users_seen.add(get_user(a))
        for r in (ueba.get("anomaly_reasons") or []):
            reason_counts[r] += 1
        ts = _alert_ts(a)   # memoised parse
        if ts is not None and ts >= one_hour_ago:
            alert_rate_1h += 1

    campaigns    = len(campaign_ids)
    unique_users = len(users_seen)
    top_reasons  = sorted(reason_counts.items(), key=lambda x: -x[1])[:5]

    cap = int(CFG.get("max_feed_alerts", 10000) or 10000)
    return {
        "total_alerts":    total,
        "highly_anomalous": highly,
        "anomalous":       anomalous,
        "suspicious":      suspicious,
        "campaigns":       campaigns,
        "unique_users":    unique_users,
        "alert_rate_1h":   alert_rate_1h,
        "top_reasons":     [{"reason": r, "count": c} for r, c in top_reasons],
        # Window truncation honesty: when the selected window holds more alerts
        # than the cap, the feed shows the most-recent `cap` and the UI says so.
        "window_total":    _get_window_total(),
        "window_cap":      cap,
        "window_capped":   _get_window_total() > cap,
    }


def _ae(ueba: dict) -> dict:
    """The autoencoder sub-block of an alert's raw scores, or {}."""
    return ((ueba or {}).get("raw_scores") or {}).get("autoencoder") or {}


def _alert_to_feed_item(a: dict, include_evidence: bool = True) -> dict:
    """Map a raw alert (as written by the engine) to the compact dict shape
    consumed by the dashboard feed table. Used by /api/feed, the SSE
    /api/stream endpoint, and the per-user/per-agent/FP drilldowns.

    `include_evidence=False` (used by the bulk /api/feed) drops the `evidence`
    blob — by far the heaviest field (~77% of the JSON) and only needed when an
    analyst expands a single row. The dashboard then lazy-fetches it via
    /api/evidence/<event_id>. The small `mitre_techniques` list is kept inline
    regardless, because the MITRE heatmap aggregates it across the whole feed
    and can't afford a fetch-per-row.
    """
    ueba = a.get("ueba", {}) or {}
    sec  = a.get("security", {}) or {}
    host = a.get("host", {}) or {}
    ev   = a.get("evidence", {}) or {}
    eid  = a.get("event_id")
    item = {
        "event_id":     eid,
        "event_time":   a.get("event_time"),
        "processed_at": ueba.get("processed_at"),
        "user":         get_user(a),
        "verdict":      ueba.get("risk_verdict"),
        "score":        ueba.get("combined_score"),
        "reasons":      ueba.get("anomaly_reasons", []),
        "campaign_id":  ueba.get("campaign_id"),
        "signature":    (sec.get("signature") or "")[:80],
        "signature_id": sec.get("signature_id"),
        "severity":     sec.get("severity"),
        "host":         host.get("name"),
        "host_ip":      host.get("ip"),
        # Slim records (from the cache) carry MITRE pre-extracted under __mitre_*;
        # full records (the live SSE stream) fall back to the deep raw paths.
        "mitre_tactic": a["__mitre_tactic"] if "__mitre_tactic" in a
            else (a.get("context", {}) or {}).get("raw_event", {}).get("rule", {}).get("mitre", {}).get("tactic", []),
        "mitre_techniques": a["__mitre_techniques"] if "__mitre_techniques" in a
            else (ev.get("signature", {}) or {}).get("mitre_techniques", []),
        "fp":           _fp_dict.get(eid) if eid else None,
        "fp_pattern":   _matching_pattern(a),
        # Present only when this alert involved a watch-listed entity. The
        # unboosted model score travels with it so the UI can show what the
        # models thought before the watch list was applied.
        "watchlist":    ueba.get("watchlist"),
        # RFP SN 54 — "display threat by user, device and MODEL". The
        # autoencoder that scored the row was computed and then discarded at
        # the API boundary: it reached the evidence pane on expand but never
        # the table, so it could not be sorted or filtered on. Both are cheap
        # string lookups already present on the alert.
        "model":        _ae(ueba).get("model_used"),
        "model_type":   _ae(ueba).get("model_type"),
        # RFP SN 47 — when this entity was first ever seen, so the table can
        # show and filter first-use and dormant-return accounts.
        "first_seen":   ((a.get("evidence") or {}).get("history") or {}).get("first_seen"),
        "model_score":  ueba.get("model_score"),
    }
    if include_evidence:
        item["evidence"] = ev
    return item


@app.route("/api/feed")
def feed():
    """Live alert feed — all loaded alerts, newest first.
    FP-marked alerts are filtered out unless ?include_fp=1 is passed.

    Evidence is omitted here (see _alert_to_feed_item) so a wide timeline window
    can return up to max_feed_alerts rows without shipping a multi-hundred-MB
    payload; the dashboard lazy-loads each alert's evidence via /api/evidence.
    """
    return jsonify(_cached_endpoint("feed", _build_feed))


def _build_feed(alerts):
    # Cap the table payload to the newest rows so a high-volume window doesn't
    # ship tens of MB and freeze the browser. alerts is oldest-first, so the
    # newest slice is the tail; reverse it to newest-first for the table.
    cap = int(CFG.get("feed_row_cap", 5000) or 5000)
    recent = alerts[-cap:] if len(alerts) > cap else alerts
    return [_alert_to_feed_item(a, include_evidence=False) for a in reversed(recent)]


def _find_evidence(event_id: str) -> dict:
    """Lazy-load one alert's evidence blob from disk by event_id.

    The in-memory caches hold SLIM records (no evidence) to keep RSS small, so a
    panel expand re-reads the source. Live file first (recent, cheapest); then
    archive zips newest-first. A cheap substring pre-filter (`id in raw_line`)
    means only the matching line is ever JSON-parsed, so scanning even a large
    file is fast; a full evidence fetch is a rare, single-row action."""
    if not event_id:
        return {}
    target = event_id.encode("utf-8", "replace")

    def _scan_lines(line_iter):
        for raw in line_iter:
            if target not in raw:
                continue
            try:
                o = _jloads(raw)
            except Exception:
                continue
            if o.get("event_id") == event_id:
                return o.get("evidence") or {}
        return None

    # Live file (raw bytes, most likely target for recent alerts).
    try:
        if ALERTS_FILE.exists():
            with open(ALERTS_FILE, "rb") as f:
                hit = _scan_lines(f)
                if hit is not None:
                    return hit
    except Exception:
        pass

    # Archives, newest day first.
    adir = Path(CFG.get("archive_dir") or "")
    if adir.is_dir():
        try:
            entries = sorted(adir.glob("ueba_alerts_*.jsonl.zip"), reverse=True)
        except Exception:
            entries = []
        for path in entries:
            try:
                with zipfile.ZipFile(path) as zf:
                    names = [n for n in zf.namelist() if n.endswith(".jsonl")] or zf.namelist()
                    for name in names:
                        with zf.open(name) as fh:
                            hit = _scan_lines(fh)
                            if hit is not None:
                                return hit
            except Exception:
                continue
    return {}


@app.route("/api/evidence/<path:event_id>")
def alert_evidence(event_id):
    """Evidence blob for one alert, looked up by event_id from disk. Backs the
    dashboard's lazy evidence panel: /api/feed omits evidence to stay light and
    the caches hold slim records, so this returns it on demand when a row is
    expanded. Returns {} if the alert isn't found or carries no evidence."""
    return jsonify(_find_evidence(event_id) or {})


@app.route("/api/users")
def users():
    """User risk leaderboard — top 20 riskiest users."""
    return jsonify(_cached_endpoint("users", _build_users))


def _build_users(alerts):
    user_stats: dict = defaultdict(lambda: {
        "count": 0, "max_score": 0.0, "verdicts": defaultdict(int),
        "reasons": defaultdict(int), "last_seen": "", "hosts": set()
    })

    for a in alerts:
        user  = get_user(a)
        ueba  = a.get("ueba", {}) or {}
        score = ueba.get("combined_score", 0) or 0
        verdict = ueba.get("risk_verdict", "")
        host = (a.get("host", {}) or {}).get("name", "")

        user_stats[user]["count"] += 1
        user_stats[user]["max_score"] = max(user_stats[user]["max_score"], score)
        user_stats[user]["verdicts"][verdict] += 1
        user_stats[user]["last_seen"] = ueba.get("processed_at", "")
        if host:
            user_stats[user]["hosts"].add(host)
        for r in (ueba.get("anomaly_reasons") or []):
            user_stats[user]["reasons"][r] += 1

    leaderboard = []
    for user, s in user_stats.items():
        if user in ("unknown", "global", ""):
            continue
        risk = s["max_score"] * 0.5 + (s["count"] / 100) * 0.3 + \
               (s["verdicts"].get("highly_anomalous", 0) / max(s["count"], 1)) * 0.2
        leaderboard.append({
            "user":             user,
            "alert_count":      s["count"],
            "max_score":        round(s["max_score"], 3),
            "risk_index":       round(risk, 3),
            "top_verdict":      max(s["verdicts"], key=s["verdicts"].get) if s["verdicts"] else "",
            "top_reason":       max(s["reasons"], key=s["reasons"].get) if s["reasons"] else "",
            "last_seen":        s["last_seen"],
            "hosts":            list(s["hosts"])[:3],
            "highly_anomalous": s["verdicts"].get("highly_anomalous", 0),
        })

    leaderboard.sort(key=lambda x: -x["risk_index"])
    return leaderboard[:20]


@app.route("/api/campaigns")
def campaigns():
    """Campaign timeline data."""
    return jsonify(_cached_endpoint("campaigns", _build_campaigns))


def _build_campaigns(alerts):
    campaign_data: dict = defaultdict(lambda: {
        "alerts": [], "users": set(), "hosts": set(),
        "first_seen": "", "last_seen": "", "verdicts": defaultdict(int),
        "reasons": defaultdict(int), "signatures": set()
    })

    for a in alerts:
        ueba = a.get("ueba", {}) or {}
        cid  = ueba.get("campaign_id")
        if not cid:
            continue
        user = get_user(a)
        host = (a.get("host", {}) or {}).get("name", "")
        t    = ueba.get("processed_at", "")
        sig  = ((a.get("security", {}) or {}).get("signature") or "")[:60]

        cd = campaign_data[cid]
        cd["users"].add(user)
        if host:
            cd["hosts"].add(host)
        cd["verdicts"][ueba.get("risk_verdict", "")] += 1
        for r in (ueba.get("anomaly_reasons") or []):
            cd["reasons"][r] += 1
        if sig:
            cd["signatures"].add(sig)
        if not cd["first_seen"] or t < cd["first_seen"]:
            cd["first_seen"] = t
        if t > cd["last_seen"]:
            cd["last_seen"] = t
        cd["alerts"].append({
            "time":    t,
            "user":    user,
            "score":   ueba.get("combined_score", 0),
            "verdict": ueba.get("risk_verdict", ""),
        })

    result = []
    for cid, cd in campaign_data.items():
        result.append({
            "campaign_id":   cid,
            "alert_count":   len(cd["alerts"]),
            "users":         list(cd["users"]),
            "hosts":         list(cd["hosts"]),
            "first_seen":    cd["first_seen"],
            "last_seen":     cd["last_seen"],
            "top_verdict":   max(cd["verdicts"], key=cd["verdicts"].get) if cd["verdicts"] else "",
            "top_reason":    max(cd["reasons"], key=cd["reasons"].get) if cd["reasons"] else "",
            "signatures":    list(cd["signatures"])[:3],
            "timeline":      sorted(cd["alerts"], key=lambda x: x["time"])[-20:],
            "highly_anomalous": cd["verdicts"].get("highly_anomalous", 0),
        })

    result.sort(key=lambda x: x["last_seen"], reverse=True)
    return result


# Verdict severity ordering, used to pick an incident's worst verdict.
_VERDICT_RANK = {"suspicious": 1, "anomalous": 2, "highly_anomalous": 3}


@app.route("/api/incidents")
def incidents():
    """Entity-behaviour incidents: alerts rolled up by (entity, time-window).

    This is the "calm" UEBA view — instead of one row per raw event (a single
    brute-force can be 1,000+ rows), each abnormal entity gets ONE incident per
    window, with a count and a drill-down list of contributing event_ids (the
    existing /api/evidence/<event_id> renders each one). It is purely additive:
    it reuses load_alerts()/get_user()/_alert_ts() so it matches every other
    panel, and changes nothing about the engine's per-event alert schema.

    Query params: ?hours=N (timeline window, same as the rest of the dashboard),
    ?window=M (rollup bucket in minutes, default 60, clamped 5..1440),
    ?include_fp=1 (show FP-marked alerts).
    """
    try:
        win_min = int(request.args.get("window", 60))
    except (TypeError, ValueError):
        win_min = 60
    win_min = max(5, min(win_min, 1440))
    # The rollup width is part of the result's identity, so it belongs in the
    # cache key — two analysts on different ?window= values must not share one
    # aggregation. This endpoint previously bypassed the result cache entirely
    # and re-aggregated the whole window on every single request.
    return jsonify(_cached_endpoint("incidents:%d" % win_min,
                                    lambda alerts: _build_incidents(alerts, win_min)))


def _build_incidents(alerts, win_min: int):
    """Roll `alerts` up into per-(entity, time-bucket) incidents. Split out of the
    route so the result cache and the background warmer can drive it."""
    win_sec = win_min * 60

    INCIDENT_CAP = 5000         # incidents returned (newest-first after sort)

    groups: dict = defaultdict(lambda: {
        "count": 0, "max_score": 0.0, "sum_score": 0.0,
        "verdicts": defaultdict(int), "reasons": defaultdict(int),
        "signatures": set(), "campaign_ids": set(), "hosts": set(),
        "first_seen": "", "last_seen": "",
    })

    for a in alerts:
        ts = _alert_ts(a)
        if ts is None:
            continue
        start_epoch = int(ts.timestamp()) // win_sec * win_sec
        window_start = datetime.fromtimestamp(start_epoch, tz=timezone.utc).isoformat()
        entity = get_user(a)
        ueba = a.get("ueba", {}) or {}
        sec  = a.get("security", {}) or {}
        t    = ueba.get("processed_at") or a.get("event_time") or ""

        g = groups[(entity, window_start)]
        g["count"] += 1
        score = float(ueba.get("combined_score") or 0.0)
        g["max_score"] = max(g["max_score"], score)
        g["sum_score"] += score
        g["verdicts"][ueba.get("risk_verdict", "")] += 1
        for r in (ueba.get("anomaly_reasons") or []):
            g["reasons"][r] += 1
        sig = ((sec.get("signature")) or "")[:60]
        if sig:
            g["signatures"].add(sig)
        cid = ueba.get("campaign_id")
        if cid:
            g["campaign_ids"].add(cid)
        host = (a.get("host", {}) or {}).get("name", "")
        if host:
            g["hosts"].add(host)
        if not g["first_seen"] or t < g["first_seen"]:
            g["first_seen"] = t
        if t > g["last_seen"]:
            g["last_seen"] = t

    result = []
    for (entity, window_start), g in groups.items():
        window_end = datetime.fromisoformat(window_start) + timedelta(minutes=win_min)
        # An incident takes the severity of its WORST event, not its most common
        # one — otherwise a burst of low-severity events would bury a single
        # highly-anomalous one inside it and sink the incident's ranking.
        present = [v for v in g["verdicts"] if v]
        top_verdict = max(present, key=lambda v: _VERDICT_RANK.get(v, 0)) if present else ""
        result.append({
            "incident_id":   f"{entity}|{window_start}",
            "entity":        entity,
            "window_start":  window_start,
            "window_end":    window_end.isoformat(),
            "window_minutes": win_min,
            "count":          g["count"],
            "max_score":      round(g["max_score"], 4),
            "avg_score":      round(g["sum_score"] / g["count"], 4) if g["count"] else 0.0,
            "top_verdict":    top_verdict,
            "verdicts":       dict(g["verdicts"]),
            "highly_anomalous": g["verdicts"].get("highly_anomalous", 0),
            "reasons":        [r for r, _ in sorted(g["reasons"].items(), key=lambda x: -x[1])[:5]],
            "signatures":     list(g["signatures"])[:5],
            "campaign_ids":   list(g["campaign_ids"]),
            "hosts":          list(g["hosts"]),
            "first_seen":     g["first_seen"],
            "last_seen":      g["last_seen"],
        })

    # Rank by risk: worst verdict, then peak score, then volume.
    result.sort(key=lambda x: (_VERDICT_RANK.get(x["top_verdict"], 0),
                               x["max_score"], x["count"]), reverse=True)
    total = len(result)
    return {
        "incidents":     result[:INCIDENT_CAP],
        "incident_total": total,
        "incident_capped": total > INCIDENT_CAP,
        "window_minutes": win_min,
    }


@app.route("/api/agents")
def agents():
    """Agent (endpoint) summary — all registered agents, merged with alert stats."""
    return jsonify(_cached_endpoint("agents", _build_agents))


def _build_agents(alerts):
    registry: list = []
    if AGENTS_REGISTRY.exists():
        try:
            registry = json.loads(AGENTS_REGISTRY.read_text())
        except Exception:
            pass

    agent_stats: dict = defaultdict(lambda: {
        "alert_count": 0, "max_score": 0.0,
        "verdicts": defaultdict(int), "users": set(),
        "reasons": defaultdict(int), "last_seen": "",
        "first_seen": "", "ip": "",
    })

    for a in alerts:
        host = (a.get("host", {}) or {}).get("name", "")
        if not host:
            continue
        ueba    = a.get("ueba", {}) or {}
        score   = ueba.get("combined_score", 0) or 0
        verdict = ueba.get("risk_verdict", "")
        user    = get_user(a)
        t       = ueba.get("processed_at", "")
        ip      = (a.get("host", {}) or {}).get("ip", "")

        s = agent_stats[host]
        s["alert_count"] += 1
        s["max_score"] = max(s["max_score"], score)
        s["verdicts"][verdict] += 1
        s["users"].add(user)
        if ip:
            s["ip"] = ip
        for r in (ueba.get("anomaly_reasons") or []):
            s["reasons"][r] += 1
        if not s["first_seen"] or t < s["first_seen"]:
            s["first_seen"] = t
        if t > s["last_seen"]:
            s["last_seen"] = t

    seen = set()
    result = []
    for reg in registry:
        name = reg["name"]
        seen.add(name)
        s = agent_stats.get(name, {})
        verdicts = s.get("verdicts", {})
        result.append({
            "agent":            name,
            "ip":               s.get("ip") or reg.get("ip", ""),
            "os":               reg.get("os", ""),
            "agent_id":         reg.get("id", ""),
            "alert_count":      s.get("alert_count", 0),
            "max_score":        round(s.get("max_score", 0), 3),
            "top_verdict":      max(verdicts, key=verdicts.get) if verdicts else "",
            "top_reason":       max(s["reasons"], key=s["reasons"].get) if s.get("reasons") else "",
            "users":            list(s.get("users", set()))[:10],
            "last_seen":        s.get("last_seen", ""),
            "first_seen":       s.get("first_seen", ""),
            "highly_anomalous": verdicts.get("highly_anomalous", 0),
            "anomalous":        verdicts.get("anomalous", 0),
            "suspicious":       verdicts.get("suspicious", 0),
        })

    for name, s in agent_stats.items():
        if name in seen:
            continue
        verdicts = s["verdicts"]
        result.append({
            "agent":            name,
            "ip":               s["ip"],
            "os":               "",
            "agent_id":         "",
            "alert_count":      s["alert_count"],
            "max_score":        round(s["max_score"], 0),
            "top_verdict":      max(verdicts, key=verdicts.get) if verdicts else "",
            "top_reason":       max(s["reasons"], key=s["reasons"].get) if s["reasons"] else "",
            "users":            list(s["users"])[:10],
            "last_seen":        s["last_seen"],
            "first_seen":       s["first_seen"],
            "highly_anomalous": verdicts.get("highly_anomalous", 0),
            "anomalous":        verdicts.get("anomalous", 0),
            "suspicious":       verdicts.get("suspicious", 0),
        })

    result.sort(key=lambda x: (-x["highly_anomalous"], -x["max_score"]))
    return result


# Register the heavy endpoint builders so the background warmer keeps the result
# cache hot for actively-viewed windows (see _warm_results_loop).
# ── Search auto-complete / auto-suggest (RFP 28) ────────────────────────────
# The vocabulary is drawn from the ALERTS IN THE CURRENT WINDOW, which is what
# makes the suggestions contextual rather than a static dictionary: an analyst
# searching a 24-hour window is offered the entities that were actually active
# in those 24 hours. Building it server-side also means suggestions cover the
# whole window, not merely the rows the browser happens to have loaded.

# Per category, so one enormous estate cannot produce a multi-megabyte payload.
_SUGGEST_PER_CATEGORY = 400

_SUGGEST_FIELDS = (
    ("user",      "User"),
    ("host",      "Host"),
    ("ip",        "Host IP"),
    ("signature", "Signature"),
    ("tactic",    "MITRE tactic"),
    ("campaign",  "Campaign"),
    ("reason",    "Anomaly reason"),
)


def _build_suggest(alerts):
    counts = {k: defaultdict(int) for k, _ in _SUGGEST_FIELDS}
    for a in alerts:
        ueba = a.get("ueba") or {}
        sec = a.get("security") or {}
        host = a.get("host") or {}
        u = get_user(a)
        if u:
            counts["user"][str(u)] += 1
        if host.get("name"):
            counts["host"][str(host["name"])] += 1
        if host.get("ip"):
            counts["ip"][str(host["ip"])] += 1
        sig = sec.get("signature")
        if sig:
            counts["signature"][str(sig)[:90]] += 1
        if ueba.get("campaign_id"):
            counts["campaign"][str(ueba["campaign_id"])] += 1
        for r in (ueba.get("anomaly_reasons") or []):
            counts["reason"][str(r)] += 1
        t = a.get("__mitre_tactic")
        if t is None:
            rule = ((a.get("context") or {}).get("raw_event") or {}).get("rule") or {}
            t = (rule.get("mitre") or {}).get("tactic") or []
        for tac in (t if isinstance(t, list) else [t]):
            if tac:
                counts["tactic"][str(tac)] += 1
    return {
        k: sorted(v.items(), key=lambda kv: (-kv[1], kv[0]))[:_SUGGEST_PER_CATEGORY]
        for k, v in counts.items()
    }


# ── Deep search over raw + enriched data (RFP 26) ───────────────────────────
# The feed's own search only reaches the SLIM projection the dashboard caches —
# entity, host, signature, reasons, tactics. _slim() drops fourteen top-level
# sections, so threat-intel verdicts, geolocation, process and command-line
# detail, HTTP/DNS fields, the evidence block and the original raw event are all
# invisible to it. This searches the full stored record instead.
#
# Matching is plain terms, deliberately: point 27 asks for search "without
# requiring to learn a custom search query language", so there is no field
# syntax to memorise. Every whitespace-separated term must appear somewhere in
# the record (AND), and "quoted phrases" match literally.
#
# The scan is NEWEST-FIRST and bounded by both a result cap and a byte budget,
# and the response says plainly whether it saw everything or stopped early — a
# search that silently examines 5% of the window and reports "3 results" is
# worse than one that admits it truncated.

# 192 MB keeps a typical search under ~10s, which is the difference between a
# tool an analyst uses and one they avoid. 512 MB was measured at 15s on a
# 24-hour window and timed out entirely on "All" — and a search that has to be
# waited out is not an interactive search. The cap is raisable per request via
# ?budget=, and the response always reports whether the scan was complete.
_DEEP_DEFAULT_BUDGET = 192 * 1024 * 1024      # bytes of decompressed JSON
_DEEP_MAX_RESULTS = 500


def _parse_terms(q: str) -> list:
    """Split a query into lowercase terms, honouring "quoted phrases"."""
    terms, buf, in_q = [], [], False
    for ch in q:
        if ch == '"':
            in_q = not in_q
            if not in_q and buf:
                terms.append("".join(buf).lower())
                buf = []
            continue
        if ch.isspace() and not in_q:
            if buf:
                terms.append("".join(buf).lower())
                buf = []
            continue
        buf.append(ch)
    if buf:
        terms.append("".join(buf).lower())
    return [t for t in terms if t]


def _where_matched(alert: dict, terms: list) -> list:
    """Which top-level sections contain the terms — so a hit is explicable.

    Only runs on records that already matched, so the cost is bounded by the
    result cap rather than by the size of the window.
    """
    hits = []
    for key, value in alert.items():
        try:
            blob = json.dumps(value, ensure_ascii=False).lower()
        except (TypeError, ValueError):
            continue
        if any(t in blob for t in terms):
            hits.append(key)
    return sorted(hits)


# A byte budget cannot bound latency on a shared box: the scan competes for the
# GIL with the dashboard's cache-warming threads, so the same 192 MB took 2s
# standalone and 85s in-request. Latency is what the analyst experiences, so it
# is what gets bounded — the scan stops at whichever limit it reaches first and
# says so.
_DEEP_TIME_BUDGET_S = 12.0


def _deep_search(terms: list, hours: int, limit: int, budget: int,
                 time_budget: float = _DEEP_TIME_BUDGET_S) -> dict:
    """Scan full alert records newest-first for records containing every term."""
    results, scanned, matched = [], 0, 0
    truncated = False
    deadline = time.time() + time_budget
    cutoff = None
    if hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Measured, not assumed. Profiling the scan showed decompression runs at
    # 284 MB/s and is NOT the bottleneck; a case-insensitive regex pre-filter
    # was 4x SLOWER than lower() + `in` and has been removed. What actually
    # dominated was json.loads() on every line that matched — for a common term
    # like "root" that is tens of thousands of full parses performed only to
    # count them and read one timestamp.
    #
    # So: match on the lowered text, pull the timestamp out with a cheap regex
    # for the window test, and parse the full record ONLY for the handful of
    # results actually returned.
    ts_probe = re.compile(r'"event_time"\s*:\s*"([^"]{4,40})"')

    def consider(raw_line: str) -> bool:
        """True to keep scanning, False once a budget is hit."""
        nonlocal scanned, matched, truncated
        scanned += len(raw_line)
        low = raw_line.lower()
        if not all(t in low for t in terms):
            return True
        if cutoff is not None:
            m = ts_probe.search(raw_line)
            if m:
                ts = _parse_iso(m.group(1))
                if ts is not None and ts < cutoff:
                    return True
        matched += 1
        if len(results) < limit:
            try:
                alert = json.loads(raw_line)
            except Exception:
                return True
            item = _alert_to_feed_item(_slim(alert))
            item["matched_in"] = _where_matched(alert, terms)
            results.append(item)
        else:
            truncated = True
        return True

    # 1. The live alert file, newest last — read it whole (it is rotated daily).
    try:
        if ALERTS_FILE.exists():
            with open(ALERTS_FILE, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        consider(line)
                    if scanned >= budget or time.time() > deadline:
                        truncated = True
                        break
    except Exception as e:
        print(f"[search] live file scan failed: {e}")

    # 2. Daily archives, newest first, until the budget runs out.
    adir = Path(CFG.get("archive_dir") or "")
    if adir.is_dir() and scanned < budget:
        try:
            entries = sorted(adir.glob("ueba_alerts_*.jsonl.zip"), reverse=True)
        except Exception:
            entries = []
        for path in entries:
            if scanned >= budget or time.time() > deadline:
                truncated = True
                break
            m = _ARCHIVE_RE.search(path.name)
            if m and cutoff is not None:
                try:
                    if datetime.strptime(m.group(1), "%Y-%m-%d").date() < cutoff.date():
                        continue
                except ValueError:
                    pass
            try:
                with zipfile.ZipFile(path) as z:
                    for name in z.namelist():
                        with z.open(name) as f:
                            for raw in f:
                                line = raw.decode("utf-8", "replace").strip()
                                if line:
                                    consider(line)
                                if scanned >= budget or time.time() > deadline:
                                    truncated = True
                                    break
                        if scanned >= budget or time.time() > deadline:
                            break
            except Exception as e:
                print(f"[search] archive {path.name} unreadable: {e}")

    results.sort(key=lambda a: a.get("processed_at") or "", reverse=True)
    return {
        "results": results,
        "matched": matched,
        "returned": len(results),
        "bytes_scanned": scanned,
        "truncated": truncated,
        "time_budget_s": time_budget,
    }


@app.route("/api/search/deep")
def api_search_deep():
    """Search the full raw + enriched record, not just the feed projection."""
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"ok": False,
                        "error": "enter at least two characters to search"}), 400
    terms = _parse_terms(q)
    if not terms:
        return jsonify({"ok": False, "error": "nothing to search for"}), 400
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), _DEEP_MAX_RESULTS))
    except ValueError:
        limit = 100
    try:
        budget = max(16 * 1024 * 1024,
                     min(int(request.args.get("budget", _DEEP_DEFAULT_BUDGET)),
                         2 * 1024 * 1024 * 1024))
    except ValueError:
        budget = _DEEP_DEFAULT_BUDGET

    started = time.time()
    out = _deep_search(terms, _window_hours(), limit, budget)
    out.update({
        "ok": True,
        "query": q,
        "terms": terms,
        "elapsed_ms": int((time.time() - started) * 1000),
    })
    return jsonify(out)


@app.route("/api/suggest")
def api_suggest():
    """Contextual search suggestions for a prefix (RFP 28)."""
    q = (request.args.get("q") or "").strip().lower()
    try:
        limit = max(1, min(int(request.args.get("limit", 8)), 25))
    except ValueError:
        limit = 8
    idx = _cached_endpoint("suggest", _build_suggest)
    if not q:
        # No query yet: offer the most active values, so the box is useful
        # before the analyst has typed anything.
        groups = [{"field": k, "label": lbl,
                   "items": [{"value": v, "count": n} for v, n in idx.get(k, [])[:3]]}
                  for k, lbl in _SUGGEST_FIELDS]
        return jsonify({"ok": True, "query": q,
                        "groups": [g for g in groups if g["items"]]})

    groups = []
    for key, label in _SUGGEST_FIELDS:
        starts, contains = [], []
        for value, n in idx.get(key, []):
            low = value.lower()
            if low.startswith(q):
                starts.append({"value": value, "count": n})
            elif q in low:
                contains.append({"value": value, "count": n})
            if len(starts) >= limit:
                break
        # Prefix matches first — that is what "auto-complete" means to the
        # person typing; substring matches fill the remainder.
        items = (starts + contains)[:limit]
        if items:
            groups.append({"field": key, "label": label, "items": items})
    return jsonify({"ok": True, "query": q, "groups": groups})


_ENDPOINT_BUILDERS.update({
    "stats":     _build_stats,
    "feed":      _build_feed,
    "users":     _build_users,
    "campaigns": _build_campaigns,
    "agents":    _build_agents,
    "suggest":   _build_suggest,
    # Default rollup width only. A non-default ?window= still caches on demand
    # under its own key; it just isn't pre-warmed.
    "incidents:60": lambda alerts: _build_incidents(alerts, 60),
})


@app.route("/api/agent/<agent_name>")
def agent_alerts(agent_name):
    """All alerts for a specific agent, newest first.

    Evidence is omitted (include_evidence=False) — exactly like /api/feed — so a
    noisy host (tens of thousands of alerts) doesn't ship a 100MB+ payload. The
    drilldown table lazy-loads each row's evidence on expand via /api/evidence.

    Capped at feed_row_cap like the feed. Dropping evidence was not enough on its
    own: with no ?hours= the window is 0 ("All", bounded only by history_days), so
    one busy host returned 1,139,873 rows / 673 MB and the browser gave up with
    "failed to load". Breaking at the cap also avoids building a million dicts
    server-side just to throw them away.
    """
    cap = int(CFG.get("feed_row_cap", 5000) or 5000)
    out = []
    for a in reversed(load_alerts(include_fp=_wants_include_fp())):
        if ((a.get("host", {}) or {}).get("name", "")) != agent_name:
            continue
        out.append(_alert_to_feed_item(a, include_evidence=False))
        if len(out) >= cap:
            break
    return jsonify(out)


@app.route("/api/user/<path:username>")
def user_alerts(username):
    """All alerts for a specific user, newest first.

    Evidence is omitted (see agent_alerts) — a single noisy entity can have 80k+
    alerts, and shipping each one's evidence blob made this a ~200MB / 6s response.
    The table lazy-loads evidence per row on expand via /api/evidence.

    Capped at feed_row_cap for the same reason agent_alerts is: without a ?hours=
    the window is "All", so row count alone can blow the payload past what a
    browser will accept even with evidence stripped.
    """
    cap = int(CFG.get("feed_row_cap", 5000) or 5000)
    out = []
    for a in reversed(load_alerts(include_fp=_wants_include_fp())):
        if get_user(a) != username:
            continue
        out.append(_alert_to_feed_item(a, include_evidence=False))
        if len(out) >= cap:
            break
    return jsonify(out)


# ── False-positive management ────────────────────────────────────────────────
@app.route("/api/false-positives")
def list_false_positives():
    """Return all FP records, each enriched with the original alert payload."""
    # Routed through the result cache like the other heavy endpoints. This used
    # to rebuild on every request, and the build indexes the WHOLE window by
    # event_id (up to 500k alerts) just to attach an alert to ~10k FP records —
    # measured at 1.9s, the slowest single call in a dashboard load.
    #
    # include_fp=True is forced (not read from the request): the lookup must be
    # able to see FP-marked alerts, which the default filtered view hides. That
    # also gives it its own cache key, so it never collides with the filtered
    # views. save_fps() calls _invalidate_result_cache(), so marking an alert FP
    # still takes effect immediately rather than after the TTL.
    #
    # The window is pinned to 0 ("All", bounded by history_days) and deliberately
    # ignores ?hours. An analyst's FP list is a record of decisions they made, not
    # a view of a time range — hiding older ones behind the timeline selector is
    # just confusing. It was also actively harmful: under a narrow window the
    # alert lookup could not see the FP-marked alerts (they are older than the
    # window), so every record came back with "alert": null — at hours=24 that
    # was all 10,830 of them. Pinning it also collapses seven possible cache
    # entries into one.
    return jsonify(_endpoint_result("false_positives", _build_false_positives,
                                    0, True))


def _build_false_positives(alerts):
    by_id = {a.get("event_id"): a for a in alerts if a.get("event_id")}
    out = []
    for eid, rec in _fp_dict.items():
        a = by_id.get(eid)
        out.append({**rec, "alert": _alert_to_feed_item(a) if a else None})
    out.sort(key=lambda r: r.get("marked_at", ""), reverse=True)
    return out


# ── Reporting (RFP 34-40, 62) ───────────────────────────────────────────────

def _rcfg():
    return CFG.get("reporting") or _DEFAULTS["reporting"]


def _reports_ready():
    return REPORTS_AVAILABLE and bool(_rcfg().get("enabled", True))


def _reports_unavailable():
    why = ("the reporting modules are not installed" if not REPORTS_AVAILABLE
           else "reporting is disabled in ueba_config.yaml")
    return jsonify({"ok": False, "error": f"Reporting unavailable — {why}."}), 503


def _smtp_cfg():
    """SMTP settings with the password resolved from the environment first.

    Config files on this box are readable by several teams, so the env var is
    the supported path and the in-file password is only a fallback for sites
    that have no better option."""
    smtp = dict((_rcfg().get("smtp") or {}))
    env_name = smtp.get("password_env")
    if env_name and os.environ.get(env_name):
        smtp["password"] = os.environ[env_name]
    return smtp


def _audit_entries_since(since_dt, limit=5000):
    """Audit records newer than `since_dt`, newest first. Used by the audit and
    compliance report (point 37)."""
    out = []
    try:
        if not AUDIT_FILE.exists():
            return out
        with open(AUDIT_FILE, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            back = min(size, limit * 512 + 65536)
            fh.seek(size - back)
            chunk = fh.read().decode("utf-8", "replace")
        lines = chunk.splitlines()
        if back < size and lines:
            lines = lines[1:]
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            try:
                e = json.loads(ln)
            except Exception:
                continue
            if since_dt is not None:
                t = _parse_iso(e.get("ts"))
                if t is None or t < since_dt:
                    continue
            out.append(e)
    except Exception as e:
        print(f"[reports] could not read audit trail: {e}")
    out.reverse()
    return out[:limit]


def _parse_iso(v):
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _report_context(hours, generated_by=None):
    """Everything the report engine needs for one period.

    Deliberately assembled in one place: the reports must describe the same
    numbers analysts see on screen, so this reuses load_alerts() and the very
    same _build_* aggregators the dashboard endpoints use rather than counting
    anything a second, subtly different way.
    """
    cap = int(_rcfg().get("max_window_alerts") or 400000)
    alerts = load_alerts(n=cap, hours=hours)
    now = datetime.now(timezone.utc)
    frm = (now - timedelta(hours=hours)) if hours else None

    try:
        campaigns = _build_campaigns(alerts)
    except Exception:
        campaigns = []
    try:
        agents = _build_agents(alerts)
    except Exception:
        agents = []

    # Health is assembled here rather than by calling /api/health, which is a
    # route that loads its own (FP-inclusive) window. Re-using it would mean a
    # report whose health figures silently disagreed with its own alert counts.
    now_1h = now - timedelta(hours=1)
    now_24h = now - timedelta(hours=24)
    n_1h = n_24h = 0
    for a in alerts:
        d = _alert_ts(a)
        if d is None:
            continue
        if d >= now_1h:
            n_1h += 1
        if d >= now_24h:
            n_24h += 1
    try:
        alerts_file_mb = round(ALERTS_FILE.stat().st_size / (1024 * 1024), 1) \
            if ALERTS_FILE.exists() else 0
    except OSError:
        alerts_file_mb = 0
    health = {
        "Alerts in period":          f"{len(alerts):,}",
        "Alerts in last hour":       f"{n_1h:,}",
        "Alerts in last 24 hours":   f"{n_24h:,}",
        "Monitored endpoints":       f"{len(agents):,}",
        "Alert store on disk":       f"{alerts_file_mb:,} MB",
        "Suppression patterns":      f"{len(_fp_patterns):,}",
        "Watch-list entries":        f"{len(ueba_watchlist.entries(WATCHLIST_FILE)) if WATCHLIST_AVAILABLE else 0:,}",
    }

    geo = []
    try:
        tm = CFG.get("threatmap") or {}
        geo = (_tail_firewall_geo(int(tm.get("window_bytes", 12582912)),
                                  int(tm.get("max_arcs", 400))) or {}).get("arcs") or []
    except Exception as e:
        print(f"[reports] geo section unavailable: {e}")
        geo = []

    return {
        "alerts":       alerts,
        "hours":        hours,
        "window":       {"from": frm, "to": now},
        "capped":       len(alerts) >= cap,
        "cap":          cap,
        "campaigns":    campaigns,
        "agents":       agents,
        "audit":        _audit_entries_since(frm),
        "watchlist":    (ueba_watchlist.entries(WATCHLIST_FILE)
                         if WATCHLIST_AVAILABLE else []),
        "fp_patterns":  list(_fp_patterns),
        "fp_count":     len(_fp_dict),
        "health":       health,
        "geo":          geo,
        # Read from the engine's own config block rather than the dashboard's:
        # an earlier version looked up a `training_retention_days` key that does
        # not exist anywhere, so the compliance report always printed the
        # hardcoded fallback whatever the deployment was actually set to.
        "retention": _retention_facts(),
        "site":         CFG.get("site_name") or "CyberSentinel UEBA",
        "generated_by": generated_by,
        "generated_at": now.isoformat(),
    }


def _retention_facts():
    """Retention settings as actually configured, for the compliance report."""
    ps = (_RAW_CFG.get("profile_store") or {})
    mode = ps.get("baseline_mode", "events")
    out = {
        "alert_history_days": CFG.get("history_days"),
        "audit_log":          AUDIT_FILE.name,
        "baseline_mode":      mode,
    }
    if mode == "time":
        out["behaviour_profiling_window_days"] = ps.get("baseline_window_days")
    else:
        # Stating this plainly matters: in "events" mode the configured day
        # count is inert, and a compliance report that implied otherwise would
        # be describing a control the deployment does not have.
        out["behaviour_profiling_window"] = (
            "event-count EWMA (alpha "
            f"{ps.get('legacy_alpha', 0.01)}) — not a time period")
    return out


def _current_username():
    if AUTH_MODULE_AVAILABLE:
        try:
            return (ueba_auth.current_user() or {}).get("username")
        except Exception:
            return None
    return None


# ── Role-based access control (RFP 23) ───────────────────────────────────────
#
# One table drives both halves of RBAC: the server gates routes with it, and the
# browser asks for the same table to decide what to show. Keeping a single source
# of truth is the point — a UI that hides a button the API still allows (or vice
# versa) is worse than no RBAC at all, because it looks enforced and is not.
#
# Tiers, by what the action actually does:
#   viewer  — reads. Exporting is here on purpose: it reformats data the viewer
#             can already see on screen, and changes no state.
#   analyst — day-to-day triage that writes state: watch lists, false positives,
#             generating and keeping reports.
#   admin   — configuration and oversight: who gets alerted, which devices matter,
#             scheduled delivery that leaves the building by email, and the audit
#             trail of everyone else's actions.
CAPABILITIES = {
    "export":           "viewer",
    "watchlist.edit":   "analyst",
    "fp.edit":          "analyst",
    "reports.generate": "analyst",
    "reports.custom":   "analyst",
    "ai.analyze":       "analyst",
    "reports.schedule": "admin",
    "devices.edit":     "admin",
    "notify.edit":      "admin",
    "audit.view":       "admin",
    "users.manage":     "admin",
}


def _rbac_enforcing():
    """True only when the auth module is present AND auth.enforce is on."""
    if not AUTH_MODULE_AVAILABLE:
        return False
    try:
        return ueba_auth.is_enforcing()
    except Exception:
        return False


def _require_cap(cap):
    """Gate a route on a capability from the table above.

    Delegates to ueba_auth.require_role, which is a no-op while auth.enforce is
    off. That is what makes it safe to decorate every route now and flip the
    flag later: nothing changes for analysts until the cutover is deliberate.
    """
    minimum = CAPABILITIES[cap]
    if AUTH_MODULE_AVAILABLE:
        return ueba_auth.require_role(minimum)

    def _passthrough(fn):
        return fn
    return _passthrough


def _capability_map():
    """{capability: allowed} for the caller — what the UI should offer."""
    # Not enforcing means everyone can do everything, so say so rather than
    # inventing a role. The UI then renders exactly as it does today.
    if not _rbac_enforcing():
        return {c: True for c in CAPABILITIES}
    try:
        user = ueba_auth.current_user()
    except Exception:
        user = None
    return {c: ueba_auth.role_at_least(user, m) for c, m in CAPABILITIES.items()}


@app.route("/api/auth/capabilities")
def api_auth_capabilities():
    """What the current caller may do. Drives which controls the SPA renders."""
    role = None
    if AUTH_MODULE_AVAILABLE:
        try:
            role = (ueba_auth.current_user() or {}).get("role")
        except Exception:
            role = None
    enforcing = _rbac_enforcing()
    return jsonify({
        "enforcing":    enforcing,
        # While enforcement is off there is no authenticated user; report the
        # effective role so the UI has something honest to display.
        "role":         role or (None if enforcing else "admin"),
        "capabilities": _capability_map(),
        "levels":       dict(CAPABILITIES),
        "roles":        list(ueba_auth.ROLES) if AUTH_MODULE_AVAILABLE else [],
    })


def _resolve_report(report_id):
    """(sections, title, base_id) for a built-in or saved custom report."""
    if report_id in ueba_reports.REPORTS:
        return None, None, report_id
    saved = next((d for d in ueba_report_store.definitions(_rcfg()["definitions_file"])
                  if d.get("id") == report_id), None)
    if saved is None:
        return None, None, None
    return saved.get("sections") or [], saved.get("name"), saved.get("base") or report_id


def _generate(report_id, hours, fmt, generated_by=None):
    """Build + render one report. Returns (bytes, mime, ext, document)."""
    sections, title, _ = _resolve_report(report_id)
    if sections is None and report_id not in ueba_reports.REPORTS:
        raise ValueError(f"unknown report {report_id!r}")
    ctx = _report_context(hours, generated_by=generated_by)
    doc = ueba_reports.build_report(report_id, ctx, sections=sections, title=title)
    data, mime, ext = ueba_report_render.render(doc, fmt)
    return data, mime, ext, doc


@app.route("/api/reports/catalogue")
def api_reports_catalogue():
    if not _reports_ready():
        return _reports_unavailable()
    cat = ueba_reports.catalogue()
    cat["formats"] = ueba_report_render.available_formats()
    cat["custom"] = ueba_report_store.definitions(_rcfg()["definitions_file"])
    cat["default_hours"] = int(_rcfg().get("default_hours") or 168)
    cat["intervals"] = list(ueba_report_store.INTERVALS)
    cat["weekdays"] = list(ueba_report_store.WEEKDAYS)
    cat["timezone"] = ueba_report_store.local_tz_label()
    cat["email_enabled"] = ueba_report_store.smtp_configured(_smtp_cfg())
    cat["ok"] = True
    return jsonify(cat)


@app.route("/api/reports/generate", methods=["POST"])
@_require_cap("reports.generate")
def api_reports_generate():
    """Generate a report now and return the file inline."""
    if not _reports_ready():
        return _reports_unavailable()
    body = request.get_json(silent=True) or {}
    report_id = (body.get("report_id") or "").strip()
    fmt = (body.get("format") or "pdf").strip().lower()
    try:
        hours = int(body.get("hours", _rcfg().get("default_hours") or 168))
    except (TypeError, ValueError):
        hours = 168
    if not report_id:
        return jsonify({"ok": False, "error": "report_id required"}), 400
    if fmt not in ueba_report_render.available_formats():
        return jsonify({"ok": False,
                        "error": f"format {fmt!r} is not available on this install"}), 400

    who = _current_username()
    try:
        data, mime, ext, doc = _generate(report_id, hours, fmt, generated_by=who)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        print(f"[reports] generate failed: {e}")
        return jsonify({"ok": False, "error": f"Report generation failed: {e}"}), 500

    rec = ueba_report_store.record_artifact(
        _rcfg()["history_file"], _rcfg()["output_dir"],
        report_id=report_id, title=doc.get("title"), fmt=ext, data=data,
        hours=hours, generated_by=who, document=doc)

    resp = Response(data, mimetype=mime)
    resp.headers["Content-Disposition"] = f'attachment; filename="{rec["file"]}"'
    resp.headers["X-Report-Id"] = rec["id"]
    # Reports are generated per request and are often large; caching them would
    # only serve a stale period to the next viewer.
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/reports/history")
def api_reports_history():
    if not _reports_ready():
        return _reports_unavailable()
    try:
        limit = max(1, min(int(request.args.get("limit", 60)), 500))
    except ValueError:
        limit = 60
    return jsonify({"ok": True,
                    "entries": ueba_report_store.history(_rcfg()["history_file"], limit)})


@app.route("/api/reports/download/<art_id>")
def api_reports_download(art_id):
    """Download a stored report, optionally re-rendered in another format.

    ?format=pdf|xlsx|… re-renders from the SOURCE DOCUMENT saved beside the
    artifact, so the alternative format describes the same period and the same
    numbers as the original. It deliberately does not re-run the report: that
    would quietly substitute today's window for the one the analyst is looking
    at in the history row.
    """
    if not _reports_ready():
        return _reports_unavailable()
    want = (request.args.get("format") or "").strip().lower()
    if want == "excel":
        want = "xlsx"

    if not want:
        path, rec = ueba_report_store.artifact_path(
            _rcfg()["output_dir"], _rcfg()["history_file"], art_id)
        if path is None:
            return jsonify({"ok": False,
                            "error": "report not found or no longer stored"}), 404
        mime = ueba_report_render.RENDERERS.get(
            rec.get("format"), (None, "application/octet-stream", ""))[1]
        resp = Response(path.read_bytes(), mimetype=mime)
        resp.headers["Content-Disposition"] = f'attachment; filename="{rec["file"]}"'
        resp.headers["Cache-Control"] = "no-store"
        return resp

    if want not in ueba_report_render.available_formats():
        return jsonify({"ok": False,
                        "error": f"format {want!r} is not available on this install"}), 400

    doc, rec = ueba_report_store.artifact_document(
        _rcfg()["output_dir"], _rcfg()["history_file"], art_id)
    if rec is None:
        return jsonify({"ok": False, "error": "report not found"}), 404
    # Asking for the format it already is: serve the stored bytes untouched.
    if want == rec.get("format"):
        return api_reports_download_original(art_id)
    if doc is None:
        return jsonify({
            "ok": False,
            "error": ("This report was generated before source documents were kept, "
                      "so it cannot be converted. Generate it again from the panel "
                      "above and the new one will be convertible."),
        }), 409

    try:
        data, mime, ext = ueba_report_render.render(doc, want)
    except Exception as e:
        print(f"[reports] re-render to {want} failed: {e}")
        return jsonify({"ok": False, "error": f"Conversion failed: {e}"}), 500

    stem = str(rec.get("file") or "report").rsplit(".", 1)[0]
    resp = Response(data, mimetype=mime)
    resp.headers["Content-Disposition"] = f'attachment; filename="{stem}.{ext}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


def api_reports_download_original(art_id):
    path, rec = ueba_report_store.artifact_path(
        _rcfg()["output_dir"], _rcfg()["history_file"], art_id)
    if path is None:
        return jsonify({"ok": False, "error": "report not found or no longer stored"}), 404
    mime = ueba_report_render.RENDERERS.get(
        rec.get("format"), (None, "application/octet-stream", ""))[1]
    resp = Response(path.read_bytes(), mimetype=mime)
    resp.headers["Content-Disposition"] = f'attachment; filename="{rec["file"]}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/reports/history/<art_id>", methods=["DELETE"])
@_require_cap("reports.generate")
def api_reports_history_delete(art_id):
    """Delete one generated report. Audited like any other mutating action."""
    if not _reports_ready():
        return _reports_unavailable()
    try:
        rec = ueba_report_store.delete_artifact(
            _rcfg()["history_file"], _rcfg()["output_dir"], art_id)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    if rec is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "id": art_id, "file": rec.get("file")})


# ── Feed export to PDF / Excel (RFP 34) ─────────────────────────────────────
# CSV, JSON and XML are produced in the browser, because they are trivial string
# formats. PDF and Excel are not: doing them client-side would mean shipping
# jsPDF and SheetJS to every page load — several hundred KB on top of a bundle
# that already carries globe.gl and three.js — to duplicate rendering this box
# can already do, and do consistently with the reports.
#
# So the CLIENT sends the rows it is displaying and the server renders them.
# That also makes the export exactly what the analyst sees: their search, MITRE,
# severity and verdict filters have already been applied to what arrives here.
# The column schema is deliberately NOT redefined server-side — it travels with
# the request, so export.js stays the single definition of what an export
# contains and the two can never drift.

# A guard, not a silent cap: over this the request is refused with an
# explanation rather than quietly exporting a truncated file.
_EXPORT_MAX_ROWS = 100000
_EXPORT_MAX_COLS = 60


@app.route("/api/export", methods=["POST"])
@_require_cap("export")
def api_export():
    if not REPORTS_AVAILABLE:
        return jsonify({"ok": False,
                        "error": "PDF/Excel export needs the report modules"}), 503
    body = request.get_json(silent=True) or {}
    fmt = (body.get("format") or "pdf").strip().lower()
    if fmt not in ("pdf", "xlsx"):
        return jsonify({"ok": False,
                        "error": "this endpoint renders pdf or xlsx only"}), 400
    if fmt not in ueba_report_render.available_formats():
        return jsonify({"ok": False,
                        "error": f"{fmt} is not available on this install"}), 400

    columns = body.get("columns") or []
    rows = body.get("rows") or []
    if not isinstance(columns, list) or not isinstance(rows, list):
        return jsonify({"ok": False, "error": "columns and rows must be lists"}), 400
    if not rows:
        return jsonify({"ok": False, "error": "nothing to export"}), 400
    if len(rows) > _EXPORT_MAX_ROWS:
        return jsonify({"ok": False,
                        "error": f"{len(rows):,} rows exceeds the {_EXPORT_MAX_ROWS:,} "
                                 "row export limit — narrow the filters or the "
                                 "timeline window"}), 413
    if len(columns) > _EXPORT_MAX_COLS:
        return jsonify({"ok": False, "error": "too many columns"}), 400

    title = str(body.get("title") or "UEBA Alert Export")[:120]
    note = str(body.get("note") or "")[:400]
    columns = [str(c) for c in columns]
    rows = [[("" if c is None else str(c)) for c in (r or [])] for r in rows]

    # Drop columns that are empty for every exported row. On a typical feed
    # three of the sixteen (FP reason, watch list, model score) apply to almost
    # nothing, and in a sixteen-column landscape table those empties cost width
    # the columns that DO carry data badly need. Reported, never silent.
    keep = [i for i in range(len(columns))
            if any((r[i].strip() if i < len(r) else "") for r in rows)]
    dropped = [columns[i] for i in range(len(columns)) if i not in keep]
    if dropped and keep:
        columns = [columns[i] for i in keep]
        rows = [[(r[i] if i < len(r) else "") for i in keep] for r in rows]

    now = datetime.now(timezone.utc)
    doc = {
        "schema":       ueba_reports.SCHEMA_VERSION,
        "report_id":    "feed_export",
        "title":        title,
        "subtitle":     f"{len(rows):,} alert(s) as filtered in the dashboard",
        "generated_at": now.isoformat(),
        "generated_by": _current_username(),
        "site":         CFG.get("site_name") or "CyberSentinel UEBA",
        "window":       {"hours": None, "from": None, "to": now.isoformat(),
                         "label": body.get("window_label") or "as displayed"},
        "sections": [ueba_reports.table(
            "Alerts", columns, rows,
            note=(note or ("Rows reflect the filters active in the dashboard when "
                           "this export was taken. False-positive-suppressed "
                           "alerts are excluded."))
                 + (f" Columns omitted as empty for every row: {', '.join(dropped)}."
                    if dropped else ""))],
    }
    try:
        data, mime, ext = ueba_report_render.render(doc, fmt)
    except Exception as e:
        print(f"[export] {fmt} render failed: {e}")
        return jsonify({"ok": False, "error": f"Export failed: {e}"}), 500

    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    resp = Response(data, mimetype=mime)
    resp.headers["Content-Disposition"] = f'attachment; filename="ueba-export-{stamp}.{ext}"'
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ── Custom report definitions (38) ──────────────────────────────────────────

@app.route("/api/reports/custom")
def api_reports_custom_list():
    if not _reports_ready():
        return _reports_unavailable()
    return jsonify({"ok": True,
                    "entries": ueba_report_store.definitions(_rcfg()["definitions_file"])})


@app.route("/api/reports/custom", methods=["POST"])
@_require_cap("reports.custom")
def api_reports_custom_save():
    if not _reports_ready():
        return _reports_unavailable()
    b = request.get_json(silent=True) or {}
    try:
        rec, created = ueba_report_store.save_definition(
            _rcfg()["definitions_file"],
            name=b.get("name"), sections=b.get("sections"),
            hours=b.get("hours"), fmt=b.get("format"), base=b.get("base"),
            did=b.get("id"), description=b.get("description"),
            created_by=_current_username())
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify({"ok": True, "entry": rec, "created": created})


@app.route("/api/reports/custom/<did>", methods=["DELETE"])
@_require_cap("reports.custom")
def api_reports_custom_delete(did):
    if not _reports_ready():
        return _reports_unavailable()
    if not ueba_report_store.delete_definition(_rcfg()["definitions_file"], did):
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "id": did})


# ── Schedules (40) ──────────────────────────────────────────────────────────

@app.route("/api/reports/schedules")
def api_reports_schedules_list():
    if not _reports_ready():
        return _reports_unavailable()
    return jsonify({"ok": True,
                    "timezone": ueba_report_store.local_tz_label(),
                    "email_enabled": ueba_report_store.smtp_configured(_smtp_cfg()),
                    "entries": ueba_report_store.schedules(_rcfg()["schedules_file"])})


@app.route("/api/reports/schedules", methods=["POST"])
@_require_cap("reports.schedule")
def api_reports_schedule_save():
    if not _reports_ready():
        return _reports_unavailable()
    b = request.get_json(silent=True) or {}
    if not (b.get("report_id") or "").strip():
        return jsonify({"ok": False, "error": "report_id required"}), 400
    try:
        rec, created = ueba_report_store.save_schedule(
            _rcfg()["schedules_file"],
            report_id=b["report_id"], interval=b.get("interval") or "daily",
            at=b.get("at") or "08:00", hours=b.get("hours"),
            fmt=b.get("format") or "pdf", recipients=b.get("recipients"),
            name=b.get("name"), weekday=b.get("weekday"), day=b.get("day"),
            enabled=b.get("enabled", True), sid=b.get("id"),
            created_by=_current_username())
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    warn = None
    if rec["recipients"] and not ueba_report_store.smtp_configured(_smtp_cfg()):
        warn = ("Saved, but SMTP is not configured — this report will be generated "
                "and stored, not emailed.")
    return jsonify({"ok": True, "entry": rec, "created": created, "warning": warn})


@app.route("/api/reports/schedules/<sid>", methods=["DELETE"])
@_require_cap("reports.schedule")
def api_reports_schedule_delete(sid):
    if not _reports_ready():
        return _reports_unavailable()
    if not ueba_report_store.delete_schedule(_rcfg()["schedules_file"], sid):
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "id": sid})


@app.route("/api/reports/schedules/<sid>/run", methods=["POST"])
@_require_cap("reports.schedule")
def api_reports_schedule_run(sid):
    """Run one schedule immediately — the way an administrator proves a
    schedule works without waiting a day for it to fire."""
    if not _reports_ready():
        return _reports_unavailable()
    sched = next((s for s in ueba_report_store.schedules(_rcfg()["schedules_file"])
                  if s.get("id") == sid), None)
    if sched is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    try:
        status = _run_schedule(sched, manual_by=_current_username())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify({"ok": True, "status": status})


def _run_schedule(sched, manual_by=None):
    """Generate, store and (if configured) email one scheduled report.

    Returns a short status string which is recorded against the schedule, so an
    administrator can see from the list whether last night's run actually
    delivered or merely generated.
    """
    report_id = sched.get("report_id")
    fmt = (sched.get("format") or "pdf").lower()
    hours = int(sched.get("hours") or _rcfg().get("default_hours") or 168)
    who = manual_by or f"schedule:{sched.get('id')}"

    data, mime, ext, doc = _generate(report_id, hours, fmt, generated_by=who)

    recipients = sched.get("recipients") or []
    delivery = None
    if recipients:
        smtp = _smtp_cfg()
        if not ueba_report_store.smtp_configured(smtp):
            delivery = "smtp not configured — stored only"
        else:
            win = (doc.get("window") or {}).get("label", "")
            ueba_report_store.send_email(
                smtp, to=recipients,
                subject=f'{doc.get("title")} — {win}',
                body=(f'{doc.get("title")}\n{doc.get("subtitle")}\n\n'
                      f'Period: {win}\n'
                      f'Generated: {doc.get("generated_at")}\n\n'
                      f'This report was generated automatically by '
                      f'{doc.get("site")}.\n'),
                attachment=data, filename=f"report.{ext}", mime=mime)
            delivery = f"emailed to {len(recipients)} recipient(s)"

    rec = ueba_report_store.record_artifact(
        _rcfg()["history_file"], _rcfg()["output_dir"],
        report_id=report_id, title=doc.get("title"), fmt=ext, data=data,
        hours=hours, generated_by=who, schedule_id=sched.get("id"),
        delivery=delivery, document=doc)
    return delivery or f"generated ({rec['file']})"


# ── Device registry and proactive alerting (RFP 10, 15) ─────────────────────

def _ncfg():
    return CFG.get("notify") or _DEFAULTS["notify"]


def _notify_ready():
    return NOTIFY_AVAILABLE and bool(_ncfg().get("enabled", True))


def _notify_unavailable():
    why = ("the notification module is not installed" if not NOTIFY_AVAILABLE
           else "notifications are disabled in ueba_config.yaml")
    return jsonify({"ok": False, "error": f"Alerting unavailable — {why}."}), 503


@app.route("/api/devices")
def api_devices_list():
    if not _notify_ready():
        return _notify_unavailable()
    items = ueba_notify.devices(_ncfg()["devices_file"])
    items.sort(key=lambda d: (ueba_notify.PRIORITIES.index(d.get("priority", "low"))
                              if d.get("priority") in ueba_notify.PRIORITIES else 0,
                              d.get("name", "")), reverse=True)
    return jsonify({"ok": True, "entries": items,
                    "priorities": list(ueba_notify.PRIORITIES)})


@app.route("/api/devices", methods=["POST"])
@_require_cap("devices.edit")
def api_devices_save():
    if not _notify_ready():
        return _notify_unavailable()
    b = request.get_json(silent=True) or {}
    try:
        rec, created = ueba_notify.save_device(
            _ncfg()["devices_file"], name=b.get("name"), label=b.get("label"),
            priority=b.get("priority") or "medium", owner=b.get("owner"),
            notes=b.get("notes"), updated_by=_current_username())
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify({"ok": True, "entry": rec, "created": created})


@app.route("/api/devices/<path:name>", methods=["DELETE"])
@_require_cap("devices.edit")
def api_devices_delete(name):
    if not _notify_ready():
        return _notify_unavailable()
    if not ueba_notify.delete_device(_ncfg()["devices_file"], name):
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "name": name})


@app.route("/api/notify/rules")
def api_notify_rules_list():
    if not _notify_ready():
        return _notify_unavailable()
    smtp_ok = (REPORTS_AVAILABLE
               and ueba_report_store.smtp_configured(_smtp_cfg()))
    return jsonify({
        "ok": True,
        "entries":    ueba_notify.rules(_ncfg()["rules_file"]),
        "priorities": list(ueba_notify.PRIORITIES),
        "verdicts":   list(ueba_notify.VERDICTS),
        "email_enabled": smtp_ok,
    })


@app.route("/api/notify/rules", methods=["POST"])
@_require_cap("notify.edit")
def api_notify_rule_save():
    if not _notify_ready():
        return _notify_unavailable()
    b = request.get_json(silent=True) or {}
    try:
        rec, created = ueba_notify.save_rule(
            _ncfg()["rules_file"], name=b.get("name"),
            min_score=b.get("min_score"), verdicts=b.get("verdicts"),
            priorities=b.get("priorities"), labels=b.get("labels"),
            tactics=b.get("tactics"),
            watchlisted_only=b.get("watchlisted_only", False),
            emails=b.get("emails"), webhook=b.get("webhook"),
            throttle_minutes=b.get("throttle_minutes"),
            max_per_hour=b.get("max_per_hour"),
            enabled=b.get("enabled", True), rid=b.get("id"),
            created_by=_current_username())
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    warn = None
    if rec["emails"] and not (REPORTS_AVAILABLE
                              and ueba_report_store.smtp_configured(_smtp_cfg())):
        warn = ("Saved, but SMTP is not configured — this rule cannot deliver "
                "email until it is. Webhook delivery is unaffected.")
    return jsonify({"ok": True, "entry": rec, "created": created, "warning": warn})


@app.route("/api/notify/rules/<rid>", methods=["DELETE"])
@_require_cap("notify.edit")
def api_notify_rule_delete(rid):
    if not _notify_ready():
        return _notify_unavailable()
    if not ueba_notify.delete_rule(_ncfg()["rules_file"], rid):
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "id": rid})


@app.route("/api/notify/rules/<rid>/test", methods=["POST"])
@_require_cap("notify.edit")
def api_notify_rule_test(rid):
    """Fire a rule against the most recent matching alert.

    An alerting rule that has never delivered is a rule nobody trusts, so an
    administrator can prove the channel works without waiting for a real match.
    """
    if not _notify_ready():
        return _notify_unavailable()
    rule = next((r for r in ueba_notify.rules(_ncfg()["rules_file"])
                 if r.get("id") == rid), None)
    if rule is None:
        return jsonify({"ok": False, "error": "not found"}), 404

    devidx = ueba_notify.device_index(_ncfg()["devices_file"])
    sample = None
    for a in reversed(load_alerts(n=4000, hours=168)):
        s = ueba_notify.summarise(a)
        if ueba_notify.matches(rule, s, devidx.get(ueba_notify._norm(s["host"]))):
            sample = s
            break
    if sample is None:
        return jsonify({"ok": False,
                        "error": "No alert in the last 7 days matches this rule, "
                                 "so there is nothing to send as a test."}), 409

    device = devidx.get(ueba_notify._norm(sample["host"]))
    sent, errors = [], []
    if rule.get("emails"):
        try:
            _notify_send_email(rule["emails"],
                               "[TEST] " + ueba_notify._subject(sample),
                               "This is a test notification sent on request.\n\n"
                               + ueba_notify._body(sample, device, rule.get("name"),
                                                   CFG.get("site_name")
                                                   or "CyberSentinel UEBA"))
            sent.append(f"email to {len(rule['emails'])} recipient(s)")
        except Exception as e:
            errors.append(f"email: {e}")
    if rule.get("webhook"):
        try:
            ueba_notify.post_webhook(rule["webhook"], {
                "source": "cybersentinel-ueba", "test": True,
                "rule": {"id": rule["id"], "name": rule.get("name")},
                "alert": sample, "device": device,
            })
            sent.append("webhook")
        except Exception as e:
            errors.append(f"webhook: {e}")
    if errors and not sent:
        return jsonify({"ok": False, "error": "; ".join(errors)}), 502
    return jsonify({"ok": True, "sent": sent, "errors": errors,
                    "sample_event": sample.get("event_id")})


def _notify_send_email(to, subject, body):
    """Adapter so the dispatcher never needs to know the SMTP configuration."""
    if not REPORTS_AVAILABLE:
        raise RuntimeError("email delivery needs the reporting modules")
    ueba_report_store.send_email(_smtp_cfg(), to=to, subject=subject, body=body)


# ── Watch lists (RFP 1) ─────────────────────────────────────────────────────
# CRUD over the store the engine reads. All three mutating verbs land in the
# audit trail automatically via _audit_mutations — adding someone to a watch
# list is precisely the kind of action that should be attributable.

def _watchlist_unavailable():
    return jsonify({"ok": False, "error": "watchlist module unavailable",
                    "entries": []}), 503


@app.route("/api/watchlist")
def api_watchlist_list():
    if not WATCHLIST_AVAILABLE:
        return _watchlist_unavailable()
    try:
        items = ueba_watchlist.entries(WATCHLIST_FILE)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "entries": []}), 500
    # Newest first — an analyst adding entries wants to see them at the top.
    items.sort(key=lambda e: e.get("added_at") or "", reverse=True)
    return jsonify({
        "ok":      True,
        "count":   len(items),
        "types":   list(ueba_watchlist.TYPES),
        "default_boost": ueba_watchlist.DEFAULT_BOOST,
        "max_boost":     ueba_watchlist.MAX_BOOST,
        "entries": items,
    })


@app.route("/api/watchlist", methods=["POST"])
@_require_cap("watchlist.edit")
def api_watchlist_add():
    if not WATCHLIST_AVAILABLE:
        return _watchlist_unavailable()
    body = request.get_json(silent=True) or {}
    etype = (body.get("type") or "").strip()
    value = (body.get("value") or "").strip()
    if not value:
        return jsonify({"ok": False, "error": "value required"}), 400
    if etype not in ueba_watchlist.TYPES:
        return jsonify({"ok": False,
                        "error": f"type must be one of {list(ueba_watchlist.TYPES)}"}), 400
    actor = None
    if AUTH_MODULE_AVAILABLE:
        try:
            u = ueba_auth.current_user()
            actor = (u or {}).get("username")
        except Exception:
            pass
    try:
        entry, created = ueba_watchlist.add(
            WATCHLIST_FILE, etype, value,
            reason=(body.get("reason") or ""),
            boost=body.get("boost"),
            added_by=actor,
        )
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify({"ok": True, "entry": entry, "created": created})


@app.route("/api/watchlist/<eid>", methods=["DELETE"])
@_require_cap("watchlist.edit")
def api_watchlist_remove(eid):
    if not WATCHLIST_AVAILABLE:
        return _watchlist_unavailable()
    try:
        removed = ueba_watchlist.remove(WATCHLIST_FILE, eid)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    if not removed:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "id": eid})


@app.route("/api/audit")
@_require_cap("audit.view")
def api_audit():
    """Most-recent audit entries, newest first.

    Read-only view over the JSONL written by _audit_mutations. Bounded because
    the file is allowed to grow to tens of MB and nobody wants that serialised
    into a single response.
    """
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 2000))
    except ValueError:
        limit = 200
    rows: list = []
    try:
        if AUDIT_FILE.exists():
            # Small enough to read plainly at the 64 MB cap, but tail the last
            # slice rather than parsing every historical line.
            with open(AUDIT_FILE, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                back = min(size, limit * 512 + 65536)
                fh.seek(size - back)
                chunk = fh.read().decode("utf-8", "replace")
            lines = chunk.splitlines()
            if back < size and lines:
                lines = lines[1:]          # drop the partial first line
            for ln in lines[-limit:]:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    continue
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "entries": []}), 500
    rows.reverse()
    return jsonify({"ok": True, "count": len(rows), "entries": rows})


@app.route("/api/false-positive", methods=["POST"])
@_require_cap("fp.edit")
def mark_false_positive():
    """Mark a single alert as FP. Also auto-creates a suppression pattern
    derived from the alert's (signature_id, user, agent) fingerprint so future
    similar alerts are filtered out of the feed. The per-event record stays
    around as an audit trail (which alert prompted the pattern).
    """
    body = request.get_json(silent=True) or {}
    eid = (body.get("event_id") or "").strip()
    reason = (body.get("reason") or "").strip()
    if not eid:
        return jsonify({"ok": False, "error": "event_id required"}), 400
    rec = {
        "event_id":  eid,
        "reason":    reason,
        "marked_at": datetime.now(timezone.utc).isoformat(),
    }
    with _fp_lock:
        _fp_dict[eid] = rec
        save_fps()

    # Auto-suppress similar alerts: derive a pattern from the underlying alert.
    raw = _read_all_alerts_for_lookup()
    alert = next((a for a in raw if a.get("event_id") == eid), None)
    pat, pat_new = (None, False)
    if alert:
        candidate = _pattern_from_alert(alert, reason)
        pat, pat_new = _add_pattern_if_new(candidate)
    return jsonify({
        "ok":          True,
        "record":      rec,
        "pattern":     pat,       # None if alert missing or no signature_id
        "pattern_new": pat_new,   # False if pattern already existed (dedupe)
    })


@app.route("/api/false-positive/<path:event_id>", methods=["DELETE"])
@_require_cap("fp.edit")
def unmark_false_positive(event_id):
    """Restore an FP-marked alert AND tear down the auto-suppression pattern
    that was created when it was marked. The mark and the pattern are created
    together by mark_false_positive — symmetry says they should be torn down
    together too.
    """
    with _fp_lock:
        existed = _fp_dict.pop(event_id, None)
        if existed:
            save_fps()

    # Resolve the alert's rule description and drop any matching pattern.
    patterns_removed = 0
    if existed:
        raw = _read_all_alerts_for_lookup()
        alert = next((a for a in raw if a.get("event_id") == event_id), None)
        if alert:
            desc = (alert.get("security", {}) or {}).get("signature")
            patterns_removed = _remove_patterns_for_descriptions([desc])

    return jsonify({
        "ok":               True,
        "removed":          bool(existed),
        "patterns_removed": patterns_removed,
    })


def _event_ids_in_campaign(campaign_id: str) -> list[str]:
    """Scan the raw (unfiltered) alert list and return every event_id whose
    ueba.campaign_id equals campaign_id."""
    raw = _read_all_alerts_for_lookup()
    return [
        a["event_id"]
        for a in raw
        if a.get("event_id")
        and (a.get("ueba", {}) or {}).get("campaign_id") == campaign_id
    ]


@app.route("/api/false-positive/campaign/<path:campaign_id>", methods=["POST"])
@_require_cap("fp.edit")
def mark_campaign_false_positive(campaign_id):
    """Mark every alert in a campaign as FP. Also auto-creates one pattern per
    unique rule description within the campaign so the suppression follows
    similar alerts forward in time."""
    body = request.get_json(silent=True) or {}
    reason = (body.get("reason") or "").strip() \
             or f"campaign {campaign_id} marked as false positive"
    eids = _event_ids_in_campaign(campaign_id)
    if not eids:
        return jsonify({"ok": False, "error": "no alerts for campaign"}), 404
    now = datetime.now(timezone.utc).isoformat()
    with _fp_lock:
        for eid in eids:
            _fp_dict[eid] = {"event_id": eid, "reason": reason, "marked_at": now}
        save_fps()

    # Auto-suppress: one pattern per unique fingerprint in the campaign.
    raw = _read_all_alerts_for_lookup()
    by_id = {a.get("event_id"): a for a in raw}
    seen: set = set()
    patterns_new = 0
    for eid in eids:
        a = by_id.get(eid)
        if not a:
            continue
        candidate = _pattern_from_alert(a, reason)
        if not candidate:
            continue
        key = _norm_desc(candidate["rule_description"])
        if key in seen:
            continue
        seen.add(key)
        _, was_new = _add_pattern_if_new(candidate)
        if was_new:
            patterns_new += 1
    return jsonify({
        "ok":           True,
        "marked":       len(eids),
        "campaign_id":  campaign_id,
        "patterns_new": patterns_new,
    })


@app.route("/api/false-positive/campaign/<path:campaign_id>", methods=["DELETE"])
@_require_cap("fp.edit")
def unmark_campaign_false_positive(campaign_id):
    """Restore every alert in a campaign AND drop the auto-suppression
    patterns that were created when the campaign was marked. Mirrors the
    per-event unmark — mark and pattern are created together, so torn down
    together.
    """
    eids = _event_ids_in_campaign(campaign_id)
    with _fp_lock:
        removed = 0
        for eid in eids:
            if _fp_dict.pop(eid, None):
                removed += 1
        if removed:
            save_fps()

    # Collect descriptions from this campaign's alerts and tear down patterns.
    raw = _read_all_alerts_for_lookup()
    by_id = {a.get("event_id"): a for a in raw}
    descs = {
        (by_id.get(eid, {}).get("security") or {}).get("signature")
        for eid in eids if eid in by_id
    }
    patterns_removed = _remove_patterns_for_descriptions(descs)

    return jsonify({
        "ok":               True,
        "removed":          removed,
        "campaign_id":      campaign_id,
        "patterns_removed": patterns_removed,
    })


# ── False-positive PATTERN management ────────────────────────────────────────
# Patterns auto-suppress any future alert whose rule description matches
# (whitespace-trimmed, case-insensitive). One pattern = one rule description.
def _read_suppress_stats() -> dict:
    """Read the engine-written per-pattern hit tally ({pattern_id: count}) from
    the sibling of the patterns file. Best-effort: missing/corrupt → {}."""
    p = FP_PATTERNS_FILE.with_name("fp_suppress_stats.json")
    try:
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8") or "{}")
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return {}


@app.route("/api/false-positive-patterns")
def list_fp_patterns():
    """Return all FP patterns with a `matched` count.

    The engine drops a suppressed alert BEFORE it is written to the alert
    file, so counting matches in the loaded alerts would (correctly) yield ~0
    once suppression is working. The real, cumulative count lives in the
    engine-written sibling file `fp_suppress_stats.json` ({pattern_id: hits}).
    We use that as the source of truth, and add any still-in-file matches
    (alerts scored before the engine picked up the pattern) so the count is
    never an under-count.
    """
    eng_counts = _read_suppress_stats()
    raw = load_alerts(include_fp=True)
    counts: dict = {}
    for a in raw:
        p = _matching_pattern(a)
        if p:
            counts[p.get("id")] = counts.get(p.get("id"), 0) + 1
    out = []
    for p in _fp_patterns:
        pid = p.get("id")
        matched = int(eng_counts.get(pid, 0)) + counts.get(pid, 0)
        out.append({**p, "matched": matched})
    out.sort(key=lambda r: r.get("marked_at", ""), reverse=True)
    return jsonify(out)


@app.route("/api/false-positive-pattern", methods=["POST"])
@_require_cap("fp.edit")
def mark_fp_pattern():
    """Add a new FP pattern directly. Body: {rule_description, reason}."""
    body = request.get_json(silent=True) or {}
    desc = (str(body.get("rule_description") or "")).strip()
    reason = (body.get("reason") or "").strip()
    if not desc:
        return jsonify({"ok": False, "error": "rule_description required"}), 400
    candidate = {
        "id":               "fpp-" + uuid.uuid4().hex[:10],
        "rule_description": desc,
        "reason":           reason,
        "marked_at":        datetime.now(timezone.utc).isoformat(),
    }
    rec, was_new = _add_pattern_if_new(candidate)
    return jsonify({"ok": True, "record": rec, "deduped": (not was_new)})


@app.route("/api/false-positive-pattern/<pat_id>", methods=["DELETE"])
@_require_cap("fp.edit")
def unmark_fp_pattern(pat_id):
    with _fp_pat_lock:
        before = len(_fp_patterns)
        _fp_patterns[:] = [p for p in _fp_patterns if p.get("id") != pat_id]
        removed = before - len(_fp_patterns)
        if removed:
            save_fp_patterns()
    return jsonify({"ok": True, "removed": bool(removed)})


# ── Engine health ────────────────────────────────────────────────────────────
@app.route("/api/health")
def health():
    """Engine + dashboard health snapshot for the Overview health card."""
    alerts = load_alerts(include_fp=True)   # include FPs so we report the real engine output
    total = len(alerts)

    now = datetime.now(timezone.utc)
    one_hour_ago  = now - timedelta(hours=1)
    one_day_ago   = now - timedelta(hours=24)
    alerts_1h     = 0
    alerts_24h    = 0
    newest_iso    = None
    newest_dt     = None
    for a in alerts:
        # Reuse the memoised timestamp (_alert_ts caches the parse on the dict)
        # instead of re-parsing every ISO string here — health runs over the full
        # window and was paying a second full parse pass on every call.
        d = _alert_ts(a)
        if d is None:
            continue
        if d >= one_hour_ago: alerts_1h  += 1
        if d >= one_day_ago:  alerts_24h += 1
        if newest_dt is None or d > newest_dt:
            newest_dt  = d
            newest_iso = (a.get("ueba", {}) or {}).get("processed_at") or a.get("event_time") or ""

    try:
        file_size = ALERTS_FILE.stat().st_size if ALERTS_FILE.exists() else 0
    except Exception:
        file_size = 0

    fp_count = len(_fp_dict)
    fp_rate  = round((fp_count / total) * 100, 2) if total > 0 else 0.0

    try:
        started = datetime.fromisoformat(_SERVER_STARTED_AT)
        uptime  = int((now - started).total_seconds())
    except Exception:
        uptime = 0

    # "Engine live" = at least one alert within the last 5 minutes.
    engine_live = bool(newest_dt and (now - newest_dt).total_seconds() < 300)

    # Feed liveness — is the engine's INPUT (enriched.jsonl) still growing? This
    # is the true "is the 222→98 feed alive" signal, INDEPENDENT of whether any
    # alert fired: a quiet period legitimately produces no alerts but the feed is
    # still healthy. The stale-feed banner keys on this, not on alert recency.
    feed_mtime_iso = None
    feed_age_secs  = None
    try:
        ep = _resolve_enriched_path(CFG.get("enriched_file"))
        if ep is not None and ep.exists():
            feed_dt = datetime.fromtimestamp(ep.stat().st_mtime, timezone.utc)
            feed_mtime_iso = feed_dt.isoformat()
            feed_age_secs  = int((now - feed_dt).total_seconds())
    except Exception:
        pass
    feed_live = feed_age_secs is not None and feed_age_secs < 180

    with _agent_sync_lock:
        agent_sync_status = {
            "enabled":    bool((CFG.get("agent_sync") or {}).get("enabled")),
            "last_at":    _agent_sync_last_at,
            "last_error": _agent_sync_last_error,
        }

    return jsonify({
        "total_alerts":           total,
        "alerts_1h":              alerts_1h,
        "alerts_24h":             alerts_24h,
        "newest_alert_time":      newest_iso,
        "alerts_file_size_bytes": file_size,
        "fp_count":               fp_count,
        "fp_rate_pct":            fp_rate,
        "server_started_at":      _SERVER_STARTED_AT,
        "uptime_secs":            uptime,
        "engine_live":            engine_live,
        "feed_mtime":             feed_mtime_iso,
        "feed_age_secs":          feed_age_secs,
        "feed_live":              feed_live,
        "agent_sync":             agent_sync_status,
    })


# ── Live event stream (Server-Sent Events) ───────────────────────────────────
# /api/stream tails ueba_alerts.jsonl from "now" and pushes every new alert as
# an SSE 'alert' event. The dashboard's initial state is already loaded via
# /api/feed at boot — the stream only delivers what arrives after connection.

@app.route("/api/stream")
def stream_alerts():
    @stream_with_context
    def event_stream():
        # Send a hello frame so the EventSource transitions from 'connecting'
        # to 'open' immediately, even before the first alert arrives.
        yield "event: hello\ndata: {}\n\n"

        # Start at the current end of the file — don't replay history.
        try:
            last_pos = ALERTS_FILE.stat().st_size if ALERTS_FILE.exists() else 0
        except Exception:
            last_pos = 0
        last_heartbeat = time.time()

        while True:
            try:
                if ALERTS_FILE.exists():
                    try:
                        size = ALERTS_FILE.stat().st_size
                    except Exception:
                        size = last_pos
                    if size < last_pos:
                        # File rotated / truncated — start from the new end.
                        last_pos = 0
                    if size > last_pos:
                        try:
                            with open(ALERTS_FILE, "r", encoding="utf-8", errors="replace") as f:
                                f.seek(last_pos)
                                chunk = f.read()
                                last_pos = f.tell()
                        except Exception:
                            chunk = ""
                        for line in chunk.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                alert = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            eid = alert.get("event_id")
                            if eid and eid in _fp_dict:
                                continue   # already a known FP, don't push it
                            if _matching_pattern(alert) is not None:
                                continue   # auto-suppressed by a stored pattern
                            payload = _alert_to_feed_item(alert)
                            yield f"event: alert\ndata: {json.dumps(payload, default=str)}\n\n"

                now = time.time()
                if now - last_heartbeat > 15:
                    # SSE comment lines keep the connection alive through
                    # proxies/load balancers without delivering an event.
                    yield ": heartbeat\n\n"
                    last_heartbeat = now
                time.sleep(1.0)
            except GeneratorExit:
                return
            except Exception as e:
                # Surface and continue; the client will keep us open.
                try:
                    yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                except Exception:
                    return
                time.sleep(2.0)

    headers = {
        "Cache-Control":     "no-cache",
        "X-Accel-Buffering": "no",       # disable nginx buffering
        "Connection":        "keep-alive",
    }
    return Response(event_stream(), mimetype="text/event-stream", headers=headers)


# ── AI Security Analyst proxy ────────────────────────────────────────────────
@app.route("/api/ai-analyze", methods=["POST"])
@_require_cap("ai.analyze")
def ai_analyze():
    """Proxy the AI Security Analyst prompt to Anthropic with a server-side key.

    Request body: { "prompt": "..." }
    Response: { "ok": bool, "text": "...", "source": "anthropic"|"fallback", "error": "..." }
    """
    ai_cfg = CFG.get("ai_analyst", {}) or {}
    body = request.get_json(silent=True) or {}
    prompt = (body.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"ok": False, "error": "missing prompt", "source": "fallback"}), 400

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()

    if not ai_cfg.get("enabled", True):
        return jsonify({"ok": False, "error": "ai_analyst disabled", "source": "fallback"})
    if not api_key:
        return jsonify({"ok": False, "error": "ANTHROPIC_API_KEY not set", "source": "fallback"})
    if requests is None:
        return jsonify({"ok": False, "error": "requests not installed", "source": "fallback"})

    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model":      ai_cfg.get("model", "claude-sonnet-4-6"),
                "max_tokens": int(ai_cfg.get("max_tokens", 1000)),
                "messages":   [{"role": "user", "content": prompt}],
            },
            timeout=int(ai_cfg.get("timeout_secs", 20)),
        )
        if r.status_code != 200:
            return jsonify({
                "ok": False,
                "error": f"upstream {r.status_code}: {r.text[:200]}",
                "source": "fallback",
            })
        data = r.json()
        text = "".join(c.get("text", "") for c in data.get("content", []) if c.get("type") == "text")
        if not text:
            return jsonify({"ok": False, "error": "empty response", "source": "fallback"})
        return jsonify({"ok": True, "text": text, "source": "anthropic"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "source": "fallback"})


# ── Live threat map (firewall geoIP) ─────────────────────────────────────────
# Tail recent FIREWALL events from the enriched feed, geolocate each external
# source IP via a local MaxMind GeoLite2 DB, and serve source→DC arcs. All
# offline — no external geo API. Degrades to empty if the DB/lib is missing.
import ipaddress

try:
    import geoip2.database as _geoip2_db  # type: ignore
except Exception:
    _geoip2_db = None

# Known on-disk locations for the GeoLite2 DBs (first existing one wins).
_GEOIP_CITY_CANDIDATES = [
    "/root/NEW_DRIVE/aditya_ueba/databases/GeoLite2-City.mmdb",
    "/data/CyberSentinel-Event-Correlation/databases/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
]
_GEOIP_ASN_CANDIDATES = [
    "/root/NEW_DRIVE/aditya_ueba/databases/GeoLite2-ASN.mmdb",
    "/data/CyberSentinel-Event-Correlation/databases/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
]

_geo_city_reader = None
_geo_asn_reader  = None
_geo_readers_tried = False
_geo_cache: dict = {}        # ip -> geo dict | None  (None = un-geolocatable, cached too)
_geo_cache_lock = __import__("threading").Lock()
_dc_loc: dict | None = None


# The install directory is wherever this file lives, so a databases/ beside it
# is found whatever BASE_DIR the installer chose. Without this, auto-detect
# only knew the lab's absolute path and the customer's own
# <install>/databases/ — which install_ueba.sh creates — was never looked at,
# so the threat map stayed empty on every install that did not happen to put
# UEBA where the lab had it. The explicit geoip_city_db / geoip_asn_db config
# keys still take precedence for sites that keep the DBs elsewhere.
_INSTALL_DB_DIR = Path(__file__).resolve().parent / "databases"
_GEOIP_CITY_CANDIDATES.insert(0, str(_INSTALL_DB_DIR / "GeoLite2-City.mmdb"))
_GEOIP_ASN_CANDIDATES.insert(0, str(_INSTALL_DB_DIR / "GeoLite2-ASN.mmdb"))


def _first_existing(explicit: str, candidates: list) -> str | None:
    if explicit and Path(explicit).is_file():
        return explicit
    for c in candidates:
        if Path(c).is_file():
            return c
    return None


def _open_geo_readers():
    """Open the GeoLite2 City/ASN readers once (lazy). Safe if absent."""
    global _geo_city_reader, _geo_asn_reader, _geo_readers_tried
    if _geo_readers_tried:
        return
    _geo_readers_tried = True
    if _geoip2_db is None:
        print("[threatmap] geoip2 not installed — /api/geofeed will be empty")
        return
    city_path = _first_existing(str(CFG.get("geoip_city_db") or ""), _GEOIP_CITY_CANDIDATES)
    asn_path  = _first_existing(str(CFG.get("geoip_asn_db") or ""),  _GEOIP_ASN_CANDIDATES)
    if not city_path:
        print("[threatmap] no GeoLite2-City.mmdb found — /api/geofeed will be empty")
        return
    try:
        _geo_city_reader = _geoip2_db.Reader(city_path)
        print(f"[threatmap] GeoLite2-City loaded from {city_path}")
    except Exception as e:
        print(f"[threatmap] failed to open City DB {city_path}: {e}")
    if asn_path:
        try:
            _geo_asn_reader = _geoip2_db.Reader(asn_path)
        except Exception as e:
            print(f"[threatmap] failed to open ASN DB {asn_path}: {e}")


def _is_public_ip(ip: str) -> bool:
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (o.is_private or o.is_loopback or o.is_reserved
                or o.is_link_local or o.is_multicast or o.is_unspecified)


def _geo_lookup(ip: str) -> dict | None:
    """Lat/lng/country/city/asn for a public IP, cached. None if not resolvable."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    result = None
    if _geo_city_reader is not None:
        try:
            c = _geo_city_reader.city(ip)
            if c.location.latitude is not None and c.location.longitude is not None:
                result = {
                    "lat": round(c.location.latitude, 4),
                    "lng": round(c.location.longitude, 4),
                    "country": c.country.iso_code or "??",
                    "country_name": c.country.name or "Unknown",
                    "city": c.city.name or "",
                }
                if _geo_asn_reader is not None:
                    try:
                        a = _geo_asn_reader.asn(ip)
                        result["asn"] = a.autonomous_system_number
                        result["org"] = a.autonomous_system_organization or ""
                    except Exception:
                        pass
        except Exception:
            result = None
    with _geo_cache_lock:
        if len(_geo_cache) > 50000:        # bound the cache
            _geo_cache.clear()
        _geo_cache[ip] = result
    return result


def _resolve_dc() -> dict:
    """The arc target: geolocate the configured DC/WAN IP once, else fall back
    to the configured DC coords."""
    global _dc_loc
    if _dc_loc is not None:
        return _dc_loc
    tm = CFG.get("threatmap") or {}
    dc_ip = str(tm.get("dc_ip") or "")
    loc = _geo_lookup(dc_ip) if dc_ip and _is_public_ip(dc_ip) else None
    if loc:
        _dc_loc = {"lat": loc["lat"], "lng": loc["lng"],
                   "country": loc.get("country", "IN"),
                   "label": tm.get("dc_label", "Datacenter")}
    else:
        _dc_loc = {"lat": float(tm.get("dc_lat", 21.1463)),
                   "lng": float(tm.get("dc_lng", 79.0849)),
                   "country": "IN", "label": tm.get("dc_label", "Datacenter")}
    return _dc_loc


def _resolve_enriched_path(spec: str):
    """Resolve `dashboard.enriched_file` to a readable JSONL file, or None.

    Accepts three forms, because the deployment topology decides which makes
    sense:

      * a literal file   — UEBA on its own host, tailing the one enriched.jsonl
                           the sync bridge appends to.
      * a directory      — UEBA on the SIEM host. There is no single
                           enriched.jsonl in that mode: the pipeline's own sink
                           writes rotating enriched_<timestamp>.jsonl files.
      * a glob           — same, stated explicitly.

    For the latter two the NEWEST UNCOMPRESSED file wins. Uncompressed matters:
    the sink gzips a file when it rotates it, so the plain .jsonl is the one
    still being appended to, and it is the only one whose tail is current. The
    callers read raw bytes and parse lines, so handing them a .gz would yield
    nothing but decode errors.

    This is what makes the threat map work without a second copy of the data or
    an extra process — the events are already on this disk, written by the
    pipeline. Before this, `enriched_file` pointed at a path that does not
    exist under Kafka ingestion, which silently cost two things: the geofeed
    returned zero arcs, and the feed-liveness check never saw an mtime, so the
    stale-feed banner was stuck on while ingestion was perfectly healthy.
    """
    import glob as _glob

    spec = str(spec or "").strip()
    if not spec:
        return None

    pth = Path(spec)
    if pth.is_file():
        return pth

    if pth.is_dir():
        pattern = str(pth / "*.jsonl")
    elif any(ch in spec for ch in "*?["):
        pattern = spec
    else:
        return None

    cands = [c for c in _glob.glob(pattern) if not c.endswith(".gz")]
    if not cands:
        return None
    try:
        return Path(max(cands, key=lambda c: os.path.getmtime(c)))
    except OSError:
        return None


def _is_firewall_event(e: dict) -> bool:
    h = e.get("host") or {}
    if h.get("type") == "firewall":
        return True
    if str((h.get("os") or {}).get("name") or "").lower() == "fortios":
        return True
    return "fortigate" in str((e.get("context") or {}).get("source") or "").lower()


# Classify a firewall event into a traffic category + arc direction, and pick the
# EXTERNAL endpoint to geolocate. Categories mirror the analyst legend:
#   incoming_threat  (red)    – external → DC, blocked/failed/attack
#   normal_incoming  (blue)   – external → DC, allowed/successful
#   outgoing         (green)  – DC → external, our server reaching out
#   external_conn    (yellow) – VPN / session connections (external → DC)
# arc_dir is "in" (external→DC) or "out" (DC→external) and drives the on-globe
# flow direction so the analyst can see which way the traffic moves.
def _classify_firewall(e: dict):
    net      = e.get("network") or {}
    direction = str(net.get("direction") or "").lower()
    outcome  = str(e.get("event_outcome") or "").lower()
    sig      = str((e.get("security") or {}).get("signature") or "").lower()
    sub_ip   = str((e.get("subject") or {}).get("ip") or "")
    obj_ip   = str((e.get("object") or {}).get("ip") or "")

    failed = ("fail" in outcome or "fail" in sig or "block" in sig or "denied" in sig
              or "deny" in sig or "attack" in sig or "drop" in sig or "invalid" in sig)
    is_vpn = "vpn" in sig

    if direction == "outgoing":
        ext = obj_ip if _is_public_ip(obj_ip) else sub_ip
        return ("outgoing", "out", ext)

    # incoming / internal / none / unknown — the external party is the source side
    ext = sub_ip if _is_public_ip(sub_ip) else obj_ip
    if is_vpn and not failed:
        return ("external_conn", "in", ext)
    if failed:
        return ("incoming_threat", "in", ext)
    return ("normal_incoming", "in", ext)


def _tail_firewall_geo(window_bytes: int, max_arcs: int) -> dict:
    """Read the tail of enriched.jsonl, keep firewall events with a public source
    IP, geolocate them, and build source→DC arcs (newest last) plus aggregates."""
    _open_geo_readers()
    dc = _resolve_dc()
    geo_ok = _geo_city_reader is not None
    path = _resolve_enriched_path(CFG.get("enriched_file"))
    arcs: list = []
    by_country: dict = {}
    by_sig: dict = {}
    by_category: dict = {"incoming_threat": 0, "normal_incoming": 0,
                         "outgoing": 0, "external_conn": 0}
    seen_ips: set = set()
    scanned = 0
    if geo_ok and path is not None and path.is_file():
        try:
            size = path.stat().st_size
            with open(path, "rb") as f:
                f.seek(max(0, size - window_bytes))
                blob = f.read()
            lines = blob.split(b"\n")
            if size > window_bytes and lines:
                lines = lines[1:]          # drop the partial first line
            for raw in lines:
                if not raw.strip():
                    continue
                try:
                    e = json.loads(raw)
                except Exception:
                    continue
                if not _is_firewall_event(e):
                    continue
                scanned += 1
                category, arc_dir, ext_ip = _classify_firewall(e)
                if not ext_ip or not _is_public_ip(str(ext_ip)):
                    continue
                g = _geo_lookup(str(ext_ip))
                if not g:
                    continue
                sig = str((e.get("security") or {}).get("signature") or "Firewall event")
                arcs.append({
                    "srcLat": g["lat"], "srcLng": g["lng"],
                    "direction": arc_dir, "category": category,
                    "country": g["country"], "country_name": g.get("country_name", ""),
                    "city": g.get("city", ""), "ip": str(ext_ip),
                    "org": g.get("org", ""), "asn": g.get("asn"),
                    "sig": sig,
                    "outcome": str(e.get("event_outcome") or ""),
                    "time": e.get("event_time") or e.get("ingest_time"),
                })
                seen_ips.add(str(ext_ip))
                by_category[category] = by_category.get(category, 0) + 1
                cc = g["country"]
                bc = by_country.setdefault(cc, {"country": cc,
                        "country_name": g.get("country_name", ""), "count": 0})
                bc["count"] += 1
                by_sig[sig] = by_sig.get(sig, 0) + 1
        except Exception as e:
            print(f"[threatmap] tail read failed: {e}")

    if len(arcs) > max_arcs:
        arcs = arcs[-max_arcs:]            # keep newest

    top_countries = sorted(by_country.values(), key=lambda x: -x["count"])[:12]
    top_sigs = sorted(({"sig": s, "count": c} for s, c in by_sig.items()),
                      key=lambda x: -x["count"])[:8]
    return {
        "geo_ok": geo_ok,
        "dc": dc,
        "arcs": arcs,
        "stats": {
            "events": scanned,
            "mapped": len(arcs),
            "unique_ips": len(seen_ips),
            "countries": len(by_country),
            "categories": by_category,
            "top_countries": top_countries,
            "top_signatures": top_sigs,
        },
    }


@app.route("/api/geofeed")
def geofeed():
    """Live firewall-attack map feed: geolocated source→DC arcs for the globe."""
    tm = CFG.get("threatmap") or {}
    try:
        window = int(request.args.get("bytes") or tm.get("window_bytes", 12582912))
    except (TypeError, ValueError):
        window = int(tm.get("window_bytes", 12582912))
    window = max(256 * 1024, min(window, 64 * 1024 * 1024))   # clamp 256KB–64MB
    try:
        max_arcs = int(request.args.get("max") or tm.get("max_arcs", 400))
    except (TypeError, ValueError):
        max_arcs = int(tm.get("max_arcs", 400))
    max_arcs = max(10, min(max_arcs, 2000))

    # The threat map polls this every 6s per open tab, and each call re-reads and
    # re-parses the 12 MB tail of enriched.jsonl. Normally ~0.1s, but it spikes
    # (measured 5.7s) whenever the engine is busy draining a backlog — exactly
    # when an analyst is most likely to be watching the map. A cache slightly
    # shorter than the poll interval makes repeated polls, and every extra
    # viewer, free without making the map any staler than its own refresh rate.
    key = (window, max_arcs)
    now = time.time()
    hit = _geofeed_cache.get(key)
    if hit is not None and (now - hit[0]) < _GEOFEED_TTL:
        return jsonify(hit[1])
    value = _tail_firewall_geo(window, max_arcs)
    _geofeed_cache[key] = (now, value)
    # Bounded: the params are clamped, so this can only ever hold a handful of
    # entries, but never let a pathological caller grow it without limit.
    if len(_geofeed_cache) > 16:
        for k in sorted(_geofeed_cache, key=lambda k: _geofeed_cache[k][0])[:8]:
            _geofeed_cache.pop(k, None)
    return jsonify(value)


# ── Static + index ───────────────────────────────────────────────────────────
def _serve_index():
    """Serve dashboard/dist/index.html if it exists, otherwise the legacy file.

    The shell is sent with `no-store`, NOT the default `no-cache`.

    Vite fingerprints every bundle (index-<hash>.js), and a rebuild deletes the
    previous hash. `no-cache` only asks the browser to revalidate — a soft reload
    or a restored tab can still reuse a stored shell, and that shell points at a
    bundle that no longer exists. The result is a page that loads but renders
    nothing, with a lone 404 for the dead bundle as the only clue (observed
    2026-09-21: repeated GET /assets/index-Bn3XzNlk.js -> 404 long after that
    bundle was replaced).

    `no-store` forbids keeping the shell at all, so every navigation fetches the
    current HTML and therefore the current bundle hash. The shell is 52 KB and
    gzips to ~13 KB, so re-fetching it costs far less than a blank dashboard.
    The hashed assets it references stay cacheable — their names change when
    their contents do, which is the whole point of fingerprinting.
    """
    dist_index = DASHBOARD_DIST / "index.html"
    if dist_index.exists():
        resp = send_from_directory(str(DASHBOARD_DIST), "index.html")
    else:
        resp = send_from_directory(str(DASHBOARD_DIR), "index.html")
    resp.headers["Cache-Control"] = "no-store, must-revalidate"
    resp.headers.pop("ETag", None)      # nothing to revalidate against
    return resp


@app.route("/")
def index():
    return _serve_index()


@app.route("/assets/<path:filename>")
def dist_assets(filename):
    """Vite's hashed JS/CSS bundles live under dashboard/dist/assets/."""
    return send_from_directory(str(DASHBOARD_DIST / "assets"), filename)


@app.route("/legacy")
def legacy_index():
    """Always serve the pre-Vite single-file dashboard for fallback debugging."""
    return send_from_directory(str(DASHBOARD_DIR), "index.legacy.html")


# SPA fallback — the client-side router activates the right tab based on the
# URL. The order is:
#   1. If a file with that exact path exists in dashboard/dist/ (e.g. logo
#      images copied from public/, favicon.ico, etc.), serve it directly.
#   2. Otherwise, if the first path segment is a known tab name, return
#      index.html so the client router can activate the right tab.
#   3. Otherwise, 404.
SPA_TAB_PATHS = {"overview", "feed", "users", "campaigns", "endpoints",
                 "false-positives", "watchlist", "reports", "alerting", "threatmap",
                 "incidents", "auth", "settings"}

@app.route("/<path:subpath>")
def spa_fallback(subpath):
    # 1. Real file in dist/ (Vite's public/ outputs land here at build time).
    candidate = DASHBOARD_DIST / subpath
    try:
        if candidate.is_file() and candidate.resolve().is_relative_to(DASHBOARD_DIST.resolve()):
            return send_from_directory(str(DASHBOARD_DIST), subpath)
    except (OSError, ValueError):
        pass
    # 2. Known SPA tab — return index.html for client-side routing.
    head = subpath.split("/", 1)[0]
    if head in SPA_TAB_PATHS:
        return _serve_index()
    # 3. Otherwise: not found.
    from flask import abort
    abort(404)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CyberSentinel UEBA Dashboard API server")
    p.add_argument("--config", default="ueba_config.yaml",
                   help="Path to ueba_config.yaml (default: ueba_config.yaml)")
    p.add_argument("--host", default=None, help="Bind host (overrides config)")
    p.add_argument("--port", type=int, default=None, help="Bind port (overrides config)")
    p.add_argument("--alerts", default=None, help="Path to ueba_alerts.jsonl (overrides config)")
    p.add_argument("--agents-registry", default=None,
                   help="Path to agents.json (overrides config)")
    p.add_argument("--fp-file", default=None,
                   help="Path to false_positives.json (overrides config)")
    p.add_argument("--fp-patterns-file", default=None,
                   help="Path to fp_patterns.json (overrides config)")
    p.add_argument("--debug", action="store_true", help="Run Flask in debug mode")
    return p.parse_args()


def _warm_archive_cache() -> None:
    """Pre-parse archived alert zips within the history window so the first wide
    ('All'/30D/90D) request doesn't block several seconds on a cold cache. Runs
    in a daemon thread; the server starts serving immediately regardless."""
    # Live file FIRST: it backs every default (24h) request and is the one the
    # first post-restart call needs. The live file can be hundreds of MB, so this
    # one-time full parse (subsequent reads are incremental/cheap) must finish
    # before the heavier 95-day archive warm, or the first request pays it.
    try:
        t = time.time()
        n = len(_read_live_alerts())
        print(f"[dashboard] live cache warmed: {n} alerts in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"[dashboard] live cache warm-up failed ({e}) — loading lazily")
    # Then the archives (wide 'All'/30D/90D windows) in the background.
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(CFG.get("history_days", 95) or 95))
        t = time.time()
        n = len(_read_archived_alerts(cutoff))
        print(f"[dashboard] archive cache warmed: {n} alerts in {time.time() - t:.1f}s "
              f"from {CFG.get('archive_dir')}")
    except Exception as e:  # never let warm-up crash startup
        print(f"[dashboard] archive cache warm-up failed ({e}) — loading lazily")

    # Now that the alert caches are hot, seed the endpoint result cache for the
    # windows analysts land on first (All=0 and 24h) so the very first dashboard
    # load after a restart is instant instead of paying the cold aggregation. The
    # background result-warmer then keeps these (and any others viewed) fresh.
    for _h in _STANDARD_WINDOWS:
        _active_windows[(_h, False)] = time.time()
    try:
        t = time.time()
        for (hours, include_fp) in [(h, False) for h in _STANDARD_WINDOWS]:
            for name, builder in list(_ENDPOINT_BUILDERS.items()):
                try:
                    _build_and_store(name, builder, hours, include_fp)
                except Exception:
                    pass
        print(f"[dashboard] result cache pre-warmed ({len(_STANDARD_WINDOWS)} windows) "
              f"in {time.time() - t:.1f}s")
    except Exception as e:
        print(f"[dashboard] result cache pre-warm failed ({e}) — building lazily")


def _start_archive_warm_thread() -> None:
    import threading
    threading.Thread(target=_warm_archive_cache, name="archive-warm", daemon=True).start()


def _start_result_warm_thread() -> None:
    """Keep the endpoint result cache hot for actively-viewed windows so loads
    stay instant (the heavy aggregation runs off the request path)."""
    import threading
    threading.Thread(target=_warm_results_loop, name="result-warm", daemon=True).start()


_notify_dispatcher = None


def _start_notify_dispatcher() -> None:
    """Start the proactive-alerting dispatcher (RFP 15)."""
    global _notify_dispatcher
    if not _notify_ready():
        return
    n = _ncfg()
    try:
        _notify_dispatcher = ueba_notify.Dispatcher(
            ALERTS_FILE, n["rules_file"], n["devices_file"], n["state_file"],
            send_email=_notify_send_email,
            site=CFG.get("site_name") or "CyberSentinel UEBA",
            poll_secs=int(n.get("poll_secs") or 15))
        _notify_dispatcher.start()
        active = [r for r in ueba_notify.rules(n["rules_file"]) if r.get("enabled")]
        print(f"[notify] dispatcher started — {len(active)} active rule(s), "
              f"{len(ueba_notify.devices(n['devices_file']))} device(s) registered")
    except Exception as e:
        # Alerting must never prevent the console from serving.
        print(f"[notify] dispatcher failed to start: {e}")


_report_scheduler = None


def _start_report_scheduler() -> None:
    """Start the periodic-report scheduler (RFP 40), if reporting is enabled."""
    global _report_scheduler
    if not _reports_ready():
        return
    rcfg = _rcfg()
    if not rcfg.get("scheduler_enabled", True):
        print("[reports] scheduler disabled in config — on-demand reports still work")
        return
    try:
        Path(rcfg["output_dir"]).mkdir(parents=True, exist_ok=True)
        _report_scheduler = ueba_report_store.Scheduler(
            rcfg["schedules_file"], _run_schedule)
        _report_scheduler.start()
        n = len(ueba_report_store.schedules(rcfg["schedules_file"]))
        print(f"[reports] scheduler started — {n} schedule(s), "
              f"times are {ueba_report_store.local_tz_label()}")
    except Exception as e:
        # A broken scheduler must never stop the dashboard from serving.
        print(f"[reports] scheduler failed to start: {e}")


def main() -> None:
    global CFG, ALERTS_FILE, AGENTS_REGISTRY, FP_FILE, FP_PATTERNS_FILE, AUDIT_FILE
    global WATCHLIST_FILE
    args = _parse_args()
    CFG = load_dashboard_config(args.config)

    if args.host:             CFG["host"] = args.host
    if args.port:             CFG["port"] = args.port
    if args.alerts:           CFG["alerts_file"] = args.alerts
    if args.agents_registry:  CFG["agents_registry"] = args.agents_registry
    if args.fp_file:          CFG["false_positives_file"] = args.fp_file
    if args.fp_patterns_file: CFG["fp_patterns_file"] = args.fp_patterns_file

    # Auth must be initialised before the first request is served. A bad auth
    # config raises here and stops the server on purpose: running "enforcing but
    # unable to authenticate anyone" is an outage, and running "meant to be
    # enforcing but silently open" is worse.
    global _RAW_CFG
    _RAW_CFG = load_raw_config(args.config) or {}

    auth_status = "module not installed"
    auth_cfg: dict = {}
    if AUTH_MODULE_AVAILABLE:
        raw_cfg = _RAW_CFG
        auth_cfg = ueba_auth.init_auth(app, raw_cfg)
        ready, reason = ueba_auth.is_ready()
        auth_status = (
            f"enabled={auth_cfg.get('enabled')} enforce={auth_cfg.get('enforce')} "
            f"ready={ready} ({reason})"
        )
    cors_status = _configure_cors(auth_cfg)

    ALERTS_FILE       = Path(CFG["alerts_file"])
    AGENTS_REGISTRY   = Path(CFG["agents_registry"])
    FP_FILE           = Path(CFG["false_positives_file"])
    FP_PATTERNS_FILE  = Path(CFG.get("fp_patterns_file") or _DEFAULTS["fp_patterns_file"])
    AUDIT_FILE        = Path(CFG.get("audit_file") or _DEFAULTS["audit_file"])
    WATCHLIST_FILE    = Path(CFG.get("watchlist_file") or _DEFAULTS["watchlist_file"])
    load_fps()
    load_fp_patterns()

    dist_ok = (DASHBOARD_DIST / "index.html").exists()
    print("CyberSentinel UEBA Dashboard")
    print(f"  Config:           {args.config}")
    print(f"  Reading alerts:   {ALERTS_FILE}")
    print(f"  Agents registry:  {AGENTS_REGISTRY}")
    print(f"  False positives:  {FP_FILE}  ({len(_fp_dict)} loaded)")
    print(f"  FP patterns:      {FP_PATTERNS_FILE}  ({len(_fp_patterns)} loaded)")
    print(f"  Dashboard build:  {'dist/ (Vite build)' if dist_ok else 'legacy index.html'}")
    print(f"  AI analyst:       "
          f"{'enabled' if CFG['ai_analyst'].get('enabled') and os.environ.get('ANTHROPIC_API_KEY') else 'fallback only'}")
    if REPORTS_AVAILABLE:
        print(f"  Reporting:        {len(ueba_reports.REPORTS)} built-in reports, "
              f"formats: {', '.join(ueba_report_render.available_formats())}"
              f"{'' if ueba_report_store.smtp_configured(_smtp_cfg()) else '  (email not configured)'}")
    else:
        print("  Reporting:        unavailable (report modules not importable)")
    print(f"  Auth/SSO:         {auth_status}")
    print(f"  CORS:             {cors_status}")
    print(f"  Listening on:     http://{CFG['host']}:{CFG['port']}")
    print(f"  Archive dir:      {CFG.get('archive_dir')}  "
          f"(history {CFG.get('history_days')}d, feed cap {CFG.get('max_feed_alerts')})")
    _start_agent_sync_thread()
    _start_archive_warm_thread()
    _start_result_warm_thread()
    _start_report_scheduler()
    _start_notify_dispatcher()
    # threaded=True: serve requests concurrently so one slow scan (e.g. a wide
    # hours=N feed query over the multi-GB enriched file) can't block every other
    # endpoint and freeze the whole dashboard.
    app.run(host=CFG["host"], port=CFG["port"], debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
