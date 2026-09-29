#!/usr/bin/env python3
"""
Report engine — out-of-the-box, custom and scheduled reports.

Covers RFP points 34-40 and 62:

    34  export / report generation (Excel, PDF, XML)
    35  out-of-the-box reports for ANALYSTS (investigation decisions)
    36  out-of-the-box reports for ADMINISTRATION AND MANAGEMENT
    37  out-of-the-box reports for AUDIT AND COMPLIANCE
    38  custom reports, and the ability to schedule them
    39  delivery as CSV, Email, PDF
    40  scheduling at periodic intervals
    62  threat report (PDF) for a specified period

DESIGN
------
Everything is built around ONE renderer-agnostic document:

    {title, subtitle, generated_at, window, sections: [...]}

A section is one of a small set of kinds — metrics / table / bars / text — and
nothing in this module knows what a PDF is. ueba_report_render.py turns that
document into PDF, Excel, CSV, HTML or JSON. Adding a sixth output format means
writing one renderer, not touching any report.

The second idea is that a report is just an ORDERED LIST OF SECTION KEYS. The
four out-of-the-box reports below are each ~8 lines of declaration over the
shared SECTIONS catalogue. That is also what makes point 38 (custom reports)
nearly free: a custom report is an analyst-chosen list of the same keys, so it
needs no new rendering, no new queries, and cannot drift from the built-in
reports as they improve.

This module deliberately does NOT import the dashboard. It receives a plain
`ctx` dict of already-loaded data, which keeps it unit-testable without a Flask
app, a model, or a running pipeline behind it.
"""
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

SCHEMA_VERSION = 1


# ── Alert field accessors ───────────────────────────────────────────────────
# Alerts reach us in two shapes: the full engine record, and the compact "slim"
# projection the dashboard caches. Every accessor below tolerates both, because
# which one arrives depends on whether the window came from cache — a detail no
# report should have to care about.

def _ueba(a):  return a.get("ueba") or {}
def _sec(a):   return a.get("security") or {}
def a_host(a):  return (a.get("host") or {}).get("name") or ""


def a_user(a):
    u = a.get("__user")
    if u:
        return u
    subj = a.get("subject") or {}
    return subj.get("name") or (a.get("data") or {}).get("srcuser") or "unknown"


def a_verdict(a):   return _ueba(a).get("risk_verdict") or "unknown"
def a_score(a):
    try:
        return float(_ueba(a).get("combined_score") or 0.0)
    except (TypeError, ValueError):
        return 0.0
def a_campaign(a):  return _ueba(a).get("campaign_id")
def a_reasons(a):   return _ueba(a).get("anomaly_reasons") or []
def a_watchlist(a): return _ueba(a).get("watchlist")
def a_signature(a): return _sec(a).get("signature") or ""
def a_sig_id(a):    return _sec(a).get("signature_id") or ""
def a_severity(a):  return _sec(a).get("severity")


def a_tactics(a):
    t = a.get("__mitre_tactic")
    if t:
        return t if isinstance(t, list) else [t]
    rule = ((a.get("context") or {}).get("raw_event") or {}).get("rule") or {}
    t = (rule.get("mitre") or {}).get("tactic") or []
    return t if isinstance(t, list) else [t]


def a_time(a):
    """Best available timestamp as an aware datetime, or None."""
    for k in ("processed_at",):
        v = _ueba(a).get(k)
        if v:
            d = _parse(v)
            if d:
                return d
    return _parse(a.get("event_time"))


def _parse(v):
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _pct(n, total):
    return f"{(100.0 * n / total):.1f}%" if total else "—"


def _fmt_dt(d):
    return d.strftime("%Y-%m-%d %H:%M UTC") if isinstance(d, datetime) else "—"


# ── Section constructors ────────────────────────────────────────────────────

def metrics(title, items, note=None):
    return {"kind": "metrics", "title": title, "items": items, "note": note}


def table(title, columns, rows, note=None):
    return {"kind": "table", "title": title, "columns": columns,
            "rows": rows, "note": note}


def bars(title, items, note=None):
    """items: [{"label":..., "value": <number>}] — rendered as a bar chart in
    PDF/HTML and as a plain two-column table everywhere else."""
    return {"kind": "bars", "title": title, "items": items, "note": note}


def text(title, body):
    return {"kind": "text", "title": title, "body": body}


# ── Section builders ────────────────────────────────────────────────────────
# Each takes the context and returns a section dict, or None to omit itself when
# it has nothing to say. Returning None rather than an empty table matters: a
# report padded with empty sections reads as a broken report.

def _sec_summary(ctx):
    alerts = ctx["alerts"]
    total = len(alerts)
    counts = Counter(a_verdict(a) for a in alerts)
    users = {a_user(a) for a in alerts}
    hosts = {a_host(a) for a in alerts if a_host(a)}
    camps = {a_campaign(a) for a in alerts if a_campaign(a)}
    hours = ctx["hours"] or 0
    rate = (total / hours) if hours else 0

    items = [
        {"label": "Total alerts",      "value": f"{total:,}"},
        {"label": "Highly anomalous",  "value": f"{counts.get('highly_anomalous', 0):,}",
         "note": _pct(counts.get("highly_anomalous", 0), total)},
        {"label": "Anomalous",         "value": f"{counts.get('anomalous', 0):,}",
         "note": _pct(counts.get("anomalous", 0), total)},
        {"label": "Suspicious",        "value": f"{counts.get('suspicious', 0):,}",
         "note": _pct(counts.get("suspicious", 0), total)},
        {"label": "Entities involved", "value": f"{len(users):,}"},
        {"label": "Hosts involved",    "value": f"{len(hosts):,}"},
        {"label": "Campaigns",         "value": f"{len(camps):,}"},
    ]
    if hours:
        items.append({"label": "Mean alert rate", "value": f"{rate:.1f}/hour"})
    return metrics("Summary", items)


def _sec_verdict_breakdown(ctx):
    counts = Counter(a_verdict(a) for a in ctx["alerts"])
    if not counts:
        return None
    order = ["highly_anomalous", "anomalous", "suspicious"]
    items = [{"label": k.replace("_", " ").title(), "value": counts.get(k, 0)}
             for k in order if counts.get(k)]
    for k, v in counts.items():
        if k not in order:
            items.append({"label": k.replace("_", " ").title(), "value": v})
    return bars("Alerts by verdict", items)


def _sec_top_users(ctx, limit=15):
    agg = defaultdict(lambda: {"n": 0, "max": 0.0, "high": 0, "hosts": set(), "last": None})
    for a in ctx["alerts"]:
        u = agg[a_user(a)]
        u["n"] += 1
        u["max"] = max(u["max"], a_score(a))
        if a_verdict(a) == "highly_anomalous":
            u["high"] += 1
        h = a_host(a)
        if h:
            u["hosts"].add(h)
        t = a_time(a)
        if t and (u["last"] is None or t > u["last"]):
            u["last"] = t
    if not agg:
        return None
    # Rank by highly-anomalous count first: an entity with 3 severe alerts
    # deserves an analyst's attention ahead of one with 3,000 routine ones.
    top = sorted(agg.items(), key=lambda kv: (kv[1]["high"], kv[1]["max"], kv[1]["n"]),
                 reverse=True)[:limit]
    rows = [[u, f"{d['n']:,}", d["high"], f"{d['max']:.3f}",
             ", ".join(sorted(d["hosts"])[:3]) or "—", _fmt_dt(d["last"])]
            for u, d in top]
    return table("Top entities by risk",
                 ["Entity", "Alerts", "Highly anom.", "Max score", "Hosts", "Last seen"],
                 rows,
                 note="Ranked by count of highly-anomalous alerts, then peak score.")


def _sec_top_hosts(ctx, limit=15):
    agg = defaultdict(lambda: {"n": 0, "high": 0, "users": set()})
    for a in ctx["alerts"]:
        h = a_host(a)
        if not h:
            continue
        d = agg[h]
        d["n"] += 1
        if a_verdict(a) == "highly_anomalous":
            d["high"] += 1
        d["users"].add(a_user(a))
    if not agg:
        return None
    top = sorted(agg.items(), key=lambda kv: (kv[1]["high"], kv[1]["n"]), reverse=True)[:limit]
    rows = [[h, f"{d['n']:,}", d["high"], f"{len(d['users']):,}"] for h, d in top]
    return table("Top hosts", ["Host", "Alerts", "Highly anom.", "Distinct entities"], rows)


def _sec_top_signatures(ctx, limit=15):
    c = Counter()
    ids = {}
    for a in ctx["alerts"]:
        s = a_signature(a)
        if not s:
            continue
        c[s] += 1
        ids.setdefault(s, a_sig_id(a))
    if not c:
        return None
    rows = [[s[:90], ids.get(s, "—"), f"{n:,}", _pct(n, len(ctx["alerts"]))]
            for s, n in c.most_common(limit)]
    return table("Top rule signatures", ["Signature", "Rule ID", "Alerts", "Share"], rows)


def _sec_mitre(ctx, limit=12):
    c = Counter()
    for a in ctx["alerts"]:
        for t in a_tactics(a):
            if t:
                c[str(t)] += 1
    if not c:
        return None
    return bars("MITRE ATT&CK tactics",
                [{"label": k, "value": v} for k, v in c.most_common(limit)],
                note="Counts alerts whose originating rule carries a MITRE tactic; "
                     "an alert with several tactics is counted under each.")


def _sec_top_reasons(ctx, limit=10):
    c = Counter()
    for a in ctx["alerts"]:
        for r in a_reasons(a):
            c[str(r)] += 1
    if not c:
        return None
    rows = [[r.replace("_", " "), f"{n:,}", _pct(n, len(ctx["alerts"]))]
            for r, n in c.most_common(limit)]
    return table("Why alerts fired", ["Anomaly reason", "Alerts", "Share"], rows)


def _sec_campaigns(ctx, limit=15):
    camps = ctx.get("campaigns") or []
    if not camps:
        return None
    rows = []
    for c in camps[:limit]:
        rows.append([
            c.get("campaign_id", "—"),
            f"{c.get('alert_count', 0):,}",
            c.get("highly_anomalous", 0),
            f"{len(c.get('users') or []):,}",
            f"{len(c.get('hosts') or []):,}",
            _fmt_dt(_parse(c.get("first_seen"))),
        ])
    return table("Correlated campaigns",
                 ["Campaign", "Alerts", "Highly anom.", "Entities", "Hosts", "First seen"],
                 rows,
                 note="Campaigns are clusters of related anomalies found by HDBSCAN, "
                      "not rule-based correlations.")


def _sec_highly_anomalous(ctx, limit=40):
    sev = [a for a in ctx["alerts"] if a_verdict(a) == "highly_anomalous"]
    if not sev:
        return None
    sev.sort(key=lambda a: (a_score(a), a_time(a) or datetime.min.replace(tzinfo=timezone.utc)),
             reverse=True)
    rows = [[_fmt_dt(a_time(a)), a_user(a), a_host(a) or "—", f"{a_score(a):.3f}",
             a_signature(a)[:70] or "—", a_campaign(a) or "—"]
            for a in sev[:limit]]
    note = f"Showing the {len(rows)} highest-scoring of {len(sev):,} highly-anomalous alerts."
    return table("Highly anomalous alerts",
                 ["Time", "Entity", "Host", "Score", "Signature", "Campaign"], rows, note)


def _sec_watchlist_hits(ctx, limit=30):
    hits = [a for a in ctx["alerts"] if a_watchlist(a)]
    if not hits:
        wl = ctx.get("watchlist") or []
        if not wl:
            return None
        return text("Watch list",
                    f"{len(wl)} entit{'y is' if len(wl) == 1 else 'ies are'} on the watch "
                    "list, but none generated alerts in this period.")
    hits.sort(key=a_score, reverse=True)
    rows = []
    for a in hits[:limit]:
        w = a_watchlist(a) or {}
        rows.append([_fmt_dt(a_time(a)), f"{w.get('type', '')}:{w.get('value', '')}",
                     f"{a_score(a):.3f}", str(_ueba(a).get("model_score", "—")),
                     a_verdict(a).replace("_", " "), (w.get("reason") or "—")[:40]])
    return table("Watch-list activity",
                 ["Time", "Watched entity", "Score", "Model score", "Verdict", "Why watched"],
                 rows,
                 note="'Score' includes the watch-list boost; 'Model score' is what the "
                      "models produced on their own.")


def _sec_alert_timeline(ctx):
    alerts = ctx["alerts"]
    if not alerts:
        return None
    hours = ctx["hours"] or 24
    # Bucket width chosen so the chart stays legible whatever the window.
    if hours <= 48:
        width, label = timedelta(hours=1), "hour"
    elif hours <= 24 * 14:
        width, label = timedelta(hours=6), "6 hours"
    else:
        width, label = timedelta(days=1), "day"
    buckets = Counter()
    for a in alerts:
        t = a_time(a)
        if not t:
            continue
        epoch = int(t.timestamp() // width.total_seconds())
        buckets[epoch] += 1
    if not buckets:
        return None
    items = []
    for e in sorted(buckets)[-30:]:
        when = datetime.fromtimestamp(e * width.total_seconds(), tz=timezone.utc)
        fmt = "%d %b" if width >= timedelta(days=1) else "%d %b %H:%M"
        items.append({"label": when.strftime(fmt), "value": buckets[e]})
    return bars(f"Alert volume (per {label})", items)


def _sec_coverage(ctx, limit=25):
    agents = ctx.get("agents") or []
    if not agents:
        return None
    rows = []
    for g in agents[:limit]:
        rows.append([g.get("agent", "—"), g.get("ip") or "—",
                     f"{g.get('alert_count', 0):,}", g.get("highly_anomalous", 0),
                     _fmt_dt(_parse(g.get("last_seen")))])
    return table("Monitored endpoints",
                 ["Agent", "IP", "Alerts", "Highly anom.", "Last seen"], rows,
                 note=f"{len(agents)} agent(s) reported activity in this period.")


def _sec_fp_activity(ctx):
    fp_count = ctx.get("fp_count") or 0
    pats = ctx.get("fp_patterns") or []
    total = len(ctx["alerts"])
    items = [
        {"label": "Alerts suppressed as false positives", "value": f"{fp_count:,}"},
        {"label": "Active suppression patterns", "value": f"{len(pats):,}"},
        {"label": "Alerts shown after suppression", "value": f"{total:,}"},
    ]
    if fp_count:
        items.append({"label": "Suppression rate", "value": _pct(fp_count, fp_count + total),
                      "note": "share of raw alerts removed before analysts saw them"})
    return metrics("False-positive suppression", items,
                   note="A high suppression rate is normal and healthy; it is how tuning "
                        "shows up. A sudden change in it is the thing worth investigating.")


def _sec_analyst_actions(ctx, limit=60):
    """Point 37 — who did what inside the product. Reads the audit trail."""
    entries = ctx.get("audit") or []
    if not entries:
        return text("Analyst actions",
                    "No state-changing actions were recorded in this period.")
    rows = []
    for e in entries[:limit]:
        detail = e.get("detail") or {}
        summary = ", ".join(f"{k}={v}" for k, v in detail.items())[:60] or "—"
        rows.append([_fmt_dt(_parse(e.get("ts"))), e.get("user") or "(unauthenticated)",
                     e.get("ip") or "—", e.get("action", "—")[:50],
                     "ok" if e.get("ok") else f"FAILED ({e.get('status')})", summary])
    note = f"{len(entries):,} action(s) recorded"
    if len(entries) > limit:
        note += f"; showing the {limit} most recent"
    return table("Analyst actions (audit trail)",
                 ["Time", "User", "From", "Action", "Result", "Detail"], rows, note + ".")


def _normalise_action(action):
    """Collapse record ids out of an audited path so actions group by ROUTE.

    Without this, "actions by type" counts DELETE /api/false-positive/<event-id>
    as a distinct kind of action per event — a chart of several hundred
    one-count rows that tells an auditor nothing. Any path segment containing a
    digit, or longer than a route word plausibly is, becomes :id.
    """
    method, _, path = str(action or "").partition(" ")
    out = []
    for seg in path.split("?")[0].split("/"):
        if not seg:
            continue
        out.append(":id" if (re.search(r"\d", seg) or len(seg) > 24) else seg)
    return f"{method} /" + "/".join(out) if out else (method or "?")


def _sec_audit_summary(ctx):
    entries = ctx.get("audit") or []
    by_action = Counter(_normalise_action(e.get("action", "?")) for e in entries)
    failed = sum(1 for e in entries if not e.get("ok"))
    actors = {e.get("user") for e in entries if e.get("user")}
    anon = sum(1 for e in entries if not e.get("user"))
    items = [
        {"label": "Recorded actions", "value": f"{len(entries):,}"},
        {"label": "Distinct authenticated users", "value": f"{len(actors):,}"},
        {"label": "Unattributed actions", "value": f"{anon:,}",
         "note": "no authenticated session; recorded by source IP"},
        {"label": "Rejected attempts", "value": f"{failed:,}"},
    ]
    secs = [metrics("Audit summary", items)]
    if by_action:
        secs.append(bars("Actions by type",
                         [{"label": k, "value": v} for k, v in by_action.most_common(10)]))
    return secs


def _sec_watchlist_config(ctx):
    wl = ctx.get("watchlist") or []
    if not wl:
        return text("Watch list", "No entities are currently on the watch list.")
    rows = [[w.get("type", "—"), w.get("value", "—"), (w.get("reason") or "—")[:50],
             f"+{float(w.get('boost') or 0):.2f}", w.get("added_by") or "—",
             _fmt_dt(_parse(w.get("added_at")))]
            for w in wl]
    return table("Watch list (current)",
                 ["Type", "Entity", "Reason", "Boost", "Added by", "Added"], rows)


def _sec_system_health(ctx):
    """Whatever the caller put in ctx['health'], rendered as-is.

    Kept deliberately schema-free: the set of health figures worth reporting
    changes as the platform grows, and a rigid key list here would mean every
    new one silently failing to appear in reports until someone noticed.
    """
    h = ctx.get("health") or {}
    if not h:
        return None
    items = [{"label": str(k).replace("_", " ").capitalize(),
              "value": f"{v:,}" if isinstance(v, int) else str(v)}
             for k, v in h.items() if v is not None]
    return metrics("System health", items) if items else None


def _sec_retention(ctx):
    r = ctx.get("retention") or {}
    if not r:
        return None
    items = [{"label": k.replace("_", " ").capitalize(), "value": str(v)}
             for k, v in r.items()]
    return metrics("Data retention", items,
                   note="Retention is enforced by the weekly retrain job, which prunes the "
                        "training corpus to the configured rolling window.")


def _sec_geo(ctx, limit=15):
    geo = ctx.get("geo") or []
    if not geo:
        return None
    c = Counter()
    for g in geo:
        country = g.get("src_country") or g.get("country") or ""
        if country:
            c[country] += 1
    if not c:
        return None
    return bars("External traffic by source country",
                [{"label": k, "value": v} for k, v in c.most_common(limit)],
                note="Derived from firewall events with an external source IP, geolocated "
                     "against a local MaxMind database.")


def _sec_scope_note(ctx):
    w = ctx["window"]
    lines = [
        f"Period covered: {_fmt_dt(w['from'])} to {_fmt_dt(w['to'])}"
        f" ({ctx['hours']} hours)." if ctx["hours"] else
        f"Period covered: all retained data, up to {_fmt_dt(w['to'])}.",
        "",
        "Alerts that analysts marked as false positives, or that match an active "
        "suppression pattern, are excluded from every figure in this report.",
    ]
    if ctx.get("capped"):
        lines.append("")
        lines.append(
            f"NOTE: this window exceeded the {ctx.get('cap'):,}-alert load cap, so the "
            "figures describe the most recent alerts within the period rather than all "
            "of them."
        )
    return text("Scope", "\n".join(lines))


# ── Section catalogue ───────────────────────────────────────────────────────
# The keys are the public vocabulary for custom reports (point 38).

SECTIONS = {
    "scope":              _sec_scope_note,
    "summary":            _sec_summary,
    "verdict_breakdown":  _sec_verdict_breakdown,
    "alert_timeline":     _sec_alert_timeline,
    "top_users":          _sec_top_users,
    "top_hosts":          _sec_top_hosts,
    "top_signatures":     _sec_top_signatures,
    "top_reasons":        _sec_top_reasons,
    "mitre_tactics":      _sec_mitre,
    "campaigns":          _sec_campaigns,
    "highly_anomalous":   _sec_highly_anomalous,
    "watchlist_hits":     _sec_watchlist_hits,
    "watchlist_config":   _sec_watchlist_config,
    "coverage":           _sec_coverage,
    "fp_activity":        _sec_fp_activity,
    "analyst_actions":    _sec_analyst_actions,
    "audit_summary":      _sec_audit_summary,
    "system_health":      _sec_system_health,
    "retention":          _sec_retention,
    "geo_origins":        _sec_geo,
}

# Human-facing labels, used by the UI's custom-report builder.
SECTION_LABELS = {
    "scope":             "Scope and period",
    "summary":           "Summary metrics",
    "verdict_breakdown": "Alerts by verdict",
    "alert_timeline":    "Alert volume over time",
    "top_users":         "Top entities by risk",
    "top_hosts":         "Top hosts",
    "top_signatures":    "Top rule signatures",
    "top_reasons":       "Why alerts fired",
    "mitre_tactics":     "MITRE ATT&CK tactics",
    "campaigns":         "Correlated campaigns",
    "highly_anomalous":  "Highly anomalous alerts",
    "watchlist_hits":    "Watch-list activity",
    "watchlist_config":  "Watch list (current)",
    "coverage":          "Monitored endpoints",
    "fp_activity":       "False-positive suppression",
    "analyst_actions":   "Analyst actions (audit trail)",
    "audit_summary":     "Audit summary",
    "system_health":     "System health",
    "retention":         "Data retention",
    "geo_origins":       "External traffic by country",
}


# ── Out-of-the-box reports ──────────────────────────────────────────────────
# Points 35, 36, 37 and 62. Each is an audience, a purpose, and an ordered list
# of section keys — nothing more.

REPORTS = {
    # 35 — for analysts making investigation decisions.
    "analyst_investigation": {
        "title":    "Analyst Investigation Report",
        "audience": "SOC analysts",
        "purpose":  "Which entities to look at next, and what they did.",
        "rfp":      "35",
        "sections": ["scope", "summary", "top_users", "highly_anomalous",
                     "watchlist_hits", "campaigns", "top_signatures",
                     "top_reasons", "mitre_tactics", "alert_timeline"],
    },
    # 36 — for administration and management.
    "admin_management": {
        "title":    "Administration & Management Report",
        "audience": "SOC management",
        "purpose":  "Operational posture, coverage and workload over the period.",
        "rfp":      "36",
        "sections": ["scope", "summary", "verdict_breakdown", "alert_timeline",
                     "coverage", "top_hosts", "fp_activity", "system_health",
                     "retention"],
    },
    # 37 — for audit and compliance.
    "audit_compliance": {
        "title":    "Audit & Compliance Report",
        "audience": "Audit and compliance",
        "purpose":  "Who did what inside the platform, and how it is configured.",
        "rfp":      "37",
        "sections": ["scope", "audit_summary", "analyst_actions", "fp_activity",
                     "watchlist_config", "retention", "system_health"],
    },
    # 62 — threat report for a specified period.
    "threat_report": {
        "title":    "Threat Report",
        "audience": "SOC and stakeholders",
        "purpose":  "The threat picture for a specified period.",
        "rfp":      "62",
        "sections": ["scope", "summary", "verdict_breakdown", "alert_timeline",
                     "mitre_tactics", "geo_origins", "highly_anomalous",
                     "campaigns", "top_users", "top_signatures"],
    },
}


def catalogue():
    """What the UI needs to offer reports and build custom ones."""
    return {
        "reports": [
            {"id": k, "title": v["title"], "audience": v["audience"],
             "purpose": v["purpose"], "rfp": v["rfp"], "sections": v["sections"]}
            for k, v in REPORTS.items()
        ],
        "sections": [{"id": k, "label": SECTION_LABELS.get(k, k)} for k in SECTIONS],
        "formats": ["pdf", "xlsx", "csv", "html", "json", "xml"],
    }


# ── Build ───────────────────────────────────────────────────────────────────

def build_report(report_id, ctx, *, sections=None, title=None, subtitle=None):
    """Assemble a report document.

    `report_id` names a built-in report, or is a custom id when `sections` is
    given explicitly. Unknown section keys are skipped rather than raising: a
    saved custom report should survive this module dropping a section in a later
    version, with the rest of the report still delivered.
    """
    spec = REPORTS.get(report_id)
    keys = sections if sections is not None else (spec or {}).get("sections") or []

    built = []
    for key in keys:
        fn = SECTIONS.get(key)
        if fn is None:
            continue
        try:
            out = fn(ctx)
        except Exception as e:                     # one bad section ≠ no report
            out = text(SECTION_LABELS.get(key, key),
                       f"This section could not be generated: {e}")
        if out is None:
            continue
        built.extend(out if isinstance(out, list) else [out])

    w = ctx["window"]
    return {
        "schema":       SCHEMA_VERSION,
        "report_id":    report_id,
        "title":        title or (spec or {}).get("title") or "UEBA Report",
        "subtitle":     subtitle or (spec or {}).get("purpose") or "",
        "audience":     (spec or {}).get("audience") or "",
        "rfp":          (spec or {}).get("rfp") or "",
        "generated_at": ctx.get("generated_at") or datetime.now(timezone.utc).isoformat(),
        "generated_by": ctx.get("generated_by"),
        "site":         ctx.get("site") or "CyberSentinel UEBA",
        "window": {
            "hours": ctx["hours"],
            "from":  w["from"].isoformat() if w.get("from") else None,
            "to":    w["to"].isoformat() if w.get("to") else None,
            "label": window_label(ctx["hours"]),
        },
        "sections":     built,
    }


def window_label(hours):
    if not hours:
        return "All retained data"
    if hours < 48:
        return f"Last {hours} hours"
    days = hours / 24
    if days < 14:
        return f"Last {days:.0f} days"
    if days < 60:
        return f"Last {days / 7:.0f} weeks"
    return f"Last {days / 30:.0f} months"
