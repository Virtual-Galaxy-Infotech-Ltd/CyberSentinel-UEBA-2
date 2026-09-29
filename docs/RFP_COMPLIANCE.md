# CyberSentinel UEBA — RFP compliance tracker

Status of the RFP points that were **not** compliant at assessment time, with the
reason and a buildability estimate. Kept in the repo deliberately: this table has
already been lost once to a compacted session.

Legend: ✅ shipped · 🔨 buildable, not started · ⛔ blocked on data or scope

## Shipped

| # | Requirement | Shipped |
|---|---|---|
| 1 | Watch lists | `ueba_watchlist.py`, shared by engine + dashboard |
| 10 / 15 | Device registry, proactive alerting | `ueba_notify.py` — rules, throttling, email/webhook |
| 28 | Auto-complete / auto-suggest | `/api/suggest`, per-window vocabulary |
| 34 / 39 | Export Excel / PDF / XML | `ueba_report_render.py`, `dashboard/src/export.js` |
| 35 / 36 / 37 | Out-of-box reports (analyst / admin / audit) | `ueba_reports.py` section catalogue |
| 38 / 40 | Custom + scheduled reports | `ueba_report_store.py` scheduler + SMTP |
| 62 | Threat Report PDF for a period | Falls out of the reporting engine |
| 65 | Audit log of actions inside UEBA | `_audit_mutations` → `ueba_audit.jsonl`, `/api/audit` |
| 23 | Role-based dashboards | `CAPABILITIES` table gates 23 routes; UI hides what the role lacks |

## Remaining — buildable

| # | Requirement | Why not compliant | Estimate |
|---|---|---|---|
| 7 | Device admin, subnet admin | 3 flat roles only; no device/subnet scoping | Medium — scoped RBAC on top of existing roles. 1–2 weeks |
| 70 | Any field as entity | Entity resolution hardcoded to user/host/IP | Medium — config-driven entity mapping. 2–3 weeks |
| 48 | Rules active for a user set until condition/time | No scoped/temporal rule engine | Medium. 2–3 weeks |
| 27 | Natural-language search | Substring match only | Medium — NL→filter translation. **See 67: no cloud LLM on customer installs** |
| 29 | Netflow ingestion | No netflow support | Medium — new collector + feature set. 3–4 weeks |
| 60 | Search with app-layer protocol decode | Not implemented | Partly — limited by what the SIEM sends; we only see enriched events |

## Remaining — blocked or out of scope

| # | Requirement | Position |
|---|---|---|
| 21 | Supervised ML | Needs labelled incident data that does not exist. Real R&D, months, and depends on analysts labelling |
| 44 | Peer-group deviation | Needs cohort definition (dept/role) from AD/HR data we don't have. 4–6 weeks once data exists |
| 32 | HA / no SPOF | Single Flask process, single engine, SQLite. Needs Postgres + leader election — 2–3 months re-architecture |
| 46 | Misuse by sequence of actions | Sequence models (LSTM/Markov) are a new detection class. Months |
| 47 | Sensitive data leakage via HTTP param manipulation | Wrong product — belongs to DLP/WAF, not UEBA |
| 69 | Profile all AD users from day 1 | AD import is easy; "day 1 profiling" is physically impossible — behavioural baselines need 3–7 days of history. Needs bid language, not code |

## How RBAC works (point 23)

`CAPABILITIES` in `ueba_dashboard_server.py` maps a capability to a minimum role,
and is the single source of truth for both halves:

* **Server** — `@_require_cap("watchlist.edit")` wraps all 23 mutating routes plus
  `/api/audit`. This is the real gate; it returns 401/403 regardless of the UI.
* **Browser** — `/api/auth/capabilities` returns `{capability: allowed}`, and
  `dashboard/src/ui/capabilities.js` turns each denial into a `nocap-*` class on
  `<body>`. CSS then hides `[data-cap="…"]`, which covers rows rendered after
  load without re-running a DOM pass.

Tiers: **viewer** reads (export included — it reformats data already on screen and
changes no state); **analyst** triages (watch lists, false positives, generating
reports); **admin** configures (devices, notification rules, scheduled email
delivery, and the audit trail of everyone else's actions).

Every gate is a **no-op while `auth.enforce` is false**, which is where the system
sits today — so this changed nothing for current users. It begins enforcing the
moment that flag is turned on, which is also the point at which SSO must be
working, or analysts are locked out.

## Standing constraint

Point 67: `ai_analyst` must stay **disabled** on customer installs. Any work on 27
must therefore avoid a cloud LLM dependency, or ship as an opt-in a customer
explicitly enables.
