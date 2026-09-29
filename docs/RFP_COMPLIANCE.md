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

## Remaining — buildable

| # | Requirement | Why not compliant | Estimate |
|---|---|---|---|
| 23 | Role-based dashboards | Roles exist; every role sees the same UI | Easy/medium — gate panels by role. ~1 week |
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

## Standing constraint

Point 67: `ai_analyst` must stay **disabled** on customer installs. Any work on 27
must therefore avoid a cloud LLM dependency, or ship as an opt-in a customer
explicitly enables.
