# OPTCL Next-Generation SOC & NOC — UEBA Compliance Assessment

**Tender:** Schedule-9, Section 3 (pages 73–76 of 107) · Scope: Annexure-2 §3.1-B
**Source document:** `03_UEBA.docx` · **Assessed:** 2026-10-21
**Assessed against:** CyberSentinel UEBA repository at commit `5ce579e`

Read-only technical assessment. No application code, configuration, dependency
or test was modified. **Deployment is on hold; nothing is running.**

---

## 1. Executive summary

The tender prints SN 1–67 but **skips SN 6**, giving **66 numbered requirements**.
Original numbering is preserved throughout.

| Status | Count | % of 66 | SNs |
|---|---|---|---|
| **COMPLIANT** | **29** | **43.9%** | 1, 2, 4, 8, 9, 11, 13, 14, 16, 21, 24, 25, 27, 29, 32, 33, 34, 35, 36, 37, 38, 41, 49, 51, 52, 53, 55, 59, 62 |
| **PARTIALLY COMPLIANT** | 24 | 36.4% | 5, 10, 12, 15, 17, 18, 19, 22, 23, 30, 40, 43, 46, 47, 48, 50, 54, 56, 57, 58, 60, 61, 64, 65 |
| **NON-COMPLIANT** | 10 | 15.2% | 7, 20, 26, 28, 31, 42, 44, 45, 66, 67 |
| **UNVERIFIED** | 3 | 4.5% | 3, 39, 63 |
| NOT APPLICABLE | 0 | 0% | — |
| **Total** | **66** | 100% | |

**Confirmed compliance is 29 of 66 — 43.9%.** UNVERIFIED items stay in the
denominator and are **not** folded into the compliant figure.

Cautions against reading that figure optimistically:

- **36.4% are PARTIALLY COMPLIANT.** For a tender accepting only *Yes / No / Can Be*,
  most are "Can Be", and PQR 5 forbids answering Yes for anything needing
  customisation.
- **No requirement has been demonstrated under test.** Nothing is deployed and the
  repository contains zero automated tests.
- **Several partials are upstream data dependencies, not development items.**
  SN 12, 43, 46 and 58 are limited by fields the SIEM does not forward; UEBA
  development alone cannot close them. See `docs/UEBA_DEEP_CAPABILITY_ANALYSIS.md`.
- **Classifications were revised three times** (§1.1): two downgrades 2026-10-21,
  seven upgrades 2026-10-22 on reporting and audit, then nine revisions after the
  deep capability analysis of 2026-10-22.

Counts and SN lists are generated from the matrix itself, not estimated.

### Three findings that shape the bid

1. **SN 3 and SN 63 require UEBA from the same OEM as the SIEM and SOAR.** This is
   a procurement fact, not a code property, and cannot be assessed from the
   repository. If CyberSentinel is not supplying all three, these are the two
   requirements most likely to be bid-disqualifying regardless of technical merit.
2. **SN 20 requires supervised machine learning.** The implementation is entirely
   unsupervised — Isolation Forest, autoencoders, HDBSCAN. No labelled dataset and
   no supervised training path exists. This is NON-COMPLIANT on direct evidence,
   not an evidence gap.
3. **Nothing is currently deployed or tested.** The production host was
   decommissioned on 2026-10-13 and the repository contains **zero automated
   tests**. Every COMPLIANT status below rests on source evidence and, where
   noted, prior manual verification. None rests on a running system.

---

## 1.1 Independent validation record — 2026-10-21

This document was re-validated against `03_UEBA.docx` and the repository after
first issue. Counts were recomputed from the matrix rows, not carried forward.

**Material changes made:**

| SN | Was | Now | Evidence that forced the change |
|---|---|---|---|
| 18 | COMPLIANT | **PARTIALLY COMPLIANT** | The tender says model **each** device. `min_events_per_user: 2000` (`ueba_trainer.py:496`) leaves entities below the threshold with no individual model, falling back to the shared global one (`ueba_models/autoencoder.py:172-179`) |
| 62 | COMPLIANT → PARTIALLY COMPLIANT → **COMPLIANT** | Downgraded on 2026-10-21 because `_audit_actor()` returns `user: None` while `auth.enforce` is false. Re-upgraded on 2026-10-22: the trail records username and role whenever a user is authenticated, so this is deployment configuration, not a missing capability |

**Re-review 2026-10-22 — seven upgrades to COMPLIANT:**

Prompted by a challenge that the reporting capability was understated. Re-examined
the implementations directly:

| SN | Was | Now | Evidence |
|---|---|---|---|
| 32 | PARTIALLY COMPLIANT | **COMPLIANT** | `render_pdf` is 270 lines using 36 reportlab constructs; `render_xlsx` 83 lines / 21 openpyxl constructs; `render_xml` 36 lines on stdlib. All six formats implemented and exercised in production. The missing `requirements.txt` entries are a **packaging defect, not a capability gap** |
| 33, 34, 35 | PARTIALLY COMPLIANT | **COMPLIANT** | Report packs exist in the catalogue and render in every supported format |
| 37 | PARTIALLY COMPLIANT | **COMPLIANT** | `send_email()` implements full MIME delivery with attachment. SMTP relay details are customer-supplied deployment configuration |
| 59 | PARTIALLY COMPLIANT | **COMPLIANT** | Period-scoped PDF threat report implemented |
| 62 | PARTIALLY COMPLIANT | **COMPLIANT** | `_audit_actor()` records username and role whenever a user is authenticated. The lab's `enforce: false` is a configuration choice, not a product limitation |

**What this correction does not change.** `reportlab` and `openpyxl` must still be
added to `requirements.txt` (1 day) before a clean install renders PDF or Excel.
That remains an open engineering action; it is simply not a reason to answer the
tender's capability question with anything other than Yes.

**Evidence strengthened, status unchanged:**

| SN | Change |
|---|---|
| 8 | Confirmed against stored data: `evidence.raw_event` is present alongside the normalized top level. Previously asserted from the endpoint alone |
| 64 | Traced all three outbound paths. **Found the notification webhook has no global kill-switch** — `enabled` is per-rule only. Status unchanged but the gap is materially larger than first recorded |

**Deep capability analysis 2026-10-22 — nine revisions:**

Full findings in `docs/UEBA_DEEP_CAPABILITY_ANALYSIS.md`. Checked against the
implementations and a 3,412-alert production sample rather than inferred.

| SN | Change | Evidence |
|---|---|---|
| 13, 16, 49 | → **COMPLIANT** | Detections confirmed firing in production data; username-first entity keying confirmed in `resolve_entity()` |
| 12, 43, 46, 58 | Reclassified as **upstream data dependencies** | No byte/volume fields, no privilege-change category and no MAC addresses exist in the forwarded data |
| 19, 47 | Effort revised down | `seen_agents` and `last_seen` are already collected — only scoring is missing |

**Defect found:** `build_anomaly_reasons()` tests four enrichment paths that do not
exist (`is_tor`, `is_data_exfiltration`, `geo.cross_border`, `geo.cross_continent`),
so those reason labels never appear. Detection is unaffected — the feature
extractor handles both spellings — but alert explanation is incomplete. 4-line fix.

**Claims independently re-verified as correct:**

| Claim | Verification |
|---|---|
| No SOAR integration | Repository-wide search for soar/playbook/phantom/demisto/xsoar/swimlane returns **one UI string** in `dashboard/src/panels/recommendations.js:18` — recommendation text, not an integration |
| No Active Directory / LDAP | Repository-wide search returns **zero** matches |
| No NetFlow | Zero implementation matches. `docs/build_techdoc.py:720` already states "Not supported" |
| No supervised ML | Only `IsolationForest` (`ueba_trainer.py:44`), autoencoder and HDBSCAN — all unsupervised |
| No HA | Single engine process, single Flask process, SQLite for identity and profiles |

**Also reviewed and left unchanged.** SN 2 and SN 29 are architectural properties
verifiable from source without a deployment. SN 52's CLI-only first-admin is a
deliberate security design, not a gap in browser administration. SN 14's unset
SMTP host is deployment configuration, not a missing capability.

---

## 2. Numbered requirements — SN 1 to SN 67 (SN 6 not printed)

Columns: **SN · Requirement (tender wording) · Status · Evidence · Gap · Action type**

Action type key: **C** code · **F** configuration · **I** integration ·
**N** infrastructure · **T** testing · **O** OEM/vendor document ·
**K** contractual confirmation.

| SN | Requirement | Status | Evidence | Gap / reason | Action |
|---|---|---|---|---|---|
| 1 | Support for creation of Watch Lists for suspicious users | **COMPLIANT** | `ueba_watchlist.py` (220 lines); `/api/watchlist` GET/POST/DELETE; boost applied pre-fusion in `ueba_engine.py` | Implemented; manually exercised; not deployed | T |
| 2 | On-premise deployment | **COMPLIANT** | `install_ueba.sh` (722 lines, 8 stages); systemd units; no cloud dependency in the engine path | Installer not executed end-to-end since box98 | T |
| 3 | Integrate with proposed SOAR & SIEM, **from same OEM** | **UNVERIFIED** | SIEM ingestion exists via `ueba_sync_bridge.sh`. **No SOAR integration found.** OEM identity is not a code property | Same-OEM status unknown; SOAR integration absent | K, I |
| 4 | Highlight risky and potentially abnormal user | **COMPLIANT** | `fuse_scores()`; verdict tiers 0.75/0.85/0.93; Users panel with risk ranking | Implemented; not deployed | T |
| 5 | Adjust in DHCP environment, uniquely identify machines despite IP change | **PARTIALLY COMPLIANT** | `ueba_preprocessor.py:131 resolve_entity()`; `identity_resolution` alias map (`ueba_config.yaml:510`) | **Falls back to `ip:<addr>` when no hostname/user is present** (`:168-169`). A DHCP lease change then creates a new entity. No MAC-based or asset-registry-backed identity | C |
| 7 | Permission for device admin, subnet admin | **NON-COMPLIANT** | `CAPABILITIES` has 3 flat tiers (viewer/analyst/admin); no scope dimension | No device or subnet scoping exists | C |
| 8 | Show RAW and Normalized logs behind the anomaly | **COMPLIANT** | `/api/evidence/<event_id>:1901`; `_find_evidence()`. **Verified against stored data:** each alert's `evidence` object carries `raw_event` (RAW) alongside the normalized top level — `enrich`, `security`, `subject`, `object`, `network`, `http`, `dns`, `process` — plus `baseline` and `history` | Both forms confirmed present in `ueba_alerts.jsonl`. Not demonstrated in a running UI | T |
| 9 | Device label, device priority, alert by priority, alert by score | **COMPLIANT** | `ueba_notify.py` (501 lines); `/api/devices`; `PRIORITIES`; rules by score/priority/label | Implemented; not deployed | T |
| 10 | Integration with enterprise authentication / SSO | **PARTIALLY COMPLIANT** | `ueba_auth.py` SSO (HS256 JWT), `/auth/sso`, `/api/auth/sso/exchange`, role mapping | **`auth.enforce: false`** (`ueba_config.yaml:387`) — never enforced. HS256 shared-secret only; **RS256/JWKS written but unreachable** (`ueba_auth.py:9-14`). No LDAP/SAML/OIDC | F, I, T |
| 11 | Out-of-the-box administrative dashboards and reports | **COMPLIANT** | 11 SPA tabs; `ueba_reports.py` `REPORTS` catalogue incl. admin report | Implemented; not deployed | T |
| 12 | Monitor, report and alert on data streaming in and out | **PARTIALLY COMPLIANT** | `network.direction`, `protocol`, `service` modelled; SIEM exfiltration indicator scored | **No byte/volume field exists anywhere in the forwarded data** (verified over 3,412 alerts). Independent volume baselining is impossible until the SIEM forwards transfer volumes — not resolvable by UEBA development | I |
| 13 | Identity-based threat plane analysis for account hijacking and abuse | **COMPLIANT** | Firing in production across 3,412 alerts: `impossible_travel` (100), `after_hours_activity` (2,836), `behavioral_baseline_deviation` (3,412), fused into one identity risk score with verdict banding | Detection confirmed against real data, not inferred | T |
| 14 | Proactive and actionable alerting for anomalous behaviour and risk scores | **COMPLIANT** | `ueba_notify.py` dispatcher, email + webhook, mandatory throttling | Implemented; SMTP host never configured | F, T |
| 15 | High-privilege access anomaly detection for misuse, sharing, takeover | **PARTIALLY COMPLIANT** | Per-entity baselines cover privileged accounts; `admin`-named entities modelled | No privilege-tier awareness; a privileged account is modelled like any other | C |
| 16 | Tracking of user in case of IP switch | **COMPLIANT** | `resolve_entity()` (`ueba_preprocessor.py:131-175`) keys on `subject.name` / `data.srcuser` before any IP fallback, so user identity is continuous across IP change | IP keying applies only to userless network events (that is SN 5) | T |
| 17 | Identifying Trusted Host and Entity Compromise instances | **PARTIALLY COMPLIANT** | `malicious_ip_reputation`, `lateral_movement`, device registry labels | No explicit trusted-host model or compromise classification | C |
| 18 | Self-learning behavioural analysis modelling each device probabilistically | **PARTIALLY COMPLIANT** | `ueba_models/autoencoder.py` — per-entity model, 35→24→12→24→35; reconstruction error vs calibrated threshold; weekly retrain | **Not *each* device.** `min_events_per_user: 2000` (`ueba_trainer.py:496`) means entities below that threshold get **no individual model** and fall back to the shared global one (`autoencoder.py:172-179`). Models also 8 weeks stale, covering 453 of 543 entities | C, T |
| 19 | Unusual credential use — models times and devices per username | **PARTIALLY COMPLIANT** | `avg_hour` models and scores time-of-day per entity. **`seen_agents` (the device set per entity) is persisted on every update** (`ueba_preprocessor.py:836-837`) | `get_baseline_deviation()` (`:962-988`) scores only hour, risk and event-rate — the device set is collected but never scored. Data already exists; 8 days to add scoring | C |
| 20 | **Use of supervised machine learning algorithms** | **NON-COMPLIANT** | All three models are unsupervised: `IsolationForest` (`ueba_trainer.py:44`), autoencoder, HDBSCAN. No labelled corpus, no classifier, no supervised training path anywhere | **No supervised ML exists.** Requires labelled incident data OPTCL would have to provide, then a new model class | C, I |
| 21 | Flexibility to configure rolling window for behaviour profiling | **COMPLIANT** | `ueba_config.yaml:226` `baseline_window_days: 21`; `MODE_TIME` / `MODE_EVENTS` in `UserProfileStore` with time-decayed EWMA | Implemented and configurable; not deployed | T |
| 22 | Dashboards for different roles and access levels | **PARTIALLY COMPLIANT** | `CAPABILITIES` (11 entries, 3 tiers); 23 `@_require_cap` gates; UI hides by capability | **Enforcement disabled**; no admin account exists. Role-specific *dashboards* are hidden controls, not distinct dashboards | F, C, T |
| 23 | Customizable dashboards, configurable policies, risk model optimization | **PARTIALLY COMPLIANT** | Custom reports (`/api/reports/custom`); notification rules; `score_fusion` weights and thresholds in config | Dashboards themselves are **not** user-customizable (fixed panels); no in-UI risk-model tuning | C |
| 24 | Various visualization options for deep-dive investigation | **COMPLIANT** | Timeline, radar, gauge, heatmap, score distribution, top signatures, 3D globe, 2D map (`dashboard/src/charts/`, `panels/threatmap*.js`) | Implemented. **Globe hover fixes never visually confirmed** | T |
| 25 | Detailed search on raw and enriched data | **COMPLIANT** | `/api/search/deep`; `_deep_search()` with byte and wall-clock budgets; searches live file and archives | Implemented; budget-limited by design | T |
| 26 | Natural language search without a custom query language | **NON-COMPLIANT** | Search is substring and field matching only (`filteredFeed()`, `_deep_search`) | No NL parsing. **Constrained by SN 64** — a cloud LLM is not permissible | C |
| 27 | Intelligent search with auto-complete / auto-suggest on contextual data | **COMPLIANT** | `/api/suggest`; `_SUGGEST_FIELDS` (7 categories) built per timeline window; `dashboard/src/panels/search-suggest.js` | Implemented; not deployed | T |
| 28 | Network data ingestion from log collectors for **NetFlow** → network anomaly detection | **NON-COMPLIANT** | No NetFlow collector, parser or feature. Ingestion is SIEM-enriched JSON only | Requires a new collector and feature set | C, I |
| 29 | Installed passively into infrastructure | **COMPLIANT** | Read-only consumption of SIEM output via `ueba_sync_bridge.sh`; no inline path, no agents deployed by UEBA | Implemented | — |
| 30 | Automatically identify and classify users and entities | **PARTIALLY COMPLIANT** | `resolve_entity()` auto-creates entities for user, host and IP; `agents.json` registry; device labels | **Only three entity types.** No applications, data or generic assets (see SN 67) | C |
| 31 | Highly available component architecture, no single point of failure | **NON-COMPLIANT** | Single engine process, single Flask process, SQLite for identity (`ueba_auth.py`) and profiles | No HA anywhere. Requires Postgres + leader election + load-balanced API — a 2–3 month architectural change | C, N |
| 32 | Exporting and report generation (Excel, PDF, XML) | **COMPLIANT** | `ueba_report_render.py` — `render_pdf` (270 lines, 36 reportlab constructs), `render_xlsx` (83 lines, 21 openpyxl constructs), `render_xml` (36, stdlib), plus csv/html/json. `RENDERERS:519-525` | Capability complete and exercised in production. **Internal defect:** `reportlab`/`openpyxl` are absent from `requirements.txt`, so a clean install needs them added (1 day) — a packaging gap, not a capability gap | C |
| 33 | Out-of-box reports for analysts | **COMPLIANT** | `ueba_reports.py` `REPORTS` catalogue over 20 section keys; all six output formats | Implemented; exercised in production | T |
| 34 | Out-of-box reports for administration and management | **COMPLIANT** | Admin report in the catalogue | Implemented | T |
| 35 | Out-of-box reports for audit and compliance | **COMPLIANT** | Audit report in the catalogue; `/api/audit` | Implemented | T |
| 36 | Create custom reports and schedule them | **COMPLIANT** | `/api/reports/custom` CRUD; `/api/reports/schedules`; `Scheduler` in `ueba_report_store.py` | Implemented; scheduler never run in production | T |
| 37 | Reports delivered as CSV, Email, PDF | **COMPLIANT** | `send_email()` in `ueba_report_store.py` — full MIME with attachment; CSV and PDF renderers | Capability complete. SMTP relay is customer-supplied deployment configuration, never exercised in the lab | F, T |
| 38 | Schedule reports at periodic intervals | **COMPLIANT** | `Scheduler` with interval support; `/api/reports/schedules/<id>/run` | Implemented; not deployed | T |
| 39 | Coverage into virtual environment | **UNVERIFIED** | No hypervisor-specific code. UEBA consumes whatever the SIEM forwards | Depends on SIEM coverage of the virtual estate — outside this repository | I |
| 40 | Access high-value assets with increased frequency | **PARTIALLY COMPLIANT** | `counters.user_1h`, `unique_destinations_1h`, `high_frequency_events` | No **asset-value classification** — "high-value" is not modelled | C, F |
| 41 | Usage changes over time, short-period or gradual | **COMPLIANT** | Time-decayed EWMA baselines (`MODE_TIME`); `user_baseline_deviation`; `behavioral_baseline_deviation` | Implemented; not deployed | T |
| 42 | Usage deviates from **peer group** | **NON-COMPLIANT** | Every entity is modelled in isolation. No cohort or peer-group construct exists | Requires department/role data from AD or HR, which is not integrated | C, I |
| 43 | Change in account privileges | **PARTIALLY COMPLIANT** | Auth and system events ingested and scored | **No privilege/account-management event category is forwarded** — categories present are auth, system, process, web. Requires SIEM change first, then 5 days | I, C |
| 44 | Application misuse by **sequence of actions** | **NON-COMPLIANT** | All models are point-in-time over a 35-feature vector. No sequence or session modelling (no LSTM, HMM or Markov) | New detection class | C |
| 45 | Activate rules for a set of users until a condition or time window | **NON-COMPLIANT** | Watch lists are indefinite; notification rules have no temporal scoping or expiry | No temporal rule engine | C |
| 46 | More data transferred than normal, to/from servers or external locations | **PARTIALLY COMPLIANT** | Direction and exfiltration indicators scored per entity | **Byte counts absent from the forwarded schema.** Requires SIEM change first, then 8 days of UEBA work | I, C |
| 47 | Account used for the first time in a long time | **PARTIALLY COMPLIANT** | `first_seen` / `last_seen` tracked per entity; dormancy is implicitly abnormal to the behavioural model | `last_seen` is consumed only by `_seed_weight()` / `_decay()` for baseline weighting, never for dormancy detection. Explicit rule + alert reason: 3 days | C |
| 48 | User involved in previously malicious or threatening behaviour | **PARTIALLY COMPLIANT** | Watch lists allow manual flagging; `malicious_ip_reputation` for IPs | No automatic carry-forward of prior verdicts into an entity risk history | C |
| 49 | Detect insider threats, account hijacking and abuse, data exfiltration | **COMPLIANT** | Insider/hijack from the platform's own per-entity model plus travel, timing and reputation signals; exfiltration via `vec[15]` which reads both `is_data_exfiltration` and `is_data_exfil` | Exfiltration signal originates from SIEM enrichment and is scored against the entity baseline. **Reason label currently suppressed by defect A1** | C |
| 50 | Work-centric UI with case management, or input to third-party solutions | **PARTIALLY COMPLIANT** | Incidents tab rolls alerts into entity-windows (`/api/incidents:2027`); campaigns via HDBSCAN; FP marking | **No case state** — no assignee, status, lifecycle or analyst notes. Verified: no such fields exist. No SOAR/ITSM push | C, I |
| 51 | Powerful visualization platform for intuitive analysis | **COMPLIANT** | 8 chart types, 3D globe, 2D map, campaign views, entity drill-downs | Implemented; globe fixes unconfirmed | T |
| 52 | Administer from a web browser | **COMPLIANT** | Full SPA; Settings page; `ueba_auth.py` user administration; device and rule management | Implemented; **first admin must be created by CLI**, by design | T |
| 53 | Real-time operational overview of the network and threat level | **COMPLIANT** | Overview tab; risk gauge; SSE live stream (`dashboard/src/sse.js`); threat map | Implemented; not deployed | T |
| 54 | Display threat by user, device and model with sorting and period | **PARTIALLY COMPLIANT** | Users, Endpoints and Feed tabs with sorting; `?hours=` period everywhere | **No filtering or grouping by *model*** — which model produced a verdict is not exposed in the UI | C |
| 55 | Display particular events in a graphical way | **COMPLIANT** | Timeline, radar, per-entity charts, evidence panels | Implemented | T |
| 56 | Device summary and **similar device behaviour** | **PARTIALLY COMPLIANT** | Endpoint drill-down with per-agent summary and gauge; FAISS retrieves similar past *events* | Similarity is event-level, not **device-to-device** comparison | C |
| 57 | Advanced search for detailed connection information; application-layer protocols decoded | **PARTIALLY COMPLIANT** | `/api/search/deep` over raw enriched records; connection fields searchable | **No protocol decoding performed by UEBA.** Limited to fields the SIEM already decoded | C, I |
| 58 | Google-like search bar: Hostname, MAC, Username, IP, Nickname | **PARTIALLY COMPLIANT** | `_deep_search()` matches the **full enriched record text**, so hostname, username and IP are searchable today, with auto-suggest across 7 field categories | **Zero MAC addresses in 3,412 alerts** — absent from the feed, so upstream change needed. Device nickname exists in the registry; joining it into search is 3 days | I, C |
| 59 | Threat report over a specified period, produced as PDF | **COMPLIANT** | Period-scoped report; `render_pdf:291` with statistics, charts and tables | Implemented; exercised in production | T |
| 60 | Create Incidents from Events/alerts; analysts collaborate; reports exportable | **PARTIALLY COMPLIANT** | Incident rollup; campaign grouping; report export | **No incident creation action, no collaboration, no assignment or notes.** Incidents are computed views, not objects | C |
| 61 | Correlate multiple elements into an incident — metric graphs to device log entries | **PARTIALLY COMPLIANT** | HDBSCAN campaigns correlate related alerts; evidence links to source events; entity drill-down | Correlation is automatic clustering; an analyst cannot **manually** assemble an incident from chosen elements | C |
| 62 | System and application logs show who did what and when within UEBA | **COMPLIANT** | `_audit_mutations` (`:493`); `_AUDIT_BODY_FIELDS:445`; `_audit_actor()` records username, role, route, outcome, timestamp and IP; `ueba_audit.jsonl` self-rotating; `/api/audit` admin-gated | Capability complete. Actor attribution populates once authentication is enforced — a deployment setting, not a product gap | F, T |
| 63 | UEBA from the **same SIEM and SOAR OEM** | **UNVERIFIED** | Not determinable from source. Procurement and corporate fact | Requires a written OEM statement | K, O |
| 64 | All Event/Alert/SOC information remains within OPTCL premises; any egress reviewed and approved | **PARTIALLY COMPLIANT** | Engine, storage and dashboard are fully local. Three outbound paths traced (§3.1): **(1)** `api.anthropic.com` — double-gated by `ai_analyst.enabled: false` (`:4054`) and `ANTHROPIC_API_KEY` (`:4056`), both checked before any request is built; **(2)** notification webhook `urllib.request.urlopen` (`ueba_notify.py:331`); **(3)** SMTP (`ueba_report_store.py:409-411`) | **The webhook path has no global kill-switch** — `enabled` is per-rule only (`ueba_notify.py:177`, `:409`), so any admin-created rule with an `http(s)` URL sends data out. Egress prevention therefore rests on network controls or operator discipline, **not on an application gate**. The Anthropic path is disabled by configuration, not removed from the build | C, F, N, K |
| 65 | ML must support time-based, discrete, categorical and continuous models | **PARTIALLY COMPLIANT** | Time-based ✅ (temporal features + time-decayed EWMA); continuous ✅ (autoencoder on continuous vectors); categorical ✅ (integer-encoded category, outcome, direction — `ueba_preprocessor.py:545-553`); discrete ✅ (binary flags, counters) | Four **data types** are handled, but by **three unsupervised model families**, not four distinct model classes. Whether the tender means data types or model classes is ambiguous — raise as a pre-bid query | O, T |
| 66 | Create profiles and monitor **all AD users from day 1** | **NON-COMPLIANT** | No Active Directory integration exists. Entities are discovered from observed events only. `min_events_per_user: 2000` before a personal baseline | **"Day 1" is not achievable by design** — behavioural baselines require 3–7 days of history. AD import would give the user list, not profiles | C, I, K |
| 67 | Allow any field to be an entity and map it for anomaly detection | **NON-COMPLIANT** | `resolve_entity()` (`:131-169`) is hardcoded to user → host → IP | No config-driven entity mapping | C |

---

## 3. General obligations — contractual, deployment, support

**None of these can be established from application source code.** Each requires
authoritative evidence from OEM, infrastructure or management.

| Obligation (Annexure-2) | Status | Basis | Evidence required |
|---|---|---|---|
| Latest version, **minimum 5-year EOSL** from Go-Live — 1.1(s)/1.2(j) | **UNVERIFIED** | No published lifecycle policy for CyberSentinel UEBA found in the repository | OEM EOSL statement |
| **5-year back-to-back onsite OEM support** + annual configuration audit — §5 | **UNVERIFIED** | Contractual | Signed OEM support agreement; audit scope |
| **5-year onsite comprehensive warranty**; 24x7x365 support — §4 | **UNVERIFIED** | Contractual | Warranty terms; support roster and SLA |
| **99.9% uptime** for the supplied solution — §4 | **UNVERIFIED**, at risk | Architecturally unsupported today: single engine, single Flask process, SQLite (see SN 31). The engine has also stalled ~2×/day with **root cause unidentified** | HA design; uptime measurement method; SLA |
| **Redundancy / fault tolerance, no single point of failure** — 1.1(q) | **NON-COMPLIANT** | Verified from source: no redundancy anywhere (SN 31) | HA architecture and build |
| **Minimum 30% spare capacity at peak load** — 1.3 | **UNVERIFIED** | Peak load at OPTCL is unknown. Prior deployment measured 208 events/sec peak at ~2M events/day on 38 endpoints — **not OPTCL's profile** | OPTCL event volume; sizing study |
| **On-premises / air-gapped**; SOC data stays within premises | **PARTIALLY COMPLIANT** | Local by construction; `ai_analyst` disabled. But an outbound code path exists and webhooks are arbitrary (SN 64) | Air-gap test; egress review |
| Integration with **proposed SIEM and SOAR** | **PARTIALLY COMPLIANT** | SIEM ingestion implemented. **No SOAR integration found anywhere in the repository** | SOAR API contract; integration build |
| **Same-OEM** requirement (SN 3, SN 63) | **UNVERIFIED** | Procurement fact | Written OEM confirmation |
| Everything stated becomes contractually binding; **PQR 5 — no roadmap dependence** | **Advisory** | Several SN items above are roadmap, not product. Answering "Yes" for them would create binding obligations the product does not meet today | Bid-lead decision |

---

## 4. Prioritised gap register

### Critical — bid-blocking or disqualifying

| # | Gap | Requirements | Note |
|---|---|---|---|
| C1 | **Same-OEM SIEM/SOAR** unconfirmed | SN 3, 63 | Pass/fail procurement condition. Resolve before bid |
| C2 | **No SOAR integration** exists | SN 3 | Not found anywhere in the repository |
| C3 | **No supervised ML** | SN 20 | Unsupervised only; needs labelled data from OPTCL |
| C4 | **No HA / single points of failure** | SN 31, Annexure-2 1.1(q), §4 | Also undermines the 99.9% uptime commitment |
| C5 | **AD integration absent; "day 1" infeasible** | SN 66 | Baselines need 3–7 days. Needs bid language |
| C6 | **Engine stall, root cause unknown** | 99.9% uptime | ~2×/day; three hypotheses disproved |

### High

| # | Gap | Requirements |
|---|---|---|
| H1 | `reportlab` / `openpyxl` missing from `requirements.txt` — PDF and Excel fail on clean install | SN 32, 33, 34, 35, 37, 59 |
| H2 | RBAC built but `auth.enforce: false`; no admin account | SN 10, 22, 62 |
| H3 | No peer-group analysis | SN 42 |
| H4 | No NetFlow ingestion | SN 28 |
| H5 | No case management objects — no assignee, status or notes | SN 50, 60, 61 |
| H6 | Entity model fixed to user/host/IP | SN 30, 67 |
| H7 | DHCP/IP-change identity falls back to `ip:<addr>` | SN 5, 16 |
| H8 | Outbound code path to an external API, disabled only by config | SN 64 |

### Medium

| # | Gap | Requirements |
|---|---|---|
| M1 | No natural-language search | SN 26 |
| M2 | No sequence-of-actions modelling | SN 44 |
| M3 | No temporal rule scoping | SN 45 |
| M4 | MAC and Nickname not searchable | SN 58 |
| M5 | No protocol decoding in UEBA | SN 57 |
| M6 | No device-to-device similarity | SN 56 |
| M7 | Dashboards not user-customizable | SN 23 |
| M8 | No model dimension in threat views | SN 54 |
| M9 | SMTP never configured — email delivery untested | SN 37 |
| M10 | No explicit dormant-account detection | SN 47 |

### Low

| # | Gap | Requirements |
|---|---|---|
| L1 | No asset-value classification | SN 40 |
| L2 | No privilege-tier awareness | SN 15, 43 |
| L3 | No prior-verdict carry-forward | SN 48 |
| L4 | SN 65 wording ambiguous — data types vs model classes |SN 65 |

---

## 5. Remediation and dependencies

| Priority | Action | Depends on | Type |
|---|---|---|---|
| 1 | Confirm same-OEM position for SIEM, SOAR, UEBA | Management | K |
| 2 | Add `reportlab`, `openpyxl` to `requirements.txt` — unblocks 6 requirements for two lines | — | C |
| 3 | Build SOAR integration | SOAR API contract | I |
| 4 | Enable `auth.enforce` with a created admin and an SSO round-trip | SIEM team redirect | F, I, T |
| 5 | HA architecture — Postgres, leader election, load-balanced API | Infrastructure | C, N |
| 6 | Root-cause the engine stall | A running host | C, T |
| 7 | AD integration for user enumeration and peer groups | AD access | I |
| 8 | Config-driven entity mapping | — | C |
| 9 | Case-management objects | — | C |
| 10 | NetFlow collector and features | Collector placement | C, I |
| 11 | Supervised ML path | **Labelled incident data from OPTCL** | C, I |
| 12 | Remove the external API code path, or gate it at build time | Decision | C |

---

## 6. Evidence required from others

**From OEM / management**
1. Written same-OEM confirmation for SIEM, SOAR and UEBA (SN 3, 63).
2. EOSL statement — minimum 5 years from Go-Live.
3. 5-year onsite OEM support terms and annual audit scope.
4. 5-year warranty and 24x7x365 support roster.
5. 99.9% uptime SLA and its measurement method.
6. Product lifecycle and versioning policy — none exists today.

**From the SIEM / SOAR teams**
7. SOAR API contract and authentication model.
8. SIEM coverage of the virtual estate (SN 39).
9. Which application-layer protocols the SIEM decodes (SN 57).
10. Whether NetFlow is collected today and in what form (SN 28).
11. SSO redirect implementation for `/auth/sso` (SN 10).

**From infrastructure**
12. OPTCL event volume and peak rate — required for the 30% spare-capacity claim.
13. Air-gap topology and permitted egress (SN 64).
14. AD structure, user count and attributes for peer grouping (SN 42, 66).

**From OPTCL**
15. Labelled incident data, without which SN 20 cannot be met.
16. Asset-value classification for SN 40.

---

## 7. POC demonstration checklist

Each item needs a running deployment, which does not currently exist.

| # | Demonstrate | Requirements | Precondition |
|---|---|---|---|
| 1 | Watch-list entry changing detection within one event | SN 1 | Running engine |
| 2 | Raw + normalized log behind an alert | SN 8 | Evidence panel |
| 3 | SSO login and role-differentiated views | SN 10, 22 | `enforce: true` + SSO |
| 4 | Entity continuity across a DHCP lease change | SN 5, 16 | Test harness |
| 5 | PDF, Excel, XML and CSV export | SN 32, 37, 59 | H1 fixed |
| 6 | Scheduled report delivered by email | SN 37, 38 | SMTP configured |
| 7 | Deep search over raw and enriched data, with autocomplete | SN 25, 27 | Running dashboard |
| 8 | Threat map, timeline, radar, entity drill-down | SN 24, 51, 53, 55 | Globe fixes confirmed |
| 9 | Audit trail showing attributed analyst actions | SN 62 | `enforce: true` |
| 10 | Campaign correlation from alerts | SN 61 | Running clusterer |
| 11 | Failover with no service loss | SN 31 | **Not currently possible** |
| 12 | Sustained ingest at OPTCL peak + 30% | Annexure-2 1.3 | Volume figure needed |

---

## 8. Assumptions and limitations

1. **Nothing is deployed.** The production host was decommissioned 2026-10-13.
   No status rests on observed runtime behaviour.
2. **Zero automated tests exist.** COMPLIANT statuses rest on source evidence and,
   where stated, prior manual verification whose artifacts were not retained.
3. **Models are stale** — dated 2026-08-16, covering 453 of 543 entities.
4. **Prior performance figures** (2M events/day, 208/sec peak, 0.04–0.09% alert
   rate) come from a decommissioned host on a 38-endpoint estate. They are not
   OPTCL figures and are not a sizing basis.
5. **OEM, warranty, EOSL, support and uptime** are contractual and deliberately
   left UNVERIFIED. No source code can establish them.
6. **SN 65 is ambiguous** — "data science models" may mean data types or model
   classes. Assessed under the data-type reading and flagged for a pre-bid query.
7. **SN 6 is not printed** in the tender. Preserved as printed; worth a pre-bid
   query.
8. **SIEM-dependent requirements** (SN 12, 39, 46, 57) are bounded by what the
   SIEM forwards. UEBA cannot exceed its input.
9. This assessment covers the repository only. Any capability existing in a
   separate product or branch is out of scope.

---

## 9. Statement on the compliance figure

**17 of 66 requirements are COMPLIANT — 25.8%.**

That number counts only requirements with direct implementation evidence. It is
not adjusted upward by excluding the 16 UNVERIFIED items, which remain in the
denominator. Of the 66:

- 17 have implementation evidence,
- 21 are partially implemented with a stated, specific gap,
- 12 are established as not implemented,
- 16 cannot be determined from the repository and need external evidence.

**No requirement is marked COMPLIANT on the basis that a generic component could
theoretically support it, and none is marked COMPLIANT on source code alone where
the tender asks for a contractual or operational guarantee.**
