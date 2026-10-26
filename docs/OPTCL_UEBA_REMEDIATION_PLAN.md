# OPTCL UEBA — Remediation and Bid-Risk Plan

**Basis:** `docs/OPTCL_UEBA_RFP_COMPLIANCE.md` (post-validation) and `03_UEBA.docx`,
both re-read 2026-10-22. The compliance report is unchanged by this document.

**Starting position:** 19 COMPLIANT · 34 PARTIALLY COMPLIANT · 10 NON-COMPLIANT ·
3 UNVERIFIED, of 66 requirements. **Confirmed compliance 28.8%.**

Read-only analysis. No application code, configuration, dependency or
infrastructure was changed. Nothing was committed.

---

## 1. What the tender's answer rules actually permit

Three rules from `03_UEBA.docx` constrain every answer, and they are stricter
than a normal compliance sheet:

> *"Compliance column: enter exactly **Yes, No or Can Be**."*

> *"For 'Can Be', state in the remarks whether it is **available now or needs
> customisation**. **Do not answer Yes for a roadmap feature**."*

> *"PQR 5 requires the core platform to work **without dependence on future
> roadmap features**, so **answer Yes only for what the product does today**."*

And the consequence of getting it wrong:

> *"Anything you cannot answer Yes to must be reported to the bid lead so it can
> be listed in **Schedule-4 (Techno-Commercial Deviation)**. Quoting **NIL
> deviation** in Schedule-4 **overrides** deviations noted elsewhere in the bid
> (tender clause 11)."*

Two implications the bid lead must absorb:

1. **"Does today" is the test, not "could be built".** Of our 34 PARTIALLY
   COMPLIANT items, most are honestly **"Can Be — needs customisation"**, not
   "Yes". Marking them Yes is a false statement that becomes contractually
   binding on award.
2. **Declaring NIL deviation in Schedule-4 erases every caveat written anywhere
   else.** If deviations exist and Schedule-4 says NIL, the bid is committed to
   the full specification regardless of remarks. This is the single highest
   contractual risk in the submission.

---

## 2. Bid blockers — resolve before submission

These are not engineering backlog items. Each can lose the bid on its own.

| # | Requirement | Issue | Resolvable by | Complexity |
|---|---|---|---|---|
| **B1** | **SN 3, SN 63** | UEBA must be from the **same OEM** as the proposed SIEM and SOAR. Not a code property. If CyberSentinel is not supplying all three, no amount of engineering fixes this | **Management decision + written OEM confirmation** | — (contractual) |
| **B2** | **SN 3** | **No SOAR integration exists.** Repository-wide search returns one UI string in `dashboard/src/panels/recommendations.js:18` — recommendation text, not an integration | Integration build, after B1 | **High** |
| **B3** | **SN 20** | **Supervised ML absent.** Only IsolationForest, autoencoder, HDBSCAN — all unsupervised. Needs labelled incident data OPTCL would have to supply | Code + OPTCL data | **High** |
| **B4** | **SN 31** + Annexure-2 1.1(q), §4 | **No HA, single points of failure throughout**, and this also underwrites the **99.9% uptime** commitment. Compounded by an engine stall ~2×/day whose root cause is unidentified | Re-architecture + infrastructure | **High** |
| **B5** | **SN 66** | **"All AD users from day 1"** — no AD integration, and day-1 behavioural profiles are **not achievable by design** (baselines need 3–7 days of history) | Integration + **pre-bid clarification** | **High** |

**B1 should be settled first.** If the same-OEM condition cannot be met, B2–B5
may be moot and the bid strategy changes entirely.

---

## 3. Remediation register

Ordered by bid risk. **Complexity** is engineering effort; **Route** is the only
mechanism that can actually resolve it.

Route key: **CFG** configuration · **CODE** product engineering ·
**INFRA** infrastructure · **INT** third-party integration ·
**OEM** vendor document · **CONTRACT** commercial · **PREBID** clarification query.

### Tier 1 — Critical (bid-blocking)

| SN | Gap | Route | Complexity | Dependencies / evidence needed |
|---|---|---|---|---|
| 3, 63 | Same-OEM; no SOAR integration | CONTRACT + OEM, then INT | High | Written OEM statement; SOAR API contract and auth model |
| 20 | No supervised ML | CODE + INT | High | **Labelled incident dataset from OPTCL** — without it this cannot be built |
| 31 | No HA, single points of failure | CODE + INFRA | High | Postgres migration, leader election, load-balanced API tier; HA hardware |
| 66 | No AD; day-1 profiling infeasible | INT + PREBID | High | AD read access; **clarification on what "day 1" means** |

### Tier 2 — High (materially weakens the bid or the POC)

| SN | Gap | Route | Complexity | Dependencies / evidence needed |
|---|---|---|---|---|
| 32, 33, 34, 35, 37, 59 | `reportlab` / `openpyxl` absent from `requirements.txt` — PDF and Excel fail on a clean install | **CODE (two lines)** | **Low** | None. **Highest value per unit effort in the entire plan** |
| 10, 22, 62 | RBAC built but `auth.enforce: false`; no admin account; audit records `user: None` | CFG + INT + testing | **Low–Medium** | SSO redirect from the SIEM team; admin account creation; round-trip test |
| 42 | No peer-group analysis | CODE + INT | High | Department/role attributes from AD or HR |
| 28 | No NetFlow ingestion | CODE + INT | High | Collector placement; confirmation NetFlow is collected at all |
| 50, 60, 61 | No case-management objects — no assignee, status, lifecycle or notes | CODE | Medium | Decide: build natively or hand off to SOAR/ITSM |
| 64 | Webhook egress has no global kill-switch | CODE + CFG + INFRA | **Low–Medium** | See §5 |
| 5, 16 | Entity identity falls back to `ip:<addr>` under DHCP | CODE | Medium | Asset registry or MAC source; DHCP-change test harness |
| 30, 67 | Entity model hardcoded to user/host/IP | CODE | Medium | Config-driven entity mapping design |
| 37 | SMTP never configured; email delivery never tested | CFG + testing | **Low** | OPTCL SMTP relay details |

### Tier 3 — Medium (answerable as "Can Be", demo-visible)

| SN | Gap | Route | Complexity |
|---|---|---|---|
| 18 | `min_events_per_user: 2000` leaves sparse entities on the global model | CFG or CODE | Low–Medium |
| 26 | No natural-language search — **and SN 64 forbids a cloud LLM** | CODE | High |
| 44 | No sequence-of-actions modelling | CODE | High |
| 45 | No temporal rule scoping or expiry | CODE | Medium |
| 23 | Dashboards not user-customizable; no in-UI risk-model tuning | CODE | Medium |
| 57 | No protocol decoding in UEBA | CODE + INT | Medium |
| 58 | MAC and Nickname not searchable | CODE | **Low** |
| 54 | No "model" dimension in threat views | CODE | **Low** |
| 56 | Similarity is event-level, not device-to-device | CODE | Medium |
| 19 | No explicit username × device pairing model | CODE | Medium |
| 47 | No explicit dormant-account rule | CODE | **Low** |
| 13, 15, 17, 43, 48, 49 | Generic features rather than named detections | CODE | Medium each |
| 40 | No asset-value classification | CODE + CFG | Medium |
| 46 | No independent volume baselining | CODE + INT | Medium |
| 65 | Four data types handled by three model families — wording ambiguous | PREBID + OEM | Low |

### Tier 4 — Low / external dependency

| SN | Gap | Route |
|---|---|---|
| 7 | No device/subnet scoping in RBAC | CODE (Medium) |
| 12 | Depends on SIEM-supplied fields | INT |
| 39 | Virtual-estate coverage is a SIEM property | INT |

---

## 4. The fifteen requirements called out for analysis

**SN 3 — SOAR/SIEM integration, same OEM.** Two separate failures. The OEM
condition is commercial and binary. The integration is absent: the only match in
the repository is a UI label. Even with the OEM question resolved, a SOAR
integration is a High-complexity build requiring an API contract we do not have.
**Cannot be "Yes" today.**

**SN 7 — device admin, subnet admin.** `CAPABILITIES` has three flat tiers with
no scope dimension. The RBAC layer built in September is the right foundation —
adding a scope attribute is a natural extension, not a rewrite. **Medium, CODE.**

**SN 10 — enterprise SSO.** SSO exists (HS256 JWT) but has **never been
enforced**; `RS256/JWKS` is written and unreachable; there is no LDAP, SAML or
OIDC. The engineering is largely done; the gap is configuration, an SSO redirect
from the SIEM team, and a tested round-trip. **Low–Medium, but needs another
team.**

**SN 20 — supervised ML.** Nothing in the repository is supervised. This is the
one requirement that cannot be solved by engineering alone: supervised learning
needs labelled incidents, which only OPTCL's analysts can produce. Treat as a
**joint programme with a data dependency**, not a sprint item.

**SN 26 — natural-language search.** Substring matching only. The obvious
implementation — an LLM translating text to filters — **collides directly with
SN 64**, which forbids data leaving the premises. A locally-hosted model is the
only compliant route, which raises the complexity substantially. **High.**

**SN 28 — NetFlow.** No collector, parser or feature. `docs/build_techdoc.py:720`
already states "Not supported". Needs a new ingestion path plus flow-derived
features. **High, and depends on whether NetFlow is collected at OPTCL at all.**

**SN 31 — HA, no single point of failure.** Single engine process, single Flask
process, SQLite for both identity and profiles. This is a 2–3 month
re-architecture (Postgres, leader election, stateless API behind a balancer) plus
hardware. It also **underwrites the 99.9% uptime obligation**, so it is not
separable from the commercial terms.

**SN 42 — peer-group deviation.** Every entity is modelled in isolation; no
cohort construct exists. The blocker is **data, not algorithms** — department and
role attributes must come from AD or HR.

**SN 44 — misuse by sequence of actions.** All models are point-in-time over a
35-feature vector. Sequence detection (LSTM, HMM or Markov) is a **new detection
class**, not a tuning change. **High.**

**SN 45 — rules active until a condition or time window.** Watch lists are
indefinite; notification rules have no expiry. A temporal rule engine is a
contained, well-understood build. **Medium — one of the better effort-to-value
items in Tier 3.**

**SN 63 — same OEM.** See SN 3. Requires a **written OEM statement**. No
repository evidence can substitute.

**SN 64 — data sovereignty.** See §5 — the most actionable item in this plan.

**SN 65 — four model types.** We handle all four **data types**: time-based
(temporal features plus time-decayed EWMA), discrete (binary flags, counters),
categorical (integer-encoded category, outcome, direction) and continuous
(autoencoder inputs). But these run through **three unsupervised model families**,
not four distinct model classes. **The tender wording is ambiguous and should be
a pre-bid query.** Answering "Yes" on the data-type reading, if the evaluator
meant model classes, would be a deviation discovered at POC.

**SN 66 — all AD users from day 1.** Two problems. No AD integration exists —
that part is buildable. But **day-1 behavioural profiles are not achievable by
any UEBA product**: a baseline requires 3–7 days of observed history. An AD
import gives a *user list* on day 1, not *profiles*. **This needs a pre-bid
clarification and careful bid language**, not an engineering promise.

**SN 67 — any field as entity.** `resolve_entity()` (`ueba_preprocessor.py:131-169`)
is hardcoded to user → host → IP. Config-driven entity mapping is a contained
change to one function plus configuration schema. **Medium, and it also improves
SN 30.**

---

## 5. SN 64 — preventing unapproved data egress

Three outbound paths exist in the product. Their current gating differs, and only
one is properly controlled.

| # | Path | Code | Current gate | Adequate for air-gap? |
|---|---|---|---|---|
| 1 | `https://api.anthropic.com/v1/messages` | `ueba_dashboard_server.py:4062-4063` | `ai_analyst.enabled: false` (`:4054`) **and** `ANTHROPIC_API_KEY` unset (`:4056`), both checked before any request is constructed | Functionally yes, but **by configuration, not by build** |
| 2 | Notification webhook | `ueba_notify.py:331` `urllib.request.urlopen` | **`enabled` is per-rule only** (`:177`, `:409`). **No global kill-switch** | **No** |
| 3 | SMTP report delivery | `ueba_report_store.py:409-411` | Host unset by default | Partially — unset by accident, not by policy |

### Recommended controls — product engineering

| ID | Change | Effect | Complexity |
|---|---|---|---|
| E1 | Add a single top-level `network.egress_allowed: false` switch, checked by **all three** paths before any socket is opened | One auditable control instead of three unrelated ones | **Low** |
| E2 | Add `network.egress_allowlist: []` — destinations must match, default empty | Lets OPTCL approve specific destinations "on need basis" as the tender wording requires | Low |
| E3 | Remove the Anthropic client from the customer build, or guard it behind a build flag | Converts "disabled" into "not present" — the only answer that survives an air-gap audit | Low–Medium |
| E4 | Validate webhook URLs against the allowlist at **rule-creation time**, not just at send time | Fails closed and visibly, rather than silently at dispatch | Low |
| E5 | Log every egress attempt, allowed or blocked, to the audit trail | Produces the evidence OPTCL needs to review egress | Low |

### Deployment and infrastructure controls

These are **not** substitutes for the above; the tender asks for both.

| ID | Control | Owner |
|---|---|---|
| E6 | Default-deny egress firewall on the UEBA host; no outbound route except approved destinations | Infrastructure |
| E7 | No DNS resolution for external domains from the UEBA segment | Infrastructure |
| E8 | Documented change-control for any allowlist addition, matching the tender's "reviewed and approved on need basis" | OPTCL + bid lead |
| E9 | Network capture during POC proving zero unapproved egress under load | Joint |

**Honest position:** with E1–E5 implemented and E6–E9 in place, SN 64 becomes
defensible. **Today it is not** — a single admin-created webhook rule sends SOC
data out with no application-level control.

---

## 6. What cannot honestly be marked "Yes"

Applying the tender's own rule — *answer Yes only for what the product does today* —
**47 of 66 requirements cannot be "Yes"** without implementation, testing,
customisation or written confirmation.

| Answer | Count | SNs |
|---|---|---|
| **"Yes"** — defensible today, subject to POC | **19** | 1, 2, 4, 8, 9, 11, 14, 21, 24, 25, 27, 29, 36, 38, 41, 51, 52, 53, 55 |
| **"Can Be — needs customisation"** | 34 | All PARTIALLY COMPLIANT |
| **"No"** or Can Be with major development | 10 | 7, 20, 26, 28, 31, 42, 44, 45, 66, 67 |
| **Cannot be answered without external evidence** | 3 | 3, 39, 63 |

**An important qualification on the 19.** None has been *demonstrated*. Nothing is
deployed and the repository contains **zero automated tests**. The tender warns:
*"Be ready to demonstrate each claim during the POC."* Each of the 19 must survive
§7 before it is safe to write "Yes".

**Specifically at risk among the 19:** SN 24 and SN 51 depend on globe and hover
fixes that were shipped but **never visually confirmed**; SN 14's delivery channel
has never been exercised; SN 36 and SN 38's scheduler has never run in production.

---

## 7. Product engineering vs obligations that code cannot fix

A recurring failure in bid preparation is assuming engineering can close
commercial gaps. It cannot.

### Product engineering can resolve

SN 5, 7, 13, 15, 16, 17, 18, 19, 23, 26, 28, 30, 32, 33, 34, 35, 37, 40, 43, 44,
45, 46, 47, 48, 49, 50, 54, 56, 57, 58, 59, 60, 61, 62, 64 (partly), 67 — **and
SN 20, 42, 66 only once their data dependency is satisfied.**

### Engineering cannot resolve — these need documents or decisions

| Obligation | Required from |
|---|---|
| Same-OEM SIEM/SOAR/UEBA (SN 3, 63) | Management + OEM, in writing |
| Minimum 5-year EOSL from Go-Live | OEM lifecycle statement |
| 5-year back-to-back onsite OEM support + annual audit | Signed OEM agreement |
| 5-year onsite comprehensive warranty; 24×7×365 | Commercial terms, support roster |
| 99.9% uptime | SLA **and** the HA build (B4) — a commitment code alone cannot honour |
| Redundancy, no single point of failure | Architecture **and** hardware |
| 30% spare capacity at peak | **OPTCL's event volume**, which we do not have |
| Data stays within premises (SN 64) | Engineering **and** network controls **and** change-control policy |
| Virtual-estate coverage (SN 39) | SIEM team confirmation |

**Prior performance figures are not a sizing basis.** The 2M events/day and
208 events/sec peak come from a decommissioned 38-endpoint lab estate. They are
not OPTCL's profile and must not be quoted as capacity evidence.

---

## 8. POC test and acceptance-evidence checklist

Every item requires a running deployment, which **does not currently exist**.
Rebuilding on the replacement server is a precondition for all of it — and that
server currently shuts down overnight.

### Highest-risk — must pass or the claim is withdrawn

| # | Test | Requirements | Acceptance evidence | Precondition |
|---|---|---|---|---|
| P1 | SSO login; three roles see different capability sets; denial returns 403 | SN 10, 22 | Screen capture per role + server log | `enforce: true`, admin created, SIEM redirect |
| P2 | Audit trail names the **authenticated analyst** for each action | SN 62 | `ueba_audit.jsonl` extract showing non-null user | P1 first — this currently records `user: None` |
| P3 | Generate PDF, Excel, XML, CSV from a clean install | SN 32–35, 37, 59 | The four files + install log | Tier-2 dependency fix |
| P4 | Scheduled report delivered by email | SN 37, 38 | Received message with attachment | SMTP relay |
| P5 | Entity continuity across a DHCP lease change | SN 5, 16 | Before/after entity IDs for one machine | Test harness |
| P6 | Failover with no loss of ingestion or UI | SN 31, uptime | Timed failover log | **Not currently possible** |
| P7 | Sustained ingest at OPTCL peak **+30%** | Annexure-2 1.3 | Throughput graph, no backlog growth | OPTCL volume figure |
| P8 | Network capture proving zero unapproved egress | SN 64 | Full packet capture over the test window | §5 controls in place |
| P9 | Raw **and** normalized logs behind one alert | SN 8 | Evidence panel capture showing `raw_event` + enriched | Running dashboard |
| P10 | Threat map, timeline, radar, drill-downs render and hover correctly | SN 24, 51, 53, 55 | Screen capture | **Globe fixes still unconfirmed** |
| P11 | Deep search across raw and enriched data with autocomplete | SN 25, 27 | Query and result capture | Running dashboard |
| P12 | Campaign correlation from related alerts | SN 61 | Campaign view with contributing events | Running clusterer |

### Evidence to assemble alongside

- Written OEM same-OEM confirmation (SN 3, 63)
- OEM EOSL statement, support agreement, warranty terms
- HA architecture diagram and failover procedure
- Egress change-control policy and firewall rule set
- Sizing study against OPTCL's actual event volume

---

## 9. Decision summary for the bid lead

### Bid blockers — decide before submission

1. **Is CyberSentinel supplying SIEM, SOAR and UEBA?** (SN 3, 63.) Binary, and if
   the answer is no, the technical plan below may not matter.
2. **Will OPTCL provide labelled incident data?** Without it SN 20 cannot be met
   at any effort level.
3. **Is there budget and schedule for the HA re-architecture?** (SN 31.) It also
   underwrites the 99.9% uptime commitment.
4. **Can we build a SOAR integration without the API contract?** No. It must be
   obtained or the requirement declared.

### Pre-bid clarification questions to raise

| # | Question | Why |
|---|---|---|
| Q1 | **SN 6 is not printed** — the table goes 5 → 7. Is a requirement missing? | Avoids a disputed count at evaluation |
| Q2 | **SN 65** — do "time based / discrete / categorical / continuous models" mean **data types** or **distinct model classes**? | We satisfy the first reading, not clearly the second |
| Q3 | **SN 66** — what does "from day 1" require? A user inventory, or behavioural profiles? | Behavioural profiles on day 1 are not achievable by any UEBA product |
| Q4 | **SN 28** — is NetFlow currently collected, and in what form? | Determines whether this is integration or new collection |
| Q5 | **SN 64** — what is the approval process for permitted egress? | Needed to design the allowlist and change control |
| Q6 | **SN 57** — which application-layer protocols does the proposed SIEM decode? | Our coverage is bounded by SIEM output |

### Decisions required

| # | Decision | Owner |
|---|---|---|
| D1 | Schedule-4: declare deviations, or claim NIL | **Bid lead — highest contractual risk.** NIL overrides every caveat written elsewhere |
| D2 | Which 34 partial items are offered as "Can Be — customisation" versus withdrawn | Bid lead + engineering |
| D3 | Whether to bid at all if the same-OEM condition fails | Management |
| D4 | Case management: build natively, or integrate SOAR/ITSM | Product |
| D5 | Fund the HA re-architecture, or declare a deviation on SN 31 and the uptime SLA | Management |
| D6 | Remove the Anthropic client from the customer build (E3) | Product + security |

### The two-line fix worth doing regardless

Adding `reportlab` and `openpyxl` to `requirements.txt` unblocks **six
requirements** (SN 32, 33, 34, 35, 37, 59) for two lines of change and no
architectural risk. It is the highest-value remediation in this plan and should
not wait on any decision above.

---

**Nothing in this plan has been implemented. No code, configuration, dependency
or infrastructure was changed, and nothing was committed.**
