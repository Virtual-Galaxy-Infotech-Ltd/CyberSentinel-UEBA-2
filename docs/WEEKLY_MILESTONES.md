# CyberSentinel UEBA — Milestones and Status

Status of record for the project. Compiled 2026-10-21 from a read-only repository
inspection, Git history across both repositories, and the project documentation.

**Deployment is on hold.** Nothing in this document describes a running system.

## How to read this

Every entry carries an evidence tier. They are not equivalent.

| Tier | Meaning |
|---|---|
| **Git** | Date and content confirmed from commit history |
| **Source** | Code verified present by inspection; no date evidence |
| **Record** | Dated in project documentation or memory, **not** in Git — work done directly on box98 before the repository existed |
| **Unverified** | Claimed but not confirmable from any artifact available now |

Classifications: **VERIFIED COMPLETE** · **PARTIALLY COMPLETE** · **IN PROGRESS** ·
**PENDING** · **UNVERIFIED**.

> **Caveat on Git coverage.** The repository was created 2026-09-29. Roughly five
> months of development happened on box98 and was never committed as it occurred;
> it arrived as one squashed import. Weekly dates before 2026-W40 come from the
> predecessor repository (`ueba-git`), and the Aug–Sep box98 work has no commit
> trail at all. Absence of a commit is not absence of work.

## Headline status

| | Count |
|---|---|
| Feature areas **implemented** (verifiable in source) | ~15 |
| Feature areas with **reproducible tests in the repository** | **0** |
| Feature areas **deployed and running** | **0** |

The distance between those three numbers is the honest status of the project.

## Completed work

### 2026-W14 (30 Mar – 3 Apr) — project start · Git

First commit 2026-03-30. Initial engine, dashboard skeleton, README. Dashboard
port settled at 3026. **VERIFIED COMPLETE**

### 2026-W20 – W22 (15 – 30 May) — dashboard becomes a product · Git

Vite build, live SSE, analyst workflow, keyboard navigation. False-positive
auto-suppression patterns introduced — the mechanism behind today's 204 patterns.
Weekly retrain wrapper. Engine-level FP feedback loop. **VERIFIED COMPLETE**

### 2026-W23 – W27 (2 Jun – 30 Jun) — surviving the data volume · Git

Highest-activity period (34 commits). 500k alert cap with lazy-loaded evidence;
timeline windowing; FAISS moved to CPU to free the shared GPU; "calm"
re-architecture; rolling 30-day corpus prune; instant-load dashboard
rearchitecture. **VERIFIED COMPLETE**

### 2026-W28 – W31 (10 – 28 Jul) — making retraining trustworthy · Git

Staged retrain with a pre-deploy validation gate (PR #1). Race-free alert writes
and read-offset persistence on shutdown (PR #2). Autoencoder threshold
calibration on a held-out split with a floor, fixing a retrain that flooded the
console. **VERIFIED COMPLETE**

### 2026-W33 (11 Aug) — corpus integrity · Git

Retrain no longer re-runs L1/L2 enrichment over already-enriched events — root
cause of corpus poisoning. Entity URL-junk guard. **VERIFIED COMPLETE**

### 2026-W35 – W36 (late Aug) — throughput · Record, not Git

Event batching (70 → 208 events/sec) and the sync-bridge rewrite (20 min → 39 s
per chunk). Dated in project memory and `docs/ARCHITECTURE.md`; no commit trail —
developed directly on box98. **VERIFIED COMPLETE (source), UNVERIFIED (date)**

### 2026-W39 (21 – 23 Sep) — RFP push · Record, not Git

Watch lists, audit trail, XML export, reporting engine, notifications, search
suggest. Modules confirmed present by inspection; dates from project memory only.
**PARTIALLY COMPLETE** — see the RFP table below for the dependency gap.

### 2026-W40 (29 – 30 Sep) — repository, RBAC, auth · Git

Nine commits. The week the code left one laptop.

| Commit | Work | Status |
|---|---|---|
| `5e51182` | Initial import to the organisation repository | **VERIFIED COMPLETE** |
| `7e54d33` | Hover overlay + globe hit-testing fixes | **PARTIALLY COMPLETE** — never visually confirmed |
| `55e15f9` | RFP compliance tracker | **VERIFIED COMPLETE** |
| `2e1171d` | RFP 23 role-based dashboards | **PARTIALLY COMPLETE** — enforcement off |
| `b702af9` | Local password accounts | **VERIFIED COMPLETE (source)** |
| `0f88840` | Watchdog forensics fix | **VERIFIED COMPLETE (source)** |
| `cd90de2` | Login gate + Settings page | **VERIFIED COMPLETE (source)** |
| `389e503` | Drilldown payload cap (673 MB → 3 MB) | **VERIFIED COMPLETE** |
| `b11d1fa` | Architecture and onboarding guide | **VERIFIED COMPLETE** |

### 2026-W42 (13 Oct) — rebuild preparation · Git

`5ce579e`. box98 decommissioned. Three silent failures found and fixed in the
install path: `ueba_rotate.sh` and the watchdog both resolved a hardcoded dead
path, and the installer never installed the watchdog at all. Rebuild runbook
written. **VERIFIED COMPLETE (source)**

## Verified detail — RBAC and authentication

| Item | Status | Evidence |
|---|---|---|
| 23 `@_require_cap` route gates | **VERIFIED COMPLETE** | Source, count confirmed |
| Zero ungated mutating routes | **VERIFIED COMPLETE** | Scan of all POST/PUT/PATCH/DELETE routes |
| 4 admin routes via `@require_role` | **VERIFIED COMPLETE** | `ueba_auth.py:1019,1029,1056,1098` |
| `CAPABILITIES` table, 11 entries, 3 tiers | **VERIFIED COMPLETE** | Source |
| Local login, password change, user CRUD | **VERIFIED COMPLETE** | 11 routes in `ueba_auth.py` |
| scrypt hashing, lockout, no default credentials | **VERIFIED COMPLETE** | Source |
| CLI: 7 subcommands incl. `check` | **VERIFIED COMPLETE** | Source |
| `ALWAYS_PUBLIC` lockout guard | **VERIFIED COMPLETE** | Source |
| Settings page, login overlay | **VERIFIED COMPLETE** | 277 + 95 lines, tab wired |
| **Enforcement active anywhere** | **PENDING** | `ueba_config.yaml:387` `enforce: false` |
| **An admin account existing** | **PENDING** | `ueba_auth.py check` last reported NOT SAFE |

**Known inconsistency:** `users.manage` appears in `CAPABILITIES` but has no
`_require_cap` gate — those routes use `@require_role("admin")` directly. Enforced,
but by a second mechanism the table does not reflect.

## RFP position

**No claim of full RFP compliance is made.**

| # | Requirement | Status |
|---|---|---|
| 1 | Watch lists | **VERIFIED COMPLETE** |
| 10 / 15 | Device registry, proactive alerting | **VERIFIED COMPLETE** |
| 28 | Auto-complete / suggest | **VERIFIED COMPLETE** |
| 65 | Audit trail | **VERIFIED COMPLETE** |
| 34 / 39 | Export — XML, CSV, JSON, HTML | **VERIFIED COMPLETE** |
| 34 / 39 | Export — **PDF and Excel** | **PARTIALLY COMPLETE** — see blocker R1 |
| 35 / 36 / 37 / 38 / 40 / 62 | Reports | **PARTIALLY COMPLETE** — same blocker for PDF/XLSX output |
| 23 | Role-based dashboards | **PARTIALLY COMPLETE** — built, not enforced |
| 7, 27, 29, 48, 60, 70 | Scoped admin, NL search, netflow, temporal rules, protocol decode, entity mapping | **PENDING** |
| 21, 32, 44, 46, 47, 69 | Supervised ML, HA, peer groups, sequence misuse, HTTP leakage, day-1 profiling | **PENDING — blocked** on data, scope or architecture |

## In progress

| Item | Status | Note |
|---|---|---|
| Utho server rebuild | **IN PROGRESS** | Runbook ready; awaiting server access |
| Confidential project record (`.docx`) | **IN PROGRESS** | Untracked; gitignore-vs-commit decision outstanding |
| Engine stall root cause | **IN PROGRESS** | Diagnostics fixed; cause not identified |

## Pending — next priorities

1. **Add `reportlab` and `openpyxl` to `requirements.txt`.** Two lines. Without
   them the reporting engine ships with two advertised formats that fail at
   runtime. Highest value per unit effort in the project.
2. **Decide `auth.enforce` and the dashboard bind address** before the console is
   exposed on the new server.
3. **Create a `tests/` directory.** The RBAC and local-auth suites existed and
   passed during development but were never committed. Recreating them converts
   the largest block of UNVERIFIED entries into standing evidence.
4. **Re-verify the globe and hover fixes visually** on the new deployment.
5. **`torch.load(weights_only=True)`** in `ueba_models/autoencoder.py:160`.
6. **Remove 1,267 lines of orphaned modules** never imported by anything
   (7 files, counted 2026-10-21).
7. **Engine stall root cause** — awaits a stall under the fixed watchdog.

## Testing and validation status

| | |
|---|---|
| Test files in the repository | **0** |
| CI configuration | **None** (`.github/` absent) |
| Test framework configuration | **None** |

The committed `docs/check_*.py` files validate the **PowerPoint deck** geometry,
fonts and coverage. They do not test any UEBA functionality.

Functional verification performed during development — RBAC gate denial,
local-auth behaviour, coordinate conversion, globe hit-test geometry, HTTP login
round-trip — was executed as throwaway scripts on box98. Those results were sound
at the time but **no artifact survives and none is reproducible**. Every item
depending on them is classified UNVERIFIED above.

## Deployment status and blockers

**Status: ON HOLD. No instance of this system is running.**

Blocker IDs match `docs/MONTHLY_RELEASE_HISTORY.md`.

| ID | Blocker | Owner |
|---|---|---|
| **D1** | Previous server (box98) permanently closed — verified unreachable 2026-10-13 | Closed, permanent |
| **D2** | Replacement Utho server shuts down overnight, preventing 24/7 operation. Reported by the project owner; not independently verified | External |
| **D3** | 24/7 Utho deployment — depends on D2 | External |
| **D4** | SIEM-side details for `10.200.10.23` — SSH user and enriched-log path | External |
| **D5** | No admin account exists; `auth.enforce` cannot be enabled safely | Engineering |
| **R1** | `reportlab` / `openpyxl` missing from `requirements.txt` | Engineering |
| **R2** | Restore bundle exists on a single laptop | Operations |

Server access has not been confirmed to engineering as of 2026-10-21.

### What survived the decommission

| Asset | State |
|---|---|
| Source code | Safe — pushed 2026-09-29, two weeks before the host was lost |
| 204 analyst false-positive patterns | Safe — local copy |
| 453 autoencoders + Isolation Forest + scaler + thresholds | Safe, dated **2026-08-16** |
| User profile database, alert history, agent registry | Safe |
| 190 GB training corpus | **Lost** — re-accumulate or seed from SIEM history |
| `features.h5`, FAISS index, alert archive, auth database | **Lost** — regenerate |

Models are eight weeks stale and cover 453 entities where production had 543.
Roughly 90 entities will fall back to the global model until the first retrain.

## Requires confirmation

These cannot be resolved from the repository and need a human answer.

1. **Does `10.200.10.23` retain historical enriched logs?** Determines whether the
   first retrain happens in days or 21 days.
2. **Utho server specifications** — sizing guidance is in `README.md`; RAM is driven
   by the retrain, not detection.
3. **Original business driver for the project.** Not recorded in any repository.
   Section "Origins" of the confidential record reconstructs intent from commits.
4. **Aug–Sep 2026 milestone dates** — throughput, bridge rewrite and the RFP push
   have no commit trail. Dates above come from project memory alone.
5. **Whether the globe and hover fixes actually work.** Shipped, never confirmed.
6. **Confidential `.docx`** — commit to the repository or keep local only.
7. **Three predecessor repositories** still contain 453 model files named after
   real users, one on a personal account. A decision was taken to leave them;
   confirm that still stands.
