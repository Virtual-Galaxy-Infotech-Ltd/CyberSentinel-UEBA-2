# CyberSentinel UEBA — Release History

Compiled 2026-10-21 from Git history, code inspection and project records.

## Important: no formal release process exists

Before reading any entry below, understand what this project does and does not have.

| | State |
|---|---|
| Git tags | **0** in both repositories |
| Version scheme for the engine, dashboard server or auth module | **None** |
| Release artifacts, changelog or release notes | **None** |
| Build or release pipeline | **None** (`.github/` absent) |
| Production deployment | **None** — no instance is running |

The only version string anywhere is `"version": "0.2.0"` in
`dashboard/package.json`, which is a private npm package marker. It is **not** a
release version, has never been tagged, and does not correspond to any deployment.

**Therefore: this document records code changes, not releases.** No release
version, release date or production deployment is claimed for any month, because
none can be verified.

---

## October 2026

### Summary

**No release occurred. No deployment occurred. No automated tests were run.**

One commit landed, containing bug fixes and documentation. Two documents were
produced but remain uncommitted. The production host was lost at the start of the
month and its replacement is not yet able to run continuously.

### Verified change — 2026-10-13

| | |
|---|---|
| **Commit** | `5ce579eb745eac7ee255518c4875e70aab71a3ea` (`5ce579e`) |
| **Timestamp** | 2026-10-13 12:31:28 +0530 (Git) |
| **Version / tag** | **None** — not tagged, not released |
| **Scope** | 5 files, +294 / −3 |
| **Deployed** | **No** — no host available |

**Subject:** Prepare for rebuild on a new server after box98 decommission

**Fixes.** Three defects in the install path, each of which would have failed
silently on a new host:

1. `ueba_rotate.sh` resolved a hardcoded `/root/NEW_DRIVE/aditya_ueba` with no
   environment fallback. Cron would have invoked it against a non-existent path,
   so log rotation would never run. Rotation failure is the documented cause of
   the September disk-exhaustion outage.
2. `ueba-engine-watchdog.sh` carried the same hardcoded path — a stalled engine
   would never have been detected on a new install.
3. `install_ueba.sh` never installed the watchdog at all. Added `install_watchdog()`
   creating the service and a 2-minute timer, armed only after the engine starts,
   and passing `UEBA_SITE_ENV` explicitly because the script is installed to
   `/usr/local/bin` and otherwise looks for its site file beside itself.

**Other changes.** `.gitignore` extended to exclude `*-state-restore-*.tar.gz`
(state bundles carry autoencoder filenames, which are real usernames).
`docs/REBUILD_RUNBOOK.md` added, 223 lines.

**Files:** `install_ueba.sh` (+51), `ueba-engine-watchdog.sh` (+9/−3),
`ueba_rotate.sh` (+9/−3), `docs/REBUILD_RUNBOOK.md` (+223), `.gitignore` (+5).

#### Tests performed and actual results

Honest record. No test suite exists in this repository.

| Check | Method | Result |
|---|---|---|
| Shell syntax, patched scripts | `bash -n` | **Passed** |
| `UEBA_BASE` resolution present | Source inspection | **Passed** — all four ops scripts |
| Installer syntax after edit | `bash -n install_ueba.sh` | **Passed** |
| Restore bundle integrity | `tar` listing, file counts | **Passed** — 453 models, 204 patterns |
| `global.pt` present | File check | **Passed** — bring-up gates on this file |
| Watchdog executed against a stalled engine | — | **NOT TESTED** — no host |
| Installer executed end to end | — | **NOT TESTED** — no host |
| Rotation executed | — | **NOT TESTED** — no host |

**Nothing in this change has been executed on a running system.** Verification was
static: syntax checking and source inspection only.

### Uncommitted work — October

| Item | Date evidence | State |
|---|---|---|
| `docs/CyberSentinel_UEBA_Confidential_Project_Record.docx` | File mtime 2026-10-13 | Untracked; commit-vs-local decision outstanding |
| `docs/WEEKLY_MILESTONES.md` | File mtime 2026-10-21 | Untracked |
| `docs/MONTHLY_RELEASE_HISTORY.md` | This document | Untracked |

### Known issues — open at month end

| ID | Issue | Status |
|---|---|---|
| K1 | Engine stall, roughly twice daily | Root cause **not identified**. Diagnostics repaired 2026-09-29; no stall captured since |
| K2 | `reportlab` and `openpyxl` absent from `requirements.txt` | PDF and Excel export advertised in `ueba_report_render.py:519` but fail on a clean install |
| K3 | RBAC implemented, enforcement disabled | `ueba_config.yaml:387` `enforce: false`; no admin account exists |
| K4 | Globe and hover fixes never visually confirmed | Shipped 2026-09-29/30; host lost before confirmation |
| K5 | No test suite, no CI | 0 test files across ~15,600 lines of Python |
| K6 | `ARCHITECTURE.md` states 543 autoencoders | 453 present on disk |

---

## Deployment status — ON HOLD

**No CyberSentinel UEBA instance is running in production or anywhere else.**

### Blockers

| ID | Blocker | Evidence | Status |
|---|---|---|---|
| **D1** | **Previous server (box98) permanently closed.** Host decommissioned; SSH unreachable from 2026-10-13 (`Operation timed out`, port 22 refused). All runtime state on it is gone except the local restore bundle. | Verified — connection attempts failed during inspection | **Confirmed, permanent** |
| **D2** | **Replacement Utho server shuts down overnight.** The new host does not stay up continuously, which prevents UEBA running as a 24/7 service. UEBA requires continuous operation: the bridge ingests constantly, the engine tails an append-only feed from a saved offset, and cron jobs run at 00:05 daily and 03:30 Sunday — all of which an overnight shutdown interrupts. | **Reported by the project owner.** Not independently verified — no access to that host | **Open — cause unconfirmed** |
| **D3** | 24/7 Utho deployment | Depends on D2 | **PENDING** |
| **D4** | SIEM-side details for `10.200.10.23` — SSH user and enriched-log path | Required by installer stage 4 | **PENDING** |
| **D5** | No admin account; `auth.enforce` cannot be enabled safely | `ueba_auth.py check` reported NOT SAFE | **PENDING** |

### Impact of D2 on the schedule

Until the overnight shutdown is resolved, a deployment would produce an engine
that stops and restarts daily. Consequences, in order of severity:

1. **Ingestion gaps.** The bridge is not running while the host is down; events
   accumulate on the SIEM side and the feed falls behind.
2. **Missed scheduled jobs.** Rotation (00:05) and the weekly retrain (03:30
   Sunday) fall inside a likely shutdown window.
3. **Cold model cache on every start.** The engine holds 100 autoencoders in
   memory; each restart discards them.
4. **Stall diagnosis blocked.** K1 needs the engine running continuously long
   enough to stall under the repaired watchdog.

A deployment onto a host with this behaviour is not recommended, and none is
planned until D2 is resolved.

---

## Prior months

Changes before October 2026 are recorded in `docs/WEEKLY_MILESTONES.md` with
per-entry evidence tiers. They are **not** reproduced here as releases, because
no release was ever cut: there are no tags, no versions and no release artifacts
for any month in the project's history.

The repository itself was created 2026-09-29. Roughly five months of prior
development was performed directly on box98 and never committed as it occurred;
it arrived as a single squashed import. Dates for that period rest on project
documentation and memory rather than Git.

---

## Unverified or pending confirmation

1. **Cause of the Utho overnight shutdown** — billing, a provider power schedule,
   an instance policy, or something else. Unknown.
2. **Whether the Utho host can be made to run 24/7**, and on what timescale.
3. **Whether `10.200.10.23` retains historical enriched logs** — determines
   whether the first retrain is days or 21 days away.
4. **Utho server specifications.**
5. **Whether a release process is wanted.** If tagged releases are expected for
   client delivery, none currently exists and one would need to be introduced.
6. **Aug–Sep 2026 change dates** — no commit trail; project memory only.
