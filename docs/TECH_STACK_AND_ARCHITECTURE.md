# CyberSentinel UEBA — Technology Stack and Architecture

Reference description of the system **as implemented**, compiled 2026-10-21 from
source inspection. Every rationale is either cited to evidence in the repository
or marked as inferred.

**Companion documents.** `docs/ARCHITECTURE.md` is the onboarding walkthrough —
read that first if you are new. This document is the evidence-backed reference:
component responsibilities, why each technology is present, and where the
limitations are. `docs/DEPENDENCY_AUDIT.md` covers versions and advisories.

**Scope note.** No architecture is proposed or redesigned here. Current
implementation and proposed improvements are kept in separate sections and
labelled. No performance claim appears without a citation to a measurement
recorded in the repository.

---

## 1. Architecture

Two hosts. UEBA consumes already-enriched events from CyberSentinel SIEM and
sends only alerts back.

```
┌─ SOC host ────────────────┐        ┌─ UEBA host ────────────────────────┐
│ CyberSentinel SIEM        │        │ ueba-bridge   (systemd)            │
│  collection               │  SSH   │      │ pulls .jsonl.gz chunks      │
│  correlation              │ tunnel │      ▼                             │
│  Kafka enrichment         ├───────►│ enriched.jsonl  (append-only)      │
│  → enriched_*.jsonl.gz    │        │      │                             │
│                           │        │      ▼                             │
│ Analyst browsers          │        │ ueba-engine   (systemd)            │
│        │                  │        │      │                             │
│        └──────────────────┼───────►│ ueba-dashboard (systemd, :3026)    │
│                           │        │      ▲                             │
│                           │        │ ueba_alerts.jsonl                  │
└───────────────────────────┘        └────────────────────────────────────┘
```

**Why split across two hosts** — *inferred, not documented.* The repository
records the split as fact but no commit or comment states the decision. The
plausible reasons (GPU availability, 190 GB corpus, SOC host load) are consistent
with the code but not evidenced. See §9, item U1.

### Component responsibilities

| Component | File | Responsibility |
|---|---|---|
| Sync bridge | `ueba_sync_bridge.sh` (322 lines) | Pulls rotated and live enriched chunks from the SOC host; appends to `enriched.jsonl` |
| Engine | `ueba_engine.py` (1,166) | Tails the feed, scores every event, writes alerts. Single process |
| Preprocessor | `ueba_preprocessor.py` (1,372) | Feature extraction, noise rules, entity profile store |
| Isolation Forest | `ueba_models/isolation_forest.py` (151) | Global outlier scoring |
| Autoencoder | `ueba_models/autoencoder.py` (246) | Per-entity behavioural deviation |
| Clusterer | `ueba_models/clusterer.py` (346) | HDBSCAN campaign grouping, own thread |
| FP suppressor | `ueba_models/fp_suppressor.py` (210) | Analyst-taught pattern suppression |
| Watch list | `ueba_watchlist.py` (220) | Pre-fusion score boost for flagged entities |
| Dashboard server | `ueba_dashboard_server.py` (4,652) | 52 API routes, SPA host, caching |
| Auth | `ueba_auth.py` (1,400) | SSO, local accounts, sessions, roles, admin CLI |
| Reporting | `ueba_reports.py` / `_render.py` / `_store.py` (1,758) | Report content, renderers, scheduling |
| Notifications | `ueba_notify.py` (501) | Device registry, rules, dispatcher |
| Trainer | `ueba_trainer.py` (792) | Isolation Forest + per-entity autoencoders |
| Watchdog | `ueba-engine-watchdog.sh` (195) | Stall detection, forensics, conditional restart |

---

## 2. Technology stack and why

Evidence column distinguishes documented rationale from inference.

| Technology | Purpose | Why — and evidence |
|---|---|---|
| **Python 3.10+** | Backend | Floor is 3.10 (8 modules use `X \| None` without `__future__`). Deployment target is 3.12. **Undeclared** — no `python_requires` |
| **Flask** | API + SPA host | Synchronous, small. *Rationale inferred* |
| **orjson** | JSON on the hot path | **Documented, measured:** *"parses JSON ~2.5x faster than the stdlib (measured on real archives: 6.4s → 2.6s per day-file)"* — `ueba_dashboard_server.py:37-38`. Falls back to stdlib transparently |
| **scikit-learn** | Isolation Forest | Imported only in the trainer, but **required at runtime**: `isolation_forest.py:65` unpickles an sklearn estimator via `joblib.load()` |
| **PyTorch (CPU build)** | Autoencoders | **Documented, measured:** *"the per-entity autoencoder trains in 0.14s on one CPU thread vs 0.5s on a shared L40S, and 99% of a retrain is disk I/O rather than compute. The CUDA wheels are ~2.5 GB and buy nothing here"* — `install_ueba.sh:478-481` |
| **HDBSCAN** | Campaign clustering | Density clustering without a preset cluster count. *Rationale inferred* |
| **FAISS (CPU)** | Similar-anomaly retrieval | **Documented:** *"cpu frees the shared GPU"* — `ueba_config.yaml:199` |
| **HDF5 / h5py** | Training feature store | Holds `features.h5`. *Rationale inferred* |
| **SQLite ×2** | Identity; entity profiles | **Documented:** auth is a *"separate DB from profiles/user_profiles.db on purpose: that one holds behavioural baselines … rewritten by the engine at speed. Identity has a different lifecycle, a different blast radius, and different backup needs"* — `ueba_auth.py:271-274` |
| **JSONL + zip archives** | Alert store | Append-only, crash-tolerant. *Rationale inferred.* See §8 L1 |
| **PyJWT** | SSO tokens | HS256 only; RS256/JWKS written but unreachable — `ueba_auth.py:9-14,126-127` |
| **Vanilla JS + Vite** | Dashboard | One runtime dependency (`globe.gl`). *Rationale inferred* |
| **globe.gl / three.js** | Threat map | Only browser-shipped dependency |
| **bash + SSH + gzip** | Transport | No broker. *Rationale inferred.* See §8 L2 |
| **systemd + cron** | Process management | 4 units + 2 cron jobs |

### A correction worth recording

Earlier project guidance described the GPU as "optional, shortens retraining."
The measurement recorded in `install_ueba.sh:478-481` does not support that: on
the lab hardware CPU training was **faster** than a shared L40S (0.14s vs 0.5s
per entity), and the installer deliberately installs CPU-only wheels. The likely
explanation is contention on a shared GPU rather than a property of the hardware,
but **the only measurement in the repository says CPU won**. Treat GPU as not
required, and do not assume it would help without re-measuring.

---

## 3. Event processing and anomaly detection

Per-event path, verified in `ueba_engine.py`.

1. **Ingest.** Bridge appends to `enriched.jsonl`. Engine tails from a saved
   offset (`.state/ueba.state`), reads in chunks, retains the partial final line.
2. **Feature extraction.** 35-dimension vector plus metadata. A failure here is
   treated as an unusable event, not an error, and is skipped.
3. **Layer 1 — Isolation Forest**, scored **once per batch** (`_process_batch`).
   The code documents the reason: per-row scoring spent ~96% of the budget inside
   sklearn's fixed per-call cost.
4. **Layer 2 — Autoencoder**, one model per entity (`:689`). Identity resolution
   maps aliases first. Below `min_events_per_user: 2000` an entity falls back to
   the global model. 100 models held in memory.
5. **Watch list**, consulted **before** fusion so a flagged entity's threshold is
   genuinely lowered rather than its alerts relabelled.
6. **Fusion** — `0.5 × IF + 0.5 × AE`, plus any watch boost, clipped to 0–1.
   Alert threshold **0.75**. Pre-boost `model_score` is retained separately.

   | Score | Verdict | Confidence |
   |---|---|---|
   | < 0.75 | discarded, nothing written | — |
   | 0.75–0.85 | suspicious | low |
   | 0.85–0.93 | anomalous | medium |
   | ≥ 0.93 | highly anomalous | high |

7. **Enrichment** of survivors: profile update, FAISS retrieval of similar past
   anomalies (`:727`), queue for clustering.
8. **Suppression**, two gates: `is_noise()` rules, then analyst-taught FP
   patterns (`:931-951`).
9. **Write** to `ueba_alerts.jsonl`.
10. **Layer 3 — campaigns**, asynchronously. HDBSCAN on the anomaly buffer every
    **900 s**, then campaign IDs patched back into the alert file. The interval
    carries a documented reason for being raised from 300 s: *"each pass rewrites
    the whole alerts file"* — `ueba_config.yaml:168`. A consequence is that the
    main loop must reopen its file handle, because the atomic swap replaces the
    inode.

**Discard rate.** Production logs recorded alert rates of 0.04%–0.09%, so roughly
999 in 1,000 events ended at step 6. That figure comes from historical log lines,
not from a current measurement — nothing is running.

---

## 4. Models, training and retrieval

### Model inventory

| Model | Scope | Shape |
|---|---|---|
| Isolation Forest | one global | sklearn, `isolation_forest.pkl` |
| Autoencoder | one per entity | 35→24→12→24→35, ~2,000 parameters |
| HDBSCAN | over anomalies | `min_cluster_size: 5`, `min_samples: 3` |
| FP suppressor | analyst patterns | 204 patterns currently |

**Why hybrid rather than per-entity everywhere.** The global forest pools data
across the estate; the per-entity autoencoder answers whether an action is
unusual for that entity specifically. The `min_events_per_user: 2000` floor with
global fallback exists because sparse entities cannot support a personal
baseline. *This reasoning is inferred from the code structure; no commit states
it.*

### Training and retraining

Weekly, `ueba_weekly_retrain.sh` via cron (Sunday 03:30):

```
prune corpus → pull chunks → append to corpus → prune again
   → ueba_prepare_training_data.py → features.h5
   → ueba_trainer.py  (Isolation Forest + per-entity autoencoders)
   → ueba_validate_models.py  (refuses to promote a regression)
   → swap models/
```

Two prunes, before and after the append, is deliberate: a before-only prune
leaves the newly appended week untrimmed.

Autoencoder thresholds are calibrated on a **held-out split with a floor**. The
floor exists because a quiet entity would otherwise receive a threshold near zero
and alert on everything.

### Feature storage — current

`features.h5` (HDF5), rebuilt from the raw corpus on every retrain. Feature
vectors computed during live scoring are **discarded**, then recomputed from raw
events at retrain time.

### FAISS retrieval

`rag.inference_device: cpu`, `top_k: 5`, `min_similarity: 0.60`,
`max_index_size: 7,000,000`, trainer seeds to 80% of that ceiling. Retrieval runs
only for events that passed the alert threshold, attaching `similar_past_events`
as evidence.

---

## 5. APIs, authentication, RBAC, dashboard, storage

### API

52 routes in `ueba_dashboard_server.py`, plus 11 in `ueba_auth.py`. Largest
groups: reports (12), notify (4), false-positive (4), watchlist (3), devices (3).

Two conventions are load-bearing:

- **Every data endpoint is scoped by `?hours=N`** (`0` = All, bounded by
  `history_days`). Two endpoints missing this returned 673 MB / 1,139,873 rows
  before being capped — `ueba_dashboard_server.py:2560-2575`.
- **Alert rows never carry evidence blobs.** Caches hold slim records; evidence is
  lazy-loaded per row via `/api/evidence` on expand.

### Authentication and RBAC — implemented, not enforced

| Mechanism | State |
|---|---|
| SSO (HS256 JWT from the SIEM) | Implemented |
| Local password accounts (stdlib scrypt, lockout, CLI-only bootstrap) | Implemented |
| `CAPABILITIES` table, 11 entries, viewer/analyst/admin | Implemented |
| 23 `@_require_cap` route gates + 4 `@require_role("admin")` | Implemented |
| Ungated mutating routes | **0** |
| **Enforcement** | **Off** — `ueba_config.yaml:387` `enforce: false` |

`require_role` returns early when `enforce` is false, so every gate is currently
a no-op. The dashboard binds `0.0.0.0:3026`.

### Dashboard

Vanilla ES modules, 49 files / 8,891 lines JS + 4,709 CSS, built by Vite into
`dashboard/dist/` and served by Flask. The whole UI renders inside
`html { zoom: var(--ui-scale) }`, which splits geometry into visual and layout
pixel spaces; `dashboard/src/ui/ui-scale.js` mediates and is consumed by 9
modules.

### Data storage

| Store | Format | Holds |
|---|---|---|
| `enriched.jsonl` | JSONL, append-only | Inbound events |
| `ueba_alerts.jsonl` + `archive/*.zip` | JSONL | Alerts and history |
| `profiles/user_profiles.db` | SQLite | Behavioural baselines |
| `ueba_auth.db` | SQLite | Identity, sessions |
| `models/` | pickle + `.pt` | Trained models |
| `vector_db/` | FAISS index + JSONL metadata | Similarity retrieval |
| `data/features.h5` | HDF5 | Training features |
| `fp_patterns.json`, `watchlist.json`, `agents.json` | JSON | Analyst-curated state |
| `.state/ueba.state` | JSON | Engine read offset |

No relational database and no message broker.

---

## 6. Background services, scheduling, transport

### systemd units

| Unit | Type | Role |
|---|---|---|
| `ueba-bridge` | simple | Pulls enriched chunks |
| `ueba-engine` | simple | Scoring loop |
| `ueba-dashboard` | simple | API + SPA |
| `ueba-engine-watchdog.timer` | oneshot, 2 min | Stall detection |

### In-process threads

- **Engine:** one — the campaign detector (`ueba_engine.py:851`).
- **Dashboard:** five — agent-sync, archive cache warm, result cache warm,
  notification dispatcher, report scheduler.

### Scheduling

```
5 0 * * *   ueba_rotate.sh           # rotation and retention
30 3 * * 0  ueba_weekly_retrain.sh   # full retrain
```

### Transport

SSH + gzip file transfer. The engine resumes from `.state/ueba.state`. **No
message broker, no acknowledgement protocol, no replay** beyond the offset file.

---

## 7. Watchdog and stall handling

The engine has stalled roughly twice daily. Observed signature: main thread `R`
(on CPU), other threads idle, flat RSS, zero swap — spinning, not deadlocked or
blocked on I/O. **Root cause is not identified.**

The watchdog writes forensics, waits `CONFIRM_SECS=240`, and restarts only if the
engine is still frozen. The confirmation window exists because stalls were
observed to self-resolve; restarting immediately discarded a warm model cache for
no benefit.

Three hypotheses are **disproved by measurement** and should not be re-chased:
memory leak (RSS flat), throughput degradation (the `rate` field is a lifetime
average), and `_patch_campaign_ids` holding the alert write lock (13 MB / 1,357
lines parses in 0.1 s).

---

## 8. Known limitations and technical debt

Current state. Nothing here is a proposal.

| ID | Limitation | Evidence |
|---|---|---|
| **L1** | Alerts in flat JSONL with no index — every query is a file scan | `ueba_dashboard_server.py`, 13 `load_alerts()` call sites |
| **L2** | Transport is a file copy over SSH with a self-managed offset; no broker, no replay | `ueba_sync_bridge.sh` |
| **L3** | Single engine process; Python GIL caps single-process throughput | One scoring loop |
| **L4** | SQLite for identity → no HA. This is RFP 32 | `ueba_auth.py` |
| **L5** | **No tests, no CI** — 0 test files across ~15,600 lines of Python | `.github/` absent |
| **L6** | No metrics endpoint; health assessed by reading a log line whose `rate` field is a lifetime average | No `/metrics` route |
| **L7** | RBAC implemented but inert; no admin account exists | `ueba_config.yaml:387` |
| **L8** | Feature extraction runs twice — live scoring then retrain | §4 |
| **L9** | No model registry or rollback; a validation gate exists but no version history | `ueba_validate_models.py` |
| **L10** | No feature schema versioning — a SIEM event-shape change degrades detection silently | No version field |
| **L11** | `reportlab` / `openpyxl` missing from `requirements.txt` while PDF/XLSX are advertised | `ueba_report_render.py:519` |
| **L12** | 1,267 lines of orphaned modules never imported | 7 files, counted 2026-10-21 |
| **L13** | `torch.load` without `weights_only=True` | `ueba_models/autoencoder.py:160` |
| **L14** | Entity names used as model filenames — leaks usernames, forces `models/` to be gitignored | `models/autoencoders/` |
| **L15** | Identity resolution is a hand-maintained alias map; unlisted aliases split a baseline silently | `ueba_config.yaml:510` |
| **L16** | Payload caps truncate silently — analysts are not told a list was cut | §5 |

---

## 9. Optimization opportunities — PROPOSED, not implemented

**None of this is built.** Each item states what is known and what is not.

| ID | Opportunity | Expected effect | Confidence |
|---|---|---|---|
| **O1** | Persist feature vectors per entity at scoring time instead of recomputing at retrain | Removes the second extraction (L8) and the `/dev/shm` unpack | **Mechanism certain; magnitude not measured.** Estimates derived from corpus size, not benchmarked |
| **O2** | Move alerts to an indexed store | Removes full-scan queries (L1) | Direction clear; no benchmark |
| **O3** | Consume the SIEM's Kafka directly | Removes the bridge, offset file and that outage class (L2) | Mechanism certain; operational cost not assessed |
| **O4** | Shard scoring by entity across processes | Addresses the GIL ceiling (L3) | **Untested.** No measurement of current single-process capacity beyond the historical 208 events/sec peak |
| **O5** | Drift-triggered retraining instead of full weekly | Shortens retrains | Depends on O1 |
| **O6** | Add a test suite | Enables safe refactoring (L5) | Certain |
| **O7** | Metrics endpoint (L6) | Replaces log-reading | Certain |

**No claim is made that the current architecture is optimal.** It has not been
benchmarked against alternatives, and the figures available are production
observations from a decommissioned host rather than controlled measurements.

The sizing and scaling projections circulated earlier are **linear extrapolations
from a single deployment**, not measurements. They should be treated as planning
estimates and re-derived once the target event volume is known.

---

## 10. Unverified and open

| ID | Item |
|---|---|
| **U1** | Why the two-host split was chosen. Not recorded anywhere |
| **U2** | Why Flask, HDBSCAN, HDF5 and JSONL were chosen over alternatives — no ADRs exist |
| **U3** | Engine stall root cause |
| **U4** | Whether the globe and hover fixes work — shipped, never visually confirmed |
| **U5** | Current performance. Nothing is running; all figures are historical |
| **U6** | Whether a fresh dependency install resolves to a working set (see `DEPENDENCY_AUDIT.md`) |

There are no architecture decision records in this repository. Section 2 marks
inferred rationale as such rather than presenting reconstruction as fact.
