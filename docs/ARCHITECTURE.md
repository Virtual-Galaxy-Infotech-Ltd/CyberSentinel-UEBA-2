# CyberSentinel UEBA — Architecture & Onboarding

Everything a new engineer needs to understand this system and start changing it
safely. Read top to bottom the first time; after that use it as a reference.

**What this system does in one sentence:** it reads already-enriched security
events from CyberSentinel SIEM, learns what "normal" looks like per entity, and
raises an alert when behaviour deviates — then clusters related alerts into
campaigns and serves them to analysts through a web console.

**What it is not:** a log collector, a correlation engine, or a SIEM. It consumes
what the SIEM has already normalised and enriched. If a field is not in the
incoming event, UEBA cannot see it.

---

## 1. The two machines

```
┌─ 222 — SOC machine ───────────┐          ┌─ box98 — GPU / engine ─────────────┐
│                               │          │                                    │
│  CyberSentinel SIEM           │   SSH    │  ueba_sync_bridge.sh               │
│    collectors                 │  reverse │       │ pulls .jsonl.gz chunks     │
│    → Kafka enrichment         │  tunnel  │       ▼                            │
│    → enriched_*.jsonl.gz      ├─────────►│  enriched.jsonl   (append-only)    │
│                               │          │       │                            │
│                               │          │       ▼                            │
│  Analysts' browsers           │          │  ueba_engine.py   ← the hot loop   │
│          │                    │          │       │                            │
│          └────────────────────┼─────────►│  ueba_dashboard_server.py (Flask)  │
│                               │          │       ▲                            │
│                               │          │  ueba_alerts.jsonl                 │
└───────────────────────────────┘          └────────────────────────────────────┘
```

**Why split.** Training needs a GPU and ~200 GB of disk; the SOC machine has
neither. The engine runs where the data and the GPU are, and only alerts travel
back. Detection itself is CPU-only — the GPU is used solely by the weekly
retrain.

**box98 is a shared, multi-user box.** Only touch paths under
`/data/aditya_ueba`. Other teams run large jobs on it; expect co-tenant CPU and
disk contention.

---

## 2. Repository map

### Runtime — the live path
| File | Role |
|---|---|
| `ueba_sync_bridge.sh` | Pulls enriched chunks from 222 into `enriched.jsonl` |
| `ueba_engine.py` | **The hot loop.** Tails the feed, scores every event, writes alerts |
| `ueba_preprocessor.py` | Feature extraction, noise rules, user profile store |
| `ueba_models/isolation_forest.py` | Layer 1 — global outlier model |
| `ueba_models/autoencoder.py` | Layer 2 — per-entity behavioural baseline |
| `ueba_models/clusterer.py` | Layer 3 — HDBSCAN campaign grouping (own thread) |
| `ueba_models/fp_suppressor.py` | Suppression from analyst-marked false positives |
| `ueba_watchlist.py` | Watch-list lookup + score boost |

### Serving
| File | Role |
|---|---|
| `ueba_dashboard_server.py` | Flask API + SPA host (~4,600 lines; the big one) |
| `ueba_auth.py` | SSO, local password accounts, sessions, roles, user admin CLI |
| `ueba_reports.py` / `_render.py` / `_store.py` | Reporting engine (content / renderers / scheduling) |
| `ueba_notify.py` | Device registry, notification rules, dispatcher |
| `dashboard/` | Vite SPA (vanilla JS modules, no framework) |

### Training
| File | Role |
|---|---|
| `ueba_weekly_retrain.sh` | Orchestrates the Sunday retrain end to end |
| `ueba_prepare_training_data.py` | Corpus → `features.h5` |
| `ueba_trainer.py` | Trains the Isolation Forest + every per-entity autoencoder |
| `ueba_validate_models.py` | Gate: refuses to promote models that regressed |
| `ueba_prune_corpus.py` | In-place corpus trim (`fallocate` COLLAPSE_RANGE) |

### Ops
| File | Role |
|---|---|
| `ueba-engine-watchdog.sh` | Detects a stalled engine, captures forensics, restarts |
| `ueba_rotate.sh` | Log/alert rotation and retention |
| `ueba_housekeeping.py` | Cold-stores orphaned caches, compresses, prunes |
| `deploy/systemd/` | Unit files for engine, dashboard, bridge, watchdog, tunnel |

---

## 3. The journey of one log line

```
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 1. TRANSPORT            ueba_sync_bridge.sh                              │
 │    222: enriched_2026-09-30_12-00-00.jsonl.gz                            │
 │      → box98: appended to enriched.jsonl                                 │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 2. TAIL                 ueba_engine.py run()                             │
 │    read(read_chunk_bytes) → split "\n" → keep partial last line          │
 │    → parse JSON → collect into a BATCH                                   │
 │    Position persisted in .state/ueba.state so restarts resume            │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 3. FEATURE EXTRACTION   ueba_preprocessor.py                             │
 │    event JSON → 35-dim float vector + metadata(user, host, ip, time)     │
 │    Failure here = unusable event, silently skipped (not an error)        │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 4. LAYER 1 — ISOLATION FOREST          ONE global model                  │
 │    "is this weird for ANYONE?"                                           │
 │    Scored ONCE PER BATCH (vectorised). Per-row scoring spent ~96% of     │
 │    the budget in sklearn's fixed per-call cost — do not undo this.       │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 5. LAYER 2 — AUTOENCODER               one model PER ENTITY (543 today)  │
 │    identity_resolution maps aliases → canonical user first               │
 │    "is this weird for YOU?"  reconstruction error = deviation            │
 │    < min_events_per_user (2000) → falls back to the global model         │
 │    100 most-recent models held in RAM (ae_cache)                         │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 6. WATCH LIST           ueba_watchlist.py                                │
 │    Looked up BEFORE fusion, so a flagged entity's bar to become an       │
 │    alert genuinely drops — it does not merely relabel existing alerts.   │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 7. FUSION               fuse_scores()                                    │
 │    combined = 0.5*IF + 0.5*AE  (+ watch_boost), clipped 0..1             │
 │    model_score keeps the PRE-boost value for auditability                │
 │                                                                          │
 │      < 0.75  → DISCARDED SILENTLY   ◄── ~99.9% of all events end here    │
 │    0.75-0.85 → suspicious        (confidence low)                        │
 │    0.85-0.93 → anomalous         (confidence medium)                     │
 │      0.93+   → highly_anomalous  (confidence high)                       │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼ survivors only
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 8. ENRICH                                                                │
 │    • profile_store.update()      — baseline stats for this entity        │
 │    • FAISS RAG retrieve()        — similar past anomalies as evidence    │
 │    • campaign_detector.add()     — queued for the next HDBSCAN run       │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 9. SUPPRESSION          two independent gates                            │
 │    a) is_noise()          — known-benign rule patterns (config)          │
 │    b) fp_suppressor       — patterns YOUR ANALYSTS taught it by marking  │
 │                             false positives in the UI                    │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 10. WRITE               ueba_alerts.jsonl  (append)                      │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 11. LAYER 3 — CAMPAIGNS       clusterer.py, SEPARATE THREAD, on interval │
 │    HDBSCAN over the anomaly buffer → campaign ids                        │
 │    _patch_campaign_ids() rewrites the alert file under the write lock    │
 │    ⇒ a fresh alert can show no campaign and gain one minutes later       │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 12. SERVE               ueba_dashboard_server.py → dashboard/ SPA        │
 │    Reads the live alert file + archived zips, applies the timeline       │
 │    window, caches, returns JSON. Evidence is NOT shipped with rows —     │
 │    it is lazy-loaded per row via /api/evidence on expand.                │
 └──────────────────────────────────────────────────────────────────────────┘
```

---

## 4. The 35 features

What the models actually see. Understanding this is the difference between
guessing at detection behaviour and reasoning about it.

| Group | Features |
|---|---|
| **Temporal** (5) | hour, day_of_week, is_weekend, is_business_hours, is_night_shift |
| **Event flags** (4) | is_auth_event, is_network_event, is_file_event, is_process_event |
| **Anomaly flags** (9) | is_brute_force, is_port_scan, is_tor, is_malicious_ip, is_impossible_travel, is_lateral_movement, is_data_exfiltration, is_after_hours, is_high_frequency |
| **Counters** (4) | src_ip_5m, src_ip_1h, user_1h, host_1h |
| **Behavioural** (3) | unique_destinations_1h, unique_ports_1h, recent_failures_5m |
| **Geo** (3) | distance_km, cross_border, cross_continent |
| **Other** (7) | risk_score, rule.level, network_intel.is_cloud, event_category, event_outcome, traffic_direction, user_baseline_deviation |

Autoencoder shape: `35 → 24 → 12 → 24 → 35`, ~2,000 parameters. Deliberately
tiny — one per entity, and there are thousands.

---

## 5. Why three layers

| Layer | Model | Question it answers | Scope |
|---|---|---|---|
| 1 | Isolation Forest | "weird for **anyone**?" | one global model |
| 2 | Autoencoder | "weird for **you**?" | one per entity |
| 3 | HDBSCAN | "are these the **same incident**?" | over anomalies |

The hybrid is intentional. A global model catches estate-wide oddities and works
*because* it pools data. A personal model catches an ordinary action that is
unusual **for that person**. Neither alone is sufficient.

**Do not make the Isolation Forest per-entity.** It needs volume to mean
anything; per-entity forests on sparse users produce confident nonsense.

---

## 6. The training cycle (separate from everything above)

Runs Sundays via cron → `ueba_weekly_retrain.sh`.

```
  prune corpus (before)        keep disk under control
        ▼
  pull new chunks from 222  →  snapshot .jsonl.gz
        ▼
  append to combined_training.jsonl     (21-day rolling corpus, ~190 GB)
        ▼
  prune corpus (after)         ← both prunes matter; see "Gotchas"
        ▼
  ueba_prepare_training_data.py  → data/features.h5   (~51 GB)
        ▼
  ueba_trainer.py    Isolation Forest + 543 autoencoders   (GPU, ~852 min)
        ▼
  ueba_validate_models.py        refuses to promote a regression
        ▼
  swap models/ → engine picks them up
```

**The retrain, not detection, drives RAM sizing.** It decompresses the snapshot
into `/dev/shm`, which peaked at **82 GB**. Steady-state detection needs ~24 GB.

---

## 7. Serving layer

- **API:** Flask, `ueba_dashboard_server.py`. Every data endpoint is scoped by
  `?hours=N` (`0` = All, bounded by `history_days`). Heavy endpoints go through
  a result cache.
- **SPA:** `dashboard/src/`, vanilla JS modules built by Vite into
  `dashboard/dist/`. **Built on box98** (local Python/node differ).
- **Payload discipline:** alert rows never carry evidence blobs; the browser
  lazy-loads them. Endpoints that return per-entity rows must cap at
  `feed_row_cap`. A route that ignores both once returned **673 MB**.
- **Auth:** SSO (HS256 JWT from the SIEM) *and* local password accounts, both
  ending in the same session cookie. Roles `viewer < analyst < admin` gate the
  API via a `CAPABILITIES` table; the UI hides what the role lacks.
  **`auth.enforce` is currently false** — every gate is deliberately inert until
  it is switched on.

---

## 8. Running it

```bash
# services (box98)
systemctl status ueba-engine ueba-dashboard ueba-bridge

# is the engine keeping up?
grep "Stats |" logs/ueba_engine.stdout.log | tail -3

# build the dashboard after a frontend change  (ALWAYS on box98)
cd /data/aditya_ueba/dashboard && npm run build && sudo systemctl restart ueba-dashboard

# accounts
./venv/bin/python3 ueba_auth.py list-users
./venv/bin/python3 ueba_auth.py create-admin --username <name>
./venv/bin/python3 ueba_auth.py check        # safe to enable auth.enforce?
```

Reading the Stats line:
```
Stats | processed: 3200526 | alerts: 1357 (0.04%) | suppressed_noise: 475205 |
suppressed_fp: 6974 | errors: 0 | rate: 50/sec | ae_cache: 100 | rss: 19.8GB
```
`rate` is a **lifetime average**, not current throughput. A falling number does
not mean the engine is slowing down.

---

## 9. Gotchas — hard-won, do not relearn these

1. **`archive/*.slimN` is a live cache, not stale data.** Deleting it forces a
   full cache rebuild.
2. **`rate` is a lifetime average.** See above.
3. **Engine "stalls" are transient.** It pauses minutes, then resumes by itself.
   Forensics land in `logs/watchdog/stall_*.log`; stacks in
   `logs/engine_stacks.log` (`kill -USR1 <pid>`). Healthy baseline: main thread
   parked at the `time.sleep(poll_ms)` in the no-new-data branch.
4. **Corpus prune runs before *and* after the append.** Before-only leaves the
   newly appended week unpruned and the disk fills.
5. **Every data endpoint must pass `?hours=`.** Without it the window is "All",
   bounded only by `history_days` (95 days).
6. **Build the frontend on box98.** Local toolchain versions differ.
7. **`html { zoom: 0.8 }` splits coordinate space.** `getBoundingClientRect()`
   and `clientX` are *visual* px; `offsetWidth` and `style.left` are *layout* px.
   Mixing them misplaces overlays. Use `dashboard/src/ui/ui-scale.js`.
8. **`backdrop-filter` on `.panel` makes it the containing block** for
   `position: fixed` children. Use `placeFixed()`, which measures rather than
   assumes.
9. **Credentials come from the environment**, never from `ueba_config.yaml`
   (`UEBA_SSO_SECRET`, `UEBA_SMTP_PASSWORD`). That file is readable by other
   teams on the shared box.
10. **`models/autoencoders/*.pt` filenames are real usernames and internal IPs.**
    They are gitignored for that reason. Do not commit them.

---

## 10. Config map — `ueba_config.yaml`

| Section | Controls |
|---|---|
| `paths` | Every file location |
| `preprocessing` | Feature extraction, `feature_dim`, `min_events_per_user` |
| `isolation_forest` / `autoencoder` | Model hyperparameters |
| `clusterer` | HDBSCAN interval, `min_cluster_size` |
| `score_fusion` | **Weights, `alert_threshold`, verdict tiers** — the knob that changes alert volume |
| `rag` | FAISS index, vector cap |
| `dashboard` | Windows, caching, `feed_row_cap`, reporting, SMTP |
| `auth` | SSO, roles, `enforce`, public paths |
| `noise_suppression` | Known-benign rules |
| `identity_resolution` | Alias → canonical user |

---

## 11. Where to start

- **Detection behaviour** → `ueba_engine.py::_process_batch` then `fuse_scores`
- **Why an event did/didn't alert** → `ueba_preprocessor.py` extraction, then the
  35 features above
- **Dashboard** → `dashboard/src/main.js`, then `panels/`
- **API** → `ueba_dashboard_server.py`, routes are grouped by feature
- **Training** → `ueba_weekly_retrain.sh` top to bottom; it is commented as a
  runbook
- **Compliance status** → `docs/RFP_COMPLIANCE.md`

Change one thing at a time and verify against the live feed. This pipeline
processes ~2M events/day; a bad change is visible within a minute in the Stats
line, and invisible in a unit test.
