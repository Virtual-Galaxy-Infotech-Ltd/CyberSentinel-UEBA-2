# Aishwarya_UEBA — Welcome to the CyberSentinel UEBA Project

**Written for:** Aishwarya, joining the UEBA project
**Date:** 26 October 2026
**Read this first.** It assumes no prior knowledge of the project and no machine-learning
background. Everything is explained in plain English before the technical detail.

When you want the deep engineering version of anything here, go to `docs/ARCHITECTURE.md`.
This document is the friendly tour; that one is the manual.

---

## Part 1 — What is UEBA, in plain words?

UEBA stands for **User and Entity Behaviour Analytics**.

Here is the whole idea in one sentence: **instead of looking for known bad things, we learn what
normal looks like for each person and each machine, and then shout when somebody stops behaving
like themselves.**

A traditional security tool works like a bouncer with a photo list of banned faces. If your face
is on the list, you are stopped. That works well — until the attacker has a face nobody has
photographed yet.

UEBA works like a receptionist who has worked in the building for ten years. She does not have a
list. She just *knows* that Rakesh from Accounts arrives at 9:30, uses the second-floor printer,
and goes home at 6. So when "Rakesh" badges in at 3:15 in the morning, logs into eleven servers
he has never touched, and starts copying files to an external drive, she does not need a list to
know something is wrong.

Our software is that receptionist. The whole project exists to build and maintain her memory.

### The two words in the name

- **User** — a person. Aishwarya, Aditya, an administrator account.
- **Entity** — anything else that behaves: a laptop, a server, a firewall, an IP address.

We watch both, because an attack usually involves a person doing something on a machine.

### Where does this fit next to the SIEM?

The SIEM (our product is called **CyberSentinel SIEM**) is the system that collects logs from
every laptop, server and firewall in the organisation and applies rules to them. It is the layer
that says *"this log line matches rule 5710, failed SSH login."*

UEBA sits **downstream** of it. The SIEM says what happened. UEBA says whether it was normal.

```
  endpoints  ──logs──►  CyberSentinel SIEM  ──enriched logs──►  UEBA  ──►  Dashboard
  (laptops,              (rules: what happened)        (is it normal?)      (analyst)
   servers,
   firewalls)
```

---

## Part 2 — Why does this project exist?

Two reasons, both real:

1. **A client bid.** OPTCL (Odisha Power Transmission Corporation Limited) issued an RFP — a
   formal tender — with 67 numbered requirements for a UEBA system. We are answering it. Several
   documents in `docs/` exist purely to track which of those 67 points we satisfy
   (`OPTCL_UEBA_RFP_COMPLIANCE.md` is the live scorecard).
2. **A product.** UEBA is a genuine capability gap in our SIEM offering. Whether or not we win
   OPTCL, this becomes part of what we sell.

So when you read a document in `docs/` and the tone suddenly turns formal and starts numbering
things "SN 42" — that is RFP language. SN = serial number of a requirement.

---

## Part 3 — The journey of one log line

This is the single most useful thing to understand. Everything in the codebase is a station on
this one assembly line.

Imagine one log line: *"user jinu logged into VGSOC-LAP11 at 03:14."*

### Station 1 — Transport: getting the log to us

**Plain English:** the SIEM lives on one machine, UEBA lives on another. Something has to carry
the logs across. That something is a shell script that compresses logs, copies them over SSH, and
appends them to a file on our side.

**File:** `ueba_sync_bridge.sh`
**Output:** everything lands in one growing text file, `enriched.jsonl` — one JSON object per
line. "jsonl" means "JSON Lines": a file where each line is its own complete JSON record. It is
unglamorous and it works.

### Station 2 — Tail: noticing a new line arrived

**Plain English:** the engine keeps a bookmark in that file. It reads from the bookmark to the
end, processes what it finds, then moves the bookmark. If the engine restarts, it picks up exactly
where it left off instead of re-reading months of logs.

**File:** `ueba_engine.py`, the `run()` function. Bookmark lives in `.state/ueba.state`.

One important detail: it reads in **batches**, not one line at a time. This matters — see the
"things we learned the hard way" section.

### Station 3 — Feature extraction: turning English into numbers

**Plain English:** a machine-learning model cannot read *"user jinu logged into VGSOC-LAP11."* It
only understands numbers. So we convert each log line into a list of **35 numbers**, which we call
a *feature vector*. Think of it as a 35-question form filled in about every single event.

**File:** `ueba_preprocessor.py`

The 35 questions, grouped:

| Group | How many | Examples |
|---|---:|---|
| **Time** | 5 | What hour was it? Weekend? Business hours? Night shift? |
| **What kind of event** | 4 | Was it a login? Network traffic? A file touch? A process start? |
| **Suspicious patterns** | 9 | Brute force? Port scan? Tor exit node? Known-bad IP? Impossible travel? |
| **Counters** | 4 | How many events from this IP in 5 min? In 1 hour? From this user? This host? |
| **Behaviour** | 3 | How many different destinations in the last hour? Different ports? Recent failures? |
| **Geography** | 3 | Distance travelled, crossed a border, crossed a continent |
| **Other** | 7 | Risk score, SIEM rule severity, cloud IP?, category, outcome, direction, deviation from the user's own baseline |

If a log line is too broken to fill in the form, we quietly skip it. That is deliberate, not a
bug — in a stream of millions, a few malformed lines are normal and should not stop the engine.

### Station 4 — Layer 1: "Is this weird for *anyone*?"

**Plain English:** we have one model that has seen the whole organisation's behaviour. Its job is
to spot things that would be odd for *any* employee — a login from North Korea, a port scan, a
thousand file deletions in a minute.

The technique is called an **Isolation Forest**. The intuition behind the name: imagine playing
"20 questions" to pin down one data point among millions. Normal, crowded, average points take
many questions to isolate. Weird, lonely outliers get isolated in two or three. The model
measures exactly that — *how easy was this point to isolate?* Easy to isolate = anomalous.

**Files:** `ueba_models/isolation_forest.py`, weights at `models/isolation_forest.pkl`
**Output:** a score from 0 (totally normal) to 1 (very strange).

### Station 5 — Layer 2: "Is this weird for *you*?"

This is the heart of UEBA and the part that makes it different from everything else we sell.

**Plain English:** a global model cannot catch an insider. If Aishwarya from Finance opens a
finance spreadsheet, that is perfectly normal for the organisation — the global model shrugs. But
if Aishwarya has never once opened the HR payroll share in two years and suddenly downloads all of
it, *that is wildly abnormal for Aishwarya* even though it is unremarkable for the company.

So: **every entity gets its own personal model.** Right now there are **453** of them, one file
each, in `models/autoencoders/`.

The technique is an **autoencoder**. The intuition: it is a model trained to squeeze an input
down to a tiny summary and then rebuild the original from that summary — like learning to
describe someone's daily routine in six words and then reconstructing the full day from those
six words. Train it only on Aishwarya's normal days and it gets very good at rebuilding
Aishwarya's normal days. Then feed it a day where she behaved completely unlike herself, and the
rebuild comes out wrong. **How wrong the rebuild is = how abnormal the behaviour is.** That error
is the score.

Each one is deliberately tiny — shape `35 → 24 → 12 → 24 → 35`, about 2,000 parameters. It has to
be tiny, because there are hundreds of them and we load them constantly. The 100 most recently
used are kept in memory (`ae_cache`); the rest load from disk on demand.

If an entity has fewer than 2,000 events in its history, it does not have enough of a track record
to judge, so we fall back to the global model instead of inventing an opinion.

### Station 6 — The watch list

**Plain English:** sometimes an analyst already knows to keep an eye on someone — an employee
serving notice, a contractor, a server that just got patched. The watch list lets them say so, and
a watch-listed entity's bar for raising an alert genuinely drops.

**File:** `ueba_watchlist.py`

The subtle but important design choice: the watch list is checked **before** the scores are
combined, not after. That means it actually changes what becomes an alert, rather than just
putting a sticker on alerts that would have fired anyway.

### Station 7 — Fusion: combining the two opinions

**Plain English:** we now have two scores — "weird for anyone" and "weird for you" — and we need
one number. We average them 50/50, add any watch-list boost, and compare against a threshold.

```
combined = (0.5 × global score) + (0.5 × personal score) + watch-list boost

  below 0.75  →  thrown away silently   ← about 99.9% of all events end here
  0.75 – 0.85 →  "suspicious"        (low confidence)
  0.85 – 0.93 →  "anomalous"         (medium confidence)
  0.93 and up →  "highly anomalous"  (high confidence)
```

**That 99.9% number is the whole point of the product.** The value we deliver is not finding
anomalies; it is throwing away the overwhelming majority of events so a human analyst only ever
looks at the handful that matter. A UEBA that alerts on everything is worse than no UEBA, because
the analyst stops reading it.

We keep the pre-boost score separately as `model_score` so that during an audit we can always
show what the model thought *before* human configuration nudged it. Thresholds live in
`ueba_config.yaml` under `score_fusion`.

### Station 8 — Enrichment: adding context to survivors

Only the ~0.1% that survived get this far, so we can afford expensive work on them:

- **Update the baseline** — this event becomes part of what is normal for this entity in future.
- **Find similar past incidents** — a **FAISS** vector search over previous anomalies. Plain
  English: "show me the five most similar things that have happened before," so the analyst sees
  precedent instead of a bare score. This technique is called **RAG** (retrieval-augmented
  generation).
- **Queue it for campaign detection** — see Station 11.

### Station 9 — Suppression: two kinds of "we know, stop telling us"

1. **Rule-based noise filter** — patterns we have declared benign in config (`is_noise()`).
2. **Learned false-positive suppressor** — `ueba_models/fp_suppressor.py`. When an analyst clicks
   "false positive" in the dashboard, the system learns that pattern and stops raising it.

The second one is a genuinely nice feature to demo: **the product gets quieter the more it is
used.**

### Station 10 — Write

Survivors are appended to `ueba_alerts.jsonl`. That file is the single source of truth for
everything the dashboard shows.

### Station 11 — Layer 3: "Are these all the same incident?"

**Plain English:** twelve separate alerts across eight machines over twenty minutes are usually
not twelve problems. They are one attacker moving through the network. Grouping them into a single
**campaign** turns twelve tickets into one story.

The technique is **HDBSCAN**, a clustering algorithm. Plain English: it looks for dense clumps in
the data and labels each clump, while leaving genuinely isolated points unlabelled. Unlike older
clustering methods, you do not have to tell it how many groups to expect — which is essential,
because we have no idea how many attacks are in progress.

**File:** `ueba_models/clusterer.py`. It runs on a **separate thread, on a timer**, not inline.

A consequence that will confuse you the first time you see it: **a fresh alert can show no
campaign and then gain one a few minutes later.** That is correct behaviour, not a bug.

### Station 12 — Serve: the dashboard

`ueba_dashboard_server.py` (4,652 lines) is a Flask web API. It reads the alert file, applies the
timeline window the analyst selected, caches results, and returns JSON. The browser app in
`dashboard/` renders it.

One performance rule baked in: the heavy evidence for each alert is **not** sent with the list.
It is fetched per-row via `/api/evidence` only when the analyst expands that row. We learned this
the hard way — see the gotchas.

---

## Part 4 — Training: where the models come from

Everything above is **inference** — using models that already exist. Training is a completely
separate cycle that runs weekly.

**Plain English:** you cannot learn what is normal from today's logs alone. You need months. So
once a week we take the accumulated history, retrain all the models, validate them, and swap them
in only if they pass.

| Step | File | What it does |
|---|---|---|
| Prepare | `ueba_prepare_training_data.py` | Turn raw history into feature vectors for training |
| Train | `ueba_trainer.py` (792 lines) | Fit the Isolation Forest + every per-entity autoencoder |
| Validate | `ueba_validate_models.py` | Sanity-check before anything goes live |
| Orchestrate | `ueba_weekly_retrain.sh`, `retrain.py` | Run the whole cycle on a schedule |
| Prune | `ueba_prune_corpus.py` | Keep the training corpus from eating the disk |

Training is GPU work. Inference is CPU work. That is why `requirements.txt` has a note about
installing GPU PyTorch wheels separately on the trainer machine.

---

## Part 5 — What features does it actually have?

### The dashboard (what the customer sees)

Each of these is one file in `dashboard/src/panels/`:

| Panel | What it does |
|---|---|
| **Overview** | Landing page — headline numbers, score distribution, recent alerts, top risky users and endpoints |
| **Feed** | The main alert stream, filterable and sortable, with expandable evidence |
| **Users** / **User detail** | Per-person view: their baseline, their history, their anomalies |
| **Agents** | Per-endpoint equivalent |
| **Campaigns** | The HDBSCAN groupings — related alerts as one story |
| **Threat map** | A 3D rotating globe (and a 2D fallback) showing live attack sources by geography |
| **MITRE** | Maps alerts to the MITRE ATT&CK framework — the industry-standard catalogue of attacker techniques. Customers expect this; it is an RFP requirement |
| **Incidents** | Case management for things being worked |
| **Watchlist** | Add/remove entities under heightened scrutiny |
| **False positives** | Mark an alert wrong; teach the suppressor |
| **Deep search** / **Search suggest** | Query the whole corpus |
| **Reports** | Generate reports (see below) |
| **Alerting** | Configure who gets notified about what |
| **Health** | Is the engine keeping up? Queue depths, throughput, lag |
| **Recommendations** | Suggested tuning actions |
| **Settings** | Account and system configuration |
| **Solar** | An alternative visualisation of the estate |
| **AI analyst** | Natural-language explanation of an alert. ⚠️ **Must stay disabled on customer installations** (RFP point 67 / SN 64) |

### The reporting engine

`ueba_reports.py` + `ueba_report_render.py` + `ueba_report_store.py`.

**Six output formats:** JSON, XML, CSV, HTML, **XLSX** (Excel, via `openpyxl`) and **PDF** (via
`reportlab`).

**Four built-in report templates:** `analyst_investigation`, `admin_management`,
`audit_compliance`, `threat_report` — plus custom reports and scheduled reports.

This covers eight separate RFP requirements on its own, so it gets disproportionate attention in
client conversations. If Excel or PDF libraries are missing, the other four formats still work and
the caller gets a clear error rather than a crash.

### Notifications

`ueba_notify.py` — email and HTTP webhooks, with per-rule conditions (minimum score, verdict,
priority) and throttling so one incident does not send 400 emails.

### Roles and access control

`ueba_auth.py` (1,400 lines). Three roles, in increasing power:

```
viewer  →  analyst  →  admin
```

Permissions are a table of **capabilities** mapped to the minimum role required
(`ueba_dashboard_server.py:2844`):

| Capability | Minimum role |
|---|---|
| `export` | viewer |
| `watchlist.edit`, `fp.edit`, `reports.generate`, `reports.custom`, `ai.analyze` | analyst |
| `reports.schedule`, `devices.edit`, `notify.edit`, `audit.view`, `users.manage` | admin |

Passwords are hashed with **scrypt** (a deliberately slow algorithm, so that stealing the database
does not hand over the passwords).

**Important current state:** every route is already decorated with its permission gate, but
enforcement is behind a config flag (`auth.enforce`) that is currently **off**. That was
intentional — it let us wire up all the gates safely without breaking anything for existing
analysts, and flip the switch as one deliberate cutover. There is also single sign-on (SSO)
written for the SIEM team to integrate with, live but not yet enforcing.

### Operations

| Script | Purpose |
|---|---|
| `install_ueba.sh`, `deploy_ueba.sh` | Set up / deploy |
| `ueba-engine-watchdog.sh` | Restart the engine if it stops keeping up, and capture forensics first |
| `ueba_rotate.sh` | Log/alert file rotation |
| `ueba_housekeeping.py` | Disk and retention management |

---

## Part 6 — The technology stack, and why each piece

| Layer | Technology | Why |
|---|---|---|
| Language | Python 3.12 | The whole ML ecosystem lives here |
| Web API | Flask + flask-cors | Small, boring, well understood |
| Frontend | Vanilla JavaScript + Vite | A single-page app with no framework — fewer moving parts to maintain |
| Globe | globe.gl / three.js | The 3D threat map |
| Deep learning | PyTorch | The autoencoders |
| Classic ML | scikit-learn | The Isolation Forest |
| Clustering | hdbscan | Campaign detection |
| Vector search | FAISS | "Show me similar past incidents" |
| Numbers | NumPy, pandas | Feature vectors and tabular work |
| Storage | h5py (HDF5), JSONL files | Training corpus; live alert stream |
| Fast JSON | orjson | ~2× faster on the hot read path; falls back to stdlib if absent |
| Geo | geoip2 | IP → country for the threat map |
| Auth | PyJWT, cryptography, scrypt | Sessions and SSO |
| Excel / PDF | openpyxl, reportlab | Report output |
| Config | PyYAML | `ueba_config.yaml` |

Everything is pinned in `requirements.txt`, which is worth reading — the comments explain *why*
each dependency is there and what breaks without it.

**One note on versions:** our local Macs run Python 3.9, the server runs 3.12. Always compile and
build on the server, never locally, or you will ship artefacts that do not run.

---

## Part 7 — Things we learned the hard way

Please read this section twice. Every line below is a bug that cost real days.

1. **The engine must process in batches, not per row.** Scoring the Isolation Forest one row at a
   time spent ~96% of the time budget in scikit-learn's fixed per-call overhead. Batching took
   throughput from 70 to 208 events/second. **Do not undo this.**

2. **Do not make the Isolation Forest per-entity.** It needs volume to mean anything. Per-entity
   forests on sparse users produce confident nonsense.

3. **Never send evidence with the alert list.** A drilldown once returned the entire retention
   window — a 673 MB response. Evidence is lazy-loaded per row.

4. **`set -euo pipefail` plus `command | head -N` will kill your script.** `head` exits early,
   the upstream command gets SIGPIPE, exits 141, and `set -e` aborts everything. This is what made
   the watchdog abort before capturing any forensics. Use a counter and `break` instead.

5. **Never pipe something into `ssh` inside a loop.** `ssh` consumes the loop's stdin and eats
   your remaining iterations. This made the sync bridge mysteriously unreliable; fixing it took one
   chunk from 20 minutes to 39 seconds.

6. **CSS `zoom` splits geometry into two coordinate systems** — visual pixels and layout pixels.
   Mouse coordinates and `getBoundingClientRect` are in one; `offsetWidth` and `style.left` are in
   the other. Mixing them is what made every hover box land in the wrong place. The bridge lives in
   `dashboard/src/ui/ui-scale.js`; use `placeFixed()` rather than setting positions by hand.

7. **`backdrop-filter` creates a containing block**, which silently breaks `position: fixed` on
   anything inside it.

8. **Always build the frontend on the server**, for the Python version reason above.

---

## Part 8 — House rules (non-negotiable)

1. **Never write the name of the upstream open-source SIEM project in anything.** The product is
   **"CyberSentinel SIEM"**, always. You *will* see the upstream project's name inside config
   files, code paths and service names — that is fine, it is our infrastructure. But it must never
   reach a document, a slide, an RFP response or a client email. Grep your output before you send
   it.

2. **Never commit `models/`.** The autoencoder filenames are real usernames and internal IP
   addresses — it is simultaneously a personal-data leak and a network-reconnaissance leak. It is
   in `.gitignore`; keep it there. Same for `*-state-restore-*.tar.gz`, `ueba_alerts.jsonl`,
   `enriched.jsonl`, `data/`, `archive/`, `vector_db/`, `profiles/`.

3. **`archive/*.slimN` is a live cache, not leftovers.** Do not clean it up.

4. **Credentials come from environment variables only** — never from `ueba_config.yaml`, never
   hardcoded, never in a commit.

5. **`ai_analyst` stays disabled on customer installations.**

6. **The canonical repository is `CyberSentinel-UEBA-2`.** Three older repositories still contain
   real usernames; do not push to them and do not treat them as reference.

---

## Part 9 — Where things stand today

**Working and in production use:** the full pipeline above, the dashboard, the reporting engine,
role-based access control (wired but not enforcing), the watchlist, FP learning, campaigns,
notifications.

**Open items you may end up touching:**

- **Deployment is on hold.** The old server (we called it "box 98") has been permanently
  decommissioned. A replacement Utho server is being provisioned. `docs/REBUILD_RUNBOOK.md` has
  the full step-by-step rebuild procedure, written in advance precisely so this goes smoothly.
- **Identity modelling is the big open design question**, and it is the most interesting problem
  in the project right now. Read `docs/UEBA_IDENTITY_MODEL_ANALYSIS.md` — written last week. Short
  version: 87.6% of our 453 "user" models are actually IP addresses, and 103 of 135 named
  "users" turned out to be SSH brute-force username guesses from the internet rather than real
  employees. The fix is about 8 days of work and would turn two RFP "No" answers into "Yes".
  There was already a small hand-written alias table in `ueba_config.yaml` under
  `identity_resolution` — five mappings someone added manually when they hit this, three of which
  turned out to be silently failing. **Phase A of the fix is now in the code** (see
  `canonical_identity()` in `ueba_preprocessor.py` and the `identity_diag.py` tool), but it is
  behind a config flag that stays off until the next retrain, because changing an entity's key
  changes which model file gets looked up. Phases B–E are still open.
- **Engine stalls** — occasional self-recovering pauses. The watchdog now captures forensics
  correctly; we are waiting for the next one to happen so we can finally see the cause.
- **A small known bug:** `build_anomaly_reasons()` in `ueba_engine.py:247` has four dead code
  paths that test for fields that do not exist in our data. Four-line fix, not yet applied. Good
  first task if you want one.

---

## Part 10 — How to find your way around

### Repository map

```
ueba/
├── ueba_engine.py              ← the live pipeline. Start here.
├── ueba_preprocessor.py        ← log line → 35 numbers
├── ueba_models/                ← the four model types
│   ├── isolation_forest.py       Layer 1: weird for anyone?
│   ├── autoencoder.py            Layer 2: weird for you?
│   ├── clusterer.py              Layer 3: same incident?
│   └── fp_suppressor.py          learned false-positive filter
├── ueba_dashboard_server.py    ← Flask API (4,652 lines)
├── ueba_auth.py                ← roles, sessions, SSO
├── ueba_watchlist.py
├── ueba_reports.py / _render / _store
├── ueba_notify.py
├── ueba_trainer.py             ← weekly training
├── ueba_config.yaml            ← nearly everything is tunable here
├── dashboard/src/              ← the browser app
│   ├── panels/                   one file per screen
│   ├── charts/                   reusable visualisations
│   └── ui/                       scaling bridge, login, capabilities
└── docs/                       ← you are here
```

### Suggested reading order for your first week

1. **This document.**
2. `docs/ARCHITECTURE.md` — the engineering version of Part 3, with far more detail.
3. `ueba_config.yaml` — read it top to bottom. It is the best single map of what the system can do,
   because every feature has knobs in it.
4. `ueba_engine.py`, the `run()` function — follow one batch all the way through.
5. `docs/UEBA_IDENTITY_MODEL_ANALYSIS.md` — the live design debate.
6. `docs/OPTCL_UEBA_RFP_COMPLIANCE.md` — what the client actually asked for.

### Other documents in `docs/` and what they are for

| File | What it is |
|---|---|
| `ARCHITECTURE.md` | The technical manual |
| `REBUILD_RUNBOOK.md` | Step-by-step server rebuild |
| `TECH_STACK_AND_ARCHITECTURE.md` | Formal stack reference |
| `OPTCL_UEBA_RFP_COMPLIANCE.md` | The 67-point client scorecard |
| `OPTCL_UEBA_REMEDIATION_PLAN.md` | What we would fix, and bid risk |
| `UEBA_DEEP_CAPABILITY_ANALYSIS.md` | Honest internal capability audit |
| `UEBA_IDENTITY_MODEL_ANALYSIS.md` | The identity design problem |
| `DEPENDENCY_AUDIT.md` | Security audit of our dependencies |
| `WEEKLY_MILESTONES.md`, `MONTHLY_RELEASE_HISTORY.md` | Project history |
| `CyberSentinel_UEBA_Technical_Document.docx` | Client-facing technical doc |
| `CyberSentinel_UEBA_Client_Presentation.pptx` | Client deck |

---

## Part 11 — A glossary, because the jargon is relentless

| Term | Plain meaning |
|---|---|
| **UEBA** | User and Entity Behaviour Analytics — our thing |
| **SIEM** | The log collection and rules platform upstream of us |
| **Entity** | Any actor we model: person, laptop, server, IP |
| **Baseline** | What normal looks like for one entity |
| **Feature vector** | The 35 numbers describing one event |
| **Anomaly score** | 0 = normal, 1 = very strange |
| **Isolation Forest** | Model that finds outliers by how easily they can be isolated |
| **Autoencoder** | Model that learns to compress-and-rebuild; rebuild error = abnormality |
| **HDBSCAN** | Clustering algorithm that finds groups without being told how many |
| **FAISS** | Fast similarity search over vectors |
| **RAG** | Retrieval-augmented generation — fetch similar past cases as evidence |
| **Fusion** | Combining the global and personal scores into one |
| **Verdict** | The label: suspicious / anomalous / highly anomalous |
| **Campaign** | Several alerts identified as one incident |
| **False positive (FP)** | An alert that was wrong |
| **Entity stitching** | Working out that `jinu`, `VGSOC-LAP11\JINU` and `JINU` are one person |
| **MITRE ATT&CK** | Industry-standard catalogue of attacker techniques |
| **RFP** | Request for Proposal — the client's formal requirement list |
| **SN** | Serial number of an RFP requirement |
| **JSONL** | A file where every line is one complete JSON record |
| **scrypt** | Deliberately slow password hashing algorithm |
| **SSE** | Server-Sent Events — how the dashboard gets live updates |

---

## One last thing

The most valuable instinct on this project is **scepticism about our own numbers**. Twice in the
last two months a confident claim turned out to be wrong when someone actually went and counted —
the RFP compliance summary had fabricated totals until we generated them programmatically, and the
"453 user models" turned out to be mostly IP addresses and brute-force noise.

So: when a document says the system does something, go and check that it does. Nobody will mind.
That habit is why the numbers in this document are measured rather than remembered.

Welcome aboard.
