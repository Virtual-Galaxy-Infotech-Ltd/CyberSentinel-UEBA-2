# High availability — design and starting base (RFP SN 31)

**Status:** design, not built. Written 18-Nov-2026, before story 4.1 starts.
**Scope:** RFP SN 31 — "support highly available component architecture ensuring
no single point of failure". 22 days total, 14 in Sprint 2 (20-Nov → 04-Dec),
architecture complete 18-Dec-2026.
**Delivers:** story 4.1 sub-point 1 (the state inventory) and sub-point 2 (the
store choice and why, including what it costs to operate).

---

## 1. What high availability actually means here

HA is not backup, and it is not uptime. It is a specific property: **the system
keeps serving when any single component dies, without a human in the loop.**
Three things have to be true, and they are usually confused with each other.

**No single point of failure.** Every component has a peer that can take its
job. One node, one process, one disk, one network path — if losing it stops the
service, it is a SPOF regardless of how reliable it is.

**Automatic failover.** A peer must *notice* the failure and take over by
itself. This is where most designs fail, because detecting "dead" is genuinely
hard: a frozen process still holds its TCP connections, and a partitioned node
still believes it is healthy. Two numbers describe the result — **RTO**, how
long until service resumes, and **RPO**, how much data is lost. For UEBA the
honest targets are RTO under a minute and RPO zero: no scored alert may be lost,
because a lost alert is a missed detection.

**Quorum, to avoid split-brain.** If two nodes each think they are in charge,
both write, and the data is corrupt in a way no failover can repair. The only
reliable defence is majority voting: an odd number of participants, and a node
may only act if it can see more than half of them. Two nodes cannot do this —
when the link between them breaks, each sees exactly half and neither can tell
"my peer is dead" from "I am the one cut off". **This is why the minimum for
automatic failover is three participants, not two** ([rivestack][r1],
[cloudrps][r2]).

For UEBA specifically there is a fourth property, and it is the hard one.

**Exactly one engine may score a window.** Alerting is not idempotent. Two
engines reading the same events produce two alerts, two SOAR actions, two
emails, and a risk history that double-counts. So UEBA cannot be made
highly available by simply running more copies — the console can, but the
engine needs a *single-writer guarantee*, which is what story 4.2 is for.
Availability here comes from having a warm standby ready to take over, not from
running both at once.

---

## 2. Where we are starting from (story 4.1, sub-point 1)

Measured against the live config on 18-Nov-2026.

### 2.1 Shared mutable state — must become clustered

Read and written by both the engine and the console, so both nodes must see the
same thing or they will disagree about what happened.

| State | File today | Role | Note |
|---|---|---|---|
| Entity profiles | `profiles/user_profiles.db` | **read on every event** | 36 MB locally, larger on the live store. The hot path. |
| Risk history **and confirmed incidents** | `profiles/risk_history.db` | written by console, read by engine | `confirm()` writes the analyst's disposition here. |
| Device identity / IP trail | `profiles/device_trail.db` | written by engine | SN 5. |
| SOAR action queue | `profiles/soar_queue.db` | written by both | Must not be double-drained. |
| Users, **sessions**, replay guard | `profiles/ueba_auth.db` | written by console | `sessions` table keyed by token hash — this is what 4.3 needs. |
| Alerts | `ueba_alerts.jsonl` | appended by engine, read constantly by console | ~600 MB on the live store. |

Six stores, **145 raw SQL call sites** across nine modules (`ueba_auth.py` 42,
`ueba_preprocessor.py` 30, `ueba_device_identity.py` 21). There is no storage
abstraction layer to swap — the SQL is written inline at each site.

### 2.2 Operator-edited JSON — must be shared, or edits go invisible

Written from the console, read by the engine. If these stay as node-local files,
an analyst adds a watch-list entry on node A and node B never applies it.

`watchlist.json`, `rules.json`, `privileged.json`, `assets.json`,
`entities.json`, `fp_patterns.json`, `device_bindings.json`, `peer_cohorts.json`

### 2.3 Derived data — replicate as files, no cluster needed

Rebuildable from a retrain, so correctness does not depend on consensus. Plain
file replication to each node is sufficient and much cheaper.

`models/` (`*.pt`, `isolation_forest.pkl`, `scaler.pkl`), `features.h5`,
`vector_db/faiss.index`, `vector_db/metadata.jsonl`, `profiles/peer_groups.json`

### 2.4 Per-node state — must **not** be shared

`logs/`, `.state/ueba.state` (the file-source byte offset),
`.state/notify.state`. Sharing the offset between two engines is precisely the
double-scoring bug.

### 2.5 Three findings that change the plan

**The Kafka source is already built, selftested, and switched off.**
`streaming.source` is `file` today; `ueba_source.py` carries a complete Kafka
consumer on its own group (`ueba-engine`) and the file source is kept as a
fallback. This matters more than anything else in this document, because a
Kafka consumer group *already solves* story 4.2 sub-point 4 — offsets are
committed in the revoke callback before a partition is surrendered, so the next
owner inherits an accurate resume point and no events are skipped or replayed
([conduktor][r3], [lydtech][r4]). **Turning this on is the single highest-value
step in Epic 4,** and it is a config change against code that already passes
its selftests.

**Sessions are already out of process memory.** Story 4.3 sub-point 2 reads
"move session state out of process memory" — but sessions are in a SQLite table
keyed by `token_hash`, not in a process dict. Two console processes on the
*same* host already share them. The real gap is cross-node, which 4.1 fixes for
free when `ueba_auth.db` moves into the cluster. **4.3.2 is nearly free once
4.1 lands,** and the sub-point should be reworded.

**Nothing currently stops two engines from running.** There is no flock, no
pidfile, no single-instance guard anywhere in the engine. Pidfiles exist only
in the retrain and watchdog scripts. So today HA is not merely absent — the
failure mode is unguarded, and a second engine started by mistake would
double-score silently.

---

## 3. What to build (story 4.1, sub-point 2 — the choice, and why)

### 3.1 The store: PostgreSQL

**Recommendation: PostgreSQL 17, one logical database, all six stores as
schemas within it.**

Why, measured against the alternatives:

- **It is the shortest path from SQLite.** Both are relational with
  near-identical SQL. The porting work is real but bounded and mechanical: 19
  `PRAGMA` statements to drop, 7 `strftime` calls, 5 `ON CONFLICT` (compatible
  syntax, different semantics in detail), 1 `AUTOINCREMENT` → `GENERATED`. A
  document store or key-value store would mean rewriting every query and every
  aggregate in the dashboard.
- **It gives us leader election with no extra component** — see 3.2.
- **It fixes the 600 MB alert file at the same time.** Moving alerts from
  append-only JSONL to an indexed table is required for HA anyway, and it
  independently fixes the dashboard slowness we already have open. One piece of
  work, two problems.
- **Synchronous replication gives RPO zero.** A commit is not acknowledged
  until the standby has it, so a node loss cannot lose a scored alert.
- It is defensible to the client: open-source, no licence cost, standard
  on-prem. Note the limit of that claim — **UEBA and the SIEM do not use
  PostgreSQL today**; the only instance on the estate belongs to another VG
  product, which does give us in-house operational familiarity and a backup
  script to copy, but this is a new dependency for this platform, not an
  existing one.

**What it costs to operate** — stated plainly, because the sub-point asks:

- A DBA-shaped job that does not exist today: backups (`pg_basebackup` + WAL
  archiving), `autovacuum` tuning, connection limits, a restore drill.
- ~2 GB RAM per node plus shared buffers, versus SQLite's near-zero.
- Failover is a *cluster* behaviour now, so there is more to understand when it
  misbehaves. SQLite cannot fail over, but it also cannot split-brain.
- Writes get slower. Synchronous replication means every commit waits for a
  network round trip. Sub-point 7 exists to measure this rather than argue
  about it, and the profile store is read on every event, so this is the number
  to watch.

**Rejected:** SQLite + filesystem replication (DRBD) — a replicated file is not
a replicated *database*; two writers corrupt it. MySQL/MariaDB Galera — no
advisory-lock equivalent, so leader election would need a separate component.
etcd or Consul as the primary store — excellent for coordination, wrong for
36 MB of profiles and millions of alerts.

### 3.2 Leader election: PostgreSQL advisory lock **plus a heartbeat**

Each engine attempts `pg_try_advisory_lock` on a fixed key at startup. One wins
and becomes the writer; the others get `false` immediately and stay followers.
If the leader's process dies, its session ends, PostgreSQL releases the lock,
and a follower takes it ([kerkour][r5], [jeremydmiller][r6]). No ZooKeeper, no
etcd, no Consul in the application layer.

**But the advisory lock alone does not satisfy sub-point 4.2.2.** The lock is
released when the *session* ends — a frozen-but-connected leader keeps holding
it. That sub-point says "a frozen leader is replaced rather than trusted", so
leadership also needs a **lease**: a heartbeat row the leader updates every few
seconds, which a follower may steal if it goes stale.

This is not theoretical for us. We have a documented history of transient,
self-recovering engine stalls. So the lease duration has to be set *above* the
longest known benign stall, or failover will flap and we will have built an
outage generator. **Measure the stall distribution before choosing the number.**

Two operational gotchas to record now:

- **Do not put the engine's PostgreSQL connection behind PgBouncer in
  transaction-pooling mode.** It reassigns the underlying connection between
  transactions, so a session-level advisory lock silently ends up owned by a
  different application session ([oneuptime][r7]). The console may pool; the
  engine must hold a direct session.
- The lock must be **session-level**, not transaction-level. Transaction locks
  are for "do this once" paths; session locks are for long-lived roles.

### 3.3 Console: two processes behind a load balancer

HAProxy with a keepalived VIP, two console nodes, health-checked. `/api/health`
already exists but needs to report **not-ready while models are still loading**
(sub-point 4.3.3) so the balancer does not send traffic too early. Sessions come
free from 3.1.

### 3.4 The architecture

```
                      keepalived VIP
                            │
                        HAProxy  (health-checked)
                       ╱          ╲
              console-A            console-B          ← both active
                       ╲          ╱
                   PostgreSQL primary ──sync──▶ standby
                            ▲                      ▲
                            │ advisory lock + lease│
                  engine-A (leader)        engine-B (follower, warm)
                            ╲                      ╱
                             ╲                    ╱
                          Kafka topic `enriched`
                        consumer group `ueba-engine`
                       (durable offsets, replay, handover)
```

---

## 4. The dependency nobody has booked yet

**HA needs three participants for quorum; the estate has five servers in
total, and we do not have a node allocation for this.**

The textbook build is Patroni + a 3-node etcd cluster + 2–3 PostgreSQL nodes,
which is 5–6 machines before UEBA itself gets one, and etcd must not be
co-located with PostgreSQL on the same hosts in the same rack — when the rack
loses power, the database and its coordination layer die together
([gse][r8], [cloudrps][r2]).

This is the real blocker on Epic 4, and it is procurement, not code. **Three
nodes minimum must be requested now**, because a two-node cluster cannot do
automatic failover safely and would have to be failed over by hand — which is
not what SN 31 asks for.

Honest consequence for the sprint: **sub-point 4.1.6 — "prove a node can be
lost without losing writes, by stopping one under load" — cannot be done
without a second database node.** Everything else in 4.1 can be built and
proven against a single PostgreSQL instance. The RFP note already concedes the
99.9% uptime evidence cannot be produced by 31-Jan; the node allocation is a
separate and earlier problem.

---

## 5. Revised sub-task plan

Sequencing changes I recommend, with reasons.

**Do Kafka first, before 4.1.** It is a config flip on code that already
passes its selftests, it removes `.state/ueba.state` from the inventory
entirely, and it delivers most of 4.2 on its own. Doing it first means 4.2 is
mostly verification rather than construction.

**Story 4.1** — sub-points 1 and 2 are delivered by this document. Then: 3
(profiles and risk history first, since they are on the hot path), 5 (migrate
with a dry run and row counts), 7 (latency before and after). Sub-point 4, the
degraded read path, deserves its own note: PostgreSQL unavailable must mean
*scoring continues on a stale local read-through cache*, not that the engine
stops.

**Two work items the sub-points do not mention:**

1. **Eleven modules invalidate their caches on file mtime and size.** When
   the operator-edited JSON moves into the database, every one of those
   `_cache` checks stops working — there is no mtime on a row. They need a
   version column or a `LISTEN`/`NOTIFY` channel. This is quiet, and it will
   look like "the console saved my change but the engine ignored it".
2. **Story 3.1 creates new analyst-settings state on 25-Nov, before 4.1
   finishes on 27-Nov.** Build it on PostgreSQL directly rather than adding a
   seventh SQLite file that then has to be migrated.

**Story 4.2** — add the heartbeat/lease explicitly; the sub-points imply the
advisory lock is sufficient and it is not. Measure the engine's stall
distribution before setting the lease duration.

**Story 4.3** — reword sub-point 2: sessions are already out of process memory,
and the work is cross-node sharing, which 4.1 provides. The genuine work is the
readiness endpoint and the balancer.

**Also stale, found while writing this:** `docs/build_techdoc.py` still lists
peer-group deviation analysis and NetFlow ingestion under "Not implemented".
Both shipped and are marked Done on the RFP sheet. The same table's HA entry —
"the current architecture is single-instance" — is still correct and should be
updated only when this work lands.

---

## Sources

- [r1] [PostgreSQL High Availability: A Practical Guide for Production](https://rivestack.io/blog/postgres-high-availability)
- [r2] [PostgreSQL HA in Production: Patroni, etcd, and Building the HA Stack](https://cloudrps.com/blog/postgresql-ha-patroni-etcd-production/)
- [r3] [Kafka Consumer Groups & Consumer Offsets](https://www.conduktor.io/kafka/kafka-consumer-groups-and-consumer-offsets)
- [r4] [Kafka Consumer Group Rebalance — The Next-Gen Protocol](https://www.lydtechconsulting.com/blog/blog-kafka-rebalance-next-gen)
- [r5] [Leader election with PostgreSQL's advisory locks](https://kerkour.com/postgresql-leader-election-advisory-lock)
- [r6] [Using PostgreSQL Advisory Locks for Leader Election](https://jeremydmiller.com/2020/05/05/using-postgresql-advisory-locks-for-leader-election/)
- [r7] [How to Use Advisory Locks in PostgreSQL](https://oneuptime.com/blog/post/2026-01-25-use-advisory-locks-postgresql/view)
- [r8] [PostgreSQL High Availability: Patroni and Pacemaker on 3 Nodes](https://gse.kz/en/blog/postgresql-high-availability-patroni-pacemaker-3-nodes)
