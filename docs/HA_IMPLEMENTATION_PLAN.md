# High availability — implementation plan (RFP SN 31)

**Written 19-Nov-2026.** Supersedes the sub-task plan in `HA_DESIGN_SN31.md`
§5; the design, the state inventory and the store choice there still stand.

This exists because four things changed in the 24 hours after that design was
written, and two of them change what we have to build.

---

## 0. What changed since the design

**Kafka ingestion went live.** The design recorded it as "built, selftested,
and switched off". It is now the live source — the engine is consuming
`enriched` on consumer group `ueba-engine`, and `confluent-kafka` is
installed. The byte-offset file is no longer the stream position.

**But Kafka is now a single point of failure we did not have before.**
Measured: **one broker, four partitions, replication factor 1, one in-sync
replica per partition.** If that broker stops, UEBA stops ingesting entirely.
A design for "no single point of failure" that leaves the input on an
unreplicated single broker has not met SN 31, however good the rest is. This
was not in the original inventory and it belongs to the SIEM team's
infrastructure, not ours.

**Kafka does NOT give us single-writer for free, as §2.5 implied.** Partition
assignment does guarantee each event is handled by exactly one consumer, so
two engines in one group would not double-score an event. But the topic is
partitioned by **source IP**, not by UEBA entity, and about 12% of messages
carry no key at all and are spread round-robin. One entity's events therefore
land on several partitions, so two engines would update the same entity's
profile and risk history concurrently. **Leader election is still required.**
We cannot repartition our way out of it either: the SIEM produces that topic.

**The indexed alert store is built and proven.** `ueba_alert_store.py` holds
236,535 alerts, imports in 12.9s, and answers every dashboard aggregate in
0.3–0.4s with nothing resident — against a 205s pre-warm that holds 922 MB.
That is a down payment on story 4.1 and it is already in `main`.

**And we learned the deployment itself is not survivable.** On 18-Nov a `git
pull` on the live install deleted both `EnvironmentFile`s and reverted the
site config to shipped defaults, taking the console down for ~25 minutes. The
SSO secret survived only because the engine process was still running and its
environment could be read from `/proc`. `/opt/ueba` is simultaneously the
production install, a git working tree, and the place a teammate commits
from. Building failover on top of that is pointless — a second node would
have been destroyed by the same pull.

---

## 1. The shape of the plan

Five phases. The ordering is deliberate: **everything that needs no new
hardware comes first**, because the hardware is the long-lead item and we
should not be idle waiting for it.

| Phase | What | New nodes? | Days |
|---|---|---|---|
| 0 | Make the deployment survivable | No | 2 |
| 1 | Single-node correctness | No | 6 |
| 2 | Leader election and single-writer | No | 4 |
| 3 | Clustered datastore | **Yes** | 6 |
| 4 | Load-balanced console | **Yes** | 4 |
| 5 | Resilient ingestion (Kafka) | **Yes, SIEM team** | 3 |

**25 days total: 22 ours, matching the RFP estimate, plus 3 for the SIEM
team.** Of our 22, **12 can start immediately** (phases 0–2) and **10 cannot
begin until nodes exist** (phases 3–4).

---

## 2. Phase 0 — make the deployment survivable (2 days, no hardware)

Not in the original plan. It is first because the 18-Nov outage proved that a
second node would not have helped: the same `git pull` would have taken both.

- **0.1** Stop site state being a tracked file. `ueba_config.yaml` is tracked,
  so every pull overwrites the live config — and on 18-Nov it did, replacing
  the real paths and port with shipped defaults. Untrack it and ship
  `ueba_config.example.yaml` instead. This changes every working copy, so it
  needs a deliberate decision rather than a drive-by commit.
- **0.2** Separate the production install from the development tree.
  `/opt/ueba` is a git working tree someone commits from. Production should be
  a deploy target, not a workspace.
- **0.3** Hold secrets outside the install directory. `UEBA_SSO_SECRET`
  existed in exactly one place after the clean — a running process's
  environment. One restart and the token contract with the SIEM team would
  have been unrecoverable.
- **0.4** A deploy that is reversible: snapshot, apply, health-check, roll
  back on failure. `rollback_deploy.sh` exists on the box; the `git clean`
  deleted its snapshot directory, which is the whole problem in one sentence.

*Partly done already: the `.gitignore` patterns that silently matched nothing
are fixed, and site state is snapshotted outside the git tree.*

## 3. Phase 1 — single-node correctness (6 days, no hardware)

Make one node behave correctly before making two.

- **1.1 Finish the alert-store cutover.** The store is built; the endpoints
  still build windows in RAM. Migrate one builder at a time behind a config
  flag, diffing old output against new. **This also closes the OOM class** —
  the console has been killed twice and that is an availability defect in its
  own right, not only a memory one.
- **1.2 Put the remaining shared state behind one storage layer.** Six SQLite
  stores, 145 raw SQL call sites across nine modules, no abstraction to swap.
  Phase 3 is a rewrite at every one of those sites unless this lands first.
- **1.3 Add the single-instance guard.** Nothing stops two engines running
  today — no flock, no pidfile. Until leader election exists, a second engine
  started by mistake silently corrupts shared state.
- **1.4 Readiness endpoint.** `/api/health` exists but reports healthy while
  models are still loading. A load balancer needs *not-ready* during warm-up
  or it sends traffic to a node that cannot answer.

## 4. Phase 2 — leader election (4 days, no hardware)

Buildable now against a single PostgreSQL or SQLite instance; the mechanism
does not need the cluster.

- **2.1** Session-level advisory lock on a fixed key. One engine wins; the
  others idle. **Not** a transaction-level lock, and **not** behind PgBouncer
  in transaction-pooling mode, which silently reassigns the connection and
  orphans the lock.
- **2.2** A heartbeat lease, because the lock alone is not enough. The lock
  dies with the session, and a *frozen* leader keeps its session. Sub-point
  4.2.2 asks for a frozen leader to be replaced, which the lock cannot do.
- **2.3 Measure the engine's stall distribution before choosing the lease
  duration.** This engine has a documented history of transient
  self-recovering pauses. A lease shorter than the longest benign stall turns
  failover into an outage generator — we would have built a flapping cluster.
- **2.4** Followers idle but warm, models already loaded, so promotion is fast.
- **2.5** Verify no events are skipped or replayed across a handover. Kafka's
  revoke callback commits offsets before surrendering a partition, so this is
  now mostly *verification* rather than construction — the one genuine gain
  from Kafka going live.

## 5. Phase 3 — clustered datastore (6 days, **needs nodes**)

PostgreSQL, per the design. Cannot start on the current host: it has ~2.6 GB
free RAM, no free swap, and shares the box with a 37 GB search cluster.

- **3.1** Stand up PostgreSQL with a synchronous standby (RPO zero).
- **3.2** Migrate profiles and risk history first — read on every event.
- **3.3** Migrate the remaining stores, then the alert store (its SQL is
  already written to port: epoch integers, no SQLite-only syntax,
  `ON CONFLICT DO UPDATE` spelled the same way).
- **3.4** A degraded read path: PostgreSQL unavailable must mean scoring
  continues on a stale local cache, not that scoring stops.
- **3.5** Migrate with a dry run and row counts before and after.
- **3.6** Record read and write latency before and after. The profile store is
  read on every event and synchronous replication adds a network round trip to
  every commit — this is the number to watch.
- **3.7** Prove a node can be lost under load. **Blocked until a second
  database node exists.**

**Hidden work item, in no sub-point:** eleven modules invalidate their caches
on file mtime and size. The moment operator-edited JSON moves into the
database those checks stop working — there is no mtime on a row. They need a
version column or `LISTEN`/`NOTIFY`. It fails quietly, and it will look like
"the console saved my change but the engine ignored it".

## 6. Phase 4 — load-balanced console (4 days, **needs nodes**)

- **4.1** Two console processes, HAProxy, keepalived VIP.
- **4.2** Sessions are already server-side in a table, so cross-node sharing
  comes free once phase 3 lands. The sub-point as written ("move session state
  out of process memory") describes work that was already done.
- **4.3** Health-checked removal of a node under load with no failed request.
- **4.4** Measure availability across a deliberate failover.

## 7. Phase 5 — resilient ingestion (3 days, **SIEM team**)

New, and not in the original plan. One broker with replication factor 1 is a
single point of failure in front of everything above.

- **5.1** Three brokers, `replication.factor=3`, `min.insync.replicas=2` on
  the `enriched` topic.
- **5.2** Confirm our consumer group rebalances cleanly when a broker is lost.
- **5.3** Confirm topic retention covers our worst recovery window, so a
  failover can replay rather than lose events.

**This is the SIEM team's infrastructure.** It needs raising with them now,
not in December, because it has the same lead time as our own nodes.

---

## 8. What blocks us, and who owns it

| Blocker | Owner | Needed by |
|---|---|---|
| Three nodes for quorum (two cannot fail over safely) | Infrastructure / procurement | Before phase 3 |
| PostgreSQL cannot run on the current host (~2.6 GB free, no swap) | Same | Before phase 3 |
| Kafka replication (1 broker, RF=1) | SIEM team | Before SN 31 can be claimed |
| Decision to untrack `ueba_config.yaml` | Us — needs agreement, changes every working copy | Phase 0 |

**The quorum requirement is arithmetic, not a tooling preference.** With two
nodes, when the link between them breaks each sees exactly half the cluster
and cannot distinguish "my partner died" from "I am the one cut off". Either
both refuse to act, which is an outage, or both act, which is split-brain and
corrupt data. No software fixes this; a third participant is what makes a
majority possible.

---

## 9. What we can honestly claim, and when

- **By 18-Dec (architecture complete):** phases 0, 1 and 2 are achievable with
  no new hardware — a correct single node, leader election, single-writer
  guaranteed, and the memory defect that has twice taken the console down
  closed. That is a genuine and demonstrable improvement.
- **Phases 3 and 4 are gated on hardware**, not on us. If nodes arrive in
  early December the 18-Dec date holds; if they do not, the architecture is
  complete on paper and unproven in fact, and we should say exactly that
  rather than claim it.
- **The 99.9% uptime evidence cannot be produced by 31-Jan regardless.** That
  figure allows about 8.8 hours of downtime a year; it can only be
  demonstrated by running, not by building. The RFP note already concedes
  this.

One thing we should not do is report SN 31 as complied while ingestion sits
on a single unreplicated broker. It would be the most visible thing in the
architecture for anyone who looked.
