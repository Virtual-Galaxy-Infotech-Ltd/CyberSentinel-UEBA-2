# UEBA Identity & Entity Modelling — Analysis and Recommendation

**Date:** 2026-10-26
**Status:** Analysis only. No code or data was modified in producing this document.
**Trigger:** Review of how the engine derives "users" from the log `user` field.

---

## 1. The question

Today `ueba_preprocessor.resolve_entity()` turns each event into one entity key, with this
priority:

```
subject.name  ->  data.srcuser / data.dstuser  ->  raw_event variants
              ->  object.name (auth events only)  ->  ip:<addr>  ->  host  ->  "unknown"
```

Every distinct string that falls out of that chain becomes its own behavioural identity: its own
row in the `users` table, its own baseline, and its own autoencoder in `models/autoencoders/`.

The concern raised was that a *user* in UEBA terms should be **a person**, and that treating every
value of the log `user` field as a new person is wrong — because one endpoint may carry 2–3 users.

That concern is correct, and the measured situation is worse than the premise. The problem is not
only that identities are split; it is that **the entity namespace does not distinguish people from
machines from strangers.**

---

## 2. What is actually in the model store

Counted from `models/autoencoders/` (453 files) and a 3,412-alert production sample of
`ueba_alerts.jsonl`.

### 2.1 Composition of the 453 per-entity models

| Key shape | Count | Share | What it really is |
|---|---:|---:|---|
| `ip_<addr>` | 397 | 87.6% | A network address, not a person |
| `host_<name>` | 23 | 5.1% | A hostname, not a person |
| Bare account name | 33 | 7.3% | Mixed: staff, service accounts, dictionary guesses |

**87.6% of our "user" models are IP addresses.** They exist because 1,954 of 3,412 alerts (57%)
carry no `subject.name` at all, so `resolve_entity()` falls through to `ip:<addr>`.

### 2.2 Of the 56 non-IP models, how many are people?

Canonicalising the keys (un-mangle escaping, strip the `DOMAIN\` / `HOST\` prefix, case-fold)
collapses 56 models to 48 keys:

- **13 keys / 15 models** are shared accounts, service accounts, dictionary names or parse
  garbage: `root`, `admin`, `Administrator`, `user`, `test`, `ubuntu`, `postgres`, `ftpuser`,
  `deploy`, `guest`, `global`, and the tokens `by`, `cbs`, `ERP`.
- **35 keys / 41 models** are plausible real identities.
- **5 of those identities are split across more than one model.**

### 2.3 The split identities, verbatim

```
sujal    <- VGSOC-LAP16_Sujal,  VGSOC-LAP16__Sujal,  VGSOCSRV__sujal
monish   <- VGSOC-LAP19__monish, host_monish
firdous  <- VGSOCSRV__firdous,  host_firdous
asus     <- LAPTOP-08MIT8SI_Asus, LAPTOP-08MIT8SI__Asus
```

The same pattern appears in the raw alert stream, independently of the model store:

```
jinu              <- 'VGSOC-LAP11\\JINU'(24), 'jinu'(20), 'VGSOC-LAP11\JINU'(6)
renuk             <- 'VakraX\\renuk'(25),     'VakraX\renuk'(19)
virtu             <- 'PRAJWAL\virtu'(13),     'PRAJWAL\\virtu'(10)
amaan             <- 'AMAANKHAN\\amaan'(11),  'AMAANKHAN\amaan'(7)
user              <- 'user'(3), 'VGSOC-LAP15\User'(3), 'VGSOC-LAP15\\User'(2), 'User'(1)
jinu.koshy        <- 'VGINFO\\jinu.koshy'(6), 'VGINFO\jinu.koshy'(1)
utkarsh.chandekar <- 'VGINFO\utkarsh.chandekar'(1), 'VGINFO\\utkarsh.chandekar'(1)
```

**10 of 135 identities (7.4%) in the alert sample are duplicates of another identity**, covering
153 alerts. Three distinct defects produce them:

1. **Escaping inconsistency** — the same event arrives sometimes as `DOMAIN\user`, sometimes as
   `DOMAIN\\user`, depending on how many JSON encode/decode hops it took through the bridge.
   These are two different dictionary keys to us.
2. **Qualified vs bare** — `VGSOC-LAP11\JINU` and `jinu` are never related.
3. **Case** — `JINU` vs `jinu`, `User` vs `user`.

Each duplicate halves the training data available to the real person's baseline and gives an
attacker a fresh, empty, instantly-trusted identity to operate under.

### 2.4 The finding that matters most: 103 of our 135 "users" are strangers

Splitting the named accounts in the sample by whether their source IP is RFC1918 or public:

| | Distinct account names | Alerts |
|---|---:|---:|
| Only ever seen from an **external** IP | **103** | 1,185 |
| Only ever seen on an **endpoint** (no src IP) | 32 | 273 |
| Mixed | 0 | — |

Zero named-account alerts in the sample come from an internal IP. The external-only list is
unmistakable:

```
root, janya, jesica, kaycie, kyrsten, makyla, michayla, monae, myesha,
postgres, y2unix, zabbix, lani, localhost, admin, debian, root1, user,
pi, mysql, guest, server, test, odoo, ...
```

These are **SSH brute-force username guesses against CPU-SRV-208 from the public internet.** They
are not employees. `janya`, `jesica`, `kaycie`, `kyrsten` and `makyla` have 14 alerts each, each
from exactly one external IP — that is a dictionary being walked, logged once per name.

The engine is building a 35→24→12→24→35 behavioural autoencoder for a username an attacker typed
once and never used again.

Two consequences, both bad:

- **`root` is one baseline for 912 alerts from 16 different external IPs.** Sixteen unrelated
  attackers are averaged into a single "normal" profile. Their collective behaviour *is* the
  baseline, so none of them deviates from it. We are teaching the model that being brute-forced
  is normal for `root`.
- **Every dictionary name is a brand-new entity with no history.** Under
  `get_baseline_deviation()` a first-sight entity has nothing to deviate from, so the per-entity
  signal contributes nothing and the fused score leans entirely on the global Isolation Forest.

---

## 3. What established UEBA products do

The industry name for the missing component is **entity stitching** (also identity resolution).
None of the major products key behaviour on a raw log username field.

### Splunk UBA

Splunk resolves identity by correlating dedicated data sources rather than trusting one field:

- **Authentication** — IP→host, IP→user, host→user
- **DNS** — IP→hostname
- **DHCP** — IP→MAC, IP→hostname
- **VPN** — IP→user

Splunk's own guidance: *"The most accurate identity resolution is achieved by having all of the
data sources ... you must have at least one."* Asset and identity correlation in Enterprise
Security is driven by lookup tables maintained outside the event stream.

- https://help.splunk.com/en/splunk-user-behavior-analytics/get-started/get-data-in/5.4.1/get-data-into-splunk-uba/data-sources-for-splunk-uba
- https://help.splunk.com/en/splunk-enterprise-security/administer/administer-splunk-enterprise-security/8.1/administer-asset-and-identity-data/overview-of-asset-and-identity-correlation

### Microsoft Sentinel UEBA

Sentinel keeps identity in a **separate, authoritative table** — `IdentityInfo` — synchronised
from Entra ID and on-premises AD, not inferred from logs. Relevant to us:

- It carries **stable identifiers**: `AccountSID`, `AccountObjectId`, `AccountUPN`,
  `SAMAccountName` (renamed `AccountName` in the unified schema), alongside the cosmetic
  `AccountDisplayName`. Behaviour is keyed on the stable ones.
- It carries **org context** used for peer comparison: `Department`, `JobTitle`, `Manager`,
  `GroupMembership`, `BlastRadius`.
- It is **refreshed on a schedule** — full resync every 14 days, incremental within 15–30 minutes
  of a change in Entra ID.
- The behavioural output (`BehaviorAnalytics`) keeps `UserName` *and* `UserPrincipalName`, plus
  `SourceDevice`, `SourceIPAddress`, `DestinationDevice` — identity and machine are separate
  dimensions of one record, never collapsed into one key.
- Baselines are explicitly scoped and time-bounded: `FirstTimeUserConnectedFromDevice` (30-day
  baseline), `DeviceUncommonlyUsedByUser` (10-day), `ActionUncommonlyPerformedAmongPeers`
  (180-day).

- https://learn.microsoft.com/en-us/azure/sentinel/ueba-reference

### Exabeam

Exabeam builds host→IP→user mappings over time so activity can be attributed to a specific person
on a specific host at a particular time, and states the requirement plainly: use **stable user
identifiers (UPN or SAMAccountName, not display name)** — *"the same user appearing as `jsmith`,
`john.smith` and `J.Smith` breaks entity stitching."*

- https://www.exabeam.com/explainers/ueba/ueba-user-and-entity-behavior-analytics/

### The common pattern

1. An **identity store** that is authoritative and external to the log stream.
2. **Canonical, stable keys** — SID/UPN/SAMAccountName — with display names treated as cosmetic.
3. **Separate entity types.** A user, a host and an IP are different kinds of thing with
   different baselines; they are related by a mapping, not merged into one namespace.
4. **Time-bounded bindings.** "IP 10.200.11.42 was Nidhi's laptop between 09:14 and 17:30" — not
   forever.
5. **Peer groups** for comparison when an individual's own history is thin.

We currently have none of the five.

---

## 4. Recommendation

Four changes, in dependency order. Effort figures are engineering days for one developer.

### Change 1 — Typed entity keys (2 days) — **IMPLEMENTED 2026-10-26**

`_typed_entity()` in `ueba_preprocessor.py`, behind `identity_resolution.typed_keys`
(default off). Five namespaces:

| Type | Key | Meaning |
|---|---|---|
| `person` | `person:<canonical>` | a human being |
| `endpoint` | `endpoint:<ip\|host>` | a machine, and userless internal traffic |
| `service` | `service:<account>@<host>` | SYSTEM, LOCAL/NETWORK SERVICE, machine accounts (`$`) |
| `shared` | `shared:<account>@<host>` | root/admin/guest, scoped per host |
| `external` | `external:<ip>` | an actor out on the internet |

`typed_keys` forces `canonicalize` on (with a log line) rather than offering the half-state where
`person:VGINFO\JINU` and `person:jinu` would be two entities.

**The decisive rule, validated before implementation:** anything presenting from a public source
IP is external, whatever account name it offers, ahead of every other classification. The rule
never has to adjudicate a real employee against it — **no named account in the sample ever
appeared from a private source IP (0 of 1,458)**.

The target endpoint deliberately does *not* absorb that traffic either. Keying a brute-force flood
to `endpoint:CPU-SRV-208` would move the poisoning from `root`'s profile onto the server's and
teach us that being attacked is normal for it. External actors have no history, so they fall
through to the global Isolation Forest — the correct model for them, since it is the one that
knows what a port scan looks like across the whole estate.

**Measured on the 3,412-alert sample:**

```
TYPED KEYS — entities, and records behind them
  type         entities    records
  person             21        261
  endpoint            3         60
  service             6         50
  shared              1          5
  external           51       3036
  TOTAL              82       3412

flat scheme today: 175 entities. typed: 82.
Of the 137 accounts in the flat scheme, typed classification keeps 21 as people.
1936 records presented an account name from a public IP and are now external:
rather than that account's baseline.
```

A crosstab confirms where everything went: all 1,936 brute-force records leave the account
namespace, and **all 35 flat `ip:` entities in this sample are public addresses** and become
`external:`.

**Caveat on that ratio.** `ueba_alerts.jsonl` is the *alerts* file — post-0.75 threshold — so it
is heavily skewed toward inbound internet traffic. Internal userless traffic rarely scores above
the threshold, which is why `endpoint:` looks tiny here. The training corpus is the opposite.
Reclassifying the actual model store shows the real shape:

| The 397 `ip_*.pt` models | Count | Share |
|---|---:|---:|
| private → `endpoint:` | 367 | 92.4% |
| public → `external:` | 30 | 7.6% |

So this **refines the headline of this document**. "87.6% of our user models are IP addresses" is
true, but the fix is not to delete them — 367 of them are legitimate machine baselines that were
merely mislabelled as users. Only the 30 public ones are genuinely worthless, because they model
attacker behaviour. Combined with the ~15 dictionary-name models, roughly 45 of 453 models should
be discarded at the cutover rather than migrated.

**Residual duplicates that typed keys cannot fix.** The person list still contains
`person:firdo` / `person:firdous` and `person:renuk` / `person:renuka` — truncations and nicknames
with different tails. Neither canonicalisation nor typing can infer those; they are exactly what
the operator `mappings` block is for. Worth reviewing that list at the cutover.

**Tests.** `identity_diag.py --selftest` asserts 22 cases with no sample file needed — 11 for
`_is_public_ip` (private ranges, loopback, link-local, whitespace, malformed input must never be
treated as public) and 11 for `_typed_entity`, each stating the rule it protects. All pass. The
flag-off path remains bit-identical across all 3,412 keys after this change.

#### Original recommendation, retained for reference



Replace the single string key with an explicit `(type, id)` pair. Entity types:

| Type | Key | Example |
|---|---|---|
| `person` | canonical account | `person:jinu.koshy` |
| `endpoint` | hostname | `endpoint:VGSOC-LAP11` |
| `service` | account, scoped to host | `service:SYSTEM@DC_AD_srv` |
| `shared` | account, scoped to host | `shared:root@CPU-SRV-208` |
| `external` | source IP | `external:45.148.10.151` |

The decisive rule: **an account seen only from a public source IP is not a person.** It is an
authentication *attempt against* an endpoint, and it should be modelled as a property of the
target endpoint and of the external source — never as a new user. This alone removes 103 of our
135 "users" and 397 of 453 models from the person namespace, and turns the `root` brute-force
flood from 912 events of self-defined "normal" into a strong anomaly signal on
`endpoint:CPU-SRV-208`.

Service and shared accounts key on **(account, host)** rather than account alone, because `root`
on the ATM server and `root` on the GPU box are not the same actor. In the sample
`NT AUTHORITY\SYSTEM` spans 3 hosts (`DC_AD_srv`, `Nidhi`, `utkarsh_Pc`) and is currently one
baseline for all three.

### Change 2 — Canonical identity normalisation (1 day) — **IMPLEMENTED 2026-10-26**

> **Correction to the original analysis.** This document first said the fix was to add
> normalisation. That was incomplete: `ueba_config.yaml` already had an `identity_resolution`
> block, `enabled: true`, with five hand-written alias mappings. The reason nobody noticed it
> was not working is more interesting than the duplicates themselves.
>
> The alias map was applied at **`ueba_engine.py:684`** — at runtime, after feature extraction.
> The trainer never applied it (`grep identity ueba_trainer.py ueba_prepare_training_data.py`
> returns nothing). So training bucketed events by the raw name while the engine looked up the
> canonical one. Testing the five mappings against the real filename sanitiser
> (`ueba_models/autoencoder.py:147`) and the files on disk:
>
> ```
> RootSeeker            -> RootSeeker\Sujal      RootSeeker_Sujal        MISS -> global fallback
> sujalthakur2003@outl  -> RootSeeker\Sujal      RootSeeker_Sujal        MISS -> global fallback
> LAPTOP-08MIT8SI       -> LAPTOP-08MIT8SI\Asus  LAPTOP-08MIT8SI_Asus    HIT
> LAPTOP-08MIT8SI\\Asu  -> LAPTOP-08MIT8SI\Asus  LAPTOP-08MIT8SI_Asus    HIT
> cybersentinel-manage  -> cybersentinel-manager cybersentinel-manager   MISS -> global fallback
> ```
>
> **Three of five silently fell back to the global model.** The two that worked did so by
> coincidence — the canonical string someone typed happened to match a file training had already
> produced. `RootSeeker_Sujal` was never trained at all; that person's events are in
> `host_RootSeeker`, because training took the host fallback path.
>
> `resolve_entity()`'s own docstring promises *"training-time bucketing and runtime AE selection
> can never diverge."* Applying the map outside `resolve_entity()` is what broke that promise.
> **So the normalisation belongs inside `resolve_entity()`** — the one place both sides already
> share — not bolted onto the engine. That is how it was implemented.

**What shipped (code, not yet enabled):**

| File | Change |
|---|---|
| `ueba_preprocessor.py` | `canonical_identity()`, `_deescape()`, `apply_identity_config()`; applied on the account branch of `resolve_entity()` only |
| `ueba_config.yaml` | `canonicalize` / `casefold` / `strip_domain` / `shared_accounts` under `identity_resolution` |
| `identity_diag.py` | New read-only tool: reports exactly which keys merge, before the flag is flipped |

Wired into `FeatureExtractor.__init__` next to the existing `apply_noise_config(config)` call,
for the reason that call already documents: every consumer that builds a `FeatureExtractor` —
engine, trainer, batch preprocessor — picks it up, so they cannot disagree about what an entity
is.

**Measured on the 3,412-alert sample (`identity_diag.py`):**

```
DISTINCT ENTITY KEYS
  kind         before    after   merged
  account         137      128        9
  ip               35       35        0
  host              3        3        0
  TOTAL           175      166        9

9 of 137 account identities (6.6%) were duplicates,
across 163 of 2252 account records (7.2%)
```

The eight merge groups:

```
jinu              <- 'VGSOC-LAP11\JINU'(6), 'VGSOC-LAP11\\JINU'(24), 'jinu'(30)
renuk             <- 'VakraX\\renuk'(25), 'VakraX\renuk'(19)
virtu             <- 'PRAJWAL\\virtu'(10), 'PRAJWAL\virtu'(13)
amaan             <- 'AMAANKHAN\\amaan'(11), 'AMAANKHAN\amaan'(7)
jinu.koshy        <- 'VGINFO\\jinu.koshy'(6), 'VGINFO\jinu.koshy'(1)
utkarsh.chandekar <- 'VGINFO\\utkarsh.chandekar'(1), 'VGINFO\utkarsh.chandekar'(1)
user              <- 'User'(1), 'user'(3)
vgsoc-lap15\user  <- 'VGSOC-LAP15\User'(3), 'VGSOC-LAP15\\User'(2)
```

That last group is the `shared_accounts` guard working: `user` is a shared local account, so it
keeps its host prefix rather than merging into the estate-wide `user` bucket. Without that guard,
`VGINFO\admin` and `LAPTOP-07\admin` would collapse into one baseline averaging unrelated
actors — the same defect that makes `root` useless today.

**Verified properties:**

1. **Flag off is a bit-identical no-op** — all 3,412 keys match the pre-change module exactly.
2. **Flag on changes the keys** — 175 → 166 distinct.
3. **`ip:` and `host:` keys are untouched either way** — all 38 identical. This is the
   type-awareness guarantee below, enforced by test rather than by intention.

**Two findings from the diagnostic:**

- `cybersentinel-manager` as a mapping target is **dead and always was**. `host_cybersentinel-manager.pt`
  exists, so that string is a *hostname*; `resolve_entity()` keys hostnames as `host:<name>` and
  canonicalisation deliberately never touches them, so no account key can ever equal it. The
  mapping should be deleted.
- `LAPTOP-08MIT8SI__Asus.pt` **and** `LAPTOP-08MIT8SI_Asus.pt` both exist on disk — the escaping
  defect visible at the model level, two files for one person. They collapse to `asus` after the
  retrain.

**Still pending:** the flag stays `false` until the retrain on the new server (Phase C). Turning
it on strands every existing per-entity model, because changing the key changes which `.pt` file
is looked up; those entities fall back to the global model until training rebuilds them. The
inert alias-map block at `ueba_engine.py:684` should be removed at that cutover — it becomes a
no-op automatically, since canonical keys never match the raw alias keys it looks for.

#### Original recommendation, retained for reference



For `person` keys only: normalise the escaping (`\\` → `\`), strip the `DOMAIN\` / `HOST\`
prefix, case-fold, and keep the original string as a display alias. This is the cheapest fix in
the whole list and immediately recovers the 7.4% duplicate rate and the 5 split models.

**Caveat, found while testing this.** A naive canonicaliser that treats `_` as a separator
*over-merges*: it collapsed `host_DC_ATM_SRV` and `host_GPU_SRV` into one key `srv`, which is a
false merge of two unrelated servers. Normalisation must therefore be **type-aware** — strip
domain prefixes on account names, never on hostnames — and must be validated against the
existing key list before it is switched on. Do not ship a blind `re.sub`.

### Change 3 — An identity-resolution table (3 days) — **IMPLEMENTED 2026-10-26**

`ueba_identity.py`, behind `identity_resolution.bindings.enabled` (default off). Answers the
question Phases A and B cannot: *"`endpoint:10.200.11.157` exfiltrated 4 GB at 02:30 — who was
that?"*

**The schema I proposed in this document was wrong in two ways, and the data is why.**

**1. No `mac` column.** A MAC address appears *nowhere* in the data — not under `mac`, `src_mac`,
`dst_mac`, `hwaddr` or `mac_address`, at any nesting depth. The column would be permanently NULL
and would imply a capability we do not have. The schema keys on `(kind, value)` instead, so `mac`
becomes a new *kind* the day a DHCP feed arrives, with no migration.

**2. No per-source `confidence` constant.** `auth=0.9, dhcp=0.8` would be numbers we invented.
What actually determines whether an attribution is trustworthy is in the data: how many distinct
people were seen on that host, and how recently. So confidence is **derived at query time**:

```
confidence = share × recency
```

`share` is this person's fraction of observations on the value; `recency` decays linearly from 1.0
at `last_seen` to 0.0 at the window edge. Deliberately pessimistic — an attribution is a lead for
an analyst, not a verdict, and a number that is honest about a shared server beats one that is
confidently wrong.

**Also measured: we have exactly one stitching source.** `event_category` over the sample is
auth 2,596 / system 523 / process 283 / web 9 / other 1. **There is no DHCP, DNS or VPN feed
reaching UEBA at all.** Splunk uses all four and says you need at least one; this is that minimum,
and the document should not have implied otherwise.

**Measured attribution coverage:**

```
BINDINGS BUILT (auth-derived, person: entities only)
  rows 35 | people 21 | distinct host/addr 23 | observations 300
  values used by >1 person: 3   <- no confident attribution from these

  utkarsh_Pc          36 events -> person:utkarsh.chandekar  conf 0.97
  Access-SRV-2.140    12 events -> person:jinu  conf 0.32  (11 candidates)
  CPU-SRV-208         12 events -> no binding

  48 of 60 endpoint: records (80%) could be attributed to a person.
```

The three cases are exactly the behaviour wanted: a personal laptop attributes confidently; a
shared access server returns eleven candidates and refuses to be confident; the brute-force target
has no binding at all, because no legitimate person ever authenticated to it internally.

**Unplanned benefit — the bindings resolve the residual duplicates.** Phases A and B could not
merge `person:firdo`/`person:firdous` or `person:renuk`/`person:renuka` (different tails). The
binding table supplies the evidence:

```
person:firdo    host:firdous(10)
person:renuk    host:Renuka(44)
```

Each truncated identity's host is named after the person the other key refers to. Those two
`mappings` entries can now be written with justification rather than guesswork.

**A bug this work found and fixed.** Opening a second SQLite connection to the profile database
deadlocks it. The binding table is written mid-transaction from `UserProfileStore.update()`, so
the binding connection held a write lock that the profile store's own connection waited on, and
the next `INSERT INTO users` failed with `database is locked` — taking out profiling, which
matters far more than a binding. `IdentityBindings` now accepts a borrowed connection and
`UserProfileStore` passes its own. One connection, one transaction, and the two tables are
consistent with each other by construction.

**Gating.** `bindings.enabled` requires `typed_keys`, because bindings key on `person:` entities;
with typed keys off every `record()` would be rejected and the table would sit empty while looking
enabled, which is worse than being off. The flag refuses and logs rather than pretending. With
the flag off, the table is never even created — verified.

**Tests.** `python3 ueba_identity.py --selftest` asserts 31 cases with no sample file: the
`+0530` timestamp format the data actually uses (no colon, which `fromisoformat` rejects before
3.11), that only `person:` keys bind, that repeat observations upsert rather than duplicate, the
share/recency maths on both an exclusive and a shared host, window expiry, and that an unknown
value returns empty rather than a guess. `identity_diag.py --bindings` previews coverage from a
sample without writing to disk.

**Not yet wired into scoring.** Using a binding to re-attribute an endpoint's anomaly to a person
changes detection behaviour, so it belongs with the retrain cutover behind its own flag.
Populating is additive and safe in the meantime, and the longer it runs first the better the
history it can answer from.

#### Original recommendation, retained for reference



A new table binding observations over time:

```sql
CREATE TABLE identity_bindings (
  person_key   TEXT,     -- canonical, from Change 2
  endpoint     TEXT,
  src_ip       TEXT,
  mac          TEXT,
  first_seen   TIMESTAMP,
  last_seen    TIMESTAMP,
  confidence   REAL,
  source       TEXT      -- 'auth' | 'dhcp' | 'dns' | 'vpn' | 'manual'
);
```

Feasibility is already confirmed in our data: of 2,596 auth events in the sample, **1,036 (40%)
carry both a user and a host**, which is exactly the IP→user / host→user edge Splunk builds from.
That is enough to seed the table today without any new log source.

The payoff is attribution for the userless majority. 39 events in the sample come from 12
*internal* source IPs with no user field — those are real staff activity we currently file under
`ip:10.200.11.x` and could attribute to a person via a time-window join. The remaining 1,851
userless events are from 48 external IPs and correctly belong to `external:` entities.

Adding DHCP and DNS feeds later raises coverage further; the schema already has the columns.

### Change 4 — Peer groups (2 days)

Once identities are canonical and typed, group them (by endpoint class, by OU, or manually for a
site the size of OPTCL's) and compare a thin-history identity against its peer group instead of
against nothing. This is what Sentinel's `*AmongPeers` enrichments do, and it is what fixes the
cold-start hole where a brand-new identity cannot deviate from a baseline it does not have.

A related gap worth closing in the same pass: `get_baseline_deviation()`
(`ueba_preprocessor.py:962`) scores only `avg_hour`, `avg_risk` and `avg_events_1h`. The `users`
table already collects **`seen_agents` and `seen_countries` and never scores them**
(`ueba_preprocessor.py:831`). Those are precisely Sentinel's
`FirstTimeUserConnectedFromDevice` and `FirstTimeUserConnectedFromCountry` signals — already
being persisted, costing nothing, and currently discarded.

### Total: ~8 engineering days

Change 2 is a 1-day fix with immediate measurable benefit and should go first regardless of
whether the rest is scheduled. Change 1 is the one that changes detection quality most.

---

## 5. Effect on the OPTCL RFP assessment

| SN | Requirement | Today | After |
|---|---|---|---|
| 5 | User/entity behaviour baselining | Partial — baselines exist but 87.6% are IP-keyed | Yes, per person |
| 16 | Peer-group comparison | **No** | Yes (Change 4) |
| 19 | Identity correlation across sources | Partial | Yes (Change 3) |
| 30 | Compromised-account detection | Weak — shared accounts averaged together | Yes (Change 1) |
| 42 | Insider-threat attribution to a named person | Partial — 7.4% split identities | Yes (Changes 2+3) |
| 66 | Lateral-movement tracking (user across hosts) | **No** — no user↔host binding | Yes (Change 3) |
| 67 | Entity risk scoring | Partial | Yes |

Two rows currently answered "Can Be" become defensible "Yes" answers, and SN 30 and SN 42 move
from a claim we would struggle to demonstrate to one we can show on screen. Given the bid, that
is a strong argument for doing Changes 1–3 before the demo rather than after award.

---

## 6. What this does not require

- No new log sources. Changes 1, 2 and 4 use data we already parse; Change 3 is seeded from auth
  events we already receive.
- No retraining infrastructure. The autoencoder architecture is unchanged; only the key under
  which each model is stored and looked up changes.
- No model migration. The 397 `ip_*.pt` files become `external:` / `endpoint:` models by
  reclassification, and the ~15 dictionary-name models should simply be discarded — they encode
  attacker behaviour, not baselines.

---

## Sources

- Splunk UBA data sources for identity resolution —
  https://help.splunk.com/en/splunk-user-behavior-analytics/get-started/get-data-in/5.4.1/get-data-into-splunk-uba/data-sources-for-splunk-uba
- Splunk Enterprise Security, asset and identity correlation —
  https://help.splunk.com/en/splunk-enterprise-security/administer/administer-splunk-enterprise-security/8.1/administer-asset-and-identity-data/overview-of-asset-and-identity-correlation
- Microsoft Sentinel UEBA reference (`IdentityInfo`, `BehaviorAnalytics`, baseline windows) —
  https://learn.microsoft.com/en-us/azure/sentinel/ueba-reference
- Exabeam, UEBA explainer (entity stitching, stable identifiers) —
  https://www.exabeam.com/explainers/ueba/ueba-user-and-entity-behavior-analytics/
