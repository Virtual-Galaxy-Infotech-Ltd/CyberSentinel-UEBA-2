# UEBA — Deep Capability Analysis

Source-level analysis, 2026-10-22. Written after an earlier assessment was found
to have under-stated the reporting capability. This pass reads the actual
implementations and the actual production data rather than matching on filenames
or keywords.

**Method change that mattered:** every claim below is checked against either the
real implementation or a sample of **3,412 production alerts**. Several earlier
conclusions were wrong because they were inferred from a manifest or a grep.

---

## 1. Defect found — four alert reasons can never fire

`ueba_engine.py::build_anomaly_reasons()` (lines 267–288) tests enrichment paths
that do not exist in the data.

| Code tests | Actual field in the data | Result |
|---|---|---|
| `enrich.anomalies.is_tor` | `enrich.anomalies.is_tor_traffic` | reason `tor_exit_node` never emitted |
| `enrich.anomalies.is_data_exfiltration` | `enrich.anomalies.is_data_exfil` | reason `data_exfiltration` never emitted |
| `enrich.geo.cross_border` | `enrich.anomalies.cross_border` | reason `cross_border_access` never emitted |
| `enrich.geo.cross_continent` | `enrich.anomalies.cross_continent` | reason `cross_continent_access` never emitted |

Confirmed against 3,412 alerts: those four reason strings appear **zero** times.

**Detection is not affected.** `ueba_preprocessor.py` already handles both
spellings with `or` fallbacks:

```
vec[11] = is_tor        OR is_tor_traffic
vec[15] = is_data_exfiltration OR is_data_exfil
vec[26] = geo.cross_border     OR anomalies.cross_border
vec[27] = geo.cross_continent  OR anomalies.cross_continent
```

So the models score these signals correctly; only the **human-readable
justification** omits them. An analyst sees the alert but not the reason.

**Severity:** medium. **Fix:** 4 lines in `build_anomaly_reasons()`. **Relevant to
SN 8** (show the basis for the anomaly) and **SN 49** (exfiltration).

---

## 2. Two baseline dimensions are collected but never scored

`UserProfileStore` persists per entity: `avg_hour`, `avg_risk`, `avg_events_1h`,
**`seen_countries`**, **`seen_agents`**, `total_events`, `first_seen`, `last_seen`.

But `get_baseline_deviation()` (lines 962–988) uses only three:

```
deviation = 0.4*hour_dev + 0.4*risk_dev + 0.2*event_rate_dev
```

`seen_agents` (the devices an entity normally uses) and `seen_countries` are
written on every update and never read by scoring.

**Why it matters:** SN 19 asks for a model of *the times and devices normally used
by each username*. Times are modelled and scored. Devices are **recorded but not
scored** — the data is already there, so this is a scoring change rather than new
collection. Estimated 8 days.

Similarly `last_seen` is used only for baseline weight decay, not for dormancy
detection (SN 47).

---

## 3. Entity resolution is stronger than first assessed

`resolve_entity()` (lines 131–175) resolves in priority order:

1. `subject.name`
2. `data.srcuser` / `data.dstuser`
3. raw-event equivalents
4. `object.name` — **only for auth events**, because on network events it is a
   destination hostname
5. `ip:<address>`
6. reporting host
7. `unknown`

It also guards against URL fragments being mistaken for usernames.

**Consequence for the tender:** a *user* is keyed on username, so user identity is
continuous across IP address changes — **SN 16 is satisfied**. IP keying applies
only to userless network and firewall events, which is where **SN 5** (uniquely
identifying *machines* under DHCP) remains partial.

The comment records why this design exists: a previous `unknown` bucket absorbed
~74% of events and produced a meaningless averaged model.

---

## 4. Several gaps are data limitations, not product gaps

Verified against the 3,412-alert sample.

| Requirement | Finding | Implication |
|---|---|---|
| **SN 12, 46** — data streaming in/out, abnormal transfer volume | **No byte, volume or transfer-size field exists anywhere in the forwarded data.** Only `network.direction`, `protocol`, `service` | Per-entity volume baselining is **impossible** until the SIEM forwards byte counts. No amount of UEBA development substitutes |
| **SN 43** — change in account privileges | Event categories present are `auth`, `system`, `process`, `web`. **No account-management or privilege category** | Requires the SIEM to forward privilege-change events |
| **SN 58** — search by MAC address | **Zero MAC addresses in 3,412 alerts** | MAC search needs the field added upstream, not a search change |
| **SN 57** — application-layer decode | `network.protocol` and `network.service` are present; deeper decode is not | Bounded by SIEM decode scope |

This distinction matters for the bid: these should be answered as dependent on the
SIEM's forwarded schema, not offered as UEBA development items with a day count
we cannot honour alone.

---

## 5. What the platform detects on its own vs what it relays

Of 13 alert reasons, **11 originate from SIEM enrichment flags** and 2 from UEBA's
own models.

| Produced by UEBA's own models | Relayed from SIEM enrichment |
|---|---|
| `isolation_forest_anomalous` / `_highly_anomalous` | brute force, impossible travel, malicious IP, port scan, lateral movement, after hours, high frequency, Tor, exfiltration, cross-border, cross-continent |
| `behavioral_baseline_deviation` | |

Firing rates across 3,412 alerts:

| Reason | Count |
|---|---|
| `behavioral_baseline_deviation` | 3,412 (100%) |
| `after_hours_activity` | 2,836 |
| `isolation_forest_anomalous` | 2,317 |
| `high_frequency_events` | 1,892 |
| `isolation_forest_highly_anomalous` | 791 |
| `malicious_ip_reputation` | 762 |
| `brute_force_detected` | 359 |
| `impossible_travel` | 100 |
| `lateral_movement` | 41 |
| `port_scan_detected` | 2 |

**This is a legitimate UEBA architecture** — the platform's contribution is
per-entity baselining, fusion, scoring and suppression, not re-detecting what the
SIEM already flags. It should be described that way rather than implying UEBA
performs all the primitive detections itself.

---

## 6. Assessment changes arising from this analysis

| SN | Was | Now | Reason |
|---|---|---|---|
| 13 | Can Be | **Yes** | Account-takeover indicators are present and firing in production (impossible travel 100, after-hours 2,836, baseline deviation 3,412), fused into an identity risk score |
| 16 | Can Be | **Yes** | Username-first entity keying gives continuous user tracking across IP changes |
| 49 | Can Be | **Yes** | Insider threat, hijacking and exfiltration are all detected; exfiltration via the SIEM indicator scored against the entity baseline |
| 12 | Can Be (dev) | **Can Be (SIEM dependency)** | No volume fields exist in the feed |
| 46 | Can Be (8d) | **Can Be (SIEM dependency + 8d)** | Byte counts must be added upstream first |
| 43 | Can Be (5d) | **Can Be (SIEM dependency + 5d)** | No privilege-change events forwarded |
| 58 | Can Be (3d) | **Can Be (3d, MAC upstream)** | Full-text search already covers hostname/user/IP; MAC absent from data |
| 19 | Can Be (10d) | **Can Be (8d)** | Device set already collected, only scoring missing |
| 47 | Can Be (3d) | **Can Be (3d)** | Confirmed `last_seen` exists but is used only for decay weighting |

**Position after this analysis: 29 Yes · 36 Can Be · 1 No.** Remaining engineering
effort 435 days, down from 467 as several items proved smaller or turned out to be
upstream dependencies.

---

## 7. Engineering actions arising

| # | Action | Effort | Priority |
|---|---|---|---|
| A1 | Fix the four dead reason checks in `build_anomaly_reasons()` | 4 lines | **High** — silently degrades alert explanation today |
| A2 | Score `seen_agents` in `get_baseline_deviation()` | 8 days | High — data already collected; closes SN 19 |
| A3 | Add `reportlab`, `openpyxl` to `requirements.txt` | 2 lines | **High** |
| A4 | Explicit dormancy rule using `last_seen` | 3 days | Medium — closes SN 47 |
| A5 | Join device registry labels into search | 3 days | Medium — part of SN 58 |
| A6 | Consider scoring `seen_countries` alongside `seen_agents` | with A2 | Medium |

## 8. Questions for the SIEM team

1. Can byte/transfer-volume counts be added to the forwarded schema? (SN 12, 46)
2. Can account-management and privilege-change events be forwarded? (SN 43)
3. Can MAC addresses be included? (SN 58)
4. Which application-layer protocols are decoded upstream? (SN 57)
5. Are the `is_tor_traffic` / `is_data_exfil` / `cross_border` field names stable?
   The drift in A1 suggests the schema has changed at least once without
   downstream notice.
