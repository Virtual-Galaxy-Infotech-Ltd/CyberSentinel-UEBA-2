# RFP SN 18 — behaviour-model coverage

Sprint 1, story 2.1, sub-points 4 and 9: the coverage baseline, and the figure
**achieved** rather than the figure intended.

Measured on the live install, 12-Nov-2026, by `tools/sn18_coverage.py`.
Re-run it after every retrain — the point of sub-point 9 is that this number
is checked, not assumed.

```
MODELS ON DISK
  per-entity : 400
  cohort     : 0
  global     : present

ENTITIES
  tracked                  : 184,195
  eligible (>= 2,000 events)  : 1,007
  placed in a cohort       : 4,965 in 8 cohorts

COVERAGE ACHIEVED — by entity count
  entity         400    0.22%
  cohort           0    0.00%
  global     183,795   99.78%

COVERAGE ACHIEVED — by event volume (the number that describes detection)
  entity      53,565,037   34.69%
  cohort               0    0.00%
  global     100,825,442   65.31%

PROJECTED after a retrain that builds every cohort model
  entity         400 entities   0.22%  |      53,565,037 events  34.69%
  cohort       1,418 entities   0.77%  |       3,325,037 events   2.15%
  global     182,377 entities  99.01%  |      97,500,405 events  63.15%
```

## Reading these numbers

**Two figures, because one of them lies.** By entity count, coverage is
0.22% — which sounds like the feature does nothing. By event volume it is
**34.69%**: better than a third of all observed activity is judged by a model
built for that specific entity. The gap is the long tail. Of 184,195 tracked
entities, the overwhelming majority have produced a handful of events each
and will never qualify for their own model, nor should they. The entity-count
figure mostly measures how many one-event entities the store has accumulated,
not how well the estate is covered.

**Cohort coverage is 0% today, and that is expected rather than broken.** The
cohort tier is active in the engine — 4,965 entities placed in 8 cohorts, as
the startup log states — but no cohort models exist on disk yet, so every
member correctly falls back to the global model. Cohort training was skipped
on every previous run by an ordering defect in the weekly script: peer groups
were rebuilt *after* the trainer had already read them (fixed in `e2164c2`,
pinned by `tests/test_retrain_order.py`). The first retrain after that fix is
what turns the projected row into the achieved row.

**400 models against 1,007 eligible entities** is not a shortfall. Eligibility
here is counted from `total_events`, which is cumulative over all time, while
the trainer re-checks how many rows an entity actually has in the *current*
`features.h5` window and skips anyone under the threshold there. The
difference is entities that were busy historically and are quiet now. The
re-check is the correct behaviour: training a model on 40 rows because an
entity was busy in August would produce a model that memorises those rows.

## One finding that needs a decision

**3,169 of the 4,965 cohort members are not tracked entities at all.** They
are address-shaped — `ip:115.242.143.178`, `ip:103.173.208.31` and so on —
and have no row in the profile store, so no entity will ever resolve to those
cohort slots. Two consequences:

1. Roughly two thirds of the cohort assignment is inert. The 8 cohorts cover
   far fewer real entities than the headline 4,965 suggests; only 1,418
   tracked entities would actually gain cohort coverage.
2. More seriously, it suggests peer grouping is clustering over **addresses**
   rather than people and hosts. SN 42 warns about exactly this: a cohort
   drawn wide over addresses makes every attacker a behavioural peer of every
   other, which is the opposite of what peer deviation is for.

This is a `build_peer_groups.py` scoping question, not a tier defect — the
tier faithfully uses whatever assignment it is given. It should be settled
before the cohort models built on that assignment are relied upon.
