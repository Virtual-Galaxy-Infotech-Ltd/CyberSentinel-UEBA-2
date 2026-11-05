#!/usr/bin/env python3
"""Which behavioural model judges an entity — RFP SN 18.

THE PROBLEM THIS SOLVES

Before this module there were exactly two tiers:

    own model (>= min_events_per_user)  -->  global.pt

and nothing between them. `min_events_per_user` is 2000 on this deployment, so
the trainer counted everyone below it and threw them away (`skipped_sparse`).
Measured on the 2026-11-03 staged run: 261 models, of which **219 were
IP-keyed and only 42 were named people or hosts**. Every other account in the
estate was judged by one model built from the whole population, which is the
definition of "UEBA stops working for quiet accounts" that SN 18 is written
against.

A quiet account is not an account with nothing to learn. It is an account with
too little history to learn from ALONE. So it is judged against the people it
behaves like, which is strictly more specific than the whole estate:

    own model  -->  cohort model  -->  global.pt

WHY THE TIER LIVES IN ITS OWN MODULE

Three copies of the filename sanitiser existed — twice in ueba_trainer.py and
once in ueba_models/autoencoder.py. The trainer decides which models to
CREATE and the scorer decides which to LOAD, and if those two ever disagree
about a name the scorer silently falls through to the global model and nothing
reports it. That is precisely the failure that broke the weekly retrain for
months: prepare and the trainer each had their own idea of where features.h5
lived, so one wrote where the other was not looking. One source of truth, used
by both sides.

WHAT IS AND IS NOT DECIDED HERE

Training time needs event counts to choose a tier. Scoring time does not — it
asks only "does a model for this entity exist on disk, then does one for its
cohort". Keeping those apart is deliberate: the scorer must never need the
training corpus to answer a question about one event.
"""
from __future__ import annotations

import re

# `cohort:` rather than a bare id, because `model_used` travels onto every
# alert and several callers test it to decide whether it names a real person
# (see is_entity_model). An unprefixed cohort id would be read as a username
# and shown to an analyst as the account that acted — the same class of bug as
# `model_used='global'` once leaking into the user column.
COHORT_PREFIX = "cohort:"

# Reserved model names that are not entities.
GLOBAL_MODEL = "global"
_NOT_AN_ENTITY = frozenset((GLOBAL_MODEL, "unknown", "", "none", "null"))

TIERS = ("entity", "cohort", "global")

# A cohort trained on a handful of pooled rows memorises them exactly as a
# sparse per-entity model would, which is the thing the cohort tier exists to
# avoid. Below this the cohort is not worth building and its members fall
# through to the global model, which is honest rather than falsely specific.
DEFAULT_COHORT_MIN_ROWS = 500

# A "cohort" of one is a per-entity model wearing a different hat: it gets the
# single member's own data and none of the generalisation that justifies the
# tier. Two is the smallest group that pools anything.
DEFAULT_COHORT_MIN_MEMBERS = 2


def safe_model_name(name) -> str:
    """The on-disk stem for a model name.

    THE one sanitiser. It reproduces exactly what ueba_trainer.py and
    ueba_models/autoencoder.py each used to compute separately, character for
    character, so existing model files keep resolving and no retrain is needed
    to adopt this module:

        "".join(c if c.isalnum() or c in "-_" else "_" for c in name)

    Note what that means for real keys: `VGINFO\\jane.doe` becomes
    `VGINFO_jane_doe` and `cohort:7` becomes `cohort_7`. Two different entities
    CAN collide (`a.b` and `a_b` both give `a_b`) — that is pre-existing
    behaviour, not introduced here, and changing it would orphan every model
    file on disk. It is recorded here because this is now the one place anyone
    would look.
    """
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in str(name or ""))


def cohort_model_key(cohort_id) -> str:
    """The logical name of a cohort's model, e.g. `cohort:sales-3`.

    This is what lands in `model_used` and what keys the entry in
    thresholds.json, so a cohort's threshold is looked up by the model that
    produced the error rather than by the entity that happened to be scored.
    """
    cid = str(cohort_id or "").strip()
    if not cid:
        return ""
    if cid.startswith(COHORT_PREFIX):
        return cid
    return "%s%s" % (COHORT_PREFIX, cid)


def is_cohort_model(model_used) -> bool:
    return str(model_used or "").startswith(COHORT_PREFIX)


def cohort_id_of(model_used) -> str:
    """The bare id inside a cohort model key, or ""."""
    m = str(model_used or "")
    return m[len(COHORT_PREFIX):] if m.startswith(COHORT_PREFIX) else ""


def is_entity_model(model_used) -> bool:
    """Whether `model_used` names a real entity, and so may be shown as one.

    Several places treat `model_used` as a username when it is not `global`
    or `unknown`. That test was a denylist, so every NEW reserved name had to
    be added to it in every copy or it would leak into the user column. A
    cohort key is the first such name since; this predicate is where the next
    one gets handled once.
    """
    m = str(model_used or "").strip()
    if m.casefold() in _NOT_AN_ENTITY:
        return False
    return not is_cohort_model(m)


def tier_of(model_used, entity=None) -> str:
    """Which tier judged this event: 'entity', 'cohort' or 'global'."""
    if is_cohort_model(model_used):
        return "cohort"
    if str(model_used or "").strip().casefold() in _NOT_AN_ENTITY:
        return "global"
    return "entity"


def cohort_for(assignment, entity) -> str:
    """The cohort id this entity belongs to, or "".

    Delegates to ueba_peers so there is one definition of membership — the
    same assignment that drives peer-group deviation (SN 42) also decides
    which model judges a quiet account, rather than a second grouping that
    could disagree with the first.
    """
    if not assignment or not entity:
        return ""
    try:
        import ueba_peers
    except Exception:
        return ""
    ent = str(entity).strip()
    candidates = [ent]
    # TYPED vs BARE keys. ueba_peers builds its assignment from the profile
    # store, which may use typed keys (`person:jane`), while the scorer is
    # handed whatever the engine resolved — and on this deployment that is a
    # bare name: thresholds.json holds `admin` and `LAPTOP-08MIT8SI\Asus`,
    # not `person:admin`. A mismatch here is invisible. The cohort tier simply
    # never fires and every quiet entity keeps falling to the global model,
    # which is indistinguishable from the bug SN 18 was raised about.
    if ":" in ent:
        candidates.append(ent.split(":", 1)[1])          # person:jane -> jane
    else:
        for prefix in ("person", "user", "entity"):
            candidates.append("%s:%s" % (prefix, ent))   # jane -> person:jane
    for cand in candidates:
        if not cand:
            continue
        try:
            hit = ueba_peers.cohort_of(assignment, cand) or {}
        except Exception:
            return ""
        if hit.get("cohort"):
            return str(hit["cohort"])
    return ""


def plan_training(entity, rows_available, assignment=None,
                  min_events: int = 2000,
                  cohort_min_rows: int = DEFAULT_COHORT_MIN_ROWS) -> dict:
    """{'tier', 'model', 'why'} — which model should learn this entity.

    TRAINING-time only; scoring does not call this. `rows_available` is the
    number of rows this entity actually has in the feature file, not the
    cumulative total from the profile store — the H5 window is usually much
    smaller and training on the larger figure was already guarded against.
    """
    ent = str(entity or "").strip()
    if not ent:
        return {"tier": "global", "model": GLOBAL_MODEL,
                "why": "no entity named"}

    if rows_available >= min_events:
        return {"tier": "entity", "model": ent,
                "why": "%d rows is enough to learn this entity alone "
                       "(threshold %d)" % (rows_available, min_events)}

    cid = cohort_for(assignment, ent)
    if cid:
        return {"tier": "cohort", "model": cohort_model_key(cid),
                "why": "only %d rows of its own (threshold %d), so it is "
                       "judged against cohort %s"
                       % (rows_available, min_events, cid)}

    return {"tier": "global", "model": GLOBAL_MODEL,
            "why": "only %d rows of its own (threshold %d) and no cohort "
                   "placement, so the general model applies"
                   % (rows_available, min_events)}


def resolve_scoring(entity, has_entity_model, assignment=None,
                    cohort_model_exists=None) -> dict:
    """{'tier', 'model', 'why'} — which model should JUDGE this event.

    Deliberately takes predicates rather than doing IO: the scorer already
    holds an LRU cache and knows what it can load, and this keeps the decision
    testable without a models directory.

    `has_entity_model(name) -> bool` and `cohort_model_exists(key) -> bool`.
    """
    ent = str(entity or "").strip()
    if ent and has_entity_model and has_entity_model(ent):
        return {"tier": "entity", "model": ent,
                "why": "this entity has its own model"}

    cid = cohort_for(assignment, ent)
    if cid:
        key = cohort_model_key(cid)
        if cohort_model_exists is None or cohort_model_exists(key):
            return {"tier": "cohort", "model": key,
                    "why": "no model of its own; judged against cohort %s" % cid}

    return {"tier": "global", "model": GLOBAL_MODEL,
            "why": "no model of its own and no cohort model available"}


def selftest() -> int:
    failures = []
    checked = []

    def ok(label, cond):
        checked.append(label)
        if not cond:
            failures.append(label)

    # ── the sanitiser must match what is already on disk ──
    # Reproduced from the two historical copies. If this drifts, every
    # existing model file stops resolving and the scorer silently falls back
    # to global for everybody — a total loss of per-entity detection that
    # nothing would report.
    legacy = lambda n: "".join(c if c.isalnum() or c in "-_" else "_" for c in n)
    for name in ("global", "jane.doe", "VGINFO\\jane.doe", "LAPTOP-08MIT8SI\\Asus",
                 "NT AUTHORITY\\\\SYSTEM", "ip_10.200.10.5", "cohort:7",
                 "Access-SRV-2.140", "utkarsh_Pc", "person:firdous"):
        ok("sanitiser matches the historical one for %r" % name,
           safe_model_name(name) == legacy(name))
    ok("a real live threshold key still resolves",
       safe_model_name("LAPTOP-08MIT8SI\\Asus") == "LAPTOP-08MIT8SI_Asus")
    ok("None is survivable", safe_model_name(None) == "")

    # ── cohort keys ──
    ok("a cohort key is prefixed", cohort_model_key("3") == "cohort:3")
    ok("prefixing is idempotent",
       cohort_model_key("cohort:3") == "cohort:3")
    ok("an empty cohort id yields no key", cohort_model_key("") == "")
    ok("a cohort key is recognised", is_cohort_model("cohort:3"))
    ok("a username is not a cohort", not is_cohort_model("jane.doe"))
    ok("the id is recoverable", cohort_id_of("cohort:sales-3") == "sales-3")
    ok("and empty for a username", cohort_id_of("jane.doe") == "")

    # ── is_entity_model: the leak guard ──
    # `model_used` is shown to analysts as the account that acted. A cohort
    # key must never be mistaken for one.
    ok("a username is an entity model", is_entity_model("jane.doe"))
    ok("global is not", not is_entity_model("global"))
    ok("GLOBAL in any case is not", not is_entity_model("GLOBAL"))
    ok("unknown is not", not is_entity_model("unknown"))
    ok("empty is not", not is_entity_model(""))
    ok("None is not", not is_entity_model(None))
    ok("a cohort key is NOT an entity model", not is_entity_model("cohort:3"))

    # ── tiers ──
    ok("tier of a username", tier_of("jane.doe") == "entity")
    ok("tier of a cohort", tier_of("cohort:3") == "cohort")
    ok("tier of global", tier_of("global") == "global")
    ok("tier of nothing is global", tier_of("") == "global")

    # ── training plan ──
    assignment = {"members": {"quiet.person": {"cohort": "c1", "source": "behaviour",
                                               "membership": 0.8, "distance": 0.2}},
                  "cohorts": {"c1": {"size": 6}}}
    p = plan_training("busy.person", 5000, assignment, min_events=2000)
    ok("a busy entity gets its own model", p["tier"] == "entity")
    ok("and the model is named after it", p["model"] == "busy.person")
    ok("and the reason gives both numbers",
       "5000" in p["why"] and "2000" in p["why"])

    p = plan_training("quiet.person", 50, assignment, min_events=2000)
    ok("a quiet entity in a cohort gets the cohort model", p["tier"] == "cohort")
    ok("named with the prefix", p["model"] == "cohort:c1")
    ok("and the reason names the cohort", "c1" in p["why"])

    p = plan_training("stranger", 50, assignment, min_events=2000)
    ok("a quiet entity with no cohort falls to global", p["tier"] == "global")
    ok("and says so plainly", "no cohort placement" in p["why"])

    p = plan_training("", 5000, assignment)
    ok("no entity means global", p["tier"] == "global")

    # Boundary: exactly at the threshold trains its own model. `>=` is the
    # documented contract of min_events_per_user, and an off-by-one here would
    # move thousands of entities between tiers silently.
    ok("exactly at the threshold is its own model",
       plan_training("x", 2000, None, min_events=2000)["tier"] == "entity")
    ok("one below is not",
       plan_training("x", 1999, None, min_events=2000)["tier"] == "global")

    # ── scoring resolution ──
    have = {"busy.person"}
    r = resolve_scoring("busy.person", lambda n: n in have, assignment)
    ok("an entity with a model uses it", r["tier"] == "entity")
    r = resolve_scoring("quiet.person", lambda n: n in have, assignment,
                        cohort_model_exists=lambda k: True)
    ok("a cohort member uses the cohort model", r["tier"] == "cohort")
    ok("and it is named cohort:c1", r["model"] == "cohort:c1")
    # The cohort was planned but its model was never built (too few pooled
    # rows). Falling through to global is correct; pretending otherwise would
    # make the scorer load a file that is not there.
    r = resolve_scoring("quiet.person", lambda n: n in have, assignment,
                        cohort_model_exists=lambda k: False)
    ok("a missing cohort model falls through to global", r["tier"] == "global")
    r = resolve_scoring("stranger", lambda n: n in have, assignment)
    ok("an unplaced entity uses global", r["tier"] == "global")
    r = resolve_scoring("busy.person", None, assignment)
    ok("no predicate still resolves", r["tier"] in TIERS)

    # ── typed vs bare entity keys ──
    # build_cohorts emits ids like `beh:person_a3` and keys members by the
    # profile-store spelling. The scorer is handed the engine's spelling. On
    # this deployment thresholds.json proves that is a BARE name, so a typed
    # assignment must still resolve or the tier never fires at all.
    typed = {"members": {"person:jane": {"cohort": "beh:person_jane",
                                         "source": "behaviour"}},
             "cohorts": {"beh:person_jane": {"size": 4}}}
    ok("a bare name finds a typed placement",
       cohort_for(typed, "jane") == "beh:person_jane")
    ok("the typed spelling still works",
       cohort_for(typed, "person:jane") == "beh:person_jane")
    bare = {"members": {"jane": {"cohort": "c2", "source": "behaviour"}},
            "cohorts": {"c2": {"size": 3}}}
    ok("a typed name finds a bare placement", cohort_for(bare, "person:jane") == "c2")
    ok("and the bare spelling works", cohort_for(bare, "jane") == "c2")
    ok("a genuine stranger is still unplaced", cohort_for(typed, "nobody") == "")
    # A cohort id containing a colon is what build_cohorts really produces.
    ok("a colon in the cohort id survives key building",
       cohort_model_key("beh:person_a3") == "cohort:beh:person_a3")
    ok("and the id comes back whole",
       cohort_id_of("cohort:beh:person_a3") == "beh:person_a3")
    ok("and it is still not an entity name",
       not is_entity_model("cohort:beh:person_a3"))
    ok("and its filename is safe",
       safe_model_name(cohort_model_key("beh:person_a3"))
       == "cohort_beh_person_a3")

    # ── cohort_for tolerates a broken assignment ──
    ok("an empty assignment places nobody", cohort_for({}, "x") == "")
    ok("None places nobody", cohort_for(None, "x") == "")
    ok("a nameless entity is placed nowhere", cohort_for(assignment, "") == "")

    total = len(checked)
    if failures:
        print("ueba_model_tiers selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_model_tiers selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
