#!/usr/bin/env python3
"""Device risk and device-to-device behavioural comparison — RFP SN 56.

WHAT WAS ALREADY THERE, AND WHY IT WAS NOT ENOUGH

/api/device/<name>/peers already ranked devices by cosine over their
L1-normalised signature-id profiles, with a 0.15 floor below which it names
nobody, and it already reported the shared signatures that drove the score.
That is a real behavioural comparison and none of it is rebuilt here.

Two things were missing against the requirement.

  1. IT COMPARED ONLY WHICH DETECTIONS FIRED. A signature-id profile is a
     profile of the ALERTS a device produced, which is close to the
     "similar-event retrieval" the requirement asks not to rely on by itself.
     Two machines can fire the same rules for entirely different reasons, at
     entirely different times of day, used by entirely different numbers of
     people. So the comparison here runs over four independent dimensions and
     says what each one contributed.

  2. IT EXPLAINED SIMILARITY BUT NOT DIFFERENCE. `shared_signatures` says why
     two devices matched. An analyst deciding whether a peer is a fair
     yardstick also needs to know where they diverge — that is the part that
     tells them whether the comparison can be trusted. Every dimension now
     reports both its drivers and its differentiators.

Separately, the device summary's only risk figure was `max_score`: the single
highest-scoring alert. That makes a machine with one 0.95 alert look riskier
than one with five hundred at 0.70, which is backwards for almost every
question an analyst asks. `risk()` below is a composite, and it reports each
component's contribution rather than one opaque number.

WHY JENSEN-SHANNON AND NOT MORE COSINE

The per-dimension measure is ueba_peers.profile_distance — Jensen-Shannon
divergence, already used to build peer cohorts and covered by that module's
tests. It is bounded on [0, 1] and symmetric, which is what makes four
dimensions combinable at all: cosine is also bounded but its midpoint carries
no consistent meaning across differently-shaped histograms, so a weighted sum
of cosines is not interpretable. Reusing one measure also means the cohorts
that judge a quiet entity (SN 18) and the peers shown next to a device (SN 56)
agree about what "behaves alike" means.

A NOTE ON EMPTY DIMENSIONS

profile_distance({}, {}) returns 1.0 — maximally different. For cohort
building that is a safe default, but here it would be wrong: two devices that
both have no recorded anomaly reasons are not maximally different in their
reasons, they are simply not comparable on that axis. So a dimension with no
data on either side is SKIPPED and the weights are renormalised over the
dimensions that remain, and the response says which ones those were.
"""
from __future__ import annotations

try:
    import ueba_peers
except Exception:          # pragma: no cover
    ueba_peers = None

# (key, weight, what it measures). Weights are relative, not absolute — they
# are renormalised over whichever dimensions both devices can actually be
# compared on.
#
# Signatures carry the most weight because they are the most specific
# statement about what a machine did. Activity rhythm is next: when a machine
# is busy separates a server from a desk, and separates a desk from the same
# desk being used at 3am. Verdict mix is weighted least because it is a coarse
# three-bucket summary of the scores the other dimensions already describe.
DIMENSIONS = (
    ("signatures", 0.40, "which detections fire on it"),
    ("hours",      0.25, "when it is active"),
    ("reasons",    0.20, "which anomaly reasons drive its scores"),
    ("verdicts",   0.15, "how its risk verdicts distribute"),
)

# Below this nothing is called a peer. Kept at the value the cosine ranking
# already used, so the "no comparable peer" behaviour does not quietly change
# for deployments that relied on it.
MIN_SIMILARITY = 0.15

# Verdict labels, from score_fusion.verdicts. `normal` is everything under the
# alert threshold.
VERDICT_WEIGHT = {
    "highly_anomalous": 1.0,
    "anomalous":        0.7,
    "suspicious":       0.4,
    "normal":           0.0,
}

# CyberSentinel SIEM rule levels run 0-15.
MAX_SEVERITY = 15.0


def _norm(counts) -> dict:
    """L1-normalise a histogram, dropping non-positive entries."""
    clean = {str(k): float(v) for k, v in (counts or {}).items()
             if isinstance(v, (int, float)) and v > 0}
    total = sum(clean.values())
    if not total:
        return {}
    return {k: v / total for k, v in clean.items()}


def _distance(a: dict, b: dict) -> float:
    """Jensen-Shannon distance between two normalised histograms, 0..1."""
    if ueba_peers is not None:
        try:
            return float(ueba_peers.profile_distance(a, b))
        except Exception:
            pass
    # Fallback: total-variation distance, same bounds and orientation. Only
    # reached if ueba_peers is unavailable, which also disables cohorts.
    keys = set(a) | set(b)
    return min(1.0, 0.5 * sum(abs(a.get(k, 0.0) - b.get(k, 0.0)) for k in keys))


def _drivers(a: dict, b: dict, limit: int = 5) -> list:
    """Keys both devices share, ranked by the mass they share.

    min(share_a, share_b) is the overlap each key actually contributes, so a
    key that is 2% of one profile and 60% of the other ranks by the 2% rather
    than looking like a strong match.
    """
    both = set(a) & set(b)
    ranked = sorted(both, key=lambda k: -min(a[k], b[k]))
    return [{"key": k, "here": round(a[k], 4), "there": round(b[k], 4),
             "shared": round(min(a[k], b[k]), 4)} for k in ranked[:limit]]


def _differentiators(a: dict, b: dict, limit: int = 5) -> list:
    """Keys where the two profiles diverge most, with the direction.

    This is the half that was missing. An analyst judging whether a peer is a
    fair comparison needs to know where it is NOT alike, not only where it is.
    """
    keys = set(a) | set(b)
    ranked = sorted(keys, key=lambda k: -abs(a.get(k, 0.0) - b.get(k, 0.0)))
    out = []
    for k in ranked[:limit]:
        here, there = a.get(k, 0.0), b.get(k, 0.0)
        out.append({
            "key": k, "here": round(here, 4), "there": round(there, 4),
            "gap": round(abs(here - there), 4),
            "only_here": there == 0.0, "only_there": here == 0.0,
        })
    return out


def _profiles(rec: dict) -> dict:
    """The four comparable histograms for one device record."""
    return {
        "signatures": _norm(rec.get("signatures")),
        "reasons":    _norm(rec.get("top_reasons")),
        "verdicts":   _norm(rec.get("verdicts")),
        "hours":      _norm(rec.get("hours")),
    }


def compare(a_rec: dict, b_rec: dict, names=("here", "there")) -> dict:
    """Behavioural similarity between two device records, with its reasoning.

    Returns {"similarity", "comparable", "dimensions", "compared_on",
    "skipped", "why"}. `similarity` is 0..1 over the dimensions that could be
    compared, never over dimensions that had no data on either side.
    """
    pa, pb = _profiles(a_rec or {}), _profiles(b_rec or {})

    dims = []
    skipped = []
    usable_weight = 0.0
    for key, weight, what in DIMENSIONS:
        x, y = pa.get(key) or {}, pb.get(key) or {}
        if not x or not y:
            # Not comparable, which is NOT the same as "completely different".
            # Scoring this 1.0 (what profile_distance would return for two
            # empty histograms) would penalise a device for data it never had.
            skipped.append({"dimension": key, "measures": what,
                            "why": "no data on %s"
                                   % (names[0] if not x else names[1])})
            continue
        sim = 1.0 - _distance(x, y)
        usable_weight += weight
        dims.append({
            "dimension": key, "measures": what, "weight": weight,
            "similarity": round(max(0.0, min(1.0, sim)), 4),
            "drivers": _drivers(x, y),
            "differentiators": _differentiators(x, y),
        })

    if not dims:
        return {"similarity": 0.0, "comparable": False, "dimensions": [],
                "compared_on": [], "skipped": skipped,
                "why": "these two devices have no dimension in common that "
                       "carries data on both sides, so no honest comparison "
                       "can be made"}

    # Renormalised over the usable dimensions, so a device missing one axis is
    # not silently scored as 0 on it.
    total = 0.0
    for d in dims:
        share = d["weight"] / usable_weight
        d["contribution"] = round(share * d["similarity"], 4)
        d["weight_used"] = round(share, 4)
        total += share * d["similarity"]

    strongest = max(dims, key=lambda d: d["contribution"])
    weakest = min(dims, key=lambda d: d["similarity"])
    why = ("%.0f%% alike overall; most alike in %s (%.0f%%), least alike in "
           "%s (%.0f%%)"
           % (total * 100, strongest["dimension"], strongest["similarity"] * 100,
              weakest["dimension"], weakest["similarity"] * 100))
    if skipped:
        why += "; %s not compared (no data on both sides)" % ", ".join(
            s["dimension"] for s in skipped)

    return {"similarity": round(total, 4), "comparable": True,
            "dimensions": dims,
            "compared_on": [d["dimension"] for d in dims],
            "skipped": skipped, "why": why}


def risk(rec: dict, estate: "dict | None" = None) -> dict:
    """A composite device risk score, 0..1, with every component shown.

    The device summary's only risk figure was `max_score` — the highest single
    alert. One 0.95 alert then outranked five hundred at 0.70, which inverts
    almost every triage question. Five components, each reported with what it
    was, what it was worth and why:

      peak      the worst single alert. Still here: one genuinely critical
                event matters regardless of volume.
      verdicts  the MIX. A device whose alerts are mostly highly_anomalous is
                a different proposition from one with the same peak and a
                long tail of `suspicious`.
      volume    how much it alerts relative to the busiest device in the
                window, on a log scale — the difference between 1 and 10
                alerts means more than between 1000 and 1010.
      severity  the SIEM's own rule level, which is independent of UEBA's
                scoring and so is not just the peak restated.
      breadth   how many distinct people used it, relative to the estate. A
                shared machine carries more exposure than a single-user desk.

    `estate` supplies the comparators ({"max_alerts", "max_users"}); without
    it the two relative components are skipped and the weights renormalise,
    exactly as in compare().
    """
    rec = rec or {}
    est = estate or {}

    def _f(v, default=0.0):
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

    import math

    # NOTHING HAPPENED is not the same as LOW RISK. With an estate comparator
    # present, a device with no alerts still picked up a peak of 0 and a
    # volume of 0, scored 0.00, and was described as "low risk, driven most by
    # peak — worst single alert scored 0.00". That sentence invites an analyst
    # to read a silent device as an assessed-and-cleared one. A device the
    # window holds no alerts for has no risk score, and says so.
    if (_f(rec.get("alerts")) <= 0 and not (rec.get("verdicts") or {})
            and not (rec.get("signatures") or {})):
        return {"score": 0.0, "band": "none", "components": [],
                "why": "this device produced no alerts in the window, so it "
                       "has no risk score"}

    comps = []

    peak = max(0.0, min(1.0, _f(rec.get("max_score"))))
    comps.append({"component": "peak", "weight": 0.30, "value": round(peak, 4),
                  "detail": "worst single alert scored %.2f" % peak})

    verdicts = _norm(rec.get("verdicts"))
    if verdicts:
        mix = sum(VERDICT_WEIGHT.get(k, 0.0) * share
                  for k, share in verdicts.items())
        top = max(verdicts, key=verdicts.get)
        comps.append({"component": "verdicts", "weight": 0.25,
                      "value": round(max(0.0, min(1.0, mix)), 4),
                      "detail": "mostly %s (%.0f%% of its alerts)"
                                % (top, verdicts[top] * 100)})

    max_alerts = _f(est.get("max_alerts"))
    alerts = _f(rec.get("alerts"))
    if max_alerts > 0:
        # log1p so the gap between 1 and 10 alerts counts for more than the
        # gap between 1000 and 1010.
        vol = math.log1p(alerts) / math.log1p(max_alerts)
        comps.append({"component": "volume", "weight": 0.20,
                      "value": round(max(0.0, min(1.0, vol)), 4),
                      "detail": "%d alerts against the window's busiest "
                                "device at %d" % (int(alerts), int(max_alerts))})

    sev = _f(rec.get("severity_max"))
    if sev > 0:
        comps.append({"component": "severity", "weight": 0.15,
                      "value": round(max(0.0, min(1.0, sev / MAX_SEVERITY)), 4),
                      "detail": "highest SIEM rule level %d of %d"
                                % (int(sev), int(MAX_SEVERITY))})

    max_users = _f(est.get("max_users"))
    users = _f(rec.get("user_count"))
    if max_users > 0:
        br = users / max_users
        comps.append({"component": "breadth", "weight": 0.10,
                      "value": round(max(0.0, min(1.0, br)), 4),
                      "detail": "%d distinct account(s) against the window's "
                                "widest at %d" % (int(users), int(max_users))})

    usable = sum(c["weight"] for c in comps)
    if not usable:
        return {"score": 0.0, "band": "none", "components": [],
                "why": "this device produced no alerts in the window, so it "
                       "has no risk score"}
    score = 0.0
    for c in comps:
        c["weight_used"] = round(c["weight"] / usable, 4)
        c["contribution"] = round(c["weight_used"] * c["value"], 4)
        score += c["contribution"]
    score = round(max(0.0, min(1.0, score)), 4)

    band = ("critical" if score >= 0.80 else
            "high" if score >= 0.60 else
            "moderate" if score >= 0.35 else "low")
    lead = max(comps, key=lambda c: c["contribution"])
    return {"score": score, "band": band, "components": comps,
            "why": "%s risk (%.2f); driven most by %s — %s"
                   % (band, score, lead["component"], lead["detail"])}


def selftest() -> int:
    failures = []
    checked = []

    def ok(label, cond):
        checked.append(label)
        if not cond:
            failures.append(label)

    srv = {"signatures": {"5710": 100, "5712": 50},
           "top_reasons": {"odd_hour": 30, "new_host": 10},
           "verdicts": {"suspicious": 80, "anomalous": 20},
           "hours": {"2": 40, "3": 60},
           "alerts": 150, "max_score": 0.80, "severity_max": 10,
           "user_count": 20}
    twin = {"signatures": {"5710": 200, "5712": 100},   # same SHAPE, 2x volume
            "top_reasons": {"odd_hour": 60, "new_host": 20},
            "verdicts": {"suspicious": 160, "anomalous": 40},
            "hours": {"2": 80, "3": 120},
            "alerts": 300, "max_score": 0.82, "severity_max": 10,
            "user_count": 22}
    other = {"signatures": {"9999": 100},
             "top_reasons": {"data_egress": 50},
             "verdicts": {"highly_anomalous": 100},
             "hours": {"14": 90, "15": 10},
             "alerts": 100, "max_score": 0.95, "severity_max": 12,
             "user_count": 1}

    # ── compare: shape, not volume ──
    r = compare(srv, twin)
    ok("two devices with the same shape are near-identical", r["similarity"] > 0.98)
    ok("and that is reported as comparable", r["comparable"])
    ok("all four dimensions were used", len(r["dimensions"]) == 4)
    ok("and none were skipped", r["skipped"] == [])
    ok("the explanation names the strongest dimension", "most alike in" in r["why"])

    r2 = compare(srv, other)
    ok("two unlike devices score low", r2["similarity"] < 0.3)
    ok("but are still comparable", r2["comparable"])
    ok("similarity is ordered correctly",
       compare(srv, twin)["similarity"] > compare(srv, other)["similarity"])
    ok("a device is maximally like itself", compare(srv, srv)["similarity"] > 0.999)
    ok("comparison is symmetric",
       abs(compare(srv, other)["similarity"]
           - compare(other, srv)["similarity"]) < 1e-9)
    ok("the score is bounded", 0.0 <= r2["similarity"] <= 1.0)

    # ── drivers and differentiators ──
    d = [x for x in r["dimensions"] if x["dimension"] == "signatures"][0]
    ok("shared signatures are reported as drivers",
       {x["key"] for x in d["drivers"]} == {"5710", "5712"})
    ok("the bigger shared signature ranks first",
       d["drivers"][0]["key"] == "5710")
    d2 = [x for x in r2["dimensions"] if x["dimension"] == "signatures"][0]
    ok("unlike devices have no drivers", d2["drivers"] == [])
    ok("but they DO have differentiators", len(d2["differentiators"]) > 0)
    keys = {x["key"]: x for x in d2["differentiators"]}
    ok("a signature only on one side is marked as such",
       keys["9999"]["only_there"] is True)
    ok("and one only on the other side too", keys["5710"]["only_here"] is True)
    ok("every dimension reports both halves",
       all("drivers" in x and "differentiators" in x for x in r2["dimensions"]))

    # ── empty dimensions are SKIPPED, not scored 0 ──
    # profile_distance({}, {}) is 1.0, so counting an absent dimension would
    # punish a device for data it never had.
    thin = dict(srv)
    thin["top_reasons"] = {}
    thin["hours"] = {}
    r3 = compare(thin, twin)
    ok("absent dimensions are skipped", len(r3["skipped"]) == 2)
    ok("and named in the response",
       {s["dimension"] for s in r3["skipped"]} == {"reasons", "hours"})
    ok("only the usable ones are compared",
       set(r3["compared_on"]) == {"signatures", "verdicts"})
    ok("the weights renormalise to 1",
       abs(sum(x["weight_used"] for x in r3["dimensions"]) - 1.0) < 1e-6)
    ok("so a thin profile is still scored highly against its twin",
       r3["similarity"] > 0.98)
    ok("and the reason says what was not compared",
       "not compared" in r3["why"])

    both_empty = {"signatures": {}, "top_reasons": {}, "verdicts": {}, "hours": {}}
    r4 = compare(both_empty, both_empty)
    ok("two profileless devices are not comparable", not r4["comparable"])
    ok("and score zero rather than one", r4["similarity"] == 0.0)
    ok("with an explanation", "no honest comparison" in r4["why"])
    ok("an empty record is survivable", compare({}, srv)["comparable"] is False)
    ok("None is survivable", compare(None, None)["similarity"] == 0.0)

    # ── risk ──
    estate = {"max_alerts": 300, "max_users": 22}
    rk = risk(srv, estate)
    ok("a risk score is produced", 0.0 < rk["score"] <= 1.0)
    ok("all five components are present", len(rk["components"]) == 5)
    ok("the weights renormalise to 1",
       abs(sum(c["weight_used"] for c in rk["components"]) - 1.0) < 1e-6)
    ok("the contributions sum to the score",
       abs(sum(c["contribution"] for c in rk["components"]) - rk["score"]) < 1e-3)
    ok("a band is assigned", rk["band"] in ("low", "moderate", "high", "critical"))
    ok("the reason names the leading component",
       rk["components"][0]["component"] in rk["why"]
       or any(c["component"] in rk["why"] for c in rk["components"]))

    # The thing max_score got wrong: volume must count for something.
    quiet_peak = {"alerts": 1, "max_score": 0.95, "severity_max": 5,
                  "user_count": 1, "verdicts": {"highly_anomalous": 1},
                  "signatures": {"1": 1}}
    busy_mid = {"alerts": 500, "max_score": 0.70, "severity_max": 10,
                "user_count": 20, "verdicts": {"suspicious": 500},
                "signatures": {"1": 500}}
    big = {"max_alerts": 500, "max_users": 20}
    ok("a busy moderate device outranks a one-off peak",
       risk(busy_mid, big)["score"] > risk(quiet_peak, big)["score"])
    ok("whereas max_score alone would have inverted that",
       quiet_peak["max_score"] > busy_mid["max_score"])

    # Relative components need the estate; without it they are skipped.
    rk2 = risk(srv, None)
    ok("without estate context the relative components are dropped",
       {c["component"] for c in rk2["components"]}
       == {"peak", "verdicts", "severity"})
    ok("and the weights still renormalise",
       abs(sum(c["weight_used"] for c in rk2["components"]) - 1.0) < 1e-6)

    ok("a device with no alerts has no score", risk({}, estate)["score"] == 0.0)
    ok("and says so", "no alerts" in risk({}, estate)["why"])
    ok("a garbage max_score does not raise",
       0.0 <= risk({"max_score": "abc", "alerts": 5},
                   {"max_alerts": 10})["score"] <= 1.0)
    ok("an out-of-range score is clamped",
       risk({"max_score": 99, "alerts": 1}, {"max_alerts": 1})["score"] <= 1.0)
    ok("bands are ordered",
       risk({"max_score": 0.1, "alerts": 1, "verdicts": {"normal": 1}},
            {"max_alerts": 1000})["score"]
       < risk({"max_score": 0.99, "alerts": 1000,
               "verdicts": {"highly_anomalous": 1000}},
              {"max_alerts": 1000})["score"])

    total = len(checked)
    if failures:
        print("ueba_device_compare selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_device_compare selftest: all %d checks passed" % total)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
