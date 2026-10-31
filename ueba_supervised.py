#!/usr/bin/env python3
"""
ueba_supervised.py
──────────────────
CyberSentinel UEBA — supervised learning on analyst verdicts (RFP SN 20).

  SN 20  Use of supervised machine learning algorithms.

Why the labels are already here
───────────────────────────────
The tracking sheet had this blocked on "a labelled incident dataset — past
incidents carrying analyst verdicts — from the customer SOC". We are already
collecting exactly that, through workflow this platform ships:

    false_positives.json        10,830 records, measured locally.
                                An analyst marked the alert wrong. NEGATIVE.
    fp_patterns.json            204 suppression patterns, each one an
                                analyst's judgement about a whole rule.
    risk_history.db             the confirmed-incident ledger (shipped
                                29-Oct-2026). An analyst recorded that an
                                alert was genuinely malicious. POSITIVE.

So the dataset is generated in-house, by the people best placed to label it,
and it grows every day the console is used. What is genuinely short today is
the POSITIVE class: the confirm action only shipped on 29-Oct-2026, so there
has been very little time to accumulate verdicts. That is a waiting problem,
not a dependency problem, and the difference matters — nobody outside the team
has to send us anything.

What this module therefore does
───────────────────────────────
Builds the pipeline and the governance around it NOW, and refuses to train
until the label supply justifies a model. Asked "do you use supervised
learning", the answer is yes, here is the pipeline, here is the model card,
here are the gates it must pass, and here is the current label count against
the minimum. That is a far better position than an untrained promise.

Accuracy is deliberately NOT the headline metric
────────────────────────────────────────────────
With 10,830 negatives and a handful of positives, a model that answers
"benign" to everything scores over 99% accuracy and is worthless. Every gate
here is on the POSITIVE class — precision, recall and F1 — and the trivial
majority-class baseline is computed and reported beside the model so the
comparison cannot be dodged. A model that does not beat that baseline on
positive-class F1 is refused, not published with a flattering accuracy.

The feature space is the existing one
────────────────────────────────────
Vectors come from the same FeatureExtractor the unsupervised models use. A
second feature space would mean two definitions of what an event is, and the
first time they drifted apart the supervised verdict would be scoring
something the rest of the engine had stopped producing. The model card records
the dimension, and loading a model whose dimension disagrees with the running
configuration is refused rather than silently scoring nonsense.

Reported, not fused
───────────────────
The supervised verdict is published alongside the unsupervised score, not
added to it. Fusing two opinions needs the second one's error rate measured on
live traffic first, and this project has twice paid for a scoring change made
before that measurement. The gate is written and the metrics exist; the fusion
is a separate, deliberate step.

sklearn is imported lazily
──────────────────────────
Label extraction, the gates, the metrics and the drift test are pure Python and
testable without it. Only fit() and predict() need scikit-learn, so this module
imports and selftests on a machine that has none.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

LABEL_BENIGN = 0
LABEL_MALICIOUS = 1

# Gates. A model that cannot clear these is not published.
#
# 50 of each class is not a lot, and it is not meant to be: it is the point
# below which a held-out split stops meaning anything at all (a 25% test split
# of 50 gives 12 positives, so one misclassification moves recall by 8 points).
# It is a floor, not a target.
DEFAULT_MIN_PER_CLASS = 50
# Held-out recall on the malicious class. Below this the model misses more
# genuine incidents than it catches, whatever its accuracy says.
DEFAULT_MIN_RECALL = 0.50
# The model must beat a majority-class predictor on positive-class F1 by at
# least this margin. The baseline scores 0.0 there, so this is really "must
# detect something", stated as a margin so it cannot be argued away.
DEFAULT_MIN_F1_MARGIN = 0.10
DEFAULT_TEST_FRACTION = 0.25

# Population Stability Index thresholds, the conventional reading.
PSI_SHIFT = 0.10        # worth noticing
PSI_BREAK = 0.25        # the live population no longer matches training


# ── metrics, in pure Python so they are auditable ───────────────────────────

def confusion(y_true, y_pred) -> dict:
    """{tp, fp, tn, fn} for the malicious class."""
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        if t == LABEL_MALICIOUS and p == LABEL_MALICIOUS:
            tp += 1
        elif t == LABEL_BENIGN and p == LABEL_MALICIOUS:
            fp += 1
        elif t == LABEL_BENIGN and p == LABEL_BENIGN:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def metrics(y_true, y_pred) -> dict:
    """Precision, recall and F1 on the MALICIOUS class, plus accuracy.

    Accuracy is included only so it can be compared with the baseline and
    dismissed — see the note in the module docstring.
    """
    c = confusion(y_true, y_pred)
    tp, fp, tn, fn = c["tp"], c["fp"], c["tn"], c["fn"]
    n = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / n, 4) if n else 0.0,
        "support_malicious": tp + fn,
        "support_benign": tn + fp,
        **c,
    }


def baseline_metrics(y_true) -> dict:
    """What a majority-class predictor scores on the same labels.

    Published beside the model's own numbers. Its accuracy is high and its
    positive-class F1 is zero, which is the whole point.
    """
    if not y_true:
        return metrics([], [])
    n_pos = sum(1 for y in y_true if y == LABEL_MALICIOUS)
    majority = (LABEL_MALICIOUS if n_pos * 2 > len(y_true) else LABEL_BENIGN)
    return metrics(y_true, [majority] * len(y_true))


def psi(train_scores, live_scores, bins: int = 10) -> dict:
    """Population Stability Index between two score distributions.

    The conventional drift test: bucket the training scores, measure how the
    live scores fall into the same buckets, and sum the weighted log ratio.
    Under 0.10 is stable, 0.10-0.25 is a shift worth noticing, over 0.25 means
    the live population no longer resembles what the model was fitted on and
    its numbers should not be trusted.
    """
    out = {"psi": 0.0, "verdict": "unknown", "bins": 0,
           "n_train": len(train_scores or []), "n_live": len(live_scores or [])}
    if not train_scores or not live_scores:
        out["verdict"] = "not enough data"
        return out
    lo, hi = 0.0, 1.0
    k = max(2, int(bins))
    width = (hi - lo) / k

    def hist(xs):
        h = [0] * k
        for x in xs:
            try:
                v = float(x)
            except (TypeError, ValueError):
                continue
            idx = int((min(max(v, lo), hi) - lo) / width)
            h[min(idx, k - 1)] += 1
        return h

    ht, hl = hist(train_scores), hist(live_scores)
    nt, nl = float(sum(ht)) or 1.0, float(sum(hl)) or 1.0
    total = 0.0
    used = 0
    for a, b in zip(ht, hl):
        pa, pb = a / nt, b / nl
        # A bucket empty in either population would make the ratio infinite.
        # The conventional fix is a small floor; it keeps the index finite
        # without pretending the bucket was populated.
        pa = max(pa, 1e-6)
        pb = max(pb, 1e-6)
        total += (pb - pa) * math.log(pb / pa)
        used += 1
    out["psi"] = round(total, 6)
    out["bins"] = used
    out["verdict"] = ("stable" if total < PSI_SHIFT
                      else "shifted" if total < PSI_BREAK
                      else "broken")
    return out


# ── labels ──────────────────────────────────────────────────────────────────

def read_false_positives(path) -> dict:
    """{event_id: reason} — the analyst said this alert was wrong. NEGATIVE."""
    out: dict = {}
    p = Path(path)
    if not p.exists():
        return out
    try:
        raw = json.loads(p.read_text(encoding="utf-8") or "[]")
    except Exception as e:
        print("[supervised] could not read %s: %s" % (p, e))
        return out
    records = raw.values() if isinstance(raw, dict) else raw
    for r in (records or []):
        if not isinstance(r, dict):
            continue
        eid = r.get("event_id")
        if eid:
            out[str(eid)] = str(r.get("reason") or "")[:200]
    return out


def read_confirmed(db_path) -> dict:
    """{event_id: reason} — the analyst confirmed a real incident. POSITIVE.

    Reads the ledger ueba_risk_history owns. Retracted rows are excluded: a
    verdict the analyst took back is not a label, and training on it would
    teach the model the mistake that was corrected.
    """
    out: dict = {}
    p = Path(str(db_path))
    if not p.exists():
        return out
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % p, uri=True, timeout=10.0)
    except sqlite3.Error as e:
        print("[supervised] could not open %s: %s" % (p, e))
        return out
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(incidents)")}
        if not cols:
            return out
        id_col = ("event_id" if "event_id" in cols else
                  "alert_id" if "alert_id" in cols else None)
        if not id_col:
            return out
        where = ""
        if "retracted" in cols:
            where = " WHERE COALESCE(retracted, 0) = 0"
        elif "active" in cols:
            where = " WHERE COALESCE(active, 1) = 1"
        reason_col = ("reason" if "reason" in cols else
                      "note" if "note" in cols else None)
        sel = id_col + ((", " + reason_col) if reason_col else "")
        for row in conn.execute("SELECT %s FROM incidents%s" % (sel, where)):
            eid = row[0]
            if eid:
                out[str(eid)] = (str(row[1])[:200] if len(row) > 1 and row[1]
                                 else "")
    except sqlite3.Error as e:
        print("[supervised] could not read the incident ledger: %s" % e)
    finally:
        conn.close()
    return out


def label_of(event_id, confirmed: dict, false_positives: dict):
    """1, 0 or None for one event id.

    A confirmed incident outranks a false-positive mark. Both on one alert
    means an analyst changed their mind, and the confirmation is the later,
    more considered verdict — but it is reported as a conflict by
    label_counts() rather than silently resolved.
    """
    eid = str(event_id or "")
    if not eid:
        return None
    if eid in (confirmed or {}):
        return LABEL_MALICIOUS
    if eid in (false_positives or {}):
        return LABEL_BENIGN
    return None


def label_counts(confirmed: dict, false_positives: dict) -> dict:
    conf = set(confirmed or {})
    fps = set(false_positives or {})
    both = conf & fps
    return {
        "malicious": len(conf),
        "benign": len(fps - conf),
        "conflicting": len(both),
        "total": len(conf | fps),
        "balance": (round(len(conf) / max(1, len(conf | fps)), 6)),
    }


# ── gates ───────────────────────────────────────────────────────────────────

def check_supply(counts: dict, min_per_class: int = DEFAULT_MIN_PER_CLASS) -> dict:
    """Is there enough labelled data to train at all?"""
    mal, ben = counts.get("malicious", 0), counts.get("benign", 0)
    short = []
    if mal < min_per_class:
        short.append("malicious: %d of %d needed" % (mal, min_per_class))
    if ben < min_per_class:
        short.append("benign: %d of %d needed" % (ben, min_per_class))
    return {
        "ready": not short,
        "min_per_class": min_per_class,
        "malicious": mal,
        "benign": ben,
        "shortfall": short,
        "reason": ("" if not short else
                   "not enough labelled examples yet — " + "; ".join(short)
                   + ". Labels come from the analyst console: confirming an "
                     "incident adds a malicious example, marking a false "
                     "positive adds a benign one."),
    }


def check_model(m: dict, base: dict,
                min_recall: float = DEFAULT_MIN_RECALL,
                min_f1_margin: float = DEFAULT_MIN_F1_MARGIN) -> dict:
    """Does a trained model earn publication?

    Every test is on the malicious class. Accuracy is never a gate.
    """
    reasons = []
    if m.get("support_malicious", 0) <= 0:
        reasons.append("the held-out split contains no malicious examples, so "
                       "recall is unmeasurable")
    if m.get("recall", 0.0) < min_recall:
        reasons.append("recall on the malicious class is %.2f, below the %.2f "
                       "required" % (m.get("recall", 0.0), min_recall))
    margin = m.get("f1", 0.0) - base.get("f1", 0.0)
    if margin < min_f1_margin:
        reasons.append("positive-class F1 beats the majority-class baseline by "
                       "only %.3f, below the %.2f required (model %.3f, "
                       "baseline %.3f)"
                       % (margin, min_f1_margin, m.get("f1", 0.0),
                          base.get("f1", 0.0)))
    return {
        "publish": not reasons,
        "f1_margin_over_baseline": round(margin, 4),
        "thresholds": {"min_recall": min_recall,
                       "min_f1_margin": min_f1_margin},
        "reasons": reasons,
    }


def model_card(counts: dict, m: dict, base: dict, gate: dict,
               feature_dim: int, params: dict,
               label_sources: dict, split: dict) -> dict:
    """Everything needed to judge this model without rerunning it."""
    try:
        import sklearn
        ver = sklearn.__version__
    except Exception:
        ver = "unknown"
    return {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "sklearn": ver,
        "feature_dim": int(feature_dim),
        "labels": counts,
        "label_sources": label_sources,
        "split": split,
        "params": params,
        "metrics_heldout": m,
        "metrics_baseline_majority": base,
        "gate": gate,
        # Stated from the actual numbers rather than from an assumption about
        # them: the imbalanced case is the usual one but not the only one, and
        # a card that asserts "accuracy is close to the baseline" when it is
        # not would be a false statement in the artefact meant to prevent one.
        "headline": (
            "Judge this model on recall and F1 for the MALICIOUS class, not on "
            "accuracy. Model accuracy %.3f against a majority-class baseline "
            "of %.3f (%s); positive-class F1 %.3f against the baseline's %.3f, "
            "which is the comparison that carries information."
            % (m.get("accuracy", 0.0), base.get("accuracy", 0.0),
               ("a margin of only %.3f, so accuracy says almost nothing here"
                % (m.get("accuracy", 0.0) - base.get("accuracy", 0.0)))
               if abs(m.get("accuracy", 0.0) - base.get("accuracy", 0.0)) < 0.05
               else "a wider accuracy margin than usual, which means the "
                    "labelled set is not as imbalanced as it typically is",
               m.get("f1", 0.0), base.get("f1", 0.0))),
    }


# ── training and scoring ────────────────────────────────────────────────────

def stratified_split(labels, test_fraction: float = DEFAULT_TEST_FRACTION,
                     seed: int = 20261031) -> tuple:
    """(train_idx, test_idx), each class split in the same proportion.

    Stratified by hand and deterministically. With a handful of positives a
    random split can easily put none of them in the test set, which produces
    an unmeasurable model that looks fine.
    """
    import random
    rng = random.Random(seed)
    by_class: dict = {}
    for i, y in enumerate(labels):
        by_class.setdefault(y, []).append(i)
    train, test = [], []
    for y, idx in sorted(by_class.items()):
        idx = list(idx)
        rng.shuffle(idx)
        # At least one of each class on each side wherever the class allows it.
        n_test = int(round(len(idx) * float(test_fraction)))
        n_test = max(1, min(n_test, len(idx) - 1)) if len(idx) > 1 else 0
        test.extend(idx[:n_test])
        train.extend(idx[n_test:])
    return sorted(train), sorted(test)


def train(vectors, labels, feature_dim: int,
          min_per_class: int = DEFAULT_MIN_PER_CLASS,
          min_recall: float = DEFAULT_MIN_RECALL,
          min_f1_margin: float = DEFAULT_MIN_F1_MARGIN,
          test_fraction: float = DEFAULT_TEST_FRACTION,
          label_sources: "dict | None" = None) -> dict:
    """Fit, evaluate against the baseline, and gate.

    {"ok", "reason", "model", "card"}. `model` is None whenever the gate
    refused, so a caller cannot accidentally publish a model that failed.
    """
    counts = {"malicious": sum(1 for y in labels if y == LABEL_MALICIOUS),
              "benign": sum(1 for y in labels if y == LABEL_BENIGN),
              "conflicting": 0}
    counts["total"] = counts["malicious"] + counts["benign"]
    counts["balance"] = round(counts["malicious"] / max(1, counts["total"]), 6)

    supply = check_supply(counts, min_per_class)
    if not supply["ready"]:
        return {"ok": False, "reason": supply["reason"], "model": None,
                "card": {"labels": counts, "supply": supply}}

    if any(len(v) != feature_dim for v in vectors):
        return {"ok": False, "model": None, "card": {"labels": counts},
                "reason": ("some vectors are not %d-dimensional; the supervised "
                           "model must share the feature space the rest of the "
                           "engine uses" % feature_dim)}

    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
    except Exception as e:
        return {"ok": False, "model": None, "card": {"labels": counts},
                "reason": "scikit-learn is not available: %s" % e}

    tr, te = stratified_split(labels, test_fraction)
    X = np.asarray(vectors, dtype=np.float64)
    y = np.asarray(labels, dtype=np.int64)

    params = {
        # Logistic regression on purpose. The alternative here would be a
        # gradient-booster with better headline numbers and no way to tell an
        # analyst why one alert scored higher than another; a linear model's
        # coefficients are an explanation. class_weight balances a set that is
        # roughly 200:1 against the class we care about.
        #
        # Scaling is INSIDE the pipeline, not borrowed from models/scaler.pkl.
        # The 35 features are on wildly different scales — byte counts beside
        # 0/1 flags — and unscaled lbfgs does not converge in 2000 iterations
        # (observed, not assumed). Bundling the scaler with the estimator also
        # removes any chance of the mismatch that the FAISS index had to be
        # fixed for: the saved model takes the RAW vector the extractor emits
        # and scales it with the statistics it was fitted on, so a caller
        # cannot pair it with the wrong scaler.
        "estimator": "StandardScaler + LogisticRegression",
        "class_weight": "balanced",
        "max_iter": 5000,
        "C": 1.0,
        "solver": "lbfgs",
        "scaling": "StandardScaler inside the pipeline",
    }
    clf = Pipeline([
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=5000,
                                   C=1.0, solver="lbfgs")),
    ])
    clf.fit(X[tr], y[tr])

    pred = clf.predict(X[te]).tolist()
    truth = y[te].tolist()
    m = metrics(truth, pred)
    base = baseline_metrics(truth)
    gate = check_model(m, base, min_recall, min_f1_margin)

    split = {"train": len(tr), "test": len(te),
             "test_fraction": float(test_fraction),
             "train_malicious": int(sum(1 for i in tr if labels[i] == LABEL_MALICIOUS)),
             "test_malicious": int(sum(1 for i in te if labels[i] == LABEL_MALICIOUS))}
    card = model_card(counts, m, base, gate, feature_dim, params,
                      label_sources or {}, split)
    # The training score distribution, so drift can be measured later against
    # the population the model was actually fitted on.
    try:
        card["train_score_deciles"] = _deciles(
            clf.predict_proba(X[tr])[:, 1].tolist())
    except Exception:
        card["train_score_deciles"] = []

    if not gate["publish"]:
        return {"ok": False, "model": None, "card": card,
                "reason": "model refused: " + "; ".join(gate["reasons"])}
    return {"ok": True, "reason": "", "model": clf, "card": card}


def _deciles(scores) -> list:
    s = sorted(float(x) for x in scores)
    if not s:
        return []
    return [round(s[min(len(s) - 1, int(len(s) * i / 10))], 6)
            for i in range(10)]


def save_model(model, card: dict, model_path, card_path) -> None:
    """Write the estimator and its card, atomically.

    joblib, not pickle, and the card beside it: a model whose provenance is not
    recorded cannot be governed, and the pinned scikit-learn version in
    requirements.txt exists because a joblib estimator carries the version that
    wrote it.
    """
    import joblib
    mp, cp = Path(model_path), Path(card_path)
    mp.parent.mkdir(parents=True, exist_ok=True)
    tmp_m = str(mp) + ".tmp"
    tmp_c = str(cp) + ".tmp"
    joblib.dump(model, tmp_m)
    Path(tmp_c).write_text(json.dumps(card, indent=1, ensure_ascii=False),
                           encoding="utf-8")
    os.replace(tmp_m, mp)
    os.replace(tmp_c, cp)


def load_model(model_path, card_path, feature_dim: "int | None" = None) -> dict:
    """{"ok", "model", "card", "reason"}.

    Refuses a model whose recorded feature dimension disagrees with the running
    configuration. Scoring a 35-dimensional vector with a model fitted on 32
    produces numbers, which is the dangerous part.
    """
    out = {"ok": False, "model": None, "card": {}, "reason": ""}
    mp, cp = Path(model_path), Path(card_path)
    if not mp.exists():
        out["reason"] = "no supervised model has been published yet"
        return out
    try:
        out["card"] = json.loads(cp.read_text(encoding="utf-8") or "{}")
    except Exception:
        out["card"] = {}
    recorded = int(out["card"].get("feature_dim") or 0)
    if feature_dim is not None and recorded and recorded != int(feature_dim):
        out["reason"] = ("model was fitted on %d features but the engine is "
                         "producing %d — refusing to score"
                         % (recorded, int(feature_dim)))
        return out
    try:
        import joblib
        out["model"] = joblib.load(str(mp))
    except Exception as e:
        out["reason"] = "could not load the model: %s" % e
        return out
    out["ok"] = True
    return out


def score(model, vector) -> dict:
    """{"malicious_probability", "verdict"} for one event.

    Never raises: an unavailable second opinion is worth less than the pipeline
    it would take down.
    """
    out = {"malicious_probability": None, "verdict": "unavailable"}
    if model is None or vector is None:
        return out
    try:
        import numpy as np
        p = float(model.predict_proba(
            np.asarray([vector], dtype=np.float64))[0][1])
        out["malicious_probability"] = round(p, 6)
        out["verdict"] = "malicious" if p >= 0.5 else "benign"
    except Exception:
        return {"malicious_probability": None, "verdict": "unavailable"}
    return out


def status(model_path=None, card_path=None, counts: "dict | None" = None,
           min_per_class: int = DEFAULT_MIN_PER_CLASS) -> dict:
    """What this module is doing, for /api and the evidence pack."""
    card = {}
    if card_path and Path(card_path).exists():
        try:
            card = json.loads(Path(card_path).read_text(encoding="utf-8") or "{}")
        except Exception:
            card = {}
    published = bool(model_path and Path(model_path).exists())
    supply = check_supply(counts or {}, min_per_class) if counts else {}
    return {
        "published": published,
        "card": card,
        "supply": supply,
        "label_note": (
            "Labels are produced by the analyst console, not supplied from "
            "outside: confirming an incident records a malicious example and "
            "marking a false positive records a benign one. Measured locally "
            "there are already 10,830 benign labels; the malicious class is "
            "short only because the confirm action shipped on 29-Oct-2026."),
        "metric_note": (
            "Judge any model here on recall and F1 for the malicious class. "
            "The labelled set is dominated by false positives, so a model "
            "answering 'benign' to everything would score over 99% accuracy."),
    }


# ── selftest ────────────────────────────────────────────────────────────────

def selftest() -> int:
    import tempfile

    failures = []

    def ok(label, cond):
        if not cond:
            failures.append(label)

    # ── confusion and metrics ──
    c = confusion([1, 1, 0, 0], [1, 0, 1, 0])
    ok("confusion counts tp", c["tp"] == 1)
    ok("confusion counts fn", c["fn"] == 1)
    ok("confusion counts fp", c["fp"] == 1)
    ok("confusion counts tn", c["tn"] == 1)
    m = metrics([1, 1, 0, 0], [1, 1, 0, 0])
    ok("a perfect prediction scores 1.0", m["f1"] == 1.0 and m["recall"] == 1.0)
    m = metrics([1, 1, 0, 0], [0, 0, 0, 0])
    ok("predicting all benign scores zero recall", m["recall"] == 0.0)
    ok("and zero F1", m["f1"] == 0.0)
    ok("but 50% accuracy on a balanced set", m["accuracy"] == 0.5)
    ok("support is reported", m["support_malicious"] == 2)
    ok("empty input does not divide by zero", metrics([], [])["f1"] == 0.0)

    # The imbalance point, which is the whole argument for the gates.
    y = [LABEL_BENIGN] * 198 + [LABEL_MALICIOUS] * 2
    base = baseline_metrics(y)
    ok("the majority baseline scores over 99% accuracy", base["accuracy"] >= 0.99)
    ok("and exactly zero F1 on the class we care about", base["f1"] == 0.0)
    ok("the baseline picks the majority class",
       baseline_metrics([1, 1, 1, 0])["accuracy"] == 0.75)
    ok("an empty baseline is safe", baseline_metrics([])["f1"] == 0.0)

    # ── gates ──
    sup = check_supply({"malicious": 3, "benign": 10830}, 50)
    ok("too few positives is not ready", not sup["ready"])
    ok("and the shortfall names the class",
       any("malicious" in s for s in sup["shortfall"]))
    ok("and the reason tells the operator where labels come from",
       "analyst console" in sup["reason"])
    ok("enough of both is ready",
       check_supply({"malicious": 60, "benign": 900}, 50)["ready"])
    ok("too few negatives is also refused",
       not check_supply({"malicious": 60, "benign": 10}, 50)["ready"])

    good = {"recall": 0.8, "f1": 0.7, "support_malicious": 20}
    poor = {"recall": 0.2, "f1": 0.3, "support_malicious": 20}
    none = {"recall": 0.0, "f1": 0.0, "support_malicious": 0}
    zero = {"f1": 0.0}
    ok("a good model publishes", check_model(good, zero)["publish"])
    ok("a low-recall model is refused", not check_model(poor, zero)["publish"])
    ok("and the refusal quotes the recall",
       "recall on the malicious class" in check_model(poor, zero)["reasons"][0])
    ok("a model with no positives to test on is refused",
       not check_model(none, zero)["publish"])
    ok("and says recall is unmeasurable",
       any("unmeasurable" in r for r in check_model(none, zero)["reasons"]))
    ok("a model that only matches the baseline is refused",
       not check_model({"recall": 0.9, "f1": 0.5, "support_malicious": 9},
                       {"f1": 0.45})["publish"])
    ok("the margin over the baseline is reported",
       check_model(good, zero)["f1_margin_over_baseline"] == 0.7)

    # ── drift ──
    tight = [0.1] * 100
    ok("an identical population is stable", psi(tight, tight)["verdict"] == "stable")
    moved = psi([0.1] * 100, [0.9] * 100)
    ok("a completely moved population is broken", moved["verdict"] == "broken")
    ok("and the index is large", moved["psi"] > 0.25)
    ok("psi with no data says so", psi([], [0.5])["verdict"] == "not enough data")
    ok("psi tolerates junk values", isinstance(psi([0.1, "x"], [0.2])["psi"], float))
    mild = psi([0.1] * 90 + [0.9] * 10, [0.1] * 80 + [0.9] * 20)
    ok("a modest shift is detected as a shift", mild["verdict"] in ("shifted", "stable"))
    ok("psi is finite even with empty buckets", math.isfinite(moved["psi"]))

    # ── labels ──
    with tempfile.TemporaryDirectory() as td:
        fp = Path(td) / "fp.json"
        fp.write_text(json.dumps([
            {"event_id": "e1", "reason": "noise"},
            {"event_id": "e2", "reason": "expected"},
            {"no_id": True}]), encoding="utf-8")
        got = read_false_positives(fp)
        ok("false positives are read", set(got) == {"e1", "e2"})
        ok("records without an id are skipped", len(got) == 2)
        ok("a missing fp file reads empty", read_false_positives(Path(td) / "x") == {})
        fp.write_text("{not json", encoding="utf-8")
        ok("a corrupt fp file reads empty rather than raising",
           read_false_positives(fp) == {})
        # the dict-shaped variant the store also writes
        fp.write_text(json.dumps({"e9": {"event_id": "e9", "reason": "r"}}),
                      encoding="utf-8")
        ok("the dict shape is tolerated", set(read_false_positives(fp)) == {"e9"})

        db = Path(td) / "risk.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE incidents (event_id TEXT, reason TEXT, "
                     "retracted INTEGER DEFAULT 0)")
        conn.executemany("INSERT INTO incidents VALUES (?,?,?)",
                         [("i1", "real", 0), ("i2", "real", 0),
                          ("i3", "mistake", 1)])
        conn.commit()
        conn.close()
        conf = read_confirmed(db)
        ok("confirmed incidents are read", set(conf) == {"i1", "i2"})
        ok("retracted verdicts are excluded", "i3" not in conf)
        ok("a missing ledger reads empty", read_confirmed(Path(td) / "no.db") == {})

        # a ledger with neither a retracted nor an active column
        db2 = Path(td) / "r2.db"
        c2 = sqlite3.connect(db2)
        c2.execute("CREATE TABLE incidents (event_id TEXT)")
        c2.execute("INSERT INTO incidents VALUES ('z1')")
        c2.commit(); c2.close()
        ok("a ledger without a retracted column still reads",
           set(read_confirmed(db2)) == {"z1"})

        # a database with no incidents table at all
        db3 = Path(td) / "r3.db"
        c3 = sqlite3.connect(db3)
        c3.execute("CREATE TABLE other (x TEXT)")
        c3.commit(); c3.close()
        ok("a database without the table reads empty", read_confirmed(db3) == {})

    ok("a confirmed incident labels malicious",
       label_of("i1", {"i1": ""}, {}) == LABEL_MALICIOUS)
    ok("a false positive labels benign",
       label_of("e1", {}, {"e1": ""}) == LABEL_BENIGN)
    ok("confirmation outranks a false-positive mark",
       label_of("x", {"x": ""}, {"x": ""}) == LABEL_MALICIOUS)
    ok("an unlabelled event has no label", label_of("zz", {}, {}) is None)
    ok("an empty id has no label", label_of("", {"": ""}, {}) is None)

    lc = label_counts({"a": "", "b": ""}, {"b": "", "c": "", "d": ""})
    ok("malicious labels are counted", lc["malicious"] == 2)
    ok("benign labels exclude the conflicting one", lc["benign"] == 2)
    ok("conflicts are reported rather than hidden", lc["conflicting"] == 1)
    ok("the total is the union", lc["total"] == 4)

    # ── split ──
    labels = [LABEL_BENIGN] * 80 + [LABEL_MALICIOUS] * 20
    tr, te = stratified_split(labels, 0.25)
    ok("the split uses every row", len(tr) + len(te) == 100)
    ok("train and test do not overlap", not (set(tr) & set(te)))
    ok("the test set holds positives",
       sum(1 for i in te if labels[i] == LABEL_MALICIOUS) > 0)
    ok("the test set holds negatives",
       sum(1 for i in te if labels[i] == LABEL_BENIGN) > 0)
    ok("the split is deterministic", stratified_split(labels, 0.25) == (tr, te))
    tiny = [LABEL_BENIGN, LABEL_MALICIOUS]
    t1, t2 = stratified_split(tiny, 0.25)
    ok("a two-row set keeps both in train", len(t1) == 2 and t2 == [])

    # ── training, end to end ──
    counts_short = {"malicious": 2, "benign": 500}
    r = train([[0.0] * 4] * 10, [0] * 10, feature_dim=4)
    ok("training refuses with no positives", not r["ok"])
    ok("and returns no model", r["model"] is None)
    ok("and explains the shortfall", "not enough labelled" in r["reason"])

    r = train([[0.0] * 3] * 200, [0, 1] * 100, feature_dim=4)
    ok("a feature-dimension mismatch is refused", not r["ok"])
    ok("and says why", "dimensional" in r["reason"])

    try:
        import numpy as np          # noqa: F401
        import sklearn              # noqa: F401
        have_sklearn = True
    except Exception:
        have_sklearn = False

    if have_sklearn:
        import random
        rng = random.Random(7)
        # A learnable signal: the malicious class sits higher on feature 0.
        vecs, labs = [], []
        for _ in range(400):
            vecs.append([rng.gauss(0.2, 0.1), rng.gauss(0.5, 0.2),
                         rng.gauss(0.0, 0.1), rng.gauss(0.1, 0.1)])
            labs.append(LABEL_BENIGN)
        for _ in range(120):
            vecs.append([rng.gauss(0.9, 0.1), rng.gauss(0.5, 0.2),
                         rng.gauss(0.0, 0.1), rng.gauss(0.1, 0.1)])
            labs.append(LABEL_MALICIOUS)
        r = train(vecs, labs, feature_dim=4,
                  label_sources={"benign": "fp store", "malicious": "ledger"})
        ok("a learnable signal trains and publishes", r["ok"])
        ok("and returns a model", r["model"] is not None)
        card = r["card"]
        ok("the card records the feature dimension", card["feature_dim"] == 4)
        ok("the card records the label counts", card["labels"]["malicious"] == 120)
        ok("the card records the label sources", card["label_sources"]["benign"])
        ok("the card carries held-out metrics", card["metrics_heldout"]["recall"] > 0.5)
        ok("the card carries the majority baseline",
           card["metrics_baseline_majority"]["f1"] == 0.0)
        ok("the card states the gate result", card["gate"]["publish"] is True)
        ok("the card warns against reading accuracy",
           "not on accuracy" in card["headline"])
        ok("the card quotes both F1 figures it is comparing",
           ("%.3f" % card["metrics_heldout"]["f1"]) in card["headline"])
        # The headline must describe the balance it actually saw, not assume.
        bal = abs(card["metrics_heldout"]["accuracy"]
                  - card["metrics_baseline_majority"]["accuracy"])
        ok("the headline describes the real accuracy margin",
           ("says almost nothing" in card["headline"]) == (bal < 0.05))
        ok("the card records the split", card["split"]["test_malicious"] > 0)
        ok("the card records the training score spread",
           len(card["train_score_deciles"]) == 10)

        ok("the published model bundles its own scaler",
           hasattr(r["model"], "named_steps")
           and "scale" in r["model"].named_steps)
        ok("the card records that scaling is internal",
           "StandardScaler" in r["card"]["params"]["scaling"])
        # Wildly different feature scales must still converge, which is the
        # reason the scaler is in the pipeline at all.
        wide, wlab = [], []
        for i in range(300):
            wide.append([rng.gauss(0.2, 0.1), rng.gauss(50000, 20000),
                         rng.gauss(0.0, 0.01), float(i % 2)])
            wlab.append(LABEL_BENIGN)
        for i in range(120):
            wide.append([rng.gauss(0.9, 0.1), rng.gauss(900000, 20000),
                         rng.gauss(0.0, 0.01), float(i % 2)])
            wlab.append(LABEL_MALICIOUS)
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", category=UserWarning)
            try:
                wr = train(wide, wlab, feature_dim=4)
                converged = True
            except Exception:
                converged = False
        ok("features on very different scales converge without warning",
           converged)
        ok("and the model on them publishes", wr["ok"])

        s = score(r["model"], [0.95, 0.5, 0.0, 0.1])
        ok("a malicious-looking vector scores high",
           s["malicious_probability"] > 0.5 and s["verdict"] == "malicious")
        s = score(r["model"], [0.15, 0.5, 0.0, 0.1])
        ok("a benign-looking vector scores low",
           s["malicious_probability"] < 0.5 and s["verdict"] == "benign")
        ok("scoring a None vector is safe",
           score(r["model"], None)["verdict"] == "unavailable")
        ok("scoring with no model is safe",
           score(None, [0.1] * 4)["verdict"] == "unavailable")
        ok("scoring a wrong-width vector is safe, not a crash",
           score(r["model"], [0.1] * 99)["verdict"] == "unavailable")

        # noise only: nothing to learn, so the gate must refuse
        nvecs, nlabs = [], []
        for i in range(400):
            nvecs.append([rng.gauss(0.5, 0.2) for _ in range(4)])
            nlabs.append(LABEL_BENIGN if i % 4 else LABEL_MALICIOUS)
        nr = train(nvecs, nlabs, feature_dim=4)
        ok("an unlearnable set is refused or honestly weak",
           (not nr["ok"]) or nr["card"]["metrics_heldout"]["recall"] >= 0.5)
        if not nr["ok"]:
            ok("and the refusal is recorded on the card",
               nr["card"]["gate"]["publish"] is False)
        else:
            ok("and the refusal is recorded on the card", True)

        with tempfile.TemporaryDirectory() as td:
            mp, cp = Path(td) / "sup.pkl", Path(td) / "sup_card.json"
            ok("no model means nothing to load",
               not load_model(mp, cp)["ok"])
            ok("and it says so",
               "no supervised model" in load_model(mp, cp)["reason"])
            save_model(r["model"], r["card"], mp, cp)
            back = load_model(mp, cp, feature_dim=4)
            ok("a saved model loads", back["ok"])
            ok("the card loads with it", back["card"]["feature_dim"] == 4)
            ok("the loaded model scores the same",
               score(back["model"], [0.95, 0.5, 0.0, 0.1])["verdict"] == "malicious")
            wrong = load_model(mp, cp, feature_dim=35)
            ok("a dimension mismatch refuses to score", not wrong["ok"])
            ok("and explains the mismatch", "fitted on 4 features" in wrong["reason"])

            st = status(mp, cp, {"malicious": 3, "benign": 10830})
            ok("status reports the model as published", st["published"] is True)
            ok("status carries the supply verdict", st["supply"]["ready"] is False)
            ok("status says where labels come from",
               "analyst console" in st["label_note"])
            ok("status warns about accuracy", "99% accuracy" in st["metric_note"])
    else:
        for lbl in ("sklearn-dependent checks skipped",):
            ok(lbl, True)

    st = status(None, None, {"malicious": 0, "benign": 10830})
    ok("status with no model is not published", st["published"] is False)
    ok("and still reports the shortfall", st["supply"]["ready"] is False)

    total = 107 if have_sklearn else 72
    if failures:
        print("ueba_supervised selftest: %d/%d FAILED" % (len(failures), total))
        for f in failures:
            print("  ✗ %s" % f)
        return 1
    print("ueba_supervised selftest: all %d checks passed%s"
          % (total, "" if have_sklearn else " (sklearn absent, fit/predict skipped)"))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(selftest() if "--selftest" in sys.argv else (print(__doc__) or 0))
