#!/usr/bin/env python3
"""Seed the FAISS RAG index from the alert history.

The trainer builds this index from features.h5, which does not exist yet — the
training corpus arrives with the first weekly retrain. Meanwhile the engine's
RAGRetriever refuses to start without an index file, so similar_events has been
empty on every alert and Layer 3 contributes nothing.

Seeding from the alert history is the honest substitute, and it is also what
the design already does at runtime: add_to_index() appends every new alert's
vector, so an index built from past alerts is the same population the engine
would have accumulated had the file existed. Vectors and metadata come from the
SAME FeatureExtractor.extract / extract_metadata pair the engine uses, and are
scaled with the SAME models/scaler.pkl the retriever scales queries with —
otherwise the similarity would be meaningless.

Replaced wholesale by the trainer on the next retrain, which is correct: a
corpus-wide index covers normal behaviour too, not only what already alerted.
"""
import json
import os
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import joblib
import numpy as np
import yaml
import faiss

from ueba_preprocessor import FeatureExtractor, UserProfileStore

# The install root, derived from this file's location so the script works on
# any deployment, with an override for running it from elsewhere.
BASE = Path(os.environ.get("UEBA_BASE") or Path(__file__).resolve().parent)
CFG = yaml.safe_load(open(BASE / "ueba_config.yaml"))
PATHS = CFG["paths"]
DIM = int(CFG["preprocessing"]["feature_dim"])
MAX = int(CFG["rag"]["max_index_size"])
FRAC = float(CFG["rag"].get("index_build_fraction", 0.8))
CEILING = max(1, int(MAX * FRAC))


def resolve(p):
    q = Path(str(p))
    return q if q.is_absolute() else (BASE / q)


IDX_PATH = resolve(PATHS["faiss_index"])
META_PATH = resolve(PATHS["faiss_metadata"])
SCALER_PATH = resolve(PATHS["scaler"])


def alert_sources():
    """Every full alert we hold: the live file, then the archived zips."""
    live = BASE / "ueba_alerts.jsonl"
    if live.exists():
        with open(live, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield line
    # The .slimN files are a projection with fields dropped, so they cannot
    # regenerate a feature vector. The .zip archives hold the full alerts.
    for z in sorted((BASE / "archive").glob("*.jsonl.zip")):
        try:
            with zipfile.ZipFile(z) as zf:
                for name in zf.namelist():
                    with zf.open(name) as fh:
                        for raw in fh:
                            line = raw.decode("utf-8", "replace").strip()
                            if line:
                                yield line
        except Exception as e:
            print("  ! could not read %s: %s" % (z.name, e))


def main():
    print("FAISS index build")
    print("  index   -> %s" % IDX_PATH)
    print("  metadata-> %s" % META_PATH)
    print("  scaler  <- %s" % SCALER_PATH)
    print("  dim=%d  ceiling=%s (%.0f%% of max_index_size %s)"
          % (DIM, "{:,}".format(CEILING), FRAC * 100, "{:,}".format(MAX)))
    print()

    if not SCALER_PATH.exists():
        print("  FATAL: scaler missing — the retriever scales queries with it, so an "
              "index built without it would return meaningless neighbours")
        return 1
    # joblib, not pickle: joblib stores the numpy arrays after the pickle
    # stream, so plain pickle.load reads the header and then chokes. This is
    # the same call the engine makes.
    scaler = joblib.load(str(SCALER_PATH))

    store = UserProfileStore(str(resolve(PATHS["profile_db"])))
    extractor = FeatureExtractor(CFG, store)

    vecs, metas, seen = [], [], set()
    read = skipped = dup = 0
    for line in alert_sources():
        if len(vecs) >= CEILING:
            break
        try:
            a = json.loads(line)
        except Exception:
            skipped += 1
            continue
        read += 1
        eid = a.get("event_id")
        if eid:
            if eid in seen:
                dup += 1
                continue
            seen.add(eid)
        try:
            v = extractor.extract(a)
            if v is None or len(v) != DIM:
                skipped += 1
                continue
            m = extractor.extract_metadata(a) or {}
            # Parity with the runtime add, which appends risk_verdict to the
            # same metadata dict.
            m["risk_verdict"] = ((a.get("ueba") or {}).get("risk_verdict") or "")
            vecs.append(np.asarray(v, dtype=np.float32))
            metas.append(m)
        except Exception:
            skipped += 1

    print("  alerts read      : %s" % "{:,}".format(read))
    print("  duplicates skipped: %s" % "{:,}".format(dup))
    print("  unusable skipped : %s" % "{:,}".format(skipped))
    print("  vectors to index : %s" % "{:,}".format(len(vecs)))
    if not vecs:
        print("  FATAL: nothing to index")
        return 1

    X = np.vstack(vecs).astype(np.float32)
    raw_sample = X[0].copy()          # unscaled, for the self-check below
    del vecs
    X = scaler.transform(X).astype(np.float32)
    faiss.normalize_L2(X)                 # cosine similarity via inner product

    index = faiss.IndexFlatIP(DIM)
    index.add(X)
    print("  index built      : %d vectors, dim %d" % (index.ntotal, index.d))
    assert index.ntotal == len(metas), "vector/metadata count must match exactly"

    IDX_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Write beside the target and move into place, so a crash mid-write cannot
    # leave the engine loading a truncated index.
    tmp_i = str(IDX_PATH) + ".tmp"
    tmp_m = str(META_PATH) + ".tmp"
    faiss.write_index(index, tmp_i)
    with open(tmp_m, "w", encoding="utf-8") as f:
        for m in metas:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")
    os.replace(tmp_i, IDX_PATH)
    os.replace(tmp_m, META_PATH)
    print()
    print("  wrote %s (%s) and %s (%s lines)"
          % (IDX_PATH.name, "{:,}".format(IDX_PATH.stat().st_size),
             META_PATH.name, "{:,}".format(len(metas))))
    print("  headroom for runtime adds: %s vectors"
          % "{:,}".format(MAX - index.ntotal))

    # Prove it answers, through the same class the engine uses.
    from ueba_models.clusterer import RAGRetriever
    r = RAGRetriever(str(IDX_PATH), str(META_PATH), scaler, CFG)
    print()
    print("  retriever available: %s" % r.available)
    if r.available and raw_sample is not None:
        # Query with a RAW (unscaled) vector, because that is what the engine
        # passes: retrieve() scales and normalises internally. Feeding it an
        # already-scaled vector would exercise a path the engine never takes.
        hits = r.retrieve(raw_sample)
        print("  sample query returned %d neighbour(s) at min_similarity=%s"
              % (len(hits), CFG["rag"]["min_similarity"]))
        for h in hits[:3]:
            print("     sim=%.4f user=%-22s cat=%-10s verdict=%s"
                  % (h["similarity_score"], str(h["user"])[:22],
                     str(h["event_category"])[:10], h["risk_verdict"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
