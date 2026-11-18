#!/usr/bin/env python3
"""Shrink the RAG FAISS index + metadata so the engine fits its 10G cgroup limit.

WHY: RAGRetriever loads EVERY metadata record into a Python list of dicts.
The Sunday 2026-11-08 retrain rebuilt the index at the configured ceiling
(rag.max_index_size = 7,000,000 x index_build_fraction 0.8 = 5.6M vectors).
3.76 GB of JSONL becomes ~15-20 GB of Python dicts, which blows MemoryMax=10G.
The engine was cgroup-OOM-killed on every start from 2026-11-09 00:05 onward.

Keeps the MOST RECENT N records: metadata.jsonl is chronological, and recent
history is what "similar past events" should surface. Index and metadata are
sliced to the SAME range so row i in the index still maps to row i in metadata
-- if that alignment breaks, every RAG result silently points at the wrong event.
"""
import json, os, shutil, sys, time
import faiss, numpy as np

VDB   = "/opt/ueba/vector_db"
IDX   = os.path.join(VDB, "faiss.index")
META  = os.path.join(VDB, "metadata.jsonl")
KEEP  = int(os.environ.get("KEEP", "1500000"))

def main():
    bak = VDB + ".bak-" + time.strftime("%y%m%d-%H%M%S")
    print("backing up ->", bak, flush=True)
    shutil.copytree(VDB, bak)

    idx = faiss.read_index(IDX)
    n = idx.ntotal
    print("index: %s vectors, type %s, d=%d" % (f"{n:,}", type(idx).__name__, idx.d))
    with open(META) as f:
        total_lines = sum(1 for _ in f)
    print("metadata: %s lines" % f"{total_lines:,}")
    if n != total_lines:
        print("REFUSING: index (%d) and metadata (%d) already disagree" % (n, total_lines))
        return 1
    if n <= KEEP:
        print("already <= KEEP (%d); nothing to do" % KEEP); return 0

    start = n - KEEP
    print("keeping the most recent %s (rows %s..%s)" % (f"{KEEP:,}", f"{start:,}", f"{n:,}"), flush=True)

    vecs = idx.reconstruct_n(start, KEEP).astype(np.float32)
    print("reconstructed %s x %d  (%.2f GB)" % (f"{len(vecs):,}", idx.d, vecs.nbytes/1e9), flush=True)

    new = faiss.IndexFlatIP(idx.d) if "IP" in type(idx).__name__ else faiss.IndexFlatL2(idx.d)
    new.add(vecs)
    print("new index built: %s vectors (%s)" % (f"{new.ntotal:,}", type(new).__name__), flush=True)

    tmp_i, tmp_m = IDX + ".new", META + ".new"
    faiss.write_index(new, tmp_i)
    kept = 0
    with open(META) as fin, open(tmp_m, "w") as fout:
        for i, line in enumerate(fin):
            if i >= start:
                fout.write(line); kept += 1
    print("metadata written: %s lines" % f"{kept:,}", flush=True)

    # verify BEFORE swapping
    chk = faiss.read_index(tmp_i)
    if chk.ntotal != kept:
        print("REFUSING to swap: index %d != metadata %d" % (chk.ntotal, kept)); return 1
    v_old = idx.reconstruct(n - 1)
    v_new = chk.reconstruct(chk.ntotal - 1)
    if not np.allclose(v_old, v_new):
        print("REFUSING to swap: last vector does not match the original"); return 1
    print("verified: counts match and the last vector is identical")

    os.replace(tmp_i, IDX); os.replace(tmp_m, META)
    print("swapped in.")
    print("  faiss.index    %.2f GB" % (os.path.getsize(IDX)/1e9))
    print("  metadata.jsonl %.2f GB" % (os.path.getsize(META)/1e9))
    print("backup kept at", bak)
    return 0

if __name__ == "__main__":
    sys.exit(main())
