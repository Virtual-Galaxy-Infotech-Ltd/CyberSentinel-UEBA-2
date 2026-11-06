#!/usr/bin/env python3
"""The per-user preload reads the feature matrix once, not once per user.

WHAT THIS IS ABOUT

HDF5Dataset read the ENTIRE features dataset on every construction and then
sliced out the rows it wanted. The features dataset is gzip-compressed, so
each read decompresses every chunk — on the live 28,888,489-row file that is
~2,890 chunks and about a minute, regardless of how few rows the caller asked
for. Per-user training builds one Dataset per user, so 1,003 eligible users
meant ~19.5 TB of reads and an estimated 32 HOURS for a job documented as
30-90 minutes. The tell was that a 1 MB user cost the same minute as a 3 MB
one: the cost tracked the FILE, not the request.

Two things have to hold for the fix to be worth anything, and they fail
differently:

  * it must be FASTER — asserted by counting actual dataset reads, not by
    timing, because a timing assertion on a small fixture is noise;
  * it must return THE SAME DATA. A fast path that quietly returns different
    rows would train every per-user model on the wrong events, and nothing
    downstream would notice.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

import h5py  # noqa: E402
import numpy as np  # noqa: E402

import ueba_trainer as TR  # noqa: E402

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


class CountingFile:
    """Wraps h5py.File to count how often the features dataset is read.

    `_real` is captured at class-definition time. Calling h5py.File from
    inside here would hit the patched name and recurse until the stack dies.
    """

    reads = 0
    _real = h5py.File

    def __init__(self, *a, **k):
        self._f = CountingFile._real(*a, **k)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self._f.close()
        return False

    def __getitem__(self, name):
        ds = self._f[name]
        if name == "features":
            return CountingDataset(ds)
        return ds

    def close(self):
        self._f.close()


class CountingDataset:
    def __init__(self, ds):
        self._ds = ds

    @property
    def shape(self):
        return self._ds.shape

    @property
    def dtype(self):
        return self._ds.dtype

    def __getitem__(self, key):
        # Count only reads that pull the whole dataset or a big slab — the
        # thing that triggers decompression of every chunk.
        if isinstance(key, slice):
            CountingFile.reads += 1
        return self._ds[key]


def build_h5(path: Path, rows: int, dim: int, users: int, seed=7):
    """A compressed features.h5 with per-user row scatter, like the real one."""
    rng = np.random.default_rng(seed)
    feats = rng.normal(0, 1, (rows, dim)).astype(np.float32)
    owner = rng.integers(0, users, rows)
    with h5py.File(path, "w") as f:
        # gzip and the same chunk shape as production: the compression is the
        # whole reason a full read is expensive.
        f.create_dataset("features", data=feats, compression="gzip",
                         chunks=(min(1000, rows), dim))
        f.create_dataset("owner", data=owner)
    return feats, owner


class IdentityScaler:
    def transform(self, X):
        return np.asarray(X, dtype=np.float32)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="preload-"))
    rows, dim, users = 20000, 35, 12
    h5 = work / "features.h5"
    feats, owner = build_h5(h5, rows, dim, users)

    # ── load_feature_matrix returns the data faithfully ──
    m = TR.load_feature_matrix(str(h5), chunk_rows=4096)
    ok("the matrix has the right shape", m.shape == (rows, dim), str(m.shape))
    ok("and is float32", m.dtype == np.float32, str(m.dtype))
    ok("and is exactly what is on disk", np.array_equal(m, feats))
    ok("chunked reading does not drop the tail",
       np.array_equal(m[-1], feats[-1]))
    ok("byte estimate matches reality",
       TR.feature_matrix_bytes(str(h5)) == m.nbytes,
       "%d vs %d" % (TR.feature_matrix_bytes(str(h5)), m.nbytes))

    # ── the shared path returns the SAME rows as the per-call path ──
    # This is the assertion that matters most: a fast path returning
    # different rows would train every model on the wrong events.
    sc = IdentityScaler()
    for uid in (0, 3, 11):
        idx = np.where(owner == uid)[0]
        old = TR.HDF5Dataset(str(h5), indices=idx, scaler=sc)
        new = TR.HDF5Dataset(str(h5), indices=idx, scaler=sc, source=m)
        ok("user %d: same row count both ways" % uid,
           len(old) == len(new) == len(idx),
           "%d / %d / %d" % (len(old), len(new), len(idx)))
        ok("user %d: identical data both ways" % uid,
           np.array_equal(old.data.numpy(), new.data.numpy()))
        ok("user %d: and it really is that user's rows" % uid,
           np.array_equal(new.data.numpy(), feats[idx]))

    # Full-dataset case, as the global model uses it.
    g_old = TR.HDF5Dataset(str(h5), scaler=sc)
    g_new = TR.HDF5Dataset(str(h5), scaler=sc, source=m)
    ok("global: same length", len(g_old) == len(g_new) == rows)
    ok("global: identical data",
       np.array_equal(g_old.data.numpy(), g_new.data.numpy()))

    # ── the read count: once, not once per user ──
    real_file = h5py.File
    try:
        h5py.File = CountingFile

        CountingFile.reads = 0
        for uid in range(users):
            idx = np.where(owner == uid)[0]
            TR.HDF5Dataset(str(h5), indices=idx, scaler=sc)
        per_call = CountingFile.reads
        ok("the OLD path reads the dataset once per user",
           per_call >= users, "%d reads for %d users" % (per_call, users))

        CountingFile.reads = 0
        shared = TR.load_feature_matrix(str(h5), chunk_rows=4096)
        after_load = CountingFile.reads
        for uid in range(users):
            idx = np.where(owner == uid)[0]
            TR.HDF5Dataset(str(h5), indices=idx, scaler=sc, source=shared)
        shared_total = CountingFile.reads
        ok("the SHARED path reads nothing per user",
           shared_total == after_load,
           "%d during load, %d total" % (after_load, shared_total))
        ok("so the shared path reads far less than the old one",
           shared_total < per_call,
           "%d vs %d for %d users" % (shared_total, per_call, users))
    finally:
        h5py.File = real_file

    # ── degenerate inputs ──
    empty = np.array([], dtype=np.int64)
    ds = TR.HDF5Dataset(str(h5), indices=empty, scaler=sc, source=m)
    ok("an empty index set yields an empty dataset", len(ds) == 0)
    one = TR.HDF5Dataset(str(h5), indices=np.array([5]), scaler=sc, source=m)
    ok("a single row works", len(one) == 1)
    ok("and is the right row", np.array_equal(one.data.numpy()[0], feats[5]))
    # Unsorted indices must still map correctly — the per-user index lists
    # come from a metadata scan and are not guaranteed ordered.
    mixed = np.array([9, 2, 17, 4])
    mx = TR.HDF5Dataset(str(h5), indices=mixed, scaler=sc, source=m)
    ok("unsorted indices keep their order",
       np.array_equal(mx.data.numpy(), feats[mixed]))

    # ── the shared matrix must not be mutated by a consumer ──
    before = m.copy()
    TR.HDF5Dataset(str(h5), indices=np.where(owner == 0)[0], scaler=sc, source=m)
    TR.HDF5Dataset(str(h5), scaler=sc, source=m)
    ok("building datasets leaves the shared matrix untouched",
       np.array_equal(m, before),
       "a consumer mutated the shared matrix; every later user would be wrong")

    total = len(_checks)
    if _failures:
        print("trainer preload: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("trainer preload: all %d checks passed" % total)
    print("workdir (safe to delete): %s" % work)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
