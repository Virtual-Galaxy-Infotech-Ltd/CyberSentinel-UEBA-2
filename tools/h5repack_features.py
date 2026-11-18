#!/usr/bin/env python3
"""Reclaim unreclaimed free space in features.h5.

HDF5 does not return freed space to the filesystem. Repeated rebuilds of the
feature store left 20.08 GB of a 20.84 GB file as unreclaimed free space, with
only 0.76 GB of real data (confirmed by a chunk-level walk). This rewrites the
datasets into a fresh file, which is what h5repack does -- the hdf5-tools
package is not installed here, and h5py does the same job without adding a
package to a production host.

It does NOT swap the file in. It writes a candidate beside the original and
verifies it byte-for-byte. The swap is a separate, deliberate step.
"""
import os, sys, time
import h5py, numpy as np

SRC = "/data/ueba_training/features.h5"
DST = "/data/ueba_training/features.h5.repacked"

FEAT_ROWS = 500_000      # 500k x 35 x 4 B = 70 MB per slab
META_ROWS = 200_000

def human(b): return "%.2f GB" % (b / 1e9)

def main():
    if os.path.exists(DST):
        print("candidate already exists, removing:", DST); os.remove(DST)

    t0 = time.time()
    with h5py.File(SRC, "r") as s, h5py.File(DST, "w") as d:
        for name in s:
            src = s[name]
            n = src.shape[0]
            dst = d.create_dataset(
                name, shape=src.shape, dtype=src.dtype,
                chunks=src.chunks, maxshape=src.maxshape,
                compression=src.compression,
                compression_opts=src.compression_opts,
                shuffle=src.shuffle, fletcher32=src.fletcher32,
            )
            for k, v in src.attrs.items():
                dst.attrs[k] = v
            step = FEAT_ROWS if src.dtype != object else META_ROWS
            print("copying %-9s %s rows ..." % (name, f"{n:,}"), flush=True)
            for i in range(0, n, step):
                j = min(i + step, n)
                dst[i:j] = src[i:j]
                if (i // step) % 10 == 0:
                    print("   %s / %s" % (f"{j:,}", f"{n:,}"), flush=True)
        for k, v in s.attrs.items():
            d.attrs[k] = v
    print("copy done in %.1f s" % (time.time() - t0), flush=True)

    # ── verify: structure, then every row ──────────────────────────────────
    print("\nVERIFYING", flush=True)
    bad = []
    with h5py.File(SRC, "r") as s, h5py.File(DST, "r") as d:
        if sorted(s.keys()) != sorted(d.keys()):
            bad.append("dataset names differ")
        for name in s:
            a, b = s[name], d[name]
            for attr in ("shape", "dtype", "chunks", "maxshape", "compression",
                         "compression_opts", "shuffle", "fletcher32"):
                va, vb = getattr(a, attr), getattr(b, attr)
                if va != vb:
                    bad.append("%s.%s: %r != %r" % (name, attr, va, vb))
            n = a.shape[0]
            step = FEAT_ROWS if a.dtype != object else META_ROWS
            for i in range(0, n, step):
                j = min(i + step, n)
                x, y = a[i:j], b[i:j]
                same = np.array_equal(x, y) if a.dtype != object else list(x) == list(y)
                if not same:
                    bad.append("%s: rows %d:%d differ" % (name, i, j)); break
            print("  %-9s %s rows compared  -> %s" %
                  (name, f"{n:,}", "identical" if not any(name in e for e in bad) else "MISMATCH"),
                  flush=True)

    ssz, dsz = os.path.getsize(SRC), os.path.getsize(DST)
    print("\n  source   : %s" % human(ssz))
    print("  repacked : %s" % human(dsz))
    print("  reclaimed: %s  (%.0f%% smaller)" % (human(ssz - dsz), 100 * (ssz - dsz) / ssz))
    if bad:
        print("\nVERIFY FAILED -- candidate left in place, original untouched:")
        for e in bad: print("   -", e)
        return 1
    print("\nVERIFY PASS -- candidate is identical to the original.")
    print("Original is untouched. Swap is a separate step.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
