#!/usr/bin/env python3
"""Sample records at spread-out byte offsets across a big jsonl and tabulate the
exact fields the preprocessor reads for the 'skewed' features, to see whether
they are genuinely constant/missing in the training corpus."""
import sys, json, os
from collections import Counter

path = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
size = os.path.getsize(path)

def gn(d, dotted, default=None):
    cur = d
    for k in dotted.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur

counters = {
    "event_category": Counter(),
    "event_outcome": Counter(),
    "rule.level": Counter(),
    "security.severity": Counter(),
    "context.raw_event.rule.level": Counter(),
    "enrich.normalization.direction": Counter(),
    "network.direction": Counter(),
    "enrich.flags.is_network_event": Counter(),
    "enrich.flags.is_auth_event": Counter(),
    "enrich.flags.is_file_event": Counter(),
    "enrich.anomalies.is_brute_force": Counter(),
    "enrich.behavioral.recent_failures_5m": Counter(),
    "schema_version": Counter(),
}

got = 0
with open(path, "rb") as f:
    # Evenly spaced offsets; realign to next full line at each.
    step = max(size // N, 1)
    off = 0
    while off < size and got < N:
        f.seek(off)
        f.readline()  # discard partial line
        line = f.readline()
        off += step
        if not line:
            continue
        try:
            d = json.loads(line.decode("utf-8", "ignore"))
        except Exception:
            continue
        got += 1
        for key, c in counters.items():
            v = gn(d, key, "<MISSING>")
            if isinstance(v, (dict, list)):
                v = type(v).__name__
            c[str(v)] += 1

print(f"file={path}\nsampled={got} (evenly across {size/1e9:.1f} GB)\n")
for key, c in counters.items():
    top = c.most_common(6)
    print(f"{key}:")
    for val, n in top:
        print(f"    {n:>7} ({100*n/max(got,1):5.1f}%)  {val[:60]}")
    print()
