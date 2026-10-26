#!/usr/bin/env python3
"""
identity_diag.py
────────────────
CyberSentinel UEBA — what identity canonicalisation would change.

Read-only. Runs resolve_entity() over an alert/enriched sample twice — once
with `identity_resolution.canonicalize` off, once on — and reports exactly
which entity keys merge, so the effect is measurable BEFORE the flag is
flipped on a deployment.

Also checks each configured `mappings` entry against the autoencoder files
actually on disk. A mapping whose target has no model file silently falls back
to the global autoencoder, which is how 3 of the original 5 mappings were
failing without anything in the logs saying so.

Usage:
  python3 identity_diag.py --config ueba_config.yaml --input ueba_alerts.jsonl
  python3 identity_diag.py --models models/autoencoders          # add disk check
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import ueba_preprocessor as pp


def _safe_name(username: str) -> str:
    """Verbatim from ueba_models/autoencoder.py — entity key → model filename."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in username)


def _keys(path, cfg, canonicalize, limit):
    """Entity key for every record in the sample, under one config setting."""
    cfg = dict(cfg)
    block = dict(cfg.get("identity_resolution", {}) or {})
    block["canonicalize"] = canonicalize
    cfg["identity_resolution"] = block
    pp.apply_identity_config(cfg)

    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            out.append(pp.resolve_entity(rec))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--input", default="ueba_alerts.jsonl")
    ap.add_argument("--models", default="models/autoencoders")
    ap.add_argument("--limit", type=int, default=0, help="0 = whole file")
    args = ap.parse_args()

    if not Path(args.input).exists():
        sys.exit("no such sample: %s" % args.input)

    cfg = pp.load_config(args.config)

    before = _keys(args.input, cfg, False, args.limit)
    after  = _keys(args.input, cfg, True,  args.limit)

    if len(before) != len(after):
        sys.exit("record counts differ (%d vs %d) — sample changed underfoot"
                 % (len(before), len(after)))

    print("records read: %d\n" % len(before))

    # ── key counts, split by entity kind ────────────────────────────────────
    def kinds(keys):
        d = defaultdict(set)
        for k in keys:
            if k.startswith("ip:"):
                d["ip"].add(k)
            elif k.startswith("host:"):
                d["host"].add(k)
            elif k == "unknown":
                d["unknown"].add(k)
            else:
                d["account"].add(k)
        return d

    kb, ka = kinds(before), kinds(after)
    print("DISTINCT ENTITY KEYS")
    print("  %-10s %8s %8s %8s" % ("kind", "before", "after", "merged"))
    for kind in ("account", "ip", "host", "unknown"):
        b, a = len(kb[kind]), len(ka[kind])
        print("  %-10s %8d %8d %8d" % (kind, b, a, b - a))
    tb, ta = len(set(before)), len(set(after))
    print("  %-10s %8d %8d %8d" % ("TOTAL", tb, ta, tb - ta))

    # ip:/host: keys must be untouched — the type-awareness guarantee
    for kind in ("ip", "host"):
        if kb[kind] != ka[kind]:
            print("\n  !! %s keys changed — canonicalisation leaked past accounts"
                  % kind)
            for k in sorted(kb[kind] ^ ka[kind])[:10]:
                print("     %s" % k)

    # ── what merged into what ───────────────────────────────────────────────
    groups = defaultdict(set)
    for b, a in zip(before, after):
        if not (b.startswith(("ip:", "host:")) or b == "unknown"):
            groups[a].add(b)
    merged = {a: bs for a, bs in groups.items() if len(bs) > 1}

    counts = defaultdict(int)
    for b in before:
        counts[b] += 1

    print("\nIDENTITIES THAT MERGE (%d)" % len(merged))
    if not merged:
        print("  none")
    for a, bs in sorted(merged.items(), key=lambda kv: -len(kv[1])):
        parts = ", ".join("%r(%d)" % (b, counts[b]) for b in sorted(bs))
        print("  %-24s <- %s" % (a, parts))

    affected = sum(counts[b] for bs in merged.values() for b in bs)
    acct_recs = sum(1 for b in before
                    if not (b.startswith(("ip:", "host:")) or b == "unknown"))
    dupes = sum(len(bs) - 1 for bs in merged.values())
    print("\n  %d of %d account identities (%.1f%%) were duplicates, "
          "across %d of %d account records (%.1f%%)"
          % (dupes, len(kb["account"]),
             100.0 * dupes / max(len(kb["account"]), 1),
             affected, acct_recs, 100.0 * affected / max(acct_recs, 1)))

    # ── do the configured mappings land on a real model file? ───────────────
    mdir = Path(args.models)
    block = cfg.get("identity_resolution", {}) or {}
    maps = block.get("mappings", {}) or {}
    if maps:
        # Evaluate the targets WITH canonicalisation on: the question is what
        # these resolve to after the cutover, not what they do today.
        _cfg = dict(cfg)
        _blk = dict(_cfg.get("identity_resolution", {}) or {})
        _blk["canonicalize"] = True
        _cfg["identity_resolution"] = _blk
        pp.apply_identity_config(_cfg)

        observed = set(after)
        have = {p.stem for p in mdir.glob("*.pt")} if mdir.is_dir() else None

        print("\nCONFIGURED MAPPINGS — where each target lands after the cutover")
        print("  %-24s %-24s %-10s %s"
              % ("target as written", "canonical key", "in sample", "model file"))
        reachable = hit = 0
        for alias, target in maps.items():
            key = pp.canonical_identity(str(target))
            fn = _safe_name(str(key))
            seen = key in observed
            reachable += seen
            if have is None:
                disk = "(no models dir)"
            else:
                ok = fn in have
                hit += ok
                disk = "HIT" if ok else "MISS -> global"
            print("  %-24s %-24s %-10s %s"
                  % (str(target)[:24], str(key)[:24],
                     "yes" if seen else "no", disk))

        print("\n  %d of %d targets are keys the sample actually produces."
              % (reachable, len(maps)))
        if reachable < len(maps):
            print("  A target marked 'no' does not appear in THIS sample. That "
                  "is worth checking but\n  is not proof the mapping is dead — "
                  "the sample may simply be too short. It IS\n  dead if the "
                  "target is a HOSTNAME, because resolve_entity() keys those as\n"
                  "  host:<name> and canonicalisation never touches them, so no "
                  "account key can\n  ever equal it. Compare against "
                  "host:<target> before deleting the mapping.")
        if have is not None:
            print("\n  %d hit, %d MISS against %s today. A MISS for a "
                  "reachable target is\n  expected pre-retrain — the model is "
                  "only built under the canonical key once\n  training has run "
                  "with canonicalize on." % (hit, len(maps) - hit, mdir))

    pp.apply_identity_config(cfg)          # leave module state as configured


if __name__ == "__main__":
    main()
