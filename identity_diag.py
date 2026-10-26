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
from collections import Counter, defaultdict
from pathlib import Path

import ueba_preprocessor as pp


def _safe_name(username: str) -> str:
    """Verbatim from ueba_models/autoencoder.py — entity key → model filename."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in username)


def _keys(path, cfg, canonicalize, limit, typed=False):
    """Entity key for every record in the sample, under one config setting."""
    cfg = dict(cfg)
    block = dict(cfg.get("identity_resolution", {}) or {})
    block["canonicalize"] = canonicalize
    block["typed_keys"] = typed
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


# Expected classifications. Each case states a rule the engine depends on, so a
# failure here means detection behaviour changed, not that a label moved.
_SELFTEST_IP = [
    ("10.200.11.76",  False), ("192.168.1.5", False), ("172.16.4.9",   False),
    ("127.0.0.1",     False), ("169.254.1.1", False), ("10.200.11.76 ", False),
    ("45.148.10.151", True),  ("2.57.121.112", True), ("8.8.8.8",      True),
    ("",              False), ("not-an-ip",   False),
]

_SELFTEST_ENTITY = [
    (("root", "45.148.10.151", "CPU-SRV-208"), "external:45.148.10.151",
     "a public source IP outranks every other classification — this is the "
     "rule that keeps 912 brute-force events out of root's baseline"),
    (("jinu", "", "VGSOC-LAP11"), "person:jinu",
     "an endpoint user with no source IP is a person"),
    (("VGSOC-LAP11\\JINU", "", "VGSOC-LAP11"), "person:jinu",
     "qualified spellings canonicalise to one person"),
    (("root", "10.200.11.5", "GPU_SRV"), "shared:root@GPU_SRV",
     "root reached internally is host-scoped, so root on the GPU box is not "
     "root on the ATM server"),
    (("NT AUTHORITY\\SYSTEM", "", "DC_AD_srv"), "service:system@DC_AD_srv",
     "Windows built-ins are services, not people"),
    (("VGSOC-LAP06$", "", "utkarsh_Pc"), "service:vgsoc-lap06$@utkarsh_Pc",
     "a trailing $ is a machine account"),
    (("", "10.200.11.76", ""), "endpoint:10.200.11.76",
     "userless internal traffic is a machine"),
    (("", "", "Nidhi"), "endpoint:Nidhi", "host fallback"),
    (("", "8.8.8.8", "fw"), "external:8.8.8.8", "userless external traffic"),
    (("", "", ""), "unknown", "nothing identifiable"),
    (("admin", "", "LAPTOP-07"), "shared:admin@LAPTOP-07",
     "shared accounts keep a host scope instead of merging estate-wide"),
]


def selftest(cfg):
    """Assert the classification rules. No sample file needed."""
    block = dict((cfg or {}).get("identity_resolution", {}) or {})
    block["typed_keys"] = True
    block.setdefault("shared_accounts",
                     ["administrator", "admin", "root", "system", "guest",
                      "user"])
    pp.apply_identity_config({"identity_resolution": block})

    fails = 0
    print("_is_public_ip")
    for addr, want in _SELFTEST_IP:
        got = pp._is_public_ip(addr)
        if got != want:
            fails += 1
            print("  FAIL %r -> %s, expected %s" % (addr, got, want))
    print("  %d case(s), %d failure(s)" % (len(_SELFTEST_IP), fails))

    efails = 0
    print("\n_typed_entity")
    for args, want, why in _SELFTEST_ENTITY:
        got = pp._typed_entity(*args)
        if got != want:
            efails += 1
            print("  FAIL %s\n    got      %s\n    expected %s\n    rule: %s"
                  % (args, got, want, why))
    print("  %d case(s), %d failure(s)" % (len(_SELFTEST_ENTITY), efails))

    total = fails + efails
    print("\n%s" % ("PASS" if not total else "FAIL — %d case(s)" % total))
    return 0 if not total else 1


def bindings_report(cfg, sample, limit):
    """Backfill an in-memory binding table from the sample and report what it
    could attribute. Writes nothing to disk."""
    import tempfile
    import ueba_identity as ui

    block = dict((cfg or {}).get("identity_resolution", {}) or {})
    block["typed_keys"] = True
    block.setdefault("shared_accounts",
                     ["administrator", "admin", "root", "system", "guest", "user"])
    pp.apply_identity_config({"identity_resolution": block})

    bcfg = block.get("bindings", {}) or {}
    db = Path(tempfile.mkdtemp()) / "bindings_preview.db"
    b = ui.IdentityBindings(str(db),
                            retention_days=bcfg.get("retention_days", 90))

    endpoints = Counter()
    latest = None
    n = 0
    with open(sample, encoding="utf-8", errors="replace") as f:
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
            n += 1
            key = pp.resolve_entity(rec)
            b.record_event(key, rec, pp.get_nested)
            if key.startswith("endpoint:"):
                endpoints[key.split(":", 1)[1]] += 1
            t = ui.event_time(rec, pp.get_nested)
            if t and (latest is None or t > latest):
                latest = t
    b.commit()

    st = b.stats()
    print("records read: %d" % n)
    print("latest event in sample: %s" % (latest.isoformat() if latest else "unknown"))
    print("\nBINDINGS BUILT (auth-derived, person: entities only)")
    print("  rows                 : %d" % st["rows"])
    print("  people bound         : %d" % st["people"])
    print("  distinct host/addr   : %d" % st["values"])
    print("  observations         : %d" % st["observations"])
    print("  values used by >1 person: %d   <- no confident attribution from these"
          % st["ambiguous_values"])

    print("\nATTRIBUTION COVERAGE — could we name a person for each endpoint:?")
    if not endpoints:
        print("  no endpoint: entities in this sample")
    for value, hits in endpoints.most_common(15):
        kind = ui.KIND_IP if value.replace(".", "").isdigit() else ui.KIND_HOST
        cands = b.owner_of(kind, value, at=latest)
        if not cands:
            print("  %-26s %5d events  -> no binding" % (value[:26], hits))
        else:
            top = cands[0]
            print("  %-26s %5d events  -> %s  conf %.2f%s"
                  % (value[:26], hits, top["person"], top["confidence"],
                     ("  (%d candidates)" % len(cands)) if len(cands) > 1 else ""))

    named = sum(h for v, h in endpoints.items()
                if b.owner_of(ui.KIND_IP if v.replace(".", "").isdigit()
                              else ui.KIND_HOST, v, at=latest))
    tot = sum(endpoints.values())
    print("\n  %d of %d endpoint: records (%.0f%%) could be attributed to a person."
          % (named, tot, 100.0 * named / max(tot, 1)))

    print("\nPEOPLE AND WHERE THEY WERE SEEN")
    for person in sorted({r[0] for r in b.conn.execute(
            "SELECT DISTINCT person FROM identity_bindings")})[:20]:
        obs = b.bindings_for(person)
        print("  %-26s %s" % (person[:26],
                              ", ".join("%s:%s(%d)" % (o["kind"], o["value"],
                                                       o["observations"])
                                        for o in obs[:4])))
    b.close()
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--input", default="ueba_alerts.jsonl")
    ap.add_argument("--models", default="models/autoencoders")
    ap.add_argument("--limit", type=int, default=0, help="0 = whole file")
    ap.add_argument("--selftest", action="store_true",
                    help="assert the classification rules and exit")
    ap.add_argument("--bindings", action="store_true",
                    help="preview the Phase D identity bindings from the sample")
    args = ap.parse_args()

    if args.bindings:
        if not Path(args.input).exists():
            sys.exit("no such sample: %s" % args.input)
        cfg = pp.load_config(args.config) if Path(args.config).exists() else {}
        sys.exit(bindings_report(cfg, args.input, args.limit))

    if args.selftest:
        cfg = (pp.load_config(args.config)
               if Path(args.config).exists() else {})
        sys.exit(selftest(cfg))

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
    # ── Phase B: what typed classification would produce ────────────────────
    typed = _keys(args.input, cfg, True, args.limit, typed=True)
    if len(typed) == len(before):
        bykind = defaultdict(set)
        recs_by_kind = defaultdict(int)
        for k in typed:
            kind = k.split(":", 1)[0] if ":" in k else "unknown"
            bykind[kind].add(k)
            recs_by_kind[kind] += 1

        print("\nTYPED KEYS (typed_keys: true) — entities, and records behind them")
        print("  %-10s %10s %10s" % ("type", "entities", "records"))
        for kind in ("person", "endpoint", "service", "shared", "external",
                     "unknown"):
            if bykind[kind] or recs_by_kind[kind]:
                print("  %-10s %10d %10d"
                      % (kind, len(bykind[kind]), recs_by_kind[kind]))
        print("  %-10s %10d %10d"
              % ("TOTAL", len(set(typed)), len(typed)))

        print("\n  flat scheme today: %d entities. typed: %d."
              % (len(set(before)), len(set(typed))))
        print("  Of the %d accounts in the flat scheme, typed classification "
              "keeps %d as people." % (len(kb["account"]), len(bykind["person"])))

        # The headline: attack traffic no longer lands on a legitimate entity.
        acct_ext = sum(1 for b, t in zip(before, typed)
                       if t.startswith("external:")
                       and not b.startswith(("ip:", "host:")))
        if acct_ext:
            print("\n  %d records presented an account name from a public IP and "
                  "are now\n  external: rather than that account's baseline. "
                  "Those are the\n  brute-force guesses." % acct_ext)

        print("\n  people kept (%d):" % len(bykind["person"]))
        ppl = sorted(bykind["person"])
        for i in range(0, min(len(ppl), 40), 4):
            print("    " + "  ".join("%-22s" % x[:22] for x in ppl[i:i + 4]))
        if len(ppl) > 40:
            print("    ... and %d more" % (len(ppl) - 40))

        for kind in ("shared", "service"):
            if bykind[kind]:
                print("\n  %s (%d):" % (kind, len(bykind[kind])))
                for k in sorted(bykind[kind])[:12]:
                    print("    %s" % k)

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
