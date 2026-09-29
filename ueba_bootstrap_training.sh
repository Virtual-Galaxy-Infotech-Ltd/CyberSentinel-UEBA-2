#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  CyberSentinel UEBA — Baseline Bootstrap
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Models CANNOT be shipped with the product. Every autoencoder is keyed to a
#  specific username, the scaler and thresholds are fitted to one estate's score
#  distribution, and "normal" at one bank is not normal at another. A fresh
#  install therefore has no models, and the engine refuses to start until it has
#  at least a global autoencoder plus thresholds.json.
#
#  This script answers the only two questions that matter on a new site:
#     1. Has enough of the customer's own traffic been collected yet?
#     2. If so, build the baseline.
#
#  Run it as often as you like — it only reports until you pass --train.
#
#     ./ueba_bootstrap_training.sh            # readiness report only
#     ./ueba_bootstrap_training.sh --train    # report, then build the baseline
#
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_SITE_ENV="${UEBA_SITE_ENV:-$SELF_DIR/ueba_site.env}"
# shellcheck source=/dev/null
[[ -r "$_SITE_ENV" ]] && . "$_SITE_ENV"

BASE="${UEBA_BASE:-$SELF_DIR}"
CONFIG="$BASE/ueba_config.yaml"
PY="${UEBA_VENV_PY:-$BASE/venv/bin/python3}"
DO_TRAIN=0
[[ "${1:-}" == "--train" ]] && DO_TRAIN=1

if [[ -t 1 ]]; then
  B=$'\e[1m'; DIM=$'\e[2m'; R=$'\e[0m'
  GRN=$'\e[38;5;114m'; YEL=$'\e[38;5;221m'; RED=$'\e[38;5;203m'; CYA=$'\e[38;5;80m'
else B=""; DIM=""; R=""; GRN=""; YEL=""; RED=""; CYA=""; fi

say() { printf '  %b\n' "$*"; }
hdr() { printf '\n  %b%s%b\n  %b────────────────────────────────────────────────%b\n' \
                "$B$CYA" "$1" "$R" "$DIM" "$R"; }

[[ -x "$PY" ]] || { say "${RED}No interpreter at $PY${R} — is UEBA installed here?"; exit 1; }
[[ -r "$CONFIG" ]] || { say "${RED}No config at $CONFIG${R}"; exit 1; }

printf '\n  %bCyberSentinel UEBA — baseline readiness%b\n' "$B" "$R"
say "${DIM}$BASE${R}"

hdr "Collected so far"
"$PY" - "$CONFIG" "$BASE" <<'PYEOF'
import os, sys, glob, sqlite3
cfg_path, base = sys.argv[1], sys.argv[2]
try:
    import yaml
    cfg = yaml.safe_load(open(cfg_path)) or {}
except Exception:
    cfg = {}

def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:,.1f} {u}"
        n /= 1024

enr = os.path.join(base, "enriched.jsonl")
sz = os.path.getsize(enr) if os.path.exists(enr) else 0
print(f"    live enriched feed      {human(sz)}")

zips = sorted(glob.glob(os.path.join(base, "training_zips", "*.json.gz")))
print(f"    training snapshots      {len(zips)}")
if zips:
    print(f"      oldest                {os.path.basename(zips[0])}")
    print(f"      newest                {os.path.basename(zips[-1])}")

# The profile store is what the trainer uses to decide who gets their own model.
prof = (cfg.get("paths") or {}).get("profile_db") or os.path.join(base, "profiles/user_profiles.db")
if not os.path.isabs(prof):
    prof = os.path.join(base, prof)
min_ev = ((cfg.get("preprocessing") or {}).get("min_events_per_user")) or 2000

if os.path.exists(prof):
    try:
        c = sqlite3.connect(f"file:{prof}?mode=ro", uri=True)
        tbl = [r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        t = "users" if "users" in tbl else (tbl[0] if tbl else None)
        if t:
            total = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            cols = [d[1] for d in c.execute(f"PRAGMA table_info({t})")]
            # Real schema uses `total_events`; keep a loose fallback in case the
            # profile store shape changes.
            ec = ("total_events" if "total_events" in cols
                  else next((x for x in cols if "event" in x.lower()), None))
            print(f"    entities profiled       {total:,}")
            if ec:
                n = c.execute(
                    f"SELECT COUNT(*) FROM {t} WHERE {ec} >= ?", (min_ev,)).fetchone()[0]
                print(f"    with >= {min_ev:,} events     {n:,}   "
                      f"({'enough for per-user models' if n else 'none yet'})")
                sys.exit(0 if n else 10)
            sys.exit(0 if total else 10)
    except Exception as e:
        print(f"    profile store unreadable: {e}")
        sys.exit(10)
else:
    print("    entities profiled       0   (profile store not built yet)")
    sys.exit(10)
PYEOF
READY=$?

hdr "Existing models"
AE_DIR="$BASE/models/autoencoders"
if [[ -f "$AE_DIR/global.pt" ]]; then
  say "    ${GRN}global autoencoder present${R}   ($(ls -1 "$AE_DIR"/*.pt 2>/dev/null | wc -l) models total)"
  HAVE_MODELS=1
else
  say "    ${YEL}no global autoencoder${R} — the engine cannot start yet"
  HAVE_MODELS=0
fi
[[ -f "$BASE/models/thresholds.json" ]]      && say "    ${GRN}thresholds.json present${R}"      || say "    ${YEL}thresholds.json missing${R}"
[[ -f "$BASE/models/isolation_forest.pkl" ]] && say "    ${GRN}isolation_forest.pkl present${R}" || say "    ${YEL}isolation_forest.pkl missing${R}"

hdr "Verdict"
if (( READY == 0 )); then
  say "    ${GRN}Enough of this customer's traffic has been collected.${R}"
  say "    ${DIM}Per-user models will be built for entities above the threshold;${R}"
  say "    ${DIM}everyone else is scored by the global model.${R}"
else
  say "    ${YEL}Not enough data yet.${R}"
  say "    ${DIM}UEBA learns what normal looks like for THIS estate, so it needs${R}"
  say "    ${DIM}a few days of the customer's own logs before a baseline means${R}"
  say "    ${DIM}anything. Typically 3-7 days. Leave the sync bridge running and${R}"
  say "    ${DIM}re-run this check.${R}"
  printf '\n'
  say "    Bridge status:  ${DIM}systemctl status ueba-bridge${R}"
fi

if (( DO_TRAIN )); then
  if (( READY != 0 )); then
    printf '\n'
    say "    ${RED}Refusing to train — there is not enough data to learn from.${R}"
    say "    ${DIM}Training on a near-empty estate produces a baseline that flags${R}"
    say "    ${DIM}everything as anomalous, which is worse than no UEBA at all.${R}"
    exit 1
  fi
  hdr "Building the baseline"
  say "    ${DIM}This is disk-I/O heavy and can take hours. Safe to re-run.${R}"
  printf '\n'
  say "    [1/2] preparing features + entity profiles"
  if ! "$PY" "$BASE/ueba_prepare_training_data.py"; then
    say "    ${RED}feature preparation failed${R}"; exit 1
  fi
  say "    [2/2] training models"
  if ! "$PY" "$BASE/ueba_trainer.py" --config "$CONFIG"; then
    say "    ${RED}training failed${R}"; exit 1
  fi
  printf '\n'
  say "    ${GRN}Baseline built.${R} Start the engine:"
  say "    ${DIM}systemctl enable --now ueba-engine${R}"
fi
printf '\n'
