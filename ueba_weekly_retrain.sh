#!/bin/bash
# ueba_weekly_retrain.sh — weekly model retraining for the UEBA pipeline.
#
# Runs from cron every Sunday at 03:30 IST. Each run:
#   1. Pulls new enriched_*.jsonl.gz chunks from 23 (since last successful
#      pull, OR last 7 days on the very first run).
#   2. Bundles them into one dated snapshot in training_zips/ — named so
#      retrain.py picks it up as a "new" training file.
#   3. Stops the engine.
#   4. Runs retrain.py (which backs up models, prepares features, retrains
#      Isolation Forest + global AE + per-user AEs + FAISS).
#   5. Restarts the engine.
#   6. Prunes weekly snapshots older than SNAPSHOT_RETENTION_DAYS.
#
# Engine downtime per run: 30–90 min (depends on features.h5 size).
# If retrain.py crashes, the engine is restarted with the previous models
# (retrain.py's own backup-then-rebuild flow ensures models/ is never half-empty).
#
# Manual invocation is safe — running mid-week pulls any new chunks since
# the last run and rebuilds normally. State tracked in .state/last_train_pull.

set -euo pipefail

# Site settings come from ueba_site.env (written by install_ueba.sh), so this
# script is identical at every customer. Fallbacks keep the original lab install
# working unchanged — box 98 has no site file.
_SITE_ENV="${UEBA_SITE_ENV:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ueba_site.env}"
# shellcheck source=/dev/null
[[ -r "$_SITE_ENV" ]] && . "$_SITE_ENV"

BASE="${UEBA_BASE:-/root/NEW_DRIVE/aditya_ueba}"
TRAINING_DIR=$BASE/training_zips
STATE_DIR=$BASE/.state
LAST_PULL_STATE=$STATE_DIR/last_train_pull
LOG=$BASE/logs/weekly_retrain.log
VENV_PY="${UEBA_VENV_PY:-$BASE/venv/bin/python3}"

# SIEM SSH config (same key and target as the sync bridge)
SOC_HOST="${SOC_HOST:-vgipl@localhost}"
SOC_PORT="${SOC_PORT:-2222}"
SOC_SSH_KEY="${SOC_SSH_KEY:-/root/.ssh/id_ueba}"
SOC_ENRICHED_DIR="${SOC_ENRICHED_DIR:-/home/vgipl/CyberSentinel-Event-Correlation-Kafka/data/enriched}"
SSH_OPTS="-p ${SOC_PORT} -i ${SOC_SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=3"

SNAPSHOT_RETENTION_DAYS=${SNAPSHOT_RETENTION_DAYS:-90}
# Rolling window for combined_training.jsonl — retrain.py only ever APPENDS to
# it, so without trimming it grows unbounded (~11 GB/day here). Keep this aligned
# with profile_store.baseline_window_days so the AE/IF baseline and the
# behavioural baseline cover the same period — both are 21 as of 2026-09-16.
#
# Lowered 30 -> 21 on 2026-09-16. At 30 days the corpus settles around 330 GB on
# a 1.8 TB disk that other teams already fill to ~1.2 TB, which left UEBA with no
# headroom and stalled the whole pipeline for 3 days. 21 days settles it around
# 230 GB and still spans three full weekly cycles, which is what actually matters
# for behavioural baselining in a bank (weekday/weekend and payroll rhythms).
# Drop to 14 if disk pressure returns; below ~14 the weekly pattern gets thin.
TRAINING_RETENTION_DAYS=${TRAINING_RETENTION_DAYS:-21}
# Derived from BASE like every other path in this script, and overridable.
#
# It used to be hardcoded to /data/ueba_training/, which is a path from the
# original host. On the co-located install there is no /data at all, and the
# directory was not in the mkdir below either, so the first scheduled run would
# have failed at the corpus step with the engine already stopped. Nothing had
# caught it because the job is weekly and had not yet been due.
#
# paths.training_data in ueba_config.yaml names the same file; keep the two
# aligned if either moves.
COMBINED="${UEBA_TRAINING_CORPUS:-$BASE/data/combined_training.jsonl}"
# Defined at top level, not inside step 0.5: the post-append prune at step
# 4.5 needs it too, and a variable set inside a skipped block is unset.
PRUNE_TOOL="$BASE/ueba_prune_corpus.py"
# The corpus lives here; the space check must measure THIS volume.
CORPUS_DIR="$(dirname "$COMBINED")"

# CORPUS_DIR included: retrain.py appends to the corpus and will not create
# its parent, and on a fresh install nothing else has.
mkdir -p "$TRAINING_DIR" "$STATE_DIR" "$(dirname "$LOG")" "$CORPUS_DIR"
exec >> "$LOG" 2>&1

echo "==================================================================="
echo "$(date '+%Y-%m-%d %H:%M:%S')  Weekly retrain start"

# ── 0.5 Prune combined_training.jsonl to a rolling window ───────────────────
# MOVED HERE 2026-09-21 (was step 5.5, after the retrain).
#
# This is the only step that FREES disk, and it used to run last — after the
# weekly snapshot (~4 GB) and features.h5 (~46 GB) had already been written.
# On a full disk those die first with ENOSPC, so the prune never ran and the
# disk stayed full: the job could not recover on its own. That deadlock took
# UEBA down on 2026-09-13 and again on 2026-09-20.
#
# Running it first makes the job self-healing — reclaim the window, then work.
# Pruning before retrain.py appends this week's events is correct: the window
# is defined by event age, not by when the append happened, and the original
# comment below already notes the prune is deliberately NOT gated on retrain
# success for the same reason.
# retrain.py APPENDS each week's new events to combined_training.jsonl and never
# trims it, so it grows unbounded. Keep only events newer than
# TRAINING_RETENTION_DAYS so features.h5 stays a rolling baseline and disk stays
# bounded. Runs AFTER the engine restart (zero added downtime). Fully defensive:
# streams to a temp file, refuses to produce an empty result, verifies the last
# line is complete JSON, and only THEN swaps — any failure leaves the original
# combined_training.jsonl untouched.
#
# NOT gated on RETRAIN_OK: combined_training.jsonl is an INPUT, and retrain.py
# appends this week's events to it BEFORE the validation gate runs. Gating the
# prune on a successful retrain meant a gate FAIL (2026-07-19) appended a week
# and never trimmed it — the file regrew 215G→260G. Whether the candidate model
# promoted has no bearing on which events belong in the rolling window.
if [ -f "$COMBINED" ]; then
  if [ -x "$PRUNE_TOOL" ] || [ -f "$PRUNE_TOOL" ]; then
    # In-place prune: fallocate(COLLAPSE_RANGE) drops the leading bytes with no
    # temp file and no copy. The previous implementation streamed the KEPT
    # portion to a temp file, so it needed as much free space as it retained
    # (~253 GB) — on this shared, routinely-full disk it had not run since
    # 2026-09-06, which is what let the corpus grow to 529 GB and take the
    # pipeline down twice. The tool carries its own safety gates and refuses
    # rather than guessing.
    echo "  Pruning combined_training.jsonl to a ${TRAINING_RETENTION_DAYS}d window (in place)..."
    if "$VENV_PY" "$PRUNE_TOOL" "$COMBINED" "$TRAINING_RETENTION_DAYS" --apply; then
      echo "  combined_training.jsonl now $(numfmt --to=iec "$(stat -c %s "$COMBINED")")"
    else
      echo "  WARNING: in-place prune declined or failed — corpus left untouched"
    fi
  else
    # Fallback: the original streaming prune. Only reachable if the tool was not
    # deployed alongside this script; needs free space >= the retained size.
    CUTOFF=$(date -d "${TRAINING_RETENTION_DAYS} days ago" +%Y-%m-%d)
    TMP="${COMBINED}.pruned.$$"
    echo "  ueba_prune_corpus.py missing — falling back to streaming prune (needs free space)"
    if "$VENV_PY" - "$COMBINED" "$TMP" "$CUTOFF" <<'PYPRUNE'
import sys
src, dst, cutoff = sys.argv[1], sys.argv[2], sys.argv[3]
KEY = b'"event_time":"'; KLEN = len(KEY); cut = cutoff.encode()
read = kept = 0
with open(src, "rb") as fi, open(dst, "wb") as fo:
    for line in fi:
        read += 1
        i = line.find(KEY)
        if i == -1:                       # no parseable ts -> keep defensively
            kept += 1; fo.write(line); continue
        if line[i + KLEN:i + KLEN + 10] >= cut:   # ISO8601 sorts lexically
            kept += 1; fo.write(line)
print(f"  PRUNE read={read} kept={kept} dropped={read - kept}")
sys.exit(0 if kept > 0 else 3)            # never leave an empty training file
PYPRUNE
    then
      if tail -1 "$TMP" | "$VENV_PY" -c "import sys,json; json.loads(sys.stdin.read())" >/dev/null 2>&1; then
        mv "$TMP" "$COMBINED"
        echo "  combined_training.jsonl pruned -> $(numfmt --to=iec "$(stat -c %s "$COMBINED")")"
      else
        echo "  WARNING: pruned temp failed JSON check — keeping original, removing temp"
        rm -f "$TMP"
      fi
    else
      echo "  WARNING: prune produced empty/failed output — keeping original, removing temp"
      rm -f "$TMP"
    fi
  fi
fi


# ── 1. Discover new chunks on 23 ────────────────────────────────────────
# Filenames are enriched_YYYY-MM-DD_HH-MM-SS.jsonl.gz, so lexicographic
# comparison == chronological. State file holds the last-pulled basename.
LAST_PULLED=$(cat "$LAST_PULL_STATE" 2>/dev/null || echo "")
if [ -n "$LAST_PULLED" ]; then
  echo "  Last pulled: $LAST_PULLED"
  REMOTE_FILES=$(ssh $SSH_OPTS $SOC_HOST \
    "ls $SOC_ENRICHED_DIR/enriched_*.jsonl.gz 2>/dev/null | sort" \
    | awk -F/ -v last="$LAST_PULLED" '$NF > last { print $NF }')
else
  echo "  First run: pulling last 7 days of .gz from 23"
  REMOTE_FILES=$(ssh $SSH_OPTS $SOC_HOST \
    "find $SOC_ENRICHED_DIR -maxdepth 1 -name 'enriched_*.jsonl.gz' -mtime -7 -printf '%f\n' | sort")
fi

if [ -z "$REMOTE_FILES" ]; then
  echo "  No new .gz on 23 — skipping retrain (engine left running)"
  exit 0
fi

CHUNK_COUNT=$(echo "$REMOTE_FILES" | wc -l)
NEWEST=$(echo "$REMOTE_FILES" | tail -1)
echo "  Found $CHUNK_COUNT new chunk(s); newest: $NEWEST"

# ── 2. Bundle into a single weekly snapshot ──────────────────────────────
WEEK_TS=$(date +%Y-%m-%d)
SNAPSHOT="enriched-weekly-${WEEK_TS}.json.gz"
SNAPSHOT_PATH="$TRAINING_DIR/$SNAPSHOT"

if [ -e "$SNAPSHOT_PATH" ]; then
  TS_SUFFIX=$(date +%H%M%S)
  SNAPSHOT="enriched-weekly-${WEEK_TS}_${TS_SUFFIX}.json.gz"
  SNAPSHOT_PATH="$TRAINING_DIR/$SNAPSHOT"
  echo "  Today's snapshot exists; using ${SNAPSHOT}"
fi

echo "  Building $SNAPSHOT (zcat $CHUNK_COUNT remote chunks → gzip)..."
REMOTE_PATHS=$(echo "$REMOTE_FILES" | awk -v dir="$SOC_ENRICHED_DIR" '{print dir"/"$0}' | tr '\n' ' ')
if ! ssh $SSH_OPTS $SOC_HOST "zcat $REMOTE_PATHS" | gzip > "$SNAPSHOT_PATH"; then
  echo "  ERROR: snapshot build failed — aborting (engine left running)"
  rm -f "$SNAPSHOT_PATH"
  exit 1
fi
echo "  Snapshot built: $(numfmt --to=iec "$(stat -c %s "$SNAPSHOT_PATH")")"

# State updated only after a successful snapshot, so a failed pull is replayed.
echo "$NEWEST" > "$LAST_PULL_STATE"

# ── 3. Stop engine ───────────────────────────────────────────────────────
# The engine runs under systemd (ueba-engine.service). Stop it THROUGH systemd so
# a clean stop does NOT trip Restart=always (which would respawn a unit-managed
# engine racing this script's restart on the same .state byte offset). Falls back
# to legacy pgrep-kill only where the unit isn't installed.
ENGINE_UNIT=ueba-engine
if systemctl cat "${ENGINE_UNIT}.service" >/dev/null 2>&1; then
  USE_SYSTEMD=1
else
  USE_SYSTEMD=0
fi

if [ "$USE_SYSTEMD" = 1 ]; then
  echo "  stopping engine via 'systemctl stop ${ENGINE_UNIT}'"
  systemctl stop "${ENGINE_UNIT}" || echo "  WARNING: systemctl stop returned non-zero"
else
  ENGINE_PID=$(pgrep -f "python3 ueba_engine\.py" | head -1 || true)
  if [ -n "$ENGINE_PID" ]; then
    echo "  Stopping engine PID=$ENGINE_PID"
    kill "$ENGINE_PID" 2>/dev/null || true
    for i in $(seq 1 30); do
      sleep 1
      kill -0 "$ENGINE_PID" 2>/dev/null || { echo "  engine exited after ${i}s"; break; }
    done
    if kill -0 "$ENGINE_PID" 2>/dev/null; then
      echo "  engine didn't exit in 30s — SIGKILL"
      kill -9 "$ENGINE_PID" || true
      sleep 1
    fi
  else
    echo "  No engine running"
  fi
fi

# ── 4. Run retrain.py ────────────────────────────────────────────────────
# Pre-flight space check. retrain.py appends this week's events to a 200+ GB
# corpus and then writes a ~50 GB features.h5, so starting it on a nearly-full
# volume is how the 13 and 20 Sep runs died — both with "No space left on
# device", after hours of work. Fail fast and loudly instead.
FREE_GB=$(df -BG --output=avail "$CORPUS_DIR" 2>/dev/null | tail -1 | tr -dc '0-9')
MIN_FREE_GB=${MIN_FREE_GB:-120}
echo "  Free space on $CORPUS_DIR: ${FREE_GB}G (minimum ${MIN_FREE_GB}G)"
if [ -n "$FREE_GB" ] && [ "$FREE_GB" -lt "$MIN_FREE_GB" ]; then
  echo "  ABORTING: only ${FREE_GB}G free, need ${MIN_FREE_GB}G."
  echo "  The corpus prune at step 0.5 has already run; if that was not enough,"
  echo "  free space manually or lower TRAINING_RETENTION_DAYS before retrying."
  echo "  Live models are untouched. Restarting the engine."
  RETRAIN_OK=0
else
  echo "  Running retrain.py..."
  cd "$BASE"
  RETRAIN_OK=1
  if ! "$VENV_PY" retrain.py; then
    echo "  retrain.py FAILED — restarting engine with previous models"
    RETRAIN_OK=0
  fi
fi

# ── 4.5 Prune AGAIN, now that this week's events have been appended ────────
# The step 0.5 prune runs before the append and therefore cannot remove what
# has not arrived yet. That matters because the weekly snapshot is built from
# whatever chunks the bridge has managed to transfer — on 27 Sep that was 715
# chunks of accumulated backlog, carrying events far older than the retention
# window. The pre-prune freed 27 GB; the append then added 70 GB, 194 GB of
# which was out-of-window data that nothing reclaimed. The volume crossed the
# feed bridge's backpressure floor and ingestion stopped for 19 hours.
#
# NOT gated on RETRAIN_OK: the append happens inside retrain.py before training,
# so the corpus grows even when training later fails — which is exactly when
# reclaiming the space matters most.
if [ -f "$COMBINED" ]; then
  echo "  Post-append prune to a ${TRAINING_RETENTION_DAYS}d window..."
  if [ -f "$PRUNE_TOOL" ]; then
    "$VENV_PY" "$PRUNE_TOOL" "$COMBINED" "$TRAINING_RETENTION_DAYS" --apply \
      || echo "  post-append prune reported a problem — corpus left as-is"
  else
    echo "  prune tool missing at $PRUNE_TOOL — skipping"
  fi
  echo "  Free space after prune: $(df -h "$CORPUS_DIR" | tail -1 | awk '{print $4}')"
fi

# ── 5. Restart engine ────────────────────────────────────────────────────
cd "$BASE"
if [ "$USE_SYSTEMD" = 1 ]; then
  echo "  starting engine via 'systemctl start ${ENGINE_UNIT}'"
  systemctl start "${ENGINE_UNIT}"
  NEW_PID=$(systemctl show -p MainPID --value "${ENGINE_UNIT}" 2>/dev/null || echo "?")
  echo "  Engine restart launched (systemd MainPID: $NEW_PID, takes ~35s to be fully ready)"
else
  setsid "$VENV_PY" ueba_engine.py >> engine.log 2>&1 < /dev/null &
  NEW_PID=$!
  echo "  Engine restart launched (new PID: $NEW_PID, takes ~35s to be fully ready)"
fi

# ── 6. Prune snapshots older than N days ─────────────────────────────────
DELETED=$(find "$TRAINING_DIR" -maxdepth 1 -name 'enriched-weekly-*.json.gz' \
            -mtime "+${SNAPSHOT_RETENTION_DAYS}" -print -delete 2>/dev/null || true)
if [ -n "$DELETED" ]; then
  DCOUNT=$(echo "$DELETED" | wc -l)
  echo "  Pruned $DCOUNT old weekly snapshot(s) >${SNAPSHOT_RETENTION_DAYS}d"
fi

if [ "$RETRAIN_OK" = "1" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S')  Weekly retrain done"
else
  echo "$(date '+%Y-%m-%d %H:%M:%S')  Weekly retrain FAILED — engine restored with old models"
  exit 1
fi
