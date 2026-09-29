#!/usr/bin/env bash
# CyberSentinel UEBA — engine liveness watchdog (heartbeat-based).
#
# Catches the "silent stall": the engine process stays alive (so systemd
# Restart= never fires) but its feed-processing loop wedges, freezing output
# while fresh logs keep arriving. That is the 2026-08-01 ~6h incident.
#
# LIVENESS SIGNAL — the engine's Stats heartbeat, NOT alert recency.
# The engine emits a "Stats | processed: N ..." line every ~60s WHENEVER it is
# looping, independent of whether any alert fired. So:
#   * healthy but quiet (few/no alerts)  -> heartbeat keeps advancing  -> OK
#   * genuinely stalled (loop wedged)    -> heartbeat goes stale       -> RESTART
# A previous version keyed off newest_alert_time (<300s) and thus false-restarted
# a healthy engine during every quiet alert period. Do NOT reintroduce that.
#
# Confirmed real stall requires ALL of:
#   1. engine process is active (else systemd is already handling it — but we
#      still restart to be safe if it's not active),
#   2. the FEED is fresh (enriched.jsonl mtime < FEED_FRESH_SECS) — there IS work,
#   3. the Stats heartbeat is stale (last "Stats |" log line > STALE_SECS old),
#   4. the processed counter has NOT advanced since the previous probe.
#
# Flap protection: <=1 restart / MIN_RESTART_GAP. Forensic snapshot before acting.

set -euo pipefail

BASE="/root/NEW_DRIVE/aditya_ueba"
ENGINE_LOG="$BASE/logs/ueba_engine.stdout.log"
FEED_FILE="$BASE/enriched.jsonl"
FORENSIC_DIR="$BASE/logs/watchdog"
STAMP_RESTART="/run/ueba-engine-watchdog.last-restart"
STATE="/run/ueba-engine-watchdog.state"     # remembers last processed count
WD_LOG="$FORENSIC_DIR/watchdog.log"

STALE_SECS=240          # >4 missed 60s heartbeats = stalled
FEED_FRESH_SECS=300     # feed considered "arriving" if mtime younger than this
MIN_RESTART_GAP=900     # never auto-restart more than once / 15 min
CONFIRM_SECS=240        # re-check this long after forensics before restarting

mkdir -p "$FORENSIC_DIR"
now="$(date +%s)"
log() { echo "$(date -Is) $*" >>"$WD_LOG"; }

# --- 0. process must exist; if systemd says it's dead, restart outright ---
if ! systemctl is-active --quiet ueba-engine; then
  log "engine not active -> restart"
  echo "$now" >"$STAMP_RESTART"
  systemctl restart ueba-engine
  exit 0
fi

# --- 1. is there work? (feed fresh) ---
if [ ! -f "$FEED_FILE" ]; then log "SKIP: feed file missing"; exit 0; fi
feed_age=$(( now - $(stat -c %Y "$FEED_FILE") ))
if [ "$feed_age" -ge "$FEED_FRESH_SECS" ]; then
  # No fresh feed → engine may be legitimately idle. Not a stall.
  exit 0
fi

# --- 2. heartbeat: age of the last "Stats |" line + its processed count ---
last_stats="$(grep -a 'Stats |' "$ENGINE_LOG" 2>/dev/null | tail -1 || true)"
if [ -z "$last_stats" ]; then
  log "SKIP: no Stats heartbeat line found in engine log yet"
  exit 0
fi
# Timestamp is the leading "YYYY-MM-DD HH:MM:SS" (box-local time).
hb_ts="$(printf '%s' "$last_stats" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' || true)"
hb_epoch="$(date -d "$hb_ts" +%s 2>/dev/null || echo 0)"
hb_age=$(( now - hb_epoch ))
processed="$(printf '%s' "$last_stats" | grep -oE 'processed: [0-9]+' | grep -oE '[0-9]+' || echo -1)"

# --- 3. compare processed counter vs previous probe ---
prev_processed=-1
[ -f "$STATE" ] && prev_processed="$(cat "$STATE" 2>/dev/null || echo -1)"
echo "$processed" >"$STATE"

# Healthy: heartbeat is recent. (Advancing processed OR fresh Stats line both ok.)
if [ "$hb_age" -lt "$STALE_SECS" ]; then
  exit 0
fi

# Heartbeat stale AND processed has not moved since last probe -> real stall.
# (If processed advanced despite an old Stats line, treat as alive: log rotation edge.)
if [ "$processed" != "$prev_processed" ] || [ "$prev_processed" = "-1" ]; then
  log "WATCH: heartbeat ${hb_age}s old but processed moved ($prev_processed->$processed); not restarting yet"
  exit 0
fi

# --- flap protection ---
if [ -f "$STAMP_RESTART" ]; then
  gap=$(( now - $(cat "$STAMP_RESTART" 2>/dev/null || echo 0) ))
  if [ "$gap" -lt "$MIN_RESTART_GAP" ]; then
    log "SUPPRESS restart (heartbeat ${hb_age}s, processed frozen @${processed}): only ${gap}s since last (<${MIN_RESTART_GAP}s)"
    exit 0
  fi
fi

# --- forensics then restart ---
snap="$FORENSIC_DIR/stall_$(date +%Y%m%d_%H%M%S).log"
{
  echo "=== UEBA engine watchdog auto-restart ==="
  echo "when:      $(date -Is)"
  echo "reason:    heartbeat ${hb_age}s old (>${STALE_SECS}s), processed frozen at ${processed}, feed_age ${feed_age}s"
  echo "last stats: $last_stats"
  echo "=== last 200 lines of engine log ==="
  tail -n 200 "$ENGINE_LOG" 2>/dev/null || echo "(engine log unreadable)"

  # ── process state, captured BEFORE the restart destroys it ────────────────
  # 36 stalls were captured with the log alone and none yielded a cause. What
  # was missing was the state of the wedged process itself.
  EPID="$(systemctl show ueba-engine -p MainPID --value 2>/dev/null)"
  echo
  echo "=== process state (pid ${EPID:-unknown}) ==="
  if [ -n "$EPID" ] && [ "$EPID" != "0" ] && [ -d "/proc/$EPID" ]; then
    grep -E "^(VmRSS|VmSize|VmSwap|Threads|FDSize):" "/proc/$EPID/status" 2>/dev/null
    echo "open fds : $(ls /proc/$EPID/fd 2>/dev/null | wc -l)"
    echo "--- per-thread state (D = uninterruptible IO wait, R = running) ---"
    # Cap with a counter, NOT `| head -40`. Under `set -euo pipefail` (line 25)
    # head closes the pipe after 40 of the engine's 120 threads, the loop dies of
    # SIGPIPE, the pipeline reports 141, and set -e then aborts this whole script
    # — before the SIGUSR1 stack dump below, before the RESTART log line, and
    # before the `systemctl restart` at the very end. That is why 57 stall
    # snapshots were captured containing no stacks at all, and why the restart
    # silently stopped happening.
    _n=0
    for t in /proc/$EPID/task/*; do
      [ -d "$t" ] || continue
      _n=$((_n+1))
      if [ "$_n" -gt 40 ]; then echo "  ... ($(ls /proc/$EPID/task 2>/dev/null | wc -l) threads total)"; break; fi
      printf "  tid=%s %-18s %s\n" "$(basename "$t")" \
        "$(cat "$t/comm" 2>/dev/null)" "$(awk '{print $3}' "$t/stat" 2>/dev/null)" || true
    done 2>/dev/null

    # Ask the engine what every thread is executing. Armed by
    # install_stack_dumper() in ueba_engine.py; harmless if absent.
    echo
    echo "=== thread stacks (SIGUSR1) ==="
    STACKS="$BASE/logs/engine_stacks.log"
    before=$(wc -c <"$STACKS" 2>/dev/null || echo 0)
    kill -USR1 "$EPID" 2>/dev/null && sleep 3
    after=$(wc -c <"$STACKS" 2>/dev/null || echo 0)
    if [ "$after" -gt "$before" ]; then
      tail -c "$((after - before))" "$STACKS"
    else
      echo "(no stack dump — engine may predate the SIGUSR1 handler)"
    fi
  else
    echo "(engine pid unavailable)"
  fi

  echo
  echo "=== system ==="
  free -g 2>/dev/null | head -3
  uptime
  echo "--- top by RSS ---"
  ps -eo rss,pcpu,user,comm --sort=-rss 2>/dev/null | head -6
} >"$snap" 2>&1 || true
# `|| true` is deliberate. Collecting diagnostics is best-effort; the restart is
# not. Without it any failure inside that block takes the script down with it and
# the wedged engine is simply left wedged — which is exactly what happened.

# --- confirmation window: did it recover while we collected forensics? ---
# These stalls are transient. One on 2026-09-29 froze for ~420s with the main
# thread on-CPU (not blocked on IO or a lock) and then resumed by itself, with no
# restart at all. STALE_SECS is 240, so the watchdog fires well inside that
# window: restarting there kills a process that was about to recover and throws
# away a warm 100-model autoencoder cache for nothing.
#
# Forensics are already on disk above, so the diagnosis is not lost either way.
# Only an engine that is STILL frozen after the confirmation window is restarted.
sleep "$CONFIRM_SECS"
now2="$(date +%s)"
last2="$(grep -a 'Stats |' "$ENGINE_LOG" 2>/dev/null | tail -1 || true)"
proc2="$(printf '%s' "$last2" | grep -oE 'processed: [0-9]+' | grep -oE '[0-9]+' || echo -1)"
hb2_ts="$(printf '%s' "$last2" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' || true)"
hb2_epoch="$(date -d "$hb2_ts" +%s 2>/dev/null || echo 0)"
hb2_age=$(( now2 - hb2_epoch ))

if [ "$proc2" != "$processed" ] || [ "$hb2_age" -lt "$STALE_SECS" ]; then
  log "RECOVERED unaided after ~${hb_age}s (processed ${processed}->${proc2}, heartbeat now ${hb2_age}s) — NOT restarting. Snapshot: $snap"
  echo "$proc2" >"$STATE"
  exit 0
fi

echo "$now" >"$STAMP_RESTART"
log "RESTART (heartbeat ${hb2_age}s old, processed still frozen @${processed} after ${CONFIRM_SECS}s confirmation) — snapshot: $snap"
systemctl restart ueba-engine
log "restart issued; new active-state: $(systemctl is-active ueba-engine)"
