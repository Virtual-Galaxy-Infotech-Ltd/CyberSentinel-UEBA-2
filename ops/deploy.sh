#!/usr/bin/env bash
#
# deploy.sh — snapshot, apply, health-check, and roll back automatically.
#
# WHY THIS EXISTS
# ───────────────
# Every deploy this project has done was a manual `install` followed by a
# `systemctl restart` and a hope. That cost us twice in one day on 18-Nov-2026:
# a console left restart-looping behind a 502, and a MemoryHigh value that
# throttled the service into a 22%-stalled crawl. Both were recoverable in
# seconds — if anyone had noticed, and if a snapshot had survived.
#
# Neither was guaranteed. The existing rollback_deploy.sh restores a FIXED list
# of files captured on 09-Nov, and the `git clean` that caused the outage also
# deleted .deploy-rollback/, destroying every snapshot on the box including the
# ones taken minutes earlier that same day.
#
# So: snapshots go OUTSIDE the install tree, the health check runs on every
# deploy rather than when someone remembers, and a failed check restores the
# previous version by itself instead of waiting to be asked.
#
# USAGE
#   ops/deploy.sh --from /tmp/staging ueba_engine.py ueba_peers.py
#   ops/deploy.sh --from /tmp/staging --no-restart docs/FOO.md
#   ops/deploy.sh --check-only          # just run the health check
#
#   BASE=/opt/ueba  SNAP_ROOT=/var/backups/ueba   (both overridable)
#
set -uo pipefail

BASE="${UEBA_BASE:-/opt/ueba}"
# Outside the install tree ON PURPOSE. A snapshot stored inside the thing it
# protects is not a snapshot; see the 18-Nov git clean.
SNAP_ROOT="${UEBA_SNAP_ROOT:-/var/backups/ueba}"
CONSOLE_URL="${UEBA_CONSOLE_URL:-https://127.0.0.1:3026/api/health}"
HEALTH_TRIES="${UEBA_HEALTH_TRIES:-10}"
HEALTH_SLEEP="${UEBA_HEALTH_SLEEP:-4}"

FROM=""
DO_RESTART=1
CHECK_ONLY=0
FILES=()

while (( $# )); do
  case "$1" in
    --from)       FROM="${2:-}"; shift 2 ;;
    --no-restart) DO_RESTART=0; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    -h|--help)    sed -n '2,30p' "$0"; exit 0 ;;
    *)            FILES+=("$1"); shift ;;
  esac
done

say()  { printf '  %s\n' "$*"; }
fail() { printf '  FAIL: %s\n' "$*" >&2; }

# ── which services does a given file affect? ───────────────────────────────
#
# Named explicitly rather than "restart everything". Restarting the engine
# costs an ingestion pause; restarting the console drops in-flight requests.
# Neither should happen because a doc changed.
services_for() {
  local f="$1"
  case "$f" in
    ueba_dashboard_server*|ueba_dashboard_server_html*|dashboard/*) echo "ueba-dashboard" ;;
    ueba_engine*|ueba_models/*|ueba_source*)                        echo "ueba-engine" ;;
    *.md|docs/*|tests/*|tools/*)                                    echo "" ;;
    # Shared modules are read by both, so both must pick them up.
    ueba_*.py)                                                      echo "ueba-engine ueba-dashboard" ;;
    *)                                                              echo "" ;;
  esac
}

health() {
  local ok=1
  for svc in ueba-engine ueba-dashboard; do
    local st; st="$(systemctl is-active "$svc" 2>/dev/null)"
    if [[ "$st" != "active" ]]; then fail "$svc is $st"; ok=0; else say "$svc active"; fi
  done
  # The console is the thing a user notices, so it is checked over HTTP rather
  # than by asking systemd whether the process exists. A process can be up and
  # serving 502s — that is exactly what happened on 18-Nov.
  local code=""
  for (( i=0; i<HEALTH_TRIES; i++ )); do
    code="$(curl -sk -m 20 -o /dev/null -w '%{http_code}' "$CONSOLE_URL" 2>/dev/null)"
    [[ "$code" == "200" ]] && break
    sleep "$HEALTH_SLEEP"
  done
  if [[ "$code" == "200" ]]; then say "console HTTP 200"; else fail "console HTTP ${code:-no answer}"; ok=0; fi
  return $(( ok == 1 ? 0 : 1 ))
}

if (( CHECK_ONLY )); then
  echo "HEALTH"
  health && { echo; say "healthy"; exit 0; } || { echo; fail "unhealthy"; exit 1; }
fi

(( ${#FILES[@]} )) || { fail "nothing to deploy (give one or more paths, or --check-only)"; exit 2; }
[[ -n "$FROM" && -d "$FROM" ]] || { fail "--from DIR is required and must exist"; exit 2; }

for f in "${FILES[@]}"; do
  [[ -f "$FROM/$f" ]] || { fail "missing in staging: $FROM/$f"; exit 2; }
done

STAMP="$(date +%y%m%d-%H%M%S)"
SNAP="$SNAP_ROOT/$STAMP"
install -d -m 0700 "$SNAP"

echo "SNAPSHOT  $SNAP"
for f in "${FILES[@]}"; do
  if [[ -f "$BASE/$f" ]]; then
    install -D -m 0644 "$BASE/$f" "$SNAP/$f"
    say "saved $f"
  else
    # Record that the file did NOT exist, so a rollback removes it rather than
    # leaving a new file behind and calling that "restored".
    install -d -m 0700 "$(dirname "$SNAP/$f")"
    : > "$SNAP/$f.ABSENT"
    say "saved $f (was absent)"
  fi
done
printf '%s\n' "${FILES[@]}" > "$SNAP/.files"
ln -sfn "$SNAP" "$SNAP_ROOT/latest"

echo
echo "APPLY"
RESTART=""
for f in "${FILES[@]}"; do
  install -D -m 0644 "$FROM/$f" "$BASE/$f"
  say "installed $f"
  RESTART="$RESTART $(services_for "$f")"
done
# shellcheck disable=SC2086
RESTART="$(printf '%s\n' $RESTART | sort -u | tr '\n' ' ')"

if (( DO_RESTART )) && [[ -n "${RESTART// /}" ]]; then
  echo
  echo "RESTART ${RESTART}"
  # shellcheck disable=SC2086
  systemctl restart $RESTART
  sleep 6
else
  echo
  say "no restart needed for these files"
fi

echo
echo "HEALTH"
if health; then
  echo
  say "deploy OK — rollback available: ops/rollback.sh $SNAP"
  exit 0
fi

echo
fail "health check failed — rolling back automatically"
for f in "${FILES[@]}"; do
  if [[ -f "$SNAP/$f.ABSENT" ]]; then
    rm -f "$BASE/$f"; say "removed $f (was absent before)"
  elif [[ -f "$SNAP/$f" ]]; then
    install -D -m 0644 "$SNAP/$f" "$BASE/$f"; say "restored $f"
  fi
done
if [[ -n "${RESTART// /}" ]]; then
  # shellcheck disable=SC2086
  systemctl restart $RESTART
  sleep 8
fi
echo
echo "HEALTH AFTER ROLLBACK"
if health; then
  say "rolled back and healthy"
else
  fail "STILL UNHEALTHY AFTER ROLLBACK — this needs a human now."
  fail "snapshot: $SNAP"
fi
exit 1
