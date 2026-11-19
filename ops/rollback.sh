#!/usr/bin/env bash
#
# rollback.sh — restore a snapshot taken by ops/deploy.sh.
#
# deploy.sh already rolls itself back when its own health check fails. This is
# for the other case: the deploy passed, and the problem showed up ten minutes
# later. An operator in that situation wants one command, not a file list.
#
# Supersedes rollback_deploy.sh, which restored a FIXED set of seven files
# captured on 09-Nov-2026 regardless of what had actually been deployed since,
# and kept its snapshots inside the install tree — where the 18-Nov `git clean`
# deleted all of them.
#
# USAGE
#   ops/rollback.sh                 # the most recent snapshot
#   ops/rollback.sh /var/backups/ueba/261119-164512
#   ops/rollback.sh --list
#
set -uo pipefail

BASE="${UEBA_BASE:-/opt/ueba}"
SNAP_ROOT="${UEBA_SNAP_ROOT:-/var/backups/ueba}"

if [[ "${1:-}" == "--list" ]]; then
  echo "SNAPSHOTS in $SNAP_ROOT"
  for d in "$SNAP_ROOT"/*/; do
    [[ -d "$d" ]] || continue
    n=$(wc -l < "$d/.files" 2>/dev/null || echo 0)
    printf '  %-44s %s file(s)   %s\n' "${d%/}" "$n" \
      "$(tr '\n' ' ' < "$d/.files" 2>/dev/null)"
  done
  exit 0
fi

SNAP="${1:-$(readlink -f "$SNAP_ROOT/latest" 2>/dev/null)}"
[[ -n "$SNAP" && -d "$SNAP" ]] || { echo "  no snapshot found: ${SNAP:-<none>}" >&2; exit 1; }
[[ -f "$SNAP/.files" ]] || { echo "  $SNAP has no .files manifest" >&2; exit 1; }

echo "RESTORING from $SNAP"
RESTART=""
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  if [[ -f "$SNAP/$f.ABSENT" ]]; then
    rm -f "$BASE/$f"
    echo "  removed $f (did not exist before that deploy)"
  elif [[ -f "$SNAP/$f" ]]; then
    install -D -m 0644 "$SNAP/$f" "$BASE/$f"
    echo "  restored $f"
  else
    echo "  WARNING: $f listed in the manifest but not in the snapshot"
  fi
  case "$f" in
    ueba_dashboard_server*|dashboard/*) RESTART="$RESTART ueba-dashboard" ;;
    ueba_engine*|ueba_models/*)         RESTART="$RESTART ueba-engine" ;;
    *.md|docs/*|tests/*|tools/*)        ;;
    ueba_*.py)                          RESTART="$RESTART ueba-engine ueba-dashboard" ;;
  esac
done < "$SNAP/.files"

# shellcheck disable=SC2086
RESTART="$(printf '%s\n' $RESTART | sort -u | tr '\n' ' ')"
if [[ -n "${RESTART// /}" ]]; then
  echo "RESTARTING ${RESTART}"
  # shellcheck disable=SC2086
  systemctl restart $RESTART
  sleep 8
fi

echo "HEALTH"
exec "$(dirname "${BASH_SOURCE[0]}")/deploy.sh" --check-only
