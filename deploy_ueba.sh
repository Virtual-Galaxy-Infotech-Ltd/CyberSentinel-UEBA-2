#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  CyberSentinel UEBA — Remote Deployer
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Runs from YOUR machine — macOS, Windows (Git Bash or WSL) or Linux — and
#  installs UEBA onto a customer's Linux server over SSH.
#
#  The server side is unchanged: it still runs install_ueba.sh natively on Linux,
#  which is the only platform the engine, systemd units and cron jobs are tested
#  on. This script just collects the answers, ships the tree across, and drives
#  that installer remotely, so nobody needs a Linux laptop to do a deployment.
#
#  Local requirements:  bash, ssh, scp, tar          (macOS: built in)
#                                                    (Windows: Git Bash or WSL2)
#  Target requirements: Ubuntu 22.04/24.04, root or passwordless sudo
#
#  Usage:
#      ./deploy_ueba.sh                          interactive
#      ./deploy_ueba.sh --answers bank-a.env     unattended
#      ./deploy_ueba.sh --check                  inspect the target, install nothing
#
#  NOTE: written for bash 3.2 so it runs on a stock macOS shell — no ${x,,},
#  no associative arrays, no mapfile.
#
set -uo pipefail

VERSION="1.0.0"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOGFILE="${TMPDIR:-/tmp}/ueba-deploy-$STAMP.log"
ANSWERS=""
CHECK_ONLY=0

if [ -t 1 ]; then
  B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
  RED=$'\033[38;5;203m'; GRN=$'\033[38;5;114m'; YEL=$'\033[38;5;221m'
  BLU=$'\033[38;5;75m'; CYA=$'\033[38;5;80m'; MAG=$'\033[38;5;177m'; GRY=$'\033[38;5;245m'
else
  B=""; DIM=""; R=""; RED=""; GRN=""; YEL=""; BLU=""; CYA=""; MAG=""; GRY=""
fi
TICK="${GRN}OK${R}"; CROSS="${RED}XX${R}"; WARNM="${YEL}!!${R}"; INFOM="${BLU}--${R}"

log()  { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOGFILE"; }
say()  { printf '  %b\n' "$*"; log "$*"; }
ok()   { printf '  %b %b\n' "$TICK" "$*"; log "OK: $*"; }
bad()  { printf '  %b %b\n' "$CROSS" "$*"; log "FAIL: $*"; }
warn() { printf '  %b %b\n' "$WARNM" "$*"; log "WARN: $*"; }
note() { printf '  %b %b\n' "$INFOM" "$*"; log "INFO: $*"; }
rule() { printf '  %b\n' "${GRY}────────────────────────────────────────────────────────────${R}"; }
die()  { printf '\n'; bad "$*"; printf '\n'; say "${DIM}Log: $LOGFILE${R}"; exit 1; }

banner() {
  printf '%b' "$CYA"
  cat <<'ART'

   ____      _              ____             _   _            _
  / ___|   _| |__   ___ _ _/ ___|  ___ _ __ | |_(_)_ __   ___| |
 | |  | | | | '_ \ / _ \ '__\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 | |__| |_| | |_) |  __/ |   ___) |  __/ | | | |_| | | | |  __/ |
  \____\__, |_.__/ \___|_|  |____/ \___|_| |_|\__|_|_| |_|\___|_|
       |___/
ART
  printf '%b' "$R"
  printf '  %bU E B A%b  %bremote deployer%b  v%s\n\n' "$B$MAG" "$R" "$GRY" "$R" "$VERSION"
}

# ── Prompts (bash 3.2 safe) ──────────────────────────────────────────────────
ask() { # ask VAR "prompt" "default"
  __v="$1"; __p="$2"; __d="${3:-}"
  if [ -n "$ANSWERS" ]; then
    eval "__cur=\${$__v:-}"
    [ -z "$__cur" ] && __cur="$__d"
    printf '  %b %s: %b%s%b\n' "$INFOM" "$__p" "$B" "$__cur" "$R"
    eval "$__v=\"\$__cur\""
    return 0
  fi
  while :; do
    if [ -n "$__d" ]; then
      printf '  %b?%b %s %b[%s]%b: ' "$B$BLU" "$R" "$__p" "$GRY" "$__d" "$R"
    else
      printf '  %b?%b %s: ' "$B$BLU" "$R" "$__p"
    fi
    IFS= read -r __a || true
    [ -z "$__a" ] && __a="$__d"
    if [ -z "$__a" ]; then warn "Required."; continue; fi
    eval "$__v=\"\$__a\""
    log "ask $__v=$__a"
    return 0
  done
}

ask_yn() { # ask_yn "prompt" y|n
  __p="$1"; __d="${2:-y}"
  if [ -n "$ANSWERS" ]; then [ "$__d" = "y" ] && return 0 || return 1; fi
  __h="[Y/n]"; [ "$__d" = "n" ] && __h="[y/N]"
  while :; do
    printf '  %b?%b %s %b%s%b: ' "$B$BLU" "$R" "$__p" "$GRY" "$__h" "$R"
    IFS= read -r __a || true
    [ -z "$__a" ] && __a="$__d"
    # bash 3.2 has no ${var,,}
    __a="$(printf '%s' "$__a" | tr '[:upper:]' '[:lower:]')"
    case "$__a" in y|yes) return 0 ;; n|no) return 1 ;; *) warn "Answer y or n." ;; esac
  done
}

# ── Local environment ────────────────────────────────────────────────────────
local_env() {
  printf '  %b[1/5]%b %bYour machine%b\n' "$B$CYA" "$R" "$B" "$R"; rule
  case "$(uname -s)" in
    Darwin)            OSNAME="macOS $(sw_vers -productVersion 2>/dev/null)" ;;
    Linux)             OSNAME="Linux" ;;
    MINGW*|MSYS*|CYGWIN*) OSNAME="Windows (Git Bash)" ;;
    *)                 OSNAME="$(uname -s)" ;;
  esac
  # WSL reports Linux but is worth naming, since paths differ from Git Bash.
  if [ -r /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
    OSNAME="Windows (WSL2)"
  fi
  ok "running on ${B}${OSNAME}${R}"
  say "    ${DIM}bash ${BASH_VERSION%%(*}${R}"

  __fail=0
  for t in ssh scp tar; do
    if command -v "$t" >/dev/null 2>&1; then ok "found: $t"
    else bad "missing: $t"; __fail=1; fi
  done
  if [ "$__fail" -ne 0 ]; then
    printf '\n'
    case "$OSNAME" in
      Windows*) say "  ${DIM}Install Git for Windows (includes ssh/scp/tar) or use WSL2.${R}" ;;
      macOS*)   say "  ${DIM}Run: xcode-select --install${R}" ;;
      *)        say "  ${DIM}Install openssh-client and tar.${R}" ;;
    esac
    die "missing local tools"
  fi
  [ -f "$SELF_DIR/install_ueba.sh" ] || die "install_ueba.sh not found beside this script"
  ok "installer payload present"
}

# ── Target ───────────────────────────────────────────────────────────────────
target_details() {
  printf '\n  %b[2/5]%b %bTarget server%b\n' "$B$CYA" "$R" "$B" "$R"; rule
  say "${DIM}The Linux box UEBA will run on (not the SIEM).${R}"
  printf '\n'
  ask TARGET_HOST "UEBA server host or IP" ""
  ask TARGET_USER "SSH user on that server" "root"
  ask TARGET_PORT "SSH port" "22"
}

RSSH() { ssh -p "$TARGET_PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 \
             "${TARGET_USER}@${TARGET_HOST}" "$@"; }

target_check() {
  printf '\n  %b[3/5]%b %bInspecting target%b\n' "$B$CYA" "$R" "$B" "$R"; rule
  RSSH true >>"$LOGFILE" 2>&1 || die "cannot SSH to ${TARGET_USER}@${TARGET_HOST}:${TARGET_PORT}"
  ok "SSH to ${TARGET_USER}@${TARGET_HOST}:${TARGET_PORT}"

  # Everything below deliberately runs REMOTELY: the specs that matter are the
  # server's, and /proc, nproc and `ip route` do not exist on macOS or Windows.
  INFO="$(RSSH 'set -e
    . /etc/os-release 2>/dev/null || true
    echo "OS=${PRETTY_NAME:-unknown}"
    echo "CORES=$(nproc 2>/dev/null || echo 0)"
    echo "RAM=$(awk "/MemTotal/{printf \"%.0f\", \$2/1048576}" /proc/meminfo 2>/dev/null || echo 0)"
    echo "PY=$(python3 -c "import sys;print(\"%d.%d\"%sys.version_info[:2])" 2>/dev/null || echo none)"
    echo "VENV=$(python3 -c "import ensurepip,venv" >/dev/null 2>&1 && echo yes || echo no)"
    echo "SYSTEMD=$(command -v systemctl >/dev/null 2>&1 && echo yes || echo no)"
    echo "CRON=$(command -v crontab >/dev/null 2>&1 && echo yes || echo no)"
    echo "ROOT=$( [ "$(id -u)" -eq 0 ] && echo yes || echo no)"
    echo "DISK=$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc 0-9 || echo 0)"
    echo "IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk "{print \$7; exit}")"
  ' 2>>"$LOGFILE")" || die "target inspection failed"

  T_OS=$(printf '%s\n' "$INFO"   | sed -n 's/^OS=//p')
  T_CORES=$(printf '%s\n' "$INFO"| sed -n 's/^CORES=//p')
  T_RAM=$(printf '%s\n' "$INFO"  | sed -n 's/^RAM=//p')
  T_PY=$(printf '%s\n' "$INFO"   | sed -n 's/^PY=//p')
  T_VENV=$(printf '%s\n' "$INFO" | sed -n 's/^VENV=//p')
  T_SD=$(printf '%s\n' "$INFO"   | sed -n 's/^SYSTEMD=//p')
  T_CRON=$(printf '%s\n' "$INFO" | sed -n 's/^CRON=//p')
  T_ROOT=$(printf '%s\n' "$INFO" | sed -n 's/^ROOT=//p')
  T_DISK=$(printf '%s\n' "$INFO" | sed -n 's/^DISK=//p')
  T_IP=$(printf '%s\n' "$INFO"   | sed -n 's/^IP=//p')

  ok "OS: ${T_OS}"
  [ "$T_ROOT" = "yes" ] && ok "running as root on target" || bad "target user is not root"
  [ "$T_PY" != "none" ] && ok "python ${T_PY}" || bad "python3 missing on target"
  [ "$T_VENV" = "yes" ] && ok "python venv module" || bad "python3-venv missing (apt-get install -y python3-venv)"
  [ "$T_SD" = "yes" ] && ok "systemd present" || bad "systemctl missing — UEBA needs a systemd host"
  [ "$T_CRON" = "yes" ] && ok "cron present" || bad "crontab missing (apt-get install -y cron)"
  [ "${T_CORES:-0}" -ge 8 ] 2>/dev/null && ok "cores: $T_CORES" || warn "cores: ${T_CORES:-?} (8+ recommended)"
  [ "${T_RAM:-0}" -ge 48 ] 2>/dev/null && ok "RAM: ${T_RAM} GB" || warn "RAM: ${T_RAM:-?} GB (48+ recommended)"
  [ "${T_DISK:-0}" -ge 500 ] 2>/dev/null && ok "free disk: ${T_DISK} GB" || warn "free disk: ${T_DISK:-?} GB (500+ recommended)"
  [ -n "$T_IP" ] && say "    ${DIM}target IP: $T_IP${R}"

  if [ "$T_ROOT" != "yes" ] || [ "$T_PY" = "none" ] || [ "$T_VENV" != "yes" ] \
     || [ "$T_SD" != "yes" ] || [ "$T_CRON" != "yes" ]; then
    die "target is not ready — fix the items marked XX above"
  fi
}

site_details() {
  printf '\n  %b[4/5]%b %bSite details%b\n' "$B$CYA" "$R" "$B" "$R"; rule
  ask CLIENT_NAME "Client / bank name" ""
  ask SIEM_HOST   "CyberSentinel SIEM manager host or IP" ""
  ask SIEM_PORT   "SIEM SSH port" "22"
  ask SIEM_USER   "SSH user on the SIEM" "root"
  ask SIEM_ENRICHED_DIR "Enriched-log directory on the SIEM" \
      "/home/${SIEM_USER}/CyberSentinel-Event-Correlation-Kafka/data/enriched"
  ask SIEM_CLIENT_KEYS "Agent registry on the CyberSentinel SIEM" "/var/ossec/etc/client.keys"
  ask BASE_DIR "UEBA install directory (on the target)" "/opt/cybersentinel/ueba"
  ask DATA_DIR "Data directory (on the target)" "/data/ueba"
  ask DASH_HOST "Dashboard bind address" "0.0.0.0"
  ask DASH_PORT "Dashboard port" "3026"
  ask SELF_IP   "Target server's own IP (suppressed as an alert source)" "${T_IP:-}"
}

ship_and_run() {
  printf '\n  %b[5/5]%b %bDeploying%b\n' "$B$CYA" "$R" "$B" "$R"; rule
  STAGE="/tmp/ueba-payload-$STAMP"

  # tar over ssh: one stream, no rsync dependency, works identically from
  # macOS/Git Bash/WSL. Excludes keep a developer's local venv and data out.
  say "shipping payload..."
  ( cd "$SELF_DIR" && tar czf - \
      --exclude='venv' --exclude='.git' --exclude='node_modules' \
      --exclude='*.jsonl' --exclude='*.pt' --exclude='*.pkl' --exclude='*.h5' \
      --exclude='archive' --exclude='training_zips' --exclude='logs' \
      . 2>/dev/null ) \
    | RSSH "mkdir -p '$STAGE' && tar xzf - -C '$STAGE'" >>"$LOGFILE" 2>&1 \
    || die "payload transfer failed"
  ok "payload delivered to ${STAGE}"

  RSSH "cat > '$STAGE/answers.env'" <<EOF
CLIENT_NAME="$CLIENT_NAME"
SIEM_HOST="$SIEM_HOST"
SIEM_PORT="$SIEM_PORT"
SIEM_USER="$SIEM_USER"
SIEM_ENRICHED_DIR="$SIEM_ENRICHED_DIR"
SIEM_CLIENT_KEYS="$SIEM_CLIENT_KEYS"
BASE_DIR="$BASE_DIR"
DATA_DIR="$DATA_DIR"
DASH_HOST="$DASH_HOST"
DASH_PORT="$DASH_PORT"
SELF_IP="$SELF_IP"
EOF
  ok "answers written"

  printf '\n'
  say "${DIM}── remote installer output ──────────────────────────────${R}"
  printf '\n'
  # -t so the installer can still prompt for the SIEM key authorisation.
  ssh -t -p "$TARGET_PORT" -o StrictHostKeyChecking=accept-new \
      "${TARGET_USER}@${TARGET_HOST}" \
      "cd '$STAGE' && chmod +x install_ueba.sh && ./install_ueba.sh --unattended '$STAGE/answers.env'"
  RC=$?
  printf '\n'
  say "${DIM}─────────────────────────────────────────────────────────${R}"
  return $RC
}

# ── Main ─────────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --answers) ANSWERS="${2:-}"; [ -f "$ANSWERS" ] && . "$ANSWERS"; shift 2 ;;
    --check)   CHECK_ONLY=1; shift ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

banner
say "${DIM}Log: $LOGFILE${R}"
printf '\n'
local_env
target_details
target_check

if [ "$CHECK_ONLY" -eq 1 ]; then
  printf '\n'
  ok "target looks ready — re-run without --check to install"
  printf '\n'
  exit 0
fi

site_details
printf '\n'
say "${B}About to install${R} UEBA for ${B}${CLIENT_NAME}${R}"
say "  target   ${TARGET_USER}@${TARGET_HOST}:${TARGET_PORT}  ->  ${BASE_DIR}"
say "  SIEM     ${SIEM_USER}@${SIEM_HOST}:${SIEM_PORT}"
printf '\n'
ask_yn "Proceed?" y || { say "aborted"; exit 0; }

ship_and_run
RC=$?
printf '\n'
if [ "$RC" -eq 0 ]; then
  ok "deployment finished"
  # Show an address the operator can actually reach. T_IP is whatever the target
  # sees on its default route, which on a NAT'd or containerised host is a
  # private address that means nothing from here — prefer the IP they supplied,
  # then the host they just connected to.
  say "  Dashboard: ${B}http://${SELF_IP:-$TARGET_HOST}:${DASH_PORT}${R}"
  [ -n "${T_IP:-}" ] && [ "${T_IP}" != "${SELF_IP:-}" ] && \
    say "  ${DIM}(target's own route address: ${T_IP})${R}"
else
  bad "remote installer exited $RC — see the output above and $LOGFILE"
fi
printf '\n'
exit $RC
