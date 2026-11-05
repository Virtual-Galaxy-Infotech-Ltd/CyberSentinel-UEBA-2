#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  CyberSentinel UEBA — Interactive Installer
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Deploys the UEBA module against a customer's CyberSentinel SIEM. Everything
#  that used to be hardcoded for the lab pair (98 <-> 23) is asked for here and
#  written into ueba_config.yaml, so the same tree deploys at any bank.
#
#  This is stage 2 of a two-stage install. Stage 1 is check_dependencies.sh,
#  which verifies packages, versions and host capacity and changes nothing;
#  this script runs it first and refuses to continue if it fails. That split
#  exists because the expensive failures used to happen late — a missing
#  python3-venv surfaced at step 7, after the SSH key had been authorised on the
#  customer's SIEM and the config had been written.
#
#  What it does, in order:
#     1. Dependencies     — delegated to check_dependencies.sh (stage 1)
#     2. Endpoints        — SIEM address/port and UEBA address/port, and the
#                           topology DERIVED from them (same host or separate)
#     3. Site details     — client name, feed source, SIEM paths
#     4. Install location — install dir (or --dir), data dir, resource caps
#     5. Connectivity     — bridge transport: direct SSH, or a reverse tunnel
#                           originated from the SIEM when inbound is blocked
#     6. SSH trust        — generate a keypair, help you authorise it, test it
#     7. Discovery        — pull the SIEM agent registry -> agents.json
#     8. Configuration    — render ueba_config.yaml + the bridge env file
#     9. Runtime          — venv + CPU-only wheels, systemd units
#    10. Bring-up         — first sync, optional training, start services
#
#  Safe to re-run: every step detects existing state and offers to keep it.
#  Nothing outside the install dir is touched except the systemd unit files.
#
#  Usage:
#     sudo ./install_ueba.sh                          interactive
#     sudo ./install_ueba.sh --dir /opt/ueba          install directory from the command line
#     sudo ./install_ueba.sh --dir /opt/ueba --data-dir /data/ueba \
#                            --siem 10.200.10.98:22 --dash 0.0.0.0:3026
#     sudo ./install_ueba.sh --unattended answers.env
#     sudo ./install_ueba.sh --dry-run                show what would happen, change nothing
#     sudo ./install_ueba.sh --skip-depcheck          stage 1 already run separately
#
set -uo pipefail

VERSION="1.0.0"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGFILE="/tmp/ueba-install-$(date +%Y%m%d-%H%M%S).log"
DRY_RUN=0
UNATTENDED=""
SKIP_DEPCHECK=0

# Values supplied on the command line. ask() treats a preset variable as a
# DEFAULT and still prompts, which is right for an answers file and wrong for
# an explicit --dir: an operator who named the directory in the command should
# not be asked to confirm it. fixed() distinguishes the two.
declare -A PRESET=()
fixed() { [[ -n "${PRESET[$1]:-}" ]]; }

# ── Styling ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
  B=$'\e[1m'; DIM=$'\e[2m'; R=$'\e[0m'
  RED=$'\e[38;5;203m'; GRN=$'\e[38;5;114m'; YEL=$'\e[38;5;221m'
  BLU=$'\e[38;5;75m';  CYA=$'\e[38;5;80m'; MAG=$'\e[38;5;177m'; GRY=$'\e[38;5;245m'
else
  B=""; DIM=""; R=""; RED=""; GRN=""; YEL=""; BLU=""; CYA=""; MAG=""; GRY=""
fi

TICK="${GRN}✔${R}"; CROSS="${RED}✘${R}"; WARN="${YEL}▲${R}"; INFO="${BLU}•${R}"
STEP_TOTAL=10
STEP_NOW=0

log()   { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOGFILE"; }
say()   { printf '  %b\n' "$*"; log "$*"; }
ok()    { printf '  %b %b\n' "$TICK" "$*"; log "OK: $*"; }
bad()   { printf '  %b %b\n' "$CROSS" "$*"; log "FAIL: $*"; }
warn()  { printf '  %b %b\n' "$WARN" "$*"; log "WARN: $*"; }
note()  { printf '  %b %b\n' "$INFO" "$*"; log "INFO: $*"; }
blank() { printf '\n'; }

die() { blank; bad "$*"; blank; say "${DIM}Full log: $LOGFILE${R}"; exit 1; }

rule() { printf '  %b\n' "${GRY}────────────────────────────────────────────────────────────────${R}"; }

banner() {
  clear 2>/dev/null || true
  printf '%b' "$CYA"
  cat <<'ART'

   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
ART
  printf '%b' "$R"
  printf '  %bU E B A%b  %b·%b  User & Entity Behaviour Analytics  %b·%b  installer v%s\n' \
         "$B$MAG" "$R" "$GRY" "$R" "$GRY" "$R" "$VERSION"
  blank
}

step() {
  STEP_NOW=$((STEP_NOW + 1))
  blank
  local bar="" i
  for ((i = 1; i <= STEP_TOTAL; i++)); do
    if   (( i <  STEP_NOW )); then bar+="${GRN}━${R}"
    elif (( i == STEP_NOW )); then bar+="${CYA}━${R}"
    else                           bar+="${GRY}━${R}"; fi
  done
  printf '  %b[%d/%d]%b %b%s%b  %b\n' "$B$CYA" "$STEP_NOW" "$STEP_TOTAL" "$R" "$B" "$1" "$R" "$bar"
  rule
}

spin() {
  # spin <message> <command...>   — runs the command, shows a spinner, keeps output in the log
  local msg="$1"; shift
  if (( DRY_RUN )); then note "${DIM}[dry-run]${R} $msg"; return 0; fi
  local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' pid i=0
  ( "$@" >>"$LOGFILE" 2>&1 ) & pid=$!
  if [[ -t 1 ]]; then
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r  %b%s%b %s' "$CYA" "${frames:i++%10:1}" "$R" "$msg"
      sleep 0.08
    done
    printf '\r\033[K'
  fi
  if wait "$pid"; then ok "$msg"; return 0; else bad "$msg"; return 1; fi
}

# ── Prompts ───────────────────────────────────────────────────────────────────
ask() { # ask <var> <prompt> <default> [validator]
  local __var="$1" prompt="$2" def="${3:-}" validator="${4:-}" val=""
  if [[ -n "$UNATTENDED" ]]; then
    val="${!__var:-$def}"
    printf '  %b %s: %b%s%b %b(from answers file)%b\n' "$INFO" "$prompt" "$B" "$val" "$R" "$GRY" "$R"
    printf -v "$__var" '%s' "$val"; return 0
  fi
  while true; do
    if [[ -n "$def" ]]; then
      printf '  %b?%b %s %b[%s]%b: ' "$B$BLU" "$R" "$prompt" "$GRY" "$def" "$R"
    else
      printf '  %b?%b %s: ' "$B$BLU" "$R" "$prompt"
    fi
    IFS= read -r val || true
    val="${val:-$def}"
    [[ -z "$val" ]] && { warn "This one is required."; continue; }
    if [[ -n "$validator" ]] && ! "$validator" "$val"; then continue; fi
    printf -v "$__var" '%s' "$val"; log "ask $__var=$val"; return 0
  done
}

ask_secret() { # never echoed, never logged
  local __var="$1" prompt="$2" val=""
  printf '  %b?%b %s %b(hidden)%b: ' "$B$BLU" "$R" "$prompt" "$GRY" "$R"
  IFS= read -rs val || true; printf '\n'
  printf -v "$__var" '%s' "$val"
}

ask_yn() { # ask_yn <prompt> <default y|n>  -> returns 0 for yes
  local prompt="$1" def="${2:-y}" val=""
  if [[ -n "$UNATTENDED" ]]; then [[ "$def" == "y" ]] && return 0 || return 1; fi
  local hint="[Y/n]"; [[ "$def" == "n" ]] && hint="[y/N]"
  while true; do
    printf '  %b?%b %s %b%s%b: ' "$B$BLU" "$R" "$prompt" "$GRY" "$hint" "$R"
    IFS= read -r val || true
    val="${val:-$def}"
    case "${val,,}" in y|yes) return 0 ;; n|no) return 1 ;; *) warn "Please answer y or n." ;; esac
  done
}

v_host() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] && return 0; warn "Use a hostname or IPv4 address."; return 1; }
v_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )) && return 0; warn "Port must be 1-65535."; return 1; }
v_abs()  { [[ "$1" = /* ]] && return 0; warn "Must be an absolute path (starting with /)."; return 1; }
v_user() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] && return 0; warn "Not a valid username."; return 1; }

# ── Address helpers ───────────────────────────────────────────────────────────
# Every address this host answers on: loopback, its own name, and each global
# IPv4/IPv6 on every interface. Collected once, because the topology question
# below is asked against it.
local_addresses() {
  {
    printf '127.0.0.1\nlocalhost\n::1\n'
    hostname 2>/dev/null
    hostname -f 2>/dev/null
    hostname -I 2>/dev/null | tr ' ' '\n'
    ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1
  } 2>/dev/null | sed '/^$/d' | tr 'A-Z' 'a-z' | sort -u
}

# is_local_address <host> — true when <host> is this machine.
#
# This is what decides co-located vs separate, and it is decided by comparing
# the SIEM address the operator typed against the addresses this host actually
# holds, rather than by asking them which it is. Two reasons: an operator
# installing on the SIEM host has already told us the answer by typing its own
# IP, and answering a yes/no wrongly silently produces the other topology —
# an unattended co-located install that builds an SSH bridge to itself.
is_local_address() {
  local want; want="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
  [[ -z "$want" ]] && return 1
  local a
  while read -r a; do [[ "$a" == "$want" ]] && return 0; done < <(local_addresses)
  # A hostname that resolves onto one of our own addresses counts too — the
  # operator may type the SIEM's DNS name on the SIEM itself.
  if have_cmd getent; then
    local r
    while read -r r; do
      [[ -z "$r" ]] && continue
      while read -r a; do [[ "$a" == "$r" ]] && return 0; done < <(local_addresses)
    done < <(getent ahostsv4 "$want" 2>/dev/null | awk '{print tolower($1)}' | sort -u)
  fi
  return 1
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# tcp_open <host> <port> [timeout] — is anything accepting connections there
tcp_open() {
  local h="$1" p="$2" t="${3:-6}"
  if have_cmd nc; then nc -z -w "$t" "$h" "$p" >/dev/null 2>&1; return $?; fi
  timeout "$t" bash -c "exec 3<>/dev/tcp/${h}/${p}" >/dev/null 2>&1
}

# ── Steps ─────────────────────────────────────────────────────────────────────
# Stage 1 lives in its own script so a customer's platform team can run it
# before the change window, without sudo and without this installer. Running it
# again here is deliberate: the host that was certified a week ago is not
# necessarily the host in front of us now.
preflight() {
  step "Dependencies"

  if (( SKIP_DEPCHECK )); then
    warn "--skip-depcheck: stage 1 was not run"
    say "${DIM}Only use this when check_dependencies.sh has already passed on THIS host.${R}"
    return 0
  fi

  local dc="$SELF_DIR/check_dependencies.sh"
  if [[ ! -f "$dc" ]]; then
    warn "check_dependencies.sh not found beside the installer — using the built-in checks"
    preflight_builtin
    return 0
  fi

  local args=(--for-install --dir "${BASE_DIR:-/opt/cybersentinel/ueba}")
  [[ -n "${DATA_DIR:-}" ]] && args+=(--data-dir "$DATA_DIR")
  [[ -n "${DASH_PORT:-}" ]] && args+=(--dash-port "$DASH_PORT")
  [[ -n "${SIEM_HOST:-}" ]] && args+=(--siem "${SIEM_HOST}:${SIEM_PORT:-22}")
  [[ -n "${KAFKA_BROKERS:-}" ]] && args+=(--kafka "${KAFKA_BROKERS%%,*}")
  [[ -n "${WHEELHOUSE:-}" ]] && args+=(--wheelhouse "$WHEELHOUSE")
  local report="/tmp/ueba-depcheck-$(date +%Y%m%d-%H%M%S).json"
  args+=(--json "$report")

  say "${DIM}stage 1: $dc${R}"
  blank
  # Its output goes straight to the terminal rather than into the log: this is
  # the one report the operator has to read, and a spinner over it would hide
  # exactly the lines that matter.
  bash "$dc" "${args[@]}"
  local rc=$?
  DEPCHECK_REPORT="$report"

  if (( rc != 0 )); then
    if (( DRY_RUN )); then
      warn "dependency check failed (rc=$rc) — continuing because this is a dry run"
      return 0
    fi
    die "Dependency check failed. Fix the items marked ✘ above and re-run. Report: $report"
  fi
  ok "dependency check passed ${GRY}(report: $report)${R}"
}

preflight_builtin() {
  # No step() here — this runs inside the Dependencies step, as its fallback,
  # and a second step() would advance the progress bar twice.
  blank
  say "${B}Built-in preflight${R} ${DIM}(reduced — stage 1 checks far more)${R}"
  local fail=0

  [[ $EUID -eq 0 ]] && ok "running as root" || { bad "must run as root (use sudo)"; fail=1; }

  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    if [[ "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *debian* ]]; then ok "OS: ${PRETTY_NAME:-unknown}"
    else warn "OS: ${PRETTY_NAME:-unknown} — tested on Ubuntu 22.04/24.04"; fi
  else warn "cannot identify OS"; fi

  local py; py="$(command -v python3 || true)"
  if [[ -n "$py" ]]; then
    local pv; pv="$($py -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo 0.0)"
    if [[ "$(printf '%s\n3.10\n' "$pv" | sort -V | head -1)" == "3.10" ]]; then ok "python $pv"
    else bad "python $pv — need 3.10 or newer"; fail=1; fi
  else bad "python3 not found"; fail=1; fi

  local cores ram_gb
  cores="$(nproc 2>/dev/null || echo 1)"
  ram_gb="$(awk '/MemTotal/{printf "%.0f", $2/1048576}' /proc/meminfo 2>/dev/null || echo 0)"
  (( cores >= 8 ))  && ok "CPU cores: $cores" || warn "CPU cores: $cores — 8+ recommended"
  (( ram_gb >= 48 )) && ok "RAM: ${ram_gb} GB"  || warn "RAM: ${ram_gb} GB — 48 GB+ recommended"

  for t in ssh scp rsync curl tar gzip systemctl crontab; do
    command -v "$t" >/dev/null 2>&1 && ok "found: $t" || { bad "missing: $t"; fail=1; }
  done

  # python3-venv ships as a separate package on Debian/Ubuntu. Without it the
  # venv build fails at step 7 — after the SSH key has been authorised and the
  # config written — so check it here, while the fix is still a one-liner.
  if [[ -n "$py" ]] && "$py" -c 'import ensurepip, venv' >/dev/null 2>&1; then
    ok "python venv module"
  else
    bad "python venv module missing — apt-get install -y python3-venv"
    fail=1
  fi
  command -v jq >/dev/null 2>&1 || warn "jq not installed (optional, nicer output)"

  (( fail )) && die "Preflight failed. Fix the items marked ✘ and re-run."
  ok "preflight passed"
}

collect_endpoints() {
  step "Endpoints"
  say "${DIM}The two addresses that define this deployment: where the SIEM is,${R}"
  say "${DIM}and where UEBA will be served from. The topology is worked out from${R}"
  say "${DIM}them rather than asked for separately.${R}"
  blank

  # Backwards compatibility with the answers files written before this step
  # existed. They carry SELF_IP and CO_LOCATED but no SIEM_HOST or UEBA_HOST,
  # and an unattended re-install of an existing site must not change behaviour
  # because the questions were reorganised.
  if [[ -n "$UNATTENDED" ]]; then
    [[ -z "${UEBA_HOST:-}" && -n "${SELF_IP:-}" ]] && UEBA_HOST="$SELF_IP"
    [[ -z "${SIEM_HOST:-}" && "${CO_LOCATED:-}" == "1" ]] && SIEM_HOST="${SELF_IP:-localhost}"
  fi

  say "${B}SIEM${R}"
  ask SIEM_HOST "CyberSentinel SIEM manager host or IP" "" v_host
  # The SSH port, not the Kafka port. This is the port the agent-registry
  # discovery and (on a separate install) the feed bridge both go through.
  # Kafka is asked for later, and only when it is the feed.
  ask SIEM_PORT "SIEM SSH port"                        "22" v_port

  blank
  say "${B}UEBA${R}"
  local guess; guess="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
  [[ -z "$guess" ]] && guess="$(hostname -I 2>/dev/null | awk '{print $1}')"
  # One address, used for three things: the URL printed at the end, the
  # suppression entry that stops this server's own sync and SSH traffic being
  # scored as alerts against the estate it watches, and the tunnel endpoint the
  # SIEM dials back to in reverse mode.
  if fixed UEBA_HOST; then
    note "UEBA hosting address: ${B}${UEBA_HOST}${R} ${GRY}(from the command line)${R}"
  else
    ask UEBA_HOST "Address this UEBA instance will be reached at" "${guess:-}" v_host
  fi
  if fixed DASH_PORT; then
    note "console port: ${B}${DASH_PORT}${R} ${GRY}(from the command line)${R}"
  else
    ask DASH_PORT "UEBA console port" "${DASH_PORT:-3026}" v_port
  fi
  SELF_IP="$UEBA_HOST"

  # Bind address is derived, not asked. Binding the loopback when the operator
  # gave a routable address produces a console that answers only to an SSH
  # port-forward, which reads as "the dashboard is down".
  if [[ -z "${DASH_HOST:-}" ]]; then
    case "$UEBA_HOST" in
      127.0.0.1|localhost|::1) DASH_HOST="127.0.0.1" ;;
      *)                       DASH_HOST="0.0.0.0" ;;
    esac
  fi

  # ── Topology, derived ───────────────────────────────────────────────────────
  blank
  say "${B}Topology${R}"
  local derived=0
  if is_local_address "$SIEM_HOST"; then derived=1; fi

  if [[ -n "${CO_LOCATED:-}" ]]; then
    # An answers file wins, but say so and say what we would have concluded —
    # a mismatch between the two is worth seeing before the install, not after.
    note "co-located mode: ${CO_LOCATED} ${GRY}(from answers file)${R}"
    if [[ "$CO_LOCATED" != "$derived" ]]; then
      local verdict="is not"; (( derived )) && verdict="is"
      warn "the answers file says CO_LOCATED=${CO_LOCATED}, but ${SIEM_HOST} ${verdict} an address of this host"
      say "${DIM}Proceeding with the answers file. If that is wrong, stop now (Ctrl-C).${R}"
    fi
  elif (( derived )); then
    CO_LOCATED=1
    ok "${SIEM_HOST} is an address of this host — ${B}same server${R}"
    say "${DIM}The SIEM pipeline already publishes every enriched event to Kafka, so${R}"
    say "${DIM}the engine consumes the topic directly: no bridge, no SSH to ourselves,${R}"
    say "${DIM}no second copy of the data on disk, and offsets kept by Kafka.${R}"
  else
    CO_LOCATED=0
    ok "${SIEM_HOST} is not an address of this host — ${B}separate servers${R}"
    say "${DIM}The feed has to cross the network, so a bridge is configured at step 5.${R}"
    # Showing the comparison is what makes the automatic answer auditable. An
    # operator who typed a VIP, a NAT address or a second interface the host
    # does not hold can see immediately why we concluded what we did.
    say "${DIM}this host holds: $(local_addresses | grep -E '^[0-9]' | paste -sd' ' -)${R}"
    if ! ask_yn "Is that right — UEBA and the SIEM are on different servers?" y; then
      CO_LOCATED=1
      note "overridden: treating this as a same-server install"
    fi
  fi
}

collect_site() {
  step "Site details"
  say "${DIM}Who this install is for, and how the feed reaches it.${R}"
  blank
  ask CLIENT_NAME "Client / bank name"                ""

  # Two topologies, and they differ by more than a hostname.
  #
  #   separate  — UEBA on its own host. ueba_sync_bridge.sh pulls rotated
  #               enriched chunks over SSH and appends them to a local file the
  #               engine tails.
  #   colocated — UEBA on the SIEM host itself. The correlation pipeline already
  #               publishes every enriched event to a Kafka topic, and its own
  #               kafka_jsonl_sink.py is just another consumer writing that topic
  #               to files. So the engine reads the topic directly: no bridge, no
  #               SSH, no second copy of the data on disk, and offsets kept
  #               durably by Kafka instead of by our own byte counter.
  #
  # CO_LOCATED is already settled: collect_endpoints derived it from the SIEM
  # address against this host's own addresses, and an answers file overrides
  # that explicitly. Nothing here asks again — a second yes/no is a second
  # chance to answer it differently from the addresses already given.
  blank
  if [[ "$CO_LOCATED" == "1" ]]; then
    SIEM_USER="root"
    ask KAFKA_BROKERS "Kafka brokers the SIEM pipeline uses" \
        "localhost:39092"
    ask KAFKA_TOPIC   "Enriched Kafka topic" "enriched"
    # Its own group, always. Kafka divides a topic's partitions among a group's
    # members, so reusing one of the pipeline's groups (enricher, correlation,
    # scorer, enriched-file-sink, scored-file-sink) would take partitions away
    # from that consumer — the pipeline's file sink would quietly stop seeing a
    # share of events, with no error logged anywhere. ueba_source.py refuses
    # those names, but defaulting correctly means nobody has to find out.
    KAFKA_GROUP="ueba-engine"
    ask SIEM_ENRICHED_DIR "Enriched-log directory (kept for reference/backfill)" \
        "/home/vgipl/CyberSentinel-Event-Correlation-Kafka/data/enriched" v_abs
    ask SIEM_CLIENT_KEYS  "SIEM agent registry" \
        "/var/ossec/etc/client.keys" v_abs
    # On a containerised SIEM the registry is not on the host filesystem at
    # all, so a plain `cat` finds nothing and every endpoint then displays as
    # a bare IP with no indication why. Offer the docker form, which is what
    # the first co-located deployment actually needed.
    AGENT_LOCAL_CMD="cat ${SIEM_CLIENT_KEYS}"
    if command -v docker >/dev/null 2>&1; then
      _mgr="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'manager' | head -1)"
      if [[ -n "$_mgr" ]] && ! [[ -r "$SIEM_CLIENT_KEYS" ]]; then
        note "registry not readable on the host; found container ${B}${_mgr}${R}"
        AGENT_LOCAL_CMD="docker exec ${_mgr} cat ${SIEM_CLIENT_KEYS}"
      fi
    fi
    ask AGENT_LOCAL_CMD "Command to read the agent registry" "$AGENT_LOCAL_CMD"
  else
    # Address and port were taken at step 2; only the account and the paths on
    # the far side are still unknown.
    note "SIEM: ${B}${SIEM_HOST}:${SIEM_PORT}${R} ${GRY}(from step 2)${R}"
    ask SIEM_USER   "SSH user on the SIEM"              "root" v_user
    ask SIEM_ENRICHED_DIR "Enriched-log directory on the SIEM" \
        "/home/${SIEM_USER}/CyberSentinel-Event-Correlation-Kafka/data/enriched" v_abs
    ask SIEM_CLIENT_KEYS  "SIEM agent registry on the SIEM" \
        "/var/ossec/etc/client.keys" v_abs
  fi
}

collect_local() {
  step "Install location"

  # --dir is the whole point of the flag: an operator who named the directory
  # on the command line has already decided, and a prompt that offers to change
  # it invites a different answer than the change record says.
  if fixed BASE_DIR; then
    note "install directory: ${B}${BASE_DIR}${R} ${GRY}(from --dir)${R}"
  else
    ask BASE_DIR "UEBA install directory" "${BASE_DIR:-/opt/cybersentinel/ueba}" v_abs
  fi
  if fixed DATA_DIR; then
    note "data directory: ${B}${DATA_DIR}${R} ${GRY}(from --data-dir)${R}"
  else
    ask DATA_DIR "Data directory (needs ~500 GB, grows ~65 GB/month)" "${DATA_DIR:-/data/ueba}" v_abs
  fi
  note "console: ${B}http://${UEBA_HOST}:${DASH_PORT}${R} ${GRY}(bind ${DASH_HOST} — from step 2)${R}"

  # Resource caps. On a dedicated host these are a safety net; on the SIEM host
  # they are the contract that stops UEBA becoming the reason the SIEM dies.
  # The kernel OOM killer picks large processes, not guilty ones, so without a
  # cgroup limit a leaking UEBA would take out whatever else is biggest —
  # ClickHouse, Elasticsearch, the SIEM's own Java heaps.
  #
  # Defaults come from measurement on the previous deployment: engine 19.5 GB
  # resident, dashboard 4.0 GB, bridge negligible. Headroom is added rather
  # than trimmed, because a cap set below real usage converts a tuning problem
  # into a crash loop. Lower them once you have watched actual usage with
  # `systemctl status ueba-engine`.
  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
    blank
    say "${DIM}UEBA will share this host with the SIEM. Caps keep it contained.${R}"
    ask MEM_ENGINE    "Memory cap for the engine"    "24G"
    ask MEM_DASHBOARD "Memory cap for the dashboard" "6G"
  else
    MEM_ENGINE="${MEM_ENGINE:-24G}"
    MEM_DASHBOARD="${MEM_DASHBOARD:-6G}"
  fi

  # SELF_IP is the UEBA address from step 2. It is suppressed as an alert
  # source, or this server's own sync and SSH traffic scores as alerts against
  # the estate it is supposed to be watching.
  SELF_IP="${SELF_IP:-$UEBA_HOST}"

  if [[ -e "$BASE_DIR" ]]; then
    warn "$BASE_DIR already exists."
    ask_yn "Reuse it (keeps data, overwrites config)?" y || die "Pick a different directory and re-run."
    REUSE=1
  else
    REUSE=0
  fi
}

configure_bridge() {
  step "Connectivity"

  # Everything downstream — setup_ssh, discover, agent_sync, the feed bridge —
  # goes through this pair rather than SIEM_HOST/SIEM_PORT directly. On a
  # reverse-tunnel install the SIEM is not reachable at its own address from
  # here at all; it is reachable at 127.0.0.1 on a port it published itself.
  SIEM_SSH_HOST="$SIEM_HOST"
  SIEM_SSH_PORT="$SIEM_PORT"
  BRIDGE_MODE="none"
  FEED_MODE="files"
  # setup_ssh owns this key, but the reverse-tunnel handover bundle has to quote
  # its public half, and that bundle is written here. Name it now; both steps
  # treat an existing key as the key.
  SSH_KEY="${SSH_KEY:-/root/.ssh/id_ueba}"

  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
    FEED_MODE="kafka"
    SIEM_SSH_HOST="localhost"
    say "${DIM}Same server: the feed never crosses the network. The engine consumes${R}"
    say "${DIM}the enriched topic the SIEM pipeline already publishes, so there is${R}"
    say "${DIM}no bridge, no tunnel and no second copy of the data on disk.${R}"
    blank
    local kb="${KAFKA_BROKERS:-}"; kb="${kb%%,*}"
    if [[ -n "$kb" ]] && tcp_open "${kb%:*}" "${kb##*:}" 6; then
      ok "Kafka broker reachable at ${kb}"
    else
      warn "cannot open ${kb:-the broker} from here"
      say "${DIM}The engine has no source until that broker answers. On a containerised${R}"
      say "${DIM}SIEM the advertised listener is often the container port, not 9092.${R}"
    fi
    ok "no bridge required"
    return 0
  fi

  # ── Separate hosts ──────────────────────────────────────────────────────────
  say "${DIM}UEBA and the SIEM are on different hosts, so the feed has to cross${R}"
  say "${DIM}the network. Which direction it is allowed to cross in is a firewall${R}"
  say "${DIM}question, and at a bank the answer is usually not the obvious one.${R}"
  blank

  # Probe first, then ask. An operator should be choosing between options they
  # have just watched succeed or fail, not guessing.
  local direct_ok=0
  if tcp_open "$SIEM_HOST" "$SIEM_PORT" 8; then
    direct_ok=1
    ok "UEBA → SIEM: ${SIEM_HOST}:${SIEM_PORT} accepts connections"
  else
    warn "UEBA → SIEM: cannot open ${SIEM_HOST}:${SIEM_PORT} from this host"
  fi

  if [[ -z "${BRIDGE_MODE_PRESET:-}" ]]; then
    blank
    say "${B}Bridge transport${R}"
    say "  ${B}1${R} direct   ${DIM}— UEBA dials the SIEM over SSH. Simplest: one key, no${R}"
    say "            ${DIM}  extra daemon. Needs outbound UEBA → SIEM:${SIEM_PORT} open.${R}"
    say "  ${B}2${R} reverse  ${DIM}— the SIEM dials UEBA and publishes its own SSH port on${R}"
    say "            ${DIM}  UEBA's loopback. Use this when the SIEM sits in a zone${R}"
    say "            ${DIM}  that accepts no inbound connections, which is the normal${R}"
    say "            ${DIM}  posture for a bank's SIEM segment. Needs outbound${R}"
    say "            ${DIM}  SIEM → UEBA on one port instead.${R}"
    blank
    local def="1"; (( direct_ok )) || def="2"
    (( direct_ok )) || note "direct failed its probe, so reverse is offered as the default"
    ask BRIDGE_CHOICE "Transport (1 direct / 2 reverse)" "$def"
    case "$BRIDGE_CHOICE" in
      1|direct)  BRIDGE_MODE="direct" ;;
      2|reverse) BRIDGE_MODE="reverse" ;;
      *) warn "unrecognised answer '${BRIDGE_CHOICE}' — using direct"; BRIDGE_MODE="direct" ;;
    esac
  else
    BRIDGE_MODE="$BRIDGE_MODE_PRESET"
    note "bridge transport: ${BRIDGE_MODE} ${GRY}(preset)${R}"
  fi

  case "$BRIDGE_MODE" in
    direct)  configure_bridge_direct ;;
    reverse) configure_bridge_reverse ;;
  esac
}

configure_bridge_direct() {
  blank
  ok "transport: ${B}direct${R} — UEBA dials ${SIEM_USER}@${SIEM_HOST}:${SIEM_PORT}"
  SIEM_SSH_HOST="$SIEM_HOST"
  SIEM_SSH_PORT="$SIEM_PORT"

  # The feed itself can take one of two shapes over that same SSH transport,
  # and they are not equivalent.
  #
  #   files  — ueba_sync_bridge.sh pulls rotated enriched chunks and appends
  #            them to a local file the engine tails. Proven, and resilient to
  #            a link that comes and goes, but it is a second copy of the data
  #            and the engine is always behind by part of a rotation interval.
  #   kafka  — an SSH local-forward carries the SIEM's broker port to this
  #            host, and the engine consumes the topic directly as its own
  #            consumer group. Live, no duplicate on disk, and offsets kept
  #            durably by Kafka. It needs the tunnel to be up for the engine to
  #            see anything, which is why it is not the default.
  blank
  say "${B}Feed shape${R}"
  say "  ${B}1${R} files  ${DIM}— pull rotated enriched chunks over SSH (default, proven)${R}"
  say "  ${B}2${R} kafka  ${DIM}— forward the broker port over SSH and consume the topic live${R}"
  blank
  ask FEED_CHOICE "Feed (1 files / 2 kafka over the tunnel)" "1"
  case "$FEED_CHOICE" in
    2|kafka)
      FEED_MODE="kafka"
      ask KAFKA_REMOTE "Broker as the SIEM sees it (host:port on that host)" "localhost:39092"
      ask KAFKA_LOCAL_PORT "Local port to publish it on here" "39092" v_port
      ask KAFKA_TOPIC "Enriched Kafka topic" "enriched"
      # Its own group, always. Kafka divides a topic's partitions among a
      # group's members, so reusing one of the pipeline's groups (enricher,
      # correlation, scorer, enriched-file-sink) would take partitions away
      # from that consumer and the SIEM's own file sink would quietly stop
      # seeing a share of events, with nothing logged anywhere.
      KAFKA_GROUP="ueba-engine"
      KAFKA_BROKERS="127.0.0.1:${KAFKA_LOCAL_PORT}"
      install_forward_tunnel
      ;;
    *)
      FEED_MODE="files"
      ok "feed: rotated enriched chunks over SSH (ueba-bridge)"
      ;;
  esac
}

# A long-lived SSH local-forward, run as a unit so systemd owns its lifetime.
# ExitOnForwardFailure matters: without it ssh happily stays connected after
# the forward is refused, and the engine then fails to reach a broker that
# looks, from the outside, like it has a healthy tunnel to it.
install_forward_tunnel() {
  local unit=/etc/systemd/system/ueba-tunnel.service
  if (( DRY_RUN )); then
    note "${DIM}[dry-run]${R} would install $unit forwarding 127.0.0.1:${KAFKA_LOCAL_PORT} → ${KAFKA_REMOTE}"
    return 0
  fi
  cat >"$unit" <<EOF
[Unit]
Description=CyberSentinel UEBA Kafka forward tunnel (${CLIENT_NAME})
Documentation=man:ssh(1)
After=network-online.target
Wants=network-online.target
Before=ueba-engine.service

[Service]
Type=simple
ExecStart=/usr/bin/ssh -NT \\
  -i ${SSH_KEY:-/root/.ssh/id_ueba} -p ${SIEM_PORT} \\
  -o ExitOnForwardFailure=yes \\
  -o ServerAliveInterval=20 -o ServerAliveCountMax=3 \\
  -o StrictHostKeyChecking=accept-new -o BatchMode=yes \\
  -L 127.0.0.1:${KAFKA_LOCAL_PORT}:${KAFKA_REMOTE} \\
  ${SIEM_USER}@${SIEM_HOST}
Restart=always
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=10

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >>"$LOGFILE" 2>&1
  ok "installed ueba-tunnel.service (127.0.0.1:${KAFKA_LOCAL_PORT} → ${KAFKA_REMOTE})"
  note "the engine starts after it: Before=ueba-engine.service"
}

# ── Reverse tunnel ────────────────────────────────────────────────────────────
# The SIEM originates the connection and publishes its own sshd onto this
# host's loopback; the bridge then talks to 127.0.0.1:<local port> exactly as
# if the SIEM were local. This is the topology the lab pair ran on, and the one
# a bank's network team will usually accept, because the protected segment
# makes an outbound connection and accepts none.
#
# Three things are deliberate here:
#
#   * A dedicated sshd on its own port, not the host's. The customer's main
#     sshd is hardened to their standard and audited; adding our forwarding
#     policy to it is a change to a control we do not own. A second daemon with
#     its own config file touches nothing on port 22.
#   * A tunnel-only account with no shell, and authorized_keys options that
#     permit forwarding and nothing else — no pty, no agent, no X11, no command.
#     The key that the SIEM holds cannot be used to run anything here.
#   * PermitListen pinned to one port on the loopback. Even with that key, the
#     SIEM cannot publish an arbitrary service onto this host, and cannot expose
#     it beyond the loopback.
configure_bridge_reverse() {
  blank
  ok "transport: ${B}reverse${R} — the SIEM dials this host"

  ask TUNNEL_SSHD_PORT  "Port for the UEBA-side tunnel daemon (SIEM connects here)" "9022" v_port
  ask TUNNEL_LOCAL_PORT "Loopback port the SIEM's SSH will appear on here"          "2222" v_port
  ask TUNNEL_USER       "Restricted local account for the tunnel"                   "ueba-tunnel" v_user

  SIEM_SSH_HOST="127.0.0.1"
  SIEM_SSH_PORT="$TUNNEL_LOCAL_PORT"

  if ! port_is_free "$TUNNEL_SSHD_PORT"; then
    warn "port ${TUNNEL_SSHD_PORT} is already in use on this host"
    say "${DIM}Pick another, or stop whatever holds it — the tunnel daemon cannot bind it.${R}"
  fi

  if (( DRY_RUN )); then
    note "${DIM}[dry-run]${R} would create user ${TUNNEL_USER}, a dedicated sshd on ${TUNNEL_SSHD_PORT},"
    note "${DIM}[dry-run]${R} a keypair for the SIEM, and a handover bundle under $BASE_DIR/handover"
    return 0
  fi

  mkdir -p "$BASE_DIR/handover"
  chmod 700 "$BASE_DIR/handover"

  # ── 1. the restricted account ──
  local home="/var/lib/${TUNNEL_USER}"
  if id "$TUNNEL_USER" >/dev/null 2>&1; then
    ok "account ${TUNNEL_USER} already exists"
    home="$(getent passwd "$TUNNEL_USER" | cut -d: -f6)"
  else
    local nologin; nologin="$(command -v nologin || echo /usr/sbin/nologin)"
    if useradd --system --create-home --home-dir "$home" --shell "$nologin" "$TUNNEL_USER" >>"$LOGFILE" 2>&1; then
      ok "created tunnel-only account ${TUNNEL_USER} ${GRY}(no shell)${R}"
    else
      die "could not create ${TUNNEL_USER} — create it by hand and re-run"
    fi
  fi
  mkdir -p "$home/.ssh"; chmod 700 "$home/.ssh"

  # ── 2. the key the SIEM will hold ──
  TUNNEL_KEY="/root/.ssh/id_ueba_tunnel"
  if [[ -f "$TUNNEL_KEY" ]]; then
    ok "tunnel keypair exists: $TUNNEL_KEY"
  else
    spin "generating the SIEM-side tunnel keypair" \
      ssh-keygen -t ed25519 -N "" -f "$TUNNEL_KEY" -C "siem-reverse-tunnel@${CLIENT_NAME// /_}" \
      || die "could not generate the tunnel keypair"
  fi

  # restrict disables everything (pty, agent and X11 forwarding, port
  # forwarding, user rc); port-forwarding then re-enables only forwarding, and
  # permitlisten narrows that to the single loopback port we expect.
  local akline="restrict,port-forwarding,permitlisten=\"127.0.0.1:${TUNNEL_LOCAL_PORT}\" $(cat "${TUNNEL_KEY}.pub")"
  touch "$home/.ssh/authorized_keys"
  if grep -qF "$(cut -d' ' -f2 <"${TUNNEL_KEY}.pub")" "$home/.ssh/authorized_keys" 2>/dev/null; then
    ok "tunnel key already authorised for ${TUNNEL_USER}"
  else
    printf '%s\n' "$akline" >>"$home/.ssh/authorized_keys"
    ok "authorised the tunnel key for ${TUNNEL_USER} ${GRY}(forwarding only, one port)${R}"
  fi
  chmod 600 "$home/.ssh/authorized_keys"
  chown -R "${TUNNEL_USER}:${TUNNEL_USER}" "$home/.ssh"

  # ── 3. the dedicated daemon ──
  local sshd_cfg="/etc/ssh/sshd_config.ueba-tunnel"
  cat >"$sshd_cfg" <<EOF
# UEBA reverse-tunnel SSH daemon — generated by install_ueba.sh for ${CLIENT_NAME}
# Deliberately NOT part of /etc/ssh/sshd_config: the host's own daemon is
# hardened and audited to the customer's standard, and this policy is ours.
Port ${TUNNEL_SSHD_PORT}
ListenAddress 0.0.0.0
PidFile /run/sshd-ueba-tunnel.pid

# No HostKey lines on purpose: the defaults are the host's existing keys, so
# this daemon presents the same identity on ${TUNNEL_SSHD_PORT} as the main one
# does on 22. A second set would make the SIEM's known_hosts entry depend on
# which port it reached us on.

AllowUsers ${TUNNEL_USER}
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no

# Forwarding: remote-forwards ONLY — 'remote' refuses -L and -D outright, so
# even a stolen key cannot use this host as a jump box into our network. Pinned
# to the one loopback port we expect to be published.
AllowTcpForwarding remote
GatewayPorts no
PermitListen 127.0.0.1:${TUNNEL_LOCAL_PORT}
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
PermitTunnel no

# Reap a tunnel whose far end has gone away. Without this a half-open tunnel
# keeps the loopback port bound and the bridge blocks in banner exchange
# forever — ConnectTimeout only covers TCP connect.
ClientAliveInterval 30
ClientAliveCountMax 3
TCPKeepAlive yes
LoginGraceTime 30
MaxAuthTries 3
MaxStartups 3:30:10
LogLevel VERBOSE
EOF
  ok "wrote $sshd_cfg"

  if /usr/sbin/sshd -t -f "$sshd_cfg" >>"$LOGFILE" 2>&1; then
    ok "sshd accepts the tunnel config"
  else
    warn "sshd rejected $sshd_cfg — see $LOGFILE"
  fi

  cat >/etc/systemd/system/sshd-ueba-tunnel.service <<EOF
[Unit]
Description=SSH daemon for the UEBA reverse tunnel (port ${TUNNEL_SSHD_PORT}, ${CLIENT_NAME})
Documentation=man:sshd(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /run/sshd
ExecStartPre=/usr/sbin/sshd -t -f ${sshd_cfg}
ExecStart=/usr/sbin/sshd -D -e -f ${sshd_cfg}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >>"$LOGFILE" 2>&1
  spin "starting the tunnel daemon on ${TUNNEL_SSHD_PORT}" \
    systemctl enable --now sshd-ueba-tunnel || warn "tunnel daemon did not start — check journalctl -u sshd-ueba-tunnel"

  # ── 4. firewall ──
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -qi active; then
    if ask_yn "ufw is active — allow ${SIEM_HOST} to reach port ${TUNNEL_SSHD_PORT}?" y; then
      ufw allow from "$SIEM_HOST" to any port "$TUNNEL_SSHD_PORT" proto tcp >>"$LOGFILE" 2>&1 \
        && ok "ufw: allowed ${SIEM_HOST} → ${TUNNEL_SSHD_PORT}/tcp" \
        || warn "ufw rule failed — add it by hand"
    fi
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    note "firewalld is active — allow the tunnel port:"
    say "    ${CYA}firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=${SIEM_HOST} port port=${TUNNEL_SSHD_PORT} protocol=tcp accept' && firewall-cmd --reload${R}"
  else
    note "no active host firewall detected — nothing to open locally"
  fi

  # ── 5. the handover bundle ──
  # The UEBA-side key has to exist before the bundle can quote it, and the
  # bundle is the one artefact the customer's SIEM team will be working from.
  # setup_ssh (step 6) treats an existing key as the key, so generating it here
  # is not a second key.
  if [[ ! -f "$SSH_KEY" ]]; then
    spin "generating the UEBA-side keypair early (for the handover bundle)" \
      ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "ueba@${CLIENT_NAME// /_}" \
      || warn "could not generate $SSH_KEY — the bundle will say so"
  fi

  # The SIEM side cannot be configured from here: it is the customer's host and
  # usually someone else's change request. So everything that side needs is
  # written out as a bundle to hand over, rather than described in a mail.
  local hv="$BASE_DIR/handover/siem-reverse-tunnel"
  mkdir -p "$hv"; chmod 700 "$hv"
  cp "$TUNNEL_KEY" "$hv/id_ueba_tunnel"; chmod 600 "$hv/id_ueba_tunnel"
  cp "${TUNNEL_KEY}.pub" "$hv/id_ueba_tunnel.pub"

  cat >"$hv/ueba-reverse-tunnel.service" <<EOF
# Install on the SIEM host as /etc/systemd/system/ueba-reverse-tunnel.service
#
# Publishes this SIEM's own SSH port onto the UEBA host's loopback, so UEBA can
# pull the enriched feed and the agent registry without anything connecting
# inbound to this machine.
[Unit]
Description=Reverse SSH tunnel to the CyberSentinel UEBA host (${UEBA_HOST})
Documentation=man:ssh(1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# -N: no remote command. -T: no pty. ExitOnForwardFailure: if the loopback port
# is already bound on the UEBA side, fail loudly instead of sitting connected
# with no tunnel — the failure mode that is impossible to diagnose from here.
ExecStart=/usr/bin/ssh -NT \\
  -i /etc/ueba/id_ueba_tunnel \\
  -p ${TUNNEL_SSHD_PORT} \\
  -o ExitOnForwardFailure=yes \\
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\
  -o StrictHostKeyChecking=accept-new -o BatchMode=yes \\
  -R 127.0.0.1:${TUNNEL_LOCAL_PORT}:127.0.0.1:${SIEM_PORT} \\
  ${TUNNEL_USER}@${UEBA_HOST}
Restart=always
RestartSec=15
StartLimitIntervalSec=300
StartLimitBurst=10

[Install]
WantedBy=multi-user.target
EOF

  cat >"$hv/README.txt" <<EOF
CyberSentinel UEBA — reverse tunnel, SIEM-side setup
Generated $(date '+%F %T') for ${CLIENT_NAME}

WHAT THIS IS
  UEBA is installed on ${UEBA_HOST} and needs to read the enriched feed and the
  agent registry from this SIEM. The bank's network policy does not allow an
  inbound connection into the SIEM segment, so the direction is reversed: this
  SIEM makes one outbound SSH connection to the UEBA host and publishes its own
  SSH port on that host's loopback. Nothing connects into this machine.

  SIEM (${SIEM_HOST})  --outbound tcp/${TUNNEL_SSHD_PORT}-->  UEBA (${UEBA_HOST})
  UEBA then reads the SIEM through 127.0.0.1:${TUNNEL_LOCAL_PORT} on its own loopback.

WHAT TO DO ON THIS SIEM HOST  (3 steps, ~5 minutes)

  1. Install the key
       sudo install -d -m 700 /etc/ueba
       sudo install -m 600 id_ueba_tunnel /etc/ueba/id_ueba_tunnel

  2. Install and start the unit
       sudo install -m 644 ueba-reverse-tunnel.service /etc/systemd/system/
       sudo systemctl daemon-reload
       sudo systemctl enable --now ueba-reverse-tunnel
       systemctl status ueba-reverse-tunnel

  3. Authorise UEBA to read this host
     UEBA connects back through the tunnel as ${SIEM_USER}. Append the UEBA
     public key below to ${SIEM_USER}'s ~/.ssh/authorized_keys here:

$(sed 's/^/       /' "${SSH_KEY:-/root/.ssh/id_ueba}.pub" 2>/dev/null || echo "       <run install_ueba.sh step 6 first, then copy /root/.ssh/id_ueba.pub>")

FIREWALL REQUEST FOR THE NETWORK TEAM
  Allow: ${SIEM_HOST}  ->  ${UEBA_HOST}  tcp/${TUNNEL_SSHD_PORT}   (outbound from the SIEM)
  Nothing inbound to ${SIEM_HOST} is required.

WHAT THE KEY CAN DO ON THE UEBA HOST
  Nothing but hold the tunnel open. It is authorised for the account
  '${TUNNEL_USER}', which has no shell, with options
  restrict,port-forwarding,permitlisten="127.0.0.1:${TUNNEL_LOCAL_PORT}" —
  so it cannot run a command, open a terminal, forward anything else, or expose
  the forwarded port off the loopback.

VERIFYING IT WORKS
  On the SIEM:  systemctl is-active ueba-reverse-tunnel
  On UEBA:      ss -ltnp | grep ${TUNNEL_LOCAL_PORT}
                ssh -i ${SSH_KEY:-/root/.ssh/id_ueba} -p ${TUNNEL_LOCAL_PORT} ${SIEM_USER}@127.0.0.1 true

IF IT WILL NOT STAY UP
  'ExitOnForwardFailure=yes' means the tunnel exits rather than running without
  a forward, so a restart loop here usually means port ${TUNNEL_LOCAL_PORT} is
  still bound on the UEBA host by a previous tunnel. On UEBA:
      systemctl restart sshd-ueba-tunnel
EOF
  chmod 600 "$hv/README.txt" "$hv/ueba-reverse-tunnel.service"

  blank
  ok "handover bundle written: ${B}$hv${R}"
  say "    ${DIM}id_ueba_tunnel  — the private key the SIEM needs (transfer it securely)${R}"
  say "    ${DIM}ueba-reverse-tunnel.service — ready to install on the SIEM${R}"
  say "    ${DIM}README.txt      — the three commands, and the firewall request${R}"
  blank
  warn "the SIEM side is not configured yet — it is a different host"
  say "${DIM}Until that unit is running on ${SIEM_HOST}, 127.0.0.1:${TUNNEL_LOCAL_PORT} here is dead,${R}"
  say "${DIM}so discovery and the first sync below will be skipped rather than fail.${R}"
}

port_is_free() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
  else
    return 0
  fi
}

setup_ssh() {
  step "SSH trust"
  SSH_KEY="/root/.ssh/id_ueba"
  if [[ -f "$SSH_KEY" ]]; then
    ok "key exists: $SSH_KEY"
  else
    spin "generating ed25519 keypair" ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "ueba@${CLIENT_NAME// /_}" \
      || die "could not generate an SSH key"
  fi

  # Reverse-tunnel installs reach the SIEM at 127.0.0.1 on the tunnel's port,
  # and only once the SIEM side is up. Everything below uses the effective
  # endpoint rather than the SIEM's own address.
  SIEM_SSH_HOST="${SIEM_SSH_HOST:-$SIEM_HOST}"
  SIEM_SSH_PORT="${SIEM_SSH_PORT:-$SIEM_PORT}"

  blank
  say "${B}Authorise this key on the SIEM${R} (${SIEM_USER}@${SIEM_HOST}):"
  blank
  printf '  %b%s%b\n' "$YEL" "$(cat "${SSH_KEY}.pub" 2>/dev/null || echo '<key unavailable>')" "$R"
  blank
  say "${DIM}Append it to ${SIEM_USER}'s ~/.ssh/authorized_keys on the SIEM.${R}"

  if (( DRY_RUN )); then
    note "${DIM}[dry-run]${R} would offer ssh-copy-id and test the connection"
  elif [[ -n "$UNATTENDED" ]]; then
    note "unattended: assuming the key is already authorised on the SIEM"
  elif [[ "${BRIDGE_MODE:-none}" == "reverse" ]]; then
    # There is nothing to copy the key to yet: the only route to the SIEM is a
    # tunnel the SIEM has not opened. The handover bundle already carries this
    # public key and the instruction to authorise it.
    note "reverse tunnel: authorise it on the SIEM using the handover bundle"
    say "${DIM}  $BASE_DIR/handover/siem-reverse-tunnel/README.txt — step 3${R}"
  elif ask_yn "Try ssh-copy-id now (asks for the SIEM password)?" y; then
    ssh-copy-id -i "${SSH_KEY}.pub" -p "$SIEM_SSH_PORT" "${SIEM_USER}@${SIEM_SSH_HOST}" 2>&1 | tee -a "$LOGFILE" || \
      warn "ssh-copy-id did not complete — authorise the key manually, then continue"
  else
    say "${DIM}Authorise it manually, then press Enter.${R}"; read -r _ || true
  fi

  SSH_BASE=(ssh -i "$SSH_KEY" -p "$SIEM_SSH_PORT"
            -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15)
  if (( DRY_RUN )); then note "${DIM}[dry-run]${R} skipping connectivity test"; return 0; fi
  # Co-located: there is no remote SIEM to reach — this host is it. Testing
  # ssh root@localhost would fail on any host that (sensibly) does not permit
  # it, and the installer would die for a connection it never needs.
  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
    note "co-located: no SSH to the SIEM needed (this host is the SIEM)"
    return 0
  fi
  if "${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_SSH_HOST}" true 2>>"$LOGFILE"; then
    ok "SSH to ${SIEM_USER}@${SIEM_SSH_HOST}:${SIEM_SSH_PORT} works"
    SSH_READY=1
  elif [[ "${BRIDGE_MODE:-none}" == "reverse" ]]; then
    # Not a failure: the far end of the tunnel is a change on someone else's
    # host. Dying here would throw away a correct local install over a step
    # that is explicitly scheduled to happen later.
    SSH_READY=0
    warn "no route to the SIEM yet — the reverse tunnel is not up"
    say "${DIM}Expected at this point. The install continues; discovery and the first${R}"
    say "${DIM}sync are skipped, and both pick themselves up once the tunnel is live.${R}"
  else
    die "SSH failed. Authorise the key above on the SIEM and re-run."
  fi
}

discover() {
  step "Discovery"
  (( DRY_RUN )) && { note "${DIM}[dry-run]${R} skipping discovery"; return 0; }

  # Co-located: the registry is a local file. Reading it through ssh would be
  # a round trip to ourselves, and fails outright where root@localhost is not
  # permitted. The dashboard needs agents.json to turn agent ids into endpoint
  # names — without it every endpoint displays as a bare IP.
  # Reverse tunnel not up yet: there is no route to query. Say what is deferred
  # and how to finish it, rather than failing a step whose precondition is a
  # change on the customer's SIEM.
  if [[ "${SSH_READY:-1}" == "0" ]]; then
    warn "skipping discovery — no route to the SIEM yet"
    say "${DIM}Once the reverse tunnel is up on ${SIEM_HOST}, run:${R}"
    say "    ${CYA}sudo $SELF_DIR/install_ueba.sh --dir $BASE_DIR${R}  ${DIM}(re-runs and picks up here)${R}"
    say "${DIM}The dashboard's agent poller also fills agents.json by itself every 5${R}"
    say "${DIM}minutes once the tunnel answers, so this is self-healing.${R}"
    AGENT_COUNT=0
    return 0
  fi

  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
    if [[ -r "$SIEM_CLIENT_KEYS" ]]; then
      mkdir -p "$BASE_DIR"
      cp "$SIEM_CLIENT_KEYS" "$BASE_DIR/.client.keys.raw" 2>>"$LOGFILE" || true
    else
      warn "cannot read $SIEM_CLIENT_KEYS — endpoints will show as IPs until agents.json exists"
      return 0
    fi
  elif "${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_SSH_HOST}" "test -r '$SIEM_CLIENT_KEYS'" 2>>"$LOGFILE"; then
    # Pull the registry and render agents.json. Counting the agents is not
    # enough: the dashboard reads agents.json to turn agent ids into endpoint
    # NAMES, and without it every endpoint at the customer shows as a bare IP.
    mkdir -p "$BASE_DIR"
    "${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_SSH_HOST}" "cat '$SIEM_CLIENT_KEYS'" 2>>"$LOGFILE" \
      >"$BASE_DIR/.client.keys.raw" || true
    AGENT_COUNT="$(python3 - "$BASE_DIR/.client.keys.raw" "$BASE_DIR/agents.json" <<'PYEOF'
import json, os, sys
raw_path, out_path = sys.argv[1], sys.argv[2]
agents, seen = [], set()
try:
    for line in open(raw_path, encoding="utf-8", errors="replace"):
        # SIEM client.keys: "<id> <name> <ip|any> <key>"
        parts = line.split()
        if len(parts) < 3 or not parts[0].strip().isdigit():
            continue
        aid, name, ip = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if aid in seen or name.startswith("!"):      # "!" marks a removed agent
            continue
        seen.add(aid)
        agents.append({"id": aid, "name": name,
                       "ip": "" if ip.lower() == "any" else ip, "os": ""})
except FileNotFoundError:
    pass
# Merge rather than clobber: a re-install must not discard the `os` field, which
# client.keys does not carry and an operator may have filled in by hand.
if os.path.exists(out_path):
    try:
        prev = {a.get("id"): a for a in json.load(open(out_path)) if isinstance(a, dict)}
        for a in agents:
            old = prev.get(a["id"])
            if old:
                a["os"] = old.get("os") or a["os"]
                a["ip"] = a["ip"] or old.get("ip", "")
    except Exception:
        pass
json.dump(agents, open(out_path, "w"), indent=2)
print(len(agents))
PYEOF
)"
    rm -f "$BASE_DIR/.client.keys.raw"
    if [[ "${AGENT_COUNT:-0}" -gt 0 ]]; then
      ok "agent registry fetched — ${B}${AGENT_COUNT}${R} endpoints written to agents.json"
      say "    ${DIM}$(python3 -c "
import json
a = json.load(open('$BASE_DIR/agents.json'))
print(', '.join(x['name'] for x in a[:5]) + (' ...' if len(a) > 5 else ''))" 2>/dev/null)${R}"
    else
      warn "registry parsed to 0 agents — endpoints will show as bare IPs"
    fi
  else
    AGENT_COUNT=0
    warn "cannot read $SIEM_CLIENT_KEYS — endpoint names will be blank until fixed"
  fi

  if "${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_SSH_HOST}" "test -d '$SIEM_ENRICHED_DIR'" 2>>"$LOGFILE"; then
    local n sz
    n="$("${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_SSH_HOST}" "ls -1 '$SIEM_ENRICHED_DIR' 2>/dev/null | wc -l")"
    sz="$("${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_SSH_HOST}" "du -sh '$SIEM_ENRICHED_DIR' 2>/dev/null | cut -f1")"
    ok "enriched logs found — ${B}${n}${R} files, ${B}${sz:-?}${R}"
  elif [[ "${FEED_MODE:-files}" == "kafka" ]]; then
    # The feed is the topic, not the directory. The directory is only a
    # reference for backfill, so its absence is a note, not a stop.
    warn "enriched directory $SIEM_ENRICHED_DIR not found — the feed is Kafka, so this only affects backfill"
  else
    die "enriched directory $SIEM_ENRICHED_DIR not found on the SIEM"
  fi
}

render_config() {
  step "Configuration"
  (( DRY_RUN )) && { note "${DIM}[dry-run]${R} would write $BASE_DIR/ueba_config.yaml"; return 0; }

  mkdir -p "$BASE_DIR"/{logs,.state,archive,profiles,models,databases} "$DATA_DIR"

  # Bridge settings live in their own env file so the shipped bridge script stays
  # generic — no per-site edits to versioned code.
  cat >"$BASE_DIR/ueba_site.env" <<EOF
# Site-specific settings for $CLIENT_NAME — generated $(date '+%F %T')
# Sourced by ueba_sync_bridge.sh and the systemd units.
UEBA_BASE="$BASE_DIR"
UEBA_DATA="$DATA_DIR"
#
# SOC_HOST/SOC_PORT are the EFFECTIVE endpoint, not the SIEM's own address. On
# a reverse-tunnel install they are 127.0.0.1 and the tunnel's loopback port,
# because that is where the SIEM is reachable from this host. The SIEM's real
# address is recorded below for the record and for the runbook.
SOC_HOST="${SIEM_USER}@${SIEM_SSH_HOST}"
SOC_PORT="$SIEM_SSH_PORT"
SOC_SSH_KEY="$SSH_KEY"
SOC_ENRICHED_DIR="$SIEM_ENRICHED_DIR"
SOC_CLIENT_KEYS="$SIEM_CLIENT_KEYS"
UEBA_SELF_IP="$SELF_IP"
UEBA_HOST_ADDR="$UEBA_HOST"
UEBA_DASH_PORT="$DASH_PORT"
SIEM_ADDR="$SIEM_HOST"
SIEM_SSH_PORT_REAL="$SIEM_PORT"
UEBA_BRIDGE_MODE="${BRIDGE_MODE:-none}"
UEBA_FEED_MODE="${FEED_MODE:-files}"
EOF
  chmod 600 "$BASE_DIR/ueba_site.env"
  ok "wrote ueba_site.env"

  if [[ -f "$SELF_DIR/ueba_config.yaml" ]]; then
    cp "$SELF_DIR/ueba_config.yaml" "$BASE_DIR/ueba_config.yaml"
    # Point every absolute path at this install, and suppress this host's own IP.
    sed -i \
      -e "s#/root/NEW_DRIVE/aditya_ueba#${BASE_DIR}#g" \
      -e "s#^\(\s*host:\s*\).*#\1\"${DASH_HOST}\"#" \
      -e "s#^\(\s*port:\s*\)3026.*#\1${DASH_PORT}#" \
      "$BASE_DIR/ueba_config.yaml"
    # Swap the lab engine IP for this site's. Without it the wrong address is
    # suppressed and this server's own sync/SSH traffic scores as alerts against
    # the estate it is supposed to be watching. (These keys only take effect
    # because apply_noise_config() now reads them — before, they were inert.)
    # Stamp the header so an operator opening the file knows whose install it is.
    sed -i -e "1,5s|^# CyberSentinel UEBA Engine .*|# CyberSentinel UEBA Engine — Configuration — ${CLIENT_NAME} (${SELF_IP})|" \
      "$BASE_DIR/ueba_config.yaml"
    # '|' as the delimiter: the replacement carries a '#' comment, which would
    # otherwise terminate the expression.
    sed -i -e "s|^\(\s*-\s*\)\"164\.52\.194\.98\".*|\1\"${SELF_IP}\"   # this UEBA server|" \
      "$BASE_DIR/ueba_config.yaml"
    # Three dashboard paths are NOT in the shipped YAML and fall back to values
    # baked into ueba_dashboard_server.py, which point at the lab install. Left
    # alone, a customer dashboard would look for its archives and its live feed
    # under /root/NEW_DRIVE/aditya_ueba and silently find nothing: no history in
    # the timeline windows, and the stale-feed banner never firing. Write them
    # explicitly. Inserted as text so the file keeps its comments.
    # Co-located: agent discovery must read the registry locally. SSHing to
    # localhost fails wherever root@localhost is not permitted, and the only
    # symptom is endpoints rendering as bare IPs because agents.json is never
    # written — nothing in the UI explains it.
    if [[ "${CO_LOCATED:-0}" == "1" ]]; then
      python3 - "$BASE_DIR/ueba_config.yaml" "$AGENT_LOCAL_CMD" >>"$LOGFILE" 2>&1 <<'APYEOF'
import re, sys
cfg, cmd = sys.argv[1], sys.argv[2]
text = open(cfg, encoding="utf-8").read()
if "agent_sync:" in text:
    text = re.sub(r'(?m)^(\s*)(enabled:\s*true\s*)$',
                  lambda m: m.group(0), text, count=0)
    # Insert mode + local_command directly under the agent_sync: key.
    text = re.sub(
        r'(?m)^(\s*)agent_sync:\s*$',
        lambda m: '%sagent_sync:\n%s  mode:               "local"\n%s  local_command:      "%s"'
                  % (m.group(1), m.group(1), m.group(1), cmd),
        text, count=1)
    open(cfg, "w", encoding="utf-8").write(text)
    print("agent_sync set to local mode: %s" % cmd)
else:
    print("no agent_sync block in config; code defaults apply")
APYEOF
      ok "agent discovery will read the registry locally"
    fi

    # Switch the engine off file-tailing and onto the topic. Keyed on the FEED,
    # not on the topology: a separate host consuming the broker through an SSH
    # local-forward wants exactly the same config, with brokers pointed at the
    # forwarded loopback port instead of the SIEM's own.
    if [[ "${FEED_MODE:-files}" == "kafka" ]]; then
      python3 - "$BASE_DIR/ueba_config.yaml" \
        "$KAFKA_BROKERS" "$KAFKA_TOPIC" "$KAFKA_GROUP" >>"$LOGFILE" 2>&1 <<'KPYEOF'
import re, sys
cfg, brokers, topic, group = sys.argv[1:5]
text = open(cfg, encoding="utf-8").read()
# streaming.source and the three kafka keys all already exist in the shipped
# YAML with safe defaults, so this edits in place and keeps the comments.
text = re.sub(r'(?m)^(\s*source:\s*)file\b', r'\1kafka', text, count=1)
text = re.sub(r'(?m)^(\s*brokers:\s*).*', r'\1"%s"' % brokers, text, count=1)
text = re.sub(r'(?m)^(\s*topic:\s*).*',   r'\1"%s"' % topic,   text, count=1)
text = re.sub(r'(?m)^(\s*group:\s*).*',   r'\1"%s"' % group,   text, count=1)
open(cfg, "w", encoding="utf-8").write(text)
print("config: streaming.source=kafka brokers=%s topic=%s group=%s"
      % (brokers, topic, group))
KPYEOF
      ok "engine will consume Kafka topic '$KAFKA_TOPIC' as group '$KAFKA_GROUP'"
    fi

    python3 - "$BASE_DIR/ueba_config.yaml" "$BASE_DIR" >>"$LOGFILE" 2>&1 <<'PYEOF'
import sys
cfg_path, base = sys.argv[1], sys.argv[2]
lines = open(cfg_path, encoding="utf-8").read().splitlines(True)
need = {
    "fp_patterns_file": f'{base}/fp_patterns.json',
    "archive_dir":      f'{base}/archive',
    "enriched_file":    f'{base}/enriched.jsonl',
}
present = set()
in_dash = False
for ln in lines:
    if ln.startswith("dashboard:"):
        in_dash = True
        continue
    if in_dash:
        if ln[:1] not in (" ", "\t", "\n", "#"):
            in_dash = False
            continue
        key = ln.strip().split(":", 1)[0]
        if key in need:
            present.add(key)
missing = {k: v for k, v in need.items() if k not in present}
if missing:
    out, done = [], False
    for ln in lines:
        out.append(ln)
        if not done and ln.startswith("dashboard:"):
            out.append("  # Written by install_ueba.sh — without these the code\n")
            out.append("  # falls back to the lab install paths.\n")
            for k, v in missing.items():
                out.append(f'  {k}: "{v}"\n')
            done = True
    open(cfg_path, "w", encoding="utf-8").write("".join(out))
print("added:", ", ".join(missing) if missing else "nothing (all present)")
PYEOF
    # Point the dashboard's agent poller at this customer's SIEM and switch it
    # on, so endpoints enrolled after install pick up their names automatically
    # instead of needing a re-install.
    # Skipped when co-located: the local-mode block written above already tells
    # the poller to read the registry with a local command, and this one would
    # replace it with an SSH poll to localhost — which fails wherever
    # root@localhost is not permitted, leaving endpoints as bare IPs with
    # nothing in the UI to explain why.
    if [[ "${CO_LOCATED:-0}" != "1" ]]; then
    python3 - "$BASE_DIR/ueba_config.yaml" "${SIEM_USER}@${SIEM_SSH_HOST}" "$SIEM_SSH_PORT" \
             "$SSH_KEY" "$SIEM_CLIENT_KEYS" >>"$LOGFILE" 2>&1 <<'PYEOF'
import re, sys
cfg, host, port, key, keys_path = sys.argv[1:6]
text = open(cfg, encoding="utf-8").read()
block = (f'  agent_sync:\n'
         f'    enabled:            true\n'
         f'    poll_interval_secs: 300\n'
         f'    ssh_host:           "{host}"\n'
         f'    ssh_port:           {port}\n'
         f'    ssh_key:            "{key}"\n'
         f'    remote_command:     "cat {keys_path}"\n'
         f'    ssh_timeout_secs:   20\n')
# Replace the existing agent_sync block (any indented lines under it), else add.
pat = re.compile(r'^  agent_sync:\n(?:    .*\n|\n)*', re.M)
text = pat.sub(block, text) if pat.search(text) else \
       text.replace("dashboard:\n", "dashboard:\n" + block, 1)
open(cfg, "w", encoding="utf-8").write(text)
print("agent_sync enabled")
PYEOF
    fi
    ok "rendered ueba_config.yaml for this site"
  else
    warn "template ueba_config.yaml not found beside the installer"
  fi

  # Every module the engine or dashboard imports has to be here. This list was
  # previously short of six of them — ueba_watchlist, ueba_notify and the three
  # reporting modules among them — so an install produced a deployment with no
  # watch lists, no notifications and no reporting engine, all of which are
  # RFP commitments. The verify step below is what stops that recurring: it
  # checks the copied tree against what the code actually imports, rather than
  # trusting this list to stay in sync by hand.
  for f in ueba_engine.py ueba_preprocessor.py ueba_trainer.py ueba_dashboard_server.py \
           ueba_auth.py ueba_prepare_training_data.py ueba_validate_models.py \
           ueba_source.py ueba_identity.py ueba_watchlist.py ueba_notify.py \
           ueba_nicknames.py ueba_egress.py ueba_risk_history.py \
           ueba_privilege.py ueba_assets.py build_faiss_seed.py \
           ueba_reports.py ueba_report_render.py ueba_report_store.py ueba_mailer.py \
           ueba_housekeeping.py ueba_prune_corpus.py identity_diag.py \
           enrich_parallel.py retrain.py requirements.txt \
           ueba_sync_bridge.sh ueba_rotate.sh ueba_weekly_retrain.sh \
           ueba_bootstrap_training.sh \
           ueba-engine-watchdog.sh pipeline_status.sh preflight_probe.sh \
           check_dependencies.sh; do
    # check_dependencies.sh travels with the install, not just with the media:
    # after the venv exists it is the verifier for it —
    #     /opt/ueba/check_dependencies.sh --venv /opt/ueba/venv --strict
    # which is the one command that proves every declared requirement is
    # present at a version it is allowed to be.
    [[ -f "$SELF_DIR/$f" ]] && cp "$SELF_DIR/$f" "$BASE_DIR/$f"
  done
  [[ -d "$SELF_DIR/ueba_models" ]] && cp -r "$SELF_DIR/ueba_models" "$BASE_DIR/"
  [[ -d "$SELF_DIR/dashboard"   ]] && cp -r "$SELF_DIR/dashboard"   "$BASE_DIR/"
  chmod +x "$BASE_DIR"/*.sh 2>/dev/null || true
  ok "copied application files"
  verify_modules
}

verify_modules() {
  # Resolve every `import ueba_*` in the copied tree against the copied tree.
  # A missing module is fatal: the engine would die on its first import, and a
  # lazily-imported one (the dashboard imports reporting inside the request
  # handler) would instead fail silently at the moment a customer clicks the
  # button. Better to refuse to install than to ship that.
  local missing=()
  local mods
  mods="$(grep -rhoE '\bueba_[a-z_]+' "$BASE_DIR"/*.py 2>/dev/null | sort -u)"
  local m
  for m in $mods; do
    [[ -f "$SELF_DIR/$m.py" ]] || continue          # not a module of ours
    [[ -f "$BASE_DIR/$m.py" ]] || missing+=("$m.py")
  done
  if (( ${#missing[@]} )); then
    bad "these modules are imported but were not copied: ${missing[*]}"
    die "install aborted — add them to the copy list in install_units' caller"
  fi
  ok "verified every imported module is present ($(echo "$mods" | wc -w | tr -d ' ') checked)"
}

setup_runtime() {
  step "Runtime"
  (( DRY_RUN )) && { note "${DIM}[dry-run]${R} would build the venv"; return 0; }

  if [[ ! -x "$BASE_DIR/venv/bin/python" ]]; then
    spin "creating virtualenv" python3 -m venv "$BASE_DIR/venv" || die "venv creation failed"
  else
    ok "venv already present"
  fi

  spin "upgrading pip" "$BASE_DIR/venv/bin/pip" install -q --upgrade pip || warn "pip upgrade failed"

  # CPU wheels on purpose: measured on the lab box, the per-entity autoencoder
  # trains in 0.14s on one CPU thread vs 0.5s on a shared L40S, and 99% of a
  # retrain is disk I/O rather than compute. The CUDA wheels are ~2.5 GB and buy
  # nothing here. Install torch first so the CPU index wins over any CUDA pin.
  spin "installing torch (CPU build)" \
    "$BASE_DIR/venv/bin/pip" install -q torch --index-url https://download.pytorch.org/whl/cpu \
    || warn "torch install failed — check $LOGFILE"
  spin "installing faiss-cpu" "$BASE_DIR/venv/bin/pip" install -q faiss-cpu || warn "faiss-cpu install failed"

  if [[ -f "$BASE_DIR/requirements.txt" ]]; then
    # Drop GPU-only pins; they are replaced by the CPU wheels above.
    grep -viE '^(torch|faiss-gpu)' "$BASE_DIR/requirements.txt" >"$BASE_DIR/.req.cpu" || true
    spin "installing python dependencies" "$BASE_DIR/venv/bin/pip" install -q -r "$BASE_DIR/.req.cpu" \
      || warn "some dependencies failed — see $LOGFILE"
    rm -f "$BASE_DIR/.req.cpu"
  fi

  # Torch defaults to one thread per core. On a 60-core box that made the tiny
  # 35->24->12 autoencoder 200x SLOWER (29s per entity vs 0.14s) purely from
  # thread contention, so pin it low for every UEBA process.
  cat >"$BASE_DIR/ueba_runtime.env" <<'EOF'
OMP_NUM_THREADS=2
MKL_NUM_THREADS=2
OPENBLAS_NUM_THREADS=2
TORCH_NUM_THREADS=2
EOF
  ok "pinned BLAS/torch threads (prevents the 200x thread-thrash)"

  install_units
}

install_units() {
  local py="$BASE_DIR/venv/bin/python3"

  # A Kafka feed has no bridge: the engine reads the topic, so a sync bridge
  # would be a second copy of data the engine is already consuming. That is
  # true of a co-located install and equally true of a separate install reading
  # the broker through the forward tunnel.
  local services="engine dashboard bridge"
  if [[ "${FEED_MODE:-files}" == "kafka" ]]; then
    services="engine dashboard"
    rm -f /etc/systemd/system/ueba-bridge.service
  fi

  for svc in $services; do
    local exec desc mem cpu
    case "$svc" in
      engine)    desc="CyberSentinel UEBA Engine";    exec="$py $BASE_DIR/ueba_engine.py --config $BASE_DIR/ueba_config.yaml"
                 mem="$MEM_ENGINE";    cpu="400%" ;;
      dashboard) desc="CyberSentinel UEBA Dashboard"; exec="$py $BASE_DIR/ueba_dashboard_server.py --config $BASE_DIR/ueba_config.yaml"
                 mem="$MEM_DASHBOARD"; cpu="200%" ;;
      bridge)    desc="CyberSentinel UEBA Sync Bridge"; exec="/bin/bash $BASE_DIR/ueba_sync_bridge.sh"
                 mem="2G";             cpu="100%" ;;
    esac
    cat >"/etc/systemd/system/ueba-${svc}.service" <<EOF
[Unit]
Description=$desc ($CLIENT_NAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$BASE_DIR
EnvironmentFile=$BASE_DIR/ueba_site.env
EnvironmentFile=$BASE_DIR/ueba_runtime.env
ExecStart=$exec
Restart=always
RestartSec=10
# A config error should stop and stay stopped; only a crash deserves retrying.
# Without this a bad argument respawns every 10s forever and buries the real
# error in a log full of identical usage messages.
StartLimitIntervalSec=300
StartLimitBurst=5
MemoryMax=$mem
CPUQuota=$cpu
StandardOutput=append:$BASE_DIR/logs/ueba_${svc}.stdout.log
StandardError=append:$BASE_DIR/logs/ueba_${svc}.stdout.log

[Install]
WantedBy=multi-user.target
EOF
  done
  install_watchdog
  systemctl daemon-reload >>"$LOGFILE" 2>&1
  ok "installed systemd units (ueba-engine, ueba-dashboard, ueba-bridge, watchdog)"
  install_cron
}

install_watchdog() {
  # The engine pauses for minutes at a time under load and usually recovers on
  # its own; when it does not, nothing else notices. The watchdog captures
  # forensics and restarts only if the engine is still frozen after a
  # confirmation window. Without it a wedged engine stays wedged until someone
  # looks at the dashboard and sees a stale feed.
  [[ -f "$SELF_DIR/ueba-engine-watchdog.sh" ]] || {
    warn "ueba-engine-watchdog.sh not found beside the installer — skipping watchdog"
    return 0
  }
  install -m 755 "$SELF_DIR/ueba-engine-watchdog.sh" /usr/local/bin/ueba-engine-watchdog.sh

  # UEBA_SITE_ENV is passed explicitly: the script looks for ueba_site.env beside
  # ITSELF, and it lives in /usr/local/bin, not in the install directory.
  cat >/etc/systemd/system/ueba-engine-watchdog.service <<EOF
[Unit]
Description=CyberSentinel UEBA engine liveness watchdog ($CLIENT_NAME)
After=ueba-engine.service

[Service]
Type=oneshot
Environment=UEBA_SITE_ENV=$BASE_DIR/ueba_site.env
ExecStart=/usr/local/bin/ueba-engine-watchdog.sh
StandardOutput=null
StandardError=journal
EOF

  cat >/etc/systemd/system/ueba-engine-watchdog.timer <<EOF
[Unit]
Description=Run the CyberSentinel UEBA engine watchdog every 2 minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec=2min
AccuracySec=15s
Unit=ueba-engine-watchdog.service

[Install]
WantedBy=timers.target
EOF
  ok "installed engine watchdog (service + 2-minute timer)"
}

install_cron() {
  # Two scheduled jobs do the work that keeps UEBA alive between restarts:
  #   00:05 daily  — rotate alerts into archive/, cap the enriched input buffer
  #   03:30 Sunday — pull a weekly training snapshot, re-prepare features, retrain
  # Without these the dashboard loses history and the models never learn the
  # customer's own users, so they are part of the install, not an afterthought.
  #
  # Written as a marked block so re-running replaces only our lines and never
  # disturbs anything else already in root's crontab.
  local marker_a="# >>> cybersentinel-ueba >>>"
  local marker_b="# <<< cybersentinel-ueba <<<"
  local tmp; tmp="$(mktemp)"
  crontab -l 2>/dev/null | sed "/${marker_a}/,/${marker_b}/d" >"$tmp" || true
  cat >>"$tmp" <<EOF
$marker_a
# Managed by install_ueba.sh — edits inside this block are overwritten on re-install.
5 0 * * *   $BASE_DIR/ueba_rotate.sh >> $BASE_DIR/logs/rotate.log 2>&1
30 3 * * 0  $BASE_DIR/ueba_weekly_retrain.sh >> $BASE_DIR/logs/weekly_retrain.log 2>&1
$marker_b
EOF
  if crontab "$tmp" 2>>"$LOGFILE"; then
    ok "scheduled daily rotation (00:05) and weekly retrain (Sun 03:30)"
  else
    warn "could not install crontab — add these two lines manually:"
    say "${DIM}  5 0 * * *  $BASE_DIR/ueba_rotate.sh${R}"
    say "${DIM}  30 3 * * 0 $BASE_DIR/ueba_weekly_retrain.sh${R}"
  fi
  rm -f "$tmp"
}

bring_up() {
  step "Bring-up"
  if (( DRY_RUN )); then
    if [[ "${FEED_MODE:-files}" == "kafka" ]]; then
      note "${DIM}[dry-run]${R} would: start dashboard + engine (no bridge; engine reads Kafka)"
    else
      note "${DIM}[dry-run]${R} would: start ueba-bridge, optionally train, start dashboard + engine"
    fi
    return 0
  fi

  # The forward tunnel carries the feed, so it comes up before anything that
  # depends on it.
  if [[ -f /etc/systemd/system/ueba-tunnel.service ]]; then
    spin "starting the Kafka forward tunnel" systemctl enable --now ueba-tunnel \
      || warn "ueba-tunnel did not start — the engine will have no source until it does"
  fi

  if [[ "${FEED_MODE:-files}" == "kafka" ]]; then
    say "  ${DIM}feed is the Kafka topic — no sync bridge (it would duplicate data)${R}"
  elif [[ "${SSH_READY:-1}" == "0" ]]; then
    warn "not starting the sync bridge — there is no route to the SIEM yet"
    say "${DIM}Start it once the reverse tunnel is up on ${SIEM_HOST}:${R}"
    say "    ${CYA}systemctl enable --now ueba-bridge${R}"
  elif ask_yn "Pull an initial batch of logs from the SIEM now?" y; then
    spin "starting sync bridge" systemctl enable --now ueba-bridge || warn "bridge did not start"
  fi

  blank
  say "${B}Behavioural baseline${R}"
  say "${DIM}Models cannot ship with the product. Each autoencoder is keyed to a${R}"
  say "${DIM}specific username, and thresholds are fitted to one estate's score${R}"
  say "${DIM}distribution — so ${CLIENT_NAME}'s baseline has to be learned from${R}"
  say "${DIM}${CLIENT_NAME}'s own traffic. That needs a few days of logs first.${R}"
  blank

  spin "starting dashboard" systemctl enable --now ueba-dashboard || warn "dashboard did not start"

  # The engine hard-fails without models/global.pt + thresholds.json, so only
  # offer to start it when a baseline actually exists. Starting it on a fresh
  # site would just crash-loop under systemd Restart=always.
  if [[ -f "$BASE_DIR/models/autoencoders/global.pt" && -f "$BASE_DIR/models/thresholds.json" ]]; then
    ok "baseline found — the engine can run"
    if ask_yn "Start the detection engine now?" y; then
      spin "starting engine" systemctl enable --now ueba-engine || warn "engine did not start"
      # Only arm the watchdog once the engine is actually running — otherwise it
      # spends every 2 minutes "restarting" a service nobody has started yet.
      systemctl enable --now ueba-engine-watchdog.timer >>"$LOGFILE" 2>&1 \
        && ok "engine watchdog armed (every 2 min)" \
        || warn "watchdog timer did not start"
    fi
  else
    note "no baseline yet — leaving the engine stopped (it would crash-loop without models)"
    blank
    say "  ${B}To build it once logs have accumulated:${R}"
    say "    ${CYA}$BASE_DIR/ueba_bootstrap_training.sh${R}          ${DIM}check readiness${R}"
    say "    ${CYA}$BASE_DIR/ueba_bootstrap_training.sh --train${R}  ${DIM}build the baseline${R}"
    say "    ${DIM}then:${R} systemctl enable --now ueba-engine"
    blank
    say "  ${DIM}The weekly job (Sun 03:30) also does this automatically once${R}"
    say "  ${DIM}there is enough history.${R}"
  fi
}

summary() {
  blank
  rule
  blank
  # Box drawn by padding the label to a fixed inner width so the right edge
  # always lines up, whatever the client name is.
  local label="UEBA is installed for ${CLIENT_NAME}" inner=58 pad
  (( ${#label} > inner )) && label="${label:0:inner}"
  # inner width = leading space + label + pad + trailing space, so subtract the 2 spaces
  pad=$(( inner - ${#label} - 2 ))
  (( pad < 0 )) && pad=0
  printf '  %b╭%s╮%b\n' "$GRN" "$(printf '─%.0s' $(seq 1 $inner))" "$R"
  printf '  %b│%b %b%s%b%*s %b│%b\n' "$GRN" "$R" "$B$GRN" "$label" "$R" "$pad" "" "$GRN" "$R"
  printf '  %b╰%s╯%b\n' "$GRN" "$(printf '─%.0s' $(seq 1 $inner))" "$R"
  blank
  # A loopback bind is not reachable at the host's own address, so printing
  # that URL would send an operator to a connection refused. Say how to get
  # there instead.
  if [[ "$DASH_HOST" == "127.0.0.1" || "$DASH_HOST" == "localhost" ]]; then
    say "${B}Dashboard${R}    http://127.0.0.1:${DASH_PORT} ${GRY}(loopback only)${R}"
    say "${DIM}             reach it with: ssh -L ${DASH_PORT}:127.0.0.1:${DASH_PORT} root@${SELF_IP}${R}"
  else
    say "${B}Dashboard${R}    http://${SELF_IP}:${DASH_PORT}"
  fi
  say "${B}Install dir${R}  $BASE_DIR"
  say "${B}Data dir${R}     $DATA_DIR"
  say "${B}SIEM${R}         ${SIEM_USER}@${SIEM_HOST}:${SIEM_PORT}"
  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
    say "${B}Topology${R}     same server as the SIEM ${GRY}(derived from the addresses given)${R}"
  else
    say "${B}Topology${R}     separate servers — bridge transport: ${B}${BRIDGE_MODE:-direct}${R}"
    [[ "${BRIDGE_MODE:-}" == "reverse" ]] && \
      say "${B}Tunnel${R}       SIEM → ${UEBA_HOST}:${TUNNEL_SSHD_PORT}, appears here as 127.0.0.1:${TUNNEL_LOCAL_PORT}"
  fi
  if [[ "${FEED_MODE:-files}" == "kafka" ]]; then
    say "${B}Feed${R}         kafka ${KAFKA_BROKERS}/${KAFKA_TOPIC} as group ${KAFKA_GROUP}"
  else
    say "${B}Feed${R}         rotated enriched chunks over SSH ${GRY}(ueba-bridge)${R}"
  fi
  [[ -n "${AGENT_COUNT:-}" ]] && say "${B}Endpoints${R}    ${AGENT_COUNT} discovered"
  blank
  rule
  say "${B}Service control${R}"
  local units="ueba-engine ueba-dashboard"
  [[ "${FEED_MODE:-files}" == "files" ]] && units+=" ueba-bridge"
  [[ -f /etc/systemd/system/ueba-tunnel.service ]] && units+=" ueba-tunnel"
  [[ "${BRIDGE_MODE:-}" == "reverse" ]] && units+=" sshd-ueba-tunnel"
  say "  systemctl status $units"
  say "  journalctl -u ueba-engine -f"

  # The one outstanding action, printed where it cannot be missed: a
  # reverse-tunnel install is not finished until a change lands on the SIEM.
  if [[ "${BRIDGE_MODE:-}" == "reverse" ]]; then
    blank
    rule
    say "${B}${YEL}Outstanding — the SIEM side${R}"
    say "  Nothing flows until the tunnel unit is running on ${B}${SIEM_HOST}${R}."
    say "  Hand this bundle to whoever owns that host:"
    say "    ${CYA}$BASE_DIR/handover/siem-reverse-tunnel/${R}"
    say "  ${DIM}It contains the key, the systemd unit, the three commands and the${R}"
    say "  ${DIM}firewall request (outbound SIEM → ${UEBA_HOST}:${TUNNEL_SSHD_PORT}, nothing inbound).${R}"
    say "  Then, back here:  ${CYA}systemctl enable --now ueba-bridge${R}"
  fi
  blank
  say "${B}Next${R}"
  if [[ "${FEED_MODE:-files}" == "kafka" ]]; then
    # No bridge to wait on: events arrive from Kafka the moment the engine
    # starts. What there is to wait for is enough history to train on.
    say "  1. Confirm intake:  docker exec siem-kafka kafka-consumer-groups \\"
    say "       --bootstrap-server localhost:9092 --describe --group ${KAFKA_GROUP}"
    say "  2. Let ${B}3 weeks${R} of history accumulate (profile_store window is 21 days)"
    say "  3. Run ${B}$BASE_DIR/ueba_weekly_retrain.sh${R} to rebuild the baseline"
  else
    say "  1. Let the bridge collect ${B}3-7 days${R} of logs"
    say "  2. Run ${B}$BASE_DIR/ueba_weekly_retrain.sh${R} to build the baseline"
    say "  3. Alerts appear on the dashboard once models exist"
  fi
  blank
  say "${DIM}Install log: $LOGFILE${R}"
  # Both of these are acceptance evidence: the stage-1 report is what shows the
  # host met its prerequisites at install time, and it is a file, not a scroll
  # of terminal output someone has to remember to copy.
  [[ -n "${DEPCHECK_REPORT:-}" ]] && say "${DIM}Dependency report: $DEPCHECK_REPORT${R}"
  say "${DIM}Re-verify the venv any time: $BASE_DIR/check_dependencies.sh --venv $BASE_DIR/venv --strict${R}"
  blank
}

# ── Main ──────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)    DRY_RUN=1; shift ;;
    --unattended) UNATTENDED="${2:-}"; [[ -f "$UNATTENDED" ]] && . "$UNATTENDED"; shift 2 ;;
    # The install directory, named on the command line. Recorded in PRESET so
    # collect_local states it instead of offering to change it.
    --dir|--install-dir)
                  BASE_DIR="${2:?--dir needs an absolute path}"
                  PRESET[BASE_DIR]=1; shift 2 ;;
    --data-dir)   DATA_DIR="${2:?--data-dir needs an absolute path}"
                  PRESET[DATA_DIR]=1; shift 2 ;;
    --siem)       _v="${2:?--siem needs host[:port]}"
                  if [[ "$_v" == *:* ]]; then SIEM_HOST="${_v%:*}"; SIEM_PORT="${_v##*:}"
                  else SIEM_HOST="$_v"; fi
                  PRESET[SIEM_HOST]=1; shift 2 ;;
    --dash)       _v="${2:?--dash needs addr[:port]}"
                  if [[ "$_v" == *:* ]]; then UEBA_HOST="${_v%:*}"; DASH_PORT="${_v##*:}"
                  else UEBA_HOST="$_v"; fi
                  PRESET[UEBA_HOST]=1; PRESET[DASH_PORT]=1; shift 2 ;;
    --bridge)     BRIDGE_MODE_PRESET="${2:?--bridge needs direct|reverse}"; shift 2 ;;
    --wheelhouse) WHEELHOUSE="${2:?--wheelhouse needs a directory}"; shift 2 ;;
    --skip-depcheck) SKIP_DEPCHECK=1; shift ;;
    -h|--help)    sed -n '2,41p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; echo "try --help" >&2; exit 2 ;;
  esac
done

# An absolute path is a precondition of everything downstream, and finding out
# at mkdir time produces a half-made tree relative to the current directory.
for _d in BASE_DIR DATA_DIR; do
  [[ -n "${!_d:-}" && "${!_d}" != /* ]] && { echo "$_d must be an absolute path: ${!_d}" >&2; exit 2; }
done

banner
(( DRY_RUN )) && { warn "DRY RUN — nothing will be changed"; blank; }
say "${DIM}Logging to $LOGFILE${R}"

preflight           # 1  dependencies (stage 1)
collect_endpoints   # 2  SIEM + UEBA addresses, topology derived from them
collect_site        # 3  client, feed source, SIEM paths
collect_local       # 4  install dir, data dir, caps
configure_bridge    # 5  transport: none / direct / reverse tunnel
setup_ssh           # 6
discover            # 7
render_config       # 8
setup_runtime       # 9
bring_up            # 10
summary
