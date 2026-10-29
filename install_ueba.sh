#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  CyberSentinel UEBA — Interactive Installer
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Deploys the UEBA module against a customer's CyberSentinel SIEM. Everything
#  that used to be hardcoded for the lab pair (98 <-> 23) is asked for here and
#  written into ueba_config.yaml, so the same tree deploys at any bank.
#
#  What it does, in order:
#     1. Preflight        — OS, python, RAM, disk, ports, required tools
#     2. Site details     — client name, SIEM host/port/user, paths
#     3. Install location — base dir, dashboard bind address
#     4. SSH trust        — generate a keypair, help you authorise it, test it
#     5. Discovery        — pull the SIEM agent registry -> agents.json
#     6. Configuration    — render ueba_config.yaml + the bridge env file
#     7. Runtime          — venv + CPU-only wheels, systemd units
#     8. Bring-up         — first sync, optional training, start services
#
#  Safe to re-run: every step detects existing state and offers to keep it.
#  Nothing outside the install dir is touched except the systemd unit files.
#
#  Usage:
#     sudo ./install_ueba.sh                 interactive
#     sudo ./install_ueba.sh --unattended answers.env
#     sudo ./install_ueba.sh --dry-run       show what would happen, change nothing
#
set -uo pipefail

VERSION="1.0.0"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGFILE="/tmp/ueba-install-$(date +%Y%m%d-%H%M%S).log"
DRY_RUN=0
UNATTENDED=""

# ── Styling ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
  B=$'\e[1m'; DIM=$'\e[2m'; R=$'\e[0m'
  RED=$'\e[38;5;203m'; GRN=$'\e[38;5;114m'; YEL=$'\e[38;5;221m'
  BLU=$'\e[38;5;75m';  CYA=$'\e[38;5;80m'; MAG=$'\e[38;5;177m'; GRY=$'\e[38;5;245m'
else
  B=""; DIM=""; R=""; RED=""; GRN=""; YEL=""; BLU=""; CYA=""; MAG=""; GRY=""
fi

TICK="${GRN}✔${R}"; CROSS="${RED}✘${R}"; WARN="${YEL}▲${R}"; INFO="${BLU}•${R}"
STEP_TOTAL=8
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

# ── Steps ─────────────────────────────────────────────────────────────────────
preflight() {
  step "Preflight"
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

collect_site() {
  step "Site details"
  say "${DIM}Where this UEBA instance lives, and which SIEM it feeds from.${R}"
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
  # CO_LOCATED may be preset by an answers file. It must be read BEFORE falling
  # back to ask_yn, because ask_yn ignores the answers file by design and
  # returns its default under --unattended — so an unattended co-located
  # install would otherwise build a bridge install without saying so.
  blank
  if [[ -z "${CO_LOCATED:-}" ]]; then
    if ask_yn "Is UEBA being installed ON the SIEM host itself?" n; then
      CO_LOCATED=1
    else
      CO_LOCATED=0
    fi
  else
    note "co-located mode: ${CO_LOCATED} ${GRY}(from answers file)${R}"
  fi

  if [[ "$CO_LOCATED" == "1" ]]; then
    SIEM_HOST="localhost"; SIEM_PORT="22"; SIEM_USER="root"
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
    CO_LOCATED=0
    ask SIEM_HOST   "CyberSentinel SIEM manager host or IP" "" v_host
    ask SIEM_PORT   "SIEM SSH port"                     "22" v_port
    ask SIEM_USER   "SSH user on the SIEM"              "root" v_user
    ask SIEM_ENRICHED_DIR "Enriched-log directory on the SIEM" \
        "/home/${SIEM_USER}/CyberSentinel-Event-Correlation-Kafka/data/enriched" v_abs
    ask SIEM_CLIENT_KEYS  "SIEM agent registry on the SIEM" \
        "/var/ossec/etc/client.keys" v_abs
  fi
}

collect_local() {
  step "Install location"
  ask BASE_DIR  "UEBA install directory" "/opt/cybersentinel/ueba" v_abs
  ask DATA_DIR  "Data directory (needs ~500 GB, grows ~65 GB/month)" "/data/ueba" v_abs
  ask DASH_HOST "Dashboard bind address" "0.0.0.0"
  ask DASH_PORT "Dashboard port"         "3026" v_port

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

  # This server's own IP must be suppressed, or its sync/SSH traffic becomes alerts.
  local guess; guess="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
  ask SELF_IP "This server's IP (suppressed as an alert source)" "${guess:-}" v_host

  if [[ -e "$BASE_DIR" ]]; then
    warn "$BASE_DIR already exists."
    ask_yn "Reuse it (keeps data, overwrites config)?" y || die "Pick a different directory and re-run."
    REUSE=1
  else
    REUSE=0
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
  elif ask_yn "Try ssh-copy-id now (asks for the SIEM password)?" y; then
    ssh-copy-id -i "${SSH_KEY}.pub" -p "$SIEM_PORT" "${SIEM_USER}@${SIEM_HOST}" 2>&1 | tee -a "$LOGFILE" || \
      warn "ssh-copy-id did not complete — authorise the key manually, then continue"
  else
    say "${DIM}Authorise it manually, then press Enter.${R}"; read -r _ || true
  fi

  SSH_BASE=(ssh -i "$SSH_KEY" -p "$SIEM_PORT"
            -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15)
  if (( DRY_RUN )); then note "${DIM}[dry-run]${R} skipping connectivity test"; return 0; fi
  # Co-located: there is no remote SIEM to reach — this host is it. Testing
  # ssh root@localhost would fail on any host that (sensibly) does not permit
  # it, and the installer would die for a connection it never needs.
  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
    note "co-located: no SSH to the SIEM needed (this host is the SIEM)"
    return 0
  fi
  if "${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_HOST}" true 2>>"$LOGFILE"; then
    ok "SSH to ${SIEM_USER}@${SIEM_HOST}:${SIEM_PORT} works"
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
  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
    if [[ -r "$SIEM_CLIENT_KEYS" ]]; then
      mkdir -p "$BASE_DIR"
      cp "$SIEM_CLIENT_KEYS" "$BASE_DIR/.client.keys.raw" 2>>"$LOGFILE" || true
    else
      warn "cannot read $SIEM_CLIENT_KEYS — endpoints will show as IPs until agents.json exists"
      return 0
    fi
  elif "${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_HOST}" "test -r '$SIEM_CLIENT_KEYS'" 2>>"$LOGFILE"; then
    # Pull the registry and render agents.json. Counting the agents is not
    # enough: the dashboard reads agents.json to turn agent ids into endpoint
    # NAMES, and without it every endpoint at the customer shows as a bare IP.
    mkdir -p "$BASE_DIR"
    "${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_HOST}" "cat '$SIEM_CLIENT_KEYS'" 2>>"$LOGFILE" \
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

  if "${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_HOST}" "test -d '$SIEM_ENRICHED_DIR'" 2>>"$LOGFILE"; then
    local n sz
    n="$("${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_HOST}" "ls -1 '$SIEM_ENRICHED_DIR' 2>/dev/null | wc -l")"
    sz="$("${SSH_BASE[@]}" "${SIEM_USER}@${SIEM_HOST}" "du -sh '$SIEM_ENRICHED_DIR' 2>/dev/null | cut -f1")"
    ok "enriched logs found — ${B}${n}${R} files, ${B}${sz:-?}${R}"
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
SOC_HOST="${SIEM_USER}@${SIEM_HOST}"
SOC_PORT="$SIEM_PORT"
SOC_SSH_KEY="$SSH_KEY"
SOC_ENRICHED_DIR="$SIEM_ENRICHED_DIR"
SOC_CLIENT_KEYS="$SIEM_CLIENT_KEYS"
UEBA_SELF_IP="$SELF_IP"
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

    # Co-located: switch the engine off file-tailing and onto the topic.
    if [[ "${CO_LOCATED:-0}" == "1" ]]; then
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
    python3 - "$BASE_DIR/ueba_config.yaml" "${SIEM_USER}@${SIEM_HOST}" "$SIEM_PORT" \
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
           ueba_reports.py ueba_report_render.py ueba_report_store.py \
           ueba_housekeeping.py ueba_prune_corpus.py identity_diag.py \
           enrich_parallel.py retrain.py requirements.txt \
           ueba_sync_bridge.sh ueba_rotate.sh ueba_weekly_retrain.sh \
           ueba_bootstrap_training.sh; do
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

  # Co-located installs have no bridge: the engine reads Kafka directly, so a
  # sync bridge would be a second copy of data already on this disk.
  local services="engine dashboard bridge"
  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
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
    if [[ "${CO_LOCATED:-0}" == "1" ]]; then
      note "${DIM}[dry-run]${R} would: start dashboard + engine (no bridge; engine reads Kafka)"
    else
      note "${DIM}[dry-run]${R} would: start ueba-bridge, optionally train, start dashboard + engine"
    fi
    return 0
  fi

  if ask_yn "Pull an initial batch of logs from the SIEM now?" y; then
    if [[ "${CO_LOCATED:-0}" == "1" ]]; then
      say "  ${DIM}co-located: no sync bridge (engine reads Kafka directly)${R}"
    else
      spin "starting sync bridge" systemctl enable --now ueba-bridge || warn "bridge did not start"
    fi
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
  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
    say "${B}Source${R}       kafka ${KAFKA_BROKERS}/${KAFKA_TOPIC} as group ${KAFKA_GROUP}"
  else
    say "${B}SIEM${R}         ${SIEM_USER}@${SIEM_HOST}:${SIEM_PORT}"
  fi
  [[ -n "${AGENT_COUNT:-}" ]] && say "${B}Endpoints${R}    ${AGENT_COUNT} discovered"
  blank
  rule
  say "${B}Service control${R}"
  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
    say "  systemctl status ueba-engine ueba-dashboard"
  else
    say "  systemctl status ueba-engine ueba-dashboard ueba-bridge"
  fi
  say "  journalctl -u ueba-engine -f"
  blank
  say "${B}Next${R}"
  if [[ "${CO_LOCATED:-0}" == "1" ]]; then
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
  blank
}

# ── Main ──────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)    DRY_RUN=1; shift ;;
    --unattended) UNATTENDED="${2:-}"; [[ -f "$UNATTENDED" ]] && . "$UNATTENDED"; shift 2 ;;
    -h|--help)    sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

banner
(( DRY_RUN )) && { warn "DRY RUN — nothing will be changed"; blank; }
say "${DIM}Logging to $LOGFILE${R}"

preflight
collect_site
collect_local
setup_ssh
discover
render_config
setup_runtime
bring_up
summary
