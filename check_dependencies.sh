#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  CyberSentinel UEBA — Dependency & Readiness Check   (install stage 1 of 2)
# ═══════════════════════════════════════════════════════════════════════════════
#
#  WHY THIS IS A SEPARATE SCRIPT
#  ─────────────────────────────
#  install_ueba.sh used to carry its own short preflight, which was enough for
#  the lab pair and not enough for a customer. Two things forced it out into a
#  script of its own:
#
#    1. It has to be runnable BEFORE anyone is near the host with sudo and an
#       install directory. A bank's change window is approved against a
#       prerequisite list, and "run the installer and see where it stops" is not
#       an acceptable way to discover that python3-venv is missing. This script
#       changes NOTHING — it reads, it reports, it exits. It is safe to hand to
#       a customer's platform team and safe to run on a production SIEM host.
#
#    2. The expensive failures all happen late. The venv build is step 7 of the
#       installer's 8, after the SSH key has been authorised on the SIEM and the
#       config has been written; a missing ensurepip there means unwinding work
#       that was already announced as done. Everything knowable up front is now
#       checked up front.
#
#  WHAT IT CHECKS
#     1. Privileges, OS, kernel, init system
#     2. Python interpreter, version, venv/ensurepip, pip
#     3. Command-line tools — required, and optional with what is lost
#     4. CPU, memory, swap
#     5. Disk space on every directory the install writes to
#     6. Ports that must be free, and what is already holding them
#     7. Network reachability — the SIEM, Kafka, the package index
#     8. Clock discipline, locale, file-descriptor limits, cgroups
#     9. The shipped package itself — is every file here
#    10. Python requirements — against a venv, or against an offline wheelhouse
#
#  EXIT STATUS
#     0  every required check passed (warnings may still be present)
#     1  at least one required check failed — do not install
#     2  bad usage
#
#  USAGE
#     ./check_dependencies.sh
#     ./check_dependencies.sh --dir /opt/cybersentinel/ueba --data-dir /data/ueba
#     ./check_dependencies.sh --siem 10.200.10.98:22 --dash 0.0.0.0:3026
#     ./check_dependencies.sh --kafka localhost:39092
#     ./check_dependencies.sh --wheelhouse /mnt/usb/ueba-wheels    # offline site
#     ./check_dependencies.sh --venv /opt/cybersentinel/ueba/venv  # after install
#     ./check_dependencies.sh --strict --json /tmp/depcheck.json --quiet
#
set -uo pipefail

VERSION="1.0.0"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGFILE="/tmp/ueba-depcheck-$(date +%Y%m%d-%H%M%S).log"

# ── Defaults ──────────────────────────────────────────────────────────────────
BASE_DIR="/opt/cybersentinel/ueba"
DATA_DIR="/data/ueba"
DASH_HOST=""
DASH_PORT="3026"
SIEM_HOST=""
SIEM_PORT="22"
KAFKA_ENDPOINT=""
WHEELHOUSE=""
VENV_DIR=""
JSON_OUT=""
STRICT=0
QUIET=0
FOR_INSTALL=0          # --for-install: root becomes a hard requirement

# Thresholds come in pairs, not singles: a FLOOR below which the install cannot
# work, and a RECOMMENDED figure below which it works badly. The floors are
# derived from the systemd caps the installer writes (MemoryMax 24G engine, 6G
# dashboard) and from measured usage on the first co-located deployment (engine
# 19.5 GB resident, dashboard 4.0 GB). The recommended figures are the sizing
# quoted in the RFP response.
PY_MIN="3.10"
CORES_FLOOR=4;    CORES_REC=8
RAM_FLOOR_GB=16;  RAM_REC_GB=48
BASE_FLOOR_GB=20; BASE_REC_GB=60       # venv alone is ~6 GB once torch is in it
DATA_FLOOR_GB=50; DATA_REC_GB=500      # the enriched feed grows ~65 GB/month
TMP_FLOOR_GB=3;   TMP_REC_GB=8         # pip unpacks and builds wheels here
NOFILE_REC=4096

# ── Styling ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
  B=$'\e[1m'; DIM=$'\e[2m'; R=$'\e[0m'
  RED=$'\e[38;5;203m'; GRN=$'\e[38;5;114m'; YEL=$'\e[38;5;221m'
  BLU=$'\e[38;5;75m';  CYA=$'\e[38;5;80m'; GRY=$'\e[38;5;245m'
else
  B=""; DIM=""; R=""; RED=""; GRN=""; YEL=""; BLU=""; CYA=""; GRY=""
fi
TICK="${GRN}✔${R}"; CROSS="${RED}✘${R}"; WARNM="${YEL}▲${R}"; INFOM="${BLU}•${R}"

PASSES=0; WARNS=0; FAILS=0
JSON_ROWS=()

log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOGFILE" 2>/dev/null || true; }
out() { (( QUIET )) || printf '%b\n' "$*"; }

# Strip SGR sequences and escape for JSON. The labels carry colour, and a
# report full of raw escape codes is not a report anyone can read.
jesc() {
  local s
  s="$(printf '%s' "$1" | sed -e 's/\x1b\[[0-9;]*m//g')"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/ }"; s="${s//$'\t'/ }"
  printf '%s' "$s"
}

chk() { # chk <ok|warn|fail|info> <id> <message> [detail]
  local st="$1" id="$2" msg="$3" detail="${4:-}"
  case "$st" in
    ok)   PASSES=$((PASSES + 1)); out "  $TICK $msg" ;;
    warn) WARNS=$((WARNS + 1));   out "  $WARNM $msg" ;;
    fail) FAILS=$((FAILS + 1));   out "  $CROSS $msg" ;;
    info)                         out "  $INFOM $msg" ;;
  esac
  [[ -n "$detail" ]] && out "      ${DIM}${detail}${R}"
  log "[$st] $id :: $(jesc "$msg")${detail:+ -- $(jesc "$detail")}"
  JSON_ROWS+=("{\"id\":\"$(jesc "$id")\",\"status\":\"$st\",\"message\":\"$(jesc "$msg")\",\"detail\":\"$(jesc "$detail")\"}")
}

section() {
  out ""
  out "  ${B}${CYA}$*${R}"
  out "  ${GRY}────────────────────────────────────────────────────────────────${R}"
}

ver_ge() { # ver_ge <have> <want> — true when have >= want
  [[ "$1" == "$2" ]] && return 0
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$2" ]]
}

have() { command -v "$1" >/dev/null 2>&1; }

gb_free() { # gb_free <path> — free GB on the filesystem that would hold <path>
  local p="$1"
  while [[ -n "$p" && "$p" != "/" && ! -d "$p" ]]; do p="$(dirname "$p")"; done
  [[ -d "$p" ]] || { echo 0; return; }
  local v
  v="$(df -BG "$p" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$4); print $4}')"
  echo "${v:-0}"
}

port_free() { # port_free <port> — 0 when nothing is listening on it
  local p="$1"
  if have ss; then
    ! ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
  elif have netstat; then
    ! netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
  else
    # No socket tool at all, which happens on a minimal image. A bind test
    # answers the same question and needs nothing but the interpreter.
    python3 -I -c '
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
' "$p" 2>/dev/null
  fi
}

port_holder() { # best-effort "who is on this port", for the detail line
  have ss || { echo ""; return; }
  ss -ltnpH 2>/dev/null | awk -v p="$1" '$4 ~ ":"p"$" {print $NF; exit}' \
    | sed -e 's/users:((//' -e 's/))$//' -e 's/,fd=[0-9]*//g'
}

tcp_open() { # tcp_open <host> <port> [timeout_s]
  local h="$1" p="$2" t="${3:-5}"
  if have nc; then nc -z -w "$t" "$h" "$p" >/dev/null 2>&1; return $?; fi
  timeout "$t" bash -c "exec 3<>/dev/tcp/${h}/${p}" >/dev/null 2>&1
}

split_hp() { # split_hp <host[:port]> <host_var> <port_var>
  local v="$1" hv="$2" pv="$3"
  if [[ "$v" == *:* ]]; then
    printf -v "$hv" '%s' "${v%:*}"
    printf -v "$pv" '%s' "${v##*:}"
  else
    printf -v "$hv" '%s' "$v"
  fi
}

# ── Arguments ─────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)         BASE_DIR="${2:?--dir needs a path}"; shift 2 ;;
    --data-dir)    DATA_DIR="${2:?--data-dir needs a path}"; shift 2 ;;
    --dash)        split_hp "${2:?--dash needs host[:port]}" DASH_HOST DASH_PORT; shift 2 ;;
    --dash-port)   DASH_PORT="${2:?--dash-port needs a port}"; shift 2 ;;
    --siem)        split_hp "${2:?--siem needs host[:port]}" SIEM_HOST SIEM_PORT; shift 2 ;;
    --kafka)       KAFKA_ENDPOINT="${2:?--kafka needs host:port}"; shift 2 ;;
    --wheelhouse)  WHEELHOUSE="${2:?--wheelhouse needs a directory}"; shift 2 ;;
    --venv)        VENV_DIR="${2:?--venv needs a directory}"; shift 2 ;;
    --json)        JSON_OUT="${2:?--json needs a path}"; shift 2 ;;
    --strict)      STRICT=1; shift ;;
    --quiet)       QUIET=1; shift ;;
    --for-install) FOR_INSTALL=1; shift ;;
    -h|--help)     sed -n '2,50p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; echo "try --help" >&2; exit 2 ;;
  esac
done

# ══ 1. Privileges, OS, init ════════════════════════════════════════════════════
check_platform() {
  section "1. Platform"

  if [[ $EUID -eq 0 ]]; then
    chk ok priv.root "running as root"
  elif (( FOR_INSTALL )); then
    chk fail priv.root "not running as root" "the installer writes /etc/systemd/system — re-run with sudo"
  else
    chk warn priv.root "not running as root" \
      "a few checks are degraded (port owners, ulimits, /var/ossec); the install itself needs sudo"
  fi

  if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    if [[ "${ID:-}" == "ubuntu" || "${ID:-}" == "debian" || "${ID_LIKE:-}" == *debian* ]]; then
      chk ok os.family "OS: ${PRETTY_NAME:-unknown}"
    elif [[ "${ID:-}" == "rhel" || "${ID:-}" == "centos" || "${ID_LIKE:-}" == *rhel* ]]; then
      # Not a failure, but the package names in every runbook are Debian ones,
      # and python3-venv does not exist as a separate package here.
      chk warn os.family "OS: ${PRETTY_NAME:-unknown}" \
        "tested on Ubuntu 22.04/24.04 — on RHEL the venv module ships inside python3-libs, not python3-venv"
    else
      chk warn os.family "OS: ${PRETTY_NAME:-unknown}" "tested on Ubuntu 22.04/24.04"
    fi
  else
    chk warn os.family "cannot identify the OS" "/etc/os-release is unreadable"
  fi

  chk info os.kernel "kernel: $(uname -r) $(uname -m)"
  if [[ "$(uname -m)" != "x86_64" ]]; then
    # faiss-cpu and the CPU torch wheels we pull are x86_64; on aarch64 pip
    # falls through to a source build that will not finish on a SIEM host.
    chk fail os.arch "architecture $(uname -m) is not supported" \
      "faiss-cpu and the pinned torch wheels are x86_64 only"
  else
    chk ok os.arch "architecture x86_64"
  fi

  if have systemctl && [[ -d /run/systemd/system ]]; then
    chk ok init.systemd "systemd is the init system ($(systemctl --version 2>/dev/null | head -1))"
  else
    chk fail init.systemd "systemd not detected" \
      "all five UEBA services are systemd units; there is no supported alternative"
  fi
}

# ══ 2. Python ══════════════════════════════════════════════════════════════════
check_python() {
  section "2. Python"

  local py; py="$(command -v python3 || true)"
  if [[ -z "$py" ]]; then
    chk fail py.present "python3 not found" "apt-get install -y python3 python3-venv python3-pip"
    return
  fi

  PYBIN="$py"
  local pv
  pv="$("$py" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo 0.0.0)"
  if ver_ge "${pv%.*}" "$PY_MIN"; then
    chk ok py.version "python $pv ($py)"
  else
    chk fail py.version "python $pv is too old" "need $PY_MIN or newer"
  fi

  # python3-venv is a separate package on Debian/Ubuntu and its absence is the
  # single most common cause of a late install failure: everything up to the
  # runtime step succeeds, then the venv build dies with "ensurepip is not
  # available". Checking it here keeps the fix a one-liner.
  if "$py" -c 'import ensurepip, venv' >/dev/null 2>&1; then
    chk ok py.venv "venv and ensurepip are available"
  else
    chk fail py.venv "the venv/ensurepip module is missing" \
      "apt-get install -y python3-venv   (the installer cannot build its virtualenv without it)"
  fi

  if "$py" -m pip --version >/dev/null 2>&1; then
    chk ok py.pip "$("$py" -m pip --version 2>/dev/null | cut -d' ' -f1-2)"
  else
    # Not fatal: ensurepip bootstraps pip inside the new venv. Worth saying,
    # because an operator who wants to pre-stage wheels needs pip outside it.
    chk warn py.pip "pip is not available to the system interpreter" \
      "the venv bootstraps its own pip, so this only matters for pre-staging wheels"
  fi

  # Dev headers. hdbscan and faiss have no wheel for every interpreter/ABI
  # combination, and when pip falls back to a source build it needs Python.h.
  if "$py" -c 'import sysconfig,os,sys; sys.exit(0 if os.path.exists(os.path.join(sysconfig.get_paths()["include"],"Python.h")) else 1)' >/dev/null 2>&1; then
    chk ok py.headers "python development headers present"
  else
    chk warn py.headers "python development headers missing" \
      "apt-get install -y python3-dev build-essential — only needed if pip has to build hdbscan or faiss from source"
  fi
}

# ══ 3. Command-line tools ══════════════════════════════════════════════════════
check_tools() {
  section "3. Command-line tools"

  # Required. Each of these is used on a path the install or the running
  # product depends on; a missing one is a hard stop.
  local -A req=(
    [ssh]="bridge transport and agent-registry discovery"
    [scp]="file transfer during setup"
    [rsync]="copying the source tree into the install directory"
    [curl]="health checks against the dashboard API"
    [tar]="unpacking"
    [gzip]="rotated enriched chunks arrive gzipped"
    [systemctl]="service management"
    [crontab]="rotation, retrain and housekeeping jobs"
    [awk]="used throughout the shipped scripts"
    [sed]="config rendering"
    [grep]="used throughout the shipped scripts"
    [df]="disk guards in the bridge"
    [timeout]="every remote call in the bridge is wrapped in it"
  )
  local t
  for t in $(printf '%s\n' "${!req[@]}" | sort); do
    if have "$t"; then chk ok "tool.$t" "found: $t"
    else chk fail "tool.$t" "missing: $t" "${req[$t]}"; fi
  done

  # Optional, each with the consequence of its absence spelled out — an
  # operator should be able to decide, not guess.
  local -A opt=(
    [ss]="port checks fall back to a bind test"
    [nc]="reachability checks fall back to bash /dev/tcp"
    [jq]="nicer output from pipeline_status.sh"
    [docker]="needed only when the SIEM manager runs in a container"
    [nginx]="needed for the TLS front end on 3443 (deploy/nginx-ueba.conf)"
    [node]="needed to rebuild the dashboard bundle on this host"
    [npm]="needed to rebuild the dashboard bundle on this host"
    [git]="needed for ops/deploy_dashboard.sh to pull updates"
    [autossh]="keeps a reverse tunnel alive across link failures; plain ssh plus systemd Restart=always is the fallback"
    [openssl]="generating a self-signed cert for the TLS front end"
  )
  for t in $(printf '%s\n' "${!opt[@]}" | sort); do
    if have "$t"; then chk ok "opt.$t" "found: $t"
    else chk warn "opt.$t" "not installed: $t" "${opt[$t]}"; fi
  done
}

# ══ 4. CPU, memory ═════════════════════════════════════════════════════════════
check_capacity() {
  section "4. CPU and memory"

  local cores ram_gb swap_gb
  cores="$(nproc 2>/dev/null || echo 0)"
  ram_gb="$(awk '/MemTotal/{printf "%d", $2/1048576}' /proc/meminfo 2>/dev/null || echo 0)"
  swap_gb="$(awk '/SwapTotal/{printf "%d", $2/1048576}' /proc/meminfo 2>/dev/null || echo 0)"

  if   (( cores >= CORES_REC ));   then chk ok   cpu.cores "CPU cores: $cores"
  elif (( cores >= CORES_FLOOR )); then chk warn cpu.cores "CPU cores: $cores" "${CORES_REC}+ recommended; the engine is configured with CPUQuota=400%"
  else chk fail cpu.cores "CPU cores: $cores" "below the floor of ${CORES_FLOOR}"; fi

  if   (( ram_gb >= RAM_REC_GB ));   then chk ok   mem.total "RAM: ${ram_gb} GB"
  elif (( ram_gb >= RAM_FLOOR_GB )); then chk warn mem.total "RAM: ${ram_gb} GB" \
      "${RAM_REC_GB} GB+ recommended; lower MEM_ENGINE/MEM_DASHBOARD from their 24G/6G defaults to fit"
  else chk fail mem.total "RAM: ${ram_gb} GB" \
      "below the floor of ${RAM_FLOOR_GB} GB — measured usage is 19.5 GB engine plus 4.0 GB dashboard"; fi

  if (( swap_gb > 0 )); then
    chk ok mem.swap "swap: ${swap_gb} GB"
  else
    chk warn mem.swap "no swap configured" \
      "with no swap the kernel OOM killer picks the largest process, not the guilty one — on a co-located host that may be the SIEM's own heap"
  fi
}

# ══ 5. Disk ════════════════════════════════════════════════════════════════════
check_disk() {
  section "5. Disk space"

  local d free
  for d in "$BASE_DIR:$BASE_FLOOR_GB:$BASE_REC_GB:install directory" \
           "$DATA_DIR:$DATA_FLOOR_GB:$DATA_REC_GB:data directory" \
           "/tmp:$TMP_FLOOR_GB:$TMP_REC_GB:pip build area" \
           "/var/log:1:4:system logs"; do
    IFS=: read -r path floor rec label <<<"$d"
    free="$(gb_free "$path")"
    if   (( free >= rec ));   then chk ok   "disk.$label" "$label $path — ${free} GB free"
    elif (( free >= floor )); then chk warn "disk.$label" "$label $path — ${free} GB free" "${rec} GB recommended"
    else chk fail "disk.$label" "$label $path — ${free} GB free" "below the floor of ${floor} GB"; fi
  done

  # The enriched feed is the thing that fills a disk here, and the bridge
  # already applies backpressure below 60 GB free (DISK_MIN_FREE_GB). Say so,
  # so nobody discovers that limit as a stalled feed.
  chk info disk.growth "the enriched feed grows ~65 GB/month; the bridge pauses pulling below 60 GB free"

  if [[ -e "$BASE_DIR" ]]; then
    chk warn install.exists "$BASE_DIR already exists" \
      "the installer will offer to reuse it (keeps data, overwrites config) — nothing outside it is touched"
  else
    chk ok install.exists "$BASE_DIR does not exist yet — a clean install"
  fi
}

# ══ 6. Ports ═══════════════════════════════════════════════════════════════════
check_ports() {
  section "6. Ports"

  local p holder
  for p in "$DASH_PORT"; do
    [[ -z "$p" ]] && continue
    if port_free "$p"; then
      chk ok "port.$p" "port $p is free (dashboard API)"
    else
      holder="$(port_holder "$p")"
      # An existing UEBA install holding its own port is expected on a re-run,
      # so this is a warning with the holder named rather than a blind failure.
      chk warn "port.$p" "port $p is already in use (dashboard API)" \
        "held by: ${holder:-unknown} — either stop it or choose another port at the prompt"
    fi
  done

  # Existing units are the clearest signal that this host has been installed
  # before, and the re-install path differs from the clean one.
  local u found=""
  for u in ueba-engine ueba-dashboard ueba-bridge ueba-engine-watchdog.timer ueba-tunnel sshd-tunnel; do
    [[ -f "/etc/systemd/system/${u}.service" || -f "/etc/systemd/system/${u}" ]] && found+="$u "
  done
  if [[ -n "$found" ]]; then
    chk warn units.existing "UEBA systemd units already present" "$found"
  else
    chk ok units.existing "no existing UEBA systemd units"
  fi
}

# ══ 7. Network ═════════════════════════════════════════════════════════════════
check_network() {
  section "7. Network"

  local ips
  ips="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd' ' -)"
  chk info net.local "this host: ${ips:-unknown}  (hostname: $(hostname -f 2>/dev/null || hostname))"

  if [[ -n "$SIEM_HOST" ]]; then
    # Reachability of the SIEM's SSH port is what decides whether a separate
    # install can use a direct bridge or needs a reverse tunnel originated from
    # the SIEM side. The installer asks the same question; answering it here
    # means the operator walks in already knowing.
    if tcp_open "$SIEM_HOST" "$SIEM_PORT" 6; then
      chk ok net.siem "SIEM reachable at ${SIEM_HOST}:${SIEM_PORT}" "a direct bridge (UEBA dials the SIEM) will work"
    else
      chk warn net.siem "cannot open ${SIEM_HOST}:${SIEM_PORT} from here" \
        "if the bank's firewall blocks UEBA → SIEM, install with a reverse tunnel (SIEM dials UEBA) instead"
    fi
  else
    chk info net.siem "no SIEM endpoint given" "re-run with --siem <ip[:port]> to test the bridge path"
  fi

  if [[ -n "$KAFKA_ENDPOINT" ]]; then
    local kh kp; kh="${KAFKA_ENDPOINT%:*}"; kp="${KAFKA_ENDPOINT##*:}"
    if tcp_open "$kh" "$kp" 6; then
      chk ok net.kafka "Kafka broker reachable at ${KAFKA_ENDPOINT}"
    else
      chk fail net.kafka "cannot open ${KAFKA_ENDPOINT}" \
        "a co-located install reads the enriched topic directly; without the broker the engine has no source"
    fi
  fi

  # Package index. At a bank this will usually fail, and that is not an error —
  # it is the signal that the install has to run from a wheelhouse.
  if [[ -z "$WHEELHOUSE" ]]; then
    if tcp_open pypi.org 443 6; then
      chk ok net.pypi "pypi.org:443 reachable — pip can resolve requirements.txt"
    else
      chk warn net.pypi "pypi.org:443 not reachable" \
        "offline site: stage wheels with 'pip download -r requirements.txt -d ueba-wheels' on a connected host, then re-run with --wheelhouse <dir>"
    fi
  fi

  # Firewall. The dashboard binds 3026 and nginx fronts it on 3443; a host
  # firewall that silently drops them produces a "the console does not load"
  # ticket with nothing in any UEBA log.
  if have ufw && ufw status 2>/dev/null | head -1 | grep -qi active; then
    chk warn fw.ufw "ufw is active" "allow the console port: ufw allow ${DASH_PORT}/tcp (and 3443/tcp if nginx fronts it)"
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    chk warn fw.firewalld "firewalld is active" "allow the console port: firewall-cmd --add-port=${DASH_PORT}/tcp --permanent"
  else
    chk ok fw.none "no active host firewall detected"
  fi
}

# ══ 8. Host hygiene ════════════════════════════════════════════════════════════
check_hygiene() {
  section "8. Host hygiene"

  # Clock. ueba_auth.py validates exp/iat with 60s leeway and rejects any
  # assertion older than 300s, so a host whose clock has drifted past that
  # rejects every valid SSO token and the failure looks like "SSO is broken".
  if have timedatectl; then
    local sync
    sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
    if [[ "$sync" == "yes" ]]; then
      chk ok clock.ntp "clock is NTP-synchronised ($(date '+%F %T %Z'))"
    else
      chk fail clock.ntp "clock is NOT NTP-synchronised" \
        "SSO rejects assertions older than 300s with 60s leeway — drift past that rejects every valid token. Fix: timedatectl set-ntp true"
    fi
  else
    chk warn clock.ntp "cannot determine clock sync (no timedatectl)" "SSO token validation is time-sensitive — confirm NTP by hand"
  fi

  # Locale. The shipped scripts and the alert text carry UTF-8; a C/POSIX
  # locale turns names in the console into mojibake and can break the report
  # writers outright.
  local lc="${LC_ALL:-${LANG:-}}"
  if [[ "$lc" == *UTF-8* || "$lc" == *utf8* ]]; then
    chk ok locale.utf8 "locale: $lc"
  else
    chk warn locale.utf8 "locale is ${lc:-unset}, not UTF-8" \
      "non-ASCII endpoint and user names will render wrongly; set LANG=C.UTF-8 in the unit environment"
  fi

  local nofile; nofile="$(ulimit -n 2>/dev/null || echo 0)"
  if (( nofile >= NOFILE_REC )); then
    chk ok limits.nofile "open-file limit: $nofile"
  else
    chk warn limits.nofile "open-file limit is $nofile" \
      "${NOFILE_REC}+ recommended — the engine holds per-user model files and Kafka partition handles open together"
  fi

  if [[ -r /sys/fs/cgroup/cgroup.controllers ]]; then
    chk ok cgroup.v2 "cgroup v2 — MemoryMax and CPUQuota will be enforced"
  elif [[ -d /sys/fs/cgroup/memory ]]; then
    chk warn cgroup.v1 "cgroup v1" "MemoryMax maps to memory.limit_in_bytes and still works, but CPUQuota accounting is coarser"
  else
    chk fail cgroup.none "no cgroup controllers found" \
      "the resource caps in the unit files are what stop UEBA from taking the host down; without them the install is unbounded"
  fi

  if have getenforce; then
    local se; se="$(getenforce 2>/dev/null || echo unknown)"
    [[ "$se" == "Enforcing" ]] \
      && chk warn sec.selinux "SELinux is Enforcing" "unconfined systemd units writing outside /opt may be denied; check audit.log if a service fails to start" \
      || chk ok sec.selinux "SELinux: $se"
  fi
}

# ══ 9. The shipped package ═════════════════════════════════════════════════════
check_package() {
  section "9. Shipped package"

  # The installer has its own module resolver (verify_modules) that aborts the
  # install if any `import ueba_*` cannot be satisfied in the copied tree. That
  # runs at step 7. This is the same question asked at step 0, against the
  # directory the operator is holding, before anything is copied anywhere.
  local f missing=0
  for f in install_ueba.sh requirements.txt ueba_config.yaml \
           ueba_engine.py ueba_dashboard_server.py ueba_auth.py ueba_source.py \
           ueba_preprocessor.py ueba_sync_bridge.sh ueba_bootstrap_training.sh \
           ueba-engine-watchdog.sh pipeline_status.sh; do
    [[ -f "$SELF_DIR/$f" ]] || { chk fail "pkg.$f" "missing from the package: $f"; missing=1; }
  done
  (( missing )) || chk ok pkg.files "all expected top-level files are present"

  [[ -d "$SELF_DIR/ueba_models" ]] \
    && chk ok pkg.models "ueba_models/ present ($(find "$SELF_DIR/ueba_models" -name '*.py' 2>/dev/null | wc -l | tr -d ' ') modules)" \
    || chk fail pkg.models "ueba_models/ is missing"

  # The browser is served dashboard/dist/, never dashboard/src/. dist/ is
  # gitignored, so a tree pulled from git has no bundle in it and the console
  # answers 404 until someone runs the build. That has been the cause of every
  # "I deployed but the UI is unchanged" report on this project.
  if [[ -d "$SELF_DIR/dashboard/dist" && -f "$SELF_DIR/dashboard/dist/index.html" ]]; then
    chk ok pkg.bundle "dashboard/dist/ is built"
  elif [[ -d "$SELF_DIR/dashboard" ]]; then
    chk warn pkg.bundle "dashboard/dist/ is not built" \
      "dist/ is a build artefact and is gitignored — run 'npm install && npm run build' in dashboard/ on this host, or ship a pre-built dist/"
  else
    chk fail pkg.bundle "dashboard/ is missing from the package"
  fi

  # An operator probe that must stay read-only. Worth confirming it is here,
  # because it is the only thing that can be run on a client SIEM before any
  # change at all is approved.
  [[ -f "$SELF_DIR/preflight_probe.sh" ]] \
    && chk ok pkg.probe "preflight_probe.sh present (read-only host survey)" \
    || chk warn pkg.probe "preflight_probe.sh missing" "the read-only pre-change survey is part of the handover"
}

# ══ 10. Python requirements ════════════════════════════════════════════════════
check_requirements() {
  section "10. Python requirements"

  local reqfile="$SELF_DIR/requirements.txt"
  if [[ ! -f "$reqfile" ]]; then
    chk fail req.file "requirements.txt not found beside this script"
    return
  fi

  local count
  count="$(grep -cE '^[A-Za-z]' "$reqfile" 2>/dev/null || echo 0)"
  chk info req.count "requirements.txt declares $count packages"

  local target=""
  if [[ -n "$VENV_DIR" ]]; then
    if [[ -x "$VENV_DIR/bin/python3" ]]; then
      target="$VENV_DIR/bin/python3"
      chk ok req.venv "checking against the venv at $VENV_DIR"
    else
      chk fail req.venv "no interpreter at $VENV_DIR/bin/python3"
      return
    fi
  fi

  if [[ -n "$target" ]]; then
    # Post-install verification. Every requirement must be installed AND
    # satisfy its specifier. scikit-learn is pinned rather than ranged because
    # joblib-pickled estimators carry the version that wrote them, and loading
    # a model written by another minor version casts doubt over every score —
    # so a mismatch there is a failure, not a note.
    local report
    report="$("$target" -I - "$reqfile" <<'PY' 2>/dev/null
import re, sys
try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    print("ERR|importlib.metadata unavailable"); raise SystemExit(0)

def norm(n):
    return re.sub(r"[-_.]+", "-", n).lower()

def parts(v):
    out = []
    for p in re.split(r"[.+-]", v):
        out.append(int(p) if p.isdigit() else 0)
    return out

def cmp(a, b):
    pa, pb = parts(a), parts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa)); pb += [0] * (n - len(pb))
    return (pa > pb) - (pa < pb)

def ok(have, op, want):
    c = cmp(have, want)
    return {"==": c == 0, ">=": c >= 0, "<=": c <= 0,
            ">": c > 0, "<": c < 0, "!=": c != 0}.get(op, True)

for raw in open(sys.argv[1], encoding="utf-8"):
    line = raw.split("#")[0].strip()
    if not line or not line[0].isalpha():
        continue
    line = line.split(";")[0].strip()          # drop environment markers
    m = re.match(r"^([A-Za-z0-9._-]+)\s*(.*)$", line)
    if not m:
        continue
    name, spec = m.group(1), m.group(2).replace(" ", "")
    try:
        have = version(norm(name))
    except PackageNotFoundError:
        print(f"MISSING|{name}|{spec}|-"); continue
    bad = []
    for s in filter(None, spec.split(",")):
        sm = re.match(r"^(==|>=|<=|!=|~=|>|<)(.+)$", s)
        if not sm:
            continue
        op, want = sm.group(1), sm.group(2)
        if op == "~=":
            op = ">="                           # close enough for a readiness check
        if not ok(have, op, want):
            bad.append(s)
    print(f"{'BAD' if bad else 'OK'}|{name}|{spec}|{have}")
PY
)"
    local line st nm sp hv miss=0 badv=0
    while IFS='|' read -r st nm sp hv; do
      [[ -z "${st:-}" ]] && continue
      case "$st" in
        MISSING) chk fail "req.$nm" "not installed: $nm $sp"; miss=$((miss + 1)) ;;
        BAD)     chk fail "req.$nm" "$nm $hv does not satisfy $sp"; badv=$((badv + 1)) ;;
        OK)      log "req ok $nm $hv ($sp)" ;;
        ERR)     chk warn req.probe "could not enumerate installed packages" "$nm" ;;
      esac
    done <<<"$report"
    (( miss == 0 && badv == 0 )) && chk ok req.satisfied "all $count requirements are installed and satisfy their specifiers"
    return
  fi

  if [[ -n "$WHEELHOUSE" ]]; then
    # Offline site. The question is not "is it installed" — nothing is yet —
    # but "can pip install it with no network at all", which means a
    # distribution for every declared package has to be sitting in this
    # directory already.
    if [[ ! -d "$WHEELHOUSE" ]]; then
      chk fail req.wheelhouse "wheelhouse $WHEELHOUSE does not exist"
      return
    fi
    local n_files
    n_files="$(find "$WHEELHOUSE" -maxdepth 1 \( -name '*.whl' -o -name '*.tar.gz' \) 2>/dev/null | wc -l | tr -d ' ')"
    chk info req.wheelhouse "wheelhouse $WHEELHOUSE holds $n_files distributions"

    local pkg norm_pkg hits missing=0
    while read -r pkg; do
      [[ -z "$pkg" ]] && continue
      # Wheel filenames normalise - and . to _, and the case varies by builder.
      norm_pkg="$(printf '%s' "$pkg" | tr 'A-Z.-' 'a-z__')"
      hits="$(find "$WHEELHOUSE" -maxdepth 1 -iname "*" -type f 2>/dev/null \
              | xargs -r -n1 basename 2>/dev/null \
              | tr 'A-Z.-' 'a-z__' | grep -cE "^${norm_pkg}_[0-9]" || true)"
      if [[ "${hits:-0}" -eq 0 ]]; then
        chk fail "wheel.$pkg" "no distribution for $pkg in the wheelhouse"
        missing=$((missing + 1))
      fi
    done < <(sed -e 's/#.*//' -e 's/;.*//' "$reqfile" | grep -oE '^[A-Za-z0-9._-]+')
    (( missing == 0 )) && chk ok req.wheelhouse.complete "every declared package has a distribution in the wheelhouse"
    return
  fi

  # Pre-install, online. The packages are expected to be absent — the installer
  # creates the venv and fills it. The useful checks here are the two that bite
  # later: enough room to build torch, and the pin that must not be floated.
  chk info req.preinstall "packages are installed into $BASE_DIR/venv at install time, not system-wide"
  chk info req.pins "scikit-learn is pinned to 1.8.0 on purpose — a joblib model written by another version makes every score doubtful; bump it only with a retrain"
  local tmpfree; tmpfree="$(gb_free /tmp)"
  if (( tmpfree < TMP_FLOOR_GB )); then
    chk fail req.buildspace "/tmp has ${tmpfree} GB free" "pip unpacks torch (~900 MB) and faiss here; set TMPDIR to a larger filesystem or free space"
  else
    chk ok req.buildspace "/tmp has ${tmpfree} GB free for pip to build in"
  fi
}

# ══ Report ═════════════════════════════════════════════════════════════════════
write_json() {
  [[ -z "$JSON_OUT" ]] && return 0
  local verdict="pass"
  (( FAILS > 0 )) && verdict="fail"
  (( FAILS == 0 && STRICT == 1 && WARNS > 0 )) && verdict="fail"
  {
    printf '{\n'
    printf '  "tool": "check_dependencies.sh",\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "host": "%s",\n' "$(jesc "$(hostname -f 2>/dev/null || hostname)")"
    printf '  "generated": "%s",\n' "$(date -Is)"
    printf '  "install_dir": "%s",\n' "$(jesc "$BASE_DIR")"
    printf '  "data_dir": "%s",\n' "$(jesc "$DATA_DIR")"
    printf '  "verdict": "%s",\n' "$verdict"
    printf '  "passed": %d, "warnings": %d, "failed": %d,\n' "$PASSES" "$WARNS" "$FAILS"
    printf '  "checks": [\n'
    local i
    for i in "${!JSON_ROWS[@]}"; do
      printf '    %s' "${JSON_ROWS[$i]}"
      (( i < ${#JSON_ROWS[@]} - 1 )) && printf ','
      printf '\n'
    done
    printf '  ]\n}\n'
  } >"$JSON_OUT"
  out "  ${DIM}machine-readable report: $JSON_OUT${R}"
}

banner() {
  out ""
  out "  ${B}${CYA}CyberSentinel UEBA${R} ${DIM}— dependency & readiness check v${VERSION}${R}"
  out "  ${GRY}stage 1 of 2 — this script changes nothing on this host${R}"
  out ""
  out "  ${DIM}install dir : $BASE_DIR${R}"
  out "  ${DIM}data dir    : $DATA_DIR${R}"
  out "  ${DIM}log         : $LOGFILE${R}"
}

banner
check_platform
check_python
check_tools
check_capacity
check_disk
check_ports
check_network
check_hygiene
check_package
check_requirements

out ""
out "  ${GRY}════════════════════════════════════════════════════════════════${R}"
out "  ${B}Result${R}  ${GRN}${PASSES} passed${R}   ${YEL}${WARNS} warnings${R}   ${RED}${FAILS} failed${R}"
out ""

RC=0
if (( FAILS > 0 )); then
  out "  ${CROSS} ${B}Not ready to install.${R} Fix every ✘ above and re-run this script."
  RC=1
elif (( STRICT && WARNS > 0 )); then
  out "  ${CROSS} ${B}--strict:${R} warnings are being treated as failures."
  RC=1
elif (( WARNS > 0 )); then
  out "  ${TICK} ${B}Ready to install${R} — with ${WARNS} warning(s) above worth reading first."
  out ""
  out "  ${DIM}Next:  sudo ./install_ueba.sh --dir $BASE_DIR${R}"
else
  out "  ${TICK} ${B}Ready to install.${R}"
  out ""
  out "  ${DIM}Next:  sudo ./install_ueba.sh --dir $BASE_DIR${R}"
fi
out ""
write_json
out "  ${DIM}Full log: $LOGFILE${R}"
out ""
exit $RC
