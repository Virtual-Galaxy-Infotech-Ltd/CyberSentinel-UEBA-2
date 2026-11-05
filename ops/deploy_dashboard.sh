#!/usr/bin/env bash
#
# deploy_dashboard.sh — pull source, rebuild the dashboard bundle, reload.
#
# WHY THIS EXISTS
# ───────────────
# The dashboard is a Vite SPA: the browser is served dashboard/dist/, never
# dashboard/src/. dist/ is gitignored (it is a build artifact and it carries no
# source), so pulling alone changes nothing a user can see — the bundle has to
# be rebuilt on the box that serves it. Every "I pushed the fix but the UI is
# unchanged" report in this project has had that same cause, including the one
# where the deployed bundle predated the Settings panel by two months.
#
# WHAT IT WILL NOT TOUCH
# ──────────────────────
# ueba_config.yaml, the operator registers (agents.json, fp_patterns.json,
# watchlist.json, …), profiles/, models/, archive/ or .state/. The live config
# on this host legitimately differs from the repository — enforce flags, site
# paths — and there is already one ueba_config.yaml.pre-*.clobbered-by-rsync in
# this tree from the last time a deploy was careless with it. Local edits to
# tracked files are stashed and restored, and the stash is KEPT on any conflict
# rather than dropped.
#
# USAGE
#     sudo /opt/ueba/ops/deploy_dashboard.sh              # pull + build + reload
#     sudo /opt/ueba/ops/deploy_dashboard.sh --no-pull    # rebuild what is on disk
#     sudo /opt/ueba/ops/deploy_dashboard.sh --check      # report only, change nothing
#
set -uo pipefail

BASE="${UEBA_BASE:-/opt/ueba}"
BRANCH="${UEBA_BRANCH:-main}"
API_PORT="${UEBA_API_PORT:-3027}"     # Flask; nginx fronts it with TLS on 3026
DO_PULL=1
CHECK_ONLY=0

for a in "$@"; do
  case "$a" in
    --no-pull) DO_PULL=0 ;;
    --check)   CHECK_ONLY=1; DO_PULL=0 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1;36m══ %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '   \033[31m✗ %s\033[0m\n' "$*"; exit 1; }

cd "$BASE" || die "$BASE does not exist — set UEBA_BASE"

# ── 1. where are we ──────────────────────────────────────────────────────────
step "Deployment"
echo "   base   : $BASE"
echo "   whoami : $(whoami)"
if [ -d .git ]; then
  echo "   git    : $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)"
  echo "   remote : $(git remote get-url origin 2>/dev/null || echo 'none')"
  IS_GIT=1
else
  warn "not a git working copy — source must be transferred another way"
  IS_GIT=0
fi

if [ "$CHECK_ONLY" = 1 ]; then
  step "Current bundle"
  ls -la dashboard/dist/assets/ 2>/dev/null || warn "dashboard/dist/ does not exist — never built"
  step "Services"
  systemctl is-active ueba-dashboard ueba-engine nginx 2>/dev/null | paste -d' ' \
    <(echo -e "ueba-dashboard\nueba-engine\nnginx") - || true
  exit 0
fi

# ── 2. pull source, protecting anything local ────────────────────────────────
if [ "$DO_PULL" = 1 ] && [ "$IS_GIT" = 1 ]; then
  step "Pulling $BRANCH"
  git fetch origin "$BRANCH" || die "fetch failed"

  STASHED=0
  if ! git diff --quiet HEAD -- 2>/dev/null; then
    warn "local edits to tracked files — stashing them first:"
    git diff --name-only HEAD -- | sed 's/^/        /'
    if git stash push -m "pre-deploy $(date -Is)" >/dev/null 2>&1; then
      STASHED=1
      ok "stashed (restored below; kept in 'git stash list' if it conflicts)"
    else
      die "could not stash local edits — resolve them by hand first"
    fi
  fi

  BEFORE=$(git rev-parse --short HEAD)
  if git merge --ff-only "origin/$BRANCH" >/dev/null 2>&1; then
    AFTER=$(git rev-parse --short HEAD)
    if [ "$BEFORE" = "$AFTER" ]; then ok "already up to date at $AFTER"
    else ok "$BEFORE → $AFTER"; git --no-pager log --oneline "$BEFORE..$AFTER" | sed 's/^/        /'
    fi
  else
    [ "$STASHED" = 1 ] && git stash pop >/dev/null 2>&1
    die "cannot fast-forward — this tree has diverged from origin/$BRANCH"
  fi

  if [ "$STASHED" = 1 ]; then
    if git stash pop >/dev/null 2>&1; then ok "local edits restored"
    else warn "local edits CONFLICT with the update and are still in 'git stash list' — resolve by hand"
    fi
  fi
fi

# ── 3. rebuild the bundle ────────────────────────────────────────────────────
step "Rebuilding the dashboard bundle"
command -v npm >/dev/null || die "npm not installed — the bundle cannot be built on this host"
cd "$BASE/dashboard" || die "no dashboard/ directory"

OLD_ASSETS=$(ls dist/assets/ 2>/dev/null | tr '\n' ' ')
npm install --no-audit --no-fund || die "npm install failed"
if ! npm run build; then
  warn "build failed — trying an esbuild rebuild (npm >=11 blocks its postinstall)"
  npm rebuild esbuild && npm run build || die "build failed"
fi
NEW_ASSETS=$(ls dist/assets/ 2>/dev/null | tr '\n' ' ')
ok "built"
echo "        before: ${OLD_ASSETS:-<none>}"
echo "        after : ${NEW_ASSETS}"
[ -s dist/index.html ] || die "dist/index.html is missing or empty after the build"
cd "$BASE"

# ── 4. reload what serves it ─────────────────────────────────────────────────
# ueba-dashboard runs the Flask API and imports ueba_auth, so a Python change
# needs the restart. It also holds an in-process gzip cache of the static
# bundle, which would otherwise keep serving the previous build's bytes.
step "Reloading services"
systemctl restart ueba-dashboard && ok "ueba-dashboard restarted" \
  || warn "could not restart ueba-dashboard"
# nginx serves dist/ off disk; a reload just drops any cached file handles.
systemctl reload nginx 2>/dev/null && ok "nginx reloaded" || warn "nginx reload skipped"
sleep 2

# ── 5. verify ────────────────────────────────────────────────────────────────
step "Verifying"
systemctl is-active --quiet ueba-dashboard \
  && ok "ueba-dashboard is active" \
  || { warn "ueba-dashboard is NOT active:"; journalctl -u ueba-dashboard -n 15 --no-pager | sed 's/^/        /'; }

HEALTH=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${API_PORT}/api/health" 2>/dev/null)
[ "$HEALTH" = "200" ] && ok "/api/health → 200" || warn "/api/health → ${HEALTH:-no response}"

# 401 proves the route is registered and demanding a session. 404 means the
# Python side is still running the old module.
UN=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
     "http://127.0.0.1:${API_PORT}/api/auth/username" 2>/dev/null)
case "$UN" in
  401|400|403) ok "/api/auth/username → $UN (route is live)" ;;
  404) warn "/api/auth/username → 404 — the OLD ueba_auth.py is still loaded" ;;
  *)   warn "/api/auth/username → ${UN:-no response}" ;;
esac

ENF=$(grep -A6 '^auth:' ueba_config.yaml 2>/dev/null | grep -E '^\s*enforce:' | head -1 | awk '{print $2}')
echo "   auth.enforce = ${ENF:-unknown}"
[ "$ENF" = "false" ] && warn "with enforce:false every capability reports true, so the admin-only
        User Management panel stays visible and My Account shows only the
        'not enforced' note — the UI changes will not be visible"

step "Done — hard-refresh the browser (Ctrl+Shift+R)"
