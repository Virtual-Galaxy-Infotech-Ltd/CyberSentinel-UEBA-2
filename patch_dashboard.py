#!/usr/bin/env python3
"""
Patch script for ueba_dashboard_server.py and dashboard/index.html
Fixes:
  1. get_user() — missing subject.ip and raw_event fallbacks → 'unknown' shown
  2. get_user() — model_used='global' leaking as username
  3. HTML auto-refresh — no setInterval, only manual refresh
  4. load_alerts() — reads whole file on every API call (no caching)

Usage:
  python3 patch_dashboard.py ueba_dashboard_server.py  dashboard/index.html
"""
import sys, re

SERVER_PATCHES = [

    # ── FIX 1 + 2: get_user() ────────────────────────────────────────────────
    # Bug 1: subject.ip never checked — 192.168.1.70 shows as 'unknown' (rule 533)
    # Bug 2: model_used='global' leaks as a username — host-level events show 'global'
    # Bug 3: no fallback to raw_event win.eventdata fields — NT AUTHORITY\SYSTEM can be null
    # Bug 4: host.name not used as last resort before 'unknown' — SocSRV_15 shows 'unknown'
    (
        "def get_user(alert):\n"
        "    return (alert.get(\"subject\", {}) or {}).get(\"name\") or \\\n"
        "           (alert.get(\"object\", {}) or {}).get(\"name\") or \\\n"
        "           (alert.get(\"ueba\", {}) or {}).get(\"raw_scores\", {}).get(\"autoencoder\", {}).get(\"model_used\") or \\\n"
        "           \"unknown\"",

        "def get_user(alert):\n"
        "    \"\"\"Resolve the most meaningful username from an alert.\n"
        "    Priority: subject.name > raw_event user fields > object.name\n"
        "              > subject.ip > ae model (if personal) > host.name > 'unknown'\n"
        "    \"\"\"\n"
        "    sub  = alert.get(\"subject\", {}) or {}\n"
        "    obj  = alert.get(\"object\", {}) or {}\n"
        "    ueba = alert.get(\"ueba\", {}) or {}\n"
        "    host = alert.get(\"host\", {}) or {}\n"
        "    raw  = (alert.get(\"context\", {}) or {}).get(\"raw_event\", {}) or {}\n"
        "    win  = (raw.get(\"data\", {}) or {}).get(\"win\", {}) or {}\n"
        "    wed  = (win.get(\"eventdata\", {}) or {})\n"
        "    raw_data = raw.get(\"data\", {}) or {}\n"
        "\n"
        "    # 1. Direct subject name — most reliable\n"
        "    name = sub.get(\"name\")\n"
        "    if name and name not in (\"\", None):\n"
        "        return name\n"
        "\n"
        "    # 2. Windows event data — subjectUserName / targetUserName\n"
        "    for field in (\"subjectUserName\", \"targetUserName\", \"subjectDomainName\"):\n"
        "        v = wed.get(field)\n"
        "        if v and v not in (\"\", \"-\", None):\n"
        "            return v\n"
        "\n"
        "    # 3. Generic raw_data fields (FortiGate, Syslog, etc)\n"
        "    for field in (\"srcuser\", \"dstuser\", \"user\", \"username\", \"accountName\"):\n"
        "        v = raw_data.get(field)\n"
        "        if v and v not in (\"\", \"-\", None):\n"
        "            return v\n"
        "\n"
        "    # 4. Object name (destination user in auth events)\n"
        "    name = obj.get(\"name\")\n"
        "    if name and name not in (\"\", None):\n"
        "        return name\n"
        "\n"
        "    # 5. Subject IP — used when no username exists (e.g. netstat rule 533)\n"
        "    ip = sub.get(\"ip\")\n"
        "    if ip and ip not in (\"\", None):\n"
        "        return ip\n"
        "\n"
        "    # 6. Autoencoder model_used — only if it's a real personal model\n"
        "    #    Exclude 'global', 'unknown', '' which are not usernames\n"
        "    model = ueba.get(\"raw_scores\", {}).get(\"autoencoder\", {}).get(\"model_used\", \"\")\n"
        "    if model and model not in (\"global\", \"unknown\", \"\", None):\n"
        "        return model\n"
        "\n"
        "    # 7. Host name — last resort before 'unknown'\n"
        "    #    Better to show 'SocSRV_15' than 'unknown' for host-level events\n"
        "    hname = host.get(\"name\")\n"
        "    if hname and hname not in (\"\", None):\n"
        "        return hname\n"
        "\n"
        "    return \"unknown\"",
    ),

    # ── FIX 4: load_alerts() caching ─────────────────────────────────────────
    # Bug: reads entire file on every /api/stats, /api/feed, /api/users, /api/campaigns,
    # /api/agents call — that's 5 full file reads per dashboard refresh.
    # Fix: cache with 10-second TTL using mtime check so we never read stale data.
    (
        "def load_alerts(n=MAX_ALERTS):\n"
        "    \"\"\"Load last N alerts from ueba_alerts.jsonl efficiently.\"\"\"\n"
        "    if not ALERTS_FILE.exists():\n"
        "        return []\n"
        "    alerts = []\n"
        "    try:\n"
        "        with open(ALERTS_FILE, \"r\", encoding=\"utf-8\", errors=\"replace\") as f:\n"
        "            lines = f.readlines()\n"
        "        for line in lines[-n:]:\n"
        "            line = line.strip()\n"
        "            if not line:\n"
        "                continue\n"
        "            try:\n"
        "                alerts.append(json.loads(line))\n"
        "            except json.JSONDecodeError:\n"
        "                continue\n"
        "    except Exception:\n"
        "        pass\n"
        "    return alerts",

        "# ── Alert cache — avoids reading the full file on every API request ──\n"
        "_alert_cache      = []\n"
        "_alert_cache_mtime = 0.0\n"
        "_CACHE_TTL_SECS    = 10   # re-read if file is >10s old in mtime terms\n"
        "\n"
        "def load_alerts(n=MAX_ALERTS):\n"
        "    \"\"\"Load last N alerts — cached by file mtime, refreshes every 10s max.\"\"\"\n"
        "    global _alert_cache, _alert_cache_mtime\n"
        "    if not ALERTS_FILE.exists():\n"
        "        return []\n"
        "    try:\n"
        "        mtime = ALERTS_FILE.stat().st_mtime\n"
        "    except Exception:\n"
        "        return _alert_cache\n"
        "    # Return cache if file hasn't changed in the last TTL window\n"
        "    import time\n"
        "    if _alert_cache and mtime == _alert_cache_mtime and \\\n"
        "            (time.time() - _alert_cache_mtime) < _CACHE_TTL_SECS:\n"
        "        return _alert_cache\n"
        "    alerts = []\n"
        "    try:\n"
        "        with open(ALERTS_FILE, \"r\", encoding=\"utf-8\", errors=\"replace\") as f:\n"
        "            lines = f.readlines()\n"
        "        for line in lines[-n:]:\n"
        "            line = line.strip()\n"
        "            if not line:\n"
        "                continue\n"
        "            try:\n"
        "                alerts.append(json.loads(line))\n"
        "            except json.JSONDecodeError:\n"
        "                continue\n"
        "    except Exception:\n"
        "        return _alert_cache\n"
        "    _alert_cache = alerts\n"
        "    _alert_cache_mtime = mtime\n"
        "    return alerts",
    ),
]

HTML_PATCHES = [

    # ── FIX 3: Add auto-refresh every 30 seconds ─────────────────────────────
    # Bug: '// ── Init — load once on open, no auto-poll' — dashboard is static
    # Fix: setInterval to fetchAll() every 30s, with visibility check so it
    #      doesn't hammer the server when the tab is hidden
    (
        "// ── Init — load once on open, no auto-poll\n"
        "showSkeletons();\n"
        "fetchAll();",

        "// ── Init — load on open, then auto-refresh every 30 seconds\n"
        "showSkeletons();\n"
        "fetchAll();\n"
        "\n"
        "// Auto-refresh: every 30s, but only when tab is visible\n"
        "// Avoids hammering the server when dashboard is in background\n"
        "const AUTO_REFRESH_MS = 30_000;\n"
        "let autoRefreshTimer = setInterval(() => {\n"
        "  if (!document.hidden) {\n"
        "    fetchAll().catch(() => {});\n"
        "  }\n"
        "}, AUTO_REFRESH_MS);\n"
        "\n"
        "// Also refresh immediately when tab becomes visible again\n"
        "// (replaces the existing visibilitychange handler below)",
    ),

    # Fix the visibilitychange handler to not double-fetch on tab focus
    (
        "document.addEventListener('visibilitychange', ()=>{ if (!document.hidden&&!feedData.length) fetchAll(); });",
        "document.addEventListener('visibilitychange', () => {\n"
        "  // Refresh immediately when tab becomes visible if data is stale (>30s)\n"
        "  if (!document.hidden) {\n"
        "    const lastText = document.getElementById('last-update').textContent;\n"
        "    const noData = !feedData.length;\n"
        "    // Always refresh if no data; otherwise let the interval handle it\n"
        "    if (noData) fetchAll().catch(() => {});\n"
        "  }\n"
        "});",
    ),
]


def apply(path, patches, label):
    with open(path, encoding='utf-8') as f:
        content = f.read()
    original = content
    for i, (old, new) in enumerate(patches, 1):
        if old not in content:
            print(f"  ✗ {label} Fix {i}: string not found — already applied or mismatch")
            print(f"    Looking for: {old[:80]!r}...")
            continue
        content = content.replace(old, new, 1)
        print(f"  ✓ {label} Fix {i} applied")
    if content == original:
        print(f"  ⚠ {label}: No changes made")
        return
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  ✓ {label}: Written to {path}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} ueba_dashboard_server.py dashboard/index.html")
        sys.exit(1)
    print(f"\n── Patching server: {sys.argv[1]}")
    apply(sys.argv[1], SERVER_PATCHES, 'SERVER')
    print(f"\n── Patching HTML: {sys.argv[2]}")
    apply(sys.argv[2], HTML_PATCHES, 'HTML')
    print("\n✓ Done. Restart the dashboard server:")
    print("  pkill -f ueba_dashboard_server.py && python3 ueba_dashboard_server.py &")
