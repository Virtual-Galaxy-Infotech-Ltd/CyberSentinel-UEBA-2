#!/usr/bin/env python3
"""
Run this on 98 to patch ueba_preprocessor.py:
  python3 patch_preprocessor.py ueba_preprocessor.py
"""
import sys, re

path = sys.argv[1] if len(sys.argv) > 1 else "ueba_preprocessor.py"
content = open(path).read()
changed = []

# ── 1. Add _SUPPRESS_SOURCE_IPS set before is_noise (if not already present) ──
if "_SUPPRESS_SOURCE_IPS" not in content:
    # Insert before def is_noise
    insert = (
        "_SUPPRESS_SOURCE_IPS = {\n"
        "    \"164.52.194.98\",   # engine server — reverse tunnel + rsync traffic\n"
        "}\n"
        "\n"
        "# Known internal agents/hostnames that should never appear as alert subjects.\n"
        "_SUPPRESS_AGENT_NAMES = {\n"
        "    \"cybersentinel-manager\",\n"
        "    \"cybersentinel-manage\",\n"
        "    \"Centos7Trial\",\n"
        "}\n"
        "\n"
    )
    if "_SUPPRESS_AGENT_NAMES" in content:
        # Replace existing block
        content = re.sub(
            r"# Known internal agents.*?_SUPPRESS_AGENT_NAMES\s*=\s*\{.*?\}\n",
            insert,
            content, flags=re.DOTALL
        )
    else:
        content = content.replace("def is_noise(", insert + "def is_noise(")
    changed.append("added _SUPPRESS_SOURCE_IPS set")

# ── 2. Add _NOISE_SIGNATURE_IDS if missing or expand it ──────────────────────
full_noise_ids = {
    "113202": "MikroTik: L2TP tunnel authenticated",
    "81619":  "Fortigate: Multiple high traffic events from same source",
    "81620":  "Fortigate: Multiple high traffic events from same destination",
    "81621":  "Fortigate: Multiple high traffic events to same port",
    "81633":  "Fortigate: App passed by firewall",
    "81634":  "Fortigate: App blocked by firewall",
    "81644":  "Fortigate: Blocked URL",
    "60107":  "Failed privileged operation (SocSRV_15 chrome.exe noise)",
}
if "_NOISE_SIGNATURE_IDS" in content:
    for sig_id in full_noise_ids:
        if f'"{sig_id}"' not in content:
            content = re.sub(
                r"(_NOISE_SIGNATURE_IDS\s*=\s*\{)",
                rf'\1\n    "{sig_id}",   # {full_noise_ids[sig_id]}',
                content
            )
            changed.append(f"added sig_id {sig_id} to _NOISE_SIGNATURE_IDS")
else:
    ids_block = "_NOISE_SIGNATURE_IDS = {\n"
    for k, v in full_noise_ids.items():
        ids_block += f'    "{k}",   # {v}\n'
    ids_block += "}\n\n"
    content = content.replace("def is_noise(", ids_block + "def is_noise(")
    changed.append("created _NOISE_SIGNATURE_IDS")

# ── 3. Patch is_noise to check source IPs and None user ──────────────────────
old_return = "    return False\n"
new_checks = (
    "    # Suppress engine server's own IP — tunnel/rsync traffic\n"
    "    src_ip = str(get_nested(log, \"enrich.geo.src_ip\") or\n"
    "                 get_nested(log, \"context.raw_event.data.srcip\") or\n"
    "                 get_nested(log, \"source.ip\") or \"\")\n"
    "    if src_ip in _SUPPRESS_SOURCE_IPS:\n"
    "        return True\n"
    "\n"
    "    dst_ip = str(get_nested(log, \"context.raw_event.data.dstip\") or\n"
    "                 get_nested(log, \"destination.ip\") or \"\")\n"
    "    if dst_ip in _SUPPRESS_SOURCE_IPS:\n"
    "        return True\n"
    "\n"
    "    # Suppress events with no resolvable user identity\n"
    "    user = str(get_nested(log, \"subject.name\") or \"\")\n"
    "    if not user or user.lower() in (\"none\", \"null\", \"\"):\n"
    "        anomaly_count = int(get_nested(log, \"enrich.anomalies.anomaly_count\") or 0)\n"
    "        if anomaly_count == 0:\n"
    "            return True\n"
    "\n"
    "    return False\n"
)

if "_SUPPRESS_SOURCE_IPS" in content and "src_ip in _SUPPRESS_SOURCE_IPS" not in content:
    # Replace last return False in is_noise
    # Find is_noise function and replace its final return False
    content = content.replace(
        "    return False\n\n\n# ── Feature Extractor",
        new_checks + "\n\n# ── Feature Extractor"
    )
    changed.append("patched is_noise with IP + None user checks")

# ── 4. Add _SUPPRESS_AGENT_NAMES check if missing ────────────────────────────
if "_SUPPRESS_AGENT_NAMES" in content and "candidate_names & _SUPPRESS_AGENT_NAMES" not in content:
    content = content.replace(
        "    return False\n\n\n# ── Feature Extractor",
        '    candidate_names = {\n'
        '        str(get_nested(log, "subject.name") or ""),\n'
        '        str(get_nested(log, "object.name") or ""),\n'
        '        str(get_nested(log, "host.name") or ""),\n'
        '        str(get_nested(log, "context.raw_event.data.dstuser") or ""),\n'
        '        str(get_nested(log, "context.raw_event.data.srcuser") or ""),\n'
        '    }\n'
        '    if candidate_names & _SUPPRESS_AGENT_NAMES:\n'
        '        return True\n\n'
        + new_checks + "\n\n# ── Feature Extractor"
    )
    changed.append("added _SUPPRESS_AGENT_NAMES check to is_noise")

open(path, "w").write(content)
print(f"✓ Patched {path}")
for c in changed:
    print(f"  · {c}")
if not changed:
    print("  · Nothing to change — already up to date")
