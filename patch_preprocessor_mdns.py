patch_preprocessor_mdns.py#!/usr/bin/env python3
"""
Patch ueba_preprocessor.py to suppress mDNS/Termius false positives.
Run: python3 patch_preprocessor_mdns.py ueba_preprocessor.py
"""
import sys, re

path = sys.argv[1] if len(sys.argv) > 1 else "ueba_preprocessor.py"
c = open(path).read()
changed = []

# ── 1. Add rule 130001 to _NOISE_SIGNATURE_IDS ────────────────────────────────
if '"130001"' not in c:
    c = re.sub(
        r'(_NOISE_SIGNATURE_IDS\s*=\s*\{)',
        r'\1\n    "130001",   # Sysmon event3: Termius/mDNS multicast discovery — false positive',
        c
    )
    changed.append("added 130001 to _NOISE_SIGNATURE_IDS")

# ── 2. Add mDNS multicast + port 5353 suppression to is_noise ─────────────────
mdns_check = (
    '    # Suppress mDNS multicast traffic — normal for SSH clients (Termius), printers, etc.\n'
    '    # 224.x.x.x is multicast address space, never a real attacker source\n'
    '    subject_ip = str(get_nested(log, "subject.ip") or "")\n'
    '    if subject_ip.startswith("224."):\n'
    '        return True\n'
    '\n'
    '    # Suppress port 5353 (mDNS) — never security relevant\n'
    '    subject_port = str(get_nested(log, "subject.port") or "")\n'
    '    object_port  = str(get_nested(log, "object.port") or "")\n'
    '    if subject_port == "5353" and object_port == "5353":\n'
    '        return True\n'
    '\n'
)

if 'subject_ip.startswith("224.")' not in c:
    # Insert before the existing src_ip _SUPPRESS_SOURCE_IPS check
    target = '    # Suppress engine server\'s own IP'
    if target in c:
        c = c.replace(target, mdns_check + target)
        changed.append("added mDNS multicast suppression (224.x.x.x)")
        changed.append("added mDNS port 5353 suppression")
    else:
        # Fallback — insert before final return False
        c = c.replace(
            '    return False\n\n\n# ── Feature Extractor',
            mdns_check + '    return False\n\n\n# ── Feature Extractor'
        )
        changed.append("added mDNS suppression (fallback insertion)")

open(path, "w").write(c)
print(f"✓ Patched {path}")
for ch in changed:
    print(f"  · {ch}")
if not changed:
    print("  · Nothing to change — already up to date")
