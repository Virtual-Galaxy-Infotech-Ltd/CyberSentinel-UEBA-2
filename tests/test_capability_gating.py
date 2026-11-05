#!/usr/bin/env python3
"""Every data-cap in the console is backed by a capability AND a hide rule.

THE BUG CLASS THIS CATCHES

UI gating needs three things to agree, in three different files:

    index.html          data-cap="x.y"              — marks the panel
    ueba_dashboard_server.py   CAPABILITIES["x.y"]  — tells the browser about it
    styles.css          body.nocap-x-y [data-cap="x.y"]  — actually hides it

Miss the second and the browser is never told the capability exists, so it
never sets the class, so the panel renders for EVERY signed-in user as a set
of controls that all come back 403. Miss the third and the same thing happens
for a different reason. Neither failure raises anything, in any file, and
both look like the feature working.

It has now happened twice. `users.manage` shipped with a panel and no hide
rule, and the whole User Management screen rendered for viewers. `smtp.edit`
shipped with a panel and a hide rule but no CAPABILITIES entry, which fails
the same way — found 2026-11-05, while a colleague was mid-build on it.

So this is not a test of one capability. It is the cross-check, and it reads
all three files so that the next one cannot ship quietly either.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("UEBA_ROOT") or HERE.parent).resolve()
sys.path.insert(0, str(ROOT))

_failures: list = []
_checks: list = []


def ok(label, cond, detail=""):
    _checks.append(label)
    if not cond:
        _failures.append("%s%s" % (label, (" — " + detail) if detail else ""))
    return bool(cond)


def nocap_class(cap: str) -> str:
    """The body class the browser sets. Mirrors bodyClass() in capabilities.js."""
    return "nocap-" + cap.replace(".", "-")


def main() -> int:
    server = ROOT / "ueba_dashboard_server.py"
    index = ROOT / "dashboard" / "index.html"
    css = ROOT / "dashboard" / "src" / "styles.css"
    capjs = ROOT / "dashboard" / "src" / "ui" / "capabilities.js"

    for p in (server, index, css, capjs):
        if not ok("%s is present" % p.name, p.exists(), str(p)):
            return _report()

    src = server.read_text(encoding="utf-8")
    html = index.read_text(encoding="utf-8")
    style = css.read_text(encoding="utf-8")
    js = capjs.read_text(encoding="utf-8")

    # ── the three sources ──
    block = re.search(r"CAPABILITIES = \{(.*?)\n\}", src, re.S)
    ok("the CAPABILITIES table is readable", block is not None)
    if block is None:
        return _report()
    declared = dict(re.findall(r'"([a-z.]+)":\s*"(viewer|analyst|admin)"',
                               block.group(1)))
    ok("capabilities are declared", len(declared) >= 15, str(len(declared)))

    marked = set(re.findall(r'data-cap="([a-z.]+)"', html))
    ok("the console marks panels with data-cap", len(marked) >= 5,
       str(sorted(marked)))

    hidden = set(re.findall(r'body\.nocap-[a-z-]+ \[data-cap="([a-z.]+)"\]',
                            style))
    ok("the stylesheet has hide rules", len(hidden) >= 10, str(len(hidden)))

    # ── the cross-check, in both directions ──
    for cap in sorted(marked):
        ok("data-cap %s is declared in CAPABILITIES" % cap,
           cap in declared,
           "the browser is never told it exists, so the panel is NEVER hidden")
        ok("data-cap %s has a hide rule" % cap,
           cap in hidden,
           "nothing in the stylesheet acts on %s" % nocap_class(cap))

    # Every DECLARED capability wants a hide rule too. A capability with no
    # panel today gets one tomorrow, and the rule is the half people forget.
    for cap in sorted(declared):
        ok("declared capability %s has a hide rule" % cap, cap in hidden,
           "add body.%s [data-cap=\"%s\"] to styles.css" % (nocap_class(cap), cap))

    # A hide rule for something nobody declares is dead CSS, and worse, it
    # suggests gating that does not exist.
    for cap in sorted(hidden):
        ok("hide rule %s matches a declared capability" % cap,
           cap in declared,
           "styles.css hides %s but the server never reports it" % cap)

    # ── the class name must match what the browser computes ──
    ok("the browser derives the class by replacing dots with dashes",
       'cap.replace(/\\./g, "-")' in js,
       "capabilities.js no longer derives nocap- the way this test assumes")
    ok("and only toggles classes for capabilities the SERVER returned",
       "Object.keys(CAPS)" in js,
       "if this changed, an undeclared capability may now be hidden after all")

    # ── the two regressions, named ──
    ok("users.manage is fully wired (it once was not)",
       "users.manage" in declared and "users.manage" in hidden)
    ok("smtp.edit is fully wired (it once was not)",
       "smtp.edit" in declared and "smtp.edit" in hidden)
    ok("and smtp.edit is admin-only", declared.get("smtp.edit") == "admin",
       repr(declared.get("smtp.edit")))

    return _report()


def _report() -> int:
    total = len(_checks)
    if _failures:
        print("capability gating: %d/%d FAILED" % (len(_failures), total))
        for f in _failures:
            print("  ✗ %s" % f)
    else:
        print("capability gating: all %d checks passed" % total)
    return 1 if _failures else 0


if __name__ == "__main__":
    sys.exit(main())
