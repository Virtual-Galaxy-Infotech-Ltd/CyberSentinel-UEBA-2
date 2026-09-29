"""Verify no shape escapes the slide and no two panels collide.

Complements the text-overflow check: that one catches text outgrowing its box,
this catches a box outgrowing the slide — the other way a generated deck ships
visibly broken without anyone opening it.
"""
import sys
from pptx import Presentation

prs = Presentation(sys.argv[1])
W, H = prs.slide_width, prs.slide_height
TOL = 9144  # 0.01 inch
problems = []

for i, slide in enumerate(prs.slides, 1):
    panels = []
    for sh in slide.shapes:
        L, T = sh.left, sh.top
        R, B = L + sh.width, T + sh.height
        if L < -TOL or T < -TOL or R > W + TOL or B > H + TOL:
            problems.append((i, "off-slide",
                             f"{sh.shape_type}, right={R/914400:.2f}in "
                             f"bottom={B/914400:.2f}in"))
        # Rounded rectangles are the card/row panels.
        if sh.shape_type is not None and "ROUNDED" in str(sh.shape_type):
            panels.append((L, T, R, B))
    for a in range(len(panels)):
        for b in range(a + 1, len(panels)):
            L1, T1, R1, B1 = panels[a]
            L2, T2, R2, B2 = panels[b]
            ox = min(R1, R2) - max(L1, L2)
            oy = min(B1, B2) - max(T1, T2)
            if ox > TOL and oy > TOL:
                problems.append((i, "panels overlap",
                                 f"{ox/914400:.2f}in x {oy/914400:.2f}in"))

print(f"  slides: {len(prs.slides)}   slide size: "
      f"{W/914400:.2f} x {H/914400:.2f} in")
if problems:
    print(f"  {len(problems)} geometry problem(s):")
    for i, kind, detail in problems[:12]:
        print(f"    slide {i:2}: {kind} — {detail}")
else:
    print("  all shapes within bounds; no panel collisions")
