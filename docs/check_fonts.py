"""Report the smallest body font on each slide. Anything under ~10pt is hard to
read from the back of a room, so a deck that silently shrank to fit is a deck
that needs its copy cut instead."""
import sys
from pptx import Presentation

prs = Presentation(sys.argv[1])
FLOOR = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
worst = []
for i, slide in enumerate(prs.slides, 1):
    sizes = []
    for sh in slide.shapes:
        if not sh.has_text_frame:
            continue
        for p in sh.text_frame.paragraphs:
            for r in p.runs:
                if r.text.strip() and r.font.size:
                    sizes.append(r.font.size.pt)
    if sizes:
        lo = min(sizes)
        # Slide numbers and footers are meant to be small; ignore them.
        body = [x for x in sizes if x > 9.6]
        lo_body = min(body) if body else lo
        worst.append((i, lo_body))
under = [(i, s) for i, s in worst if s < FLOOR]
print(f"  slides: {len(worst)}   smallest body font overall: "
      f"{min(s for _, s in worst):.1f}pt")
if under:
    print(f"  BELOW {FLOOR}pt on {len(under)} slide(s):")
    for i, s in under:
        print(f"    slide {i:2}: {s:.1f}pt")
else:
    print(f"  every slide keeps body text at {FLOOR}pt or above")
