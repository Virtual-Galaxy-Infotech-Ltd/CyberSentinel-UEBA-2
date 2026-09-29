# UEBA documentation

| File | Audience |
|---|---|
| `CyberSentinel_UEBA_Technical_Document.docx` | Technical reference — architecture, detection methodology, technology stack, operations, capability statement. 13 sections. |
| `CyberSentinel_UEBA_Client_Presentation.pptx` | Client presentation. 6 slides, 16:9. |

## Regenerating

    scp deck_style.py build_*.py check_*.py box98:/root/NEW_DRIVE/aditya_ueba/
    ssh box98 'cd /root/NEW_DRIVE/aditya_ueba && \
      ./venv/bin/python3 build_techdoc.py && ./venv/bin/python3 build_deck.py'

## Checks — run after editing deck copy

| Script | Catches |
|---|---|
| `check_deck.py <pptx>` | Text overflowing its box — invisible until the file is opened, and the usual way a generated deck ships broken. |
| `check_fonts.py <pptx> [floor]` | Body text shrunk below a readable size. |
| `check_geometry.py <pptx>` | Shapes escaping the slide; panels colliding. |

All three pass clean on the deck as shipped.

## Notes

Arial throughout — Segoe UI is Windows-only and falls back to a serif on macOS.

Every figure in both documents was measured on the running deployment on
**23 September 2026**. Re-verify before reusing against a different installation.
