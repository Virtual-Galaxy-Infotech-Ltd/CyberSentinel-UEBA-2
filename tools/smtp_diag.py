#!/usr/bin/env python3
"""Diagnose mail delivery from THIS host — RFP SN 39 (report/alert email).

Why this exists: the console's test button reports one sentence, and the
underlying exception is ambiguous. Measured against Gmail on 18-Nov-2026, a
*wrong password* does not arrive as SMTPAuthenticationError — the server hangs
up part-way through AUTH and smtplib raises SMTPServerDisconnected, which looks
identical to a network filter cutting the session. This separates the two by
walking the connection one stage at a time and naming the stage that failed.

It never prints the password, and it does not send mail unless --send is given.

    python3 tools/smtp_diag.py --config ueba_config.yaml
    python3 tools/smtp_diag.py --config ueba_config.yaml --send you@example.com
"""
from __future__ import annotations

import argparse
import json
import os
import smtplib
import socket
import ssl
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_cfg(cfg_path: str, store_path: str | None) -> dict:
    """Effective settings: YAML first, then whatever the console saved."""
    import yaml
    smtp: dict = {}
    try:
        c = yaml.safe_load(open(cfg_path)) or {}
        smtp.update(((c.get("reporting") or {}).get("smtp") or {}))
    except Exception as e:
        print("  ! could not read %s: %s" % (cfg_path, e))
    # The console's saved settings override the YAML, which is the precedence
    # ueba_dashboard_server._smtp_cfg() applies.
    #
    # Resolving the path the way _smtp_store_path() does matters more than it
    # looks. That function places the file beside an operator-state file the
    # site has actually configured, so it is NOT at a fixed location — on this
    # deployment it is /opt/ueba/smtp_settings.json, derived from the alert
    # store. A guessed list of names found nothing and this tool reported "no
    # mail server configured" while the console had one saved all along.
    cands = [store_path] if store_path else []
    if not store_path:
        try:
            c = yaml.safe_load(open(cfg_path)) or {}
            paths = c.get("paths") or {}
            explicit = ((c.get("reporting") or {}).get("smtp_file"))
            if explicit:
                cands.append(explicit)
            for key in ("false_positives_file", "watchlist_file",
                        "nicknames_file", "ueba_output"):
                sib = paths.get(key) or c.get(key)
                if sib:
                    cands.append(str(Path(sib).parent / "smtp_settings.json"))
        except Exception:
            pass
        cands += ["smtp_settings.json", "profiles/smtp.json", ".state/smtp.json"]
    seen = set()
    for cand in [c for c in cands if c and not (c in seen or seen.add(c))]:
        p = Path(cand)
        if p.exists():
            try:
                d = json.loads(p.read_text())
                if isinstance(d, dict):
                    smtp.update({k: v for k, v in d.items() if v not in (None, "")})
                    print("  console settings found: %s" % p)
                    break
            except Exception as e:
                print("  ! %s unreadable: %s" % (p, e))
    env = smtp.get("password_env") or "UEBA_SMTP_PASSWORD"
    if os.environ.get(env):
        smtp["password"] = os.environ[env]
        print("  password taken from $%s" % env)
    return smtp


def main() -> int:
    ap = argparse.ArgumentParser(description="Diagnose SMTP from this host")
    ap.add_argument("--config", default="ueba_config.yaml")
    ap.add_argument("--store", default=None, help="path to the console's smtp.json")
    ap.add_argument("--host"), ap.add_argument("--port", type=int)
    ap.add_argument("--send", metavar="ADDR", help="actually send a test message")
    ap.add_argument("--timeout", type=int, default=20)
    a = ap.parse_args()

    print("EFFECTIVE SETTINGS")
    cfg = load_cfg(a.config, a.store)
    host = a.host or (cfg.get("host") or "").strip()
    port = int(a.port or cfg.get("port") or 587)
    user = (cfg.get("username") or "").strip()
    pw = cfg.get("password") or ""
    use_ssl = bool(cfg.get("ssl")) or port == 465
    want_starttls = bool(cfg.get("starttls", True))

    print("  host=%r port=%d ssl=%s starttls=%s" % (host, port, use_ssl, want_starttls))
    print("  username=%r  password=%s (%d chars)"
          % (user, "SET" if pw else "NOT SET", len(pw)))
    if not host:
        print("\nNo mail server configured. Set it in Settings -> Email.")
        return 2
    if user and pw and host.lower().endswith(("gmail.com", "googlemail.com")):
        # Gmail app passwords are 16 characters. Anything else is almost
        # certainly the account password, which Gmail refuses over SMTP.
        stripped = pw.replace(" ", "")
        if len(stripped) != 16:
            print("  ! %d characters. A Gmail app password is 16. This looks "
                  "like the account password, which Gmail will refuse."
                  % len(stripped))

    print("\nSTAGE 1 — TCP reach")
    try:
        s = socket.create_connection((host, port), timeout=a.timeout)
        s.close()
        print("  OK  %s:%d accepts connections" % (host, port))
    except Exception as e:
        print("  FAIL %s: %s" % (type(e).__name__, e))
        print("  -> the port is blocked or nothing is listening. Nothing below "
              "can work until this does.")
        return 1

    print("\nSTAGE 2 — SMTP session and encryption")
    srv = None
    try:
        if use_ssl:
            srv = smtplib.SMTP_SSL(host, port, timeout=a.timeout)
            print("  OK  implicit TLS established (ssl=true)")
        else:
            srv = smtplib.SMTP(host, port, timeout=a.timeout)
            print("  OK  plaintext session open")
        srv.ehlo()
        offers = "starttls" if srv.has_extn("starttls") else "no starttls"
        print("  server offers: %s" % offers)
        if not use_ssl and want_starttls and srv.has_extn("starttls"):
            srv.starttls(context=ssl.create_default_context()
                         if cfg.get("verify_tls", True)
                         else ssl._create_unverified_context())
            srv.ehlo()
            print("  OK  STARTTLS negotiated")
        elif not use_ssl and not srv.has_extn("starttls"):
            print("  !   server does not offer STARTTLS on this port")
        auth = srv.esmtp_features.get("auth", "")
        print("  AUTH advertised: %s" % (auth.strip() or "<none>"))
        if user and not auth.strip():
            print("  !   a username is configured but the server will not take "
                  "a login on this connection — encryption is usually missing")
    except Exception as e:
        print("  FAIL %s: %s" % (type(e).__name__, str(e)[:200]))
        if isinstance(e, ssl.SSLError):
            print("  -> ssl/port mismatch: 465 needs ssl=true, 587 needs "
                  "ssl=false with starttls=true")
        return 1

    print("\nSTAGE 3 — sign in")
    if not user:
        print("  skipped: no username configured (unauthenticated relay)")
    elif not pw:
        print("  FAIL username set but no password available")
        return 1
    else:
        try:
            srv.login(user, pw)
            print("  OK  signed in as %s" % user)
        except smtplib.SMTPAuthenticationError as e:
            print("  FAIL credentials rejected: %s" % str(e)[:160])
            return 1
        except smtplib.SMTPServerDisconnected:
            print("  FAIL the server hung up DURING sign-in.")
            print("  -> this is what a wrong password looks like on Gmail; it "
                  "does not return an auth error, it disconnects.")
            print("  -> Gmail needs a 16-character app password (Google "
                  "Account -> Security -> App passwords, 2-Step must be on).")
            print("  -> if the password is definitely right, a network filter "
                  "is cutting the session; stages 1 and 2 passed, so the path "
                  "is open but something is inspecting it.")
            return 1
        except Exception as e:
            print("  FAIL %s: %s" % (type(e).__name__, str(e)[:160]))
            return 1

    if a.send:
        print("\nSTAGE 4 — send")
        try:
            from email.message import EmailMessage
            m = EmailMessage()
            m["From"] = cfg.get("from_addr") or user or "ueba@localhost"
            m["To"] = a.send
            m["Subject"] = "CyberSentinel UEBA — SMTP diagnostic"
            m.set_content("Sent by tools/smtp_diag.py. Mail delivery works.\n")
            srv.send_message(m)
            print("  OK  accepted for delivery to %s" % a.send)
        except Exception as e:
            print("  FAIL %s: %s" % (type(e).__name__, str(e)[:200]))
            return 1
    else:
        print("\nSTAGE 4 — send: skipped (pass --send ADDR to try it)")

    try:
        srv.quit()
    except Exception:
        pass
    print("\nAll stages passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
