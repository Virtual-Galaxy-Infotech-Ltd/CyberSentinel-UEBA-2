#!/usr/bin/env python3
"""
ueba_mailer.py: send report and alert email through a connected mailbox.

WHY THIS EXISTS
---------------
Asking a client to configure SMTP (server names, ports, STARTTLS, app
passwords, SMTP AUTH policies) is the step where email setup always stalls.
Instead, someone on the SOC team clicks "Connect Gmail" or "Connect
Microsoft", signs in on Google's or Microsoft's own page, and grants this
product permission to *send* mail as them. Nothing else is configured on the
client side.

  Google     Gmail API, scope gmail.send (send only; cannot read the mailbox)
  Microsoft  Microsoft Graph, delegated Mail.Send (send only)

Both use OAuth 2.0 authorization code flow with PKCE. The refresh token is
kept on this server in a file only this service's user can read, and is used
to mint short-lived access tokens when a report or alert needs to go out.

ONE-TIME VENDOR SETUP
---------------------
The OAuth *applications* are registered once by the product vendor (one
Google Cloud OAuth client, one Microsoft Entra multi-tenant app) and their
IDs are shipped in ueba_config.yaml under dashboard.email. Clients never see
or edit them. See docs/EMAIL_SETUP.md.

FALLBACK
--------
If no mailbox is connected but reporting.smtp.host is set in the YAML (an
internal relay on an air-gapped site, say), mail goes over SMTP as before.
"""
import base64
import hashlib
import json
import os
import secrets
import threading
import time
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlencode

import requests

try:
    import ueba_egress
except Exception:          # the gate is optional in unit tests
    ueba_egress = None

PROVIDERS = ("google", "microsoft")
LABELS = {"google": "Gmail", "microsoft": "Microsoft 365 / Outlook"}

GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_SEND = "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send?uploadType=media"
GOOGLE_REVOKE = "https://oauth2.googleapis.com/revoke"
GOOGLE_SCOPES = "openid email https://www.googleapis.com/auth/gmail.send"

MS_AUTH = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
MS_TOKEN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
MS_SEND = "https://graph.microsoft.com/v1.0/me/sendMail"
MS_ME = "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName,displayName"
MS_SCOPES = ("openid email offline_access "
             "https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read")

# Graph's single-request sendMail rejects messages over ~4 MB once the
# attachment is base64-encoded. Larger reports are still saved and downloadable.
MS_MAX_ATTACHMENT = 3 * 1024 * 1024

HTTP_TIMEOUT = 30
PENDING_TTL = 600            # an unfinished sign-in expires after 10 minutes

# Hosts these flows talk to, for the egress allowlist.
EGRESS_HOSTS = {
    "google": ["accounts.google.com", "oauth2.googleapis.com", "gmail.googleapis.com"],
    "microsoft": ["login.microsoftonline.com", "graph.microsoft.com"],
}

_lock = threading.Lock()
_pending = {}                # state -> {...}; single-process server, so in memory is fine


class MailError(RuntimeError):
    """A send or sign-in failure with a message fit to show an operator."""


# ── configuration ───────────────────────────────────────────────────────────

def _secret(block):
    env = (block or {}).get("client_secret_env")
    if env and os.environ.get(env):
        return os.environ[env]
    return (block or {}).get("client_secret") or ""


def provider_cfg(cfg, provider):
    block = dict((cfg or {}).get(provider) or {})
    block["client_secret"] = _secret(block)
    if provider == "microsoft":
        block["tenant"] = block.get("tenant") or "common"
    return block


def available(cfg):
    """{provider: bool} — which Connect buttons can work on this install."""
    return {p: bool(provider_cfg(cfg, p).get("client_id") and provider_cfg(cfg, p).get("client_secret"))
            for p in PROVIDERS}


def _guard(url, provider):
    if ueba_egress is None:
        return
    try:
        ueba_egress.guard(url)
    except Exception as e:
        hosts = ", ".join(EGRESS_HOSTS[provider])
        raise MailError(
            f"This server's outbound-connection policy blocked {LABELS[provider]} "
            f"({e}). To allow sending through {LABELS[provider]}, add these hosts "
            f"to egress.allow in ueba_config.yaml and restart the dashboard: {hosts}.")


# ── connection store ────────────────────────────────────────────────────────

def load(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) and d.get("provider") in PROVIDERS else None
    except (FileNotFoundError, ValueError):
        return None


def _save(path, conn):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(conn, fh, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def public(conn):
    """What the browser may see about the connection: never a token."""
    if not conn:
        return None
    return {k: conn.get(k) for k in
            ("provider", "email", "name", "connected_by", "connected_at", "last_sent_at",
             "last_error")} | {"label": LABELS.get(conn.get("provider"), "")}


def disconnect(path, cfg):
    conn = load(path)
    if not conn:
        return False
    # Best effort: tell Google the token is no longer wanted. Microsoft has no
    # per-token revoke endpoint; the user can remove the app from their account.
    if conn.get("provider") == "google" and conn.get("refresh_token"):
        try:
            _guard(GOOGLE_REVOKE, "google")
            requests.post(GOOGLE_REVOKE, data={"token": conn["refresh_token"]}, timeout=10)
        except Exception:
            pass
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return True


# ── sign-in ─────────────────────────────────────────────────────────────────

def start(cfg, provider, redirect_uri, user):
    """URL of the provider's sign-in page for this attempt."""
    if provider not in PROVIDERS:
        raise MailError("Unknown email provider")
    pc = provider_cfg(cfg, provider)
    if not (pc.get("client_id") and pc.get("client_secret")):
        raise MailError(f"{LABELS[provider]} sign-in is not enabled on this installation.")
    # Fail now, not after the user has signed in, if this server may not reach
    # the provider to finish the job.
    _guard(GOOGLE_TOKEN if provider == "google" else MS_TOKEN.format(tenant=pc["tenant"]), provider)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)
    now = time.time()
    with _lock:
        for k in [k for k, v in _pending.items() if now - v["at"] > PENDING_TTL]:
            _pending.pop(k, None)
        _pending[state] = {"provider": provider, "verifier": verifier, "at": now,
                           "user": user, "redirect_uri": redirect_uri}
    params = {
        "client_id": pc["client_id"], "redirect_uri": redirect_uri,
        "response_type": "code", "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if provider == "google":
        params.update(scope=GOOGLE_SCOPES, access_type="offline", prompt="consent",
                      include_granted_scopes="true")
        return GOOGLE_AUTH + "?" + urlencode(params)
    params.update(scope=MS_SCOPES, prompt="select_account", response_mode="query")
    return MS_AUTH.format(tenant=pc["tenant"]) + "?" + urlencode(params)


def _jwt_claims(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _token_request(provider, pc, data):
    url = GOOGLE_TOKEN if provider == "google" else MS_TOKEN.format(tenant=pc["tenant"])
    _guard(url, provider)
    data = dict(data, client_id=pc["client_id"], client_secret=pc["client_secret"])
    try:
        r = requests.post(url, data=data, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        raise MailError(f"Could not reach {LABELS[provider]}: {e}")
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code != 200:
        err = body.get("error") or f"HTTP {r.status_code}"
        desc = (body.get("error_description") or "").split("\r\n")[0]
        if err == "invalid_grant":
            raise MailError(f"{LABELS[provider]} no longer accepts this connection "
                            f"(the permission was removed or expired). Reconnect the mailbox "
                            f"in Alerting → Email Sender.")
        raise MailError(f"{LABELS[provider]} refused the request: {err}" + (f" ({desc})" if desc else ""))
    return body


def finish(cfg, path, state, code, error=None, error_description=None):
    """Complete a sign-in from the provider's redirect. Returns the public view."""
    with _lock:
        p = _pending.pop(state or "", None)
    if not p or time.time() - p["at"] > PENDING_TTL:
        raise MailError("This sign-in link has expired. Start again from Alerting → Email Sender.")
    provider = p["provider"]
    if error:
        if error in ("access_denied", "consent_required"):
            raise MailError(f"Permission was not granted on the {LABELS[provider]} page, so "
                            f"no mailbox was connected."
                            + (" Your organisation may require an administrator to approve this "
                               "app first." if provider == "microsoft" else ""))
        raise MailError(f"{LABELS[provider]} sign-in failed: {error_description or error}")
    if not code:
        raise MailError("The sign-in did not return an authorisation code.")
    pc = provider_cfg(cfg, provider)
    tok = _token_request(provider, pc, {
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": p["redirect_uri"], "code_verifier": p["verifier"],
    })
    if not tok.get("refresh_token"):
        raise MailError(f"{LABELS[provider]} did not grant long-term access. Try connecting again.")
    claims = _jwt_claims(tok.get("id_token") or "")
    email, name = claims.get("email"), claims.get("name")
    if provider == "microsoft":
        try:
            _guard(MS_ME, provider)
            me = requests.get(MS_ME, headers={"Authorization": "Bearer " + tok["access_token"]},
                              timeout=HTTP_TIMEOUT).json()
            email = me.get("mail") or me.get("userPrincipalName") or email
            name = me.get("displayName") or name
        except Exception:
            pass
    if provider == "google" and "gmail.send" not in (tok.get("scope") or ""):
        raise MailError("Permission to send email was not ticked on the Google page. "
                        "Connect again and allow \"Send email on your behalf\".")
    conn = {
        "provider": provider, "email": email or "", "name": name or "",
        "connected_by": p.get("user") or "", "connected_at": _now(),
        "refresh_token": tok["refresh_token"],
        "access_token": tok.get("access_token"),
        "expires_at": time.time() + int(tok.get("expires_in") or 3000) - 60,
    }
    with _lock:
        _save(path, conn)
    return public(conn)


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _access_token(cfg, path, conn):
    if conn.get("access_token") and time.time() < float(conn.get("expires_at") or 0):
        return conn["access_token"]
    pc = provider_cfg(cfg, conn["provider"])
    if not (pc.get("client_id") and pc.get("client_secret")):
        raise MailError(f"{LABELS[conn['provider']]} sign-in is no longer enabled on this installation.")
    data = {"grant_type": "refresh_token", "refresh_token": conn["refresh_token"]}
    if conn["provider"] == "microsoft":
        data["scope"] = MS_SCOPES
    tok = _token_request(conn["provider"], pc, data)
    conn["access_token"] = tok["access_token"]
    conn["expires_at"] = time.time() + int(tok.get("expires_in") or 3000) - 60
    if tok.get("refresh_token"):            # Microsoft rotates it on every use
        conn["refresh_token"] = tok["refresh_token"]
    with _lock:
        _save(path, conn)
    return conn["access_token"]


# ── sending ─────────────────────────────────────────────────────────────────

def _record(path, conn, error):
    conn["last_error"] = error
    if not error:
        conn["last_sent_at"] = _now()
    try:
        with _lock:
            _save(path, conn)
    except Exception:
        pass


def send(cfg, path, *, to, subject, body, attachment=None, filename=None,
         mime="application/octet-stream"):
    """Send through the connected mailbox. Raises MailError with a readable reason."""
    conn = load(path)
    if not conn:
        raise MailError("No mailbox is connected. Connect one in Alerting → Email Sender.")
    to = [t for t in (to or []) if t]
    if not to:
        raise MailError("No recipients")
    provider = conn["provider"]
    try:
        token = _access_token(cfg, path, conn)
        if provider == "google":
            _send_gmail(token, conn, to, subject, body, attachment, filename, mime)
        else:
            _send_graph(token, to, subject, body, attachment, filename, mime)
    except MailError as e:
        _record(path, conn, str(e))
        raise
    except requests.RequestException as e:
        msg = f"Could not reach {LABELS[provider]}: {e}"
        _record(path, conn, msg)
        raise MailError(msg)
    _record(path, conn, None)


def _send_gmail(token, conn, to, subject, body, attachment, filename, mime):
    msg = EmailMessage()
    msg["From"] = conn.get("email") or "me"
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg.set_content(body)
    if attachment is not None:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(attachment, maintype=maintype or "application",
                           subtype=(subtype or "octet-stream").split(";")[0].strip(),
                           filename=filename or "report")
    _guard(GOOGLE_SEND, "google")
    r = requests.post(GOOGLE_SEND, data=msg.as_bytes(), timeout=HTTP_TIMEOUT * 2,
                      headers={"Authorization": "Bearer " + token,
                               "Content-Type": "message/rfc822"})
    if r.status_code >= 300:
        raise MailError("Gmail did not send the message: " + _api_error(r))


def _send_graph(token, to, subject, body, attachment, filename, mime):
    message = {
        "subject": subject,
        "body": {"contentType": "Text", "content": body},
        "toRecipients": [{"emailAddress": {"address": a}} for a in to],
    }
    if attachment is not None:
        if len(attachment) > MS_MAX_ATTACHMENT:
            raise MailError("The report is too large to email through Microsoft 365 "
                            f"({len(attachment) // 1024 // 1024} MB; the limit is 3 MB). It is saved "
                            "under Recent Reports, or choose a shorter period or the CSV format.")
        message["attachments"] = [{
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": filename or "report", "contentType": mime,
            "contentBytes": base64.b64encode(attachment).decode(),
        }]
    _guard(MS_SEND, "microsoft")
    r = requests.post(MS_SEND, json={"message": message, "saveToSentItems": True},
                      timeout=HTTP_TIMEOUT * 2, headers={"Authorization": "Bearer " + token})
    if r.status_code >= 300:
        raise MailError("Microsoft 365 did not send the message: " + _api_error(r))


def _api_error(r):
    try:
        e = r.json().get("error")
        if isinstance(e, dict):
            return f"{e.get('message') or e.get('code')} (HTTP {r.status_code})"
        if e:
            return f"{e} (HTTP {r.status_code})"
    except ValueError:
        pass
    return f"HTTP {r.status_code}"
