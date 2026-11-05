# Email sender: one-time setup

Reports and alert notifications are sent from a mailbox that someone on the
client's SOC team connects by clicking **Connect Gmail** or **Connect
Microsoft 365 / Outlook** under **Alerting → Email Sender**. They sign in on
Google's or Microsoft's own page and allow UEBA to *send* mail. They never
enter a server name, port or password.

For those buttons to appear, the vendor registers **one OAuth app per provider,
once**, and ships the IDs with the product. Clients don't repeat this.

## What each client install needs

1. **An HTTPS address for the dashboard**, e.g. `https://ueba.client.com`.
   Google and Microsoft only send the browser back to HTTPS addresses (or
   `localhost`). A bare IP over plain HTTP won't work. Set it as
   `dashboard.email.public_url`.
2. **That install's callback URL added to the OAuth apps**:
   `https://ueba.client.com/api/email/oauth/callback`.
   It is also shown by `GET /api/email/status` as `redirect_uri`.
3. **Outbound HTTPS to the provider.** Under `egress.mode: on_premises`, add
   the hosts for each provider you enable to `egress.allow`:
   - Google: `accounts.google.com`, `oauth2.googleapis.com`, `gmail.googleapis.com`
   - Microsoft: `login.microsoftonline.com`, `graph.microsoft.com`

## Google (Gmail and Google Workspace)

1. In Google Cloud Console, create a project and enable the **Gmail API**.
2. **OAuth consent screen**: User type *External*. Add the scope
   `https://www.googleapis.com/auth/gmail.send`. This is a *sensitive* scope,
   so publish the app and submit it for **Google verification**. Until it is
   verified, only listed test users can connect, and they see an
   "unverified app" warning.
3. **Credentials → Create OAuth client ID → Web application.** Add each
   install's callback URL under *Authorised redirect URIs*.
4. Put the client ID in `dashboard.email.google.client_id`, and the secret in
   the `UEBA_GOOGLE_CLIENT_SECRET` environment variable of the
   `ueba-dashboard` service.

## Microsoft (Microsoft 365, Outlook.com)

1. In the Microsoft Entra admin center: **App registrations → New
   registration**. Supported account types: *Accounts in any organizational
   directory and personal Microsoft accounts*. Platform *Web*, with each
   install's callback URL as a redirect URI.
2. **API permissions → Microsoft Graph → Delegated**: `Mail.Send`,
   `User.Read`, `offline_access`, `openid`, `email`.
3. **Certificates & secrets → New client secret.**
4. Complete **publisher verification** so client admins see a verified
   publisher.
5. Put the application (client) ID in `dashboard.email.microsoft.client_id`,
   and the secret in `UEBA_MS_CLIENT_SECRET`.

Many organisations block users from consenting to apps themselves. In that
case the client's Microsoft 365 admin approves the app once, using the link
in Entra → Enterprise applications → *Grant admin consent*. After that
anyone in the organisation can connect.

## Behaviour

- Only one mailbox is connected per install. Connecting a new one replaces it.
- The refresh token is stored in `email_connection.json`, next to the other
  reporting state, with mode 0600.
- Disconnecting deletes it, and for Google also revokes the token.
- If no mailbox is connected but `reporting.smtp.host` is set, mail goes
  through that SMTP relay. This is for air-gapped sites.
- Microsoft Graph rejects attachments over about 3 MB in a single send. A
  larger report is still saved under Recent Reports, and the failure says so.

## This install: the callback URL to register

The guide above says "add each install's callback URL". Working out what that
is for an on-premises box is the step that stalls, so for this deployment it
is settled here.

**Register exactly this, in both provider consoles:**

```
https://localhost:3026/api/email/oauth/callback
```

### Why localhost and not the console's own address

| Candidate | Verdict |
| --- | --- |
| `https://10.200.10.23:3026/...` | **Refused.** Google does not accept a private IP as a redirect URI for a web application client. |
| `https://csen-siem.vgipl.com:3026/...` | Resolves publicly (103.252.168.197) but ports 3026 and 443 are filtered from outside, so the browser cannot be sent back to it. |
| `https://localhost:3026/...` | **Works.** localhost is the one host both providers accept without a public domain, over http or https. |

It must stay on **3026 over https**. Port 3026 is nginx, whose `server_name`
already includes `localhost`; `auth.cookie_secure` is true, so the session
cookie is not sent over plain http — tunnelling to Flask's 3027 directly
would leave the admin unable to log in at all.

### Connecting a mailbox

```
ssh -L 3026:localhost:3026 vgipl
```

Then open `https://localhost:3026`, accept the self-signed certificate, sign
in, and go to **Alerting → Email Sender → Connect Gmail** (or Connect
Microsoft). The sign-in happens on Google's or Microsoft's own page; the
refresh token is stored on the server and the mailbox can be disconnected at
any time from either side.

The tunnel is only needed to *connect* the mailbox. Once connected, reports
and alert emails send without it.

### The config block

Add this under `dashboard:` in `/opt/ueba/ueba_config.yaml`:

```yaml
  # ── Email sender (OAuth) ──────────────────────────────────────────────────
  # Lets an admin connect a Gmail or Microsoft 365 mailbox by signing in, so
  # no app password or SMTP server is configured on this box at all. The
  # product is only granted permission to SEND as that mailbox; it cannot read
  # it, and the connection can be revoked from the provider at any time.
  #
  # public_url is the address the ADMIN'S BROWSER reaches this console on, and
  # it is what gets sent to Google/Microsoft as the OAuth callback. It is
  # localhost here on purpose:
  #
  #   * Google REFUSES a private IP (10.200.10.23) as a redirect URI for a web
  #     application client, so the console's own address cannot be used.
  #   * csen-siem.vgipl.com resolves publicly (103.252.168.197) but ports 3026
  #     and 443 are filtered from outside, so the console is not reachable
  #     there either.
  #   * localhost is the one host both providers accept without a public
  #     domain, so the admin forwards a port and signs in through that.
  #
  # It must stay on 3026 and https: 3026 is nginx (which already answers to the
  # name "localhost"), and auth.cookie_secure is true, so the session cookie
  # is not sent over plain http — tunnelling to Flask's 3027 directly would
  # leave the admin unable to log in.
  #
  # To connect a mailbox:
  #     ssh -L 3026:localhost:3026 vgipl
  #     open https://localhost:3026  (accept the self-signed certificate)
  #     Alerting → Email Sender → Connect Gmail / Connect Microsoft
  #
  # The redirect URI to register in BOTH provider consoles is exactly:
  #     https://localhost:3026/api/email/oauth/callback
  email:
    public_url: "https://localhost:3026"
    google:
      # From Google Cloud Console → Credentials → OAuth client ID → Web
      # application. The Gmail API must be enabled and the
      # .../auth/gmail.send scope added to the consent screen.
      client_id: ""
      # Never the secret itself: it is read from this environment variable on
      # the ueba-dashboard service.
      client_secret_env: UEBA_GOOGLE_CLIENT_SECRET
    microsoft:
      # Microsoft Entra → App registrations → New registration, platform Web.
      # Delegated Graph permissions: Mail.Send, User.Read, offline_access,
      # openid, email.
      client_id: ""
      client_secret_env: UEBA_MS_CLIENT_SECRET
      # "common" lets both work and personal Microsoft accounts connect.
      tenant: common
```

Then put the two secrets on the service rather than in the file:

```
systemctl edit ueba-dashboard
```

```
[Service]
Environment=UEBA_GOOGLE_CLIENT_SECRET=...
Environment=UEBA_MS_CLIENT_SECRET=...
```

```
systemctl daemon-reload && systemctl restart ueba-dashboard
```

### Checking it took

`GET /api/email/status` reports `readiness`, which names what is still
missing — per provider, whether it is the `client_id` or the secret and which
environment variable it should come from — and whether the callback URL will
be refused. Until an OAuth app is registered it reads:

> no OAuth application is configured yet, so the Connect buttons cannot work

and once one is, it reads:

> ready to connect a mailbox
