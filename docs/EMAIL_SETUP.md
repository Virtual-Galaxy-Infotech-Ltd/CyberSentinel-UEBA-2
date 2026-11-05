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
