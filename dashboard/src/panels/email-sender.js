// Alerting → Email Sender. Connect the mailbox reports and alerts are sent
// from by signing in with Google or Microsoft. No server names, ports or
// passwords: the provider's own sign-in page grants a send-only permission.

import { showToast } from "../ui/toast.js";

const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function fmtWhen(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

const GOOGLE_ICON = `<svg viewBox="0 0 48 48" width="16" height="16" aria-hidden="true"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z"/><path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z"/></svg>`;
const MS_ICON = `<svg viewBox="0 0 23 23" width="15" height="15" aria-hidden="true"><path fill="#f35325" d="M1 1h10v10H1z"/><path fill="#81bc06" d="M12 1h10v10H12z"/><path fill="#05a6f0" d="M1 12h10v10H1z"/><path fill="#ffba08" d="M12 12h10v10H12z"/></svg>`;

let _status = null;

function render() {
  const st = $("em-status"), act = $("em-actions"), badge = $("em-badge");
  if (!st || !act) return;
  const s = _status;
  if (!s) {
    st.textContent = "Email sending is not available on this server.";
    act.innerHTML = "";
    return;
  }
  const c = s.connection;
  if (c) {
    if (badge) badge.textContent = "connected";
    st.innerHTML = `
      <div class="em-conn">
        <span class="em-conn-icon">${c.provider === "google" ? GOOGLE_ICON : MS_ICON}</span>
        <div>
          <div class="em-conn-email">${esc(c.email || "Connected mailbox")}</div>
          <div class="em-conn-meta">${esc(c.label)} · connected${c.connected_by ? " by " + esc(c.connected_by) : ""}
            ${c.connected_at ? " · " + esc(fmtWhen(c.connected_at)) : ""}
            ${c.last_sent_at ? " · last sent " + esc(fmtWhen(c.last_sent_at)) : ""}</div>
          ${c.last_error ? `<div class="em-conn-err">Last attempt failed: ${esc(c.last_error)}</div>` : ""}
        </div>
      </div>
      <div class="em-note">Scheduled reports and alert notifications are sent from this mailbox.</div>`;
    act.innerHTML = `
      <input id="em-test-to" class="wl-input" type="text" placeholder="Send a test to (defaults to ${esc(c.email || "this mailbox")})" autocomplete="off" style="flex:1 1 260px">
      <button class="export-btn wl-add-btn" id="em-test-btn">Send test email</button>
      <button class="fp-btn-inline" id="em-disconnect-btn">Disconnect</button>`;
    $("em-test-btn").addEventListener("click", sendTest);
    $("em-disconnect-btn").addEventListener("click", disconnect);
    return;
  }

  if (badge) badge.textContent = s.smtp_fallback ? "using mail relay" : "not connected";
  const p = s.providers || {};
  const none = !p.google && !p.microsoft;
  st.innerHTML = none
    ? `<div class="em-note">Sign-in with Gmail or Microsoft has not been enabled on this installation yet.
         ${s.smtp_fallback ? "Email is currently sent through the mail relay configured on the server." : "Contact your CyberSentinel support team to enable it."}</div>`
    : `<div class="em-note">Choose the mailbox that should send reports and alerts. You will sign in on
         Google's or Microsoft's own page and allow UEBA to <b>send</b> email. It cannot read your inbox.
         ${s.smtp_fallback ? "<br>Until then, email goes through the mail relay configured on the server." : ""}</div>`;
  act.innerHTML = `
    ${p.google ? `<button class="em-connect" id="em-google">${GOOGLE_ICON}<span>Connect Gmail</span></button>` : ""}
    ${p.microsoft ? `<button class="em-connect" id="em-ms">${MS_ICON}<span>Connect Microsoft 365 / Outlook</span></button>` : ""}`;
  if (p.google) $("em-google").addEventListener("click", () => connect("google"));
  if (p.microsoft) $("em-ms").addEventListener("click", () => connect("microsoft"));
}

async function readJson(r) {
  try { return await r.json(); } catch { return {}; }
}

export async function loadEmailSender() {
  if (!$("em-status")) return;
  try {
    const r = await fetch("/api/email/status", { credentials: "same-origin" });
    if (!r.ok) { _status = null; render(); return; }
    const d = await readJson(r);
    _status = d.ok ? d : null;
  } catch {
    _status = null;
  }
  render();
}

async function connect(provider) {
  try {
    const r = await fetch("/api/email/connect/" + provider, { method: "POST", credentials: "same-origin" });
    const d = await readJson(r);
    if (!r.ok || !d.url) throw new Error(d.error || `HTTP ${r.status}`);
    location.href = d.url;           // Google / Microsoft sign-in page
  } catch (e) {
    showToast("Could not start sign-in: " + e.message, "error", 8000);
  }
}

async function disconnect() {
  const c = _status && _status.connection;
  if (!confirm(`Disconnect ${c && c.email ? c.email : "this mailbox"}? Reports and alerts will stop being emailed until another mailbox is connected.`)) return;
  try {
    const r = await fetch("/api/email/disconnect", { method: "POST", credentials: "same-origin" });
    const d = await readJson(r);
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast("Mailbox disconnected", "success");
    loadEmailSender();
  } catch (e) {
    showToast("Could not disconnect: " + e.message, "error");
  }
}

async function sendTest() {
  const to = ($("em-test-to")?.value || "").trim();
  const btn = $("em-test-btn");
  if (btn) btn.disabled = true;
  showToast("Sending test email…", "info");
  try {
    const r = await fetch("/api/email/test", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to }),
    });
    const d = await readJson(r);
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Test email sent to ${(d.sent_to || []).join(", ")}`, "success", 6000);
  } catch (e) {
    showToast("Test email failed: " + e.message, "error", 12000);
  } finally {
    if (btn) btn.disabled = false;
    loadEmailSender();
  }
}

/** Show the outcome of a sign-in the provider just redirected back from. */
function consumeRedirectResult() {
  const q = new URLSearchParams(location.search);
  const ok = q.get("email_connected"), err = q.get("email_error");
  if (!ok && !err) return;
  if (ok) showToast(`Connected ${ok}. Reports and alerts will be sent from it.`, "success", 7000);
  if (err) showToast(err, "error", 14000);
  q.delete("email_connected"); q.delete("email_error");
  const rest = q.toString();
  history.replaceState(history.state, "", location.pathname + (rest ? "?" + rest : "") + location.hash);
}

export function initEmailSender() {
  consumeRedirectResult();
  loadEmailSender();
  const tab = document.querySelector('.tab[data-tab="alerting"]');
  if (tab) tab.addEventListener("click", loadEmailSender);
}
