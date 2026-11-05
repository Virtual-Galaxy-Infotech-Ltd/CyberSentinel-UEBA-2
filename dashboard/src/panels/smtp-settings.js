// Settings → Email (SMTP). Admin only: the panel carries data-cap="smtp.edit"
// and every endpoint behind it is gated on the same capability server-side.
//
// Scheduled reports and alert-rule emails both send through these settings.
// The password never comes back from the server; the field stays blank and a
// blank save keeps the stored one.

import { showToast } from "../ui/toast.js";

const PRESETS = {
  gmail: {
    host: "smtp.gmail.com", port: 587, security: "starttls",
    help: `<b>Gmail:</b> Google does not accept your normal password here. Turn on
      2-Step Verification for the account, then create an <b>App password</b> at
      <code>myaccount.google.com/apppasswords</code> and paste the 16-letter code
      as the password. Login is your full Gmail address. Google Workspace (work)
      accounts on Gmail work the same way, if your admin allows app passwords.`,
  },
  office365: {
    host: "smtp.office365.com", port: 587, security: "starttls",
    help: `<b>Outlook / Office 365:</b> login is your full work email address. Your
      IT admin must allow <b>SMTP AUTH</b> for the mailbox (Microsoft 365 admin
      center → Users → Mail → Manage email apps → Authenticated SMTP). If your
      account uses multi-factor sign-in, use an app password.`,
  },
  custom: {
    host: "", port: 587, security: "starttls",
    help: `<b>Work mail server:</b> ask IT for the SMTP server name, port and
      whether it needs a login. Port 587 normally uses STARTTLS, 465 uses SSL/TLS,
      and an internal relay on port 25 often needs no login at all (leave login and
      password empty).`,
  },
};

const $ = (id) => document.getElementById(id);

function guessProvider(host) {
  const h = (host || "").toLowerCase();
  if (h.includes("gmail") || h.includes("googlemail")) return "gmail";
  if (h.includes("office365") || h.includes("outlook")) return "office365";
  return "custom";
}

function showHelp(provider, saved) {
  const el = $("set-smtp-help");
  if (!el) return;
  const status = saved && saved.configured
    ? `Currently sending through <code>${saved.host}:${saved.port}</code>` +
      (saved.username ? ` as <code>${saved.username}</code>` : "") +
      (saved.has_password ? " (password saved)." : " (no password saved).")
    : "No mail server is set yet, so report and alert emails cannot be sent.";
  el.innerHTML = `${PRESETS[provider].help}<br><br>${status}`;
}

function applyPreset(provider) {
  const p = PRESETS[provider];
  if (p.host || provider !== "custom") $("set-smtp-host").value = p.host;
  $("set-smtp-port").value = p.port;
  $("set-smtp-security").value = p.security;
  showHelp(provider, _saved);
}

let _saved = null;

function fill(s) {
  _saved = s;
  const provider = s.host ? guessProvider(s.host) : "gmail";
  $("set-smtp-provider").value = provider;
  if (s.host) {
    $("set-smtp-host").value = s.host;
    $("set-smtp-port").value = s.port || 587;
    $("set-smtp-security").value = s.ssl ? "ssl" : (s.starttls === false ? "none" : "starttls");
  } else {
    applyPreset(provider);
  }
  $("set-smtp-user").value = s.username || "";
  $("set-smtp-from").value = s.from_addr && s.from_addr !== "ueba@cybersentinel.local" ? s.from_addr : "";
  $("set-smtp-pass").value = "";
  $("set-smtp-pass").placeholder = s.has_password
    ? "Password saved (leave blank to keep it)" : "Password / app password";
  const badge = $("set-smtp-badge");
  if (badge) badge.textContent = s.configured ? "configured" : "not set";
  showHelp(provider, s);
}

export async function loadSmtp() {
  if (!$("set-smtp-host")) return;
  try {
    const r = await fetch("/api/settings/smtp", { credentials: "same-origin" });
    if (!r.ok) return;                       // not an admin, or reporting off
    const d = await r.json();
    if (d.ok) fill(d.smtp || {});
  } catch { /* leave the form as it is */ }
}

async function readJson(r) {
  try { return await r.json(); } catch { return {}; }
}

async function save() {
  const security = $("set-smtp-security").value;
  const body = {
    host: $("set-smtp-host").value.trim(),
    port: parseInt($("set-smtp-port").value, 10) || 587,
    ssl: security === "ssl",
    starttls: security === "starttls",
    username: $("set-smtp-user").value.trim(),
    password: $("set-smtp-pass").value,
    from_addr: $("set-smtp-from").value.trim(),
  };
  if (!body.host) { showToast("Enter the mail server", "error"); return false; }
  try {
    const r = await fetch("/api/settings/smtp", {
      method: "PUT", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = await readJson(r);
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    fill(d.smtp || {});
    showToast("Email settings saved", "success");
    return true;
  } catch (e) {
    showToast("Could not save email settings: " + e.message, "error", 8000);
    return false;
  }
}

async function sendTest() {
  const to = $("set-smtp-test-to").value.trim() || $("set-smtp-user").value.trim();
  if (!to) { showToast("Enter an address to send the test to", "error"); return; }
  // Save first if the form has unsaved edits, so the test uses what is on screen.
  if ($("set-smtp-pass").value || !_saved || $("set-smtp-host").value.trim() !== (_saved.host || "")) {
    if (!(await save())) return;
  }
  const btn = $("set-smtp-test");
  btn.disabled = true;
  showToast("Sending test email…", "info");
  try {
    const r = await fetch("/api/settings/smtp/test", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to }),
    });
    const d = await readJson(r);
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Test email sent to ${to}. Check the inbox (and spam).`, "success", 6000);
  } catch (e) {
    showToast("Test email failed: " + e.message, "error", 12000);
  } finally {
    btn.disabled = false;
  }
}

export function initSmtp() {
  if (!$("set-smtp-host")) return;
  $("set-smtp-provider").addEventListener("change", (e) => applyPreset(e.target.value));
  $("set-smtp-security").addEventListener("change", (e) => {
    const port = $("set-smtp-port");
    if (e.target.value === "ssl") port.value = 465;
    else if (e.target.value === "starttls") port.value = 587;
    else port.value = 25;
  });
  $("set-smtp-save").addEventListener("click", save);
  $("set-smtp-test").addEventListener("click", sendTest);
  showHelp("gmail", null);
}
