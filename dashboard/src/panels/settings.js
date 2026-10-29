// Settings — account self-service for everyone, user management for admins
// (RFP 23, and the identity half of running UEBA without CyberSentinel SIEM).
//
// Two panels with deliberately different audiences:
//
//   My Account      — every signed-in user. Local accounts need somewhere to
//                     rotate their own password; SSO accounts are told plainly
//                     that theirs lives in the SIEM rather than being shown a
//                     form that cannot work.
//   User Management — admins only, and gated twice: this panel carries
//                     data-cap="users.manage" so it is hidden without the
//                     capability, and every endpoint behind it is
//                     @require_role("admin") on the server. The UI gate is
//                     cosmetic; the server one is the actual control.

import { showToast } from "../ui/toast.js";
import { state } from "../state.js";

let _users = [];
let _roles = ["viewer", "analyst", "admin"];
let _me = null;

// Mirrors password_problem() in ueba_auth.py. Checked client-side purely so a
// too-short password fails instantly in the form rather than after a round
// trip — the server remains the authority and rejects it regardless.
const MIN_PASSWORD = 12;

function passwordProblem(pw) {
  if (!pw) return "Enter a password.";
  if (pw.length < MIN_PASSWORD) {
    return `Password must be at least ${MIN_PASSWORD} characters (that one is ${pw.length}).`;
  }
  return null;
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function fmtWhen(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return "—";
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

// ── My Account ───────────────────────────────────────────────────────────────
async function loadMe() {
  try {
    const r = await fetch("/api/auth/me", { credentials: "same-origin" });
    const d = await r.json();
    _me = d.authenticated ? d.user : null;
    state.rbacEnforcing = !!d.enforce;
  } catch (e) {
    _me = null;
  }
  renderMe();
}

function renderMe() {
  const box = document.getElementById("set-me");
  if (!box) return;

  if (!state.rbacEnforcing) {
    box.innerHTML = `
      <div class="set-note">
        Authentication is <b>not being enforced</b>, so every visitor currently has
        full access and there is no account to manage. Roles, the gates on each
        panel and everything below are live and ready — they begin applying the
        moment <code>auth.enforce</code> is turned on in <code>ueba_config.yaml</code>.
        <br><br>
        Create the first administrator before enabling it, or nobody will be able
        to sign in:
        <code>python3 ueba_auth.py create-admin --username &lt;name&gt;</code>,
        then <code>python3 ueba_auth.py check</code> to confirm.
      </div>`;
    return;
  }
  if (!_me) {
    box.innerHTML = `<div class="set-note">Not signed in.</div>`;
    return;
  }

  const isLocal = String(_me.sub || "").startsWith("local:");
  box.innerHTML = `
    <div class="set-kv"><span>Signed in as</span><b>${esc(_me.username || "—")}</b></div>
    <div class="set-kv"><span>Role</span><b>${esc(_me.role || "—")}</b></div>
    <div class="set-kv"><span>Account type</span><b>${isLocal ? "Local" : "SSO (CyberSentinel SIEM)"}</b></div>
    ${isLocal ? `
      <div class="set-sub">Change password</div>
      <div class="wl-form">
        <input id="set-pw-cur" class="wl-input" type="password" placeholder="Current password" autocomplete="current-password" style="flex:1 1 180px">
        <input id="set-pw-new" class="wl-input" type="password" placeholder="New password (min 12 characters)" autocomplete="new-password" style="flex:1 1 220px">
        <button id="set-pw-btn" class="export-btn wl-add-btn">Update password</button>
      </div>
      <div class="set-note">Changing it signs out your other sessions.</div>
    ` : `
      <div class="set-note">
        This account signs in through CyberSentinel SIEM, so its password is
        managed there rather than here.
      </div>
    `}`;

  const btn = document.getElementById("set-pw-btn");
  if (btn) btn.addEventListener("click", changeMyPassword);
}

async function changeMyPassword() {
  const cur = document.getElementById("set-pw-cur");
  const nw  = document.getElementById("set-pw-new");
  const current_password = (cur && cur.value) || "";
  const new_password = (nw && nw.value) || "";
  const pwProblem = new_password ? passwordProblem(new_password) : "Enter your new password.";
  if (!current_password || pwProblem) {
    showToast(!current_password ? "Enter your current password." : pwProblem, "error");
    return;
  }
  try {
    const r = await fetch("/api/auth/password", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password, new_password }),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    if (cur) cur.value = ""; if (nw) nw.value = "";
    showToast("Password updated. Your other sessions have been signed out.", "success");
  } catch (e) {
    showToast("Could not change password: " + e.message, "error");
  }
}

// ── User management (admin) ──────────────────────────────────────────────────
export async function loadUsers() {
  try {
    const r = await fetch("/api/auth/users", { credentials: "same-origin" });
    if (r.status === 401 || r.status === 403) { _users = []; renderUsers(); return; }
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    _users = d.users || [];
    _roles = d.roles || _roles;
  } catch (e) {
    _users = null;
    console.warn("[ueba] user list failed:", e);
  }
  renderUsers();
}

function renderUsers() {
  const tb = document.getElementById("set-users-tbody");
  const badge = document.getElementById("set-users-badge");
  if (!tb) return;
  if (badge) badge.textContent = _users ? _users.length : 0;

  if (_users === null) {
    tb.innerHTML = `<tr><td colspan="7" class="wl-empty">Could not load accounts.</td></tr>`;
    return;
  }
  if (!_users.length) {
    tb.innerHTML = `<tr><td colspan="7" class="wl-empty">No accounts yet — use the form above to
      create one. The first account should be an <b>Admin</b>, or nobody will be able to manage
      the rest.</td></tr>`;
    return;
  }

  tb.innerHTML = _users.map((u) => {
    const opts = _roles.map((r) =>
      `<option value="${esc(r)}" ${u.role === r ? "selected" : ""}>${esc(r)}</option>`).join("");
    return `
      <tr>
        <td><b>${esc(u.username || u.sub)}</b>${u.locked ? ' <span class="wl-badge">LOCKED</span>' : ""}</td>
        <td>${u.is_local ? "local" : "sso"}</td>
        <td><select class="wl-input set-role" data-sub="${esc(u.sub)}">${opts}</select></td>
        <td>${u.active ? "yes" : "no"}</td>
        <td>${u.has_password ? "yes" : "—"}</td>
        <td>${esc(fmtWhen(u.last_login))}</td>
        <td>
          <button class="fp-btn-inline" data-act="toggle" data-sub="${esc(u.sub)}" data-active="${u.active ? 1 : 0}">${u.active ? "Disable" : "Enable"}</button>
          ${u.locked ? `<button class="fp-btn-inline" data-act="unlock" data-sub="${esc(u.sub)}">Unlock</button>` : ""}
          ${u.is_local ? `<button class="fp-btn-inline" data-act="reset" data-sub="${esc(u.sub)}" data-name="${esc(u.username)}">Reset password</button>` : ""}
          <button class="fp-btn-inline" data-act="delete" data-sub="${esc(u.sub)}" data-name="${esc(u.username)}">Delete</button>
        </td>
      </tr>`;
  }).join("");

  tb.querySelectorAll("select.set-role").forEach((sel) => {
    sel.addEventListener("change", () => patchUser(sel.dataset.sub, { role: sel.value },
      `Role changed to ${sel.value}.`));
  });
  tb.querySelectorAll("button[data-act]").forEach((b) => {
    b.addEventListener("click", () => {
      const sub = b.dataset.sub;
      const act = b.dataset.act;
      if (act === "toggle") {
        const makeActive = b.dataset.active !== "1";
        patchUser(sub, { active: makeActive },
          makeActive ? "Account enabled." : "Account disabled and its sessions signed out.");
      } else if (act === "unlock") {
        patchUser(sub, { unlock: true }, "Lockout cleared.");
      } else if (act === "reset") {
        const pw = window.prompt(
          `Set a new password for ${b.dataset.name}.\n\n` +
          `Minimum ${MIN_PASSWORD} characters. Their existing sessions will be signed out.`, "");
        if (pw !== null) {
          const bad = passwordProblem(pw);
          if (bad) showToast(bad, "error");
          else patchUser(sub, { password: pw },
                         "Password reset; their sessions were signed out.");
        }
      } else if (act === "delete") {
        if (window.confirm(`Delete the account "${b.dataset.name}"?\n\nThis cannot be undone.`)) {
          deleteUser(sub, b.dataset.name);
        }
      }
    });
  });
}

async function patchUser(sub, body, okMsg) {
  try {
    const r = await fetch("/api/auth/users/" + encodeURIComponent(sub), {
      method: "PATCH", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(okMsg || "Updated.", "success");
    loadUsers();
  } catch (e) {
    // The server refuses to strip the last admin; surface that verbatim rather
    // than as a generic failure, because it is a deliberate guard, not a bug.
    showToast(e.message, "error");
    loadUsers();
  }
}

async function deleteUser(sub, name) {
  try {
    const r = await fetch("/api/auth/users/" + encodeURIComponent(sub), {
      method: "DELETE", credentials: "same-origin" });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Deleted ${name || sub}.`, "success");
    loadUsers();
  } catch (e) {
    showToast(e.message, "error");
    loadUsers();
  }
}

async function createUser() {
  const u = document.getElementById("set-new-user");
  const p = document.getElementById("set-new-pass");
  const r = document.getElementById("set-new-role");
  const username = (u && u.value || "").trim();
  const password = (p && p.value) || "";
  const role = (r && r.value) || "viewer";
  if (!username) {
    showToast("Enter a username.", "error");
    return;
  }
  const problem = passwordProblem(password);
  if (problem) {
    showToast(problem, "error");
    return;
  }
  try {
    const res = await fetch("/api/auth/users", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, role }),
    });
    const d = await res.json();
    if (!res.ok || d.ok === false) throw new Error(d.error || `HTTP ${res.status}`);
    if (u) u.value = ""; if (p) p.value = "";
    showToast(`Created ${username} as ${role}.`, "success");
    loadUsers();
  } catch (e) {
    showToast("Could not create account: " + e.message, "error");
  }
}

export function initSettings() {
  const btn = document.getElementById("set-new-btn");
  if (btn) btn.addEventListener("click", createUser);

  // Re-read on every visit. Accounts are changed by other admins and by the
  // CLI, so a list cached since page load is routinely wrong. The trigger is
  // the account-menu item, since Settings no longer has a sidebar tab.
  const entry = document.getElementById("account-settings");
  if (entry) entry.addEventListener("click", refreshSettings);

  refreshSettings();
}

export function refreshSettings() {
  loadMe();
  loadUsers();
}
