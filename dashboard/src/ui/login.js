// Login gate.
//
// Shown only when the server is BOTH enforcing auth and reports nobody signed
// in. While auth.enforce is off this never renders, so the dashboard behaves
// exactly as it always has.
//
// It is an overlay inside the SPA rather than a separate page because the shell
// already loads unauthenticated — the request gate only guards /api/ — so there
// is one bundle, one origin, and no redirect dance. The overlay covers the app
// so no stale data is readable behind it.

import { showToast } from "./toast.js";

function overlay() {
  let el = document.getElementById("login-overlay");
  if (el) return el;
  el = document.createElement("div");
  el.id = "login-overlay";
  el.innerHTML = `
    <div class="login-card">
      <div class="login-brand">CyberSentinel <b>UEBA</b></div>
      <div class="login-sub">Sign in to continue</div>
      <form id="login-form" autocomplete="on">
        <input id="login-user" class="wl-input" type="text" placeholder="Username"
               autocomplete="username" autofocus />
        <input id="login-pass" class="wl-input" type="password" placeholder="Password"
               autocomplete="current-password" />
        <button id="login-btn" type="submit" class="export-btn wl-add-btn">Sign in</button>
        <div id="login-error" class="login-error"></div>
      </form>
    </div>`;
  document.body.appendChild(el);

  const form = el.querySelector("#login-form");
  form.addEventListener("submit", (e) => { e.preventDefault(); submit(); });
  return el;
}

async function submit() {
  const u = document.getElementById("login-user");
  const p = document.getElementById("login-pass");
  const err = document.getElementById("login-error");
  const btn = document.getElementById("login-btn");
  const username = (u && u.value || "").trim();
  const password = (p && p.value) || "";
  if (!username || !password) {
    if (err) err.textContent = "Enter your username and password.";
    return;
  }
  if (btn) btn.disabled = true;
  if (err) err.textContent = "";
  try {
    const r = await fetch("/api/auth/login", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    // Reload rather than patching state in place: capabilities, role chip and
    // every panel's data all have to be re-fetched as the new user, and a reload
    // is the one path guaranteed to leave nothing behind from the signed-out view.
    location.reload();
  } catch (e) {
    // Show the server's wording verbatim — it distinguishes a bad password from
    // a locked or disabled account, which is what the user needs to know.
    if (err) err.textContent = e.message;
    if (p) p.value = "";
  } finally {
    if (btn) btn.disabled = false;
  }
}

/** Put the gate up if, and only if, the server says it is required. */
export async function initLogin() {
  try {
    const r = await fetch("/api/auth/me", { credentials: "same-origin" });
    if (!r.ok) return;
    const d = await r.json();
    if (d.enforce && !d.authenticated) {
      overlay().classList.add("show");
      document.body.classList.add("login-gated");
    }
  } catch (e) {
    // Never gate on a failed probe: a transient error must not lock the
    // dashboard behind a login the server may not even be asking for.
  }
}

export async function logout() {
  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  } catch (e) { /* fall through to the reload regardless */ }
  location.reload();
}
