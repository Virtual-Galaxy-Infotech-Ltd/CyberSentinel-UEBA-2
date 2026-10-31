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
//
// LAYOUT
// ──────
// Two columns: a brand panel on the left and the sign-in card on the right,
// per the approved design. Below 1050px the brand panel is dropped rather than
// stacked — on a narrow window it is the sign-in box that matters, and a
// marketing column above it only pushes the fields off the first screen.
//
// Every control here does something real. "Remember me" stores the username
// only, never the password, so the field is pre-filled next time; it does not
// pretend to extend the session, which is the server's to decide. "Forgot
// password?" says who can actually reset it, because this product has no
// self-service reset — an admin does it from Settings → User Management.

import { showToast } from "./toast.js";

const REMEMBER_KEY = "ueba.login.remember";

// Inline rather than linked: this is the one screen that has to render for a
// user with no session, so it should not depend on another asset arriving.
const ICON = {
  user: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
  lock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  eye: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>`,
  eyeOff: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M9.9 4.24A9.1 9.1 0 0 1 12 4c6.5 0 10 7 10 7a18 18 0 0 1-2.16 3.19M6.6 6.6A18 18 0 0 0 2 11s3.5 7 10 7a9 9 0 0 0 5.4-1.6"/>
          <path d="m2 2 20 20"/></svg>`,
  signin: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><path d="m10 17 5-5-5-5"/><path d="M15 12H3"/></svg>`,
  arrow: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>`,
  bars: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M3 3v18h18"/><rect x="7" y="11" width="3" height="7" rx="1"/><rect x="12.5" y="7" width="3" height="11" rx="1"/><rect x="18" y="4" width="3" height="14" rx="1"/></svg>`,
  shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>`,
  people: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M17 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9.5" cy="7" r="4"/>
          <path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  doc: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/>
          <path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h6"/></svg>`,
};

const FEATURES = [
  ["bars", "Behavior Analytics"],
  ["shield", "Anomaly Detection"],
  ["people", "Entity Risk Profiling"],
  ["doc", "Actionable Insights"],
];

function overlay() {
  let el = document.getElementById("login-overlay");
  if (el) return el;
  el = document.createElement("div");
  el.id = "login-overlay";
  el.innerHTML = `
    <div class="lg-bg" aria-hidden="true"></div>
    <div class="lg-wrap">

      <section class="lg-left">
        <div class="lg-logo">
          <img class="lg-mark" src="/cybersentinel-mark.png" alt="" aria-hidden="true"/>
          <div class="lg-word">
            <div class="lg-word-main"><span>Cyber</span>Sentinel</div>
            <div class="lg-word-ueba">UEBA</div>
            <div class="lg-word-sub">User and Entity Behavior Analytics</div>
          </div>
        </div>

        <div class="lg-rule"></div>

        <h1 class="lg-head">See the unseen.<br/><span>Stay ahead.</span></h1>
        <p class="lg-copy">Detect abnormal behavior, identify risky entities, and
          investigate threats before they impact your organization.</p>

        <ul class="lg-feats">
          ${FEATURES.map(([ico, label]) => `
            <li><span class="lg-feat-ico">${ICON[ico]}</span><span>${label}</span></li>`).join("")}
        </ul>
      </section>

      <section class="lg-card">
        <div class="lg-eyebrow"><i class="lg-dot"></i>Secure access · UEBA</div>
        <h2 class="lg-title">Sign in</h2>
        <p class="lg-sub">Access your CyberSentinel UEBA workspace.</p>

        <form id="login-form" autocomplete="on" novalidate>
          <label class="lg-label" for="login-user">Username</label>
          <div class="lg-field">
            <span class="lg-field-ico">${ICON.user}</span>
            <input id="login-user" type="text" placeholder="Enter your username"
                   autocomplete="username" spellcheck="false" autofocus/>
          </div>

          <label class="lg-label" for="login-pass">Password</label>
          <div class="lg-field">
            <span class="lg-field-ico">${ICON.lock}</span>
            <input id="login-pass" type="password" placeholder="Enter your password"
                   autocomplete="current-password"/>
            <button type="button" id="login-eye" class="lg-eye"
                    aria-label="Show password" title="Show password">${ICON.eye}</button>
          </div>

          <div class="lg-row">
            <label class="lg-check">
              <input type="checkbox" id="login-remember"/>
              <span class="lg-box" aria-hidden="true"></span>
              <span>Remember me</span>
            </label>
            <button type="button" id="login-forgot" class="lg-forgot">Forgot password?</button>
          </div>

          <button id="login-btn" type="submit" class="lg-submit">
            <span class="lg-submit-ico">${ICON.signin}</span>
            <span class="lg-submit-text">Sign in securely</span>
            <span class="lg-submit-arrow">${ICON.arrow}</span>
          </button>

          <div id="login-error" class="login-error" role="alert" aria-live="polite"></div>
        </form>

        <div class="lg-foot">Protected by <b><i>Cyber</i>Sentinel</b></div>
      </section>
    </div>`;
  document.body.appendChild(el);

  el.querySelector("#login-form")
    .addEventListener("submit", (e) => { e.preventDefault(); submit(); });

  // Reveal toggle. Swaps the icon and the accessible name together, so a screen
  // reader is not left announcing "Show password" over a visible one.
  const eye = el.querySelector("#login-eye");
  const pass = el.querySelector("#login-pass");
  eye.addEventListener("click", () => {
    const show = pass.type === "password";
    pass.type = show ? "text" : "password";
    eye.innerHTML = show ? ICON.eyeOff : ICON.eye;
    eye.setAttribute("aria-label", show ? "Hide password" : "Show password");
    eye.setAttribute("title", show ? "Hide password" : "Show password");
    pass.focus();
  });

  el.querySelector("#login-forgot").addEventListener("click", () => {
    showToast("There is no self-service reset here. Ask an administrator to set a "
              + "new password from Settings → User Management.", "info");
  });

  // Pre-fill a remembered username. Only the username is ever stored: a password
  // in localStorage would be readable by any script running on this origin.
  try {
    const saved = localStorage.getItem(REMEMBER_KEY);
    if (saved) {
      el.querySelector("#login-user").value = saved;
      el.querySelector("#login-remember").checked = true;
      setTimeout(() => el.querySelector("#login-pass").focus(), 0);
    }
  } catch (e) { /* storage blocked — just start with an empty form */ }

  return el;
}

async function submit() {
  const u = document.getElementById("login-user");
  const p = document.getElementById("login-pass");
  const err = document.getElementById("login-error");
  const btn = document.getElementById("login-btn");
  const remember = document.getElementById("login-remember");
  const username = (u && u.value || "").trim();
  const password = (p && p.value) || "";
  if (!username || !password) {
    if (err) err.textContent = "Enter your username and password.";
    const target = username ? p : u;
    if (target) target.focus();
    return;
  }
  if (btn) { btn.disabled = true; btn.classList.add("is-busy"); }
  if (err) err.textContent = "";
  try {
    const r = await fetch("/api/auth/login", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    try {
      if (remember && remember.checked) localStorage.setItem(REMEMBER_KEY, username);
      else localStorage.removeItem(REMEMBER_KEY);
    } catch (e) { /* storage blocked — the sign-in itself still succeeded */ }
    // Reload rather than patching state in place: capabilities, role chip and
    // every panel's data all have to be re-fetched as the new user, and a reload
    // is the one path guaranteed to leave nothing behind from the signed-out view.
    location.reload();
  } catch (e) {
    // Show the server's wording verbatim — it distinguishes a bad password from
    // a locked or disabled account, which is what the user needs to know.
    if (err) err.textContent = e.message;
    if (p) { p.value = ""; p.focus(); }
  } finally {
    if (btn) { btn.disabled = false; btn.classList.remove("is-busy"); }
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
