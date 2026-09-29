// Role-based UI gating (RFP 23).
//
// The server is the real gate — every mutating route is wrapped in
// _require_cap() and returns 403 regardless of what the browser renders. This
// module only stops the UI *offering* actions that would come back 403, which
// is a usability concern, not a security one. Treat it accordingly: never move
// a check here and drop it server-side.
//
// Gating is applied as classes on <body> rather than by walking the DOM, because
// most of this dashboard renders HTML strings on every refresh. A class plus a
// CSS rule covers rows that do not exist yet; a DOM pass would have to be
// re-run after every render and would silently rot the first time someone added
// a panel and forgot to call it.
//
// While auth.enforce is off the server reports every capability as true, so
// nothing is hidden and the UI is exactly as it was.

import { state } from "../state.js";

const CAPS = {};

/** Has the capability, or we simply do not know yet — the server still decides. */
export function can(cap) {
  return CAPS[cap] !== false;
}

function bodyClass(cap) {
  return "nocap-" + cap.replace(/\./g, "-");
}

export async function initCapabilities() {
  try {
    const r = await fetch("/api/auth/capabilities", { credentials: "same-origin" });
    if (!r.ok) return;                       // leave the UI permissive
    const d = await r.json();
    Object.assign(CAPS, d.capabilities || {});
    state.role = d.role || null;
    state.rbacEnforcing = !!d.enforcing;

    const b = document.body;
    Object.keys(CAPS).forEach((cap) => {
      b.classList.toggle(bodyClass(cap), CAPS[cap] === false);
    });
    b.setAttribute("data-role", state.role || "");

    const chip = document.getElementById("role-chip");
    if (chip) chip.textContent = state.role || "";
  } catch (e) {
    // Unreachable endpoint must not blank the dashboard — stay permissive and
    // let the server reject anything the user is not entitled to.
  }
}
