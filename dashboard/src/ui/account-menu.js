// Account menu in the header: who is signed in, Settings, and Sign out.
//
// It occupies the slot that used to hold the "Updated HH:MM" readout. The
// engine-live pill immediately to its left already tells an analyst whether
// data is flowing, so the timestamp was the weaker of the two claims on a
// fixed amount of header space.
//
// Settings moved here out of the sidebar. The page and its /settings URL are
// unchanged — only the way in is different — so a bookmark still works and
// nothing about the settings panel itself had to move.

import { navigate } from "../router.js";
import { logout } from "./login.js";

const ID = {
  wrap:   "account-menu",
  btn:    "account-btn",
  drop:   "account-dropdown",
  avatar: "account-avatar",
  name:   "account-who-name",
  role:   "account-who-role",
  gear:   "account-settings",
  out:    "account-logout",
};

function initial(nameOrNull) {
  const n = (nameOrNull || "").trim();
  if (!n) return "?";
  // First letter of the account part, so "VGSOCSRV\rohan" reads as "R" rather
  // than "V" — the domain is the same for everyone and tells the viewer nothing.
  const account = n.split(/[\\/]/).pop() || n;
  return (account[0] || "?").toUpperCase();
}

/** Fill in who is signed in. Safe to call repeatedly. */
export async function refreshAccount() {
  const avatar = document.getElementById(ID.avatar);
  const name   = document.getElementById(ID.name);
  const role   = document.getElementById(ID.role);
  if (!avatar) return;

  let me = null, enforcing = false;
  try {
    const r = await fetch("/api/auth/me", { credentials: "same-origin" });
    const d = await r.json();
    enforcing = !!d.enforce;
    me = d.authenticated ? d.user : null;
  } catch (e) {
    // A failed probe must not blank the menu — Settings and Sign out stay
    // usable, which is the whole point of the control.
    return;
  }

  if (me) {
    const label = me.display_name || me.username || me.sub || "Signed in";
    avatar.textContent = initial(me.username || label);
    if (name) name.textContent = label;
    if (role) role.textContent = me.role || "";
  } else {
    avatar.textContent = enforcing ? "?" : "·";
    if (name) name.textContent = enforcing ? "Not signed in" : "Sign-in not enforced";
    if (role) role.textContent = "";
  }
}

export function initAccountMenu() {
  const wrap = document.getElementById(ID.wrap);
  const btn  = document.getElementById(ID.btn);
  const drop = document.getElementById(ID.drop);
  if (!wrap || !btn || !drop) return;

  const setOpen = (open) => {
    drop.hidden = !open;
    wrap.classList.toggle("open", open);
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  };
  const close = () => setOpen(false);

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    const willOpen = drop.hidden;
    setOpen(willOpen);
    if (willOpen) {
      // Re-read on open rather than only at startup: an admin can change their
      // own role from the Settings page, and a stale label here would contradict
      // the page they just left.
      refreshAccount();
      const first = document.getElementById(ID.gear);
      if (first) first.focus();
    }
  });

  // Click anywhere else, or Escape, closes it.
  document.addEventListener("click", (e) => {
    if (!drop.hidden && !wrap.contains(e.target)) close();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !drop.hidden) {
      close();
      btn.focus();
    }
  });

  const gear = document.getElementById(ID.gear);
  if (gear) {
    gear.addEventListener("click", () => {
      close();
      navigate("settings");
    });
  }

  const out = document.getElementById(ID.out);
  if (out) {
    out.addEventListener("click", () => {
      close();
      logout();
    });
  }

  refreshAccount();
}
