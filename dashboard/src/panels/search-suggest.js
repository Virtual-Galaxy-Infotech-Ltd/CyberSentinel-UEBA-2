// Search auto-complete / auto-suggest (RFP 28).
//
// Suggestions come from the SERVER, built over every alert in the current
// timeline window rather than the rows the browser happens to have loaded. That
// matters: the feed is capped, so a client-side vocabulary would quietly stop
// suggesting entities that exist in the window but fell outside the cap.
//
// Suggestions are contextual in the sense the requirement asks for — they are
// the users, hosts, signatures, tactics, campaigns and reasons actually present
// in the window being viewed, ranked by how often they occur.

import { state } from "../state.js";
import { layoutRect } from "../ui/ui-scale.js";

const DEBOUNCE_MS = 130;
const MAX_ROWS = 40;

let box = null;          // dropdown element
let rows = [];           // flat list of {value, field} for keyboard nav
let active = -1;         // highlighted row
let open = false;
let lastQuery = null;
let seq = 0;             // guards against out-of-order responses
let onPick = () => {};

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// Highlight the matched portion so it is obvious why a suggestion appeared.
function mark(value, q) {
  if (!q) return esc(value);
  const i = value.toLowerCase().indexOf(q.toLowerCase());
  if (i < 0) return esc(value);
  return esc(value.slice(0, i)) + "<b>" + esc(value.slice(i, i + q.length)) +
         "</b>" + esc(value.slice(i + q.length));
}

function ensureBox(input) {
  if (box) return box;
  box = document.createElement("div");
  box.className = "sug-pop";
  box.id = "feed-suggest";
  box.setAttribute("role", "listbox");
  // Appended to <body> and positioned fixed, for the same reason the MITRE
  // popover is: no ancestor's overflow or stacking context can clip it.
  document.body.appendChild(box);
  box.addEventListener("mousedown", (e) => {
    // mousedown, not click — the input's blur would otherwise close the
    // dropdown before the click landed.
    const el = e.target.closest("[data-val]");
    if (!el) return;
    e.preventDefault();
    apply(input, el.getAttribute("data-val"));
  });
  return box;
}

function place(input) {
  // LAYOUT px — the dropdown is positioned with style.left/top/width.
  const r = layoutRect(input);
  box.style.left = `${r.left}px`;
  box.style.top = `${r.bottom + 4}px`;
  box.style.width = `${Math.max(r.width, 320)}px`;
}

function hide() {
  open = false;
  active = -1;
  rows = [];
  if (box) box.style.display = "none";
}

function apply(input, value) {
  input.value = value;
  state.feedSearch = value;
  hide();
  onPick();
  input.focus();
}

function render(input, groups, q) {
  ensureBox(input);
  rows = [];
  const parts = [];
  for (const g of groups || []) {
    if (!g.items || !g.items.length) continue;
    parts.push(`<div class="sug-group">${esc(g.label)}</div>`);
    for (const it of g.items) {
      if (rows.length >= MAX_ROWS) break;
      const idx = rows.length;
      rows.push({ value: it.value, field: g.field });
      parts.push(
        `<div class="sug-row" role="option" data-i="${idx}" data-val="${esc(it.value)}">` +
        `<span class="sug-val">${mark(it.value, q)}</span>` +
        `<span class="sug-count">${Number(it.count || 0).toLocaleString()}</span></div>`);
    }
  }
  if (!parts.length) { hide(); return; }
  box.innerHTML = parts.join("");
  place(input);
  box.style.display = "block";
  open = true;
  active = -1;
}

function highlight() {
  if (!box) return;
  box.querySelectorAll(".sug-row").forEach((el) => {
    const on = Number(el.getAttribute("data-i")) === active;
    el.classList.toggle("active", on);
    if (on) el.scrollIntoView({ block: "nearest" });
  });
}

async function fetchSuggestions(input) {
  const q = input.value.trim();
  if (q === lastQuery && open) return;
  lastQuery = q;
  const mine = ++seq;
  try {
    const hours = state.timelineHours ?? state.windowHours ?? 24;
    const r = await fetch(
      `/api/suggest?q=${encodeURIComponent(q)}&hours=${encodeURIComponent(hours)}`);
    const d = await r.json();
    // A slower earlier request must not overwrite a newer one's results.
    if (mine !== seq) return;
    if (!r.ok || d.ok === false) { hide(); return; }
    render(input, d.groups, q);
  } catch {
    hide();   // suggestions are a convenience; never surface a failure
  }
}

export function initSearchSuggest(rerender) {
  const input = document.getElementById("feed-search-input");
  if (!input) return;
  onPick = typeof rerender === "function" ? rerender : () => {};

  let timer;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => fetchSuggestions(input), DEBOUNCE_MS);
  });
  input.addEventListener("focus", () => fetchSuggestions(input));
  input.addEventListener("blur", () => setTimeout(hide, 120));

  input.addEventListener("keydown", (e) => {
    if (!open || !rows.length) {
      if (e.key === "ArrowDown") fetchSuggestions(input);
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      active = (active + 1) % rows.length;
      highlight();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      active = (active - 1 + rows.length) % rows.length;
      highlight();
    } else if (e.key === "Enter") {
      if (active >= 0) { e.preventDefault(); apply(input, rows[active].value); }
      else hide();
    } else if (e.key === "Escape") {
      hide();
    }
  });

  window.addEventListener("resize", () => { if (open) place(input); });
  window.addEventListener("scroll", () => { if (open) place(input); }, true);
}
