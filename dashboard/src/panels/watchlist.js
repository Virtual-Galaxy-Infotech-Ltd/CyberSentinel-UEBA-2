// Watch lists — users, hosts and IPs an analyst has flagged for elevated
// scrutiny (RFP point 1).
//
// The list lives server-side in watchlist.json and is read by the ENGINE, not
// just by this dashboard: a watched entity gets a small additive boost to its
// anomaly score, applied before the alert threshold. So adding a row here
// changes what the pipeline alerts on, within one event — there is no restart
// and no delay. That is worth keeping in mind when reading the wording below;
// the UI says "elevated scrutiny" rather than "filter" for exactly that reason.

import { showToast } from "../ui/toast.js";

let _entries = [];
let _meta = { default_boost: 0.1, max_boost: 0.5, types: ["user", "host", "ip"] };

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

export async function loadWatchlist() {
  try {
    const r = await fetch("/api/watchlist");
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    _entries = d.entries || [];
    _meta = {
      default_boost: d.default_boost ?? 0.1,
      max_boost:     d.max_boost ?? 0.5,
      types:         d.types || _meta.types,
    };
  } catch (e) {
    // A failed load must not blank the panel silently — say so in the table.
    _entries = null;
    console.warn("[ueba] watchlist load failed:", e);
  }
  renderWatchlist();
}

export function renderWatchlist() {
  const tbody = document.getElementById("wl-tbody");
  const badge = document.getElementById("wl-badge");
  const nav   = document.getElementById("wl-nav-badge");
  if (!tbody) return;

  if (_entries === null) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-row">Could not load the watch list.</td></tr>`;
    if (badge) badge.textContent = "—";
    return;
  }

  const n = _entries.length;
  if (badge) badge.textContent = String(n);
  if (nav)   nav.textContent   = String(n);

  if (!n) {
    tbody.innerHTML =
      `<tr><td colspan="7" class="empty-row">No entities are being watched. ` +
      `Add a user, host or IP above to raise the pipeline's sensitivity to it.</td></tr>`;
    return;
  }

  tbody.innerHTML = _entries.map((e) => `
    <tr>
      <td><span class="wl-type wl-type-${esc(e.type)}">${esc(e.type)}</span></td>
      <td class="wl-value">${esc(e.value)}</td>
      <td>${esc(e.reason) || "<span class='wl-dim'>—</span>"}</td>
      <td class="wl-boost">+${Number(e.boost || 0).toFixed(2)}</td>
      <td>${esc(e.added_by) || "<span class='wl-dim'>—</span>"}</td>
      <td class="wl-dim">${fmtWhen(e.added_at)}</td>
      <td><button class="fp-btn-inline" title="Stop watching ${esc(e.value)}"
            data-cap="watchlist.edit" onclick="removeWatchEntry('${esc(e.id)}','${esc(e.value)}')">Remove</button></td>
    </tr>`).join("");
}

export async function addWatchEntry() {
  const typeEl   = document.getElementById("wl-type");
  const valueEl  = document.getElementById("wl-value");
  const reasonEl = document.getElementById("wl-reason");
  const boostEl  = document.getElementById("wl-boost");
  const value    = (valueEl && valueEl.value || "").trim();

  if (!value) {
    showToast("Enter a user, host or IP to watch", "error");
    if (valueEl) valueEl.focus();
    return;
  }
  const body = {
    type:   (typeEl && typeEl.value) || "user",
    value,
    reason: (reasonEl && reasonEl.value || "").trim(),
  };
  const boost = parseFloat(boostEl && boostEl.value);
  if (!isNaN(boost)) body.boost = boost;

  try {
    const r = await fetch("/api/watchlist", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(
      d.created
        ? `Now watching ${body.type} "${value}" — its activity is scored more sensitively from the next event.`
        : `Updated the existing watch entry for "${value}".`,
      "success"
    );
    if (valueEl)  valueEl.value = "";
    if (reasonEl) reasonEl.value = "";
    if (boostEl)  boostEl.value = "";
    loadWatchlist();
  } catch (e) {
    showToast("Failed to add watch entry: " + e.message, "error");
  }
}

export async function removeWatchEntry(id, label) {
  if (!id) return;
  try {
    const r = await fetch("/api/watchlist/" + encodeURIComponent(id), { method: "DELETE" });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Stopped watching ${label || id}`, "success");
    loadWatchlist();
  } catch (e) {
    showToast("Failed to remove watch entry: " + e.message, "error");
  }
}

export function initWatchlist() {
  const btn = document.getElementById("wl-add-btn");
  if (btn) btn.addEventListener("click", addWatchEntry);
  const val = document.getElementById("wl-value");
  if (val) {
    val.addEventListener("keydown", (e) => { if (e.key === "Enter") addWatchEntry(); });
  }
  loadWatchlist();
}
