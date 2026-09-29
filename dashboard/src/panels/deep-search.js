// Deep search over raw + enriched data (RFP 26).
//
// The feed's own search only reaches the slim projection the dashboard caches.
// This asks the server to scan the FULL stored record — threat-intel verdicts,
// geolocation, process and command line, HTTP/DNS fields, the evidence block
// and the original raw event — none of which the browser ever holds.
//
// Results are routed through filteredFeed(), so they render in the normal alert
// table and export through the existing CSV/JSON/XML/Excel/PDF buttons without
// any of that needing to know deep search exists.

import { state } from "../state.js";
import { showToast } from "../ui/toast.js";

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function banner() {
  return document.getElementById("deep-banner");
}

function renderBanner() {
  const el = banner();
  if (!el) return;
  const m = state.deepMeta;
  if (!state.deepMode || !m) {
    el.style.display = "none";
    el.innerHTML = "";
    return;
  }
  // Truncation is stated outright. A search that quietly examined part of the
  // window and reported a count would be worse than one that admits its limit.
  const warn = m.truncated
    ? `<span class="deep-warn">partial — ${m.matched.toLocaleString()} matched, showing ` +
      `${m.returned.toLocaleString()}; narrow the terms or the window for the rest</span>`
    : `<span class="deep-ok">complete scan</span>`;
  el.innerHTML =
    `<span class="deep-tag">RAW SEARCH</span>` +
    `<span class="deep-q">${esc(m.query)}</span>` +
    `<span class="deep-stats">${m.matched.toLocaleString()} match${m.matched === 1 ? "" : "es"} · ` +
    `${fmtBytes(m.bytes_scanned)} scanned · ${m.elapsed_ms} ms</span>` +
    warn +
    `<button class="deep-exit" onclick="exitDeepSearch()">✕ back to feed</button>`;
  el.style.display = "flex";
}

export async function runDeepSearch() {
  const input = document.getElementById("feed-search-input");
  const q = (input && input.value || "").trim();
  if (q.length < 2) {
    showToast("Type at least two characters to search the raw data", "info");
    return;
  }
  const btn = document.getElementById("deep-search-btn");
  const restore = btn ? btn.textContent : null;
  if (btn) { btn.disabled = true; btn.textContent = "Scanning…"; }
  showToast(`Scanning raw and enriched records for "${q}"…`, "info");
  try {
    const hours = state.timelineHours ?? 24;
    const r = await fetch(
      `/api/search/deep?q=${encodeURIComponent(q)}&hours=${encodeURIComponent(hours)}`);
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);

    state.deepResults = d.results || [];
    state.deepMeta = d;
    state.deepMode = true;
    state.feedRenderLimit = 200;
    renderBanner();
    const { renderFeed } = await import("./feed.js");
    renderFeed();
    showToast(
      d.matched
        ? `${d.matched.toLocaleString()} record(s) matched in raw data`
        : "No matches in the raw or enriched data for that term",
      d.matched ? "success" : "info");
  } catch (e) {
    showToast("Raw search failed: " + e.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = restore; }
  }
}

export async function exitDeepSearch() {
  state.deepMode = false;
  state.deepResults = [];
  state.deepMeta = null;
  renderBanner();
  const { renderFeed } = await import("./feed.js");
  renderFeed();
}

export function initDeepSearch() {
  const btn = document.getElementById("deep-search-btn");
  if (btn) btn.addEventListener("click", runDeepSearch);
  const input = document.getElementById("feed-search-input");
  if (input) {
    // Shift+Enter searches the raw data; plain Enter keeps its existing meaning.
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.shiftKey) {
        e.preventDefault();
        runDeepSearch();
      }
    });
  }
}
