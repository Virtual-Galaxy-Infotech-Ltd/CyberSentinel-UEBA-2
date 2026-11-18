// User risk leaderboard (main tab + Overview top-N panel).

import { state } from "../state.js";
import { fmtDate, scoreColor } from "../helpers.js";

// ── User Risk search ──────────────────────────────────────────────────────────

let _urQuery = "";
let _urFocusIdx = -1;

function _urEsc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function _urHighlight(text, q) {
  if (!q) return _urEsc(text);
  const idx = text.toLowerCase().indexOf(q.toLowerCase());
  if (idx === -1) return _urEsc(text);
  return _urEsc(text.slice(0, idx))
    + '<mark class="psearch-hl">' + _urEsc(text.slice(idx, idx + q.length)) + '</mark>'
    + _urEsc(text.slice(idx + q.length));
}

function _applyUrFilter() {
  const q = _urQuery;
  document.querySelectorAll("#users-list .user-row").forEach((el) => {
    const name = (el.querySelector(".user-name")?.textContent || "").toLowerCase();
    el.style.display = (!q || name.includes(q)) ? "" : "none";
  });
}

function _buildUrSuggestions() {
  const q = _urQuery;
  const sugg = document.getElementById("ur-suggestions");
  if (!sugg) return;
  if (!q) { sugg.hidden = true; _urFocusIdx = -1; return; }
  const matches = state.usersData
    .filter((u) => u.user.toLowerCase().includes(q))
    .slice(0, 8);
  if (!matches.length) { sugg.hidden = true; _urFocusIdx = -1; return; }
  sugg.innerHTML = matches.map((u) => {
    const riColor = u.risk_index > 0.7 ? "var(--red)" : u.risk_index > 0.5 ? "var(--orange)" : "var(--yellow)";
    return `<div class="psearch-item" data-name="${_urEsc(u.user)}">
      <span class="psearch-item-name">${_urHighlight(u.user, q)}</span>
      <span class="psearch-item-meta" style="color:${riColor}">RI ${u.risk_index.toFixed(3)}</span>
      <span class="psearch-item-cnt" style="color:var(--text3)">${u.alert_count} alerts</span>
    </div>`;
  }).join("");
  sugg.hidden = false;
  _urFocusIdx = -1;
  sugg.querySelectorAll(".psearch-item").forEach((item) => {
    item.addEventListener("mousedown", (e) => { e.preventDefault(); _selectUr(item.dataset.name); });
  });
}

function _setUrFocus(idx) {
  const sugg = document.getElementById("ur-suggestions");
  if (!sugg || sugg.hidden) return;
  const items = sugg.querySelectorAll(".psearch-item");
  _urFocusIdx = Math.max(-1, Math.min(idx, items.length - 1));
  items.forEach((el, i) => el.classList.toggle("focused", i === _urFocusIdx));
  if (_urFocusIdx >= 0) items[_urFocusIdx].scrollIntoView({ block: "nearest" });
}

function _selectUr(name) {
  const input = document.getElementById("ur-search");
  const sugg  = document.getElementById("ur-suggestions");
  if (input) { input.value = name; _urQuery = name.toLowerCase(); }
  if (sugg)  sugg.hidden = true;
  _applyUrFilter();
  const row = Array.from(document.querySelectorAll("#users-list .user-row")).find(
    (el) => (el.querySelector(".user-name")?.textContent || "") === name
  );
  if (row) row.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

export function initUserSearch() {
  const input = document.getElementById("ur-search");
  const sugg  = document.getElementById("ur-suggestions");
  if (!input) return;
  input.addEventListener("input", () => {
    _urQuery = input.value.trim().toLowerCase();
    _applyUrFilter();
    _buildUrSuggestions();
  });
  input.addEventListener("keydown", (e) => {
    if (!sugg || sugg.hidden) return;
    if (e.key === "ArrowDown")  { e.preventDefault(); _setUrFocus(_urFocusIdx + 1); }
    else if (e.key === "ArrowUp")  { e.preventDefault(); _setUrFocus(_urFocusIdx - 1); }
    else if (e.key === "Enter") {
      const focused = sugg.querySelector(".psearch-item.focused");
      if (focused) { e.preventDefault(); _selectUr(focused.dataset.name); }
    }
    else if (e.key === "Escape") { sugg.hidden = true; _urFocusIdx = -1; }
  });
  input.addEventListener("focus", () => { if (_urQuery) _buildUrSuggestions(); });
  document.addEventListener("click", (e) => {
    if (!e.target.closest("#ur-search, #ur-suggestions")) {
      if (sugg) sugg.hidden = true;
    }
  });
}

export function renderUsers() {
  document.getElementById("users-badge").textContent = state.usersData.length;
  if (!state.usersData.length) {
    document.getElementById("users-list").innerHTML =
      '<div class="empty-state"><p>NO USER DATA</p></div>';
    _applyUrFilter();
    return;
  }
  document.getElementById("users-list").innerHTML = state.usersData.map((u, i) => {
    const rankCls = i === 0 ? "top1" : i < 3 ? "top3" : i < 5 ? "top5" : "";
    const riColor = u.risk_index > 0.7 ? "var(--red)" : u.risk_index > 0.5 ? "var(--orange)" : "var(--yellow)";
    const safeName = u.user.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
    const activeCls = state.selectedUser && state.selectedUser === u.user ? " active" : "";
    return `<div class="user-row clickable${activeCls}" onclick="loadUserDetail('${safeName}')">
      <div class="rank-num ${rankCls}">${i + 1}</div>
      <div class="user-name">${u.user}</div>
      <div class="risk-index-cell"><span class="risk-index-val" style="color:${riColor}">${u.risk_index.toFixed(3)}</span></div>
      <div class="count-val">${u.alert_count}</div>
      <div class="max-score-val" style="color:${scoreColor(u.max_score)}">${u.max_score.toFixed(3)}</div>
      <div class="top-reason-val">${(u.top_reason || "—").replace(/_/g, " ")}</div>
      <div class="last-seen-val">${fmtDate(u.last_seen)}</div>
    </div>`;
  }).join("");
  _applyUrFilter();
}

export function renderOverviewUsers() {
  document.getElementById("overview-users").innerHTML =
    state.usersData.slice(0, 8).map((u, i) => {
      const riColor = u.risk_index > 0.7 ? "var(--red)" : u.risk_index > 0.5 ? "var(--orange)" : "var(--yellow)";
      const rankCls = i === 0 ? "top1" : i < 3 ? "top3" : "";
      const hostLabel =
        u.hosts && u.hosts.length ? ` <span style="color:var(--text3)">[${u.hosts[0]}]</span>` : "";
      return `<div class="user-row-compact">
        <div class="urc-rank ${rankCls}">${i + 1}</div>
        <div class="urc-name">${u.user}${hostLabel}</div>
        <div class="urc-score" style="color:${riColor}">${u.risk_index.toFixed(3)}</div>
        <div class="urc-count">${u.alert_count} alerts</div>
      </div>`;
    }).join("") || '<div class="empty-state"><p>NO DATA</p></div>';
}
