// Device registry and proactive alerting (RFP 10, 15).
//
// Two panels on one tab, because they are two halves of the same job: you label
// and prioritise devices so that notification rules can alert on that priority.
// A rule can also alert purely on score or verdict, so the device registry is
// useful but not a prerequisite.

import { showToast } from "../ui/toast.js";

let DEVICES = [];
let RULES = [];
let META = { priorities: ["low", "medium", "high", "critical"],
             verdicts: ["suspicious", "anomalous", "highly_anomalous"],
             email_enabled: false };

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

// ── Devices (RFP 10) ────────────────────────────────────────────────────────

export async function loadDevices() {
  try {
    const r = await fetch("/api/devices");
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    DEVICES = d.entries || [];
    if (d.priorities) META.priorities = d.priorities;
  } catch (e) {
    DEVICES = null;
    console.warn("[ueba] devices unavailable:", e);
  }
  renderDevices();
}

function renderDevices() {
  const tb = document.getElementById("dev-tbody");
  const badge = document.getElementById("dev-badge");
  if (!tb) return;
  if (DEVICES === null) {
    tb.innerHTML = `<tr><td colspan="7" class="empty-row">Device registry unavailable.</td></tr>`;
    return;
  }
  if (badge) badge.textContent = String(DEVICES.length);
  if (!DEVICES.length) {
    tb.innerHTML = `<tr><td colspan="7" class="empty-row">No devices registered. ` +
      `Label a device and give it a priority so alerting rules can target it.</td></tr>`;
    return;
  }
  tb.innerHTML = DEVICES.map((d) => `
    <tr>
      <td class="wl-value">${esc(d.name)}</td>
      <td>${esc(d.label) || "<span class='wl-dim'>—</span>"}</td>
      <td><span class="prio prio-${esc(d.priority)}">${esc(d.priority)}</span></td>
      <td class="wl-dim">${esc(d.owner) || "—"}</td>
      <td class="wl-dim">${esc(d.notes) || "—"}</td>
      <td class="wl-dim">${esc(d.updated_by) || "—"} · ${fmtWhen(d.updated_at)}</td>
      <td><button class="fp-btn-inline" onclick="deleteDevice('${esc(d.name)}')">Remove</button></td>
    </tr>`).join("");
}

export async function saveDevice() {
  const g = (id) => (document.getElementById(id)?.value || "").trim();
  const name = g("dev-name");
  if (!name) { showToast("Enter a device name", "error"); return; }
  try {
    const r = await fetch("/api/devices", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, label: g("dev-label"),
                             priority: document.getElementById("dev-priority")?.value,
                             owner: g("dev-owner"), notes: g("dev-notes") }),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(d.created ? `Registered ${name}` : `Updated ${name}`, "success");
    ["dev-name", "dev-label", "dev-owner", "dev-notes"].forEach((id) => {
      const el = document.getElementById(id); if (el) el.value = "";
    });
    loadDevices();
  } catch (e) {
    showToast("Could not save device: " + e.message, "error");
  }
}

export async function deleteDevice(name) {
  try {
    const r = await fetch("/api/devices/" + encodeURIComponent(name), { method: "DELETE" });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Removed ${name}`, "success");
    loadDevices();
  } catch (e) {
    showToast("Could not remove device: " + e.message, "error");
  }
}

// ── Notification rules (RFP 15) ─────────────────────────────────────────────

export async function loadRules() {
  try {
    const r = await fetch("/api/notify/rules");
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    RULES = d.entries || [];
    META.email_enabled = !!d.email_enabled;
    if (d.priorities) META.priorities = d.priorities;
    if (d.verdicts) META.verdicts = d.verdicts;
  } catch (e) {
    RULES = null;
    console.warn("[ueba] notification rules unavailable:", e);
  }
  renderRules();
}

function conditionSummary(r) {
  const bits = [];
  if (r.min_score != null) bits.push(`score ≥ ${Number(r.min_score).toFixed(2)}`);
  if (r.verdicts?.length) bits.push(r.verdicts.map((v) => v.replace(/_/g, " ")).join(" / "));
  if (r.priorities?.length) bits.push(`priority ${r.priorities.join(" / ")}`);
  if (r.labels?.length) bits.push(`label ${r.labels.join(" / ")}`);
  if (r.tactics?.length) bits.push(`MITRE ${r.tactics.join(" / ")}`);
  if (r.watchlisted_only) bits.push("watch-listed only");
  return bits.length ? bits.join(" · ") : "any alert";
}

function renderRules() {
  const tb = document.getElementById("ntf-tbody");
  const badge = document.getElementById("ntf-badge");
  const note = document.getElementById("ntf-note");
  if (!tb) return;
  if (note) {
    note.textContent = META.email_enabled
      ? "Email delivery is configured."
      : "SMTP is not configured, so email rules are stored but cannot deliver. "
        + "Webhook rules work regardless.";
  }
  if (RULES === null) {
    tb.innerHTML = `<tr><td colspan="7" class="empty-row">Alerting unavailable.</td></tr>`;
    return;
  }
  if (badge) badge.textContent = String(RULES.length);
  const nav = document.getElementById("ntf-nav-badge");
  if (nav) nav.textContent = String(RULES.filter((r) => r.enabled).length);
  if (!RULES.length) {
    tb.innerHTML = `<tr><td colspan="7" class="empty-row">No notification rules. ` +
      `Create one to be told about anomalous behaviour as it happens.</td></tr>`;
    return;
  }
  tb.innerHTML = RULES.map((r) => {
    const ch = [];
    if (r.emails?.length) ch.push(`${r.emails.length} email`);
    if (r.webhook) ch.push("webhook");
    return `
    <tr>
      <td>${esc(r.name)}</td>
      <td class="wl-dim">${esc(conditionSummary(r))}</td>
      <td class="wl-dim">${esc(ch.join(" + ")) || "—"}</td>
      <td class="wl-dim">${esc(r.throttle_minutes)}m · ${esc(r.max_per_hour)}/h</td>
      <td class="wl-dim">${esc(r.fired_count || 0)} sent${r.suppressed_count ? ` · ${esc(r.suppressed_count)} held` : ""}</td>
      <td>${r.enabled ? '<span class="prio prio-high">on</span>' : '<span class="wl-dim">off</span>'}
          <span class="wl-dim"> ${r.last_fired ? fmtWhen(r.last_fired) : ""}</span></td>
      <td style="white-space:nowrap">
        <button class="fp-btn-inline" onclick="testRule('${esc(r.id)}','${esc(r.name)}')">Test</button>
        <button class="fp-btn-inline" onclick="deleteRule('${esc(r.id)}','${esc(r.name)}')">Delete</button>
      </td>
    </tr>`;
  }).join("");
}

export async function saveRule() {
  const g = (id) => (document.getElementById(id)?.value || "").trim();
  const name = g("ntf-name");
  if (!name) { showToast("Give the rule a name", "error"); return; }
  const score = g("ntf-score");
  const body = {
    name,
    min_score: score === "" ? null : Number(score),
    verdicts: [...document.querySelectorAll("#ntf-verdicts input:checked")].map((i) => i.value),
    priorities: [...document.querySelectorAll("#ntf-priorities input:checked")].map((i) => i.value),
    watchlisted_only: !!document.getElementById("ntf-watchonly")?.checked,
    emails: g("ntf-emails").split(/[,;\s]+/).filter(Boolean),
    webhook: g("ntf-webhook"),
    throttle_minutes: Number(g("ntf-throttle") || 15),
    max_per_hour: Number(g("ntf-cap") || 20),
  };
  try {
    const r = await fetch("/api/notify/rules", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(d.warning || `Rule "${name}" saved`, d.warning ? "info" : "success");
    ["ntf-name", "ntf-emails", "ntf-webhook"].forEach((id) => {
      const el = document.getElementById(id); if (el) el.value = "";
    });
    document.querySelectorAll("#ntf-verdicts input:checked, #ntf-priorities input:checked")
      .forEach((i) => { i.checked = false; });
    loadRules();
  } catch (e) {
    showToast("Could not save rule: " + e.message, "error");
  }
}

export async function testRule(id, name) {
  showToast(`Testing "${name}"…`, "info");
  try {
    const r = await fetch(`/api/notify/rules/${encodeURIComponent(id)}/test`, { method: "POST" });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Test sent: ${(d.sent || []).join(", ") || "nothing"}`
      + (d.errors?.length ? ` — errors: ${d.errors.join("; ")}` : ""),
      d.errors?.length ? "info" : "success");
    loadRules();
  } catch (e) {
    showToast("Test failed: " + e.message, "error");
  }
}

export async function deleteRule(id, name) {
  try {
    const r = await fetch("/api/notify/rules/" + encodeURIComponent(id), { method: "DELETE" });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Removed "${name}"`, "success");
    loadRules();
  } catch (e) {
    showToast("Could not delete rule: " + e.message, "error");
  }
}

export function initAlerting() {
  const on = (id, ev, fn) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(ev, fn);
  };
  on("dev-save-btn", "click", saveDevice);
  on("ntf-save-btn", "click", saveRule);
  // Same reasoning as the reports panel: nothing here may reject into main.js.
  Promise.all([loadDevices(), loadRules()])
    .catch((e) => console.warn("[ueba] alerting init failed:", e));
}
