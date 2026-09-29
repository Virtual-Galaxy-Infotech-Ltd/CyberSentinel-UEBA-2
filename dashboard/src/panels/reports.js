// Reports — generate, customise and schedule (RFP 34-40, 62).
//
// Four things live on this tab:
//   1. Generate now      — pick a report, a period and a format; get the file.
//   2. Custom reports    — compose your own from the same section catalogue
//                          the built-in reports are made of (point 38).
//   3. Schedules         — run a report periodically and email it (points 39/40).
//   4. Recent reports    — what has been generated, re-downloadable.
//
// The catalogue is fetched once and drives every dropdown, so the UI can never
// offer a report or a format the server cannot actually produce — an install
// without reportlab simply has no PDF option rather than a button that 500s.

import { showToast } from "../ui/toast.js";

let CAT = null;           // server catalogue
let CUSTOM = [];
let SCHEDULES = [];

const PERIODS = [
  { h: 24,   label: "Last 24 hours" },
  { h: 72,   label: "Last 3 days" },
  { h: 168,  label: "Last 7 days" },
  { h: 720,  label: "Last 30 days" },
  { h: 2160, label: "Last 90 days" },
  { h: 0,    label: "All retained data" },
];

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

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function allReports() {
  const builtin = (CAT?.reports || []).map((r) => ({ ...r, builtin: true }));
  const custom = CUSTOM.map((c) => ({
    id: c.id, title: c.name, audience: "Custom",
    purpose: c.description || `${(c.sections || []).length} sections`,
    builtin: false,
  }));
  return [...builtin, ...custom];
}

// ── Load ────────────────────────────────────────────────────────────────────

export async function loadReports() {
  try {
    const r = await fetch("/api/reports/catalogue");
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    CAT = d;
    CUSTOM = d.custom || [];
  } catch (e) {
    CAT = null;
    console.warn("[ueba] report catalogue unavailable:", e);
  }
  const safely = (label, fn) => {
    try { fn(); } catch (err) { console.warn("[ueba] reports render failed:", label, err); }
  };
  safely("generate", renderGenerate);
  safely("sections", renderSectionPicker);
  await Promise.all([
    loadSchedules().catch((e) => console.warn("[ueba] schedules:", e)),
    loadHistory().catch((e) => console.warn("[ueba] report history:", e)),
  ]);
}

async function loadSchedules() {
  try {
    const r = await fetch("/api/reports/schedules");
    const d = await r.json();
    SCHEDULES = (d && d.entries) || [];
  } catch { SCHEDULES = []; }
  renderSchedules();
}

async function loadHistory() {
  let entries = [];
  try {
    const r = await fetch("/api/reports/history?limit=40");
    const d = await r.json();
    entries = (d && d.entries) || [];
  } catch { /* leave empty */ }
  const tb = document.getElementById("rp-hist-tbody");
  if (!tb) return;
  if (!entries.length) {
    tb.innerHTML = `<tr><td colspan="6" class="empty-row">No reports have been generated yet.</td></tr>`;
    return;
  }
  tb.innerHTML = entries.map((e) => `
    <tr>
      <td class="wl-dim">${fmtWhen(e.generated_at)}</td>
      <td>${esc(e.title || e.report_id)}</td>
      <td><span class="wl-type">${esc(e.format)}</span></td>
      <td class="wl-dim">${esc(e.generated_by || "—")}</td>
      <td class="wl-dim">${fmtBytes(e.bytes)}${e.delivery ? ` · ${esc(e.delivery)}` : ""}</td>
      <td style="white-space:nowrap">
        <a class="fp-btn-inline" href="/api/reports/download/${encodeURIComponent(e.id)}"
           title="Download as generated (${esc(e.format)})">Download</a>
        ${altFormatButtons(e)}
        <button class="fp-btn-inline" data-cap="reports.generate" onclick="deleteReport('${esc(e.id)}','${esc(e.title || e.report_id)}')">Delete</button>
      </td>
    </tr>`).join("");
}

// Offer the rendered formats this row is NOT already in. Conversion re-renders
// the report's stored source document, so it is the same period and the same
// numbers — not a fresh run of the report over today's window.
function altFormatButtons(e) {
  const avail = new Set(CAT?.formats || []);
  const out = [];
  for (const [fmt, label] of [["pdf", "PDF"], ["xlsx", "Excel"]]) {
    if (e.format === fmt || !avail.has(fmt)) continue;
    // Anything falsy, not just an explicit false: rows written before source
    // documents were kept have no has_document field at all, and a strict
    // `=== false` check left those showing an enabled button that 409s.
    if (!e.has_document) {
      out.push(`<button class="fp-btn-inline" disabled
        title="Generated before source documents were kept, so it cannot be converted. Generate this report again and the new one will convert.">${label}</button>`);
    } else {
      // Fetched rather than linked: a conversion can fail (missing sidecar,
      // renderer error) and a plain href would navigate the analyst to a page
      // of raw JSON instead of telling them what went wrong.
      out.push(`<button class="fp-btn-inline"
        onclick="downloadReportAs('${esc(e.id)}','${fmt}','${label}')"
        title="Download this same report as ${label}">${label}</button>`);
    }
  }
  return out.join(" ");
}

export async function downloadReportAs(id, fmt, label) {
  showToast(`Converting to ${label}…`, "info");
  try {
    const r = await fetch(
      `/api/reports/download/${encodeURIComponent(id)}?format=${encodeURIComponent(fmt)}`);
    if (!r.ok) {
      let msg = `HTTP ${r.status}`;
      try { msg = (await r.json()).error || msg; } catch { /* not json */ }
      throw new Error(msg);
    }
    const blob = await r.blob();
    const m = /filename="?([^"]+)"?/.exec(r.headers.get("Content-Disposition") || "");
    const a = document.createElement("a");
    const url = URL.createObjectURL(blob);
    a.href = url;
    a.download = m ? m[1] : `report.${fmt}`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
    showToast(`${label} ready`, "success");
  } catch (e) {
    showToast(`Could not convert to ${label}: ${e.message}`, "error");
  }
}

export async function deleteReport(id, title) {
  // Deleting removes the stored file, not just the row, and there is no undo —
  // so unlike the reversible FP controls this one asks first.
  if (!window.confirm(
        `Delete "${title || id}"?\n\nThe generated file is removed from the server ` +
        `and cannot be recovered. The report can always be generated again.`)) {
    return;
  }
  try {
    const r = await fetch("/api/reports/history/" + encodeURIComponent(id), { method: "DELETE" });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast("Report deleted", "success");
    loadHistory();
  } catch (e) {
    showToast("Could not delete report: " + e.message, "error");
  }
}

// ── 1. Generate now ─────────────────────────────────────────────────────────

function renderGenerate() {
  const sel = document.getElementById("rp-report");
  const fmt = document.getElementById("rp-format");
  const per = document.getElementById("rp-period");
  if (!sel) return;

  if (!CAT) {
    sel.innerHTML = `<option>Reporting unavailable</option>`;
    sel.disabled = true;
    const btn = document.getElementById("rp-generate-btn");
    if (btn) btn.disabled = true;
    const d = document.getElementById("rp-desc");
    if (d) d.textContent = "The server reports that the reporting modules are unavailable.";
    return;
  }
  sel.disabled = false;
  const keep = sel.value;
  sel.innerHTML = allReports().map((r) =>
    `<option value="${esc(r.id)}">${esc(r.title)}${r.builtin ? "" : "  (custom)"}</option>`).join("");
  if (keep) sel.value = keep;

  if (fmt && !fmt.dataset.filled) {
    fmt.innerHTML = (CAT.formats || []).map((f) =>
      `<option value="${esc(f)}">${esc(f.toUpperCase())}</option>`).join("");
    fmt.dataset.filled = "1";
  }
  if (per && !per.dataset.filled) {
    per.innerHTML = PERIODS.map((p) =>
      `<option value="${p.h}"${p.h === (CAT.default_hours || 168) ? " selected" : ""}>${p.label}</option>`).join("");
    per.dataset.filled = "1";
  }
  describeSelected();
}

function describeSelected() {
  const sel = document.getElementById("rp-report");
  const out = document.getElementById("rp-desc");
  if (!sel || !out) return;
  const r = allReports().find((x) => x.id === sel.value);
  if (!r) { out.textContent = ""; return; }
  out.innerHTML = `<b>${esc(r.audience)}</b> — ${esc(r.purpose)}` +
    (r.builtin && r.rfp ? ` <span class="wl-dim">(RFP ${esc(r.rfp)})</span>` : "");
}

export async function generateReport() {
  const id  = document.getElementById("rp-report")?.value;
  const fmt = document.getElementById("rp-format")?.value || "pdf";
  const hrs = parseInt(document.getElementById("rp-period")?.value ?? "168", 10);
  const btn = document.getElementById("rp-generate-btn");
  if (!id) return;

  const restore = btn ? btn.textContent : null;
  if (btn) { btn.disabled = true; btn.textContent = "Generating…"; }
  try {
    const r = await fetch("/api/reports/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report_id: id, hours: hrs, format: fmt }),
    });
    if (!r.ok) {
      // The error path returns JSON even though the success path returns a file.
      let msg = `HTTP ${r.status}`;
      try { msg = (await r.json()).error || msg; } catch { /* not json */ }
      throw new Error(msg);
    }
    const blob = await r.blob();
    const name = filenameFrom(r.headers.get("Content-Disposition")) || `report.${fmt}`;
    downloadBlob(blob, name);
    showToast(`Report ready — ${name}`, "success");
    loadHistory();
  } catch (e) {
    showToast("Report failed: " + e.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = restore; }
  }
}

function filenameFrom(disposition) {
  const m = /filename="?([^"]+)"?/.exec(disposition || "");
  return m ? m[1] : null;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}

// ── 2. Custom reports (38) ──────────────────────────────────────────────────

function renderSectionPicker() {
  const box = document.getElementById("rp-sections");
  if (!box) return;
  if (!CAT) { box.innerHTML = ""; return; }
  box.innerHTML = (CAT.sections || []).map((s) => `
    <label class="rp-check">
      <input type="checkbox" value="${esc(s.id)}"> ${esc(s.label)}
    </label>`).join("");
  renderCustomList();
}

function renderCustomList() {
  const tb = document.getElementById("rp-custom-tbody");
  const badge = document.getElementById("rp-custom-badge");
  if (!tb) return;
  if (badge) badge.textContent = String(CUSTOM.length);
  if (!CUSTOM.length) {
    tb.innerHTML = `<tr><td colspan="5" class="empty-row">No custom reports yet. Tick the sections you want above and save one.</td></tr>`;
    return;
  }
  tb.innerHTML = CUSTOM.map((c) => `
    <tr>
      <td>${esc(c.name)}</td>
      <td class="wl-dim">${esc((c.sections || []).length)} sections · ${esc(c.format || "pdf")}</td>
      <td class="wl-dim">${esc(c.description || "—")}</td>
      <td class="wl-dim">${esc(c.created_by || "—")} · ${fmtWhen(c.created_at)}</td>
      <td><button class="fp-btn-inline" data-cap="reports.custom" onclick="deleteCustomReport('${esc(c.id)}','${esc(c.name)}')">Delete</button></td>
    </tr>`).join("");
}

export async function saveCustomReport() {
  const name = (document.getElementById("rp-custom-name")?.value || "").trim();
  const desc = (document.getElementById("rp-custom-desc")?.value || "").trim();
  const hours = parseInt(document.getElementById("rp-custom-period")?.value ?? "168", 10);
  const fmt = document.getElementById("rp-custom-format")?.value || "pdf";
  const sections = [...document.querySelectorAll("#rp-sections input:checked")].map((i) => i.value);

  if (!name) { showToast("Give the report a name", "error"); return; }
  if (!sections.length) { showToast("Pick at least one section", "error"); return; }
  try {
    const r = await fetch("/api/reports/custom", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, description: desc, sections, hours, format: fmt }),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Saved "${name}" — it is now in the report list.`, "success");
    document.getElementById("rp-custom-name").value = "";
    document.getElementById("rp-custom-desc").value = "";
    document.querySelectorAll("#rp-sections input:checked").forEach((i) => { i.checked = false; });
    await loadReports();
  } catch (e) {
    showToast("Could not save report: " + e.message, "error");
  }
}

export async function deleteCustomReport(id, name) {
  try {
    const r = await fetch("/api/reports/custom/" + encodeURIComponent(id), { method: "DELETE" });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Deleted "${name || id}"`, "success");
    await loadReports();
  } catch (e) {
    showToast("Could not delete: " + e.message, "error");
  }
}

// ── 3. Schedules (40) ───────────────────────────────────────────────────────

function renderSchedules() {
  const tb = document.getElementById("rp-sched-tbody");
  const badge = document.getElementById("rp-sched-badge");
  const tz = document.getElementById("rp-tz");
  if (!tb) return;
  if (badge) badge.textContent = String(SCHEDULES.length);
  if (tz && CAT) {
    tz.textContent = CAT.timezone
      ? `Times are ${CAT.timezone}.` + (CAT.email_enabled ? "" :
          " Email delivery is not configured, so scheduled reports are stored for download rather than sent.")
      : "";
  }
  // Keep the report dropdown in the schedule form in step with the catalogue.
  const sel = document.getElementById("rp-sched-report");
  if (sel && CAT) {
    const keep = sel.value;
    sel.innerHTML = allReports().map((r) =>
      `<option value="${esc(r.id)}">${esc(r.title)}</option>`).join("");
    if (keep) sel.value = keep;
  }
  if (!SCHEDULES.length) {
    tb.innerHTML = `<tr><td colspan="7" class="empty-row">Nothing is scheduled.</td></tr>`;
    return;
  }
  tb.innerHTML = SCHEDULES.map((s) => {
    const when = s.interval === "weekly" ? `${s.weekday ?? "monday"} ${s.at}`
      : s.interval === "monthly" ? `day ${s.day ?? 1}, ${s.at}`
      : s.interval === "hourly" ? `hourly at :${(s.at || "").split(":")[1] || "00"}`
      : `daily ${s.at}`;
    const title = (allReports().find((r) => r.id === s.report_id) || {}).title || s.report_id;
    return `
    <tr>
      <td>${esc(s.name || title)}</td>
      <td class="wl-dim">${esc(title)} · ${esc(s.format)}</td>
      <td>${esc(when)}</td>
      <td class="wl-dim">${(s.recipients || []).length ? esc((s.recipients || []).join(", ")) : "stored only"}</td>
      <td class="wl-dim">${s.last_status ? esc(s.last_status) : "not run yet"}</td>
      <td class="wl-dim">${fmtWhen(s.next_run)}</td>
      <td style="white-space:nowrap">
        <button class="fp-btn-inline" data-cap="reports.schedule" onclick="runScheduleNow('${esc(s.id)}')">Run now</button>
        <button class="fp-btn-inline" data-cap="reports.schedule" onclick="deleteSchedule('${esc(s.id)}','${esc(s.name || title)}')">Delete</button>
      </td>
    </tr>`;
  }).join("");
}

export async function saveSchedule() {
  const report_id = document.getElementById("rp-sched-report")?.value;
  const interval  = document.getElementById("rp-sched-interval")?.value || "daily";
  const at        = document.getElementById("rp-sched-at")?.value || "08:00";
  const hours     = parseInt(document.getElementById("rp-sched-period")?.value ?? "168", 10);
  const format    = document.getElementById("rp-sched-format")?.value || "pdf";
  const name      = (document.getElementById("rp-sched-name")?.value || "").trim();
  const recipients = (document.getElementById("rp-sched-to")?.value || "")
    .split(/[,;\s]+/).filter(Boolean);
  if (!report_id) { showToast("Pick a report to schedule", "error"); return; }
  try {
    const r = await fetch("/api/reports/schedules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report_id, interval, at, hours, format, name, recipients }),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(d.warning || "Schedule saved", d.warning ? "info" : "success");
    document.getElementById("rp-sched-name").value = "";
    document.getElementById("rp-sched-to").value = "";
    loadSchedules();
  } catch (e) {
    showToast("Could not save schedule: " + e.message, "error");
  }
}

export async function runScheduleNow(id) {
  showToast("Running…", "info");
  try {
    const r = await fetch(`/api/reports/schedules/${encodeURIComponent(id)}/run`, { method: "POST" });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Run complete — ${d.status}`, "success");
    loadSchedules(); loadHistory();
  } catch (e) {
    showToast("Run failed: " + e.message, "error");
  }
}

export async function deleteSchedule(id, name) {
  try {
    const r = await fetch("/api/reports/schedules/" + encodeURIComponent(id), { method: "DELETE" });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Removed schedule "${name || id}"`, "success");
    loadSchedules();
  } catch (e) {
    showToast("Could not delete schedule: " + e.message, "error");
  }
}

// ── Init ────────────────────────────────────────────────────────────────────

export function initReports() {
  const on = (id, ev, fn) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener(ev, fn);
  };
  on("rp-generate-btn", "click", generateReport);
  on("rp-report", "change", describeSelected);
  on("rp-custom-save-btn", "click", saveCustomReport);
  on("rp-sched-save-btn", "click", saveSchedule);
  // The weekday/day inputs only make sense for their own interval.
  on("rp-sched-interval", "change", () => {
    const v = document.getElementById("rp-sched-interval").value;
    const at = document.getElementById("rp-sched-at");
    if (at) at.disabled = false;
    document.getElementById("rp-sched-at").title =
      v === "hourly" ? "Only the minutes are used for an hourly schedule" : "";
  });
  // main.js calls this at module top level. Nothing in here may be allowed to
  // reject or throw into that: an earlier change on another panel took the
  // whole dashboard down because one failing step aborted the init sequence.
  // A broken Reports tab should cost you the Reports tab.
  loadReports().catch((e) => console.warn("[ueba] reports init failed:", e));
}
