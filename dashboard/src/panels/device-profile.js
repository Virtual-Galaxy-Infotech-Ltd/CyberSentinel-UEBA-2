// Device profile and peer comparison (RFP SN 56).
//
// A third tab on the endpoint drilldown. Everything here is fetched ONLY when
// the tab is first opened: the two calls behind it aggregate the whole window
// server-side, and paying for them on every agent click would slow down the
// two panes an analyst actually opens first.
//
// Two things the UI has to be careful to say honestly, because the API is
// careful to say them:
//
//   * a device with no comparable peer renders the server's reason, not an
//     empty table. "Nothing scored above 0.15" and "this is the only device
//     with alerts" are different facts and an analyst needs to know which.
//   * similarity is alert-profile similarity, not role. Two devices can match
//     at 0.93 and be a server and a laptop. The basis line says so rather than
//     leaving the number to be read as "same kind of machine".

import { state } from "../state.js";

const cache = new Map();   // device -> { summary, peers }

function esc(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function simColor(sim) {
  if (sim >= 0.7) return "var(--red)";
  if (sim >= 0.4) return "var(--orange)";
  return "var(--yellow)";
}

function roleBadge(role, why) {
  if (!role) return "";
  const col = role === "server" ? "var(--blue, #4aa3ff)" : "var(--text2)";
  return `<span title="${esc(why)}" style="font-family:var(--mono2);font-size:9px;
    letter-spacing:1px;text-transform:uppercase;border:1px solid ${col};
    color:${col};border-radius:3px;padding:1px 6px;">${esc(role)}</span>`;
}

function kv(label, value) {
  return `<div style="display:flex;justify-content:space-between;gap:10px;
    padding:3px 0;border-bottom:1px solid var(--line, rgba(255,255,255,.06));">
    <span style="font-family:var(--mono2);font-size:9px;letter-spacing:1px;
      text-transform:uppercase;color:var(--text3);">${esc(label)}</span>
    <span style="font-family:var(--mono);font-size:11px;color:var(--text);
      text-align:right;">${value}</span></div>`;
}

function touchedSection(touched, note) {
  const kinds = Object.keys(touched || {});
  if (!kinds.length) {
    return `<div style="font-size:11px;color:var(--text3);line-height:1.5;">
      Nothing recorded against this machine yet.
      <span style="display:block;margin-top:3px;font-size:10px;">${esc(note || "")}</span>
    </div>`;
  }
  return kinds.map((kind) => {
    const rows = (touched[kind] || []).slice(0, 12).map((r) => `
      <div style="display:flex;justify-content:space-between;gap:8px;padding:2px 0;">
        <span style="font-family:var(--mono);font-size:11px;">${esc(r.value)}</span>
        <span style="font-family:var(--mono2);font-size:10px;color:var(--text3);">${r.events}</span>
      </div>`).join("");
    return `<div style="margin-bottom:10px;">
      <div style="font-family:var(--mono2);font-size:9px;letter-spacing:1px;
        text-transform:uppercase;color:var(--text3);margin-bottom:3px;">${esc(kind)}</div>
      ${rows}</div>`;
  }).join("");
}

function peersSection(p) {
  if (!p.comparable) {
    return `<div class="empty-state" style="padding:18px 14px;">
      <p style="color:var(--text2);font-size:12px;margin:0 0 4px;">NO COMPARABLE DEVICE</p>
      <div style="font-size:11px;color:var(--text3);line-height:1.5;max-width:520px;">
        ${esc(p.reason || "")}
      </div>
    </div>`;
  }
  const rows = (p.peers || []).map((x) => {
    const sigs = (x.shared_signatures || []).map((s) => `
      <div style="display:flex;gap:8px;padding:1px 0;font-size:10px;color:var(--text3);">
        <span style="font-family:var(--mono2);min-width:52px;">${esc(s.signature_id)}</span>
        <span style="flex:1;">${esc((s.signature || "").slice(0, 64))}</span>
        <span style="font-family:var(--mono2);">${s.here}/${s.there}</span>
      </div>`).join("");
    const overlap = x.account_overlap > 0
      ? `${(x.account_overlap * 100).toFixed(0)}% account overlap`
      : "no shared accounts";
    return `<div style="border:1px solid var(--line, rgba(255,255,255,.08));
      border-radius:4px;padding:9px 11px;margin-bottom:8px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
        <span style="font-family:var(--mono);font-size:12px;">${esc(x.device)}</span>
        ${roleBadge(x.role, "")}
        <span style="flex:1;"></span>
        <span style="font-family:var(--mono);font-size:14px;color:${simColor(x.similarity)};">
          ${x.similarity.toFixed(2)}</span>
      </div>
      <div style="font-size:10px;color:var(--text3);margin-bottom:5px;">
        ${x.alerts} alerts · ${x.user_count} accounts · ${esc(overlap)}
      </div>
      ${sigs}
    </div>`;
  }).join("");
  return `<div style="font-size:10px;color:var(--text3);margin-bottom:8px;line-height:1.5;">
      Ranked against ${p.compared_against} other device(s). ${esc(p.basis || "")}
    </div>${rows}`;
}

function render(el, summary, peers) {
  const presence = (summary.presence && summary.presence.accounts) || [];
  el.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
      <div class="ep-chart-card" style="padding:12px;">
        <div style="font-family:var(--mono2);font-size:8px;color:var(--text3);
          letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">
          ⬡ Classification</div>
        ${kv("Role", roleBadge(summary.role, summary.role_why) || "—")}
        ${kv("Why", `<span style="font-size:10px;color:var(--text2);">${esc(summary.role_why || "—")}</span>`)}
        ${kv("Address", esc(summary.ip || "—"))}
        ${kv("Accounts seen (all traffic)", summary.accounts_seen ?? 0)}
        ${kv("Accounts in alerts", summary.user_count ?? 0)}
        ${kv("Alerts in window", summary.alerts ?? 0)}
        ${kv("Max score", (summary.max_score ?? 0).toFixed ? summary.max_score.toFixed(3) : summary.max_score)}
        ${kv("First seen", esc((summary.first_seen || "—").slice(0, 19)))}
        ${kv("Last seen", esc((summary.last_seen || "—").slice(0, 19)))}
      </div>
      <div class="ep-chart-card" style="padding:12px;">
        <div style="font-family:var(--mono2);font-size:8px;color:var(--text3);
          letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">
          ⬡ Seen on this machine</div>
        ${touchedSection(summary.touched, summary.touched_note)}
      </div>
    </div>

    <div class="ep-chart-card" style="padding:12px;margin-top:12px;">
      <div style="font-family:var(--mono2);font-size:8px;color:var(--text3);
        letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">
        ⬡ Accounts on this machine (all traffic)</div>
      ${presence.length ? presence.slice(0, 15).map((r) => `
        <div style="display:flex;justify-content:space-between;gap:8px;padding:2px 0;">
          <span style="font-family:var(--mono);font-size:11px;">${esc(r.entity)}</span>
          <span style="font-family:var(--mono2);font-size:10px;color:var(--text3);">
            ${r.events} events</span>
        </div>`).join("")
        : `<div style="font-size:11px;color:var(--text3);">No presence rows for this machine.</div>`}
    </div>

    <div class="ep-chart-card" style="padding:12px;margin-top:12px;">
      <div style="font-family:var(--mono2);font-size:8px;color:var(--text3);
        letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">
        ⬡ Devices that behave like this one</div>
      ${peersSection(peers)}
    </div>`;
}

export async function loadDeviceProfile(device, { force = false } = {}) {
  const el = document.getElementById("agent-pane-profile");
  if (!el || !device) return;

  const key = `${device}|${state.timelineHours || 0}`;
  if (!force && cache.has(key)) {
    const hit = cache.get(key);
    render(el, hit.summary, hit.peers);
    return;
  }

  el.innerHTML = '<div class="loading"><div class="spinner"></div> Loading profile...</div>';
  const hours = state.timelineHours || 0;
  const q = `?hours=${hours}`;
  try {
    // Both in parallel: the peer ranking does not depend on the summary, and
    // serialising them doubled the time the pane spent empty.
    const [summary, peers] = await Promise.all([
      fetch(`/api/device/${encodeURIComponent(device)}${q}`).then((r) => r.json()),
      fetch(`/api/device/${encodeURIComponent(device)}/peers${q}`).then((r) => r.json()),
    ]);
    cache.set(key, { summary, peers });
    render(el, summary, peers);
  } catch (e) {
    el.innerHTML = `<div class="empty-state"><p>FAILED TO LOAD PROFILE</p>
      <div style="font-size:11px;color:var(--text3);">${esc(e && e.message)}</div></div>`;
  }
}

// Dropped when the window changes, so switching the timeline does not show a
// profile aggregated over a different period than the one selected.
export function clearDeviceProfileCache() {
  cache.clear();
}
