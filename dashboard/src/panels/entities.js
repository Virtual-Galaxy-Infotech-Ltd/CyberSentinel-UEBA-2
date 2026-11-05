// Tracked entities — the admin screen for RFP SN 30 and SN 67.
//
// SN 67 is "the operator can nominate any field and have its values tracked as
// entities". Until now that worked only by POSTing to /api/entities/mappings,
// which is not a console feature. This is the screen.
//
// Two things it deliberately does, because the API already does them and the
// UI would be lying if it did not:
//
//   * A REFUSAL IS SHOWN IN FULL. The server refuses a field whose values
//     never repeat — an id, a hash, a timestamp — because tracking it would
//     create one entity per event. The reason it returns is the useful part, so
//     it is surfaced verbatim rather than flattened into "invalid field".
//
//   * THE CLASSIFIER'S REASONING IS SHOWN. A device's role carries why it was
//     decided (name shape, operator override, how many accounts were seen).
//     An override that silently replaces a verdict teaches nobody anything;
//     showing both lets an admin see what they are overruling.

import { showToast } from "../ui/toast.js";

let _mappings = [];
let _status = null;

function esc(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function fmtWhen(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString([], {
      year: "2-digit", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return String(iso).slice(0, 16);
  }
}

export async function loadEntities() {
  const tb = document.getElementById("set-ent-tbody");
  if (!tb) return;
  try {
    const r = await fetch("/api/entities", { credentials: "same-origin" });
    if (r.status === 401 || r.status === 403) {
      _mappings = []; _status = null; render(); return;
    }
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    _status = d;
    _mappings = d.mappings || [];
  } catch (e) {
    _status = null;
    _mappings = null;
    console.warn("[ueba] entity mappings failed:", e);
  }
  render();
}

function render() {
  const tb = document.getElementById("set-ent-tbody");
  const badge = document.getElementById("set-ent-badge");
  const kinds = document.getElementById("set-ent-kinds");
  const overrides = document.getElementById("set-ent-overrides");
  if (!tb) return;

  if (badge) badge.textContent = _mappings ? _mappings.length : 0;

  if (kinds && _status) {
    // The built-in kinds, and the scope note the API ships. That note says
    // plainly that no data-asset kind exists and why; repeating it here is
    // what stops someone looking for a screen that was never built.
    const builtin = (_status.builtin_kinds || []).map(
      (k) => `<b>${esc(k)}</b>`).join(", ");
    kinds.innerHTML =
      `Classified automatically, with no configuration: ${builtin}. ` +
      `Anything you add below is tracked alongside them.` +
      (_status.data_asset_kind
        ? `<div style="margin-top:5px;opacity:.85">${esc(_status.data_asset_kind)}</div>`
        : "");
  }

  if (overrides && _status) {
    const n = _status.host_overrides || 0;
    overrides.textContent = n
      ? `${n} override${n === 1 ? "" : "s"} currently set.`
      : "No overrides set — every device is classified automatically.";
  }

  if (_mappings === null) {
    tb.innerHTML = `<tr><td colspan="5" class="wl-empty">Could not load tracked fields.</td></tr>`;
    return;
  }
  if (!_mappings.length) {
    tb.innerHTML = `<tr><td colspan="5" class="wl-empty">No extra fields are tracked yet.
      Users, devices, servers and applications are already recognised without any
      configuration — add a field above only to track something beyond those.</td></tr>`;
    return;
  }

  tb.innerHTML = _mappings.map((m) => `
    <tr>
      <td><code>${esc(m.field)}</code></td>
      <td><b>${esc(m.kind)}</b></td>
      <td>${esc(m.note || "—")}</td>
      <td>${esc(fmtWhen(m.added_at))}${m.added_by ? ` · ${esc(m.added_by)}` : ""}</td>
      <td>
        <button class="fp-btn-inline" data-act="untrack"
                data-field="${esc(m.field)}" data-kind="${esc(m.kind)}">Stop tracking</button>
      </td>
    </tr>`).join("");

  tb.querySelectorAll("button[data-act='untrack']").forEach((b) => {
    b.addEventListener("click", () => untrack(b.dataset.field, b.dataset.kind));
  });

  // The behaviour browser reads the same _status, so it repaints whenever the
  // mappings do — including right after an operator adds or removes one,
  // which is exactly when they want to see whether it took effect.
  renderBehaviour();
}

async function addMapping() {
  const fEl = document.getElementById("set-ent-field");
  const kEl = document.getElementById("set-ent-kind");
  const nEl = document.getElementById("set-ent-note");
  const field = (fEl?.value || "").trim();
  const kind = (kEl?.value || "").trim();
  if (!field || !kind) {
    showToast("Give both a field path and a name to track it as.", "error");
    return;
  }
  try {
    const r = await fetch("/api/entities/mappings", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ field, kind, note: (nEl?.value || "").trim() }),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) {
      // 422 is the interesting case: a well-formed request refused on its
      // merits. The server's sentence explains WHY the field is unusable, and
      // that sentence is the whole value of the refusal — so it is shown as
      // given rather than replaced with a generic message.
      throw new Error(d.error || `HTTP ${r.status}`);
    }
    showToast(`Now tracking ${d.entry.field} as ${d.entry.kind}.`, "ok");
    if (fEl) fEl.value = "";
    if (kEl) kEl.value = "";
    if (nEl) nEl.value = "";
    loadEntities();
  } catch (e) {
    showToast(String(e.message || e), "error");
  }
}

async function untrack(field, kind) {
  if (!window.confirm(
      `Stop tracking ${field} as ${kind}?\n\n` +
      `Entities already recorded under it are kept; nothing new is added.`)) {
    return;
  }
  try {
    const r = await fetch("/api/entities/mappings", {
      method: "DELETE",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ field, kind }),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    showToast(`Stopped tracking ${field}.`, "ok");
    loadEntities();
  } catch (e) {
    showToast(String(e.message || e), "error");
  }
}

async function setHostRole() {
  const hEl = document.getElementById("set-ent-host");
  const rEl = document.getElementById("set-ent-role");
  const host = (hEl?.value || "").trim();
  const role = rEl?.value ?? "";
  if (!host) {
    showToast("Name the device first.", "error");
    return;
  }
  try {
    // Show what the classifier currently thinks, so the admin can see what
    // they are overruling rather than overwriting it blind.
    let before = null;
    try {
      const q = await fetch(`/api/entities/classify?host=${encodeURIComponent(host)}`,
                            { credentials: "same-origin" });
      if (q.ok) before = await q.json();
    } catch { /* the override is still valid without it */ }

    const r = await fetch("/api/entities/hosts", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host, role }),
    });
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);

    if (!role) {
      showToast(`Override cleared — ${host} is classified automatically again.`, "ok");
    } else if (before && before.role && before.source !== "register") {
      showToast(`${host} is now ${role}. It was ${before.role} ` +
                `(${before.why}).`, "ok");
    } else {
      showToast(`${host} is now ${role}.`, "ok");
    }
    if (hEl) hEl.value = "";
    loadEntities();
  } catch (e) {
    showToast(String(e.message || e), "error");
  }
}

export function initEntities() {
  document.getElementById("set-ent-btn")
    ?.addEventListener("click", addMapping);
  document.getElementById("set-ent-host-btn")
    ?.addEventListener("click", setHostRole);
  // Enter in either field submits, which is what anyone typing a field path
  // expects to be able to do.
  ["set-ent-field", "set-ent-kind", "set-ent-note"].forEach((id) => {
    document.getElementById(id)?.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") addMapping();
    });
  });
  document.getElementById("set-ent-host")?.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") setHostRole();
  });
}

// ── Entity behaviour (RFP SN 30 / SN 67) ────────────────────────────────────
//
// The panels above let an operator DEFINE an entity kind. This browser is
// what makes that worth doing: it shows, per kind, which values exist and
// whether any of them is behaving oddly.
//
// Two scores are shown side by side and never blended, because they answer
// different questions and an analyst acts differently on each:
//
//   DRIFT   unlike ITSELF       — the later half of the window vs the earlier
//   PEER    unlike OTHERS       — this value vs the pooled profile of its kind
//
// A value can be perfectly steady yet unlike every sibling (a special-purpose
// service account), or entirely typical for its kind yet changing fast (an
// application being taken over). One number cannot say which, so there are
// two columns and the drill-down names the dimension behind each.

let _kind = "";          // the kind currently open
let _kindData = null;    // its rows, or null while loading
let _openValue = "";     // the value expanded inside it
let _valueData = null;

function scoreColour(v) {
  if (v === null || v === undefined) return "var(--text3)";
  if (v >= 0.7) return "var(--red, #f85149)";
  if (v >= 0.45) return "var(--orange, #f0883e)";
  if (v >= 0.25) return "var(--yellow, #d29922)";
  return "var(--green, #3fb950)";
}

function pct(v) {
  return (v === null || v === undefined) ? "—" : Math.round(v * 100) + "%";
}

function supportSection(st) {
  const rk = (st && st.recognised_kinds) || {};
  const names = Object.keys(rk);
  if (!names.length) return "";
  const rows = names.sort().map((k) => {
    const r = rk[k];
    const on = !!r.supported_by_feed;
    return `<div style="display:flex;gap:8px;align-items:baseline;padding:2px 0;font-size:10px;">
      <span style="font-family:var(--mono2);min-width:104px;color:var(--text2);">${esc(k)}</span>
      <span style="color:${on ? "var(--green, #3fb950)" : "var(--text3)"};
        font-family:var(--mono2);min-width:74px;">${on ? "available" : "no field"}</span>
      <span style="flex:1;color:var(--text3);">${esc(r.describes || "")}${
        on ? ` · ${esc((r.fields_present || []).slice(0, 2).join(", "))}`
           : ` · map any field that carries one`}</span>
    </div>`;
  }).join("");
  return `<div class="panel-header" style="margin-top:14px">
      <div class="panel-title">ENTITY KINDS THIS FEED SUPPORTS</div>
    </div>
    <div class="set-note" style="margin-bottom:6px">
      Servers, endpoints and applications are classified without configuration.
      The kinds below are recognised by name so a report can speak about them
      consistently &mdash; whether this deployment can populate one depends on
      whether its events carry a suitable field, which is measured here rather
      than assumed.
    </div>
    ${rows}`;
}

function kindBar(st) {
  const profiled = (st && st.profiled_kinds) || [];
  if (!profiled.length) {
    return `<div class="set-note">No entity kind has been seen in the
      selected window yet, so there is nothing to assess.</div>`;
  }
  const chips = profiled.map((k) => {
    const on = k === _kind;
    return `<button class="export-btn" data-act="kind" data-kind="${esc(k)}"
      style="font-family:var(--mono2);font-size:10px;padding:2px 8px;
      ${on ? "border-color:var(--blue, #4aa3ff);color:var(--blue, #4aa3ff);" : ""}">
      ${esc(k)}</button>`;
  }).join(" ");
  return `<div class="wl-form" style="gap:6px;flex-wrap:wrap;">${chips}</div>`;
}

function dimRows(dims, scoreKey, sharedKey, unlikeKey) {
  return (dims || []).map((d) => {
    const v = d[scoreKey];
    const shared = (d[sharedKey] || []).slice(0, 3)
      .map((x) => esc(x.key)).join(", ");
    const unlike = (d[unlikeKey] || []).slice(0, 3).map((x) => {
      const mark = x.appeared ? "new" : x.stopped ? "gone" : "";
      return esc(x.key) + (mark ? ` (${mark})` : "");
    }).join(", ");
    return `<div style="padding:3px 0;border-top:1px solid var(--line, rgba(255,255,255,.05));">
      <div style="display:flex;gap:6px;align-items:baseline;font-size:10px;">
        <span style="font-family:var(--mono2);text-transform:uppercase;
          letter-spacing:1px;min-width:72px;color:var(--text2);">${esc(d.dimension)}</span>
        <span style="flex:1;color:var(--text3);">${esc(d.measures || "")}</span>
        <span style="font-family:var(--mono2);color:${scoreColour(v)};">${pct(v)}</span>
      </div>
      ${shared ? `<div style="font-size:10px;color:var(--text3);padding-left:78px;">
        same: ${shared}</div>` : ""}
      ${unlike ? `<div style="font-size:10px;color:var(--text3);padding-left:78px;">
        differs: ${unlike}</div>` : ""}
    </div>`;
  }).join("");
}

function valueDetail() {
  if (!_valueData) {
    return `<div style="font-size:10px;color:var(--text3);padding:6px 0;">Loading…</div>`;
  }
  const d = _valueData;
  if (d.profiled === false) {
    return `<div style="font-size:10px;color:var(--text3);padding:6px 0;">
      ${esc(d.note || "Nothing to assess for this value.")}</div>`;
  }
  const a = d.assessment || {};
  const drift = a.self_drift || {};
  const peer = a.peer_outlier || {};
  const actors = (d.actors || []).slice(0, 8).map((x) =>
    `<span style="font-family:var(--mono2);font-size:10px;color:var(--text3);
      margin-right:8px;">${esc(x.entity)} <span style="opacity:.6">${x.events}</span></span>`
  ).join("");
  const half = d.halves || {};
  return `<div style="padding:6px 0 2px;">
    <div style="font-size:10px;color:var(--text2);margin-bottom:6px;line-height:1.5;">
      ${esc(a.why || "")}
    </div>
    <div style="font-size:10px;color:var(--text3);margin-bottom:6px;">
      ${d.events} events · ${d.actor_count} account(s) ·
      ${half.baseline ?? 0} before / ${half.recent ?? 0} after the split
    </div>
    ${actors ? `<div style="margin-bottom:6px;">${actors}</div>` : ""}

    <div style="font-family:var(--mono2);font-size:8px;letter-spacing:2px;
      text-transform:uppercase;color:var(--text3);margin-top:8px;">
      Unlike itself — ${pct(drift.score)}</div>
    ${drift.comparable
      ? dimRows(drift.dimensions, "drift", "stable", "changed")
      : `<div style="font-size:10px;color:var(--text3);">${esc(drift.why || "")}</div>`}

    <div style="font-family:var(--mono2);font-size:8px;letter-spacing:2px;
      text-transform:uppercase;color:var(--text3);margin-top:10px;">
      Unlike others of its kind — ${pct(peer.score)}</div>
    ${peer.comparable
      ? dimRows(peer.dimensions, "distance", "shared", "unlike")
      : `<div style="font-size:10px;color:var(--text3);">${esc(peer.why || "")}</div>`}
  </div>`;
}

function kindTable() {
  if (!_kind) return "";
  if (!_kindData) {
    return `<div style="font-size:10px;color:var(--text3);padding:8px 0;">Loading ${esc(_kind)}…</div>`;
  }
  const rows = _kindData.rows || [];
  if (!rows.length) {
    return `<div style="font-size:11px;color:var(--text3);padding:8px 0;">
      No values recorded under <b>${esc(_kind)}</b> in this window.</div>`;
  }
  const a = _kindData.assessment || {};
  const body = rows.map((r) => {
    const open = r.value === _openValue;
    // `source` matters: entity_presence fills as new events arrive, while the
    // stored history is already there. An operator checking a mapping they
    // just made needs to know which they are looking at.
    const src = r.source === "alerts" ? "history" : "live";
    return `<tr data-act="value" data-value="${esc(r.value)}"
        style="cursor:pointer;${open ? "background:rgba(255,255,255,.03);" : ""}">
        <td><span style="font-family:var(--mono);font-size:11px;">${esc(r.value)}</span>
          <span style="font-family:var(--mono2);font-size:8px;color:var(--text3);
            margin-left:6px;">${src}</span></td>
        <td style="font-family:var(--mono2);font-size:10px;">${r.events ?? "—"}</td>
        <td style="font-family:var(--mono2);font-size:10px;">${r.entities ?? "—"}</td>
        <td style="font-family:var(--mono2);font-size:11px;color:${scoreColour(r.self_drift)};">
          ${pct(r.self_drift)}</td>
        <td style="font-family:var(--mono2);font-size:11px;color:${scoreColour(r.peer_outlier)};">
          ${pct(r.peer_outlier)}</td>
      </tr>
      ${open ? `<tr><td colspan="5" style="padding:0 10px 8px;">${valueDetail()}</td></tr>` : ""}`;
  }).join("");
  return `<div style="font-size:10px;color:var(--text3);margin:8px 0 6px;line-height:1.5;">
      ${a.values ?? rows.length} value(s), ${a.scored ?? 0} with enough history to
      score. <b>Drift</b> is how much a value changed between the two halves of
      the window; <b>peer</b> is how unlike the other values of its kind it is.
      They are not combined &mdash; a value can be steady but unusual, or
      ordinary but changing.${
        a.truncated ? ` Only the first ${a.cap} values are profiled.` : ""}
    </div>
    <div class="feed-table-wrap">
      <table>
        <thead><tr>
          <th>Value</th><th>Events</th><th>Accounts</th>
          <th>Drift</th><th>Peer</th>
        </tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>`;
}

function renderBehaviour() {
  const el = document.getElementById("set-ent-behaviour");
  if (!el) return;
  el.innerHTML = `
    <div class="panel-header" style="margin-top:14px">
      <div class="panel-title">ENTITY BEHAVIOUR</div>
    </div>
    ${kindBar(_status)}
    ${kindTable()}
    ${supportSection(_status)}`;

  el.querySelectorAll("button[data-act='kind']").forEach((b) => {
    b.addEventListener("click", () => openKind(b.dataset.kind));
  });
  el.querySelectorAll("tr[data-act='value']").forEach((t) => {
    t.addEventListener("click", () => openValue(t.dataset.value));
  });
}

async function openKind(kind) {
  if (_kind === kind) { _kind = ""; _kindData = null; _openValue = ""; renderBehaviour(); return; }
  _kind = kind;
  _kindData = null;
  _openValue = "";
  _valueData = null;
  renderBehaviour();
  try {
    const r = await fetch(`/api/entities/kind/${encodeURIComponent(kind)}`,
                          { credentials: "same-origin" });
    _kindData = r.ok ? await r.json() : { rows: [] };
  } catch {
    _kindData = { rows: [] };
  }
  renderBehaviour();
}

async function openValue(value) {
  if (_openValue === value) { _openValue = ""; _valueData = null; renderBehaviour(); return; }
  _openValue = value;
  _valueData = null;
  renderBehaviour();
  try {
    const r = await fetch(
      `/api/entities/profile/${encodeURIComponent(_kind)}/${encodeURIComponent(value)}`,
      { credentials: "same-origin" });
    _valueData = r.ok ? await r.json() : { profiled: false, note: "Could not load." };
  } catch {
    _valueData = { profiled: false, note: "Could not load." };
  }
  renderBehaviour();
}

export function renderEntityBehaviour() {
  renderBehaviour();
}
