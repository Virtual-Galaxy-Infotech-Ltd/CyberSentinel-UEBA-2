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
