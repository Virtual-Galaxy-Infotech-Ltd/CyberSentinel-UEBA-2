// Dashboard customisation modal.
//
// Renders a draggable list of all panels with visibility checkboxes.
// Saves preferences to /api/dashboard/layout on "Apply".
// Resets to the shipped default via DELETE /api/dashboard/layout.
//
// Drag-and-drop uses the HTML5 Drag API so there is no extra dependency.
// Tabs and overview rows each form their own ordering scope.

import { showToast } from "../ui/toast.js";
import {
  TAB_PANELS, OVERVIEW_ROWS, OVERVIEW_PANELS, OTHER_PANELS,
  applyDashboardLayout, getDefaultLayout,
} from "./dashboard-layout.js";
import { saveDashboardLayout, resetDashboardLayout, fetchDashboardLayout } from "../api.js";

// ── Current in-modal state ──────────────────────────────────────────────────

let _tabOrder       = TAB_PANELS.map((p) => ({ ...p, visible: true }));
let _rowOrder       = OVERVIEW_ROWS.map((r) => ({ ...r, visible: true }));
let _panelVisible   = Object.fromEntries(OVERVIEW_PANELS.map((p) => [p.id, true]));
let _otherVisible   = Object.fromEntries(OTHER_PANELS.map((p) => [p.id, true]));

// ── Public API ───────────────────────────────────────────────────────────────

export function initCustomise() {
  const btn = document.getElementById("customise-btn");
  if (btn) btn.addEventListener("click", openCustomiseModal);
}

export async function openCustomiseModal() {
  try {
    const data = await fetchDashboardLayout();
    _syncStateFromLayout(data && data.layout ? data.layout : null);
  } catch (e) {
    _syncStateFromDom();
  }
  _render();
}

// ── State sync ───────────────────────────────────────────────────────────────

function _syncStateFromLayout(layout) {
  if (!layout) {
    _tabOrder     = TAB_PANELS.map((p) => ({ ...p, visible: true }));
    _rowOrder     = OVERVIEW_ROWS.map((r) => ({ ...r, visible: true }));
    _panelVisible = Object.fromEntries(OVERVIEW_PANELS.map((p) => [p.id, true]));
    _otherVisible = Object.fromEntries(OTHER_PANELS.map((p) => [p.id, true]));
    return;
  }

  if (layout.panels) {
    const savedMap = Object.fromEntries(layout.panels.map((s) => [s.id, s]));
    const savedIds = layout.panels.map((s) => s.id);
    _tabOrder = [
      ...savedIds.map((id) => TAB_PANELS.find((p) => p.id === id))
        .filter(Boolean)
        .map((p) => ({ ...p, visible: savedMap[p.id]?.visible !== false })),
      ...TAB_PANELS.filter((p) => !savedIds.includes(p.id))
        .map((p) => ({ ...p, visible: true })),
    ];
  } else {
    _tabOrder = TAB_PANELS.map((p) => ({ ...p, visible: true }));
  }

  if (layout.overview_rows) {
    const savedMap = Object.fromEntries(layout.overview_rows.map((s) => [s.id, s]));
    const savedIds = layout.overview_rows.map((s) => s.id);
    _rowOrder = [
      ...savedIds.map((id) => OVERVIEW_ROWS.find((r) => r.id === id))
        .filter(Boolean)
        .map((r) => ({ ...r, visible: savedMap[r.id]?.visible !== false })),
      ...OVERVIEW_ROWS.filter((r) => !savedIds.includes(r.id))
        .map((r) => ({ ...r, visible: true })),
    ];
  } else {
    _rowOrder = OVERVIEW_ROWS.map((r) => ({ ...r, visible: true }));
  }

  if (layout.overview_panels) {
    const savedMap = Object.fromEntries(layout.overview_panels.map((s) => [s.id, s]));
    _panelVisible = Object.fromEntries(
      OVERVIEW_PANELS.map((p) => [p.id, savedMap[p.id]?.visible !== false])
    );
  } else {
    _panelVisible = Object.fromEntries(OVERVIEW_PANELS.map((p) => [p.id, true]));
  }

  if (layout.other) {
    const savedMap = Object.fromEntries(layout.other.map((s) => [s.id, s]));
    _otherVisible = Object.fromEntries(
      OTHER_PANELS.map((p) => [p.id, savedMap[p.id]?.visible !== false])
    );
  } else {
    _otherVisible = Object.fromEntries(OTHER_PANELS.map((p) => [p.id, true]));
  }
}

function _syncStateFromDom() {
  _tabOrder = TAB_PANELS.map((p) => {
    const el = document.querySelector(`[data-panel-id="${p.id}"]`);
    return { ...p, visible: !el?.classList.contains("panel-hidden") };
  });
  _rowOrder = OVERVIEW_ROWS.map((r) => {
    const el = document.querySelector(`[data-panel-id="${r.id}"]`);
    return { ...r, visible: !el?.classList.contains("panel-hidden") };
  });
  _panelVisible = Object.fromEntries(OVERVIEW_PANELS.map((p) => {
    const el = document.querySelector(`[data-panel-id="${p.id}"]`);
    return [p.id, !el?.classList.contains("panel-hidden")];
  }));
  _otherVisible = Object.fromEntries(OTHER_PANELS.map((p) => {
    const el = document.querySelector(`[data-panel-id="${p.id}"]`);
    return [p.id, !el?.classList.contains("panel-hidden")];
  }));
}

// ── Render ───────────────────────────────────────────────────────────────────

function _render() {
  let modal = document.getElementById("customise-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "customise-modal";
    modal.className = "cust-overlay";
    document.body.appendChild(modal);
    modal.addEventListener("click", (e) => { if (e.target === modal) _close(); });
  }

  modal.innerHTML = `
    <div class="cust-dialog" role="dialog" aria-modal="true" aria-labelledby="cust-title">
      <div class="cust-header">
        <span id="cust-title" class="cust-title">Customise Dashboard Layout</span>
        <button class="cust-close" id="cust-close" aria-label="Close">✕</button>
      </div>
      <div class="cust-body">
        <p class="cust-hint">Drag ≡ to reorder · toggle checkbox to show/hide · click Apply to save.</p>

        <div class="cust-section">
          <div class="cust-section-title">Navigation Panels</div>
          <div class="cust-section-hint">Which tabs appear in the sidebar and in what order.</div>
          <ul class="cust-list" id="cust-tabs-list">
            ${_tabOrder.map((p) => _rowItemHtml(p)).join("")}
          </ul>
        </div>

        <div class="cust-section">
          <div class="cust-section-title">Overview Dashboard Sections</div>
          <div class="cust-section-hint">Drag sections to reorder them on the Overview page. Toggle individual panels inside each section to show or hide them.</div>
          <ul class="cust-list" id="cust-rows-list">
            ${_rowOrder.map((r) => _ovRowItemHtml(r)).join("")}
          </ul>
        </div>

        <div class="cust-section">
          <div class="cust-section-title">Other Panels</div>
          <div class="cust-section-hint">Individual sub-panels you can show or hide.</div>
          <ul class="cust-list" id="cust-other-list">
            ${OTHER_PANELS.map((p) => _rowItemHtml({ ...p, visible: _otherVisible[p.id] !== false }, false)).join("")}
          </ul>
        </div>
      </div>
      <div class="cust-footer">
        <button class="cust-btn cust-btn-reset" id="cust-reset">Reset to Default</button>
        <div class="cust-footer-right">
          <button class="cust-btn cust-btn-cancel" id="cust-cancel">Cancel</button>
          <button class="cust-btn cust-btn-save" id="cust-save">Apply</button>
        </div>
      </div>
    </div>
  `;

  _attachListeners(modal);
  modal.classList.add("cust-open");
  document.body.classList.add("cust-modal-open");
}

function _rowItemHtml(item, draggable = true) {
  const checked = item.visible !== false ? "checked" : "";
  const dragHandle = draggable
    ? `<span class="cust-drag" title="Drag to reorder" aria-hidden="true">⠿</span>`
    : `<span class="cust-drag cust-drag-noop" aria-hidden="true">⠿</span>`;
  return `
    <li class="cust-item" data-id="${item.id}" draggable="${draggable}">
      ${dragHandle}
      <label class="cust-label">
        <input type="checkbox" class="cust-check" data-id="${item.id}" ${checked}/>
        <span class="cust-name">${item.name}</span>
      </label>
    </li>`;
}

function _ovRowItemHtml(row) {
  const checked = row.visible !== false ? "checked" : "";
  const subPanels = OVERVIEW_PANELS.filter((p) => p.row === row.id);
  const subHtml = subPanels.map((p) => {
    const pChecked = _panelVisible[p.id] !== false ? "checked" : "";
    return `
      <li class="cust-subitem" data-id="${p.id}">
        <label class="cust-label">
          <input type="checkbox" class="cust-subcheck" data-id="${p.id}" ${pChecked}/>
          <span class="cust-name cust-subname">${p.name}</span>
        </label>
      </li>`;
  }).join("");

  const subsSection = subPanels.length > 0
    ? `<ul class="cust-sublist">${subHtml}</ul>`
    : "";

  return `
    <li class="cust-item" data-id="${row.id}" draggable="true">
      <span class="cust-drag" title="Drag to reorder" aria-hidden="true">⠿</span>
      <div class="cust-row-wrap">
        <label class="cust-label">
          <input type="checkbox" class="cust-check" data-id="${row.id}" ${checked}/>
          <span class="cust-name">${row.name}</span>
        </label>
        ${subsSection}
      </div>
    </li>`;
}

// ── Event listeners ──────────────────────────────────────────────────────────

function _attachListeners(modal) {
  modal.querySelector("#cust-close").addEventListener("click", _close);
  modal.querySelector("#cust-cancel").addEventListener("click", _close);
  modal.querySelector("#cust-save").addEventListener("click", _save);
  modal.querySelector("#cust-reset").addEventListener("click", _reset);

  modal.querySelector("#cust-tabs-list").addEventListener("change", () => _enforceMinTab(modal));

  _initDragAndDrop(modal.querySelector("#cust-tabs-list"));
  _initDragAndDrop(modal.querySelector("#cust-rows-list"));
}

function _enforceMinTab(modal) {
  const checks = Array.from(modal.querySelectorAll("#cust-tabs-list .cust-check"));
  if (!checks.some((c) => c.checked)) {
    checks[0].checked = true;
    showToast("At least one navigation panel must remain visible.", "warning");
  }
}

// ── Drag-and-drop ─────────────────────────────────────────────────────────────

let _dragSrc = null;

function _initDragAndDrop(list) {
  if (!list) return;

  list.addEventListener("dragstart", (e) => {
    const item = e.target.closest(".cust-item");
    if (!item) return;
    _dragSrc = item;
    item.classList.add("cust-dragging");
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", item.dataset.id);
  });

  list.addEventListener("dragend", () => {
    list.querySelectorAll(".cust-dragging, .cust-drag-over")
      .forEach((el) => el.classList.remove("cust-dragging", "cust-drag-over"));
    _dragSrc = null;
  });

  list.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    const target = e.target.closest(".cust-item");
    if (!target || target === _dragSrc) return;
    list.querySelectorAll(".cust-drag-over").forEach((el) => el.classList.remove("cust-drag-over"));
    target.classList.add("cust-drag-over");
  });

  list.addEventListener("dragleave", (e) => {
    const target = e.target.closest(".cust-item");
    if (target) target.classList.remove("cust-drag-over");
  });

  list.addEventListener("drop", (e) => {
    e.preventDefault();
    const target = e.target.closest(".cust-item");
    if (!target || !_dragSrc || target === _dragSrc) return;
    target.classList.remove("cust-drag-over");
    const rect  = target.getBoundingClientRect();
    const after = e.clientY > rect.top + rect.height / 2;
    if (after) target.after(_dragSrc);
    else       target.before(_dragSrc);
  });
}

// ── Save / Reset / Close ─────────────────────────────────────────────────────

async function _save() {
  const modal = document.getElementById("customise-modal");
  if (!modal) return;

  const layout = _buildLayout(modal);
  const btn = modal.querySelector("#cust-save");
  if (btn) { btn.disabled = true; btn.textContent = "Saving…"; }

  try {
    await saveDashboardLayout(layout);
    applyDashboardLayout(layout);
    showToast("Dashboard layout saved.", "success");
    _close();
  } catch (e) {
    showToast("Failed to save layout: " + e.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Apply"; }
  }
}

async function _reset() {
  if (!confirm("Reset your dashboard to the original shipped layout?")) return;
  const btn = document.getElementById("cust-reset");
  if (btn) { btn.disabled = true; btn.textContent = "Resetting…"; }
  try {
    await resetDashboardLayout();
    applyDashboardLayout(null);
    showToast("Dashboard reset to default.", "success");
    _close();
  } catch (e) {
    showToast("Failed to reset layout: " + e.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Reset to Default"; }
  }
}

function _close() {
  const modal = document.getElementById("customise-modal");
  if (modal) {
    modal.classList.remove("cust-open");
    document.body.classList.remove("cust-modal-open");
  }
}

// ── Build layout from modal DOM ───────────────────────────────────────────────

function _buildLayout(modal) {
  const readList = (listId) =>
    Array.from(modal.querySelectorAll(`#${listId} > .cust-item`)).map((li) => ({
      id:      li.dataset.id,
      visible: !!li.querySelector(".cust-check")?.checked,
    }));

  const ovPanels = Array.from(modal.querySelectorAll("#cust-rows-list .cust-subcheck")).map((cb) => ({
    id:      cb.dataset.id,
    visible: cb.checked,
  }));

  return {
    panels:          readList("cust-tabs-list"),
    overview_rows:   readList("cust-rows-list"),
    overview_panels: ovPanels,
    other:           readList("cust-other-list"),
  };
}
