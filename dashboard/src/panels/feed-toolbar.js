// Feed toolbar — search, MITRE multi-select, severity threshold, export
// buttons. Wires DOM events to state + renderFeed and keeps the toolbar
// in sync with state on each repaint.

import { state } from "../state.js";
import { renderFeed, filteredFeed, availableTactics } from "./feed.js";
import { exportCsv, exportJson, exportXml, exportPdf, exportXlsx } from "../export.js";
import { initSearchSuggest } from "./search-suggest.js";
import { initDeepSearch } from "./deep-search.js";
import { layoutRect, layoutViewport } from "../ui/ui-scale.js";

const SEARCH_DEBOUNCE_MS = 150;

function _resetPaginationAndRender() {
  state.feedRenderLimit = 200;
  renderFeed();
}

function _refreshMitreButton() {
  const cnt = document.getElementById("mitre-btn-count");
  if (!cnt) return;
  const n = state.feedTactics.size;
  cnt.textContent = n === 0 ? "All" : `${n} selected`;
}

function _refreshMitrePopBody() {
  const body = document.getElementById("mitre-pop-body");
  if (!body) return;
  const tactics = availableTactics();
  if (!tactics.length) {
    body.innerHTML = '<div class="mitre-pop-empty">No MITRE tactics in current data</div>';
    return;
  }
  body.innerHTML = tactics.map((t) => `
    <label class="mitre-row">
      <input type="checkbox" data-tactic="${escapeAttr(t)}" ${state.feedTactics.has(t) ? "checked" : ""}/>
      <span>${escapeHtml(t)}</span>
    </label>`).join("");
  body.querySelectorAll("input[type=checkbox]").forEach((cb) => {
    cb.addEventListener("change", () => {
      const t = cb.dataset.tactic;
      if (cb.checked) state.feedTactics.add(t);
      else state.feedTactics.delete(t);
      _refreshMitreButton();
      _resetPaginationAndRender();
    });
  });
}

export function initFeedToolbar() {
  // ── Free-text search (debounced) ─────────────────────────────────────────
  const input = document.getElementById("feed-search-input");
  const clear = document.getElementById("feed-search-clear");
  if (input) {
    let timer;
    input.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        state.feedSearch = input.value;
        _resetPaginationAndRender();
      }, SEARCH_DEBOUNCE_MS);
    });
  }
  if (clear) {
    clear.addEventListener("click", () => {
      if (input) input.value = "";
      state.feedSearch = "";
      _resetPaginationAndRender();
    });
  }

  // Auto-complete / auto-suggest over the current window's vocabulary.
  // Picking a suggestion sets the search term and re-renders immediately,
  // bypassing the debounce above — the analyst has already chosen.
  initSearchSuggest(_resetPaginationAndRender);
  initDeepSearch();

  // ── MITRE tactic dropdown ────────────────────────────────────────────────
  // The popover is MOVED out of the toolbar to <body> so no parent flex/grid
  // layout can affect its position. We then pin it with position:fixed
  // coords computed from the MITRE button's bounding rect at open time.
  const btn  = document.getElementById("mitre-btn");
  const pop  = document.getElementById("mitre-pop");
  const wrap = document.getElementById("mitre-dropdown");

  if (pop && pop.parentElement !== document.body) {
    document.body.appendChild(pop);
  }

  function _positionPop() {
    if (!btn || !pop || pop.hasAttribute("hidden")) return;
    // style.top/left are LAYOUT px, so anchor and clamp entirely in that space
    // (layoutRect / layoutViewport) rather than mixing a VISUAL client rect with
    // a LAYOUT offsetWidth — under `html { zoom }` those disagree by 1/zoom.
    const r  = layoutRect(btn);
    const vw = layoutViewport().width;
    // Width is set in CSS (260-320px); use the actual width for clamping.
    const popW = pop.offsetWidth || 260;
    let left = r.left;
    if (left + popW > vw - 12) left = vw - popW - 12;
    if (left < 8) left = 8;
    pop.style.top  = (r.bottom + 6) + "px";
    pop.style.left = left + "px";
  }

  function _closePop() {
    if (!pop || !wrap) return;
    pop.setAttribute("hidden", "");
    wrap.classList.remove("open");
    if (btn) btn.setAttribute("aria-expanded", "false");
  }

  if (btn && pop && wrap) {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const opening = pop.hasAttribute("hidden");
      if (opening) {
        _refreshMitrePopBody();
        // Make visible, then position. Default CSS top/left = -9999px so the
        // popover is never visible at the wrong spot.
        pop.removeAttribute("hidden");
        wrap.classList.add("open");
        btn.setAttribute("aria-expanded", "true");
        // Position after a microtask so the browser has computed offsetWidth.
        _positionPop();
        requestAnimationFrame(_positionPop);
      } else {
        _closePop();
      }
    });
    const closeBtn = document.getElementById("mitre-pop-close");
    if (closeBtn) {
      closeBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        _closePop();
      });
    }
    document.addEventListener("click", (e) => {
      // Note: pop is now a child of body, not wrap. Check both.
      if (!wrap.contains(e.target) && !pop.contains(e.target)) {
        _closePop();
      }
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !pop.hasAttribute("hidden")) _closePop();
    });
    // Keep the popover anchored if the viewport changes while it's open.
    window.addEventListener("resize", _positionPop);
    window.addEventListener("scroll", _positionPop, true);
  }
  const clearBtn = document.getElementById("mitre-clear-btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      state.feedTactics.clear();
      _refreshMitrePopBody();
      _refreshMitreButton();
      _resetPaginationAndRender();
    });
  }

  // ── Severity threshold ───────────────────────────────────────────────────
  const sev = document.getElementById("severity-select");
  if (sev) {
    sev.addEventListener("change", () => {
      state.feedSeverityMin = parseInt(sev.value, 10) || 0;
      _resetPaginationAndRender();
    });
  }

  // ── Export buttons ───────────────────────────────────────────────────────
  const csvBtn  = document.getElementById("export-csv-btn");
  const jsonBtn = document.getElementById("export-json-btn");
  const xmlBtn  = document.getElementById("export-xml-btn");
  if (csvBtn)  csvBtn.addEventListener("click",  () => exportCsv(filteredFeed()));
  if (jsonBtn) jsonBtn.addEventListener("click", () => exportJson(filteredFeed()));
  if (xmlBtn)  xmlBtn.addEventListener("click",  () => exportXml(filteredFeed()));
  const pdfBtn  = document.getElementById("export-pdf-btn");
  const xlsxBtn = document.getElementById("export-xlsx-btn");
  // PDF and Excel round-trip to the server, so they can take a moment on a wide
  // filter. Disable while in flight rather than let an impatient analyst queue
  // five identical 5,000-row renders.
  const guard = (btn, fn) => {
    if (!btn) return;
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try { await fn(filteredFeed()); } finally { btn.disabled = false; }
    });
  };
  guard(pdfBtn,  exportPdf);
  guard(xlsxBtn, exportXlsx);

  // ── Pagination ───────────────────────────────────────────────────────────
  window.__loadMoreFeed = () => {
    state.feedRenderLimit = (state.feedRenderLimit || 200) + 200;
    renderFeed();
  };
  window.__loadAllFeed = () => {
    state.feedRenderLimit = Number.MAX_SAFE_INTEGER;
    renderFeed();
  };

  _refreshMitreButton();
}

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function escapeAttr(s) {
  return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
