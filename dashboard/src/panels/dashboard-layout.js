// Dashboard layout persistence — applies a saved panel arrangement to the DOM.
//
// The layout has three independent scopes:
//   panels         — sidebar navigation tabs (order + visibility)
//   overview_rows  — the row-level sections on the Overview page (order only)
//   overview_panels — individual widget cards (visibility only; some within rows)
//   other           — miscellaneous sub-panels on other pages (visibility only)

// ── Navigation tab panels (11 tabs; settings is always present and not listed)

export const TAB_PANELS = [
  { id: "tab-overview",        name: "Overview",          tab: "overview" },
  { id: "tab-incidents",       name: "Incidents",         tab: "incidents" },
  { id: "tab-feed",            name: "Alert Feed",        tab: "feed" },
  { id: "tab-users",           name: "User Risk",         tab: "users" },
  { id: "tab-campaigns",       name: "Campaigns",         tab: "campaigns" },
  { id: "tab-endpoints",       name: "Endpoints",         tab: "endpoints" },
  { id: "tab-false-positives", name: "False Positives",   tab: "false-positives" },
  { id: "tab-alerting",        name: "Alerting",          tab: "alerting" },
  { id: "tab-reports",         name: "Reports",           tab: "reports" },
  { id: "tab-watchlist",       name: "Watch List",        tab: "watchlist" },
  { id: "tab-threatmap",       name: "Threat Map",        tab: "threatmap" },
];

// ── Overview row-level sections (direct children of #page-overview).
// These are the units that get reordered; each may contain multiple panels.

export const OVERVIEW_ROWS = [
  { id: "ov-banner",     name: "Alert Metrics Banner" },
  { id: "ov-row-gauge",  name: "Risk Analysis Row",        panels: ["ov-gauge", "ov-radar", "ov-timeline"] },
  { id: "ov-row-recent", name: "Activity Overview Row",    panels: ["ov-recent-alerts", "ov-top-users", "ov-endpoints-widget"] },
  { id: "ov-row-dist",   name: "Distribution Row",         panels: ["ov-score-dist", "ov-heatmap"] },
  { id: "ov-ai-analyst", name: "AI Security Analyst",      panels: ["ov-ai-analyst"] },
  { id: "ov-row-sigs",   name: "Analysis & Actions Row",   panels: ["ov-top-sigs", "ov-rec-actions"] },
  { id: "ov-row-mitre",  name: "Coverage & Health Row",    panels: ["ov-mitre", "ov-health"] },
];

// ── Individual overview sub-panels (show/hide within their row group).

export const OVERVIEW_PANELS = [
  { id: "ov-gauge",            name: "Behavioural Risk Meter",         row: "ov-row-gauge" },
  { id: "ov-radar",            name: "Security Activity Pattern",      row: "ov-row-gauge" },
  { id: "ov-timeline",         name: "Alert Timeline",                 row: "ov-row-gauge" },
  { id: "ov-recent-alerts",    name: "Recent Alerts",                  row: "ov-row-recent" },
  { id: "ov-top-users",        name: "Top Risk Users",                 row: "ov-row-recent" },
  { id: "ov-endpoints-widget", name: "Endpoints Overview",             row: "ov-row-recent" },
  { id: "ov-score-dist",       name: "Alert Score Distribution",       row: "ov-row-dist" },
  { id: "ov-heatmap",          name: "Hourly Alert Heatmap",           row: "ov-row-dist" },
  { id: "ov-ai-analyst",       name: "AI Security Analyst",            row: "ov-ai-analyst" },
  { id: "ov-top-sigs",         name: "Top Rule Descriptions",          row: "ov-row-sigs" },
  { id: "ov-rec-actions",      name: "Recommended Security Actions",   row: "ov-row-sigs" },
  { id: "ov-mitre",            name: "MITRE ATT&CK Coverage",          row: "ov-row-mitre" },
  { id: "ov-health",           name: "Engine Health",                  row: "ov-row-mitre" },
  // ov-banner is a row that has no child panels; visibility is at the row level.
];

// ── Other page sub-panels (show/hide only, no reorder).

export const OTHER_PANELS = [
  { id: "fp-patterns", name: "Auto-Suppression Patterns", page: "false-positives" },
  { id: "fp-list",     name: "False Positives List",       page: "false-positives" },
];

export const ALL_PANELS = [
  ...TAB_PANELS,
  ...OVERVIEW_PANELS,
  ...OTHER_PANELS,
];

/** Build the default layout (all panels visible, in shipped order). */
export function getDefaultLayout() {
  return {
    panels:          TAB_PANELS.map((p) => ({ id: p.id, visible: true })),
    overview_rows:   OVERVIEW_ROWS.map((r) => ({ id: r.id, visible: true })),
    overview_panels: OVERVIEW_PANELS.map((p) => ({ id: p.id, visible: true })),
    other:           OTHER_PANELS.map((p) => ({ id: p.id, visible: true })),
  };
}

/**
 * Apply a layout object returned by GET /api/dashboard/layout.
 * Passing null/undefined is a no-op — the shipped default is preserved.
 */
export function applyDashboardLayout(layout) {
  if (!layout) return;
  if (layout.panels)          _applyTabLayout(layout.panels);
  if (layout.overview_rows)   _applyOverviewRows(layout.overview_rows);
  if (layout.overview_panels) _applyOverviewPanels(layout.overview_panels);
  if (layout.other)           _applyOtherPanels(layout.other);
}

// ── Tab / sidebar layout ─────────────────────────────────────────────────────

function _applyTabLayout(panels) {
  const nav = document.querySelector(".side-nav");
  if (!nav) return;

  panels.forEach((entry) => {
    const el = nav.querySelector(`[data-panel-id="${entry.id}"]`);
    if (!el) return;
    el.classList.toggle("panel-hidden", entry.visible === false);
  });

  // Reorder: saved order first, unlisted items trail in their original order.
  const slots  = Array.from(nav.querySelectorAll("[data-panel-id]"));
  const idList = panels.map((p) => p.id);
  [
    ...idList.map((id) => slots.find((s) => s.dataset.panelId === id)).filter(Boolean),
    ...slots.filter((s) => !idList.includes(s.dataset.panelId)),
  ].forEach((el) => nav.appendChild(el));
}

// ── Overview row ordering ─────────────────────────────────────────────────────

function _applyOverviewRows(rows) {
  const page = document.getElementById("page-overview");
  if (!page) return;

  rows.forEach((entry) => {
    const el = page.querySelector(`:scope > [data-panel-id="${entry.id}"]`);
    if (!el) return;
    el.classList.toggle("panel-hidden", entry.visible === false);
  });

  // Reorder direct children by moving them to the end in saved order.
  const children = Array.from(page.querySelectorAll(":scope > [data-panel-id]"));
  const idList   = rows.map((r) => r.id);
  [
    ...idList.map((id) => children.find((c) => c.dataset.panelId === id)).filter(Boolean),
    ...children.filter((c) => !idList.includes(c.dataset.panelId)),
  ].forEach((el) => page.appendChild(el));
}

// ── Individual overview panel visibility ─────────────────────────────────────

function _applyOverviewPanels(panels) {
  panels.forEach((entry) => {
    const el = document.querySelector(`[data-panel-id="${entry.id}"]`);
    if (!el) return;
    el.classList.toggle("panel-hidden", entry.visible === false);
  });
}

// ── Other page sub-panels ────────────────────────────────────────────────────

function _applyOtherPanels(panels) {
  panels.forEach((entry) => {
    const el = document.querySelector(`[data-panel-id="${entry.id}"]`);
    if (!el) return;
    el.classList.toggle("panel-hidden", entry.visible === false);
  });
}
