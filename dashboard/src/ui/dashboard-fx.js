// Dashboard FX — small cosmetic polish, all additive & self-contained:
//   1. Count-up animation on the KPI banner numbers (roll up on load/change).
//   2. Severity accent bars on Alert-Feed rows (tags each row from its badge).
//   3. Sliding underline that glides between the active nav tabs.
// Purely cosmetic — remove the import in main.js to revert.

/* ── 1. KPI count-up ──────────────────────────────────────────────────────── */
const KPI_IDS = [
  "s-highly", "s-anomalous", "s-suspicious", "s-total",
  "dm-campaigns", "dm-users-count", "dm-critical-pct", "s-users",
];
const DUR = 900;

function parseNum(txt) {
  const m = String(txt).replace(/,/g, "").match(/^(\D*)(-?\d+(?:\.\d+)?)(.*)$/);
  if (!m) return null;
  const dec = m[2].includes(".") ? m[2].split(".")[1].length : 0;
  return { prefix: m[1] || "", num: parseFloat(m[2]), suffix: m[3] || "", dec };
}
function fmtNum(n, dec, prefix, suffix) {
  const parts = n.toFixed(dec).split(".");
  parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return prefix + parts.join(".") + suffix;
}
function settle(el, toText, num) {
  // Land on the app's own string immediately, with no animation left in flight.
  el.textContent = toText;
  el.__lastNum   = num;
  el.__toText    = toText;
  el.__animating = false;
}
function animateEl(el, toText) {
  const t = parseNum(toText);
  if (!t) { settle(el, toText, null); return; }
  // No previous number (tiles start as an em-dash placeholder). Rolling 0 -> N
  // from here is what made a stalled animation read as a hard "0", so land on
  // the real value the first time we see one.
  if (el.__lastNum == null) { settle(el, toText, t.num); return; }
  const from = el.__lastNum;
  if (from === t.num) { settle(el, toText, t.num); return; }
  // requestAnimationFrame does not run in a hidden tab: an animation started
  // here would stall mid-roll and strand __animating = true, after which the
  // observer ignores every future update and the tile is frozen for good.
  if (document.hidden) { settle(el, toText, t.num); return; }
  el.__animating = true;
  el.__toText = toText;
  const start = performance.now();
  el.__animStart = start;
  function step(now) {
    const p = Math.min((now - start) / DUR, 1);
    const eased = 1 - Math.pow(1 - p, 3); // easeOutCubic
    if (p < 1) {
      el.textContent = fmtNum(from + (t.num - from) * eased, t.dec, t.prefix, t.suffix);
      requestAnimationFrame(step);
    } else {
      settle(el, toText, t.num);          // land exactly on the app's own string
    }
  }
  requestAnimationFrame(step);
}
function initCountUp() {
  KPI_IDS.forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    const seed = parseNum(el.textContent.trim());
    el.__lastNum = seed ? seed.num : null;
    const ob = new MutationObserver(() => {
      const txt = el.textContent.trim();
      if (el.__animating) {
        // Watchdog. A rolling animation deliberately ignores incoming updates so
        // it can land on its own target — but if rAF stalled (hidden tab, or the
        // main thread blocked parsing a large payload) that flag would stay set
        // and this tile would silently swallow every later value, which is how
        // the KPI tiles ended up stuck near zero. Overran its budget? Take over.
        if (performance.now() - (el.__animStart || 0) < DUR * 3) return;
        el.__animating = false;
      }
      if (txt === el.__toText) return;
      animateEl(el, txt);
    });
    ob.observe(el, { childList: true, characterData: true, subtree: true });
  });
}

/* ── 2. Severity accent bars on feed rows ─────────────────────────────────── */
const SEV = {
  "v-highly_anomalous": "sev-critical",
  "v-anomalous": "sev-anom",
  "v-suspicious": "sev-susp",
};
function tagRows() {
  document.querySelectorAll("tr.feed-row:not([data-sev])").forEach((tr) => {
    const badge = tr.querySelector(".verdict-badge");
    let sev = "none";
    if (badge) badge.classList.forEach((c) => { if (SEV[c]) sev = SEV[c]; });
    tr.setAttribute("data-sev", sev);
  });
}
function initSeverityRows() {
  let pending = false;
  const obs = new MutationObserver(() => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => { pending = false; tagRows(); });
  });
  obs.observe(document.querySelector("main") || document.body, { childList: true, subtree: true });
  tagRows();
}

/* ── 3. Sliding nav underline ─────────────────────────────────────────────── */
function initNavUnderline() {
  const nav = document.querySelector("nav");
  if (!nav) return;
  const ind = document.createElement("div");
  ind.className = "tab-underline";
  ind.setAttribute("aria-hidden", "true");
  nav.appendChild(ind);
  const move = () => {
    const active = nav.querySelector(".tab.active");
    if (!active) { ind.style.opacity = "0"; return; }
    ind.style.opacity = "1";
    ind.style.transform = `translateX(${active.offsetLeft}px)`;
    ind.style.width = active.offsetWidth + "px";
  };
  nav.querySelectorAll(".tab").forEach((t) =>
    new MutationObserver(move).observe(t, { attributes: true, attributeFilter: ["class"] })
  );
  window.addEventListener("resize", move);
  requestAnimationFrame(move); // after first layout
}

/* ── 4. Live browser-tab badge — critical count in the <title> ────────────── */
function initTitleBadge() {
  const base = "CyberSentinel UEBA";
  const el = document.getElementById("s-highly"); // HIGHLY ANOMALOUS / critical count
  if (!el) return;
  const update = () => {
    const n = parseInt(String(el.textContent).replace(/,/g, ""), 10);
    document.title = n > 0 ? `⚠ ${n.toLocaleString()} · ${base}` : base;
  };
  new MutationObserver(update).observe(el, { childList: true, characterData: true, subtree: true });
  update();
}

function init() {
  // initCountUp() is DELIBERATELY NOT CALLED.
  //
  // index.html ships its own KPI count-up animator (parse/run/commit/scan). That
  // one is the keeper: it handles negatives and prefers-reduced-motion, and its
  // commit() disconnects its observer around each write so it can't re-trigger
  // itself. What it cannot guard against is a SECOND observer on the same nodes.
  //
  // Running both meant each animator saw the other's intermediate frames and
  // restarted from them — an unbounded requestAnimationFrame loop that pegged the
  // main thread (the dashboard "loading very late") and left the tiles parked on
  // whatever frame the fight stalled at: 0, or even "-60,919" total alerts.
  //
  // Keep exactly one animator on .banner-stat-value. If you ever want this one
  // instead, delete the inline animator in index.html in the same commit.
  initSeverityRows();
  initNavUnderline();
  initTitleBadge();
}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
