// Coordinate-space bridge for `html { zoom: var(--ui-scale) }` (see styles.css).
//
// Zooming the root splits page geometry into two coordinate spaces, and the
// browser does NOT convert between them for you:
//
//   VISUAL — getBoundingClientRect(), MouseEvent.clientX/clientY,
//            window.innerWidth/innerHeight, SVG getScreenCTM().
//            Real on-screen pixels, with the zoom factor already applied.
//
//   LAYOUT — offsetWidth/clientWidth, style.left/top/width, CSS custom
//            properties, canvas drawing units, three.js / globe.gl sizes.
//            Pre-zoom pixels; the browser multiplies these by the zoom on paint.
//
// Reading a pointer (VISUAL) and handing it straight to a LAYOUT consumer
// misplaces it by 1/zoom, and the error grows with distance from the viewport
// origin. That is why a tooltip drifts further off the further down the page it
// opens, and why a hover near the middle of the globe resolves to a country up
// and to the left of the cursor.
//
// Convert at the boundary with the helpers below instead of sprinkling `/ 0.8`
// around: the factor is MEASURED, so it follows --ui-scale automatically and
// collapses to 1 — making every helper here a no-op — on a browser that does
// not fold zoom into client rects.

const PROBE_PX = 1000;   // big enough that sub-pixel rounding is noise

let _scale = 1;
let _probe = null;

function remeasure() {
  try {
    if (!_probe) {
      if (!document.body) return _scale;      // too early; retried on DOM ready
      _probe = document.createElement("div");
      _probe.setAttribute("aria-hidden", "true");
      // visibility:hidden, NOT display:none — a display:none box has no rect.
      _probe.style.cssText =
        "position:absolute;top:0;left:-9999px;height:0;" +
        "visibility:hidden;pointer-events:none;width:" + PROBE_PX + "px;";
      document.body.appendChild(_probe);
    }
    // `width` above is declared in LAYOUT px and read back in VISUAL px, so the
    // ratio *is* the conversion factor, whatever the browser does with `zoom`.
    const w = _probe.getBoundingClientRect().width;
    if (w > 0) _scale = w / PROBE_PX;
  } catch (e) {
    /* keep the last good factor rather than breaking every hover */
  }
  return _scale;
}

/** The measured VISUAL-per-LAYOUT pixel ratio (0.8 at the default --ui-scale). */
export function uiScale() { return _scale; }

/** VISUAL px → LAYOUT px. */
export function toLayout(px) { return px / _scale; }

/** LAYOUT px → VISUAL px. */
export function toVisual(px) { return px * _scale; }

/**
 * An element's box in LAYOUT px — the space style.left/top and offsetWidth use,
 * so this is what to measure with before positioning an absolute/fixed overlay.
 */
export function layoutRect(el) {
  const r = el.getBoundingClientRect();
  const s = _scale;
  return {
    left: r.left / s, top:    r.top    / s,
    right: r.right / s, bottom: r.bottom / s,
    width: r.width / s, height: r.height / s,
  };
}

/** The viewport in LAYOUT px — clamp against this when writing style.left/top. */
export function layoutViewport() {
  return {
    width:  window.innerWidth  / _scale,
    height: window.innerHeight / _scale,
  };
}

/**
 * Pointer position relative to `el`'s top-left corner, in LAYOUT px — the space
 * canvas drawing units and CSS offsets share, so hit-testing lands on the pixel
 * actually under the cursor.
 */
export function localPoint(el, ev) {
  const r = el.getBoundingClientRect();
  return {
    x: (ev.clientX - r.left) / _scale,
    y: (ev.clientY - r.top)  / _scale,
  };
}

/**
 * Place a `position: fixed` overlay so its top-left corner lands on the given
 * VIEWPORT point (the space getBoundingClientRect and MouseEvent.clientX use).
 *
 * Assigning viewport coordinates straight to style.left/top is wrong here for
 * two independent reasons, and this measures its way around both:
 *
 *  1. CONTAINING BLOCK. `position: fixed` resolves against the viewport only
 *     while no ancestor establishes a containing block. Any ancestor with a
 *     transform, filter, backdrop-filter, perspective, contain or will-change
 *     does establish one — and liquid-glass.css puts `backdrop-filter` on
 *     .panel / .stat-card / .stat-banner, so every tooltip inside a panel is
 *     positioned relative to that panel, not the window.
 *  2. SCALE. style.left is in LAYOUT px, which `html { zoom }` then scales.
 *
 * Rather than trying to predict either, we park the element at 0,0, read where
 * that actually put it, and correct by the difference. That is exact whatever
 * the containing block turns out to be, and it self-heals if the glass theme
 * moves `backdrop-filter` to a different element later.
 */
export function placeFixed(el, viewportX, viewportY) {
  el.style.left = "0px";
  el.style.top  = "0px";
  const origin = el.getBoundingClientRect();   // where 0,0 really landed
  const s = _scale || 1;
  el.style.left = ((viewportX - origin.left) / s) + "px";
  el.style.top  = ((viewportY - origin.top)  / s) + "px";
}

remeasure();
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", remeasure, { once: true });
}
// A resize can change devicePixelRatio (window moved between displays) and is
// also when a responsive --ui-scale override would kick in.
window.addEventListener("resize", remeasure, { passive: true });
