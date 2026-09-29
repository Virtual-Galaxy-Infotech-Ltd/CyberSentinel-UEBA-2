// Info-btn tooltip — anchored under the button it belongs to.
//
// The tooltip is `position: fixed`, but it is NOT positioned against the
// viewport: liquid-glass.css puts `backdrop-filter` on .panel / .stat-card /
// .stat-banner, and that makes the panel the containing block for any fixed
// descendant. So the coordinates below are computed in viewport space and
// handed to placeFixed(), which measures where the element actually lands and
// corrects for both the containing block and the `html { zoom }` scale.
import { placeFixed, uiScale } from "./ui-scale.js";

export function initInfoTooltip() {
  document.addEventListener("mouseover", (e) => {
    const btn = e.target.closest(".info-btn");
    if (!btn) return;
    const tip = btn.querySelector(".info-tooltip");
    if (!tip) return;

    const r = btn.getBoundingClientRect();          // viewport px
    // :hover already applies by the time mouseover fires, so the tooltip is laid
    // out and can report a real width. offsetWidth is layout px — scale it up to
    // compare against innerWidth, which is viewport px.
    const tipW = tip.offsetWidth * uiScale() || 252;
    let left = r.left;
    if (left + tipW > window.innerWidth - 12) left = window.innerWidth - tipW - 12;
    if (left < 8) left = 8;
    placeFixed(tip, left, r.bottom + 8);
  });
}
