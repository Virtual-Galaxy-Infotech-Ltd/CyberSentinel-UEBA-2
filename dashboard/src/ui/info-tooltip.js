// Info-btn tooltip — fixed positioning anchored to the button's rect.
import { layoutRect, layoutViewport } from "./ui-scale.js";

export function initInfoTooltip() {
  document.addEventListener("mouseover", (e) => {
    const btn = e.target.closest(".info-btn");
    if (!btn) return;
    const tip = btn.querySelector(".info-tooltip");
    if (!tip) return;
    // The tooltip is position:fixed but still inside the zoomed root, so its
    // top/left are LAYOUT px. Measure the button and the viewport in that same
    // space — feeding it a raw client rect drops it ~25% of the way toward the
    // top-left of the window.
    const r  = layoutRect(btn);
    const vw = layoutViewport().width;
    // :hover already applies by the time mouseover fires, so the tooltip is
    // laid out and can report its real width instead of a hardcoded guess.
    const tipW = tip.offsetWidth || 252;
    let left = r.left;
    if (left + tipW > vw - 12) left = vw - tipW - 12;
    if (left < 8) left = 8;
    tip.style.top  = r.bottom + 8 + "px";
    tip.style.left = left + "px";
  });
}
