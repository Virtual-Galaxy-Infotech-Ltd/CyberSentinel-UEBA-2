// Info-btn tooltip — anchored under (or above) the button it belongs to.
//
// The tooltip markup lives inside each .info-btn, but it is never shown there:
// liquid-glass.css puts `backdrop-filter` on .panel, which makes every panel its
// own stacking context, so a tooltip inside one panel is painted UNDER the next
// panel no matter its z-index. Instead, on hover we copy its contents into one
// shared element attached to <body>, which sits above everything.
import { placeFixed, uiScale } from "./ui-scale.js";

let portal = null;
let activeBtn = null;

function getPortal() {
  if (!portal) {
    portal = document.createElement("div");
    portal.className = "info-tooltip info-tip-portal";
    portal.setAttribute("role", "tooltip");
    document.body.appendChild(portal);
  }
  return portal;
}

function hide() {
  activeBtn = null;
  if (portal) portal.classList.remove("show");
}

function show(btn) {
  const src = btn.querySelector(".info-tooltip");
  if (!src) return;
  activeBtn = btn;
  const tip = getPortal();
  tip.innerHTML = src.innerHTML;
  tip.classList.remove("above");
  tip.classList.add("show");

  const s = uiScale() || 1;
  const r = btn.getBoundingClientRect();            // viewport px
  const tipW = tip.offsetWidth * s;
  const tipH = tip.offsetHeight * s;
  const gap = 10;

  let left = r.left + r.width / 2 - 24;             // caret sits ~24px in
  if (left + tipW > window.innerWidth - 12) left = window.innerWidth - tipW - 12;
  if (left < 8) left = 8;

  let top = r.bottom + gap;
  if (top + tipH > window.innerHeight - 8 && r.top - gap - tipH > 8) {
    top = r.top - gap - tipH;
    tip.classList.add("above");
  }

  // Point the caret at the button even when the box was nudged sideways.
  const caret = Math.max(10, Math.min(tipW - 18, r.left + r.width / 2 - left - 4));
  tip.style.setProperty("--caret-left", caret / s + "px");
  placeFixed(tip, left, top);
}

export function initInfoTooltip() {
  document.addEventListener("mouseover", (e) => {
    const btn = e.target.closest(".info-btn");
    if (btn && btn !== activeBtn) show(btn);
  });
  document.addEventListener("mouseout", (e) => {
    if (!activeBtn) return;
    const to = e.relatedTarget;
    if (!to || !activeBtn.contains(to)) hide();
  });
  window.addEventListener("scroll", hide, { passive: true, capture: true });
  window.addEventListener("resize", hide, { passive: true });
}
