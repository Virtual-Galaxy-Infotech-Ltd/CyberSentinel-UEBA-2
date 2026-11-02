// Overview risk gauge — canvas arc + needle.
// updateGauge() computes the score as the average across all agents and
// renders the gauge + risk pill + score-breakdown numbers.
// animateGaugeTo() interpolates the needle.
//
// The per-agent mini gauge in the Endpoints drilldown is a separate canvas
// (#agent-risk-gauge) drawn by drawAgentGauge() in src/panels/agents.js.

import { state } from "../state.js";

export function drawGauge(score) {
  const canvas = document.getElementById("risk-gauge");
  if (!canvas) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const cssW = rect.width  || 260;
  const cssH = rect.height || 150;
  canvas.width  = Math.round(cssW * dpr);
  canvas.height = Math.round(cssH * dpr);
  // NB: do NOT write canvas.style.width/height here — the CSS (width:100%;
  // aspect-ratio) already sizes the element. Writing a fixed px back from a
  // zoom-scaled getBoundingClientRect() creates a feedback loop under CSS
  // `zoom` that shrinks the gauge on every redraw until it vanishes.
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);

  const W = cssW, H = cssH;
  ctx.clearRect(0, 0, W, H);

  // ── GEOMETRY IS DERIVED, NOT HARD-CODED ──────────────────────────────────
  // Every dimension here used to be a fixed pixel value -- band 20, ticks 14
  // and 8, label offset 14, hub 7 -- chosen when this canvas was ~250px wide.
  // The panel was later compacted and the canvas roughly halved, which halved
  // the radius while leaving the band at 20px: a stroke 36% as wide as the
  // circle it sat on, which reads as a fat ring rather than a gauge.
  //
  // The value arc made it worse by using a ROUND line cap. A round cap adds
  // half the band to EACH end of the arc, so at a low score the arc was
  // shorter than its own caps: it drew as a rounded blob, and the start cap
  // pushed it back past the horizontal, below where zero is. That is the
  // green lozenge sticking out of the left of the dial.
  //
  // Everything below is now a fraction of the radius, and the radius is
  // whatever is left after reserving room for the tick labels -- so the gauge
  // keeps its proportions at any canvas size, and nothing can be clipped by
  // the canvas edge the way the "0" and "100" labels were.
  const cx        = W / 2;
  const cy        = H - Math.max(6, H * 0.10);
  const tickFont  = Math.max(8, Math.round(H * 0.115));
  // "100" is the widest label: half of it, plus a gap, has to fit outside the
  // arc on the right. The same reserve above the arc keeps "50" on-canvas.
  const labelPad  = tickFont * 2.7;
  const r         = Math.max(12, Math.min(W / 2 - labelPad, cy - labelPad));
  const band      = Math.max(5, r * 0.22);
  const tickOuter = r + band / 2;
  const labelR    = tickOuter + tickFont * 0.9;

  // Background track: the four risk zones, faint.
  const segments = [
    { from: 0,  to: 25,  color: "#06d6a0" },
    { from: 25, to: 50,  color: "#ffd166" },
    { from: 50, to: 75,  color: "#ff8c42" },
    { from: 75, to: 100, color: "#ff3b5c" },
  ];
  ctx.lineCap = "butt";
  segments.forEach((s) => {
    const a1 = Math.PI + (s.from / 100) * Math.PI;
    const a2 = Math.PI + (s.to   / 100) * Math.PI;
    ctx.beginPath();
    ctx.arc(cx, cy, r, a1, a2);
    ctx.lineWidth = band; ctx.strokeStyle = s.color;
    ctx.globalAlpha = 0.18; ctx.stroke();
  });
  ctx.globalAlpha = 1;

  // Value arc, drawn over the track. Butt cap, so it starts exactly at zero
  // and its length is honestly the score -- no cap overhang either end.
  const sc = Math.min(Math.max(score, 0), 100);
  const fillColor = sc < 25 ? "#06d6a0" : sc < 50 ? "#ffd166" : sc < 75 ? "#ff8c42" : "#ff3b5c";
  if (sc > 0) {
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, Math.PI + (sc / 100) * Math.PI);
    ctx.lineWidth = band; ctx.strokeStyle = fillColor;
    ctx.globalAlpha = 0.95; ctx.lineCap = "butt"; ctx.stroke();
    ctx.globalAlpha = 1;
  }

  // Hairline along the outer edge of the band.
  ctx.beginPath();
  ctx.arc(cx, cy, tickOuter, Math.PI, Math.PI * 2);
  ctx.lineWidth = 1; ctx.strokeStyle = "rgba(255,255,255,0.04)";
  ctx.stroke();

  // Ticks, cut inward from the outer edge so they sit on the band.
  for (let i = 0; i <= 10; i++) {
    const a = Math.PI + (i / 10) * Math.PI;
    const isMajor = i % 2 === 0;
    const iLen = isMajor ? band * 0.72 : band * 0.40;
    ctx.beginPath();
    ctx.moveTo(cx + (tickOuter - iLen) * Math.cos(a), cy + (tickOuter - iLen) * Math.sin(a));
    ctx.lineTo(cx + tickOuter * Math.cos(a),          cy + tickOuter * Math.sin(a));
    ctx.strokeStyle = isMajor ? "rgba(255,255,255,0.18)" : "rgba(255,255,255,0.07)";
    ctx.lineWidth = isMajor ? 1.5 : 0.8; ctx.stroke();
    if (isMajor) {
      ctx.fillStyle = "#3d5a72";
      ctx.font = `600 ${tickFont}px "JetBrains Mono", monospace`;
      ctx.textAlign = "center"; ctx.textBaseline = "middle";
      ctx.fillText(String(i * 10), cx + labelR * Math.cos(a), cy + labelR * Math.sin(a));
    }
  }

  // Needle and hub, both scaled off the radius for the same reason.
  const needleA = Math.PI + (sc / 100) * Math.PI;
  const nLen  = r - band * 0.35;
  const nBase = Math.max(3, r * 0.075);
  const hubR  = Math.max(4, r * 0.13);
  const perpA = needleA + Math.PI / 2;
  ctx.beginPath();
  ctx.moveTo(cx + nLen  * Math.cos(needleA), cy + nLen  * Math.sin(needleA));
  ctx.lineTo(cx + nBase * Math.cos(perpA),   cy + nBase * Math.sin(perpA));
  ctx.lineTo(cx - nBase * Math.cos(perpA),   cy - nBase * Math.sin(perpA));
  ctx.closePath();
  ctx.fillStyle = "#ffffff"; ctx.globalAlpha = 0.9; ctx.fill(); ctx.globalAlpha = 1;

  ctx.beginPath(); ctx.arc(cx, cy, hubR, 0, Math.PI * 2);
  ctx.fillStyle = "#0f1720"; ctx.fill();
  ctx.beginPath(); ctx.arc(cx, cy, hubR * 0.58, 0, Math.PI * 2);
  ctx.fillStyle = fillColor; ctx.fill();
  ctx.beginPath(); ctx.arc(cx, cy, hubR * 0.29, 0, Math.PI * 2);
  ctx.fillStyle = "#fff"; ctx.fill();
}

// Per-agent score uses the SAME formula as drawAgentGauge() in panels/agents.js
// so the Overview gauge (an average across agents) and the per-agent mini gauge
// stay on the same scale.
function _scoreForAgent(a) {
  const total    = a.alert_count || 0;
  const crit     = a.highly_anomalous || 0;
  const anom     = a.anomalous || 0;
  const maxScore = a.max_score || 0;
  const cc = (crit / Math.max(total, 1)) * 60;
  const ac = (anom / Math.max(total, 1)) * 20;
  const mc = maxScore * 15;
  return { score: Math.min(100, cc + ac + mc), cc, ac, mc };
}

export function updateGauge(stats, feedData) {
  let score = 0;
  let critContrib = 0, anomContrib = 0, maxContrib = 0;

  if (state.agentsData && state.agentsData.length) {
    let totalScore = 0, totalCc = 0, totalAc = 0, totalMc = 0;
    state.agentsData.forEach((a) => {
      const r = _scoreForAgent(a);
      totalScore += r.score;
      totalCc    += r.cc;
      totalAc    += r.ac;
      totalMc    += r.mc;
    });
    const n = state.agentsData.length;
    score       = Math.round((totalScore / n) * 10) / 10;
    critContrib = Math.round((totalCc    / n) * 10) / 10;
    anomContrib = Math.round((totalAc    / n) * 10) / 10;
    maxContrib  = Math.round((totalMc    / n) * 10) / 10;
  } else if (feedData && feedData.length) {
    // Fallback when per-agent breakdown isn't loaded yet — use global stats.
    const total   = stats.total_alerts || 0;
    const critPct = total > 0 ? (stats.highly_anomalous || 0) / total : 0;
    const anomPct = total > 0 ? (stats.anomalous       || 0) / total : 0;
    const maxFromFeed = Math.max(...feedData.map((a) => a.score || 0));
    critContrib = critPct * 60;
    anomContrib = anomPct * 20;
    maxContrib  = maxFromFeed * 15;
    score = Math.min(100, critContrib + anomContrib + maxContrib);
    score       = Math.round(score       * 10) / 10;
    critContrib = Math.round(critContrib * 10) / 10;
    anomContrib = Math.round(anomContrib * 10) / 10;
    maxContrib  = Math.round(maxContrib  * 10) / 10;
  }

  animateGaugeTo(score);

  const scoreEl    = document.getElementById("risk-score-val");
  const labelEl    = document.getElementById("risk-label-pill");
  const agentLabel = document.getElementById("risk-gauge-agent-label");
  if (agentLabel) {
    const n = state.agentsData ? state.agentsData.length : 0;
    agentLabel.textContent = n > 0 ? `AVG · ${n} AGENTS` : "GLOBAL";
    agentLabel.style.color = "var(--accent)";
  }
  if (scoreEl) scoreEl.textContent = score.toFixed(1);

  const el = (id, v) => { const e = document.getElementById(id); if (e) e.textContent = v; };
  el("gauge-crit-contrib", critContrib.toFixed(1));
  el("gauge-anom-contrib", anomContrib.toFixed(1));
  el("gauge-max-contrib",  maxContrib.toFixed(1));

  if (labelEl && scoreEl) {
    if (score < 25) {
      scoreEl.style.color = "var(--green)";
      labelEl.className = "risk-pill risk-low";
      labelEl.textContent = "● LOW RISK — Normal behaviour";
    } else if (score < 50) {
      scoreEl.style.color = "var(--yellow)";
      labelEl.className = "risk-pill risk-medium";
      labelEl.textContent = "● MODERATE — Review recommended";
    } else if (score < 75) {
      scoreEl.style.color = "var(--orange)";
      labelEl.className = "risk-pill risk-high";
      labelEl.textContent = "● HIGH — Investigate immediately";
    } else {
      scoreEl.style.color = "var(--red)";
      labelEl.className = "risk-pill risk-critical";
      labelEl.textContent = "● CRITICAL — Incident response!";
    }
  }
  return score;
}

let _gaugeCurrentScore = 0;
let _gaugeAnimFrame = null;
export function animateGaugeTo(targetScore) {
  if (_gaugeAnimFrame) cancelAnimationFrame(_gaugeAnimFrame);
  const start = _gaugeCurrentScore;
  const delta = targetScore - start;
  const duration = 800; // ms
  const startTime = performance.now();
  function step(now) {
    const t = Math.min(1, (now - startTime) / duration);
    const ease = 1 - Math.pow(1 - t, 3); // ease-out cubic
    const current = start + delta * ease;
    _gaugeCurrentScore = current;
    drawGauge(current);
    if (t < 1) _gaugeAnimFrame = requestAnimationFrame(step);
  }
  _gaugeAnimFrame = requestAnimationFrame(step);
}
