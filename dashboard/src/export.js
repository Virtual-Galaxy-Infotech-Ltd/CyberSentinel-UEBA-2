// CSV / XML / JSON / PDF / Excel export of the filtered feed.
//
// `exportCsv(rows)` produces a flat, analyst-friendly schema (no nested
// evidence) suitable for opening in Excel/Sheets.
// `exportXml(rows)` uses that same flat schema, for SIEM/GRC tools that ingest
// XML rather than CSV.
// `exportJson(rows)` exports the full feed-item shape including evidence so
// the file can round-trip back into another tool. Because the bulk feed no
// longer carries evidence inline (it's lazy-loaded per row), exportJson
// re-attaches it — from the in-memory cache first, then fetching the rest,
// capped so an enormous filtered set can't fire tens of thousands of requests.

import { fetchEvidence } from "./api.js";
import { evidenceCache } from "./panels/feed.js";
import { showToast } from "./ui/toast.js";

// Above this many alerts we skip the evidence re-attach (the JSON still exports,
// just without nested evidence, flagged via evidence_included:false).
const EVIDENCE_EXPORT_CAP = 5000;

const CSV_COLUMNS = [
  "processed_at", "event_id", "user", "host", "host_ip",
  "verdict", "score", "severity", "campaign_id",
  "signature_id", "signature", "reasons", "mitre_tactic",
  "fp_reason",
  // Appended (not inserted) so existing consumers that read by column position
  // keep working. `score` above is the boosted figure; without these two an
  // exported watch-listed alert would look inexplicably high-scoring.
  "watchlist", "model_score",
];

function _csvEscape(v) {
  if (v === null || v === undefined) return "";
  const s = Array.isArray(v) ? v.join("; ") : String(v);
  // Quote if it contains comma, quote, newline, or leading/trailing whitespace
  if (/[",\n\r]/.test(s) || s !== s.trim()) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function _row(a) {
  return {
    processed_at: a.processed_at || "",
    event_id:     a.event_id     || "",
    user:         a.user         || "",
    host:         a.host         || "",
    host_ip:      a.host_ip      || "",
    verdict:      a.verdict      || "",
    score:        (a.score || 0).toFixed(4),
    severity:     a.severity ?? "",
    campaign_id:  a.campaign_id  || "",
    signature_id: a.signature_id || "",
    signature:    a.signature    || "",
    reasons:      (a.reasons || []).join("; "),
    mitre_tactic: (a.mitre_tactic || []).join("; "),
    fp_reason:    (a.fp && a.fp.reason) || "",
    watchlist:    a.watchlist ? `${a.watchlist.type}:${a.watchlist.value}` : "",
    model_score:  a.model_score != null ? Number(a.model_score).toFixed(4) : "",
  };
}

function _download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    a.remove();
  }, 0);
}

function _timestamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return (
    d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) +
    "-" +
    p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds())
  );
}

export function exportCsv(rows) {
  const head = CSV_COLUMNS.join(",");
  const body = rows
    .map((a) => {
      const r = _row(a);
      return CSV_COLUMNS.map((c) => _csvEscape(r[c])).join(",");
    })
    .join("\n");
  const csv = head + "\n" + body + "\n";
  _download(new Blob([csv], { type: "text/csv;charset=utf-8" }), `ueba-export-${_timestamp()}.csv`);
}

// Resolve evidence for any rows that lack it (cache → fetch), with bounded
// concurrency. Returns a new row array; original rows are left untouched.
async function _withEvidence(rows) {
  const missing = rows.filter((a) => a && a.event_id && a.evidence === undefined && !evidenceCache.has(a.event_id));
  const ids = [...new Set(missing.map((a) => a.event_id))];
  let i = 0;
  const worker = async () => {
    while (i < ids.length) {
      const id = ids[i++];
      try { evidenceCache.set(id, (await fetchEvidence(id)) || {}); }
      catch { evidenceCache.set(id, {}); }
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, ids.length) }, worker));
  return rows.map((a) =>
    a && a.evidence === undefined && a.event_id && evidenceCache.has(a.event_id)
      ? { ...a, evidence: evidenceCache.get(a.event_id) }
      : a
  );
}

const _XML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" };

function _xmlEscape(v) {
  if (v === null || v === undefined) return "";
  const s = Array.isArray(v) ? v.join("; ") : String(v);
  return s
    // XML 1.0 has no representation for most control characters — not even as
    // numeric entities — so they have to be dropped rather than escaped. Alert
    // signatures occasionally carry them through from raw log text, and a
    // single stray 0x01 makes the whole document unparseable.
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "")
    .replace(/[&<>"']/g, (c) => _XML_ESCAPES[c]);
}

// XML export uses the same flat schema as CSV (via _row) rather than the nested
// shape exportJson produces. The consumers that ask for XML are SIEM/GRC import
// tools, which want one predictable record per alert — not lazy-loaded evidence
// blobs of varying shape.
export function exportXml(rows) {
  const body = rows
    .map((a) => {
      const r = _row(a);
      const fields = CSV_COLUMNS
        .map((c) => `    <${c}>${_xmlEscape(r[c])}</${c}>`)
        .join("\n");
      return `  <alert>\n${fields}\n  </alert>`;
    })
    .join("\n");
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    `<ueba_export generated_at="${_xmlEscape(new Date().toISOString())}" ` +
    `count="${rows.length}">\n` +
    (body ? body + "\n" : "") +
    "</ueba_export>\n";
  _download(
    new Blob([xml], { type: "application/xml;charset=utf-8" }),
    `ueba-export-${_timestamp()}.xml`
  );
}

// PDF and Excel are rendered server-side (POST /api/export) rather than in the
// browser. Doing them here would mean bundling jsPDF and SheetJS — several
// hundred KB on every page load — to reproduce rendering the server already
// does for scheduled reports. The column schema above travels with the request,
// so all five formats stay defined in exactly one place.
// Human column headings for the rendered formats. CSV and XML keep the raw
// field names, because those are machine-read and downstream parsers key off
// them; a PDF is read by a person, and "mod el_s core" fragmenting across three
// lines in a narrow column is not a heading.
const EXPORT_LABELS = {
  processed_at: "Time",     event_id:     "Event ID",  user:       "User",
  host:         "Host",     host_ip:      "Host IP",   verdict:    "Verdict",
  score:        "Score",    severity:     "Sev",       campaign_id: "Campaign",
  signature_id: "Rule ID",  signature:    "Signature", reasons:    "Reasons",
  mitre_tactic: "MITRE Tactic", fp_reason: "FP Reason",
  watchlist:    "Watch List",   model_score: "Model Score",
};

async function _serverExport(rows, fmt, label) {
  if (!rows || !rows.length) {
    showToast("Nothing to export — no alerts match the current filters", "info");
    return;
  }
  const body = {
    format: fmt,
    title: "UEBA Alert Export",
    columns: CSV_COLUMNS.map((c) => EXPORT_LABELS[c] || c),
    rows: rows.map((a) => {
      const r = _row(a);
      return CSV_COLUMNS.map((c) => (r[c] === undefined || r[c] === null ? "" : String(r[c])));
    }),
  };
  showToast(`Building ${label} for ${rows.length.toLocaleString()} alerts…`, "info");
  try {
    const res = await fetch("/api/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      // The failure path returns JSON even though success returns a file.
      try { msg = (await res.json()).error || msg; } catch { /* not json */ }
      throw new Error(msg);
    }
    const blob = await res.blob();
    const m = /filename="?([^"]+)"?/.exec(res.headers.get("Content-Disposition") || "");
    _download(blob, m ? m[1] : `ueba-export-${_timestamp()}.${fmt}`);
    showToast(`${label} ready`, "success");
  } catch (e) {
    showToast(`${label} export failed: ${e.message}`, "error");
  }
}

// Above this, a PDF of the raw feed stops being a document and becomes a dump:
// measured against the live feed, 5,000 alerts render to 711 pages and take
// ~30s. Rather than silently truncating — an export that quietly drops rows is
// worse than a slow one — say what it will produce and let the analyst decide.
// Excel has no equivalent problem; 5,000 rows is an ordinary spreadsheet.
const PDF_WARN_ROWS = 1500;
const PDF_ROWS_PER_PAGE = 7;        // measured, not guessed

export function exportPdf(rows) {
  const n = (rows || []).length;
  if (n > PDF_WARN_ROWS) {
    const pages = Math.ceil(n / PDF_ROWS_PER_PAGE);
    const ok = window.confirm(
      `Export ${n.toLocaleString()} alerts to PDF?\n\n` +
      `That is roughly ${pages.toLocaleString()} pages and may take up to a minute ` +
      `to build.\n\nFor a dataset this size Excel or CSV is usually more useful. ` +
      `Narrowing the search, severity or timeline filters first will give a ` +
      `document you can actually read.\n\nPress OK to build the PDF anyway.`
    );
    if (!ok) return Promise.resolve();
  }
  return _serverExport(rows, "pdf", "PDF");
}

export function exportXlsx(rows) { return _serverExport(rows, "xlsx", "Excel file"); }

export async function exportJson(rows) {
  const needFetch = rows.filter((a) => a && a.event_id && a.evidence === undefined && !evidenceCache.has(a.event_id)).length;
  const withEvidence = needFetch <= EVIDENCE_EXPORT_CAP;
  const alerts = withEvidence ? await _withEvidence(rows) : rows;
  const payload = {
    generated_at:      new Date().toISOString(),
    count:             rows.length,
    evidence_included: withEvidence,
    alerts,
  };
  _download(
    new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }),
    `ueba-export-${_timestamp()}.json`
  );
}
