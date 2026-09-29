#!/usr/bin/env python3
"""Generate the CyberSentinel UEBA Technical & Architecture Document (.docx).

Every figure in this document is taken from the running deployment, not
estimated. Where a capability is absent it is stated as absent — a technical
document that overstates coverage is worse than one that is merely thin.
"""
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

NAVY   = RGBColor(0x0B, 0x22, 0x40)
ACCENT = RGBColor(0x0B, 0x6F, 0xA4)
INK    = RGBColor(0x1A, 0x1A, 0x1A)
MUTED  = RGBColor(0x5B, 0x6B, 0x7A)

DOC_VERSION = "1.0"
DOC_DATE    = "23 September 2026"

d = Document()

# ── base styles ─────────────────────────────────────────────────────────────
st = d.styles["Normal"]
st.font.name = "Arial"
st.font.size = Pt(10.5)
st.paragraph_format.space_after = Pt(6)
st.paragraph_format.line_spacing = 1.15

for name, size, color, before in (("Heading 1", 17, NAVY, 20),
                                  ("Heading 2", 13.5, ACCENT, 14),
                                  ("Heading 3", 11.5, NAVY, 10)):
    s = d.styles[name]
    s.font.name = "Arial"
    s.font.size = Pt(size)
    s.font.color.rgb = color
    s.font.bold = True
    s.paragraph_format.space_before = Pt(before)
    s.paragraph_format.space_after = Pt(5)
    # A heading stranded at the foot of a page with its content overleaf is the
    # classic tell of a generated document.
    s.paragraph_format.keep_with_next = True
    s.paragraph_format.keep_together = True

# Widow/orphan control on body text, for the same reason.
st.paragraph_format.widow_control = True

sec = d.sections[0]
sec.left_margin = sec.right_margin = Inches(0.9)
sec.top_margin = Inches(0.8)
sec.bottom_margin = Inches(0.8)
# The title page carries the document identity already; a running head there
# would be redundant.
sec.different_first_page_header_footer = True


def para(text="", size=10.5, bold=False, italic=False, color=INK,
         align=None, space_after=6, style=None):
    p = d.add_paragraph(style=style)
    r = p.add_run(text)
    r.font.size = Pt(size)
    r.bold = bold
    r.italic = italic
    r.font.color.rgb = color
    if align is not None:
        p.alignment = align
    p.paragraph_format.space_after = Pt(space_after)
    return p


def bullets(items, style="List Bullet"):
    for it in items:
        p = d.add_paragraph(style=style)
        if isinstance(it, tuple):
            r = p.add_run(it[0] + " ")
            r.bold = True
            r.font.size = Pt(10.5)
            r2 = p.add_run(it[1])
            r2.font.size = Pt(10.5)
        else:
            r = p.add_run(it)
            r.font.size = Pt(10.5)
        p.paragraph_format.space_after = Pt(3)


def shade(cell, hexcolor):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:fill"), hexcolor)
    tcPr.append(shd)


def repeat_header(row):
    """Mark a row as a table header so Word repeats it on every page the table
    spans. Several tables here run past a page boundary, and a continuation
    with no column headings is unreadable."""
    trPr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:tblHeader")
    el.set(qn("w:val"), "true")
    trPr.append(el)


def table(headers, rows, widths=None, font=9.5):
    t = d.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    # Word ignores explicit column widths while autofit is on, which is why an
    # earlier draft's `widths` argument had no visible effect.
    t.autofit = False
    hdr = t.rows[0].cells
    for i, h in enumerate(headers):
        hdr[i].text = ""
        p = hdr[i].paragraphs[0]
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run(h)
        r.bold = True
        r.font.size = Pt(font)
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        shade(hdr[i], "0B6FA4")
    repeat_header(t.rows[0])
    for n, row in enumerate(rows):
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = ""
            p = cells[i].paragraphs[0]
            r = p.add_run("" if v is None else str(v))
            r.font.size = Pt(font)
            p.paragraph_format.space_after = Pt(2)
        if n % 2 == 1:
            for c in cells:
                shade(c, "F2F6F9")      # banding, for legibility across wide rows
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Inches(w)
    d.add_paragraph().paragraph_format.space_after = Pt(4)
    return t


def caption(text):
    para(text, size=9, italic=True, color=MUTED, space_after=12)


def page_break():
    d.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def add_running_heads(section):
    """Header and footer on every page. Word field codes are used for the page
    number because python-docx has no first-class API for one."""
    hp = section.header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    hr = hp.add_run("CyberSentinel UEBA  ·  Technical & Architecture Document")
    hr.font.size = Pt(8)
    hr.font.color.rgb = MUTED
    hp.paragraph_format.space_after = Pt(2)
    # A hairline under the running head, drawn as a bottom border on the
    # paragraph rather than as a shape.
    pPr = hp._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "4")
    bottom.set(qn("w:color"), "D7DEE5")
    borders.append(bottom)
    pPr.append(borders)

    p = section.footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("Confidential  ·  Page ")
    r.font.size = Pt(8)
    r.font.color.rgb = MUTED
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), "PAGE")
    p._p.append(fld)


def set_properties(doc):
    """File metadata, so the document identifies itself in a document library
    rather than showing up as an untitled Word file."""
    cp = doc.core_properties
    cp.title = "CyberSentinel UEBA — Technical & Architecture Document"
    cp.subject = ("System design, detection methodology, technology stack and "
                  "operations")
    cp.category = "Technical reference"
    cp.comments = ("Figures measured against the running deployment on "
                   + DOC_DATE + ".")
    cp.keywords = "UEBA; behavioural analytics; CyberSentinel; architecture"


# ════════════════════════════════════════════════════════════════════════════
# TITLE PAGE
# ════════════════════════════════════════════════════════════════════════════
for _ in range(5):
    d.add_paragraph()
para("CyberSentinel", size=30, bold=True, color=NAVY, align=WD_ALIGN_PARAGRAPH.CENTER,
     space_after=0)
para("User and Entity Behaviour Analytics", size=20, bold=True, color=ACCENT,
     align=WD_ALIGN_PARAGRAPH.CENTER, space_after=22)
para("Technical & Architecture Document", size=14, color=INK,
     align=WD_ALIGN_PARAGRAPH.CENTER, space_after=4)
para("System design, detection methodology, technology stack and operations",
     size=10.5, italic=True, color=MUTED, align=WD_ALIGN_PARAGRAPH.CENTER,
     space_after=40)
table(["Field", "Value"], [
    ["Document version", DOC_VERSION],
    ["Date", DOC_DATE],
    ["Classification", "Confidential — for the named recipient"],
    ["Product", "CyberSentinel UEBA"],
    ["Document type", "Technical and architecture reference"],
    ["Basis", "Measured against the running deployment; no estimated figures"],
], widths=[2.0, 4.6])
page_break()

# ════════════════════════════════════════════════════════════════════════════
# CONTENTS
# Written out rather than inserted as a Word TOC field: a field arrives empty
# until the reader updates it, which looks like a defect in a document that is
# being handed to a client.
# ════════════════════════════════════════════════════════════════════════════
d.add_heading("Contents", level=1)
table(["Section", "Subject"], [
    ["1.  Executive Summary", "What the platform is and the principle it rests on"],
    ["2.  System Overview", "Processing chain and runtime services"],
    ["3.  Detection Methodology", "The four analytical layers and score fusion"],
    ["4.  Feature Engineering", "Feature vector, entity resolution, noise suppression"],
    ["5.  Analyst Capabilities", "Console, suppression, watch lists, reporting"],
    ["6.  Model Lifecycle", "Why models are not pre-shipped; retraining cycle"],
    ["7.  Security and Governance", "Authentication, audit trail, data sovereignty"],
    ["8.  Technology Stack", "Platform, machine learning, application and console"],
    ["9.  Deployment and Operations", "Specification, storage, observed scale"],
    ["10. Current Capability Statement", "Implemented, pending activation, and absent"],
    ["Appendix A", "Component reference"],
    ["Appendix B", "Principal configuration parameters"],
], widths=[2.5, 4.1])
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("1. Executive Summary", level=1)
para(
    "CyberSentinel UEBA is a behavioural analytics platform that detects insider "
    "threat, account compromise and anomalous entity activity by learning what "
    "normal looks like in a specific estate and reporting deviation from it. It "
    "consumes security events from an existing SIEM, scores every event through "
    "an unsupervised machine-learning pipeline, correlates related anomalies into "
    "campaigns, and presents the result to analysts through a web console with "
    "investigation, suppression and reporting workflows."
)
para(
    "The central design decision is that models are never shipped with the "
    "product. Each behavioural baseline is fitted to one estate's own population "
    "and its own score distribution, because \"normal\" at one organisation is not "
    "normal at another. A new installation therefore trains on the client's own "
    "traffic before it produces meaningful alerts. This is a deliberate accuracy "
    "trade-off, and it is described in full in Section 6."
)
d.add_heading("Key characteristics", level=2)
bullets([
    ("Fully unsupervised.", "No labelled incident data is required to begin. "
     "Detection is based on deviation from a learned baseline, not on signatures "
     "or pre-trained threat models."),
    ("Entity-level baselines.", "A separate behavioural model is maintained per "
     "entity, so an action that is routine for one account and unprecedented for "
     "another is scored accordingly."),
    ("On-premise by design.", "The platform operates entirely within the client "
     "perimeter. No event data, and no derived content, is transmitted to any "
     "external service in the deployed configuration."),
    ("SIEM-complementary.", "The platform consumes normalised events from the "
     "existing SIEM rather than replacing it, and returns enriched alerts that "
     "can be consumed downstream."),
])
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("2. System Overview", level=1)
para(
    "The platform is organised as four cooperating services and a shared data "
    "layer. Each service has a single responsibility and communicates through "
    "append-only files on disk rather than a message broker, which keeps the "
    "deployment footprint small and makes every stage independently restartable "
    "and independently auditable."
)

d.add_heading("2.1 Processing chain", level=2)
table(["#", "Stage", "Responsibility", "Component"], [
    ["1", "Collection", "Security events are produced by endpoint and network "
     "agents and normalised by the SIEM.", "CyberSentinel SIEM"],
    ["2", "Enrichment", "Events are decorated with threat intelligence, "
     "classification, risk scoring and fingerprinting.", "enrich_parallel.py"],
    ["3", "Transport", "Enriched events are synchronised from the SIEM host to "
     "the analytics host over an authenticated tunnel.", "ueba_sync_bridge.sh"],
    ["4", "Feature extraction", "Each event is projected into a 35-dimension "
     "numeric feature vector and an entity is resolved.", "ueba_preprocessor.py"],
    ["5", "Detection", "Four analytical layers score the event and correlate it "
     "with recent anomalies.", "ueba_engine.py"],
    ["6", "Presentation", "Alerts, investigation context, suppression, watch "
     "lists and reporting are served to analysts.", "ueba_dashboard_server.py"],
], widths=[0.35, 1.25, 3.4, 1.6])
caption("Table 2.1 — Processing chain. Stages 1–3 run on the SIEM side; stages 4–6 "
        "run on the analytics host.")

d.add_heading("2.2 Runtime services", level=2)
table(["Service", "Function", "Restart behaviour"], [
    ["ueba-engine", "Streaming detection. Tails the enriched event feed, scores "
     "events and emits alerts.", "Resumes from a persisted byte offset; no events "
     "are re-scored or skipped."],
    ["ueba-dashboard", "Web console, REST API, reporting engine and scheduler.",
     "Stateless with respect to detection; safe to restart at any time."],
    ["ueba-bridge", "Event transport from the SIEM host.", "Resumes from a "
     "persisted position marker."],
    ["sshd-tunnel", "Dedicated authenticated tunnel for the transport path.",
     "Managed independently of the system SSH daemon."],
], widths=[1.35, 3.3, 1.95])
caption("Table 2.2 — All four services are managed by systemd and start on boot.")
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("3. Detection Methodology", level=1)
para(
    "Detection is performed by four analytical layers. The first two produce "
    "independent anomaly scores that are fused into a single verdict; the third "
    "and fourth add correlation and investigative context rather than score."
)

d.add_heading("3.1 Layer 1 — Isolation Forest (global outlier detection)", level=2)
para(
    "An Isolation Forest is trained across the whole estate and scores every event "
    "for global rarity: how unusual this event is relative to all observed "
    "activity, irrespective of who performed it. Isolation Forests isolate "
    "anomalies in fewer partitions than normal points, which makes them effective "
    "on high-volume, unlabelled data and inexpensive at inference time."
)
table(["Parameter", "Value", "Rationale"], [
    ["Estimators", "200", "Stable scoring without disproportionate inference cost."],
    ["Contamination", "0.005", "Expected outlier fraction; deliberately "
     "conservative to limit baseline alert volume."],
    ["Training sample", "500,000 events", "Representative sample of the estate; "
     "bounds training time and memory."],
    ["Inference batching", "128 events", "Scoring is dominated by a large fixed "
     "per-call cost, so the batch amortises it across many events."],
], widths=[1.35, 1.35, 3.9])

d.add_heading("3.2 Layer 2 — Per-entity autoencoders (behavioural baseline)", level=2)
para(
    "Each sufficiently active entity receives its own autoencoder: a neural "
    "network trained to reconstruct that entity's own behaviour. When an event "
    "reconstructs poorly, it is behaviour the entity has not exhibited before. "
    "This is the layer that distinguishes UEBA from generic outlier detection, "
    "because it judges an action against the actor rather than against the "
    "population."
)
table(["Property", "Value"], [
    ["Architecture", "35 → 24 → 12 → 24 → 35 (symmetric undercomplete autoencoder)"],
    ["Activation / regularisation", "ReLU, dropout 0.1"],
    ["Anomaly threshold", "95th percentile of the entity's own reconstruction error"],
    ["Eligibility for a private model", "Entities with at least the configured "
     "minimum event count (currently 2,000)"],
    ["Fallback", "A global autoencoder scores entities below that threshold, so "
     "sparse entities are still covered"],
    ["Models in the reference deployment", "556 per-entity models plus one global model"],
], widths=[2.3, 4.3])
para(
    "Training runs on GPU where available and inference runs on CPU. This split is "
    "deliberate: the models are small, and GPU inference for a ~2,000-parameter "
    "network is dominated by transfer overhead rather than computation.",
    size=10
)

d.add_heading("3.3 Layer 3 — HDBSCAN campaign correlation", level=2)
para(
    "Anomalies rarely occur in isolation. Recent anomalous events are clustered "
    "in feature space by HDBSCAN, which groups related activity into campaigns "
    "without being told how many clusters to expect and marks genuinely isolated "
    "events as noise rather than forcing them into a group. An analyst can "
    "therefore triage one campaign instead of forty separate alerts."
)
table(["Parameter", "Value"], [
    ["Minimum cluster size", "5 events"],
    ["Minimum samples", "3"],
    ["Distance metric", "Euclidean"],
    ["Clustering interval", "900 seconds"],
    ["Rolling anomaly buffer", "1,000 events"],
    ["Minimum cluster persistence", "0.3"],
], widths=[2.6, 4.0])

d.add_heading("3.4 Layer 4 — Vector similarity retrieval", level=2)
para(
    "Every scored anomaly is indexed in a FAISS vector store. When a new anomaly "
    "is raised, the most similar historical anomalies are retrieved and attached "
    "to it, so an analyst can immediately see whether the activity resembles "
    "something previously investigated and how it was resolved. In the reference "
    "deployment the index holds approximately 5.6 million vectors."
)
table(["Parameter", "Value"], [
    ["Neighbours retrieved", "5"],
    ["Minimum similarity", "0.6"],
    ["Index capacity", "7,000,000 vectors"],
    ["Inference device", "CPU"],
], widths=[2.6, 4.0])

d.add_heading("3.5 Score fusion and verdicts", level=2)
para(
    "The Isolation Forest and autoencoder scores are combined into a single "
    "0–1 score, which is then banded into a verdict. Both layers carry equal "
    "weight: global rarity and personal deviation are treated as equally "
    "meaningful signals."
)
table(["Band", "Score range", "Verdict", "Confidence"], [
    ["Below threshold", "< 0.75", "Not alerted — discarded", "—"],
    ["1", "0.75 – 0.85", "Suspicious", "Low"],
    ["2", "0.85 – 0.93", "Anomalous", "Medium"],
    ["3", "0.93 – 1.00", "Highly anomalous", "High"],
], widths=[1.2, 1.4, 2.2, 1.8])
caption("Table 3.5 — Alert threshold and verdict bands. All values are configurable "
        "per deployment.")
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("4. Feature Engineering", level=1)
para(
    "Every event is reduced to a 35-dimension numeric feature vector before it "
    "reaches any model. The feature set spans temporal behaviour, identity and "
    "access, network characteristics, rule and severity context, and enrichment "
    "signals such as threat-intelligence matches and geographic origin."
)
d.add_heading("4.1 Entity resolution", level=2)
para(
    "Feature extraction resolves each event to a single canonical entity. Where a "
    "username is present it is normalised through an identity-resolution map so "
    "that aliases for the same human converge on one baseline. Where no user can "
    "be attributed — firewall and network telemetry, for example — the event is "
    "keyed to the host or source address instead of being discarded or collapsed "
    "into a single unattributed bucket, which would poison that bucket's baseline."
)
d.add_heading("4.2 Noise suppression", level=2)
para(
    "Before scoring, configurable suppression removes classes of event that are "
    "known to be operationally uninteresting in a given estate: specific rule "
    "identifiers, zero-risk internal network chatter, IPv6 multicast, nominated "
    "source addresses, and hostnames that would otherwise be mistaken for user "
    "accounts. Suppression is applied at ingestion so that noise never enters a "
    "behavioural baseline in the first place."
)
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("5. Analyst Capabilities", level=1)

d.add_heading("5.1 Investigation console", level=2)
bullets([
    ("Alert feed.", "Filterable by free text, MITRE ATT&CK tactic, severity "
     "threshold, verdict and timeline window, with per-alert evidence loaded on "
     "demand."),
    ("Evidence panel.", "Per-alert reconstruction of why the alert fired: model "
     "scores against thresholds, contributing anomaly reasons, the entity's "
     "baseline for comparison, and similar historical events."),
    ("Entity and endpoint views.", "Risk-ranked entities and monitored endpoints, "
     "each drillable to the underlying activity."),
    ("Campaign view.", "Correlated clusters of related anomalies, triageable as a "
     "single unit."),
    ("Incident rollups.", "Time-bounded groupings for shift-level review."),
    ("Live threat map.", "Geolocated external-to-datacentre traffic derived from "
     "firewall telemetry, resolved against a local offline geolocation database."),
])

d.add_heading("5.2 False-positive control", level=2)
para(
    "Analysts can mark an individual alert as a false positive, or create a "
    "suppression pattern that automatically filters future alerts matching the "
    "same fingerprint. Suppression applies only to alerts received after the "
    "pattern was created; historical alerts remain visible so that the record is "
    "not rewritten retrospectively. The engine reloads patterns on change, so a "
    "suppression takes effect on the next event without a restart."
)

d.add_heading("5.3 Watch lists", level=2)
para(
    "Named users, hosts or addresses can be placed under elevated scrutiny. A "
    "watched entity receives a small additive boost to its anomaly score, applied "
    "before the alert threshold is evaluated, so that borderline activity surfaces "
    "and genuinely anomalous activity escalates a band. The boost is deliberately "
    "small: a value large enough to alert on everything an entity does would be "
    "muted by analysts within a day. Alerts raised with a watch-list contribution "
    "record both the final score and the unboosted model score, so the "
    "contribution is always visible and auditable."
)

d.add_heading("5.4 Reporting", level=2)
para(
    "The platform includes four out-of-the-box reports — analyst investigation, "
    "administration and management, audit and compliance, and a threat report for "
    "a specified period — together with a custom report builder, periodic "
    "scheduling and optional email delivery."
)
table(["Capability", "Detail"], [
    ["Output formats", "PDF, Excel (XLSX), CSV, HTML, JSON, XML"],
    ["Custom reports", "Composed from the same catalogue of 20 sections the "
     "built-in reports use"],
    ["Scheduling", "Hourly, daily, weekly or monthly, at a nominated local time"],
    ["Delivery", "Download from the console, or email with the report attached"],
    ["Retention", "Generated reports are indexed, re-downloadable and "
     "convertible to other formats without re-running the report"],
], widths=[1.8, 4.8])
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("6. Model Lifecycle", level=1)
d.add_heading("6.1 Why models are not pre-shipped", level=2)
para(
    "Each per-entity autoencoder is keyed to a specific account, and the scaler, "
    "thresholds and Isolation Forest are all fitted to one estate's score "
    "distribution. A model trained on one organisation's population encodes that "
    "organisation's working patterns and is actively misleading elsewhere. A new "
    "installation therefore begins with no models and requires a period of "
    "observation before it produces meaningful alerts. The engine will not start "
    "without trained models, by design, rather than emitting scores it cannot "
    "justify."
)
d.add_heading("6.2 Continuous retraining", level=2)
table(["Stage", "Action"], [
    ["Corpus maintenance", "The training corpus is pruned to a rolling retention "
     "window before each cycle, so behaviour from the distant past does not "
     "anchor the current baseline."],
    ["Feature preparation", "Events are projected to feature vectors and stored "
     "in a columnar dataset for efficient batch training."],
    ["Global model", "The Isolation Forest and scaler are refitted on a "
     "representative sample of the estate."],
    ["Entity models", "Per-entity autoencoders are retrained for entities meeting "
     "the minimum activity threshold; the global fallback is refitted."],
    ["Threshold calibration", "Per-entity anomaly thresholds are recalculated at "
     "the configured percentile of each entity's own reconstruction error."],
    ["Validation", "Refitted models are validated before they are promoted."],
], widths=[1.6, 5.0])
caption("Table 6.2 — Retraining runs on a scheduled cycle and is idempotent; a "
        "failed cycle leaves the previous models in service.")
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("7. Security, Access Control and Governance", level=1)

d.add_heading("7.1 Authentication", level=2)
para(
    "The console supports single sign-on through signed JSON Web Tokens issued by "
    "the client's identity provider or SIEM. Token signature, audience, issuer and "
    "expiry are verified on every exchange, and a short-lived session cookie is "
    "issued on success. Three roles are defined — viewer, analyst and "
    "administrator — with role claims carried in the assertion."
)
d.add_heading("7.2 Audit trail", level=2)
para(
    "Every state-changing action taken inside the platform is recorded to an "
    "append-only audit log: the actor, the action, the target, the source address, "
    "the outcome and the timestamp. Rejected attempts are recorded alongside "
    "successful ones, because a refused action is frequently the more interesting "
    "record. Request bodies are deliberately not captured wholesale — only an "
    "explicit allow-list of non-sensitive fields — so that the audit trail cannot "
    "accumulate credentials. The log self-rotates and is exposed to the audit and "
    "compliance report."
)
d.add_heading("7.3 Data sovereignty", level=2)
para(
    "In the deployed configuration the platform makes no outbound connection to "
    "any third-party service. Geolocation is resolved against a local offline "
    "database. The optional AI-assisted analysis feature, which would require an "
    "external model provider, is disabled by default and must not be enabled on a "
    "client installation without written approval, as it would constitute egress "
    "of event-derived content beyond the client perimeter."
)
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("8. Technology Stack", level=1)
para("All versions below are those in service in the reference deployment.", size=10,
     italic=True, color=MUTED)

d.add_heading("8.1 Platform", level=2)
table(["Layer", "Technology", "Version"], [
    ["Operating system", "Ubuntu LTS", "24.04.4 (kernel 6.8)"],
    ["Runtime", "Python", "3.12.3"],
    ["Frontend build", "Node.js / Vite", "22.22.1"],
    ["Process supervision", "systemd", "—"],
], widths=[1.8, 2.8, 2.0])

d.add_heading("8.2 Machine learning and numerical", level=2)
table(["Component", "Library", "Version", "Role"], [
    ["Outlier detection", "scikit-learn", "1.8.0", "Isolation Forest, scaling"],
    ["Behavioural models", "PyTorch", "2.10.0 (CUDA 12.8)", "Per-entity autoencoders"],
    ["Clustering", "HDBSCAN", "—", "Campaign correlation"],
    ["Vector search", "FAISS", "1.14.1", "Similar-anomaly retrieval"],
    ["Numerics", "NumPy", "2.4.2", "Feature vectors and batch operations"],
    ["Model persistence", "joblib", "1.5.3", "Serialised estimators"],
    ["Training datasets", "h5py", "3.15.1", "Columnar feature storage"],
], widths=[1.5, 1.4, 1.5, 2.2])

d.add_heading("8.3 Application and services", level=2)
table(["Component", "Library", "Version", "Role"], [
    ["Web framework", "Flask", "3.1.3", "REST API and console delivery"],
    ["Cross-origin policy", "Flask-CORS", "6.0.2", "Controlled browser access"],
    ["Authentication", "PyJWT", "2.13.0", "SSO assertion verification"],
    ["Serialisation", "orjson", "3.11.9", "High-throughput JSON"],
    ["Configuration", "PyYAML", "6.0.3", "Single-file configuration"],
    ["Geolocation", "geoip2", "5.2.0", "Offline IP geolocation"],
    ["PDF generation", "ReportLab", "5.0.1", "Reports and exports"],
    ["Spreadsheets", "openpyxl", "3.1.5", "Excel reports and exports"],
], widths=[1.5, 1.3, 1.2, 2.6])

d.add_heading("8.4 Console", level=2)
table(["Component", "Technology", "Role"], [
    ["Application", "Vanilla ES modules, built with Vite",
     "No frontend framework dependency; small, auditable bundle"],
    ["3D visualisation", "globe.gl / three.js", "Live threat map"],
    ["Charts", "Hand-written canvas and SVG",
     "Gauges, heatmaps, radar, score distribution, timelines — no charting library"],
    ["Transport", "REST with server-sent events", "Live alert streaming"],
], widths=[1.4, 2.2, 3.0])
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("9. Deployment and Operations", level=1)

d.add_heading("9.1 Reference deployment specification", level=2)
table(["Resource", "Reference deployment", "Notes"], [
    ["CPU", "60 cores", "Detection is CPU-bound at inference."],
    ["Memory", "201 GB", "Dominated by the in-memory vector index."],
    ["GPU", "NVIDIA L40S (46 GB)", "Used for model training only; optional."],
    ["Storage", "Multi-terabyte, separate data volume",
     "Event history and vector index grow with retention."],
], widths=[1.3, 2.2, 3.1])
para(
    "The GPU accelerates retraining but is not required for detection: inference "
    "runs on CPU by design. A CPU-only deployment is supported, with retraining "
    "taking correspondingly longer.", size=10)

d.add_heading("9.2 Storage profile", level=2)
table(["Store", "Reference size", "Content"], [
    ["Enriched event feed", "8.4 GB", "Live ingestion feed from the SIEM"],
    ["Vector index", "4.3 GB", "FAISS index and metadata for retrieval"],
    ["Alert archive", "2.0 GB", "Rotated and compressed daily alert history"],
    ["Entity profiles", "42 MB", "Per-entity behavioural profile store"],
    ["Models", "11 MB", "Isolation Forest, scaler and all autoencoders"],
], widths=[1.8, 1.3, 3.5])
caption("Table 9.2 — Model artefacts are small; storage is dominated by retained "
        "event history and the retrieval index.")

d.add_heading("9.3 Observed operating scale", level=2)
table(["Measure", "Observed value"], [
    ["Sustained ingestion throughput", "208 events/second"],
    ["Events held in the live enriched feed", "1,566,510"],
    ["Monitored endpoints reporting", "38"],
    ["Distinct entities modelled", "1,566"],
    ["Alerts raised over a seven-day window", "70,542"],
    ["Correlated campaigns in that window", "79"],
    ["Console load time", "Approximately 0.7 seconds"],
], widths=[3.4, 3.2])
caption("Table 9.3 — Figures measured on the reference deployment. Alert volumes "
        "are a function of estate size, tuning maturity and threshold "
        "configuration, and should be expected to differ between installations.")

d.add_heading("9.4 Operational characteristics", level=2)
bullets([
    ("Resumable ingestion.", "The engine and transport both persist their "
     "position, so a restart neither re-scores nor skips events."),
    ("Hot configuration.", "Suppression patterns and watch lists are reloaded on "
     "change; operational tuning does not require a restart."),
    ("Bounded growth.", "Alert history is rotated and compressed daily, the "
     "training corpus is pruned to a rolling window, and generated reports are "
     "capped by both count and total size."),
    ("Graceful degradation.", "Optional components fail closed and in isolation: "
     "absent geolocation data disables the map without affecting detection, and "
     "absent document libraries reduce the available report formats rather than "
     "preventing reporting."),
])
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("10. Current Capability Statement", level=1)
para(
    "The following is an accurate statement of what is implemented today. It is "
    "included so that scope can be discussed against fact rather than inference.",
    size=10, italic=True, color=MUTED
)
d.add_heading("10.1 Implemented and in service", level=2)
bullets([
    "Unsupervised detection across four analytical layers, with per-entity baselines",
    "Campaign correlation and similar-anomaly retrieval",
    "Investigation console with evidence, entity, endpoint, campaign and incident views",
    "False-positive marking and pattern-based auto-suppression",
    "Watch lists with score elevation and full provenance on resulting alerts",
    "Out-of-the-box, custom and scheduled reporting in six output formats",
    "Email delivery of scheduled reports (requires an SMTP relay to be configured)",
    "Append-only audit trail of all state-changing actions",
    "Single sign-on through signed JWT assertions",
    "Live geolocated threat map from firewall telemetry",
])
d.add_heading("10.2 Available but not yet activated", level=2)
table(["Capability", "Status"], [
    ["SSO enforcement", "Implemented and verified end to end, but not currently "
     "enforcing. Activation requires the identity provider to complete the "
     "redirect contract."],
    ["Email report delivery", "Implemented and verified against a test relay. "
     "Requires client SMTP details to become operational."],
    ["AI-assisted alert narrative", "Implemented but disabled by default, and "
     "intentionally so: enabling it would send event-derived content to an "
     "external provider."],
], widths=[1.9, 4.7])
d.add_heading("10.3 Not implemented", level=2)
table(["Capability", "Position"], [
    ["Supervised detection models", "Requires labelled incident history, which "
     "does not exist at a new installation. Candidate for a later phase once "
     "analyst dispositions have accumulated."],
    ["Peer-group deviation analysis", "Requires organisational structure from a "
     "directory or HR source to define cohorts."],
    ["High availability without a single point of failure", "The current "
     "architecture is single-instance. High availability is an architectural "
     "change, not a configuration option."],
    ["Network flow (NetFlow) ingestion", "Not supported; the platform consumes "
     "SIEM-normalised events."],
], widths=[2.3, 4.3])
page_break()

# ════════════════════════════════════════════════════════════════════════════
d.add_heading("Appendix A — Component Reference", level=1)
table(["Module", "Size", "Responsibility"], [
    ["ueba_dashboard_server.py", "3,974 lines", "Console, REST API, caching, "
     "reporting endpoints, audit trail"],
    ["ueba_preprocessor.py", "1,183 lines", "Feature extraction, entity "
     "resolution, noise suppression, profile store"],
    ["ueba_engine.py", "1,101 lines", "Streaming detection, score fusion, alert "
     "emission, evidence assembly"],
    ["ueba_trainer.py", "792 lines", "Model training and threshold calibration"],
    ["ueba_auth.py", "773 lines", "SSO, sessions and role enforcement"],
    ["ueba_reports.py", "691 lines", "Report composition and section catalogue"],
    ["ueba_report_render.py", "557 lines", "PDF, Excel, CSV, HTML, JSON and XML "
     "rendering"],
    ["ueba_report_store.py", "510 lines", "Custom reports, scheduling, delivery, "
     "artefact retention"],
    ["ueba_prepare_training_data.py", "379 lines", "Training dataset assembly"],
    ["enrich_parallel.py", "259 lines", "Parallel event enrichment"],
    ["retrain.py", "249 lines", "Retraining orchestration"],
    ["ueba_watchlist.py", "220 lines", "Shared watch-list store and matching"],
    ["ueba_prune_corpus.py", "175 lines", "In-place training-corpus retention"],
], widths=[2.2, 1.0, 3.4])

d.add_heading("Appendix B — Principal Configuration Parameters", level=1)
table(["Parameter", "Value", "Effect"], [
    ["alert_threshold", "0.75", "Fused score at or above which an alert is raised"],
    ["isolation_forest_weight", "0.5", "Weight of global rarity in the fused score"],
    ["autoencoder_weight", "0.5", "Weight of personal deviation in the fused score"],
    ["feature_dim", "35", "Dimension of the event feature vector"],
    ["min_events_per_user", "2,000", "Activity required before an entity receives "
     "its own model"],
    ["threshold_percentile", "95", "Percentile of reconstruction error used as the "
     "per-entity threshold"],
    ["contamination", "0.005", "Expected outlier proportion for the Isolation Forest"],
    ["min_cluster_size", "5", "Smallest group HDBSCAN will treat as a campaign"],
    ["run_interval_seconds", "900", "Campaign clustering cadence"],
    ["poll_interval_ms", "100", "Engine feed polling interval"],
    ["if_batch_size", "128", "Events scored per Isolation Forest call"],
], widths=[2.0, 0.9, 3.7])

para()
para("— End of document —", size=9.5, italic=True, color=MUTED,
     align=WD_ALIGN_PARAGRAPH.CENTER)

add_running_heads(d.sections[0])
set_properties(d)
out = "/root/NEW_DRIVE/aditya_ueba/docs/CyberSentinel_UEBA_Technical_Document.docx"
import os
os.makedirs(os.path.dirname(out), exist_ok=True)
d.save(out)
print(f"  written: {out}")
