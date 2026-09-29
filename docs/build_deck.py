#!/usr/bin/env python3
"""CyberSentinel UEBA — client presentation (7 slides).

Feature-complete but short. Every workspace, panel, visualisation and capability
in the product is named somewhere in these seven slides.

One deliberate omission: the AI Security Analyst panel exists in the console but
is disabled by default and must not be enabled on a client installation, because
it would send event-derived content to an external provider. Presenting it as an
available capability would contradict the data-sovereignty commitment on slide 6,
so it is left out rather than caveated.
"""
from deck_style import Deck

d = Deck()

# 1 ─────────────────────────────────────────────────────────────────────────
d.title_slide(
    "CyberSentinel UEBA",
    "User and Entity Behaviour Analytics",
    "Detecting insider threat and account compromise by learning what normal "
    "looks like in your estate — and reporting what deviates from it.",
    "Confidential  ·  Prepared for client evaluation  ·  September 2026")
d.n = 0

# 2 ─────────────────────────────────────────────────────────────────────────
d.cards(
    "What it detects", "Detection capability",
    [("Compromised credentials",
      "A valid session doing things the real account holder never does."),
     ("Insider misuse",
      "Legitimate access used outside the entity's established pattern."),
     ("Behavioural drift",
      "Gradual change that never crosses a fixed threshold on any single day."),
     ("Coordinated activity",
      "Related anomalies across users and hosts, grouped into one campaign."),
     ("Estate-wide rare events",
      "Activity unusual against the whole population, not just one account."),
     ("High-risk watched entities",
      "Users, hosts or addresses your analysts have placed under scrutiny.")],
    lead="Four analytical layers — global outlier detection (Isolation Forest), "
         "per-entity behavioural baselines (autoencoders), campaign clustering "
         "(HDBSCAN) and similarity retrieval — fuse into one prioritised verdict.")

# 3 ─────────────────────────────────────────────────────────────────────────
d.cards(
    "Ten analyst workspaces", "The console",
    [("Overview", "At-a-glance posture, risk and system health"),
     ("Incidents", "Entity incidents, time-bounded for shift review"),
     ("Alert Feed", "Full alert stream with filtering and evidence"),
     ("User Risk", "Entities ranked by risk index, drillable"),
     ("Campaigns", "Correlated anomaly clusters and their timeline"),
     ("Endpoints", "Per-agent coverage, activity and detail"),
     ("Threat Map", "Live geolocated external traffic, 3D and 2D"),
     ("False Positives", "Marked alerts and auto-suppression patterns"),
     ("Watch List", "Entities under elevated scrutiny"),
     ("Reports", "Generate, customise, schedule and download")],
    per_row=5, body=11,
    lead="Every capability in the product is reachable from one of these ten "
         "workspaces.")

# 4 ─────────────────────────────────────────────────────────────────────────
d.cards(
    "Analytics and visualisation", "Seeing the estate",
    [("Overview dashboard",
      "Recent alerts, top risk users, top rule descriptions, endpoints, "
      "recommended actions and engine health on a single page."),
     ("Behavioural Risk Meter",
      "A single gauge for current estate-wide behavioural risk."),
     ("Security Activity Pattern",
      "Radar view of activity shape across categories."),
     ("Alert Timeline",
      "Volume over time, across any selected window."),
     ("Alert Score Distribution",
      "Where alerts sit across the scoring range — the shape of your tuning."),
     ("Hourly Alert Heatmap",
      "Activity by hour and day, exposing off-hours behaviour."),
     ("MITRE ATT&CK Coverage",
      "Which tactics your alerting is actually exercising."),
     ("Live Threat Map",
      "Geolocated external-to-datacentre traffic as a 3D globe or 2D map, "
      "resolved entirely offline.")],
    per_row=4, body=11.5)

# 5 ─────────────────────────────────────────────────────────────────────────
d.cards(
    "Investigation and tuning", "Working the alerts",
    [("Filtering",
      "Free text, MITRE ATT&CK tactic, severity threshold and verdict, applied "
      "live to the feed."),
     ("Seven timeline windows",
      "24 hours, 3, 7, 30, 60 and 90 days, or all retained history."),
     ("Evidence on every alert",
      "Model scores against that entity's thresholds, anomaly reasons, its "
      "baseline, and similar past events."),
     ("Entity and endpoint drill-down",
      "From any alert into the full history of the user or host involved."),
     ("False-positive suppression",
      "Mark one alert, or derive a pattern that filters matching future alerts "
      "— effective on the next event, no restart."),
     ("Watch lists",
      "Elevate scrutiny on named users, hosts or IPs. Score contribution is "
      "always recorded and visible.")],
    lead="The alert feed streams live, so new alerts appear without a refresh.")

# 6 ─────────────────────────────────────────────────────────────────────────
d.cards(
    "Reporting, export and governance", "Evidence and control",
    [("Four built-in reports",
      "Analyst investigation, administration and management, audit and "
      "compliance, and a threat report for any period."),
     ("Custom reports",
      "Composed from the same catalogue of 20 sections the built-in reports "
      "are assembled from."),
     ("Scheduled and delivered",
      "Hourly, daily, weekly or monthly — downloaded from the console or "
      "emailed with the report attached."),
     ("Six export formats",
      "PDF, Excel, CSV, HTML, JSON and XML — from a report, or straight from "
      "the filtered alert feed."),
     ("Single sign-on and roles",
      "Signed assertions from your identity provider, with viewer, analyst and "
      "administrator roles."),
     ("Audit trail and sovereignty",
      "Every state-changing action recorded, including rejected attempts. No "
      "outbound connection to any third party.")])

# 7 ─────────────────────────────────────────────────────────────────────────
d.metrics(
    "Running at operational scale today", "Evidence",
    [("208/sec", "Events ingested and scored"),
     ("1,566", "Entities with maintained baselines"),
     ("556", "Dedicated per-entity models"),
     ("5.6M", "Anomaly vectors indexed"),
     ("70,542", "Alerts across a seven-day window"),
     ("79", "Correlated campaigns identified"),
     ("38", "Monitored endpoints reporting"),
     ("~0.7s", "Console load time")],
    lead="Measurements from the running deployment, not projections.",
    footnote="Measured 23 September 2026. Alert volumes depend on estate size, "
             "tuning maturity and threshold configuration, and will differ "
             "between installations. We would welcome a proof of value against "
             "your own event data.")

d.save("/root/NEW_DRIVE/aditya_ueba/docs/CyberSentinel_UEBA_Client_Presentation.pptx")
