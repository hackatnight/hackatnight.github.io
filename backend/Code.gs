/**
 * HACKATNIGHT (hackatnight.com) — Unified Google Workspace Backend (router.gs)
 * Handles:
 *  - Visitor Logging & Sanitized Telemetry (Visits Log / Summary)
 *  - Infrastructure & Endpoint Uptime Monitor (Monitored_Nodes / Status_Log + Time Trigger)
 *  - Global Upstream & Outage Telemetry (Outage_Targets + GitHub Action / Live Browser Sync)
 *  - Automated Git Push Changelog Ingestion (Changelog + GitHub Action Push Hook)
 *  - Token-Gated Client File & Diagnostic Upload Vault (Google Drive + Vault_Uploads / Client_Keys)
 *  - Live Projects, Changelog & Download Counters (Projects / Changelog / Downloads)
 *  - IT Support Intake, Direct Comms & Bug Triage (IT_Support_Queue / Comms_Inbox / Bug_Triage + HTML Email Alerts)
 */

const CONFIG = {
  ADMIN_EMAIL: Session.getEffectiveUser().getEmail(),
  VAULT_FOLDER_NAME: "HACKATNIGHT_CLIENT_VAULT",
  SITE_NAME: "HACKATNIGHT",
  SITE_URL: "https://hackatnight.com",
  MAX_UPLOAD_BYTES: 25 * 1024 * 1024,
  GITHUB_USER: "hackatnight",
  MAX_VISIT_ROWS: 500,        // Visits Log keeps the newest 500; older rows move to Visits_Archive
  MAX_STATUS_ROWS: 3000,      // Status_Log keeps the newest 3000; older rows move to Status_Log_Archive
  UPTIME_WINDOW_HOURS: 24,    // Uptime % is calculated over this rolling window
  PROBE_COOLDOWN_SEC: 300,    // probe_now can trigger a real probe at most once per 5 minutes
  // Per-action write limits: [max requests, window in seconds]
  RATE_LIMITS: {
    visit: [60, 60],
    download: [30, 60],
    support: [5, 300],
    comms: [5, 300],
    triage: [5, 300],
    vault_upload: [5, 300],
    status_sync: [6, 600],
    changelog_sync: [20, 3600],
    project_sync: [10, 3600]
  },
  CHANGELOG_TAGS: ["🟢 FEAT", "🟢 RELEASE", "🟠 FIX", "🟣 INFRA", "🔵 UPDATE", "🟠 FIRMWARE"]
};

/* ---------- Abuse protection helpers ---------- */
function isRateLimited(action) {
  const rule = CONFIG.RATE_LIMITS[action];
  if (!rule) return false;
  const cache = CacheService.getScriptCache();
  const key = "rl_" + action;
  const count = Number(cache.get(key) || 0);
  if (count >= rule[0]) return true;
  cache.put(key, String(count + 1), rule[1]);
  return false;
}

/* ---------- Log trimming (moves old rows to archive tabs instead of deleting them) ---------- */
function getArchiveSheet(ss, name, headerSource) {
  let sheet = ss.getSheetByName(name);
  if (!sheet) {
    sheet = ss.insertSheet(name);
    const header = headerSource.getRange(1, 1, 1, headerSource.getLastColumn()).getValues();
    sheet.getRange(1, 1, 1, header[0].length).setValues(header).setFontWeight("bold");
    sheet.setFrozenRows(1);
  }
  return sheet;
}

// Visits Log: newest rows are at the top, so the overflow is at the bottom.
function trimVisitsLog() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName("Visits Log");
  if (!sheet) return 0;
  const dataRows = sheet.getLastRow() - 1;
  const excess = dataRows - CONFIG.MAX_VISIT_ROWS;
  if (excess <= 0) return 0;
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) return 0;
  try {
    const firstExcessRow = CONFIG.MAX_VISIT_ROWS + 2;
    const n = sheet.getLastRow() - firstExcessRow + 1;
    if (n <= 0) return 0;
    const cols = sheet.getLastColumn();
    const values = sheet.getRange(firstExcessRow, 1, n, cols).getValues();
    const archive = getArchiveSheet(ss, "Visits_Archive", sheet);
    archive.getRange(archive.getLastRow() + 1, 1, n, cols).setValues(values);
    sheet.deleteRows(firstExcessRow, n);
    return n;
  } finally {
    lock.releaseLock();
  }
}

// Status_Log: rows are appended at the bottom, so the overflow is the oldest rows at the top.
function trimStatusLog() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName("Status_Log");
  if (!sheet) return 0;
  const excess = (sheet.getLastRow() - 1) - CONFIG.MAX_STATUS_ROWS;
  if (excess <= 0) return 0;
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) return 0;
  try {
    const cols = sheet.getLastColumn();
    const values = sheet.getRange(2, 1, excess, cols).getValues();
    const archive = getArchiveSheet(ss, "Status_Log_Archive", sheet);
    archive.getRange(archive.getLastRow() + 1, 1, excess, cols).setValues(values);
    sheet.deleteRows(2, excess);
    return excess;
  } finally {
    lock.releaseLock();
  }
}

function setupSheets() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const schemas = {
    "Visits Log": ["Timestamp", "IP Address", "Country / Region", "Page Path", "Device Type", "Referrer", "Page Title", "Session ID", "Browser / User Agent"],
    "Monitored_Nodes": ["Node ID", "Node Name", "Endpoint URL", "Expected Status", "Category", "Enabled"],
    "Outage_Targets": ["Node ID", "Service Name", "Check Type", "Endpoint URL", "Enabled", "Last State", "Last Latency"],
    "Status_Log": ["Timestamp", "Node ID", "Node Name", "HTTP Status", "Latency (ms)", "State"],
    "Vault_Uploads": ["Timestamp", "Ticket ID", "Client Email", "File Name", "Size (KB)", "SHA-256", "Drive File URL", "Notes"],
    "Client_Keys": ["Access Key", "Release Title", "File Name", "Drive File ID", "Expires At", "Downloads Remaining", "Issued To"],
    "Projects": ["Project ID", "Title", "Category", "Status", "Version", "Description", "Live URL", "Source URL", "Updated Date"],
    "Changelog": ["Date", "Version", "Project", "Summary", "Tag"],
    "Downloads": ["File ID", "Title", "Version", "Platform", "Size", "SHA-256", "Download URL", "Count"],
    "IT_Support_Queue": ["Timestamp", "Ticket ID", "Client Name", "Email", "Service Tier", "Urgency", "System / Hardware", "Description", "Status"],
    "Comms_Inbox": ["Timestamp", "Handle / Name", "Email", "Subject", "Checksum", "Message", "IP Address"],
    "Bug_Triage": ["Timestamp", "Issue ID", "Project", "Severity", "Reporter", "Summary", "Environment", "Status"]
  };

  Object.keys(schemas).forEach(tabName => {
    let sheet = ss.getSheetByName(tabName);
    if (!sheet) {
      sheet = ss.insertSheet(tabName);
      sheet.appendRow(schemas[tabName]);
      sheet.getRange(1, 1, 1, schemas[tabName].length).setFontWeight("bold");
      sheet.setFrozenRows(1);
    } else if (sheet.getLastRow() === 0) {
      sheet.appendRow(schemas[tabName]);
      sheet.getRange(1, 1, 1, schemas[tabName].length).setFontWeight("bold");
      sheet.setFrozenRows(1);
    }
  });

  // Seed default monitored endpoints if empty
  const nodesSheet = ss.getSheetByName("Monitored_Nodes");
  if (nodesSheet.getLastRow() === 1) {
    nodesSheet.appendRow(["NODE-01", "HACKATNIGHT_CORE", "https://hackatnight.com", 200, "WEB_EDGE", true]);
    nodesSheet.appendRow(["NODE-02", "TESTING_REPO_DEMO", "https://hackatnight.github.io/TestingRepo/", 200, "APP_HOST", true]);
    nodesSheet.appendRow(["NODE-03", "GITHUB_API_RELAY", "https://api.github.com/users/hackatnight", 200, "UPSTREAM_API", true]);
  }

  // Seed default upstream outage targets if empty
  const outageSheet = ss.getSheetByName("Outage_Targets");
  if (outageSheet && outageSheet.getLastRow() === 1) {
    outageSheet.appendRow(["NODE-FRNT", "📡 Frontier Fiber (FL ISP)", "http", "https://frontier.com/helpcenter/categories/internet/troubleshooting/service-status", true, "🟢 ONLINE", "28 ms"]);
    outageSheet.appendRow(["NODE-XFIN", "📡 Comcast / Xfinity (FL ISP)", "http", "https://www.xfinity.com/support/status", true, "🟢 ONLINE", "32 ms"]);
    outageSheet.appendRow(["NODE-SPEC", "📡 Spectrum / Charter (FL ISP)", "http", "https://www.spectrum.net/support/internet/outage", true, "🟢 ONLINE", "35 ms"]);
    outageSheet.appendRow(["NODE-ATT", "📡 AT&T Fiber (FL ISP)", "http", "https://www.att.com/outages/", true, "🟢 ONLINE", "39 ms"]);
    outageSheet.appendRow(["NODE-TMO", "📶 T-Mobile 5G Home ISP", "http", "https://www.t-mobile.com/support/coverage", true, "🟢 ONLINE", "44 ms"]);
    outageSheet.appendRow(["NODE-VZ", "📡 Verizon 5G / Fios ISP", "http", "https://www.verizon.com/support/check-network-status/", true, "🟢 ONLINE", "41 ms"]);
    outageSheet.appendRow(["NODE-CTL", "📡 CenturyLink / Quantum (FL)", "http", "https://www.centurylink.com/home/help/internet/outages.html", true, "🟢 ONLINE", "47 ms"]);
    outageSheet.appendRow(["NODE-HTW", "📡 Hotwire Fision (FL Fiber)", "http", "https://gethotwired.com", true, "🟢 ONLINE", "31 ms"]);
    outageSheet.appendRow(["NODE-STLK", "🛰️ Starlink Satellite ISP", "http", "https://www.starlink.com", true, "🟢 ONLINE", "52 ms"]);
    outageSheet.appendRow(["NODE-MS365", "🟦 Microsoft 365 / Azure", "http", "https://status.cloud.microsoft", true, "🟢 ONLINE", "38 ms"]);
    outageSheet.appendRow(["NODE-OUTLOOK", "📧 Microsoft Outlook", "http", "https://portal.office.com/servicestatus", true, "🟢 ONLINE", "41 ms"]);
    outageSheet.appendRow(["NODE-EXCH", "🔄 MS Exchange Online", "http", "https://outlook.office365.com/owa/healthcheck.htm", true, "🟢 ONLINE", "29 ms"]);
    outageSheet.appendRow(["NODE-GWS", "🌐 Google Workspace", "google", "https://www.google.com/appsstatus/dashboard/incidents.json", true, "🟢 ONLINE", "31 ms"]);
    outageSheet.appendRow(["NODE-AWS", "🟧 Amazon Web Services", "http", "https://health.aws.amazon.com/health/status", true, "🟢 ONLINE", "45 ms"]);
    outageSheet.appendRow(["NODE-CF", "☁️ Cloudflare Edge", "statuspage", "https://www.cloudflarestatus.com/api/v2/status.json", true, "🟢 ONLINE", "19 ms"]);
    outageSheet.appendRow(["NODE-META", "📘 Facebook / Meta", "meta", "https://metastatus.com/data/orgs.json", true, "🟢 ONLINE", "44 ms"]);
    outageSheet.appendRow(["NODE-OA", "🧠 OpenAI API", "statuspage", "https://status.openai.com/api/v2/status.json", true, "🟢 ONLINE", "62 ms"]);
    outageSheet.appendRow(["NODE-SLK", "💼 Slack", "slack", "https://status.slack.com/api/v2.0.0/current", true, "🟢 ONLINE", "33 ms"]);
    outageSheet.appendRow(["NODE-ZM", "📹 Zoom", "statuspage", "https://status.zoom.us/api/v2/status.json", true, "🟢 ONLINE", "47 ms"]);
    outageSheet.appendRow(["NODE-GH", "🐙 GitHub Pages / API", "statuspage", "https://www.githubstatus.com/api/v2/status.json", true, "🟢 ONLINE", "34 ms"]);
    outageSheet.appendRow(["NODE-DC", "💬 Discord Infra", "statuspage", "https://discordstatus.com/api/v2/status.json", true, "🟢 ONLINE", "48 ms"]);
    outageSheet.appendRow(["NODE-RD", "👽 Reddit", "statuspage", "https://www.redditstatus.com/api/v2/status.json", true, "🟢 ONLINE", "39 ms"]);
    outageSheet.appendRow(["NODE-DO", "🌊 DigitalOcean", "statuspage", "https://status.digitalocean.com/api/v2/status.json", true, "🟢 ONLINE", "41 ms"]);
    outageSheet.appendRow(["NODE-CORE", "🛡️ HACKATNIGHT_CORE", "http", "https://hackatnight.com", true, "🟢 ONLINE", "36 ms"]);
  }

  // Seed default projects if empty
  const projSheet = ss.getSheetByName("Projects");
  if (projSheet.getLastRow() === 1) {
    projSheet.appendRow(["PRJ-01", "ESP32-2432S024C Handheld Game Boy Emulator", "EMBEDDED", "ACTIVE", "v1.4.2", "Peanut-GB core on CYD hardware with LovyanGFX, CST816S touch UI, GPIO haptics, and SD ROM streaming.", "https://hackatnight.github.io/TestingRepo/", "https://github.com/hackatnight/TestingRepo", "2026-10-24"]);
    projSheet.appendRow(["PRJ-02", "ESP32 CYD Live OBD-II Vehicle Telemetry Gauge", "AUTOMOTIVE", "ACTIVE", "v1.1.0", "Real-time CAN/OBD-II diagnostic cluster via Bluetooth ELM327 and custom CYD display.", "", "https://github.com/hackatnight", "2026-10-18"]);
    projSheet.appendRow(["PRJ-03", "9211B Head Unit Firmware & CAN-Bus Bridge", "AUTOMOTIVE", "STABLE", "v2.0.3", "Debloated Android 8 automotive head unit image with custom CAN-bus steering/telemetry bindings.", "", "https://github.com/hackatnight", "2026-10-12"]);
    projSheet.appendRow(["PRJ-04", "Sovereign Home Lab & Enterprise Mesh Stack", "INFRA", "PROD", "v3.2.0", "Segmented VLAN architecture, Synology private cloud storage, and self-hosted media/container orchestration.", "", "https://github.com/hackatnight", "2026-09-30"]);
  }

  // Seed default downloads if empty
  const dlSheet = ss.getSheetByName("Downloads");
  if (dlSheet.getLastRow() === 1) {
    dlSheet.appendRow(["DL-01", "CYD-GB-Emulator-Firmware.bin", "v1.4.2", "ESP32-2432S024C", "1.42 MB", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "https://github.com/hackatnight/TestingRepo", 148]);
    dlSheet.appendRow(["DL-02", "FireOS8-Debloat-ADB-Kit.zip", "v1.0.8", "Windows / Linux ADB", "312 KB", "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4", "https://github.com/hackatnight", 94]);
    dlSheet.appendRow(["DL-03", "ELM327-OBD2-PID-Scanner.ino", "v1.1.0", "PlatformIO / Arduino", "64 KB", "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "https://github.com/hackatnight", 73]);
  }
}

function doGet(e) {
  const action = (e && e.parameter && e.parameter.action) ? e.parameter.action : "bootstrap";
  try {
    if (action === "bootstrap") {
      return jsonOut({
        status: "ok",
        timestamp: new Date().toISOString(),
        telemetry: getSanitizedTelemetry(),
        uptime: getUptimeSummary(),
        outageTargets: getOutageTargets(),
        projects: getSheetObjects("Projects"),
        changelog: getSheetObjects("Changelog"),
        downloads: getSheetObjects("Downloads"),
        triage: getSanitizedTriage()
      });
    }
    if (action === "outage_targets") {
      return jsonOut({
        status: "ok",
        targets: getOutageTargets()
      });
    }
    if (action === "unlock_key") {
      const key = (e.parameter.key || "").trim();
      return jsonOut(validateAndRedeemKey(key));
    }
    return jsonOut({ status: "error", message: "Unknown GET action" });
  } catch (err) {
    return jsonOut({ status: "error", message: err.toString() });
  }
}

function doPost(e) {
  try {
    const body = JSON.parse(e.postData.contents || "{}");
    const action = body.action || body.type || "visit";

    if (isRateLimited(action)) {
      return jsonOut({ status: "error", message: "RATE_LIMITED: too many " + action + " requests, try again shortly" });
    }

    switch (action) {
      case "visit":
        return jsonOut(logVisit(body));
      case "download":
        return jsonOut(incrementDownload(body.fileId));
      case "support":
        return jsonOut(createSupportTicket(body));
      case "comms":
        return jsonOut(createCommsMessage(body));
      case "triage":
        return jsonOut(createBugTriage(body));
      case "vault_upload":
        return jsonOut(handleVaultUpload(body));
      case "probe_now": {
        // Only run a real probe if none ran recently; otherwise return the latest results
        const cache = CacheService.getScriptCache();
        const probed = !cache.get("probe_cooldown");
        if (probed) {
          cache.put("probe_cooldown", "1", CONFIG.PROBE_COOLDOWN_SEC);
          runHealthChecks();
        }
        return jsonOut({ status: "ok", probed: probed, uptime: getUptimeSummary() });
      }
      case "status_sync":
        return jsonOut(syncOutageStatus(body));
      case "changelog_sync":
        return jsonOut(logChangelogEntry(body));
      case "project_sync":
        return jsonOut(syncProjectEntry(body));
      default:
        return jsonOut({ status: "error", message: "Unknown POST action: " + action });
    }
  } catch (err) {
    return jsonOut({ status: "error", message: err.toString() });
  }
}

function syncProjectEntry(d) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Projects");
  if (!sheet) return { status: "error", message: "Projects tab missing" };

  // Only accept real, non-fork public repos owned by CONFIG.GITHUB_USER, and take the row
  // data from GitHub itself rather than trusting the browser's payload.
  const m = String(d.sourceUrl || "").trim().match(/^https:\/\/github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)\/?$/);
  if (!m || m[1].toLowerCase() !== CONFIG.GITHUB_USER.toLowerCase()) {
    return { status: "error", message: "project_sync only accepts github.com/" + CONFIG.GITHUB_USER + " repositories" };
  }
  const ghRes = UrlFetchApp.fetch("https://api.github.com/repos/" + CONFIG.GITHUB_USER + "/" + encodeURIComponent(m[2]), {
    muteHttpExceptions: true,
    headers: { "User-Agent": "HACKATNIGHT-Router" }
  });
  if (ghRes.getResponseCode() !== 200) {
    return { status: "error", message: "Repository not found on GitHub" };
  }
  const repo = JSON.parse(ghRes.getContentText());
  if (repo.fork || repo.private) {
    return { status: "error", message: "Forks and private repositories are not synced" };
  }
  d = {
    title: repo.name,
    category: String(repo.language || "CODE").toUpperCase(),
    status: "PUBLIC_REPO",
    version: "HEAD",
    description: repo.description || "Public engineering repository maintained by hackatnight.",
    liveUrl: repo.homepage || "",
    sourceUrl: repo.html_url,
    updatedDate: String(repo.pushed_at || new Date().toISOString()).slice(0, 10)
  };

  const rows = sheet.getDataRange().getValues();
  const titleIn = String(d.title || "").trim().toLowerCase();
  const sourceIn = String(d.sourceUrl || "").trim().toLowerCase();

  // Deduplicate by Title or specific Source URL (ignoring generic profile URLs like https://github.com/hackatnight)
  for (let i = 1; i < rows.length; i++) {
    const existingTitle = String(rows[i][1] || "").trim().toLowerCase();
    const existingSource = String(rows[i][7] || "").trim().toLowerCase();
    if (titleIn && existingTitle === titleIn) {
      return { status: "exists", projectId: rows[i][0] };
    }
    if (sourceIn && sourceIn !== "https://github.com/hackatnight" && existingSource === sourceIn) {
      return { status: "exists", projectId: rows[i][0] };
    }
  }

  const nextNum = Math.max(1, rows.length);
  const projId = "PRJ-" + String(nextNum).padStart(2, "0");
  const nextRow = sheet.getLastRow() + 1;
  const rowRange = sheet.getRange(nextRow, 1, 1, 9);
  rowRange.setValues([[
    projId,
    d.title || "Untitled Project",
    d.category || "CODE",
    d.status || "PUBLIC_REPO",
    d.version || "HEAD",
    d.description || "Public engineering repository maintained by hackatnight.",
    d.liveUrl || "",
    d.sourceUrl || "https://github.com/hackatnight",
    d.updatedDate || new Date().toISOString().slice(0, 10)
  ]]);

  // Copy exact cell formatting, borders, alignment, and column colors from Row 2 so every row matches
  if (nextRow > 2) {
    sheet.getRange(2, 1, 1, 9).copyTo(rowRange, SpreadsheetApp.CopyPasteType.PASTE_FORMAT, false);
  }

  return { status: "ok", projectId: projId, title: d.title };
}

function logChangelogEntry(d) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Changelog");
  if (!sheet) return { status: "error", message: "Changelog tab missing" };

  // Validate the entry so random POSTs can't put junk in the Changelog
  const version = String(d.version || "").trim();
  const summary = String(d.summary || "").trim();
  if (!/^v\.\d+\.\d+\.\d+$/.test(version)) {
    return { status: "error", message: "Invalid version format (expected v.X.Y.Z)" };
  }
  if (!summary || summary.length > 400) {
    return { status: "error", message: "Summary must be 1-400 characters" };
  }
  if (d.tag && CONFIG.CHANGELOG_TAGS.indexOf(d.tag) === -1) {
    return { status: "error", message: "Unknown changelog tag" };
  }
  d.project = String(d.project || "H@N Core").slice(0, 60);

  // Skip exact duplicates (same version + same summary), e.g. two visitors syncing the manifest at once
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return { status: "error", message: "Changelog busy, try again" };
  try {
    const existing = sheet.getLastRow() > 1 ? sheet.getRange(2, 2, sheet.getLastRow() - 1, 3).getValues() : [];
    for (let i = 0; i < existing.length; i++) {
      if (String(existing[i][0]).trim() === version && String(existing[i][2]).trim() === summary) {
        return { status: "exists", logged: version, summary: summary };
      }
    }
    return insertChangelogRow(sheet, d);
  } finally {
    lock.releaseLock();
  }
}

function insertChangelogRow(sheet, d) {
  // Insert at Row 2 so newest releases always appear at the top of the table
  sheet.insertRowBefore(2);
  const rowRange = sheet.getRange(2, 1, 1, 5);
  rowRange.setValues([[
    d.date || new Date().toISOString().slice(0, 10),
    d.version || "v.2.5.1",
    d.project || "H@N Core",
    d.summary || "Repository push update",
    d.tag || "🔵 UPDATE"
  ]]);

  // Preserve the dark terminal styling on newly inserted Row 2
  rowRange
    .setBackground("#181124")
    .setFontColor("#EBEFF4")
    .setFontFamily("Roboto Mono")
    .setFontSize(10)
    .setFontWeight("normal");
  sheet.getRange(2, 2).setFontColor("#00E5FF").setFontWeight("bold");

  return { status: "ok", logged: d.version, summary: d.summary };
}

function getOutageTargets() {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Outage_Targets");
  if (!sheet || sheet.getLastRow() < 2) return [];
  const rows = sheet.getDataRange().getValues();
  rows.shift(); // remove header row
  return rows
    .filter(r => r[0] && r[3])
    .map(r => ({
      id: r[0],
      name: r[1],
      type: r[2] || "statuspage",
      url: r[3],
      enabled: r[4],
      lastState: r[5] || "🟢 ONLINE",
      lastLatency: r[6] || "--"
    }));
}

function syncOutageStatus(d) {
  if (!Array.isArray(d.nodes)) {
    return { status: "error", message: "Missing nodes array" };
  }
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const targetSheet = ss.getSheetByName("Outage_Targets");
  const statusSheet = ss.getSheetByName("Status_Log");
  const now = new Date();

  const targetRows = targetSheet ? targetSheet.getDataRange().getValues() : [];

  // Only accept nodes that exist in Outage_Targets (blocks junk rows from random POSTs)
  const knownIds = {};
  for (let i = 1; i < targetRows.length; i++) knownIds[String(targetRows[i][0])] = true;
  const validStates = { ONLINE: true, DEGRADED: true, OFFLINE: true };
  const nodes = d.nodes
    .filter(n => n && knownIds[String(n.id)] && validStates[n.state])
    .slice(0, Math.max(0, targetRows.length - 1));
  const statusRows = [];

  nodes.forEach(node => {
    const badge = node.state === "ONLINE" ? "🟢 ONLINE" :
                  node.state === "DEGRADED" ? "🟡 DEGRADED" : "🔴 OFFLINE";

    // Update Last State & Last Latency inside Outage_Targets
    if (targetSheet && targetRows.length > 1) {
      for (let i = 1; i < targetRows.length; i++) {
        if (String(targetRows[i][0]) === String(node.id)) {
          targetSheet.getRange(i + 1, 6).setValue(badge);
          targetSheet.getRange(i + 1, 7).setValue((Number(node.latency_ms) || 0) + " ms");
        }
      }
    }

    // Queue for Status_Log. HTTP status 0 means unreachable/timeout and must stay 0, not become 200.
    statusRows.push([
      now,
      node.id,
      String(node.name || "").slice(0, 80),
      Number(node.http_status) || 0,
      Number(node.latency_ms) || 0,
      node.state
    ]);
  });

  // One batched write instead of one appendRow per node
  if (statusSheet && statusRows.length) {
    statusSheet.getRange(statusSheet.getLastRow() + 1, 1, statusRows.length, 6).setValues(statusRows);
  }
  trimStatusLog();

  return { status: "ok", synced: nodes.length, rejected: d.nodes.length - nodes.length };
}

function logVisit(d) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Visits Log");
  if (!sheet) return { status: "error", message: "Visits Log tab missing" };

  // Insert at Row 2 so newest visits always appear at the top of the sheet
  // Column order: Timestamp, IP Address, Country / Region, Page Path, Device Type, Referrer, Page Title, Session ID, Browser / User Agent
  sheet.insertRowBefore(2);
  const rowRange = sheet.getRange(2, 1, 1, 9);
  rowRange.setValues([[
    new Date(),
    d.ipAddress || "Unknown",
    d.country || "Unknown",
    d.pagePath || "/",
    d.deviceType || "Unknown",
    d.referrer || "Direct",
    d.pageTitle || "H@N",
    d.sessionId || "",
    d.userAgent || ""
  ]]);

  // Preserve the dark terminal styling on newly inserted Row 2
  rowRange
    .setBackground("#181124")
    .setFontColor("#EBEFF4")
    .setFontFamily("Roboto Mono")
    .setFontSize(10)
    .setFontWeight("normal");

  trimVisitsLog();
  return { status: "ok" };
}

function incrementDownload(fileId) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Downloads");
  const rows = sheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0]) === String(fileId)) {
      const nextCount = (Number(rows[i][7]) || 0) + 1;
      sheet.getRange(i + 1, 8).setValue(nextCount);
      return { status: "ok", fileId: fileId, count: nextCount };
    }
  }
  return { status: "error", message: "File ID not found" };
}

function createSupportTicket(d) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("IT_Support_Queue");
  const ticketId = "HACK-" + Math.floor(1000 + Math.random() * 9000);
  const now = new Date();
  sheet.appendRow([
    now,
    ticketId,
    d.name || "Anonymous",
    d.email || "",
    d.serviceTier || "General IT Support",
    d.urgency || "STANDARD",
    d.hardware || "Not specified",
    d.description || "",
    "NEW"
  ]);

  sendFormattedAlert(
    "[HACKATNIGHT] New IT Support Request: " + ticketId + " (" + (d.urgency || "STANDARD") + ")",
    "New IT Support Ticket: " + ticketId + "\nClient: " + d.name + " (" + d.email + ")\nService: " + d.serviceTier + "\nDetails: " + d.description,
    [
      ["Ticket ID", ticketId],
      ["Client Name", d.name || "N/A"],
      ["Reply Email", d.email || "N/A"],
      ["Service Tier", d.serviceTier || "General IT Support"],
      ["Urgency", d.urgency || "STANDARD"],
      ["Target System", d.hardware || "Not specified"],
      ["Timestamp", now.toUTCString()]
    ],
    d.description || "No description provided."
  );

  return { status: "ok", ticketId: ticketId };
}

function createCommsMessage(d) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Comms_Inbox");
  const now = new Date();
  sheet.appendRow([
    now,
    d.handle || "Operator",
    d.email || "",
    d.subject || "Direct Transmission",
    d.checksum || "",
    d.message || "",
    d.ipAddress || "Unknown"
  ]);

  sendFormattedAlert(
    "[HACKATNIGHT] Direct Comms: " + (d.subject || "New Message"),
    "From: " + d.handle + " <" + d.email + ">\nSubject: " + d.subject + "\n\n" + d.message,
    [
      ["Sender Handle", d.handle || "Anonymous"],
      ["Return Address", d.email || "N/A"],
      ["Subject", d.subject || "Direct Transmission"],
      ["Payload Checksum", d.checksum || "N/A"],
      ["Timestamp", now.toUTCString()]
    ],
    d.message || ""
  );

  return { status: "ok" };
}

function createBugTriage(d) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Bug_Triage");
  const issueId = "BUG-" + Math.floor(100 + Math.random() * 899);
  const now = new Date();
  sheet.appendRow([
    now,
    issueId,
    d.project || "General",
    d.severity || "LOW",
    d.reporter || "Anonymous",
    d.summary || "",
    d.environment || "",
    "NEW"
  ]);

  sendFormattedAlert(
    "[HACKATNIGHT] Triage Report " + issueId + " [" + (d.severity || "LOW") + "]",
    "Issue: " + issueId + "\nProject: " + d.project + "\nSummary: " + d.summary,
    [
      ["Issue ID", issueId],
      ["Target Project", d.project || "General"],
      ["Severity", d.severity || "LOW"],
      ["Reporter", d.reporter || "Anonymous"],
      ["Environment", d.environment || "Not specified"],
      ["Timestamp", now.toUTCString()]
    ],
    d.summary || ""
  );

  return { status: "ok", issueId: issueId };
}

function handleVaultUpload(d) {
  if (!d.base64Data || !d.fileName) {
    return { status: "error", message: "Missing file payload" };
  }
  const bytes = Utilities.base64Decode(d.base64Data);
  if (bytes.length > CONFIG.MAX_UPLOAD_BYTES) {
    return { status: "error", message: "File exceeds 25 MB limit" };
  }

  const rootIter = DriveApp.getFoldersByName(CONFIG.VAULT_FOLDER_NAME);
  const rootFolder = rootIter.hasNext() ? rootIter.next() : DriveApp.createFolder(CONFIG.VAULT_FOLDER_NAME);

  const safeTicket = (d.ticketId || "UNASSIGNED").replace(/[^a-zA-Z0-9_-]/g, "");
  const subIter = rootFolder.getFoldersByName(safeTicket);
  const targetFolder = subIter.hasNext() ? subIter.next() : rootFolder.createFolder(safeTicket);

  const blob = Utilities.newBlob(bytes, d.mimeType || "application/octet-stream", d.fileName);
  const file = targetFolder.createFile(blob);
  const fileUrl = file.getUrl();
  const now = new Date();

  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Vault_Uploads");
  sheet.appendRow([
    now,
    safeTicket,
    d.clientEmail || "Not provided",
    d.fileName,
    (bytes.length / 1024).toFixed(2),
    d.sha256 || "",
    fileUrl,
    d.notes || ""
  ]);

  sendFormattedAlert(
    "[HACKATNIGHT VAULT] Diagnostic File Uploaded (" + safeTicket + ")",
    "File: " + d.fileName + "\nTicket: " + safeTicket + "\nDrive URL: " + fileUrl,
    [
      ["Ticket ID", safeTicket],
      ["File Name", d.fileName],
      ["Payload Size", (bytes.length / 1024).toFixed(1) + " KB"],
      ["SHA-256", d.sha256 || "N/A"],
      ["Client Email", d.clientEmail || "Not provided"],
      ["Drive Location", fileUrl]
    ],
    d.notes || "Uploaded via HACKATNIGHT Client Vault."
  );

  return { status: "ok", fileName: d.fileName, ticketId: safeTicket, size: bytes.length };
}

function validateAndRedeemKey(key) {
  if (!key) return { status: "denied", message: "ACCESS_DENIED: Empty key" };
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Client_Keys");
  const rows = sheet.getDataRange().getValues();
  const now = new Date();

  for (let i = 1; i < rows.length; i++) {
    if (String(rows[i][0]).trim().toUpperCase() === key.toUpperCase()) {
      const title = rows[i][1];
      const fileName = rows[i][2];
      const driveFileId = String(rows[i][3]).trim();
      const expiresAt = rows[i][4] ? new Date(rows[i][4]) : null;
      const remaining = Number(rows[i][5]) || 0;

      if (expiresAt && expiresAt < now) {
        return { status: "denied", message: "ACCESS_DENIED: Release key expired" };
      }
      if (remaining <= 0) {
        return { status: "denied", message: "ACCESS_DENIED: Download quota exhausted" };
      }

      sheet.getRange(i + 1, 6).setValue(remaining - 1);
      let downloadUrl = "";
      if (driveFileId) {
        downloadUrl = "https://drive.google.com/uc?export=download&id=" + encodeURIComponent(driveFileId);
      }

      return {
        status: "ok",
        title: title,
        fileName: fileName,
        remaining: remaining - 1,
        downloadUrl: downloadUrl
      };
    }
  }
  return { status: "denied", message: "ACCESS_DENIED: Invalid release key" };
}

function runHealthChecks() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const nodesSheet = ss.getSheetByName("Monitored_Nodes");
  const logSheet = ss.getSheetByName("Status_Log");
  const rows = nodesSheet.getDataRange().getValues();
  const now = new Date();

  for (let i = 1; i < rows.length; i++) {
    const [nodeId, nodeName, url, expectedCode, category, enabled] = rows[i];
    if (!enabled || !url) continue;

    const start = Date.now();
    let code = 0;
    let state = "ONLINE";
    try {
      const res = UrlFetchApp.fetch(url, { muteHttpExceptions: true, followRedirects: true });
      code = res.getResponseCode();
      if (code !== Number(expectedCode || 200)) {
        state = "DEGRADED";
      }
    } catch (e) {
      code = 503;
      state = "OFFLINE";
    }
    const latency = Date.now() - start;
    logSheet.appendRow([now, nodeId, nodeName, code, latency, state]);

    // Email only when a node's state changes (down, degraded, or recovered), not on every 15-minute probe
    const props = PropertiesService.getScriptProperties();
    const stateKey = "node_state_" + nodeId;
    const previous = props.getProperty(stateKey) || "ONLINE";
    if (previous !== state) {
      props.setProperty(stateKey, state);
      sendFormattedAlert(
        "[HACKATNIGHT " + (state === "ONLINE" ? "RECOVERED" : "ALERT") + "] Node " + nodeName + " is " + state + " (HTTP " + code + ")",
        "Endpoint " + url + " returned HTTP " + code + " (" + latency + " ms).",
        [
          ["Node", nodeName + " (" + nodeId + ")"],
          ["Endpoint URL", url],
          ["HTTP Status", String(code)],
          ["Latency", latency + " ms"],
          ["State", state],
          ["Timestamp", now.toUTCString()]
        ],
        state === "ONLINE"
          ? nodeName + " is responding normally again (previously " + previous + ")."
          : "Automated background probe detected an anomaly on " + nodeName + " (previously " + previous + ")."
      );
    }
  }
  trimStatusLog();
  trimVisitsLog();
}

function getSanitizedTelemetry() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName("Visits Log");
  const rows = sheet.getDataRange().getValues();
  // Total views include rows already moved to Visits_Archive (unique sessions cover the live 500 only)
  const archive = ss.getSheetByName("Visits_Archive");
  const archivedViews = archive ? Math.max(0, archive.getLastRow() - 1) : 0;
  const totalViews = Math.max(0, rows.length - 1) + archivedViews;
  const sessions = {};
  const regions = {};
  const devices = { Desktop: 0, Mobile: 0, Tablet: 0 };
  const recent = [];

  // Dynamic header index lookup so column reordering never breaks telemetry parsing
  const headers = (rows[0] || []).map(h => String(h).trim().toLowerCase());
  const idxTs  = headers.findIndex(h => h.includes("timestamp") || h.includes("date"));
  const idxIp  = headers.findIndex(h => h.includes("ip"));
  const idxReg = headers.findIndex(h => h.includes("country") || h.includes("region"));
  const idxPth = headers.findIndex(h => h.includes("path"));
  const idxDev = headers.findIndex(h => h.includes("device"));
  const idxRef = headers.findIndex(h => h.includes("referrer"));
  const idxSid = headers.findIndex(h => h.includes("session"));

  const cTs  = idxTs  !== -1 ? idxTs  : 0;
  const cReg = idxReg !== -1 ? idxReg : 2;
  const cPth = idxPth !== -1 ? idxPth : 3;
  const cDev = idxDev !== -1 ? idxDev : 4;
  const cRef = idxRef !== -1 ? idxRef : 5;
  const cSid = idxSid !== -1 ? idxSid : 7;

  for (let i = 1; i < rows.length; i++) {
    const sid = rows[i][cSid];
    const region = rows[i][cReg];
    const dev = rows[i][cDev];
    if (sid) sessions[sid] = true;
    const reg = String(region || "Unknown");
    regions[reg] = (regions[reg] || 0) + 1;
    const cleanDev = String(dev || "").replace(/[💻📱📟🖥️]/g, "").trim();
    if (devices[cleanDev] !== undefined) devices[cleanDev]++;
  }

  // Read top 12 rows directly (newest visits on top at Row 2)
  const limit = Math.min(rows.length - 1, 12);
  for (let i = 1; i <= limit; i++) {
    recent.push({
      timestamp: rows[i][cTs] ? new Date(rows[i][cTs]).toISOString() : "",
      path: rows[i][cPth] || "/",
      referrer: rows[i][cRef] || "Direct",
      device: rows[i][cDev] || "Desktop",
      region: rows[i][cReg] || "Unknown"
    });
  }

  let topRegion = "America/New_York";
  let maxReg = 0;
  Object.keys(regions).forEach(r => {
    if (regions[r] > maxReg) {
      maxReg = regions[r];
      topRegion = r;
    }
  });

  return {
    totalViews: totalViews,
    uniqueSessions: Object.keys(sessions).length,
    topRegion: topRegion,
    devices: devices,
    regions: regions,
    recent: recent
  };
}

function getUptimeSummary() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const nodes = getSheetObjects("Monitored_Nodes").filter(n => n["Enabled"] !== false);
  const logSheet = ss.getSheetByName("Status_Log");
  const logs = logSheet.getDataRange().getValues();
  const cutoff = Date.now() - CONFIG.UPTIME_WINDOW_HOURS * 3600 * 1000;

  return nodes.map(n => {
    const id = n["Node ID"];
    const matching = [];
    for (let i = 1; i < logs.length; i++) {
      const ts = logs[i][0] instanceof Date ? logs[i][0].getTime() : new Date(logs[i][0]).getTime();
      if (String(logs[i][1]) === String(id) && !(ts < cutoff)) {
        const rawState = String(logs[i][5] || "ONLINE").replace(/[🟢🟡🔴]/g, "").trim();
        matching.push({
          status: Number(logs[i][3]) || 200,
          latency: parseInt(logs[i][4], 10) || 45,
          state: rawState || "ONLINE"
        });
      }
    }
    const recent = matching.slice(-16);
    const okCount = matching.filter(m => m.state === "ONLINE").length;
    const uptimePct = matching.length ? ((okCount / matching.length) * 100).toFixed(2) : "100.00";
    const latest = recent.length ? recent[recent.length - 1] : { status: 200, latency: 42, state: "ONLINE" };

    return {
      id: id,
      name: n["Node Name"],
      url: n["Endpoint URL"],
      category: n["Category"] || "SERVICE",
      uptime: uptimePct,
      latency: latest.latency,
      status: latest.status,
      state: latest.state,
      history: recent.length ? recent.map(r => r.latency) : [44, 41, 46, 39, 43, 45, 42, 40]
    };
  });
}

function getSanitizedTriage() {
  return getSheetObjects("Bug_Triage").slice(-15).reverse().map(r => ({
    id: r["Issue ID"],
    project: r["Project"],
    severity: r["Severity"],
    summary: r["Summary"],
    status: r["Status"] || "NEW"
  }));
}

function getSheetObjects(tabName) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(tabName);
  if (!sheet || sheet.getLastRow() < 2) return [];
  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  return data.slice(1).map(row => {
    const obj = {};
    headers.forEach((h, idx) => { obj[h] = row[idx]; });
    return obj;
  });
}

function sendFormattedAlert(subject, plainText, rows, bodyBlock) {
  const trs = rows.map(r =>
    '<tr>' +
      '<td style="padding:8px 12px;border-bottom:1px solid #1e293b;color:#94a3b8;font-family:monospace;font-size:12px;width:150px;">' + escHtml(r[0]) + '</td>' +
      '<td style="padding:8px 12px;border-bottom:1px solid #1e293b;color:#f8fafc;font-family:monospace;font-size:13px;">' + escHtml(r[1]) + '</td>' +
    '</tr>'
  ).join("");

  const html =
    '<div style="background:#090d16;padding:24px;font-family:monospace;color:#e2e8f0;">' +
      '<div style="max-width:600px;margin:0 auto;background:#0f172a;border:1px solid #10b981;border-radius:6px;overflow:hidden;">' +
        '<div style="background:#064e3b;padding:14px 20px;border-bottom:1px solid #10b981;">' +
          '<span style="color:#34d399;font-weight:bold;letter-spacing:1px;">root@hackatnight.com:~$ // SYSTEM_DISPATCH</span>' +
        '</div>' +
        '<div style="padding:20px;">' +
          '<table style="width:100%;border-collapse:collapse;margin-bottom:16px;">' + trs + '</table>' +
          '<div style="background:#090d16;border:1px solid #1e293b;border-radius:4px;padding:14px;color:#cbd5e1;white-space:pre-wrap;font-size:13px;line-height:1.5;">' +
            escHtml(bodyBlock) +
          '</div>' +
          '<p style="margin:16px 0 0;font-size:11px;color:#64748b;">Dispatched automatically by HACKATNIGHT Workspace Router (' + CONFIG.SITE_URL + ')</p>' +
        '</div>' +
      '</div>' +
    '</div>';

  MailApp.sendEmail({
    to: CONFIG.ADMIN_EMAIL,
    subject: subject,
    body: plainText,
    htmlBody: html
  });
}

function escHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function jsonOut(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
