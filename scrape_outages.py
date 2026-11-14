import urllib.request
import urllib.error
import urllib.parse
import json
import time
import os
from datetime import datetime, timezone

TARGETS = [
    {"id": "NODE-GH",      "name": "🐙 GitHub Pages / API",      "type": "statuspage", "url": "https://www.githubstatus.com/api/v2/status.json"},
    {"id": "NODE-CF",      "name": "☁️ Cloudflare Edge",         "type": "statuspage", "url": "https://www.cloudflarestatus.com/api/v2/status.json"},
    {"id": "NODE-META",    "name": "📘 Facebook / Meta",         "type": "meta",       "url": "https://metastatus.com/data/orgs.json"},
    {"id": "NODE-MS365",   "name": "🪟 Microsoft 365 / Azure",   "type": "http",       "url": "https://status.cloud.microsoft"},
    {"id": "NODE-OUTLOOK", "name": "📧 Microsoft Outlook",       "type": "http",       "url": "https://portal.office.com/servicestatus"},
    {"id": "NODE-EXCH",    "name": "🔄 MS Exchange Online",      "type": "http",       "url": "https://outlook.office365.com/owa/healthcheck.htm"},
    {"id": "NODE-GWS",     "name": "🌐 Google Workspace",        "type": "google",     "url": "https://www.google.com/appsstatus/dashboard/incidents.json"},
    {"id": "NODE-AWS",     "name": "🟧 Amazon Web Services",     "type": "http",       "url": "https://health.aws.amazon.com/health/status"},
    {"id": "NODE-DC",      "name": "💬 Discord Infra",           "type": "statuspage", "url": "https://discordstatus.com/api/v2/status.json"},
    {"id": "NODE-OA",      "name": "🧠 OpenAI API",              "type": "statuspage", "url": "https://status.openai.com/api/v2/status.json"},
    {"id": "NODE-RD",      "name": "👽 Reddit",                  "type": "statuspage", "url": "https://www.redditstatus.com/api/v2/status.json"},
    {"id": "NODE-SLK",     "name": "💼 Slack",                   "type": "slack",      "url": "https://status.slack.com/api/v2.0.0/current"},
    {"id": "NODE-ZM",      "name": "📹 Zoom",                    "type": "statuspage", "url": "https://status.zoom.us/api/v2/status.json"},
    {"id": "NODE-DO",      "name": "🌊 DigitalOcean",            "type": "statuspage", "url": "https://status.digitalocean.com/api/v2/status.json"},
    {"id": "NODE-XFIN",    "name": "📡 Comcast / Xfinity ISP",   "type": "http",       "url": "https://www.xfinity.com/support/status"},
    {"id": "NODE-SPEC",    "name": "📡 Spectrum / Charter ISP",  "type": "http",       "url": "https://www.spectrum.net/support/internet/outage"},
    {"id": "NODE-ATT",     "name": "📡 AT&T Fiber / ISP",        "type": "http",       "url": "https://www.att.com/outages/"},
    {"id": "NODE-VZ",      "name": "📡 Verizon Fios / ISP",      "type": "http",       "url": "https://www.verizon.com/support/check-network-status/"},
    {"id": "NODE-01",      "name": "🛡️ HACKATNIGHT_CORE",        "type": "http",       "url": "https://hackatnight.com"}
]

APPS_SCRIPT_WEBHOOK = os.environ.get("APPS_SCRIPT_WEBHOOK", "").strip() or "https://script.google.com/macros/s/AKfycbwjIa-86sZJdIEaH2B33IJAq5C1fv8k55KLur_NLZ_jZIIyMSHSWklse0K5P4blisuG/exec"

def check_target(target):
    start = time.time()
    ctype = (target.get("type") or "http").lower()
    try:
        req = urllib.request.Request(
            target["url"],
            headers={"User-Agent": "Mozilla/5.0 (compatible; H@N-Telemetry-Monitor/2.4.0)"}
        )
        with urllib.request.urlopen(req, timeout=10) as res:
            latency_ms = int((time.time() - start) * 1000)
            http_code = res.getcode()
            raw_bytes = res.read(65536)

            if ctype == "statuspage":
                body = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
                indicator = body.get("status", {}).get("indicator", "none")
                description = body.get("status", {}).get("description", "All Systems Operational")
                if indicator == "none":
                    state = "ONLINE"
                elif indicator in ("minor", "maintenance"):
                    state = "DEGRADED"
                else:
                    state = "OFFLINE"
            elif ctype == "slack":
                body = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
                st = body.get("status", "ok")
                state = "ONLINE" if st == "ok" else "DEGRADED"
                description = "All Systems Operational" if st == "ok" else f"Slack Status: {st}"
            elif ctype == "meta":
                state = "ONLINE" if http_code == 200 else "DEGRADED"
                description = "Meta Graph & Services Nominal"
            elif ctype == "google":
                state = "ONLINE" if http_code == 200 else "DEGRADED"
                description = "Google Workspace Nominal"
            else:
                state = "ONLINE" if 200 <= http_code < 400 else "DEGRADED"
                description = f"HTTP {http_code} Reachable"

            return {
                "id": target["id"],
                "name": target["name"],
                "url": target["url"],
                "http_status": http_code,
                "latency_ms": latency_ms,
                "state": state,
                "detail": description
            }
    except urllib.error.HTTPError as e:
        latency_ms = int((time.time() - start) * 1000)
        # WAF/Bot protection on ISP pages (403) still proves the ISP edge router is up and responding
        if ctype == "http" and e.code in (401, 403, 405):
            return {
                "id": target["id"],
                "name": target["name"],
                "url": target["url"],
                "http_status": e.code,
                "latency_ms": latency_ms,
                "state": "ONLINE",
                "detail": f"Edge Active (HTTP {e.code})"
            }
        return {
            "id": target["id"],
            "name": target["name"],
            "url": target["url"],
            "http_status": e.code,
            "latency_ms": latency_ms,
            "state": "DEGRADED" if e.code == 429 else "OFFLINE",
            "detail": f"HTTP Error {e.code}"
        }
    except Exception:
        return {
            "id": target["id"],
            "name": target["name"],
            "url": target["url"],
            "http_status": 0,
            "latency_ms": 0,
            "state": "OFFLINE",
            "detail": "Connection Timeout / Unreachable"
        }

def push_to_backend(results, timestamp):
    if not APPS_SCRIPT_WEBHOOK:
        return
    payload = json.dumps({
        "type": "status_sync",
        "timestamp": timestamp,
        "nodes": results
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            APPS_SCRIPT_WEBHOOK,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"Backend webhook sync skipped or failed: {e}")

def fetch_sheet_targets():
    if not APPS_SCRIPT_WEBHOOK:
        return TARGETS
    try:
        url = APPS_SCRIPT_WEBHOOK + ("&" if "?" in APPS_SCRIPT_WEBHOOK else "?") + "action=outage_targets"
        req = urllib.request.Request(url, headers={"User-Agent": "H@N-Telemetry-Monitor/2.4.0"})
        with urllib.request.urlopen(req, timeout=10) as res:
            data = json.loads(res.read().decode("utf-8"))
            if isinstance(data.get("targets"), list) and len(data["targets"]) > 0:
                dynamic = []
                for row in data["targets"]:
                    if str(row.get("enabled", True)).upper() == "FALSE":
                        continue
                    dynamic.append({
                        "id": row.get("id") or row.get("Node ID", "NODE-X"),
                        "name": row.get("name") or row.get("Service Name", "Custom Node"),
                        "type": (row.get("type") or row.get("Check Type", "http")).lower(),
                        "url": row.get("url") or row.get("Endpoint URL", "")
                    })
                if dynamic:
                    return dynamic
    except Exception as e:
        print(f"Using default TARGETS (sheet fetch fallback): {e}")
    return TARGETS

def main():
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    active_targets = fetch_sheet_targets()
    results = [check_target(t) for t in active_targets]

    online_count = sum(1 for r in results if r["state"] == "ONLINE")
    outage_data = {
        "lastUpdated": now_iso,
        "summary": f"{online_count}/{len(results)} NODES NOMINAL",
        "services": results
    }

    with open("outages.json", "w", encoding="utf-8") as f:
        json.dump(outage_data, f, indent=2, ensure_ascii=False)

    push_to_backend(results, now_iso)
    print(f"[{now_iso}] Wrote outages.json ({online_count}/{len(results)} ONLINE)")

if __name__ == "__main__":
    main()
