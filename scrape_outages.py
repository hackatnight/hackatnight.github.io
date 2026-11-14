import urllib.request
import urllib.error
import json
import time
import os
from datetime import datetime, timezone

TARGETS = [
    {"id": "NODE-GH", "name": "GitHub Pages / API", "type": "statuspage", "url": "https://www.githubstatus.com/api/v2/status.json"},
    {"id": "NODE-CF", "name": "Cloudflare Edge", "type": "statuspage", "url": "https://www.cloudflarestatus.com/api/v2/status.json"},
    {"id": "NODE-DC", "name": "Discord Infra", "type": "statuspage", "url": "https://discordstatus.com/api/v2/status.json"},
    {"id": "NODE-OA", "name": "OpenAI API", "type": "statuspage", "url": "https://status.openai.com/api/v2/status.json"},
    {"id": "NODE-DO", "name": "DigitalOcean", "type": "statuspage", "url": "https://status.digitalocean.com/api/v2/status.json"},
    {"id": "NODE-01", "name": "HACKATNIGHT_CORE", "type": "http", "url": "https://hackatnight.com"},
    {"id": "NODE-02", "name": "GR33N_ORG_NODE", "type": "http", "url": "https://gr33n.org"}
]

APPS_SCRIPT_WEBHOOK = os.environ.get(
    "APPS_SCRIPT_WEBHOOK",
    "https://script.google.com/macros/s/AKfycbwjIa-86sZJdIEaH2B33IJAq5C1fv8k55KLur_NLZ_jZIIyMSHSWklse0K5P4blisuG/exec"
)

def check_target(target):
    req = urllib.request.Request(
        target["url"],
        headers={"User-Agent": "H@N-Telemetry-Monitor/2.3.0"}
    )
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            latency_ms = int((time.time() - start) * 1000)
            http_code = res.getcode()

            if target["type"] == "statuspage":
                body = json.loads(res.read().decode("utf-8"))
                indicator = body.get("status", {}).get("indicator", "none")
                description = body.get("status", {}).get("description", "All Systems Operational")

                if indicator == "none":
                    state = "ONLINE"
                elif indicator in ("minor", "maintenance"):
                    state = "DEGRADED"
                else:
                    state = "OFFLINE"
            else:
                state = "ONLINE" if http_code == 200 else "DEGRADED"
                description = f"HTTP {http_code} OK"

            return {
                "id": target["id"],
                "name": target["name"],
                "http_status": http_code,
                "latency_ms": latency_ms,
                "state": state,
                "detail": description
            }
    except urllib.error.HTTPError as e:
        latency_ms = int((time.time() - start) * 1000)
        return {
            "id": target["id"],
            "name": target["name"],
            "http_status": e.code,
            "latency_ms": latency_ms,
            "state": "DEGRADED" if e.code in (403, 429) else "OFFLINE",
            "detail": f"HTTP Error {e.code}"
        }
    except Exception:
        return {
            "id": target["id"],
            "name": target["name"],
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

def main():
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    results = [check_target(t) for t in TARGETS]

    online_count = sum(1 for r in results if r["state"] == "ONLINE")
    outage_data = {
        "lastUpdated": now_iso,
        "summary": f"{online_count}/{len(results)} NODES NOMINAL",
        "services": results
    }

    with open("outages.json", "w", encoding="utf-8") as f:
        json.dump(outage_data, f, indent=2)

    push_to_backend(results, now_iso)
    print(f"[{now_iso}] Wrote outages.json ({online_count}/{len(results)} ONLINE)")

if __name__ == "__main__":
    main()
