import urllib.request
import json
import subprocess
import re
import os
from datetime import datetime, timezone

APPS_SCRIPT_WEBHOOK = os.environ.get("APPS_SCRIPT_WEBHOOK", "").strip() or "https://script.google.com/macros/s/AKfycbwjIa-86sZJdIEaH2B33IJAq5C1fv8k55KLur_NLZ_jZIIyMSHSWklse0K5P4blisuG/exec"

def get_latest_commit():
    try:
        msg = subprocess.check_output(["git", "log", "-1", "--pretty=%s"], text=True).strip()
        sha = subprocess.check_output(["git", "log", "-1", "--pretty=%h"], text=True).strip()
        author = subprocess.check_output(["git", "log", "-1", "--pretty=%an"], text=True).strip()
        return msg, sha, author
    except Exception:
        return "Manual deployment update", "HEAD", "gr33n"

def extract_app_version():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            content = f.read()
        m = re.search(r'APP_VERSION:\s*["\']([^"\']+)["\']', content)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "v.2.8.2"

def classify_commit(msg):
    low = msg.lower()
    if low.startswith("feat") or "release" in low:
        return "🟢 FEAT"
    if low.startswith("fix") or "bug" in low or "repair" in low:
        return "🟠 FIX"
    if low.startswith("chore") or "ci" in low or "workflow" in low:
        return "🟣 INFRA"
    return "🔵 UPDATE"

def main():
    msg, sha, author = get_latest_commit()
    # Skip automated bot commits from outages.json sync so they don't spam the Changelog tab
    if "chore(telemetry): update live outages.json" in msg or author == "hackatnight-bot":
        print(f"Skipping automated telemetry commit ({sha}): {msg}")
        return

    version = extract_app_version()
    tag = classify_commit(msg)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    payload = {
        "action": "changelog_sync",
        "date": date_str,
        "version": version,
        "project": "H@N Core",
        "summary": f"{msg[:380]} ({sha})",
        "tag": tag
    }

    try:
        req = urllib.request.Request(
            APPS_SCRIPT_WEBHOOK,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as res:
            resp_text = res.read().decode("utf-8")
            print(f"[{date_str}] Logged commit {sha} ({version}) to Changelog tab: {resp_text}")
    except Exception as e:
        print(f"Failed to log changelog to backend: {e}")

if __name__ == "__main__":
    main()
