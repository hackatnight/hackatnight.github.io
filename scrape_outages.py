import urllib.request
import urllib.error
import urllib.parse
import json
import time
import os
import socket
from datetime import datetime, timezone

TARGETS = [
    {"id": "NODE-GH",      "name": "🐙 GitHub Pages / API",      "type": "statuspage", "url": "https://www.githubstatus.com/api/v2/status.json"},
    {"id": "NODE-CF",      "name": "☁️ Cloudflare Edge",         "type": "statuspage", "url": "https://www.cloudflarestatus.com/api/v2/status.json"},
    {"id": "NODE-META",    "name": "📘 Facebook / Meta",         "type": "meta",       "url": "https://metastatus.com/data/orgs.json"},
    {"id": "NODE-MS365",   "name": "🪟 Microsoft 365 / Azure",   "type": "http",       "url": "https://status.cloud.microsoft"},
    {"id": "NODE-OUTLOOK", "name": "📧 Microsoft Outlook",       "type": "http",       "url": "https://portal.office.com/servicestatus"},
    {"id": "NODE-EXCH",    "name": "🔄 MS Exchange Online",      "type": "http",       "url": "https://outlook.office365.com/owa/healthcheck.htm"},
    {"id": "NODE-GWS",     "name": "🌐 Google Workspace",        "type": "google",     "url": "https://www.google.com/appsstatus/dashboard/incidents.json"},
    {"id": "NODE-AWS",     "name": "🟧 Amazon Web Services",     "type": "aws",        "url": "https://health.aws.amazon.com/health/status"},
    {"id": "NODE-DC",      "name": "💬 Discord Infra",           "type": "statuspage", "url": "https://discordstatus.com/api/v2/status.json"},
    {"id": "NODE-OA",      "name": "🧠 OpenAI API",              "type": "statuspage", "url": "https://status.openai.com/api/v2/status.json"},
    {"id": "NODE-RD",      "name": "👽 Reddit",                  "type": "statuspage", "url": "https://www.redditstatus.com/api/v2/status.json"},
    {"id": "NODE-SLK",     "name": "💼 Slack",                   "type": "slack",      "url": "https://status.slack.com/api/v2.0.0/current"},
    {"id": "NODE-ZM",      "name": "📹 Zoom",                    "type": "statuspage", "url": "https://status.zoom.us/api/v2/status.json"},
    {"id": "NODE-DO",      "name": "🌊 DigitalOcean",            "type": "statuspage", "url": "https://status.digitalocean.com/api/v2/status.json"},
    {"id": "NODE-XFIN",    "name": "📡 Comcast / Xfinity ISP",   "type": "radar:7922",       "url": "https://www.xfinity.com/support/status"},
    {"id": "NODE-SPEC",    "name": "📡 Spectrum / Charter ISP",  "type": "radar:20115,33363",       "url": "https://www.spectrum.net/support/internet/outage"},
    {"id": "NODE-ATT",     "name": "📡 AT&T Fiber / ISP",        "type": "radar:7018",       "url": "https://www.att.com/outages/"},
    {"id": "NODE-VZ",      "name": "📡 Verizon Fios / ISP",      "type": "radar:701,6167",       "url": "https://www.verizon.com/support/check-network-status/"},
    {"id": "NODE-CORE",    "name": "🛡️ HACKATNIGHT_CORE",        "type": "http",       "url": "https://hackatnight.com"}
]

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 H@N-Telemetry/2.5",
    "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

APPS_SCRIPT_WEBHOOK = os.environ.get("APPS_SCRIPT_WEBHOOK", "").strip() or "https://script.google.com/macros/s/AKfycbwjIa-86sZJdIEaH2B33IJAq5C1fv8k55KLur_NLZ_jZIIyMSHSWklse0K5P4blisuG/exec"

# ---------- Status checks ----------
# Check types (Outage_Targets "Check Type" column):
#   statuspage      Atlassian Statuspage /api/v2/status.json (official indicator)
#   slack           Slack status API
#   google          Google Workspace incidents.json (ongoing incidents)
#   meta            Meta orgs.json (any service not "No known issues")
#   aws             AWS Health public current-events feed (URL column stays the human status page)
#   azure           Azure status RSS feed (URL column stays the human status page)
#   radar:<asn,...> ISP network health from Cloudflare Radar outages + traffic anomalies for those ASNs
#   http            Page reachability only. A 2xx means the page loads; a block page (403 etc.) proves nothing,
#                   so it is UNVERIFIED rather than ONLINE.
AWS_EVENTS_URL = "https://health.aws.amazon.com/public/currentevents"
AZURE_FEED_URL = "https://azure.status.microsoft/en-us/status/feed/"
RADAR_TOKEN = os.environ.get("CLOUDFLARE_RADAR_TOKEN", "").strip()

def fetch(url, headers=None, limit=4 * 1024 * 1024, timeout=15):
    req = urllib.request.Request(url, headers=headers or BROWSER_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return res.getcode(), res.read(limit)

def decode_json(raw):
    # AWS serves UTF-16 with a BOM; everyone else UTF-8
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return json.loads(raw.decode("utf-16"))
    return json.loads(raw.decode("utf-8-sig", errors="ignore"))

def result(target, code, latency, state, detail):
    return {"id": target["id"], "name": target["name"], "url": target["url"],
            "http_status": code, "latency_ms": latency, "state": state, "detail": detail}

def short(text, n=70):
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"

def radar_get(path):
    req = urllib.request.Request("https://api.cloudflare.com/client/v4/radar/" + path,
                                 headers={"Authorization": "Bearer " + RADAR_TOKEN, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as res:
        return json.loads(res.read().decode("utf-8")).get("result", {})

def check_radar(target, asns):
    if not RADAR_TOKEN:
        return result(target, 0, 0, "UNVERIFIED", "Cloudflare Radar token missing")
    start = time.time()
    outages, anomalies, ok_calls = [], [], 0
    for asn in asns:
        try:
            for a in radar_get(f"annotations/outages?asn={asn}&dateRange=7d&limit=10&format=json").get("annotations", []):
                if not a.get("endDate"):
                    outages.append(a)
            ok_calls += 1
        except Exception as e:
            print(f"Radar outages lookup failed for AS{asn}: {e}")
        try:
            for a in radar_get(f"traffic_anomalies?asn={asn}&dateRange=1d&limit=10&format=json").get("trafficAnomalies", []):
                if not a.get("endDate"):
                    anomalies.append(a)
            ok_calls += 1
        except Exception as e:
            print(f"Radar anomaly lookup failed for AS{asn}: {e}")
    latency = int((time.time() - start) * 1000)
    if not ok_calls:
        return result(target, 0, latency, "UNVERIFIED", "Cloudflare Radar lookup failed")
    if outages:
        o = outages[0]
        cause = (o.get("outage") or {}).get("outageCause", "")
        return result(target, 200, latency, "OFFLINE", short("Internet outage: " + (o.get("description") or cause or "confirmed by Cloudflare Radar")))
    verified = [a for a in anomalies if str(a.get("status", "")).upper() == "VERIFIED"]
    if verified or anomalies:
        tag = "Verified" if verified else "Possible"
        return result(target, 200, latency, "DEGRADED", f"{tag} traffic drop on network (Cloudflare Radar)")
    return result(target, 200, latency, "ONLINE", "No network disruptions (Cloudflare Radar)")

def check_target(target):
    ctype = (target.get("type") or "http").strip().lower()
    if ctype.startswith("radar"):
        asns = [a.strip().upper().replace("AS", "") for a in ctype.split(":", 1)[-1].split(",") if a.strip()]
        asns = [a for a in asns if a.isdigit()]
        if asns:
            return check_radar(target, asns)
        ctype = "http"

    url = {"aws": AWS_EVENTS_URL, "azure": AZURE_FEED_URL}.get(ctype, target["url"])
    start = time.time()
    try:
        code, raw = fetch(url)
        latency = int((time.time() - start) * 1000)

        if ctype == "statuspage":
            body = decode_json(raw)
            indicator = body.get("status", {}).get("indicator", "none")
            desc = body.get("status", {}).get("description", "All Systems Operational")
            state = "ONLINE" if indicator == "none" else "DEGRADED" if indicator in ("minor", "maintenance") else "OFFLINE"
            return result(target, code, latency, state, desc)

        if ctype == "slack":
            st = decode_json(raw).get("status", "ok")
            return result(target, code, latency, "ONLINE" if st == "ok" else "DEGRADED",
                          "All Systems Operational" if st == "ok" else f"Slack Status: {st}")

        if ctype == "google":
            ongoing = [i for i in decode_json(raw) if not i.get("end")]
            if not ongoing:
                return result(target, code, latency, "ONLINE", "No active Google Workspace incidents")
            worst = "OFFLINE" if any(i.get("severity") == "high" for i in ongoing) else "DEGRADED"
            return result(target, code, latency, worst, short(f"{len(ongoing)} active: {ongoing[0].get('service_name', '')} - {ongoing[0].get('external_desc', '')}"))

        if ctype == "meta":
            issues = [(o.get("name", ""), s.get("name", ""), s.get("status", ""))
                      for o in decode_json(raw) for s in o.get("services", [])
                      if str(s.get("status", "")).strip().lower() not in ("", "no known issues")]
            if not issues:
                return result(target, code, latency, "ONLINE", "No known issues across Meta products")
            return result(target, code, latency, "DEGRADED", short(f"{len(issues)} issue(s): {issues[0][0]} {issues[0][1]} - {issues[0][2]}"))

        if ctype == "aws":
            events = decode_json(raw) if raw.strip() else []
            if not events:
                return result(target, code, latency, "ONLINE", "No active AWS service events")
            levels = [int(v.get("current", 0) or 0) for e in events for v in (e.get("impacted_services") or {}).values()]
            levels += [int(e.get("status", 0) or 0) for e in events]
            worst = max(levels or [1])
            state = "OFFLINE" if worst >= 3 else "DEGRADED" if worst >= 2 else "ONLINE"
            e0 = events[0]
            return result(target, code, latency, state, short(f"{len(events)} event(s): {e0.get('service_name', '')} {e0.get('region_name', '')} - {e0.get('summary', '')}"))

        if ctype == "azure":
            text = raw.decode("utf-8", errors="ignore")
            items = text.count("<item>") + text.count("<item ")
            if not items:
                return result(target, code, latency, "ONLINE", "No active Azure incidents")
            title = text.split("<item", 1)[1].split("<title>", 1)[-1].split("</title>", 1)[0] if "<title>" in text.split("<item", 1)[1] else ""
            return result(target, code, latency, "DEGRADED", short(f"{items} active: {title.replace('<![CDATA[', '').replace(']]>', '')}"))

        # Plain page check
        if 200 <= code < 400:
            return result(target, code, latency, "ONLINE", f"Page reachable (HTTP {code}) // no status feed")
        return result(target, code, latency, "UNVERIFIED", f"HTTP {code}")
    except urllib.error.HTTPError as e:
        latency = int((time.time() - start) * 1000)
        if e.code >= 500:
            return result(target, e.code, latency, "OFFLINE", f"Server error (HTTP {e.code})")
        if e.code == 429:
            return result(target, e.code, latency, "UNVERIFIED", "Rate limited (HTTP 429)")
        # 4xx: the site answered but refused or blocked the check, so we can't tell either way
        return result(target, e.code, latency, "UNVERIFIED", f"Blocked by site (HTTP {e.code}) // can't verify")
    except Exception as e:
        is_timeout = isinstance(e, (TimeoutError, socket.timeout)) or "timed out" in str(e).lower()
        if ctype in ("statuspage", "slack", "google", "meta", "aws", "azure") and isinstance(e, ValueError):
            return result(target, 0, 0, "UNVERIFIED", "Status feed format changed")
        return result(target, 0, 0, "OFFLINE",
                      "Probe timed out (may block GitHub runners)" if is_timeout else "Connection failed / unreachable")

# ---------- Redundancy: an independent second source per target ----------
# ISPs: IODA (Georgia Tech Internet Outage Detection & Analysis) alerts for the same ASNs.
# Online services: a direct check of the service itself (not its status page). Any answer below 500 means
# the service's front door is up (401/403/404 from an API are normal); 5xx or no answer means it is not.
SECOND_PROBES = [
    ("githubstatus.com",     "GitHub.com",            "https://github.com/"),
    ("cloudflarestatus.com", "Cloudflare edge",       "https://www.cloudflare.com/cdn-cgi/trace"),
    ("openai.com",           "OpenAI API",            "https://api.openai.com/v1/models"),
    ("slack.com",            "Slack API",             "https://slack.com/api/api.test"),
    ("zoom.us",              "Zoom.us",               "https://zoom.us/"),
    ("discordstatus.com",    "Discord API",           "https://discord.com/api/v10/gateway"),
    ("redditstatus.com",     "Reddit.com",            "https://www.reddit.com/robots.txt"),
    ("digitalocean.com",     "DigitalOcean API",      "https://api.digitalocean.com/v2/"),
    ("google.com",           "Gmail",                 "https://mail.google.com/mail/"),
    ("metastatus.com",       "Meta Graph API",        "https://graph.facebook.com/"),
    ("aws.amazon.com",       "AWS S3 endpoint",       "https://s3.amazonaws.com/"),
    ("azure.status.microsoft", "Azure management API", "https://management.azure.com/"),
    ("cloud.microsoft",      "Azure management API",  "https://management.azure.com/"),
    ("office.com",           "Microsoft sign-in",     "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"),
    ("office365.com",        "Microsoft sign-in",     "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"),
]
IODA_URL = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/alerts?entityType=asn&entityCode={asn}&from={frm}&until={until}"

def second_probe(target):
    host = (urllib.parse.urlparse(target["url"]).hostname or "").lower()
    match = next(((n, u) for d, n, u in SECOND_PROBES if host == d or host.endswith("." + d)), None)
    if not match:
        return None
    name, url = match
    start = time.time()
    try:
        code, _ = fetch(url, limit=2048, timeout=12)
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        return {"source": name, "state": "DOWN", "detail": "no response" if "timed out" in str(e).lower() else "connection failed"}
    ms = int((time.time() - start) * 1000)
    return {"source": name, "state": "DOWN" if code >= 500 else "ONLINE", "detail": f"HTTP {code} in {ms} ms"}

def ioda_check(asns):
    now = int(time.time())
    levels, ok = [], 0
    for asn in asns:
        try:
            req = urllib.request.Request(IODA_URL.format(asn=asn, frm=now - 3 * 3600, until=now),
                                         headers={"User-Agent": "H@N-Telemetry-Monitor/2.9"})
            with urllib.request.urlopen(req, timeout=15) as res:
                alerts = json.loads(res.read().decode("utf-8")).get("data") or []
            ok += 1
            # Latest alert per data source decides that source's current level
            latest = {}
            for a in alerts:
                src = a.get("datasource", "?")
                if src not in latest or a.get("time", 0) > latest[src].get("time", 0):
                    latest[src] = a
            levels += [str(a.get("level", "normal")).lower() for a in latest.values()]
        except Exception as e:
            print(f"IODA lookup failed for AS{asn}: {e}")
    if not ok:
        return None
    if "critical" in levels:
        return {"source": "IODA (Georgia Tech)", "state": "DOWN", "detail": "outage alert on network"}
    if "warning" in levels:
        return {"source": "IODA (Georgia Tech)", "state": "DEGRADED", "detail": "warning on network"}
    return {"source": "IODA (Georgia Tech)", "state": "ONLINE", "detail": "no alerts in last 3 h"}

PRIMARY_NAMES = {"statuspage": "Official status page", "slack": "Official status API", "google": "Official incident feed",
                 "meta": "Official status feed", "aws": "AWS Health feed", "azure": "Azure status feed", "http": "Page check"}

def cross_check(target, r):
    ctype = (target.get("type") or "http").strip().lower()
    if ctype.startswith("radar"):
        asns = [a.strip().upper().replace("AS", "") for a in ctype.split(":", 1)[-1].split(",") if a.strip().replace("AS", "").replace("as", "").isdigit()]
        second = ioda_check(asns) if asns else None
        primary_name = "Cloudflare Radar"
    else:
        second = second_probe(target)
        primary_name = PRIMARY_NAMES.get(ctype, "Primary check")
    r["sources"] = [{"source": primary_name, "state": r["state"], "detail": r["detail"]}]
    if not second:
        r["agree"] = "1 source"
        return r
    r["sources"].append(second)
    p, s2 = r["state"], second["state"]
    if p == "ONLINE" and s2 == "ONLINE":
        r["agree"] = "2/2 agree"
    elif p == "ONLINE":
        # Status page says fine but the independent check disagrees
        r["state"], r["agree"] = "DEGRADED", "sources disagree"
        r["detail"] = f"{second['source']}: {second['detail']} // official status says operational"
    elif p == "UNVERIFIED":
        r["state"] = "ONLINE" if s2 == "ONLINE" else "DEGRADED"
        r["agree"] = "1/2 (primary blocked)"
        r["detail"] = f"{second['source']} {'reachable' if s2 == 'ONLINE' else second['detail']} // {r['detail']}"
    elif s2 == "ONLINE":
        r["agree"] = "sources disagree"   # official incident, but the service still answers (partial outage)
    else:
        r["agree"] = "2/2 agree"
        if ctype.startswith("radar") and "DOWN" in (s2,):
            r["state"] = "OFFLINE"
    return r

# ---------- Server location lookup ----------
# Each target's hostname is resolved from the GitHub runner and the IP is geolocated (ipwho.is, no key needed).
# Big providers sit behind CDNs/anycast, so for them this is the edge or network location, not a single
# data center; those are flagged with "cdn" so the site can say so. Results are cached for a day in outages.json.
GEO_TTL_SEC = 24 * 3600
CDN_HINTS = ["cloudflare", "akamai", "fastly", "cloudfront", "amazon", "google", "microsoft", "azure",
             "edgecast", "edgio", "incapsula", "imperva", "stackpath", "bunny", "verizon digital"]

def load_geo_cache():
    try:
        with open("outages.json", encoding="utf-8") as f:
            old = json.load(f)
        return {s.get("geo", {}).get("host"): s["geo"] for s in old.get("services", []) if isinstance(s.get("geo"), dict)}
    except Exception:
        return {}

def locate_host(url, cache):
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return None
    if not host:
        return None
    cached = cache.get(host)
    if cached and time.time() - cached.get("checked", 0) < GEO_TTL_SEC:
        return cached
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET)[0][4][0]
        fields = "success,city,region,country,country_code,latitude,longitude,connection"
        req = urllib.request.Request(f"https://ipwho.is/{ip}?fields={fields}", headers={"User-Agent": "H@N-Telemetry-Monitor/2.8"})
        with urllib.request.urlopen(req, timeout=8) as res:
            j = json.loads(res.read().decode("utf-8"))
        if not j.get("success"):
            return cached
        conn = j.get("connection") or {}
        network = str(conn.get("org") or conn.get("isp") or "").strip()
        low = network.lower()
        cdn = next((h for h in CDN_HINTS if h in low), "")
        return {
            "host": host,
            "ip": ip,
            "city": j.get("city") or "",
            "region": j.get("region") or "",
            "country": j.get("country") or "",
            "countryCode": j.get("country_code") or "",
            "lat": round(float(j.get("latitude") or 0), 3),
            "lon": round(float(j.get("longitude") or 0), 3),
            "network": network[:60],
            "asn": conn.get("asn") or "",
            "cdn": bool(cdn),
            "checked": int(time.time()),
        }
    except Exception as e:
        print(f"Geo lookup skipped for {host}: {e}")
        return cached

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
    results = [cross_check(t, check_target(t)) for t in active_targets]
    geo_cache = load_geo_cache()
    for t, r in zip(active_targets, results):
        r["type"] = t.get("type", "http")
        geo = locate_host(t["url"], geo_cache)
        if geo:
            r["geo"] = geo
            geo_cache[geo["host"]] = geo

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
