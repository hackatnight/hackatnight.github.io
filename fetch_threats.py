"""
H@N Threat Intel Aggregator
Builds threat_feed.json for the "threat intel" box under the globe on hackatnight.com.

Sources (CISA, public, no keys):
  - Known Exploited Vulnerabilities (KEV) catalog
  - ICS / ICS-Medical advisories (CSAF files)
Both are read from CISA's own GitHub repositories first (reliable from GitHub Actions),
with cisa.gov as a fallback. If every source fails, the existing threat_feed.json is kept.

Location data for the globe:
  - ICS advisories carry "Countries/areas deployed" and "Company headquarters location" notes.
  - KEV entries carry only a vendor name, so they are pinned at the vendor's headquarters country
    when it is known (VENDOR_HQ below) and are always marked as exploited in the wild.

Testing: set THREAT_KEV_FILE and/or THREAT_CSAF_DIR to read local copies instead of the network.
"""
import csv
import io
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

OUTPUT = "threat_feed.json"
MAX_KEV = 15
MAX_ICS = 15
MAX_ITEMS = 30

KEV_URLS = [
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
]
CSAF_BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; H@N-Threat-Intel/1.0; +https://hackatnight.com)",
    "Accept": "application/json,text/csv,*/*",
}

# Country names as CISA writes them -> ISO code
COUNTRY_CODES = {
    "united states": "US", "usa": "US", "u.s.": "US", "canada": "CA", "mexico": "MX", "brazil": "BR",
    "peru": "PE", "el salvador": "SV", "dominican republic": "DO", "argentina": "AR", "chile": "CL",
    "colombia": "CO", "united kingdom": "GB", "uk": "GB", "ireland": "IE", "france": "FR", "germany": "DE",
    "switzerland": "CH", "austria": "AT", "italy": "IT", "spain": "ES", "portugal": "PT", "netherlands": "NL",
    "belgium": "BE", "luxembourg": "LU", "denmark": "DK", "sweden": "SE", "norway": "NO", "finland": "FI",
    "poland": "PL", "czechia": "CZ", "czech republic": "CZ", "slovakia": "SK", "slovenia": "SI", "hungary": "HU",
    "romania": "RO", "bulgaria": "BG", "greece": "GR", "cyprus": "CY", "latvia": "LV", "lithuania": "LT",
    "estonia": "EE", "ukraine": "UA", "russia": "RU", "turkey": "TR", "israel": "IL",
    "united arab emirates": "AE", "uae": "AE", "saudi arabia": "SA", "india": "IN", "nepal": "NP",
    "china": "CN", "taiwan": "TW", "japan": "JP", "south korea": "KR", "korea": "KR", "singapore": "SG",
    "vietnam": "VN", "thailand": "TH", "malaysia": "MY", "indonesia": "ID", "philippines": "PH",
    "australia": "AU", "new zealand": "NZ", "south africa": "ZA", "gambia": "GM", "egypt": "EG",
    "nigeria": "NG", "kenya": "KE",
}
REGION_KEYS = {
    "north america": "NA", "south america": "SA_CONT", "latin america": "SA_CONT", "europe": "EU",
    "asia": "AS", "middle east": "ME", "africa": "AF", "oceania": "OC",
}
WORLDWIDE_WORDS = ("worldwide", "global", "world-wide")

# KEV vendorProject -> headquarters country (best known; open-source projects intentionally omitted)
VENDOR_HQ = {
    "microsoft": "US", "cisco": "US", "apple": "US", "adobe": "US", "google": "US", "android": "US",
    "oracle": "US", "ivanti": "US", "fortinet": "US", "citrix": "US", "vmware": "US", "broadcom": "US",
    "sonicwall": "US", "synacor": "US", "zimbra": "US", "palo alto networks": "US", "qualcomm": "US",
    "solarwinds": "US", "ibm": "US", "red hat": "US", "progress": "US", "telerik": "US", "f5": "US",
    "juniper": "US", "juniper networks": "US", "netgear": "US", "gitlab": "US", "plex": "US", "n-able": "US",
    "arista": "US", "beyondtrust": "US", "connectwise": "US", "ubiquiti": "US", "watchguard": "US",
    "gladinet": "US", "fortra": "US", "nagios": "US", "accellion": "US", "barracuda networks": "US",
    "barracuda": "US", "smartertools": "US", "meta platforms": "US", "crushftp": "US", "qlik": "US",
    "veritas": "US", "dell": "US", "hp": "US", "hewlett packard enterprise": "US", "hpe": "US",
    "intel": "US", "nvidia": "US", "commvault": "US", "kaseya": "US", "mozilla": "US", "craft cms": "US",
    "samsung": "KR", "atlassian": "AU", "papercut": "AU", "sap": "DE", "siemens": "DE", "rarlab": "DE",
    "zyxel": "TW", "d-link": "TW", "dlink": "TW", "qnap": "TW", "draytek": "TW", "gigabyte": "TW",
    "asus": "TW", "realtek": "TW", "trend micro": "JP", "arm": "GB", "sophos": "GB", "simplehelp": "GB",
    "zoho": "IN", "mitel": "CA", "sangoma": "CA", "check point": "IL", "jfrog": "IL", "sysaid": "IL",
    "telemessage": "IL", "tp-link": "CN", "hikvision": "CN", "huawei": "CN", "dahua": "CN", "lenovo": "CN",
    "mikrotik": "LV", "jetbrains": "CZ", "kentico": "CZ", "sitecore": "DK", "veeam": "CH",
    "trueconf": "RU", "dassault systèmes": "FR", "dassault systemes": "FR", "schneider electric": "FR",
}


def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return res.read()


def clean(text, limit):
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text[:limit]


def parse_places(text):
    """Return (worldwide, [country codes], [region keys]) found in a free-text location string."""
    raw = str(text or "")
    low = raw.lower()
    worldwide = any(w in low for w in WORLDWIDE_WORDS)
    codes, regions = [], []
    # Longest names first so "south korea" wins over "korea", "united arab emirates" over "uae"
    for name in sorted(COUNTRY_CODES, key=len, reverse=True):
        if re.search(r"(?<![a-z])" + re.escape(name) + r"(?![a-z])", low):
            code = COUNTRY_CODES[name]
            if code not in codes:
                codes.append(code)
            low = re.sub(r"(?<![a-z])" + re.escape(name) + r"(?![a-z])", " ", low)
    for name, key in REGION_KEYS.items():
        if re.search(r"(?<![a-z])" + re.escape(name) + r"(?![a-z])", low) and key not in regions:
            regions.append(key)
    return worldwide, codes, regions


# ---------------------------------------------------------------- KEV
def load_kev():
    local = os.environ.get("THREAT_KEV_FILE")
    if local:
        with open(local, encoding="utf-8") as f:
            return json.load(f)
    for url in KEV_URLS:
        try:
            return json.loads(http_get(url))
        except Exception as e:
            print(f"[threat] KEV source failed: {url} ({e})")
    return None


def kev_items():
    data = load_kev()
    if not data or not isinstance(data.get("vulnerabilities"), list):
        return None
    vulns = sorted(
        data["vulnerabilities"],
        key=lambda v: (str(v.get("dateAdded", "")), str(v.get("cveID", ""))),
        reverse=True,
    )[:MAX_KEV]
    items = []
    for v in vulns:
        cve = clean(v.get("cveID"), 30)
        if not re.match(r"^CVE-\d{4}-\d+$", cve):
            continue
        vendor = clean(v.get("vendorProject"), 60)
        hq = VENDOR_HQ.get(vendor.lower().strip())
        ransomware = str(v.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"
        items.append({
            "id": cve,
            "source": "KEV",
            "title": clean(v.get("vulnerabilityName") or f"{vendor} {v.get('product', '')}", 160),
            "vendor": vendor,
            "product": clean(v.get("product"), 80),
            "date": clean(v.get("dateAdded"), 10),
            "due": clean(v.get("dueDate"), 10),
            "severity": "RANSOMWARE" if ransomware else "EXPLOITED",
            "summary": clean(v.get("shortDescription"), 280),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "geo": {
                "worldwide": True,                      # KEV = exploited in the wild, location unspecified
                "countries": [hq] if hq else [],
                "regions": [],
                "basis": "Vendor HQ" if hq else "Global (vendor HQ unknown)",
            },
        })
    return items


# ---------------------------------------------------------------- ICS (CSAF)
def csaf_get(path):
    local = os.environ.get("THREAT_CSAF_DIR")
    if local:
        with open(os.path.join(local, path), "rb") as f:
            return f.read()
    return http_get(CSAF_BASE + path)


def ics_items():
    try:
        changes = csaf_get("changes.csv").decode("utf-8", "replace")
    except Exception as e:
        print(f"[threat] CSAF changes.csv failed ({e})")
        return None
    paths = []
    for row in csv.reader(io.StringIO(changes)):
        if not row:
            continue
        path = row[0].strip()
        if re.match(r"^\d{4}/ics(?:m)?a-\d{2}-\d{3}-\d{2}\.json$", path) and path not in paths:
            paths.append(path)
        if len(paths) >= MAX_ICS:
            break

    items = []
    for path in paths:
        try:
            doc_all = json.loads(csaf_get(path))
        except Exception as e:
            print(f"[threat] CSAF {path} failed ({e})")
            continue
        doc = doc_all.get("document", {})
        notes = {str(n.get("title", "")).strip().lower(): str(n.get("text", "")) for n in doc.get("notes", [])}
        advisory_id = os.path.basename(path).replace(".json", "")
        deployed = notes.get("countries/areas deployed", "")
        hq_text = notes.get("company headquarters location", "")
        worldwide, dep_codes, regions = parse_places(deployed)
        _, hq_codes, _ = parse_places(hq_text)

        scores = []
        cves = []
        for v in doc_all.get("vulnerabilities", []):
            if v.get("cve"):
                cves.append(v["cve"])
            for s in v.get("scores", []):
                for key in ("cvss_v4", "cvss_v3"):
                    try:
                        scores.append(float(s.get(key, {}).get("baseScore")))
                    except (TypeError, ValueError):
                        pass
        top = max(scores) if scores else None
        if top is None:
            sev = "INFO"
        elif top >= 9:
            sev = "CRITICAL"
        elif top >= 7:
            sev = "HIGH"
        elif top >= 4:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        vendors = [b.get("name") for b in doc_all.get("product_tree", {}).get("branches", []) if b.get("name")]
        tracking = doc.get("tracking", {})
        # Use the latest release date so updated advisories ("Update A") sort by when they changed
        date = str(tracking.get("current_release_date") or tracking.get("initial_release_date") or "")[:10]
        kind = "ics-medical-advisories" if advisory_id.startswith("icsma") else "ics-advisories"
        items.append({
            "id": advisory_id.upper(),
            "source": "ICS-MED" if advisory_id.startswith("icsma") else "ICS",
            "title": clean(doc.get("title"), 160),
            "vendor": clean(", ".join(vendors[:2]), 60),
            "product": "",
            "date": date,
            "severity": sev,
            "cvss": top,
            "cves": len(cves),
            "sectors": clean(notes.get("critical infrastructure sectors", ""), 140),
            "summary": clean(f"Deployed: {deployed or 'n/a'}. Vendor HQ: {hq_text or 'n/a'}.", 280),
            "url": f"https://www.cisa.gov/news-events/{kind}/{advisory_id}",
            "geo": {
                "worldwide": worldwide,
                "countries": dep_codes,
                "regions": regions,
                "hq": hq_codes[:3],
                "basis": "Deployment areas" if (worldwide or dep_codes or regions) else ("Vendor HQ" if hq_codes else "Unknown"),
            },
        })
    return items


def main():
    kev = kev_items()
    ics = ics_items()
    if kev is None and ics is None:
        print("[threat] every source failed; keeping the existing threat_feed.json")
        return 0

    previous = {}
    if os.path.exists(OUTPUT):
        try:
            with open(OUTPUT, encoding="utf-8") as f:
                previous = json.load(f)
        except Exception:
            previous = {}
    prev_items = previous.get("items", []) if isinstance(previous, dict) else []
    # If one source failed this run, keep its last good items instead of dropping them
    if kev is None:
        kev = [i for i in prev_items if i.get("source") == "KEV"]
    if ics is None:
        ics = [i for i in prev_items if str(i.get("source", "")).startswith("ICS")]

    items = sorted(kev + ics, key=lambda i: (i.get("date", ""), i.get("id", "")), reverse=True)[:MAX_ITEMS]
    out = {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": [
            {"id": "KEV", "name": "CISA Known Exploited Vulnerabilities", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
            {"id": "ICS", "name": "CISA ICS Advisories", "url": "https://www.cisa.gov/news-events/ics-advisories"},
        ],
        "items": items,
    }
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[threat] wrote {OUTPUT}: {len(kev)} KEV + {len(ics)} ICS -> {len(items)} items")
    return 0


if __name__ == "__main__":
    sys.exit(main())
