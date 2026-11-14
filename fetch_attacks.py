"""
H@N Attack Map Fetcher
Builds attack_map.json for the attack layer on the hackatnight.com globe.

Sources:
  - Cloudflare Radar: top origin -> target country pairs for layer 3 (network/DDoS) and
    layer 7 (application) attacks over the last 24 hours. Needs a free API token in the
    CLOUDFLARE_RADAR_TOKEN environment variable (GitHub secret). Skipped when it is missing.
  - SANS ISC DShield: top 20 most active scanning/attacking networks with their country
    (https://feeds.dshield.org/block.txt). No key needed. Data use requires attribution to
    SANS Technology Institute, Internet Storm Center, and DShield asks feeds not be pulled
    more than once an hour, so this script only refetches it after 55 minutes.

Each part keeps its last good data when a fetch fails. Nothing is written if nothing changed.
Testing: set ATTACK_DSHIELD_FILE / ATTACK_CF_L3_FILE / ATTACK_CF_L7_FILE to local files.
"""
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

OUTPUT = "attack_map.json"
DSHIELD_URL = "https://feeds.dshield.org/block.txt"
DSHIELD_MIN_AGE = timedelta(minutes=55)
CF_BASE = "https://api.cloudflare.com/client/v4/radar/attacks/"
CF_QUERY = "top/attacks?limit=25&dateRange=1d&limitDirection=ORIGIN&limitPerLocation=4&format=json"
UA = "Mozilla/5.0 (compatible; H@N-Attack-Map/1.0; +https://hackatnight.com)"


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def http_get(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=dict({"User-Agent": UA}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return res.read()


# ---------------------------------------------------------------- DShield
def parse_dshield(text):
    nets = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) < 6:
            continue
        start, _end, bits, count, name, cc = [c.strip() for c in cols[:6]]
        cc = cc.upper()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", start) or not re.match(r"^[A-Z]{2}$", cc):
            continue
        try:
            count = int(count)
            bits = int(bits)
        except ValueError:
            continue
        nets.append({
            "network": f"{start}/{bits}",
            "name": name[:60],
            "country": cc,
            "targets": count,
        })
    return nets[:20]


def fetch_dshield(previous):
    local = os.environ.get("ATTACK_DSHIELD_FILE")
    prev = (previous or {}).get("dshield") or {}
    if not local:
        last = prev.get("fetched")
        try:
            if last and now_utc() - datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) < DSHIELD_MIN_AGE:
                print("[attacks] DShield: fetched less than an hour ago, reusing")
                return prev
        except ValueError:
            pass
    try:
        if local:
            with open(local, encoding="utf-8") as f:
                text = f.read()
        else:
            text = http_get(DSHIELD_URL).decode("utf-8", "replace")
        nets = parse_dshield(text)
        if not nets:
            raise ValueError("no rows parsed")
        print(f"[attacks] DShield: {len(nets)} networks")
        return {
            "fetched": iso(now_utc()),
            "networks": nets,
            "attribution": "SANS Technology Institute, Internet Storm Center (DShield), https://isc.sans.edu",
        }
    except Exception as e:
        print(f"[attacks] DShield failed: {e}; keeping previous data")
        return prev or None


# ---------------------------------------------------------------- Cloudflare Radar
def parse_pairs(payload):
    result = (payload or {}).get("result") or {}
    rows = result.get("top_0") or []
    pairs = []
    for r in rows:
        o = str(r.get("originCountryAlpha2", "")).upper()
        t = str(r.get("targetCountryAlpha2", "")).upper()
        if not (re.match(r"^[A-Z]{2}$", o) and re.match(r"^[A-Z]{2}$", t)):
            continue
        try:
            value = round(float(r.get("value", 0)), 3)
        except (TypeError, ValueError):
            continue
        pairs.append({
            "origin": o,
            "originName": str(r.get("originCountryName", o))[:60],
            "target": t,
            "targetName": str(r.get("targetCountryName", t))[:60],
            "value": value,
        })
    return pairs


def fetch_cloudflare(previous):
    prev = (previous or {}).get("cloudflare") or {}
    token = os.environ.get("CLOUDFLARE_RADAR_TOKEN", "").strip()
    local = {"layer3": os.environ.get("ATTACK_CF_L3_FILE"), "layer7": os.environ.get("ATTACK_CF_L7_FILE")}
    if not token and not any(local.values()):
        print("[attacks] Cloudflare Radar: no CLOUDFLARE_RADAR_TOKEN secret yet, skipping")
        return {"enabled": False}
    out = {"enabled": True, "fetched": iso(now_utc()), "window": "24h",
           "attribution": "Cloudflare Radar, https://radar.cloudflare.com"}
    for layer in ("layer3", "layer7"):
        try:
            if local[layer]:
                with open(local[layer], encoding="utf-8") as f:
                    payload = json.load(f)
            else:
                payload = json.loads(http_get(CF_BASE + layer + "/" + CF_QUERY,
                                              headers={"Authorization": f"Bearer {token}"}))
            if not payload.get("success", True):
                raise ValueError(str(payload.get("errors"))[:200])
            out[layer] = parse_pairs(payload)
            print(f"[attacks] Cloudflare {layer}: {len(out[layer])} origin->target pairs")
        except Exception as e:
            # Never print the token; only the error text
            print(f"[attacks] Cloudflare {layer} failed: {e}; keeping previous data")
            out[layer] = prev.get(layer, [])
    return out


def main():
    previous = {}
    if os.path.exists(OUTPUT):
        try:
            with open(OUTPUT, encoding="utf-8") as f:
                previous = json.load(f)
        except Exception:
            previous = {}

    dshield = fetch_dshield(previous)
    cloudflare = fetch_cloudflare(previous)
    data = {"dshield": dshield, "cloudflare": cloudflare}
    old = {"dshield": previous.get("dshield"), "cloudflare": previous.get("cloudflare")}
    if data == old:
        print("[attacks] no changes")
        return 0
    data["updated"] = iso(now_utc())
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[attacks] wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
