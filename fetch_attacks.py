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


def geolocate_networks(nets, prev_nets):
    """Adds city/state/company to each DShield /24 by looking up its first host IP (ipwho.is, no key).
    Results are reused from the previous run for the same network, so each block is looked up once."""
    cache = {n.get("network"): n.get("geo") for n in (prev_nets or []) if n.get("geo")}
    for n in nets:
        if n.get("geo"):
            continue
        if cache.get(n["network"]):
            n["geo"] = cache[n["network"]]
            continue
        try:
            base = n["network"].split("/")[0].split(".")
            ip = ".".join(base[:3] + [str(int(base[3]) + 1)])
            fields = "success,city,region,country_code,latitude,longitude,connection"
            j = json.loads(http_get(f"https://ipwho.is/{ip}?fields={fields}", timeout=10))
            if not j.get("success"):
                continue
            conn = j.get("connection") or {}
            n["geo"] = {
                "city": str(j.get("city") or "")[:40],
                "region": str(j.get("region") or "")[:40],
                "countryCode": str(j.get("country_code") or "")[:2],
                "lat": round(float(j.get("latitude") or 0), 3),
                "lon": round(float(j.get("longitude") or 0), 3),
                "org": str(conn.get("org") or conn.get("isp") or "")[:60],
                "asn": conn.get("asn") or "",
            }
        except Exception as e:
            print(f"[attacks] geo lookup skipped for {n.get('network')}: {e}")
    located = sum(1 for n in nets if n.get("geo"))
    print(f"[attacks] DShield: {located}/{len(nets)} networks located to city level")
    return nets


def fetch_dshield(previous):
    local = os.environ.get("ATTACK_DSHIELD_FILE")
    prev = (previous or {}).get("dshield") or {}
    if not local:
        last = prev.get("fetched")
        try:
            if last and now_utc() - datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) < DSHIELD_MIN_AGE:
                print("[attacks] DShield: fetched less than an hour ago, reusing")
                if prev.get("networks") and not all(n.get("geo") for n in prev["networks"]):
                    prev = dict(prev, networks=geolocate_networks([dict(n) for n in prev["networks"]], prev["networks"]))
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
        nets = geolocate_networks(nets, prev.get("networks"))
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
    # Companies/networks behind the most web (layer 7) attacks; Radar gives names, not locations or targets
    try:
        payload = json.loads(http_get(CF_BASE + "layer7/top/ases/origin?limit=10&dateRange=1d&format=json",
                                      headers={"Authorization": f"Bearer {token}"}))
        rows = ((payload.get("result") or {}).get("top_0")) or []
        out["topAses"] = [{"asn": str(r.get("originAsn", ""))[:12], "name": str(r.get("originAsnName", ""))[:60],
                           "value": round(float(r.get("value", 0) or 0), 3)} for r in rows][:10]
        print(f"[attacks] Cloudflare top attacking networks: {len(out['topAses'])}")
    except Exception as e:
        print(f"[attacks] Cloudflare top ASes failed: {e}; keeping previous data")
        out["topAses"] = prev.get("topAses", [])
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
