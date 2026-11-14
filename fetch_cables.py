"""
H@N Submarine Cable Fetcher
Builds cables.json (submarine telecom cables) for the hackatnight.com globe from OpenStreetMap via the
Overpass API. Data (c) OpenStreetMap contributors, licensed under the ODbL (https://www.openstreetmap.org/copyright);
the site shows that attribution whenever cables are drawn.

Runs from the telemetry workflow but only refetches once a day. Keeps the previous file on any failure.
"""
import json
import math
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

OUTPUT = "cables.json"
MAX_AGE = timedelta(hours=23)
ENDPOINTS = ["https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter"]
QUERY = """
[out:json][timeout:240];
(
  way["communication"="line"]["submarine"="yes"];
  way["communication"="line"]["location"~"^(underwater|submarine)$"];
  way["telecom"="line"]["submarine"="yes"];
  way["telecom"="line"]["location"~"^(underwater|submarine)$"];
  way["seamark:type"="cable_submarine"]["seamark:cable_submarine:category"~"tele|communication",i];
);
out tags geom;
"""
UA = "H@N-Cable-Map/1.0 (+https://hackatnight.com)"


def now():
    return datetime.now(timezone.utc)


def dp(pts, tol):
    """Douglas-Peucker line simplification (degrees)."""
    if len(pts) < 3:
        return pts
    ax, ay = pts[0]
    bx, by = pts[-1]
    dx, dy = bx - ax, by - ay
    norm = math.hypot(dx, dy) or 1e-12
    dmax, idx = 0.0, 0
    for i in range(1, len(pts) - 1):
        px, py = pts[i]
        d = abs(dy * px - dx * py + bx * ay - by * ax) / norm if (dx or dy) else math.hypot(px - ax, py - ay)
        if d > dmax:
            dmax, idx = d, i
    if dmax > tol:
        return dp(pts[: idx + 1], tol)[:-1] + dp(pts[idx:], tol)
    return [pts[0], pts[-1]]


def length_km(pts):
    total = 0.0
    for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
        p1, p2 = math.radians(y1), math.radians(y2)
        dl = math.radians(x2 - x1)
        c = math.sin(p1) * math.sin(p2) + math.cos(p1) * math.cos(p2) * math.cos(dl)
        total += 6371 * math.acos(max(-1.0, min(1.0, c)))
    return total


def main():
    previous = None
    if os.path.exists(OUTPUT):
        try:
            with open(OUTPUT, encoding="utf-8") as f:
                previous = json.load(f)
            updated = datetime.strptime(previous.get("updated", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if now() - updated < MAX_AGE and not os.environ.get("CABLES_FORCE"):
                print("[cables] fetched within the last day, skipping")
                return 0
        except Exception:
            pass

    data = None
    for url in ENDPOINTS:
        try:
            req = urllib.request.Request(url, data=urllib.parse.urlencode({"data": QUERY}).encode(),
                                         headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=300) as res:
                data = json.loads(res.read().decode("utf-8"))
            print(f"[cables] {url}: {len(data.get('elements', []))} ways")
            break
        except Exception as e:
            print(f"[cables] {url} failed: {e}")
            time.sleep(5)
    if not data:
        print("[cables] all endpoints failed; keeping previous file")
        return 0

    # Group segments by cable name; unnamed bits are kept only if they are long (real cable spans)
    groups = {}
    for el in data.get("elements", []):
        geom = el.get("geometry") or []
        pts = [(round(g["lon"], 3), round(g["lat"], 3)) for g in geom if "lon" in g and "lat" in g]
        if len(pts) < 2:
            continue
        tags = el.get("tags") or {}
        name = (tags.get("name") or tags.get("name:en") or tags.get("seamark:name") or "").strip()
        km = length_km(pts)
        if not name and km < 150:
            continue
        key = name or f"Unnamed cable {el.get('id')}"
        g = groups.setdefault(key, {"n": key, "op": "", "km": 0.0, "lines": []})
        if not g["op"]:
            g["op"] = (tags.get("operator") or tags.get("owner") or "").strip()[:80]
        g["km"] += km
        g["lines"].append(pts)

    cables, total_pts = [], 0
    for g in sorted(groups.values(), key=lambda x: -x["km"]):
        if g["km"] < 20:
            continue
        lines = []
        for pts in g["lines"]:
            s = dp(pts, 0.03)
            if len(s) >= 2:
                lines.append([[round(x, 2), round(y, 2)] for x, y in s])
        if not lines:
            continue
        total_pts += sum(len(l) for l in lines)
        cables.append({"n": g["n"][:80], "op": g["op"], "km": int(g["km"]), "p": lines})

    if len(cables) < 20:
        print(f"[cables] only {len(cables)} cables parsed; keeping previous file")
        return 0
    out = {
        "source": "OpenStreetMap contributors (ODbL), https://www.openstreetmap.org/copyright",
        "updated": now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(cables),
        "cables": cables,
    }
    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"), ensure_ascii=False)
    print(f"[cables] wrote {OUTPUT}: {len(cables)} cables, {total_pts} points, {os.path.getsize(OUTPUT) // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
