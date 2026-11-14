# H@N v.2.5.10 — Bug fixing and security

_Released 2026-11-14_

Bug fixing and security release covering v.2.5.6 – v.2.5.10.

## Security
- **HTML injection fixed (v.2.5.8):** all sheet and visitor-supplied data (visit paths, regions, triage, changelog, projects, downloads, uptime, outage cards) is HTML-escaped before display; project/download links only accept `http(s)` URLs.
- **Backend hardening (v.2.5.7):** per-action rate limits, `probe_now` cooldown, validated changelog/status/project syncs (projects only from real `github.com/hackatnight` repos).
- **Privacy:** the public site shows visitor country + timezone only — never city, IP or coordinates.

## Bug fixes
- **Telemetry & Outage Sync workflow** no longer crashes when the webhook secret is empty; actions moved to Node 24 (v.2.5.6).
- **Forms** (support, comms, triage, vault) only report success when the backend confirms it (v.2.5.7).
- **Logs:** Visits Log capped at 500 rows and Status_Log at 3,000, with overflow moved to archive tabs; uptime uses a rolling 24h window; timeouts logged as HTTP 0 instead of 200; alert emails only on state changes.
- **False OFFLINE readings** for Exchange (HTTP 417) fixed; duplicate `NODE-01` outage target renamed `NODE-CORE`.
- **Outage feed follows the Outage_Targets tab instantly** — enabling, disabling, adding or deleting targets shows on the next page load (v.2.5.10).
- **Sheet1 dashboard** formulas anchored so new visits no longer push them out of range.
- **Visits Log repair:** rows misaligned by the old GeoIP attempt restored; geo backfill never overwrites existing data.

## New
- **Visitor location (v.2.5.9):** server-side IP geolocation (cached, fallback provider, `GEO_LOOKUP` kill switch) adds City / Region / Country / Country Code / Latitude / Longitude to the Visits Log.
- **Backend source under version control** in `backend/Code.gs`.
