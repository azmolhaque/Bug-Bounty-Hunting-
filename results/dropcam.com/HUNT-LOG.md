# Hunt Log — dropcam.com (Google VRP TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER1 (Dropcam / Nest Labs)
**Started:** 2026-06-21
**Status:** RECON — Session 1 queued

---

## Scope (from config/scope.yaml)

```
- dropcam.com    # TIER1, under "Dropcam / Nest Labs"
```

Dropcam was acquired by Google/Nest in 2014. The domain is actively used as a
WebSocket camera-streaming backend: `wss://*.dropcam.com:80` and `wss://*.dropcam.com`
appear in the Nest home.ft.nest.com SPA CSP (`connect-src`), meaning real active
traffic still routes through dropcam.com infrastructure.

---

## Pre-Recon Thesis

Dropcam.com is a camera/video streaming platform. The Nest SPA uses it for WebSocket
connections to live camera feeds. Key angles:

| Rank | Surface | Why | Bug class |
|------|---------|-----|-----------|
| 1 | WebSocket endpoint (`wss://*.dropcam.com`) | Camera-streaming WSS — real-time frame delivery; potential cross-tenant camera access | Cross-tenant IDOR / auth bypass |
| 2 | API surface (`api.dropcam.com` or similar) | Camera management API — CRUD on camera devices, clips, sharing | IDOR (device/user ID) |
| 3 | Subdomain enumeration | Older infrastructure, potentially less monitored | Auth bypass / info disclosure |
| 4 | dropcam.com apex + www | What does the main site serve now? Redirect to Nest? Or still active? | Recon anchor |

**Hypothesis:** dropcam.com is older infrastructure (pre-Google). It may retain legacy API
endpoints or auth flows from before the Nest integration, which are less hardened than the
current nest.com cluster.

---

## Session 1 — 2026-06-21 (COMPLETE)

**DNS:**
- `dropcam.com`, `www.dropcam.com`, `api.dropcam.com` → all resolve to `35.227.226.203` (GCP)
- All other common subdomains (app, stream, ws, camera, nest, beta, staging) → NXDOMAIN
- `x-nl-request-id` header present → Nest Labs nginx infrastructure

**HTTP:**
- `dropcam.com/` → 301 → `https://www.dropcam.com/`
- `www.dropcam.com/` → 301 → `https://www.nest.com/camera/meet-nest-cam/?dropcam=true`
- ALL paths on `dropcam.com` (/api, /api/v1, /api/v2, /health, /v1, /robots.txt, /cameras, /oauth2/token) → **301**

`api.dropcam.com` resolves (same IP) — probed in Session 1b.

## Session 1b — 2026-06-21 (COMPLETE)

`api.dropcam.com/` → **301** → `https://www.nest.com/camera/meet-nest-cam/?dropcam=true`
Same `x-nl-request-id` header, same nginx. Confirmed same redirector.

## ⛔ DROPCAM CLOSED (pending api.dropcam.com confirmation)

Blanket-301 on all paths mirrors Waze ad-API decommission pattern. The `wss://*.dropcam.com`
CSP entries use internal subdomains (camera-ID or region-specific) that don't resolve publicly.
No unauthenticated external API surface exists.

**PIVOT → Tenor.com** (TIER1, GIF platform, active content upload API, potential SSRF/IDOR).

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| DRC-L001 | API / WebSocket surface | `api.dropcam.com`, `wss://*.dropcam.com` | ❌ CLOSED — blanket 301 redirectors, internal WS subdomains not publicly resolvable |
