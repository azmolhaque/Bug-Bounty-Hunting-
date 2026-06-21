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

## Session 1 — 2026-06-21 (QUEUED)

See runbooks/PI-RUNBOOK-dropcam-session1.md.

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| (none yet) | — | — | Recon pending |
