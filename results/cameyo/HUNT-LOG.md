# Hunt Log — Cameyo (cameyo.com / online.cameyo.com / marketplace.cameyo.com)
Target: Cameyo — cloud application streaming platform
Program: Google / Alphabet VRP — bughunters.google.com
Tier: TIER0
Acquisition: ~2023
Started: 2026-06-20

---

## Status Summary

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| — | — | — | No confirmed findings — unauthenticated surface exhausted |

---

## Session 1 — 2026-06-20

### Infrastructure

| Host | Status | Stack |
|------|--------|-------|
| cameyo.com | 302 → online.cameyo.com | Redirect |
| online.cameyo.com | 200 | ASP.NET + Angular SPA (GCP GCLB, `GCLB` cookie) |
| marketplace.cameyo.com | 200 | nginx/1.22.1 — Management Backend |
| getip/session/gwebhook.svc.cameyo.com | 000 | TCP refused from Pi (geo-block or internal) |

**Stack**: ASP.NET (confirmed by `302 → /errorHandler.aspx?aspxerrorpath=/openapi.json`)

### online.cameyo.com — All Paths Are SPA Catch-All

Every 200 path returns `content-type: text/html` (Angular SPA serving `index.html`).
Every real endpoint returns 302 → `/login`.

| Path | HTTP | Verdict |
|------|------|---------|
| /apps | 302 → /login | Auth required |
| /apps/public | 302 → /login | Auth required despite "public" name |
| /api/users, /api/apps, /api/sessions, /api/orgs, /api/GetUsers, /api/GetApps | 200 text/html | SPA catch-all |
| /graphql, /oauth2, /.well-known/openid-configuration | 200 text/html | SPA catch-all |
| /openapi.json | 302 → /errorHandler.aspx | No schema |

### marketplace.cameyo.com — Management Backend

| Path | HTTP | Body |
|------|------|------|
| /api | 200 text/plain | `"Cameyo Management Backend API server"` |
| /api/* (all sub-paths) | 404 | — |

### Negative Tests

| Test | Result |
|------|--------|
| CORS sweep (api/v1, api/v2, graphql) | No ACAO headers |
| setCookie param | Server generates own session ID, does NOT reflect param value |
| redirUrl bypass (//evil.com, domain confusion) | Client-side JS only; server returns 200, no Location header |
| Log4Shell JNDI, Spring Boot actuators | Wrong stack (ASP.NET, not Java) |

### Key JS Observations

- `/apps?filter=` and `/apps/public?filter=` are referenced in client JS as real endpoints
- `getSafeRedirectUrl()` validates `redirUrl` param — checks `url.hostname !== window.location.hostname` (client-side only)
- `setCookie` param does not reflect into Set-Cookie response

### Blocker

All real API surface requires authentication. No free trial visible without sales contact.

### Decision

**PARK** — unauthenticated surface exhausted from Pi.
Revisit after obtaining Cameyo trial account (cameyo.com/get-started or sales contact).
With auth, test: IDOR on org/session integer IDs, cross-tenant isolation (Org A vs Org B apps).
