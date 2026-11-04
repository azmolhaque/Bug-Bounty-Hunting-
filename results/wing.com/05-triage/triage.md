# Triage Report — wing.com

| ID | Severity | CVSS | Target | Gate | Title |
|----|----------|------|--------|------|-------|
| — | N/A | N/A | wing.com / opensky.wing.com | CLOSED | No exploitable attack surface found |

## Closure Summary

**Date**: 2026-06-19  
**Decision**: CLOSE / DROP — no findings, no viable leads

### Surface Assessment

| Host | Tech | Backend? | Verdict |
|------|------|----------|---------|
| `wing.com` | Framer CDN (marketing site) | NO | Static — no server logic |
| `opensky.wing.com` | Google sffe → 301 → Framer | NO | Pure redirect to Framer marketing page |
| `wing-prod` GCS bucket | GCS (CDN assets) | N/A | Public CDN read only, no write access, no listing |

### HTTP Probe Results

- `opensky.wing.com` → 301 → `wing.com/opensky/` → 308 → Framer → 200
- Server stack: Google sffe frontend + Framer/2ea93c3
- No auth endpoints, no API paths, no backend services reachable
- All path probes (health, metrics, api, graphql, swagger, etc.) redirect to Framer 404 page
- CORS tests: no misconfiguration (wildcard on public CDN assets only — intentional)

### GCS Bucket `wing-prod`

- List (JSON API): 401 — correctly blocked
- List (XML API): 403 — correctly blocked  
- Read specific objects: 200 — public CDN assets, CORS `*` — **intentional/by design for media delivery**
- Write (PUT): 403 — correctly blocked
- IAM testPermissions: empty — no anonymous permissions beyond intended public reads

### Why Closed

Per scope.yaml acquisition domain default-deny rule:
- Only `wing.com` and `opensky.wing.com` are in scope
- Both are marketing/redirect surfaces with zero backend attack surface
- Out-of-scope subdomains that WOULD have attack surface: `delivery-staging.wing.com`,
  `partner.wing.com`, `app.wing.com`, `marketplace.wing.com` — all OOS
- Partner API requires corporate onboarding via `partnerships@wing.com`
- Consumer app (OpenSky) geo-restricted + requires mobile app RE

### Time Invested

- Phase 1 (DNS recon): ~20 min
- Phase 2 (HTTP probe): ~10 min  
- GCS bucket test: ~5 min
- Total: ~35 min

**Recommendation**: Do not revisit unless scope.yaml is updated to explicitly include
`app.wing.com`, `delivery-staging.wing.com`, or `partner.wing.com`.
