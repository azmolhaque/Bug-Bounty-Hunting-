# Hunt Log — tenor.com (Google VRP TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER1
**Started:** 2026-06-21
**Status:** RECON — Session 1 queued

---

## Scope (from config/scope.yaml)

```
- tenor.com    # TIER1, acquired 2018
```

**SCOPE NOTE:** Only `tenor.com` apex is explicitly listed. Per acquisition-domain rules,
unlisted subdomains default to TIER4. Key implication: `api.tenor.com` and `www.tenor.com`
are technically OOS unless the Google VRP rules treat the listed apex as covering direct
subdomains. Probe `tenor.com` itself first; if real API surface exists at apex level (e.g.,
`tenor.com/api/...`), that is clearly in scope.

The GIF developer API (`tenor.googleapis.com`) is served through `googleapis.com` which is
explicitly TIER4 in scope.yaml — do NOT probe it.

---

## Pre-Recon Hypothesis

| Rank | Surface | Why | Bug class |
|------|---------|-----|-----------|
| 1 | `tenor.com` API paths | GIF platform — upload, search, embed endpoints | SSRF (URL import), IDOR (GIF/user ID), stored XSS |
| 2 | Upload endpoint | Animated GIF processing — URL-based import = SSRF | SSRF |
| 3 | Content delivery | Cross-account GIF access, unlisted content | IDOR |

---

## Session 1 — 2026-06-21 (COMPLETE)

**tenor.com root (HTTP/2 200):**
- Live web application: 250KB response, App Engine Flex backend
- Build: `release=r260617-1-master-a09c` (2026-06-17 — very recent)
- `set-cookie: countryCode=BD; path=/` — geo-detection cookie, not auth
- `unsafe-eval` present in `script-src` (alongside nonce)
- `via: 1.1 google` — GFE proxied

**CSP domains (passive, informational):**
- `connect-src`: `*.tenor.co`, `*.tenor.com`, `*.googleapis.com`, `tenor.googleapis.com`
- `img-src / media-src`: `media.tenor.co`, `media.tenor.com`, `media1.tenor.co`, `media1.tenor.com`, `c.tenor.com`
- All subdomains OOS (unlisted acquisition subdomains = TIER4)

**Path probe results:**
| Path | Status | Notes |
|------|--------|-------|
| `/` | **200** | Live SPA |
| `/search` | **200** | Real endpoint — not a catch-all |
| `/robots.txt` | **200** | To be mined |
| `/api` | 301 | Redirect |
| `/api/v1` | 404 | Real 404 — route table exists (not catch-all) |
| `/health` | 404 | — |
| `/upload` | 404 | — |
| `/gif` | 404 | — |
| `/trending` | 404 | — |
| `/.well-known/openid-configuration` | 404 | No OIDC |

**www.tenor.com:** 301 → `https://tenor.com/`. Response includes `x-debug-*` headers:
`x-debug-canonicalpath`, `x-debug-currentpath`, `x-debug-host`, `x-debug-hostname`,
`x-debug-protocol`, `x-debug-scheme` — debug routing headers in production. www.tenor.com
is OOS (unlisted subdomain), so not directly reportable, but confirms same App Engine app.

**Session 1 verdict:** tenor.com is LIVE with a real route table. Pursue Session 2.

---

## Session 2 — 2026-06-21 (QUEUED)

Objectives:
1. Mine `robots.txt` for disallowed paths
2. Probe `/search` — is it HTML or JSON? Does it accept query params? Any CORS?
3. GAE standard paths (`/_ah/...`)
4. CORS probe on tenor.com root + search
5. Discover authenticated endpoints via JS bundle

See runbooks/PI-RUNBOOK-tenor-session2.md.

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| TEN-L001 | Search endpoint | `tenor.com/search` (200) | ⏳ ACTIVE — probe content + CORS in S2 |
| TEN-L002 | JS bundle mining | tenor.com SPA bundle (`main.min.js`) | ⏳ NEW — Session 2 |
| TEN-L003 | GAE internal paths | `tenor.com/_ah/...` | ⏳ NEW — Session 2 |
