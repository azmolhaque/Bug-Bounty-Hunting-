# Waze — OSINT Research Report

**Date:** 2026-06-21 | **Method:** Web search + public source analysis, no live system access

---

## 1. Product Overview

**What it is:** Waze is a crowdsourced navigation app (acquired by Google 2013). The relevant VRP surfaces are:

- **`biz.waze.com`** — Waze Business Portal (formerly the Waze Ads self-serve advertising platform)
- **`adsapi.waze.com` / `adsapi-staging.waze.com`** — Legacy Waze Ads API
- **`proxy.waze.com` / `proxy-staging.waze.com`** — Unknown function (SSRF candidate)
- **`www.waze.com/partnerhub`** — Waze for Cities partner hub (data feed submissions)
- **`ads.wazeapis.com`** — Waze Ads Management API host (newer gRPC-transcoded REST API)

**CRITICAL PLATFORM STATUS:**
Waze Ads stopped accepting new campaigns on **August 31, 2023**. No new Waze Ads business accounts can be created. The biz.waze.com portal now shows wind-down messaging. Advertising inventory migrated to Google Ads Performance Max.

**Implication for testing:** The authenticated portion of biz.waze.com requires a pre-2023 Waze Ads account. Self-serve access is blocked. Focus shifts to:
1. Unauthenticated surface probing (`proxy.waze.com`, `adsapi-staging.waze.com`)
2. Whether `ads.wazeapis.com` WAM API health/discovery endpoints are accessible without auth
3. Waze business listing management (separate from ads — potentially still accessible)

---

## 2. Tech Stack

| Component | Technology | Evidence |
|-----------|-----------|----------|
| Business portal (`biz.waze.com`) | SPA (React or Angular suspected), Google Cloud hosting | Login page at `/app/login`, path structure |
| Auth | Google SSO / OAuth 2.0 | Documentation confirms "Sign in with Google" only |
| WAM API | REST (gRPC transcoding) at `ads.wazeapis.com/v1/` | Official docs |
| WAM Auth | WAZE_ACCESS_TOKEN (1-hour validity), obtained from `biz.world.waze.com/app/auth/refresh-token` | Documentation |
| GID format | Region prefix + sequential integer (e.g., 105678 = NA account 5678) | Official docs |
| Legacy ads API | `adsapi.waze.com` | scope.yaml scope entry |
| Partner Hub feeds | GeoRSS XML/JSON fetched server-side by Waze every few minutes | Official docs |

**Two distinct URL variants exist:**
- `biz.waze.com` — standard URL
- `biz.world.waze.com` — variant used for WAM API auth token retrieval

---

## 3. WAM API Resource Hierarchy (IDOR Attack Surface)

Official API base: `https://ads.wazeapis.com/v1/`

Key resource paths (from official documentation):
```
GET  /v1/accounts/{account}/campaigns
GET  /v1/accounts/{account}/campaigns/{campaign}
POST /v1/accounts/{account}/campaigns/{campaign}:activate
GET  /v1/accounts/{account}/ads
GET  /v1/accounts/{account}/ads/{ad}
GET  /v1/accounts/{account}/locations
GET  /v1/accounts/{account}/locations/{location}
GET  /v1/accounts/{account}/roleAssignments
GET  /v1/accounts/{account}/regions
GET  /v1/health   ← health endpoint (possibly unauthenticated)
```

**IDOR Hypothesis**: Account IDs use a GID format: `{region_code}{sequential_id}` where region codes include:
- `10` = North America
- Other region codes for EU, LATAM, etc.

If the API validates the WAZE_ACCESS_TOKEN without checking that the token's associated account matches the `{account}` in the URL, an attacker with any valid WAZE_ACCESS_TOKEN can read another account's campaigns, locations, and role assignments.

**Impact of IDOR**: Cross-account read of:
- Business location data (addresses, opening hours, coordinates)
- Ad campaign performance data (impressions, clicks, spend)
- Role assignments (who has admin access to the account)
- Historical billing data

**Blocker**: Requires an existing WAZE_ACCESS_TOKEN (i.e., a pre-2023 Waze Ads account). Cannot be tested without one.

---

## 4. Partner Hub Data Feed — SSRF Surface

Waze for Cities partners register a URL with the Partner Hub. Waze's backend fetches the URL every few minutes ("content acquisition system" with dynamic IPs — no static IP list).

**SSRF vector**: If a partner-registered URL can point to an internal GCP address, the Waze content acquisition system would make a server-side request to it from inside GCP infrastructure.

**Friction**: Requires being an approved "Waze for Cities" partner (municipalities, transit authorities). Not self-serve — requires a formal partnership agreement.

**Assessment**: High potential severity (server-side fetch from GCP → IMDS), but high friction to test. Log as hypothesis only.

---

## 5. Prior Disclosures

| Date | Reporter | Type | Target | Reward | Notes |
|------|----------|------|--------|--------|-------|
| 2018-03-28 | Rojan Rijal | Stored XSS | `biz.waze.com` | Unknown | Ad content fields; fixed |
| 2018-05-25 | PanguTeam | Remote vulnerabilities | Waze app | Unknown | Unspecified iOS/Android |
| 2020-08-25 | Peter Gasper | User tracking | Waze API | $1,337 | UI elements leaked driver identity |

**Zero CVEs** for the Waze Business Portal specifically. Three total disclosures spanning 2018-2020 — no recent security research attention.

**What this means for novelty**: The stored XSS on biz.waze.com from 2018 was in ad content fields (presumably the ad headline/description). The 2018 fix likely added output encoding. However:
1. New fields may have been added since then without the same encoding
2. The WAM API (gRPC layer) may have different encoding than the web portal
3. Location name/description fields might be a separate XSS surface if they're user-editable

---

## 6. Attack Classes — Ranked by Priority

### #1 — `proxy.waze.com` Investigation ⭐ HIGHEST PRIORITY (UNKNOWN)

**Why**: The domain name "proxy" in a Waze-owned hostname strongly suggests a server-side URL-fetching service. No public documentation found. Could be:
- A URL/image proxy (SSRF if it fetches attacker-supplied URLs)
- A gRPC-HTTP transcoding proxy for the WAM API
- An API gateway for app-to-server traffic

**Test plan (from Pi, unauthenticated)**:
```bash
# Probe what's at proxy.waze.com
curl -sv https://proxy.waze.com/ 2>&1 | head -30
curl -sv https://proxy.waze.com/health 2>&1 | head -20
curl -sv https://proxy.waze.com/status 2>&1 | head -20

# Staging variant (likely weaker controls)
curl -sv https://proxy-staging.waze.com/ 2>&1 | head -30
curl -sv https://proxy-staging.waze.com/health 2>&1 | head -20
```

**If it accepts a URL parameter → test SSRF immediately.**

---

### #2 — `adsapi-staging.waze.com` Unauthenticated Probe ⭐ HIGH PRIORITY

**Why**: Staging APIs often have weaker authentication, enabled debug endpoints, or exposed Swagger/OpenAPI docs.

**Test plan**:
```bash
curl -sv https://adsapi-staging.waze.com/ 2>&1 | head -30
for path in /health /status /api /v1 /swagger /swagger.json /openapi.json /docs /api/v1 /api/v2; do
  echo "=== $path ==="
  curl -sk -w "HTTP_%{http_code}" https://adsapi-staging.waze.com${path} -o /dev/null
done
```

---

### #3 — WAM API Health/Discovery Probe

**URL**: `https://ads.wazeapis.com/v1/health`

```bash
# Health endpoint — might respond without API key
curl -sk -w "\nHTTP_%{http_code}" "https://ads.wazeapis.com/v1/health"

# List accounts — what error without auth?
curl -sk -w "\nHTTP_%{http_code}" "https://ads.wazeapis.com/v1/accounts"

# Error format analysis
curl -sk -w "\nHTTP_%{http_code}" \
  -H "Authorization: Bearer test-invalid-token" \
  "https://ads.wazeapis.com/v1/accounts"
```

---

### #4 — `biz.waze.com` Pre-auth Surface

**Why**: Even a wind-down portal may have pre-auth paths (forgot password, account lookup, signup forms) with user enumeration, open redirect, or injection.

**Test plan**:
```bash
# What does the login page return?
curl -sk "https://biz.waze.com/app/login" -L | head -100

# Common pre-auth paths
for path in / /app/login /app/signup /app/forgot-password /app/reset-password \
  /api/health /health /api/v1 /.well-known/openid-configuration; do
  echo -n "=== $path === "
  curl -sko /dev/null -w "HTTP_%{http_code}" "https://biz.waze.com${path}" --max-time 10
  echo
done
```

---

### #5 — `adsapi.waze.com` Production API Probe

```bash
curl -sk -w "\nHTTP_%{http_code}" "https://adsapi.waze.com/"
curl -sk -w "\nHTTP_%{http_code}" "https://adsapi.waze.com/health"
curl -sk -w "\nHTTP_%{http_code}" "https://adsapi.waze.com/v1/"
curl -sk -w "\nHTTP_%{http_code}" \
  -H "Authorization: Bearer invalid" \
  "https://adsapi.waze.com/v1/accounts"
```

---

## 7. Strategic Constraints Summary

| Constraint | Impact |
|-----------|--------|
| Waze Ads shut down Sept 2023 | No new business account registration → authenticated portal access blocked |
| WAM API requires WAZE_ACCESS_TOKEN | Need pre-2023 Waze Ads account → blocked unless user has one |
| Partner Hub data feed → requires approved Waze for Cities partner status | SSRF angle blocked |
| `proxy.waze.com` undocumented | Unknown — highest uncertainty |

**Bottom line**: Waze is a MEDIUM-FRICTION target. The advertising platform shutdown removes most write-surface (ad creation = XSS/SSRF vector). What remains:
1. Unauthenticated probe of proxy.waze.com / adsapi-staging.waze.com — can do from Pi immediately
2. WAM API IDOR — blocked without pre-2023 account
3. Partner data feed SSRF — blocked without partner status

**Recommend**: Run the Pi probes in Session 1. If `proxy.waze.com` or `adsapi-staging.waze.com` expose unauthenticated surface → invest deeply. If not → deprioritize Waze and focus on Photomath portal IDOR (TIER0, cleaner path to finding).
