# Apigee — Hunt Log
**Program:** Google/Alphabet VRP (bughunters.google.com)
**Target:** login.apigee.com, api.apigee.com, console.apigee.com, community.apigee.com, registry.apigee.com
**Started:** 2026-06-20
**Status:** ACTIVE — pending Pi verification of POST redirect_uri bypass

---

## Session 1 — 2026-06-20 (Recon + Surface Mapping)

### Infrastructure fingerprinting

| Host | Stack | Notes |
|------|-------|-------|
| login.apigee.com | CloudFoundry UAA (Apache) | Identity server for Apigee Edge |
| api.apigee.com | Apigee Edge Management API | Returns SPA HTML for all paths (auth required) |
| console.apigee.com | React SPA | Edge management UI; redirects to console.login.apigee.com for auth |
| console.login.apigee.com | CloudFoundry UAA variant | OAuth authorize endpoint; 404s without valid rfp nonce |
| community.apigee.com | Discourse 2026.6.0-latest | Forum; public API accessible |
| registry.apigee.com | Google Cloud Apigee Registry API | All paths 404 |
| app.apigee.com | Legacy redirect | Redirects to console.apigee.com |

### OIDC Discovery (login.apigee.com)
```json
{
  "response_types_supported": ["code", "token"],
  "grant_types_supported": ["authorization_code", "client_credentials", "password", "implicit"],
  "issuer": "https://login.apigee.com",
  "authorization_endpoint": "https://login.apigee.com/oauth/authorize",
  "token_endpoint": "https://login.apigee.com/oauth/token",
  "userinfo_endpoint": "https://login.apigee.com/userinfo",
  "jwks_uri": "https://login.apigee.com/token_key"
}
```

### client_id Discovery
Followed console.apigee.com redirect chain with `curl -sv -L`:
```
https://console.login.apigee.com/oauth/authorize?
  client_id=unifiedui
  &response_type=code
  &redirect_uri=https%3A%2F%2Fconsole.apigee.com%2FoauthCallback
  &state=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyZnAiOiI...
```
- **client_id = `unifiedui`** — real Apigee Edge management console client
- **redirect_uri = `https://console.apigee.com/oauthCallback`** — registered URI
- **state JWT**: `alg:none` (unsigned), payload `{"rfp":"<nonce>","target_link_uri":"https://console.apigee.com/edge"}`

### /sign_up redirect_uri Injection — CONFIRMED at GET level

**Request:**
```
GET /sign_up?client_id=unifiedui&redirect_uri=https://example.com HTTP/1.1
Host: login.apigee.com
```

**Response:** 200 HTML — form fields include:
```html
<input type="hidden" name="client_id" value="unifiedui">
<input type="hidden" name="redirect_uri" value="https://example.com">
```
Form action: `POST /apigee_create_account_request`

- `redirect_uri=https://example.com` is reflected into hidden form field with no server-side validation at render time
- `redirect_uri=https://console.apigee.com/oauthCallback` is the real registered value

**Attack chain hypothesis:**
1. Victim visits `https://login.apigee.com/sign_up?client_id=unifiedui&redirect_uri=https://attacker.com`
2. Victim fills out form and submits
3. POST to `/apigee_create_account_request` completes account creation
4. Server redirects victim to `https://attacker.com` with OAuth auth code in query string
5. Attacker exchanges code for token → full Apigee management console access

**CRITICAL UNKNOWN:** Does POST `/apigee_create_account_request` validate `redirect_uri` against the registered allowlist?

---

## Lead Status

| ID | Class | Endpoint | Status | Next Step |
|----|-------|----------|--------|-----------|
| APG-L001 | OAuth redirect_uri bypass | /sign_up + /apigee_create_account_request | UNCONFIRMED LEAD | Run Pi verification (see runbook) |

---

## Discourse (community.apigee.com)
- `/site.json`, `/about.json`, `/categories.json` — 200 public
- `/admin/users/list/active.json` — 403
- Version: 2026.6.0-latest
- No sensitive data exposed in public endpoints

## Spring Boot Actuator
- All actuator paths at login.apigee.com → 404 or non-exploitable

## /xredirect
- Test ran; results needed from Pi (egress blocked from cloud env)

---

## Decisions Log

- `community.apigee.com` Discourse: public API returns no sensitive data → DROP
- `/xredirect` open redirect: need Pi output to evaluate; if no token in redirect chain → DROP per §3
- Spring Boot actuators: all 404 → DROP
- `registry.apigee.com`: all 404 → DROP (requires GCP auth)
- `client_id=unifiedui` in state JWT with `alg:none`: interesting but rfp nonce prevents direct abuse without browser session → LOG as context
- APG-L001: primary lead; awaiting POST validation test on Pi
