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

| ID | Class | Endpoint | Status | Decision |
|----|-------|----------|--------|----------|
| APG-L001 | OAuth redirect_uri bypass | /sign_up + /apigee_create_account_request | DROPPED | FALSE POSITIVE — see Session 2 |

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
- APG-L001: DROPPED — FALSE POSITIVE. See Session 2.

---

## Session 2 — 2026-06-20 (APG-L001 Verification + Closure)

### /oauth/authorize redirect_uri validation test (Pi)

All four tests (external redirect_uri, registered redirect_uri, no client_id, bogus client_id) returned:
```
HTTP/1.1 302
Location: https://login.apigee.com/login
SSO_JSESSIONID=<session>
```

The server defers ALL validation (client_id, redirect_uri) to a server-side session evaluated AFTER
authentication. This is standard CloudFoundry UAA behavior — not a vulnerability. Pre-auth there is
no differentiation between valid and invalid redirect_uri values.

### APG-L001 Final Evidence (browser test on phone)

Full sign_up flow with `redirect_uri=https://example.com` and `client_id=unifiedui`:
1. GET `/sign_up?client_id=unifiedui&redirect_uri=https://example.com` → form loads with injected hidden fields ✓
2. POST `/apigee_create_account_request` → HTTP 200, "Check your inbox" (account created, no redirect_uri error) ✓
3. Email confirmation link clicked → browser lands at `apigee.com/no-orgs-available` (NOT `example.com`) ✗

**VERDICT: FALSE POSITIVE — DROP APG-L001**

The server accepts the injected `redirect_uri` in the POST body without a server-side validation error,
but the OAuth callback completion stage uses the registered URI (`console.apigee.com/oauthCallback`)
or the default dashboard, ignoring the user-supplied value.

The GET-level reflection into hidden form fields is real but produces no exploitable redirect.
Does NOT meet CLAUDE.md §3 bar: "Open redirect without chaining to token exfiltration or account takeover."

### New Asset — Test Apigee Edge Account
A test Apigee Edge account was created during verification (no org provisioned — new Edge orgs are 
disabled for trial accounts). This account could be used for authenticated API testing.
- Account email: zahinshahriar3@gmail.com
- Org: none (Edge trial provisioning disabled)
- Potential use: test authenticated management API endpoints, JWT token handling, account-level IDORs

### Next Hunting Direction
With APG-L001 closed, options:
1. **Apigee Edge authenticated surface** — use test account to probe management API with real JWT
2. **Apigee X** — newer platform, different attack surface, may have less-reviewed code
3. **Move to new target** — Siemplify SOAR, Waze Biz Portal, or Dataform per deep-research ranking
