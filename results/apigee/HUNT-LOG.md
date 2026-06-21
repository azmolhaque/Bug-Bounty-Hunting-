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

---

## Session 3 — 2026-06-21 (UAA Auth Path + SAML SSO Bypass Attempt)

### UAA /info fingerprint
- `GET /info` returns HTML login page, NOT the standard UAA JSON `{"app":{"version":"..."}}`.
- Footer text reveals `Version: 240322` — custom Apigee build stamp (not semantic UAA version).
- OIDC discovery at `/.well-known/openid-configuration` returns grant types: authorization_code, client_credentials, password, implicit.
- **`saml2-bearer` NOT listed** → CVE-2026-22734 not applicable → DROPPED immediately.

### SAML SP fingerprint
- `GET /saml/metadata` → HTTP 200, full SP descriptor.
- ACS: `https://login.apigee.com/saml/SSO/alias/apigee-saml-login`
- EntityID: `apigee-saml-login`
- SAML SSO is ACTIVE with a known ACS endpoint.

### SAML SSO Bypass Attempt (APG-L005 — OPEN)
Script: `scripts/apigee_saml_sso.sh`  
Two unsigned SAML Response payloads sent via POST to ACS:
- Test 1: Issuer=`attacker-test.invalid`, InResponseTo=`_test` (random SP-initiated flow ID)
- Test 2: Issuer=`apigee-saml-login` (entity ID), no InResponseTo

**Both results:** HTTP 302 → `Location: https://login.apigee.com/saml_error`

Server processes the assertion but rejects it. Exact rejection reason unknown — `/saml_error` page content is mostly CSS and base64 image data; text extraction attempt failed to isolate the error string.

**Hypotheses for rejection:**
1. "No registered IDP for this Issuer" — server only accepts assertions from IDPs registered via admin UI
2. "Bad signature" — server IS checking XML-DSig and rejects unsigned assertions
3. "No active SP-initiated flow matching InResponseTo" — CSRF protection

**Next step:** Determine which hypothesis is correct (affects whether further SAML bypass angles exist).

### MFA / Basic Auth Block
Account `azmolhaque95@gmail.com` uses Google SSO; no native UAA password exists.
- Basic auth to management API → 401 for all endpoints (expected with MFA)
- Password grant (`grant_type=password&username=...&password=...`) → UAA prompts JSON

### Passcode Flow Attempt (PARTIAL — blocked by wrong command format)
Obtained one-time passcode `IF2IPBb3tyRawofHH9eUR1m8BPYhAOWh` from `login.apigee.com/passcode`.

Exchange command used (WRONG — missing `username` field):
```bash
curl -X POST "https://login.apigee.com/oauth/token" \
  -u "edgecli:edgeclisecret" \
  -d "grant_type=password&passcode=${PASSCODE}&response_type=token"
```
Result: `{"error":"unauthorized","error_description":"No password supplied"}`

**Root cause:** UAA passcode grant requires `username` in the form body. The passcode alone is not sufficient; it is used as a substitute for `password` but `username` must still be provided.

**Fix applied:** `scripts/apigee_get_token.sh` created with correct format:
```bash
curl -X POST "https://login.apigee.com/oauth/token" \
  -u "edgecli:edgeclisecret" \
  -d "grant_type=password&username=azmolhaque95@gmail.com&passcode=${PASSCODE}"
```
Passcode expired before fix was applied; needs fresh code.

---

## Lead Status (Updated)

| ID | Class | Endpoint | Status | Decision |
|----|-------|----------|--------|----------|
| APG-L001 | OAuth redirect_uri bypass | /sign_up + /apigee_create_account_request | DROPPED | FALSE POSITIVE |
| APG-L002 | Management API IDOR | /v1/users/{email} | BLOCKED | Needs valid Bearer token |
| APG-L003 | Privilege escalation | /v1/organizations, /v1/users | BLOCKED | Needs valid Bearer token |
| APG-L004 | Token revocation bypass (CVE-2026-22723) | /oauth/token/revoke | BLOCKED | Needs valid Bearer token |
| APG-L005 | SAML SSO assertion bypass | /saml/SSO/alias/apigee-saml-login | OPEN | Both tests → /saml_error; rejection reason unknown |

---

## Next Actions (Priority Order)

1. **[IMMEDIATE] Get fresh passcode** → visit `login.apigee.com/passcode` → run `scripts/apigee_get_token.sh`
   - If `edgecli:edgeclisecret` fails: capture token from browser DevTools (Network tab on console.apigee.com)
   - Once token obtained → run `scripts/apigee_mgmt_token_probe.sh` (APG-L002, L003, L004)

2. **[PARALLEL] Determine SAML /saml_error content** → re-run `/saml_error` fetch with better HTML stripping
   - If "no registered IDP" → explore IDP registration via other vectors
   - If "signature" → SAML bypass path requires signed assertions (private key needed) → CLOSE

3. **[IF TOKEN FAILS] DevTools fallback** — use console.apigee.com in browser, capture Bearer token from XHR to `api.enterprise.apigee.com`
