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

---

## Session 4 — 2026-06-21 (Token Obtained — Authenticated Probes)

### Token obtained (azmolhaque95@gmail.com)

Passcode exchange with `username` field fix → SUCCESS:
- Token type: Bearer (edgecli client), expires in ~12h
- Scopes: `scim.emails.read scim.me openid password.write approvals.me scim.ids.read oauth.approvals`
- User ID: `80dc0e8a-f939-414c-9f9c-0b8f9699a877`
- JTI: `ab94838d-adef-48d9-b34b-6d34f347faf5`
- Origin: `usergrid`
- `/userinfo` → HTTP 200 ✓ ("Tester BD")

### SCIM API probe (APG-L006 — CLOSED)

All UAA SCIM endpoints properly blocked:
- `/Users` → 403 `"scope":"scim.read zones.uaa.admin"` (needs more than we have)
- `/Users?attributes=id,emails` → 403 same (scim.emails.read does NOT allow bulk enum)
- `/Users?filter=emails.value+pr` → 403 same
- `/ids/Users` → 403 `"scope":"scim.userids"` (scim.ids.read ≠ scim.userids)
- `/Users/{other-id}` → 403 same (scim.me only covers own user)

**VERDICT APG-L006: CLOSED — properly secured.** The `scim.emails.read` and `scim.ids.read` scopes in the edgecli token do NOT grant enumeration access. All SCIM endpoints enforce `scim.read` for listing.

### /check_token blocked

`POST /check_token` with `edgecli:edgeclisecret` → 403 "access_denied".  
`edgecli` client lacks `tokens.read` on this UAA. JTI extracted directly from JWT payload instead.

### Management API — BLOCKED (no org)

`GET /v1/users/azmolhaque95@gmail.com` (with correct email) → HTTP 403, empty body.

**Root cause:** `azmolhaque95@gmail.com` has no Apigee Edge organization. The management API at `api.enterprise.apigee.com` requires org membership even to read own user profile. The edgecli token is valid (UAA accepts it) but the management API's own RBAC layer enforces org membership.

**Impact:** APG-L002 and APG-L003 (management API IDOR and priv esc) are BLOCKED until we have an account with an Apigee org.

### /Groups HTTP 500 Anomaly — CLASSIFIED

**Behavior:**
- No token → HTTP 401 `{"error":"unauthorized","error_description":"Full authentication is required..."}`
- Bad token → HTTP 401 `{"error":"invalid_token","error_description":"Invalid token (could not decode)..."}`
- Valid edgecli token → HTTP 500 `{"signupX":"...","passwd":"...","signup":"..."}` (REPRODUCIBLE × 3)

**Classification: APG-L007 — Unhandled Exception in SCIM Groups Handler (LOW/INFO)**

The scope check for `GET /Groups` with a valid-but-insufficient token triggers an unhandled exception that falls through to a default UAA handler returning prompts JSON with HTTP 500 instead of the expected 403.

This is a real application defect (improper error handling), but:
- Yields no data access, no bypass
- Response body is UAA login prompts JSON (URLs to signup/reset) — not sensitive
- Does not chain to any higher severity
- Would be remediated with proper scope-check exception handling

**VERDICT APG-L007: LOG ONLY — not a standalone reportable finding** (CLAUDE.md §3: "stack traces/verbose errors with no exploitable data"). Would only be worth mentioning as supplement to a higher-severity finding.

### Token Revocation Bypass — PENDING

JTI extracted from JWT payload (`ab94838d-adef-48d9-b34b-6d34f347faf5`). Running fresh with JTI-from-JWT fallback.

---

## Lead Status (Final — Session 4)

| ID | Class | Endpoint | Status | Decision |
|----|-------|----------|--------|----------|
| APG-L001 | OAuth redirect_uri bypass | /sign_up + /apigee_create_account_request | CLOSED | FALSE POSITIVE |
| APG-L002 | Management API IDOR | /v1/users/{email} | BLOCKED | No Apigee org on test account |
| APG-L003 | Privilege escalation | /v1/organizations, /v1/users | BLOCKED | No Apigee org on test account |
| APG-L004 | Token revocation bypass | /oauth/token/revoke/{JTI} | PENDING | JTI from JWT; revocation test in progress |
| APG-L005 | SAML SSO assertion bypass | /saml/SSO/alias/apigee-saml-login | ON HOLD | /saml_error = generic "Uh oh"; no intel on rejection reason |
| APG-L006 | SCIM email/ID enumeration | /Users, /ids/Users | CLOSED | Properly blocked (needs scim.read) |
| APG-L007 | /Groups HTTP 500 anomaly | /Groups | LOG ONLY | Improper error handling, no exploitable impact |

---

## Strategic Assessment

All unauthenticated and authenticated (no-org) attack paths are exhausted or blocked.
Remaining viable paths require either:
1. An Apigee Edge account WITH org → management API IDOR/priv esc (APG-L002/L003)
2. Token revocation bypass result (APG-L004 — pending JTI-from-JWT fix)

**If APG-L004 is negative → recommend pivot to next target.**

Next candidates (per deep-research ranking):
- Siemplify SOAR (acquired 2022, multi-tenant SOAR platform, likely IDOR surface)
- Waze Biz Portal (location + business data, potential auth/tenant isolation bugs)
- Dataform (SQL transformation SaaS, recently more active)
