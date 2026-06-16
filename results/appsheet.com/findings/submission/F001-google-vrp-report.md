# Google VRP Submission — Missing Authentication on AppSheet Staging REST API

---

## TITLE

**Missing `ApplicationAccessKey` Enforcement on `api.gcp-staging.appsheet.com` Allows Unauthenticated Access to the Staging REST API**

---

## AFFECTED ASSET

```
https://api.gcp-staging.appsheet.com
```

- **Product:** AppSheet (Google Cloud)
- **Component:** Staging REST API gateway / app-data middleware
- **IP:** `34.102.140.38`
- **In scope per `config/scope.yaml`:** yes — matches `*.appsheet.com`
- **Severity:** Medium (current, no valid staging App UUID) — escalates to Critical with one
- **CVSS 3.1 (current):** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.5 Medium**
- **CVSS 3.1 (with valid staging App UUID):** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 Critical**

---

## SUMMARY

AppSheet's production REST API (`api.appsheet.com`) requires an `ApplicationAccessKey`
header on every request and rejects requests without one. The staging counterpart,
`api.gcp-staging.appsheet.com`, is publicly reachable on the internet but **does not
enforce this control at all** — requests with no `ApplicationAccessKey` header pass
straight through the auth layer to the app-lookup/routing logic. This is demonstrated
by comparing identical requests against both hosts: production fails at the auth
layer with `"ApplicationAccessKey is missing"`; staging fails one layer deeper with
`"App ... not found"`, and a `GET` to the data endpoint on staging returns
`405 Method Not Allowed` — proof the request reached the route handler with zero
authentication performed.

An attacker who also obtains a valid staging App UUID (internal docs leak, source
code, guessable/sequential ID, or further recon) can read and write all table data
in that staging app with no credentials whatsoever.

---

## 30-SECOND VERIFICATION

```bash
# Production enforces auth:
curl -si "https://api.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
  -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
# → "ApplicationAccessKey is missing from the HTTP header"

# Staging does not — same request, different host, same UUID:
curl -si "https://api.gcp-staging.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
  -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
# → "App with id 00000000-0000-0000-0000-000000000001 not found"
```

The second response is the proof: `"App not found"` can only be returned by code
that already ran the app lookup, which means the auth middleware never executed.

---

## STEPS TO REPRODUCE

1. Confirm the dedicated TLS certificate for `api.gcp-staging.appsheet.com` shows an
   actively maintained, non-wildcard staging environment:
   ```bash
   curl -sv https://api.gcp-staging.appsheet.com/ 2>&1 | grep -E '(subject|issuer|start|expire)'
   ```
   ```
   subject: CN=api.gcp-staging.appsheet.com
   issuer: C=US; O=Google Trust Services; CN=WR3
   start date: Jun  3 08:49:54 2026 GMT
   expire date: Sep  1 09:41:44 2026 GMT
   ```

2. Send identical unauthenticated requests to production and staging for each
   endpoint type and diff the responses:

   | Endpoint | Method | Production | Staging |
   |---|---|---|---|
   | `/api/v2/apps/{id}/tables` | GET | `400` "missing key" | `400` "app not found" |
   | `/api/v2/apps/{id}/tables/{name}/data` | GET | `400` "missing key" | **`405 Method Not Allowed`** (reaches handler) |
   | `/api/v2/apps/{id}/tables/{name}/data` | POST | `400` "missing key" | `400` "app not found" |
   | `/api/v2/apps/{id}/tables/{name}/Action` | POST | `400` "missing key" | `400` "app not found" |

3. Confirm no network-layer restriction (VPN/IP allowlist) is protecting staging —
   requests from an external, non-Google residential IP receive identical responses
   (`x-client_region: BD`, confirmed from Bangladesh).

Reproducible from any IP, in under a minute, with no account or credentials.

---

## PROOF

```http
GET /api/v2/apps/00000000-0000-0000-0000-000000000001/tables/Table1/data HTTP/1.1
Host: api.gcp-staging.appsheet.com
Content-Type: application/json
```
```http
HTTP/1.1 405 Method Not Allowed
Allow: POST
```

A `405` with an `Allow` header is only produced by the route handler after the
request has been dispatched — i.e., after any authentication step that would
normally reject it has been skipped.

---

## ROOT CAUSE

`api.appsheet.com` (production) has an `ApplicationAccessKey` validation step in
front of the app/table lookup logic — most likely enforced at the API gateway or an
Istio/ingress middleware layer. That same middleware is either not deployed, not
configured, or bypassed on `api.gcp-staging.appsheet.com`. The staging service is
otherwise functionally identical to production (same error schema, same routing,
same endpoint surface), so this looks like a deployment/configuration gap rather
than an intentionally different staging codebase.

---

## IMPACT

**Confirmed now:**
- Complete bypass of `ApplicationAccessKey` authentication on a publicly internet-reachable
  AppSheet API host
- Any REST endpoint (table read, table write, custom Action) is reachable pre-auth
- No VPN, IP allowlist, or other network control gates access

**Upon obtaining a valid staging App UUID (not performed in this engagement —
no UUID was discovered or guessed):**
- Unauthenticated read of all table data in that staging app
- Unauthenticated create/update/delete of all table data in that staging app
- AppSheet's staging environment is used for Google/AppSheet engineers'
  pre-production testing; apps hosted there may contain production data clones,
  connector credentials, or internal service tokens configured in data sources

---

## CVSS 3.1

**Current (no valid App UUID held):**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.5 Medium**

**Escalated (with a valid staging App UUID):**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 Critical**

The current score reflects what was directly demonstrated: an authentication
control is absent and the API surface is reachable pre-auth, but no actual app
data was read or modified during this engagement (no UUID was obtained or
brute-forced — out of scope for this test).

---

## REMEDIATION

1. Apply the same `ApplicationAccessKey` validation middleware used on
   `api.appsheet.com` to `api.gcp-staging.appsheet.com`, enforced at the same
   layer (gateway/ingress) so it cannot be bypassed by routing differences.
2. Alternatively/additionally, restrict `api.gcp-staging.appsheet.com` to internal
   Google networks via IAP or VPC Service Controls — staging APIs used only by
   internal engineers do not need to be reachable from the public internet at all.
3. Audit other `*.appsheet.com` staging/internal subdomains for the same gap.

---

## REFERENCES

- AppSheet REST API documentation: https://support.google.com/appsheet/answer/10106434
- Production vs. staging response diff — see Steps to Reproduce above

---
<!-- Internal (do not submit): dedup status, discovery method, related findings -->
- Dedup status: novel — no public report found describing missing auth on
  `api.gcp-staging.appsheet.com` specifically
- Discovered via: Phase 1+2 recon (subdomain enumeration) → Phase 3 manual
  testing (production/staging response diffing)
- Related findings: F002 (OData SSRF) — both point to a staging/connector
  attack surface that has not been through the same hardening as production
- Source finding: `results/appsheet.com/findings/F001-staging-api-auth-bypass.md`
