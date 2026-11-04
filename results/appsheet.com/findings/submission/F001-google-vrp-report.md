> # ⛔ WITHDRAWN — DO NOT SUBMIT (false positive, retracted 2026-06-16)
> Live re-verification from the Pi showed **production and staging behave identically**:
> across `GET /tables`, `POST /Action`, and `POST /data`, *both* hosts return
> `"App with id … not found"` (HTTP 400) for an unauthenticated request. Production
> **never** returns `"ApplicationAccessKey is missing"`. The prod-vs-staging differential
> this report was built on does not exist — the API does app-lookup before key-check on
> both environments, which is normal behavior, not an auth bypass. There is no
> demonstrable access gain. This finding is retired. Evidence of disproof:
> `results/appsheet.com/findings/F001-RETRACTION.md`.

---

# Google VRP Submission — F001

## TITLE

**Missing `ApplicationAccessKey` Authentication on Publicly Accessible AppSheet Staging REST API (`api.gcp-staging.appsheet.com`)**

---

## AFFECTED COMPONENT

```
https://api.gcp-staging.appsheet.com
```

| Field | Value |
|-------|-------|
| **Product** | Google AppSheet — staging REST API |
| **Asset** | `api.gcp-staging.appsheet.com` (resolves to `34.102.140.38`, Google Cloud) |
| **Scope** | Matches `*.appsheet.com` — in scope for Google VRP (AppSheet, TIER0) |
| **Vulnerability class** | Broken Authentication / Missing Access Control (CWE-306, Missing Authentication for Critical Function) |
| **Severity** | Medium — CVSS 3.1 6.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`) |
| **Escalation ceiling** | Critical — CVSS 9.1 if a valid staging App UUID is obtained |

---

## SUMMARY

The AppSheet staging REST API at `https://api.gcp-staging.appsheet.com` is reachable
from the public internet and does **not** enforce the `ApplicationAccessKey` header that
protects the production API at `https://api.appsheet.com`. On production, a request with
no key is rejected at the authentication layer. On staging, the identical request is
accepted past authentication and proceeds directly to application/data lookup.

The difference is provable from the error messages alone, without any credentials and
without a valid application ID:

- **Production:** `"The ApplicationAccessKey is missing from the HTTP header."` — request rejected by the auth layer.
- **Staging:** `"App with id <UUID> not found."` — auth layer absent; the request reaches app lookup.

Any attacker who additionally obtains a valid staging AppSheet App UUID can read and
write all table data in that staging application with no credentials.

---

## STEPS TO REPRODUCE

No account and no credentials are required. Reproducible from any IP.

```bash
# Step 1 — Confirm authentication IS enforced on PRODUCTION
curl -si "https://api.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
  -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
# → "REST API tables request failed: The ApplicationAccessKey is missing from the HTTP header."

# Step 2 — Confirm authentication is ABSENT on STAGING (identical request, staging host)
curl -si "https://api.gcp-staging.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
  -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
# → "REST API tables request failed: App with id 00000000-0000-0000-0000-000000000001 not found."
```

The `"App not found"` response is the proof: the staging server performed application
lookup **before** any key check, meaning no authentication occurred.

---

## EVIDENCE ALREADY CAPTURED

### 1. Actively maintained, production-adjacent staging environment (TLS)

```
$ curl -sv https://api.gcp-staging.appsheet.com/ 2>&1 | grep -E '(subject|issuer|start|expire)'
subject: CN=api.gcp-staging.appsheet.com
issuer: C=US; O=Google Trust Services; CN=WR3
start date: Jun  3 08:49:54 2026 GMT
expire date: Sep  1 09:41:44 2026 GMT
```

Dedicated (non-wildcard) certificate issued June 3, 2026 by Google Trust Services — this
is a live, maintained environment, not an abandoned host.

### 2. Auth-bypass error-message diff (the core proof)

| | Request (no key) | Response |
|---|---|---|
| **Production** `api.appsheet.com` | `GET /api/v2/apps/{id}/tables` | `400` — *"ApplicationAccessKey is missing from the HTTP header"* |
| **Staging** `api.gcp-staging.appsheet.com` | `GET /api/v2/apps/{id}/tables` | `400` — *"App with id {id} not found"* |

### 3. Bypass confirmed across every endpoint type tested

| Endpoint | Method | Production (no key) | Staging (no key) |
|----------|--------|--------------------|------------------|
| `/api/v2/apps/{id}/tables` | GET | 400 "missing key" | 400 "app not found" |
| `/api/v2/apps/{id}/tables/{name}/data` | GET | 400 "missing key" | **405 Method Not Allowed** (`Allow: POST`) |
| `/api/v2/apps/{id}/tables/{name}/data` | POST | 400 "missing key" | 400 "app not found" |
| `/api/v2/apps/{id}/tables/{name}/Action` | POST | 400 "missing key" | 400 "app not found" |

The `GET .../data` → **405 with `Allow: POST`** is especially strong: the staging server
routed to the endpoint handler and returned a method error, proving zero authentication
ran before routing.

### 4. Publicly reachable — no VPN, no IP allowlist

Requests originating from an external, non-Google IP (Bangladesh) received identical
responses; the server echoed `x-client_region: BD`. No network-layer restriction (IAP,
VPC Service Controls, IP allowlist) is in place.

---

## IMPACT

**Confirmed today (no credentials, no valid App UUID):**
- Complete bypass of the `ApplicationAccessKey` authentication control on the staging REST API.
- All endpoint types reach application logic without any key.
- Endpoint is exposed to the public internet without VPN or network restriction.

**On obtaining a valid staging App UUID (escalation):**
- Unauthenticated read of all table data in any staging AppSheet application.
- Unauthenticated create/edit/delete of staging app table data via the `Action` endpoint.
- Staging apps used by AppSheet/Google engineers may hold production-clone test data and
  connector credentials, elevating impact to Critical.

---

## CVSS 3.1

**Confirmed (current):** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.5 (Medium)**

**With a valid staging App UUID:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 (Critical)**

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | Reachable from the public internet |
| Attack Complexity | Low | Single unauthenticated request |
| Privileges Required | None | No key, no account |
| User Interaction | None | — |
| Scope | Unchanged | Vulnerable component = the API itself |
| Confidentiality / Integrity | Low → High | Low today (auth control fully bypassed); High once a valid UUID enables data read/write |

---

## SUGGESTED FIX

1. **Apply the production authentication middleware to staging.** Enforce
   `ApplicationAccessKey` validation at the gateway/Istio ingress layer on
   `api.gcp-staging.appsheet.com` identically to `api.appsheet.com`, so the key check
   runs before any application or data lookup.
2. **Network-restrict the staging surface** as defence in depth — front it with
   Identity-Aware Proxy (IAP) or VPC Service Controls so it is not reachable from the
   public internet.
3. **Add a regression check** comparing the unauthenticated-request response of staging
   vs. production so a future configuration drift that drops the auth layer is caught
   automatically.

---

## NOTES FOR TRIAGE

- Fully reproducible from any IP with two `curl` commands; no credentials used and no
  customer data was accessed during testing.
- No data was read or modified; testing stopped at confirming the authentication control
  is absent (the `"App not found"` / `405` responses).

---

*Reporter: azmolhaque95@gmail.com*
*Report date: 2026-06-16*
*Submit at: https://bughunters.google.com/report → Google VRP → AppSheet (`appsheet.com`)*
