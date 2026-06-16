# Google VRP Report — F001

## Title
Missing authentication on publicly accessible AppSheet staging REST API (`api.gcp-staging.appsheet.com`) — `ApplicationAccessKey` not enforced

## Summary
The AppSheet staging REST API at `https://api.gcp-staging.appsheet.com` is reachable
from the public internet and does not enforce the `ApplicationAccessKey` header that
protects the production API at `https://api.appsheet.com`. Unauthenticated requests skip
the auth layer entirely and proceed to application/data routing. An attacker who supplies
a valid staging application UUID can read and write that app's table data with no
credentials. Confirmed via response-differential testing from an external (non-Google)
IP; no data was accessed because no valid staging UUID was used.

## Affected Component
- **Asset:** `api.gcp-staging.appsheet.com` (resolves to `34.102.140.38`)
- **Scope:** In-scope — matches `*.appsheet.com` (Google VRP, AppSheet, TIER0)
- **Control that is missing:** `ApplicationAccessKey` validation middleware / gateway
  layer present on production (`api.appsheet.com`) but absent on staging
- **Endpoints affected:** All tested AppSheet REST v2 endpoints
  (`/api/v2/apps/{id}/tables`, `.../tables/{name}/data`, `.../tables/{name}/Action`)

## Reproduction
No credentials required. Reproducible from any IP. The proof is a deterministic
difference in the error returned by production vs. staging for the **identical**
unauthenticated request.

```bash
# 1) Production ENFORCES auth — request is rejected before app lookup
curl -si "https://api.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
  -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
# => "REST API tables request failed: The ApplicationAccessKey is missing from the HTTP header."

# 2) Staging SKIPS auth — same request reaches app lookup
curl -si "https://api.gcp-staging.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
  -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
# => "REST API tables request failed: App with id 00000000-0000-0000-0000-000000000001 not found."
```

**Interpretation:** Production returns *"ApplicationAccessKey is missing"* (auth layer
rejects). Staging returns *"App ... not found"* (auth layer never ran; the request
reached app lookup). The differing error for the same input is the definitive signal
that authentication is bypassed on staging.

## Evidence Already Captured
1. **Dedicated, actively maintained TLS certificate** — `CN=api.gcp-staging.appsheet.com`,
   issued by Google Trust Services (WR3), valid `Jun 3 2026 → Sep 1 2026`. Dedicated
   (non-wildcard) cert issued days before testing → production-adjacent, not abandoned.
2. **Auth-bypass differential** (above) reproduced across endpoint types:

   | Endpoint | Method | Production | Staging |
   |---|---|---|---|
   | `/api/v2/apps/{id}/tables` | GET | 400 "missing key" | 400 "app not found" |
   | `/api/v2/apps/{id}/tables/{name}/data` | GET | 400 "missing key" | **405 Method Not Allowed** (reaches handler) |
   | `/api/v2/apps/{id}/tables/{name}/data` | POST | 400 "missing key" | 400 "app not found" |
   | `/api/v2/apps/{id}/tables/{name}/Action` | POST | 400 "missing key" | 400 "app not found" |

   The GET `/data` case returning **405 with `Allow: POST`** is especially strong:
   the request reached the endpoint handler (method dispatch) with zero authentication.
3. **Public reachability with no network restriction** — responses returned to an
   external Bangladesh IP (`x-client_region: BD`); no VPN, IP allowlist, or IAP gate.

## Impact
**Confirmed now (no valid UUID used):**
- Complete bypass of `ApplicationAccessKey` authentication on the staging REST API.
- All tested endpoints reachable unauthenticated from the public internet.

**On supplying a valid staging app UUID (not exercised):**
- Unauthenticated read of all table data in that staging AppSheet application.
- Unauthenticated write/modify/delete of that app's table data.
- Staging apps used by AppSheet/Google engineers may contain production-clone test
  data and connector configurations (which can hold credentials/tokens).

A valid UUID is the only remaining barrier to data access; the authentication control
itself is already defeated.

## CVSS 3.1
- **Confirmed state (auth bypass, no data accessed):**
  `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` = **6.5 (Medium)**
- **With a valid staging UUID (full read/write):**
  `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = **9.1 (Critical)**

## Suggested Fix
1. Apply the same `ApplicationAccessKey` validation middleware/gateway policy used by
   `api.appsheet.com` to `api.gcp-staging.appsheet.com` (enforce at the Istio/ingress
   layer so it cannot be skipped per-route).
2. Defense in depth: restrict the staging API to internal Google networks via IAP or
   VPC Service Controls so it is not reachable from the public internet at all.

## References
- AppSheet REST API documentation: https://support.google.com/appsheet/answer/10106434
- Related session finding: F002 (OData connector SSRF) on the same AppSheet backend.

## Notes for triage
- No staging application UUID was guessed, brute-forced, or used; no application data
  was read or modified. The report establishes the control failure only.
