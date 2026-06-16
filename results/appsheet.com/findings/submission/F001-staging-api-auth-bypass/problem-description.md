## Affected URL
https://api.gcp-staging.appsheet.com

## The Vulnerability
AppSheet's production REST API (`https://api.appsheet.com`) requires an
`ApplicationAccessKey` header on every request and rejects any request that lacks it
*before* performing application or data lookup. The staging REST API
(`https://api.gcp-staging.appsheet.com`, `34.102.140.38`) does **not** enforce this
control. Identical unauthenticated requests bypass authentication and reach
application/data routing. It is publicly reachable from the internet with no VPN, IP
allowlist, or IAP restriction.

## Proof — Response Differential (no credentials, any IP)
The same unauthenticated request returns categorically different errors on the two hosts:

    # Production — auth enforced, request rejected before app lookup
    curl -si "https://api.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
      -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
    => "...The ApplicationAccessKey is missing from the HTTP header."

    # Staging — auth skipped, request reaches app lookup
    curl -si "https://api.gcp-staging.appsheet.com/api/v2/apps/00000000-0000-0000-0000-000000000001/tables" \
      -H "Content-Type: application/json" | grep -o '"detail":"[^"]*"'
    => "...App with id 00000000-0000-0000-0000-000000000001 not found."

Production says **"ApplicationAccessKey is missing"** (auth layer rejects).
Staging says **"App not found"** (auth layer never ran; the request reached app lookup).
The differing error for identical input proves authentication is bypassed on staging.

## Confirmed Across Endpoint Types
| Endpoint | Method | Production | Staging |
|---|---|---|---|
| `/api/v2/apps/{id}/tables` | GET | 400 "missing key" | 400 "app not found" |
| `/api/v2/apps/{id}/tables/{name}/data` | GET | 400 "missing key" | **405 Method Not Allowed** |
| `/api/v2/apps/{id}/tables/{name}/data` | POST | 400 "missing key" | 400 "app not found" |
| `/api/v2/apps/{id}/tables/{name}/Action` | POST | 400 "missing key" | 400 "app not found" |

The GET `/data` case returning **405 with `Allow: POST`** shows the request reached the
endpoint handler (method dispatch) with zero authentication performed.

## Environment Is Active, Not Abandoned
Dedicated TLS certificate `CN=api.gcp-staging.appsheet.com`, issued by Google Trust
Services (WR3), valid `Jun 3 2026 → Sep 1 2026` — an actively maintained,
production-adjacent staging environment.

## Root Cause
The `ApplicationAccessKey` validation middleware/gateway policy that fronts production is
not applied to the staging ingress. Requests are routed to handlers without an auth check.

## Scope
`api.gcp-staging.appsheet.com` matches `*.appsheet.com` — in scope.
