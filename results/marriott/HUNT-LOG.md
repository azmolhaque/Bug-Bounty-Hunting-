# Hunt Log — Marriott Bug Bounty Program

**Program:** Marriott Bug Bounty (HackerOne — hackerone.com/marriott)
**Platform:** HackerOne
**Started:** 2026-06-21
**Status:** SESSION 20 IN PROGRESS — Session 19 complete (ACS probe closed, UAT hosts discovered). Session 20 runbook created: GraphQL endpoint hunt on gateway-apc.marriott.com + UAT host fingerprint (micmt.uat.marriott.com).
**Scope file:** `config/marriott-scope.yaml`
**Scope check:** `SCOPE_FILE=config/marriott-scope.yaml ./scripts/scope-check.sh <host>`

---

## Program Overview

| Stat | Value |
|------|-------|
| Program live | Feb 2020 |
| Total bounties paid | $559,803 |
| 90-day bounties | $38,057 |
| 90-day reports | 239 |
| Reports resolved | 776 |
| Hackers thanked | 377 |
| In-scope assets | 80 |
| Response efficiency | 97% |
| Avg time to first response | 2 hours |
| Avg time to triage | 21 hours |
| Avg time to bounty | ~3 days |

### Bounty Table

| Severity | Range | Avg |
|----------|-------|-----|
| Critical | $8,001 – $11,000 | $11,000 |
| High | $6,000 – $8,000 | $4,465 |
| Medium | $600 – $3,429 | $2,202 |
| Low | $300 – $599 | $442 |

---

## Attack Surface Analysis

### High-Value Clusters (by report count + freshness)

| Asset | Severity Tier | Prior Reports | Priority |
|-------|--------------|--------------|----------|
| `gatewaydsapdev2.marriott.com` | Critical | 0 | **TOP — DEV env, untouched** |
| `psp.marriott.com` | Critical | 0 | **TOP — payment system, untouched** |
| `lawmanager.marriott.com` | Critical | 0 | **TOP — legal data, untouched** |
| `*gateway-apc.marriott.com` | Critical | 0 | **TOP — new wildcard Oct 2025** |
| `*.artifactory.marriott.com` | High | 0 | **TOP — artifact stores = cred exposure** |
| `*.apigwc.marriott.com` | High | 0 | **TOP — API gateway wildcard, untouched** |
| `*.apigatewayc.marriott.com` | High | 0 | **TOP — API gateway wildcard, untouched** |
| `auth-apc.marriott.com` | High | 0 | **TOP — auth endpoint, untouched** |
| `ssm-marriottms.saviyntcloud.com` | High | 0 | **TOP — IAM platform, new Oct 2025** |
| `*uat.marriott.com` | High | 0 | **TOP — UAT env wildcard, untouched** |
| `gatewaydsaptst1.marriott.com` | Critical | 2 | HIGH — TEST env |
| `dcfgatewaytst1.marriott.com` | Critical | 1 | HIGH — TEST env |
| `passwordchallenge.marriott.com` | Critical | 2 | HIGH — employee PW reset |
| `sso.marriott.com` | Critical | 33 | MEDIUM — well-tested but critical |
| `homes-and-villas.marriott.com` | Critical | 17 | MEDIUM — multi-tenant property IDOR |
| `help.marriott.com` | Critical | 17 | MEDIUM — support data access |
| `owa.marriott.com` | Medium | 0 | HIGH — OWA/Exchange NTLM disclosure |

### Bug Class Hypothesis by Target

**DEV/TEST Gateways** (`gatewaydsapdev2`, `gatewaydsaptst1`, `dcfgatewaytst1`, `*uat.marriott.com`):
- Missing auth on API endpoints (401 not 403 → register → test)
- Spring Boot Actuator exposure (`/actuator`, `/actuator/env`, `/actuator/heapdump`)
- Swagger / OpenAPI without auth (`/swagger-ui.html`, `/v2/api-docs`, `/v3/api-docs`)
- Debug endpoints (`/debug`, `/console`, `/trace`)
- SAP DSP gateway-specific endpoints (`/sap/opu/odata/`, `/sap/bc/`)
- Hardcoded credentials or API keys in JS bundles

**Artifactory** (`*.artifactory.marriott.com`):
- Anonymous access to artifact repositories
- API token exposure in artifact metadata
- Unauthenticated REST API (`/api/v1/system/ping`, `/api/v1/repositories`, `/api/storage/`)
- Package files containing hardcoded credentials (`.env`, `application.properties`)

**API Gateways** (`*.apigwc.marriott.com`, `*.apigatewayc.marriott.com`, `*.dcfgateway.marriott.com`):
- SSRF via URL-forwarding parameters
- Auth bypass on GET vs POST (method confusion)
- Missing auth on `/health`, `/status`, `/metrics` endpoints
- Token replay / JWT algorithm confusion

**PSP** (`psp.marriott.com` — payment service):
- Webhook URL SSRF (Stripe/payment webhook forwarder)
- Payment amount manipulation (integer, negative, zero)
- Cross-tenant payment context leak
- IDORs on payment records (`/payments/{id}`, `/transactions/{id}`)

**Auth/SSO** (`sso.marriott.com`, `auth-apc.marriott.com`):
- OIDC redirect_uri bypass
- OAuth state parameter fixation
- Token leakage via Referer header
- Account pre-takeover (email change flow race condition)

**Saviynt IAM** (`ssm-marriottms.saviyntcloud.com`):
- Role enumeration without auth
- Privilege escalation via role assignment API
- User management IDOR (access others' role assignments)

**OWA** (`owa.marriott.com`):
- NTLM hash disclosure via `/autodiscover/autodiscover.xml`
- Pre-auth internal host enumeration via `/EWS/Exchange.asmx`

---

## OOS Quick Reference (avoid these or lose the bounty)

- Reflected XSS → OOS since April 2025
- DOM XSS requiring interaction → OOS
- Open redirects → OOS unless chain to ATO
- Web Cache Poisoning → OOS
- Leaked tokens → need ATO proof
- HTML injection → OOS
- MITM at hotel network → OOS
- Do NOT fuzz with 10k+ requests

---

## Sessions

### Session 1 — 2026-06-21 (COMPLETE — Recon + Phase A HTTP done)

**Goal:** Phase 1-2 recon — DNS fingerprint + HTTP surface mapping.
**Status:** COMPLETE. 60/80 assets resolved. Phase A HTTP probes complete from Pi.

**Key recon findings:**
- `sso.marriott.com` is **NXDOMAIN** — 33-report SSO endpoint dead. Auth surface moved.
- **7 raw AWS EC2 hosts with no WAF/CDN**: esupplier, device, marrtool, marriottfranchisetransactions, mgs, splunk-phantom-nlb, university — direct exploitation viable
- **APC cluster convergence**: auth-apc, apcgateway, gateway-apc all → `23.61.96.201`

**Phase A HTTP Probe Results (from Pi 2026-06-21):**

| Host | Result | Action |
|------|--------|--------|
| `psp.marriott.com` | **200 / 4853B** | PURSUE — live payment service |
| `esupplier.marriott.com` | **200 / 54985B** | PURSUE — large live app, raw EC2, no WAF |
| `mgs.marriott.com` | **200 / 19501B** | PURSUE — live messaging portal |
| `marriottfranchisetransactions.marriott.com` | **200 / 12595B** | PURSUE — live financial portal |
| `homes-and-villas.marriott.com` | **200 / 3.8MB** | PURSUE (known 17 reports) |
| `traveler.marriott.com` | **200 / 267KB** | PURSUE |
| `eidhelp.marriott.com` | **200 / 7767B** | PURSUE — small employee identity app |
| `www.ritzcarlton.com` | **200 / 256KB** | PURSUE |
| `ci-propertyconversionportal.marriott.com` | **200 / 5939B** | PURSUE — small app, 1 prior report |
| `cpp.marriott.com` | **301 → /s/** | **Salesforce Community Cloud** — IDOR target |
| `ssm-marriottms.saviyntcloud.com` | **302 → /ECM** | PURSUE — Saviynt IAM confirmed alive |
| `efast.marriott.com` | **401 / 6834B** | PURSUE — auth required, service alive |
| `bpa2.marriott.com` | **302 → /Login/Login** | PURSUE — portal alive |
| `owa.marriott.com` | **302 → /owa/** | PURSUE — Exchange confirmed alive |
| `gatewaydsapdev2.marriott.com` | 404 / 261B | Probe specific paths (actuator/swagger) |
| `apcgateway.marriott.com` | 503 | Service unavailable |
| `dcfgatewaytst1.marriott.com` | **000 timeout** | Private DC — only accessible internally? |
| `lawmanager.marriott.com` | **000 timeout** | Zscaler internal — inaccessible externally |
| `sso.marriott.com` | **000 (NXDOMAIN)** | DEAD — find new auth endpoint |

**NEW SCOPE GAP DISCOVERIES (via redirects):**
- `device.marriott.com` → redirects to **`mdmconsole.marriott.com/AirWatch/default.aspx`**
  - AirWatch (VMware Workspace ONE) MDM console! `mdmconsole.marriott.com` NOT in scope list
  - Action: Email domain.administrator@marriott.com to confirm scope, or test only `device.marriott.com` itself
- `passwordchallenge.marriott.com` → redirects to **`mgscloud.marriott.com`**
  - `mgscloud.marriott.com` NOT in explicit scope list — do NOT follow redirect

**cpp.marriott.com Salesforce Finding:**
- `cpp.marriott.com/s/` = Salesforce Community Cloud (Experience Cloud)
- Salesforce Guest User Object Exposure is a common bug class: unauthenticated API access to `sObject` data
- Probe: `/services/data/v55.0/sobjects/`, `/s/sfsites/aura`, aura actions without auth

**Infrastructure map:**

| Infra | Count | Notable |
|-------|-------|---------|
| Akamai (WAF) | 24 | Most public-facing assets |
| AWS EC2 direct (NO WAF) | 7 | esupplier, device, marrtool, franchisetx, mgs, splunk, university |
| AWS CloudFront | 8 | mipartnerprivileges, ifast, efast, eidhelp, activities, ifast |
| Zscaler/Marriott-CDN | 6 | owa, lawmanager, oasisprod, bpa2 — internal-facing |
| Marriott Private DC | 2 | dcfgatewaytst1, sba.marriott.com |
| Cloudflare | 2 | ssm-marriottms.saviyntcloud.com, hotel-development |
| GCP | 2 | join.marriott.com, moments.marriott.com |
| Oracle Cloud OCI | 1 | ocijlbex1prd.marriott.com |
| NXDOMAIN (dead) | 6 | **sso.marriott.com** (33 prior reports — moved), wechat.api, ifast alt |

### Session 2 — 2026-06-21 (RAN on Pi — analysis context lost, see note)

**Goal:** Active HTTP probe (8 phases) of raw EC2 hosts, CT log enum, APC cluster, DEV gateways,
PSP, Saviynt IAM, OWA, Salesforce Community Cloud.
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session2.md`
**Status:** Ran on Pi 2026-06-21 (confirmed by terminal screenshots). All 8 phases executed.
Output saved at: `~/hunt/session2/session2-output.txt` on the Pi.

**NOTE:** Analysis was interrupted when session context was compressed. Results need to be
re-read from the Pi output file. Run on Pi:
```bash
cat ~/hunt/session2/session2-output.txt | less -R
# Or to sync with this repo:
cp ~/hunt/session2/session2-output.txt ~/bug-bounty-hunting-/results/marriott/session2/
```

**Phase coverage confirmed:**
- Phase 1: CT log wildcard enum (*.apigwc, *.apigatewayc, *uat, *gateway-apc, *.artifactory)
- Phase 2: Raw EC2 probes + port scans (esupplier, device, marrtool, franchisetx, mgs, splunk)
- Phase 3: APC cluster Host-header routing (23.61.96.201, Akamai)
- Phase 4: SAP DEV gateways (actuator/swagger/OData paths)
- Phase 5: PSP deep probe
- Phase 6: Saviynt IAM (/ECM/api/v5/* without auth)
- Phase 7: OWA NTLM autodiscover
- Phase 7b: Salesforce Community Cloud Aura API + REST sObject
- Phase 8: Live CT-discovered subdomain probe
- Decision Gate: output visible in screenshots

**Awaiting analysis of output file. Start Session 3 after reading session 2 results.**

---

### Session 3 — COMPLETE (2026-06-22)

**Goal:** Targeted manual testing with CVE-informed approach.
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session3.md`
**Status:** COMPLETE. Key results below.

**Session 3 Results (2026-06-22):**

| Phase | Target | Result | Status |
|-------|--------|--------|--------|
| A — Saviynt CVE-2022-23855 | `/ECM/maintenance/forgotpasswordstep1` | HTTP 500 (endpoint exists, not patched-clean 404/403) | AMBIGUOUS — try GET + other payloads |
| A — Saviynt API | `/ECM/api/v5/user/getUser` | **HTTP 401** (auth required, 0B body — WAF or auth wall) | Expected behavior |
| **B — Salesforce Aura** | `cpp.marriott.com/s/sfsites/aura` | **GET HTTP 200 + POST `"state":"SUCCESS"` on User | **CONFIRMED LEAD** |
| B — User getObjectInfo | Aura POST w/ getObjectInfo | **4,500,982 bytes SUCCESS** — User schema returned WITHOUT auth | **ACTIVE — need record test** |
| B — Contact/Account/Lead/Opp | Aura POST getObjectInfo | **4,336,904 bytes ERROR** each — suspiciously large errors | **Parse required** |
| C — esupplier | IIS/10.0 + ASP.NET, all paths 404 | No API endpoints found via generic paths | ASP.NET — need source analysis |
| D — franchisetx | ALL paths 200/7080B (SPA catch-all) | Homepage 12594B, /login 7080B = SPA index.html served everywhere | SPA — need JS bundle |
| E — mgs.marriott.com | Root 200/19501B, all other paths 404 | Nothing open | Low signal |
| PATH errors | grep/head/cat/sort not found | Same PATH issue as session 2 | Fixed in session 4 |

**M002 — Salesforce Aura (cpp.marriott.com): CONFIRMED LEAD**
- Aura API endpoint `/s/sfsites/aura` accessible without credentials (HTTP 200)
- `getObjectInfo` on `User` returns `"state":"SUCCESS"` with **4.5MB response** (full User object schema)
- Contact/Account/Lead/Opportunity return ERROR but with 4.3MB each (need to parse error body — may contain schema data)
- `getItems` on Contact returned ERROR/4.3MB (parse needed to determine if records in error payload)
- **Next: test `getRecord` with User IDs, `getItems` on User, parse ERROR bodies, try SOQL**
- Severity if schema only: ~Medium (5.3). If records readable: High (8.6) to Critical.

**M006 — Saviynt (500 on forgotpassword): AMBIGUOUS**
- `/ECM/maintenance/forgotpasswordstep1` GET → 500, POST → 500 (same error HTML)
- Not a clean 404/403 (patch would give that) — endpoint IS live and erroring
- Could mean: payload format wrong, partial patch, or endpoint broken independently
- Next: try GET with `?username=admin` query param, try form-encoded POST

**M004 — Franchise transactions SPA catch-all: NEEDS JS HUNTING**
- ALL paths return 200 (SPA router serves index.html for unknown routes)
- Need to extract JS bundle from homepage, find real API endpoints
- Next: parse 12594B homepage for script tags → extract JS bundle → mine endpoints

---

### Session 4 — COMPLETE (2026-06-22)

**Goal:** Salesforce Aura deep investigation + Franchise JS extraction + Saviynt retry.
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session4.md`

**Session 4 Results:**

| Phase | Target | Result | Status |
|-------|--------|--------|--------|
| A — Salesforce User schema | `getObjectInfo User` | **SUCCESS 203 fields — Email, FirstName, Address, Company confirmed accessible** | CONFIRMED MEDIUM → test record access |
| A — Contact/Account/Lead | `getObjectInfo` | ERROR 4.3MB each — Aura bootstrap context, NOT data | Schema blocked for guest |
| A — getItems User | `ACTION$getItems` | Internal server error (not ACCESS_DENIED) | Try different descriptor |
| A — REST `/services/data/` | GET | **HTTP 200 / 2556B** | Get response body (version list likely) |
| A — REST `/services/data/v55.0/` | GET | HTTP 401 (auth required) | Expected |
| **B — Franchise /ajax.php** | `/login` source | **Form action=/ajax.php, params: module, function, email, password** | **NEW HIGH LEAD M018** |
| B — JS bundle | `/assets/scripts.jgz?v=7` | Found — need to decompress + mine module/function pairs | Session 5 |
| C — Saviynt forgotpw | All variants | HTTP 500 + uniform 1038B for all ?id=N | **DEPRIORITIZED — likely patched** |
| PATH bug | Phase C loop | `for PATH in /ECM/...` overwrote $PATH — curl not found | Fixed in session 5 |

**M002 — Salesforce Aura Status:**

**CONFIRMED MEDIUM — pending record access test for High/Critical upgrade**

Evidence:
- `cpp.marriott.com/s/sfsites/aura` → unauthenticated POST accepted (`aura.token=undefined`)
- `getObjectInfo User` → `"state":"SUCCESS"` | **203 fields** including: `Email`, `FirstName`, `Address`, `CommunityNickname`, `CompanyName`, `BannerPhotoUrl`, `HasUserVerifiedEmail`
- Guest User profile has "API Enabled" — this is the Salesforce misconfiguration class (ShinyHunters, 2026)
- Contact/Account schema: ERROR state (restricted for guest)
- Record access (`getItems`): "internal server error" not "access denied" — try `getListRecordsByName` with `AllUsers` viewApiName
- REST API `/services/data/` → 200 (version list)

**Immediate next test:** `getListRecordsByName User AllUsers` + download+decompress scripts.jgz

**M018 — Franchise Transactions /ajax.php: NEW LEAD (HIGH)**

PHP application with module/function POST routing:
```
POST /ajax.php
module=<X>&function=<Y>&email_address=<...>&password=<...>
```
If any `module/function` combo is accessible without auth → auth bypass finding (High).
JS bundle `/assets/scripts.jgz?v=7` should contain all valid module/function names.

---

### Session 5 — COMPLETE (2026-06-22)

**Goal:** Salesforce record access + Franchise /ajax.php module enumeration.
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session5.md`

**Session 5 Results:**

| Phase | Target | Result | Status |
|-------|--------|--------|--------|
| A — Salesforce REST | `/services/data/` | 200 = version list (31.0-35.0) — public, not a finding | Informational |
| A — Salesforce records | getListRecordsByName User/Contact | ERROR 4.3MB — records blocked for guest | Schema-only Medium |
| A — Salesforce REST sObjects | With guest cookie | 401 INVALID_SESSION_ID | No guest REST access |
| **B — Franchise user/list** | `module=user&function=list` | **HTTP 200 / 431B / PHP Fatal Error: json_decode()** | **CONFIRMED AUTH BYPASS** |
| B — All other module/func combos | 93B uniform | Standard false-response (function not found/unauth) | Expected |
| B — JS bundle decompressed | `/assets/scripts.jgz` | **352KB JS — real modules: applications_v2, user_auth, auth** | **Module names extracted** |
| B — Real functions | assignee_delete, save_fields, process_submit, etc. | Found in JS — test in session 6 | Queue |

**M018 — Franchise Transactions CRITICAL LEAD:**

**CONFIRMED AUTH BYPASS — `module=user&function=list` reaches server code without session**

Evidence:
- All other module/function combos → 93B `{"html":false,"data":false,...}` (standard not-found/unauth)
- `module=user&function=list` → **431B + PHP Fatal Error: `json_decode(): Argument #1 ($json)`**
- Fatal error means: function IS executing (auth check bypassed), fails because we sent form-encoded not JSON
- Real module names from JS bundle: `applications_v2`, `user_auth`, `auth`
- Real functions: `prelogin`, `continue_session`, `forms`, `render_checklist`, `save_fields`, `process_submit`
- CSRF token extracted: `5551b494fdf90c7381bbfe7942a54b5dd2f6fd59` (refreshed per session)
- App title: **"Marriott Owner and Franchise Services"** — franchise hotel owners' financial portal

**Session 6 tests:** Send proper JSON `data` parameter to get user data; test real module names.

---

### Session 6 — COMPLETE (2026-06-22)

**Goal:** Franchise auth bypass exploitation + Salesforce Aura confirmation.
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session6.md`
**Status:** COMPLETE. Two findings confirmed report-ready.

**Session 6 Results:**

| Phase | Target | Result | Status |
|-------|--------|--------|--------|
| A1 — JSON body | `/ajax.php` Content-Type:application/json | **93B false** — module/function not parsed from JSON body | Expected ($POST array not populated) |
| **A2 — Form + data={}** | `/ajax.php module=user&function=list&data={}` | **430B PHP Fatal Error + STACK TRACE** | **CONFIRMED — full trace captured** |
| A3 — Form + data=null | Same | 430B fatal error | Identical to A2 |
| A4 — Form + data= (empty) | Same | 430B fatal error | Identical |
| A5/A6/A7 — JSON variants | Various | 93B false | JSON body never routes |
| B — Real module names | `applications_v2/*, user_auth/*` (13 functions) | **93B false for all** | Real functions auth-protected |
| C — user/list without cookie | Confirm unauthenticated | **430B without session cookie** | **AUTH BYPASS CONFIRMED** |
| D — Salesforce reconfirm | `getObjectInfo(User)` | **`state=SUCCESS` | 203 fields** | **MEDIUM CONFIRMED READY TO REPORT** |

**M018 — CONFIRMED FINDING: Auth Bypass + Absolute Path Disclosure**

Full PHP stack trace captured (no session cookie required):
```
Fatal error: Uncaught TypeError: json_decode(): Argument #1 ($json) must be of type string,
array given in /FranLic/www/html/lib/internal/request.inc.php:233
Stack trace:
#0 /FranLic/www/html/lib/internal/request.inc.php(233): json_decode(Array)
#1 /FranLic/www/html/ajax.php(26): process_request(Object(MysqliDb))
#2 {main}
```

Evidence confirms:
- `module=user&function=list` reaches server code WITHOUT session cookie (93B → 430B = different code path)
- `MysqliDb` object constructed and passed = DB connection live behind auth gate
- PHP 8 strict typing prevents data return (`json_decode(Array)` throws TypeError)
- **Absolute server path disclosed**: `/FranLic/www/html/` ("FranLic" = Franchise Licensing)
- Real module names (`applications_v2`, `user_auth`) all return 93B → properly protected

**CVSS estimate:** 5.3 Medium (auth bypass demonstrable, data not returned due to PHP 8 type error)  
**Status: REPORT-READY**

**M002 — CONFIRMED FINDING: Salesforce Guest User Aura API Exposure**

Session 6 Phase D reconfirmed: `getObjectInfo(User)` → `"state":"SUCCESS"` | 203 fields including Email, FirstName, Address, CommunityNickname, CompanyName, HasUserVerifiedEmail.  
Guest User profile has API access enabled — matches ShinyHunters attack class (March 2026 wave).  
Contact/Account schema blocked for guest profile.  
Session 7 further confirmed: Phone + MobilePhone fields added, LWC endpoints discovered live, Salesforce org instance usa850 identified. Report held pending Session 8 LWC exploration.

**CVSS estimate:** 5.3 Medium  
**Status: REPORT-READY (holding for Session 8 LWC chain test)**

---

### Session 7 — COMPLETE (2026-06-22)

**Goal:** Reconfirm M018 + M002, chain elevation attempts, new targets.
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session7.md`
**Status:** COMPLETE. Both findings confirmed. LWC new surface discovered.

**Session 7 Results:**

| Phase | Target | Result | Status |
|-------|--------|--------|--------|
| A — M018 reconfirm | `module=user&function=list` (no cookie) | **430B fatal error CONFIRMED** | Auth bypass still active |
| B1/B2 — GET routing bypass | `?module=user&function=list` + JSON body | 93B — routing uses `$_POST`, not `$_REQUEST` | Chain closed |
| **B3 — Multipart test** | `-F module=user -F function=list -F data={"page":1}` | **430B — definitively proves `json_decode($_POST)` bug** | **KEY EVIDENCE** |
| B4 — HTTP Parameter Pollution | Double `module=` parameter | 430B (PHP uses last value, both path same) | No new bypass |
| **B5 — CSRF bypass** | No `activekey` field at all | **430B — CSRF not validated** | **CSRF bypass confirmed** |
| B6/B7 — Function/module enum | 24 user functions + financial modules | All 93B | Only user/list bypasses auth |
| B8 — Backup files | `.env`, `.git/HEAD`, `phpinfo.php` etc. | All 7080B SPA catch-all (false positives) | SPA serves index.html for all unknown paths |
| C — M002 reconfirm | getObjectInfo(User) | **state=SUCCESS \| 203 fields \| Phone+MobilePhone added** | CONFIRMED MEDIUM |
| C2 — Contrast | getObjectInfo(Contact) | state=ERROR | Contrast confirmed |
| D1-D5 — Record access | searchRecords, getListUi, getItems, getRecord, getCurrentUserOrGuest | All `state=warning` 11279B (framework mismatch, NOT "access denied") | Records not returned; different code path from permission block |
| D6 — CommLoginController | Three email addresses | All 11279B identical | User enumeration NOT possible (no differential) |
| **D9 — Error body analysis** | Contact ERROR body | **Real fwuid extracted; Salesforce instance: usa850** | FWUID for future session tests |
| **D10 — LWC discovery** | `/s/sfsites/lwr/` + `/s/sfsites/lwr/fetch` | **200 / 1368B and 200 / 1383B — LIVE** | **NEW UNEXPLORED ATTACK SURFACE** |
| D8 — Apex REST | `/services/apexrest/*` | All 404 | Not exposed |
| E1 — marrtool.com | All paths | 000 timeout | Unreachable externally (IP-restricted or internal only) |

**M018 FINAL STATUS:** REPORT-READY (Medium, CVSS 5.3). B3 and B5 strengthen the finding.
**M002 STATUS:** One more session needed — LWC endpoints unexplored. Hold M002 report until Session 8.

**M019 — NEW LEAD: Salesforce LWC Wire Endpoints**
- `/s/sfsites/lwr/` → HTTP 200 / 1368B
- `/s/sfsites/lwr/fetch` → HTTP 200 / 1383B
- LWC is the newer Salesforce component framework with a different wire protocol
- If LWC wire adapters allow guest record access (different access control model than Aura), this could elevate M002 to High
- Session 8 focus

---

### Session 8 — COMPLETE (2026-06-22)

**Goal:** LWC wire endpoint probe, real fwuid Aura tests, psp.marriott.com, esupplier.
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session8.md`
**Status:** COMPLETE. Both findings confirmed report-ready. LWC closed. PSP blocked.

**Session 8 Results:**

| Phase | Target | Result | Status |
|-------|--------|--------|--------|
| **A — LWC wire endpoints** | `/s/sfsites/lwr/*` all subpaths | All 200 + **JavaScript login redirect** → `/s/login?ec=302` | **M019 CLOSED — LWR requires auth, properly protected** |
| B — Real fwuid Aura tests | All requests | 298B (broken helper — `aura.context=` prefix missing) | **Helper bug; real fwuid not actually tested** |
| C — Salesforce direct org | `usa850.salesforce.com` | 000 timeout — pod not externally accessible | Blocked |
| **D — psp.marriott.com** | Root page + endpoints | Root = **meta-refresh to PingFederate SSO** → `extranet.marriott.com/2FAmarrsso/idp/startSSO.ping?PartnerSpId=Marriott-SAML2-SP-EverestRCD-PROD` | **BLOCKED — employee SAML2 SSO required** |
| D2 — psp endpoints | All 40+ paths | Only `/login` returns 301 | No open endpoints |
| E — esupplier | ASP.NET paths | `/trace.axd` → 403 (exists, blocked) | Not a finding |

**Key discoveries:**
- `psp.marriott.com` → PingFederate SAML2 ("EverestRCD" app) via `extranet.marriott.com` — requires Marriott employee credentials, inaccessible externally
- LWR properly protected (auth redirect, not open)
- Session 8 confirms M002 record access is definitively blocked: LWR gated, Apex REST 404, REST SOQL 401, all Aura record calls blocked

**FINAL STATUS for both findings:**
- **M018:** REPORT-READY. Confirmed across Sessions 5-7 with 3 encoding variants and CSRF bypass.
- **M002:** REPORT-READY. Confirmed across Sessions 3-8. All record access paths exhausted. Schema exposure as Medium is the finding.

---

### Session 9 — COMPLETE (2026-06-22)

**Goal:** M018 submission + M002 chain elevation attempt (getConfigData, executeGraphQL, getObjectInfos batch).
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session9-M002-chain.md`
**Status:** COMPLETE. M018 submitted. M002 chain partially tested.

**Session 9 Results:**

| Phase | Target | Result | Status |
|-------|--------|--------|--------|
| — | M018 | Submitted to HackerOne as **#3816825** (CWE-287 + CWE-209, Medium) | **SUBMITTED** |
| A — Bootstrap | fwuid validation | state=SUCCESS \| 203 fields — fwuid confirmed valid | Phase A complete |
| B — Record access | getItems, getListUi, searchRecords, getCurrentUserOrGuest | All return `actions:[]` (11092B) — empty actions array | Blocked at Aura framework layer |
| E2 — getObjectInfos batch | User + Contact + Account + Lead + Opportunity | 176674B state=SUCCESS — User=203F, all others 403 | Partial success |
| P3 — Self-registration | NetworkSelfRegistration | returnValue=False | Self-reg disabled |
| getConfigData | 187 objects | **187 accessible sObject names + key prefixes including OauthToken, UserLogin, NetworkMember** | **NEW EVIDENCE** |
| executeGraphQL | User query | state=SUCCESS but ValidationError: `Id {value}` on scalar type ID! | Syntax bug — fixable |
| getItems on 187 objects | All objects | SyntaxError in parse_items helper (`return` outside function) | **BUG — all tests failed** |

**Session 9 bugs discovered (fixed in Session 10):**
1. `parse_items` Python function had `return` at top level → SyntaxError on all getItems tests
2. `executeGraphQL` query used `Id {value}` but `Id` is scalar type `ID!` — cannot use `{value}` wrapper

---

### Session 10 — COMPLETE (2026-06-22)

**Goal:** Fix getItems SyntaxError + executeGraphQL scalar Id fix, re-run all record access attempts.
**Runbook:** `runbooks/PI-RUNBOOK-marriott-session10-M002-getitems.md`
**Status:** COMPLETE. All getItems tests run. Record access definitively blocked.

**Session 10 Results:**

| Phase | Target | Result | Status |
|-------|--------|--------|--------|
| B1-B4 — getItems Tier 1 | NetworkMember, OauthToken, UserLogin, User | **actions:[] empty (0B actionsTotal)** — Aura framework block | Record access: BLOCKED |
| C1-C8 — getItems Tier 2 | ContentDocument, ContentVersion, CollaborationGroup, FeedItem, Network, Profile, Organization | **actions:[] empty** — all Aura-blocked | Record access: BLOCKED |
| D — getListUi | User, NetworkMember, CollaborationGroup | 11092B actions:[] | Blocked |
| E — executeGraphQL | User, NetworkMember, CollaborationGroup, FeedItem | state=ERROR, INVALID_INPUT "GraphQL input is required for POST" | Reachable action but wrong format |
| F — searchRecords (SOSL) | User, NetworkMember, ContentDocument | 11092B actions:[] | Blocked |
| G — getCurrentUserOrGuest | Guest user ID | 11092B actions:[] | Blocked |
| H — CommLoginController | Email enumeration × 3 | 11092B actions:[] | Not accessible to guest |
| I1 — getObjectInfos batch | NetworkMember, OauthToken, UserLogin | NetworkMember=INVALID_TYPE — not in UI API | Cannot schema-test these objects |

**Key finding from Session 10:**
- `actionsTotal=0` for ALL getItems/getListUi/searchRecords → Aura FRAMEWORK-level block (not app-level access denied)
- `executeGraphQL` has `actionsTotal=3` (action was routed and executed) → NOT blocked at framework level, but INVALID_INPUT error persists

---

### Session 11 — COMPLETE (2026-06-22)

**Goal:** Final executeGraphQL format investigation + getObjectInfos I2 with fixed parser + additional picklist enumeration.
**Runbook:** `runbooks/PI-FOLLOWUP-session11-final.sh`
**Status:** COMPLETE. All tests done. M002 evidence complete. Chain elevation closed.

**Session 11 Results:**

| Test | Target | Result | Status |
|------|--------|--------|--------|
| executeGraphQL 1a | Direct curl, bare Id, single-quoted | state=ERROR, INVALID_INPUT, actionsTotal=6 | Still fails — not a shell escaping issue |
| executeGraphQL 1b | `document` instead of `query` param key | state=ERROR, INVALID_INPUT, actionsTotal=3 | Same error — not a param key issue |
| executeGraphQL 1c | NetworkMember query | state=ERROR, INVALID_INPUT, actionsTotal=5 | Same error — architectural: action reads query from HTTP body, not Aura params |
| **getObjectInfos I2 (fixed parser)** | ContentDocument, ContentVersion, FeedItem | **ACCESSIBLE: ContentDocument 27F, ContentVersion 47F, FeedItem 28F** | **NEW EVIDENCE** |
| getObjectInfos I3 | User, Profile, Organization, Network | **User 203F, Profile 517F, Organization 41F, Network 10F** | **Profile 517F is new headline finding** |
| getPicklistValues | LanguageLocaleKey, LocaleSidKey, TimeZoneSidKey | **SUCCESS: 18, 279, 426 values respectively** | Confirmed multiple picklist actions work |
| getPicklistValues | ProfileId | state=ERROR (correct — reference field, not picklist) | Expected |

**executeGraphQL conclusion:** Consistently fails with same INVALID_INPUT error across all format variants (both `query`/`document` param names, both curl helper and direct single-quoted curl, both User and NetworkMember objects). The action is architecturally proxying to an internal GraphQL endpoint and reading the query from the HTTP request body directly (not from Aura params), which is incompatible with the Aura form-encoded request format. **This path is definitively closed.**

**M002 FINAL STATUS:**
- 7 sObjects with accessible schemas: User (203), Profile (517), Organization (41), Network (10), ContentDocument (27), ContentVersion (47), FeedItem (28) = **873 total fields**
- getPicklistValues confirmed working: UserType (8 values), LanguageLocaleKey (18), LocaleSidKey (279), TimeZoneSidKey (426)
- getConfigData confirmed: 187-object inventory with key prefixes
- All record access paths definitively blocked at Aura framework layer
- **SUBMIT AS MEDIUM (5.3) — all chain paths exhausted**

---

### Session 12 — COMPLETE (2026-06-22)

**Goal:** Final three unexplored escalation paths — executeGraphQL separate field format, direct REST GraphQL, custom Apex controllers.
**Runbook:** `runbooks/PI-ESCALATION-session12.sh`
**Status:** COMPLETE. All three paths closed. Root cause of executeGraphQL failure identified.

**Session 12 Results:**

| Path | Test | Result | Conclusion |
|------|------|--------|-----------|
| 1a executeGraphQL | Separate `query=` field, params={}, User | `actionsTotal=0` state=ERROR INVALID_INPUT | Aura framework block — empty params fails before routing |
| 1b executeGraphQL | Separate field, params has empty query string | `actionsTotal=0` state=ERROR INVALID_INPUT | Same |
| 1c executeGraphQL | Separate field, NetworkMember query | `actionsTotal=2` state=ERROR INVALID_INPUT | Routed but still fails |
| 2a REST GraphQL GET | /v55.0/graphql + guest cookie | **HTTP 403 / 125B** | Access denied |
| 2b REST GraphQL POST | /v55.0/graphql + JSON body | **`API_DISABLED_FOR_ORG` — "Chatter Connect API not enabled"** | **ROOT CAUSE FOUND** |
| 2c REST GraphQL POST | /v57.0/graphql | Same `API_DISABLED_FOR_ORG` | Permanent org config |
| 3a CPP Apex controllers | 15 names × 11 methods | All actions:[] (no output) | All Aura-framework blocked |
| 3b Standard community controllers | 7 controllers (NetworkMemberController etc.) | All actions:[] | All blocked |
| 3c CommLoginController | 2 email addresses | `actionsTotal=0` both | Aura-layer blocked |

**Root cause of executeGraphQL failure (resolved):** `"API_DISABLED_FOR_ORG"` — `"The Chatter Connect API is not enabled for this organization or user type."` Salesforce's GraphQL API uses the Chatter Connect API infrastructure. This org has Chatter Connect API disabled at the org level. The `executeGraphQL` Aura action cannot succeed on this org because the underlying API it proxies to is unavailable. This is an administrative org-level setting and is permanently blocked.

**Chain elevation: DEFINITIVELY CLOSED across 12 sessions.**

All record access mechanisms confirmed blocked:
- Aura record actions (getItems, getListUi, searchRecords, getCurrentUserOrGuest): `actions:[]` framework block
- executeGraphQL: Chatter Connect API disabled at org level
- REST GraphQL (/services/data/vXX/graphql): 403 + API_DISABLED_FOR_ORG
- REST SOQL: 401 INVALID_SESSION_ID
- Custom Apex controllers (15 CPP-themed + 7 standard community): Aura framework block
- LWC /lwr/fetch: Dead endpoint (404)

**SUBMIT M002 AS MEDIUM (5.3) — NO FURTHER ESCALATION POSSIBLE.**

---

### Session 13 — COMPLETE (2026-06-22)

**Goal:** Four-target sweep — gatewaydsapdev2 (M005), esupplier (M001), eidhelp (M010), bpa2 (M012).
**Runbooks:** `runbooks/PI-RUNBOOK-session13-four-targets.sh`, `runbooks/PI-FOLLOWUP-session13-bpa2-esupplier.sh`
**Status:** COMPLETE. All four targets assessed; none yielded a submittable finding.

**Session 13 Results:**

| Target | Lead | Result | Decision |
|--------|------|--------|----------|
| `gatewaydsapdev2.marriott.com` | M005 | Akamai WAF returns uniform 404/261B for **all** probed paths (root, actuator, swagger-ui, SAP OData, Spring Boot debug, backup files). No path visibility past the WAF. | **CLOSED** |
| `esupplier.marriott.com` | M001 | Root page (54985B) is a static Microsoft Word HTML document (Word 14, saved 2014, Windows-1252). No ASP.NET app here. Real Oracle PeopleSoft Financials portal lives at `extranet.marriott.com/psfin` — `extranet.marriott.com` is **OUT-OF-SCOPE** (scope-check: `*.marriott.com` catch-all applies, not explicitly listed). Document paths (`/marrforms/esuppliersplash.htm`, etc.) not yet probed due to shell PATH error. | **PARKED — static host; real app OOS** |
| `eidhelp.marriott.com` | M010 | Static S3+CloudFront site. All 12+ dropdown options (Associates, Franchisees, Owners, Ritz-Carlton, Vendors, Consultants, etc.) route to identical URL: `https://eidhelp.marriott.com/help/index.html`. No API surface, no JS bundles mining value, no dynamic endpoints. `x-amz-meta-user-agent-id: jblaney@s-3be2486a258a4a059` in headers (IAM username — informational, no exploit path). | **CLOSED** |
| `bpa2.marriott.com` | M012 | Checkpoint Web Server (CPWS) allowlist routing. Only `/Login/Login.css` (7835B) accessible outside allowlist; all other paths return uniform 403/5125B "not configured." Login form tests (CSRF extraction, user enumeration differential, SQLi probe) did not complete — script jumped from B2 to B6 due to cookie-check redirect loop (`CheckCookieSupport=1`). | **PARKED — CPWS locked; low ROI** |

**Infrastructure note — scope-check.sh critical fix:**
- Bug discovered: `*.marriott.com` catch-all in `out_of_scope` was blocking all explicitly listed in-scope targets.
- Fix applied in `scripts/scope-check.sh`: exact (non-wildcard) in_scope entries now checked FIRST before out_of_scope (specific beats general). Wildcard out-of-scope still beats wildcard in-scope.
- Verified: all 4 session-13 targets correctly return IN-SCOPE; `random-unlisted.marriott.com` still OUT-OF-SCOPE; `extranet.marriott.com` correctly OUT-OF-SCOPE.

**Next session:** mgs.marriott.com (M007) — raw EC2 200/19501B, no WAF, zero prior reports. Secondary: ci-propertyconversionportal.marriott.com (M011, 200/5939B, 1 prior report).

---

### Session 14 — COMPLETE (2026-06-22)

**Goal:** mgs.marriott.com (M007) + ci-propertyconversionportal (M011) + esupplier document paths (S13 leftover).
**Runbook:** `runbooks/PI-RUNBOOK-session14-mgs-ciportal.sh`
**Status:** COMPLETE. mgs parked; ci-portal has active differentials; esupplier docs confirmed accessible.

**Session 14 Results:**

| Target | Lead | Result | Decision |
|--------|------|--------|----------|
| `mgs.marriott.com` | M007 | **X-Powered-By: CrafterCMS** — Marriott Global Source employee intranet. All 78 probed paths return 404/387B (CrafterCMS custom 404). No login page, no API surface, no GraphQL. AWSALB cookies confirm ALB (not raw EC2 — earlier recon was wrong about no WAF). Root title: "Marriott International's Global Intranet and Business Application (eTool) Gateway." Employee credentials required. | **PARKED — employee intranet, no external API** |
| `ci-propertyconversionportal.marriott.com` | M011 | Akamai-fronted SPA (title: "PCT Modernization"). SPA catch-all = 5939-5940B. **Three non-catch-all differentials found** (see below). `/.env`, `/web.config`, `/web.config.bak` all return **403 with varying sizes** (406/412/420B — path embedded in error body = app-level block, not Akamai generic). | **ACTIVE — API surface + config file exposure signals** |
| `esupplier.marriott.com` | M001 | `/marrforms/esuppliersplash.htm` → 200/48043B, `/ESupplier-Basics%20Job%20Aid.doc` → 200/564KB, `/Electronic%20Payment%20Authorization%20form.doc` → 200/90KB, `/e-Supplier-%20Self%20Help.pdf` → 200/370KB, `/default_files/filelist.xml` → 200/273B. All publicly accessible. | **DOCUMENT AUDIT — read filelist.xml for more paths; check splash page** |

**ci-propertyconversionportal.marriott.com differential analysis:**

| Path | Response | Interpretation |
|------|----------|----------------|
| `/health` | 200 / **0B** | Real health endpoint — NOT the SPA (SPA = 5940B). Empty 200 = app alive, health ping. |
| `/openapi.json` | 200 / **1280B** | NOT SPA (5940B) and NOT Akamai filler (would be 404). Real small JSON document — likely OpenAPI spec stub. READ CONTENT NEXT. |
| `/v2/api-docs` | 200 / **1280B** | Swagger v2 (Springfox) endpoint — same differential. Same size as openapi.json — may be same content or both stubs. READ CONTENT NEXT. |
| `/.env` | 403 / 406B | Path-aware block (`.env` in body). App-level WAF or nginx deny rule. File may or may not exist. |
| `/web.config` | 403 / 412B | Path-aware block — size differs from .env (6B difference = path length difference in error body). |
| `/web.config.bak` | 403 / 420B | Path-aware block — 8B bigger = `.bak` suffix in error body. Same pattern. |
| `SPA catch-all` | 200 / 5939-5940B | All other paths — SPA index.html served for unknown routes. |

**CrafterCMS note (mgs):** `/rest/v1/delivery` found in Adobe DTM bundle (not relevant — DTM is analytics, not the app API). Uniform 404 across all paths confirms pure employee intranet with no external endpoints.

**Next session:** ci-propertyconversionportal.marriott.com deep dive — read openapi.json + v2/api-docs content, probe all paths with `Accept: application/json` to bypass SPA catch-all, test discovered API endpoints for auth bypass and IDOR.

---

### Session 15 — COMPLETE (2026-06-22)

**Goal:** ci-propertyconversionportal deep dive — read non-SPA differential content, JSON-Accept bypass, actuator, auth discrimination. esupplier document audit.
**Runbook:** `runbooks/PI-RUNBOOK-session15-ci-portal-deep.sh`
**Status:** COMPLETE. ci-portal closed; esupplier dead end confirmed.

**Session 15 Results:**

| Phase | Finding | Conclusion |
|-------|---------|-----------|
| A — Read differential content | `/health`, `/openapi.json`, `/v2/api-docs`, `/robots.txt`, `/sitemap.xml` all return **Akamai 403 `cdn-cache: HIT`** | Session 14 "interesting" differentials were Akamai cache MISSes serving empty origin responses padded with 1280B RUM script. Cache flipped to HIT 403 between sessions. No real API content at those paths. |
| B — JSON Accept probe | Root: 403/398B. All `/api/**` paths: 403 (varying sizes = path-name embedded). `/actuator/health`, `/actuator/info`, `/actuator/env`, `/actuator/mappings`: **200/5939-5940B** = SPA catch-all | Akamai blocks `/api/**` and sensitive dev-path patterns. Spring Boot actuator paths pass through as SPA HTML. No actual actuator data accessible. |
| C — Actuator with Spring Accept header | `/actuator`, `/actuator/health`, `/actuator/env`, `/actuator/mappings`: all **403 HIT** | Akamai blocks `vnd.spring-boot.actuator.v3+json` Accept header on these paths. Different WAF trigger than generic JSON Accept. |
| E — Auth discrimination | `no-auth=403|424` = `fake-token=403|424` for all `/api/v1/*` paths | Akamai blocks BEFORE auth evaluation — cannot distinguish 401 vs 403 at origin. No bypass available without origin IP. |
| F — esupplier filelist.xml | `<o:MainFile HRef="../default.htm"/>` plus image/theme files | Microsoft Office manifest for Word doc support files. Root page (`default.htm`) is the same Word HTML. No application code. Email: `mercuryworkflowadministrator@marriott.com` (legacy Mercury workflow — informational). |
| F — esupplier splash | 5 links, all relative to `esuppliersplash_files/` directory (Word doc artifacts: filelist.xml, editdata.mso, themedata.thmx) | No application links, no login forms, no API hints. Pure static Word document. |

**Root cause of Session 14 "1280B differentials" (now explained):**
- Akamai's `x-akamai-transformed: 9 1280 0 pmb=mRUM,2` confirms Akamai **injected** 1280 bytes of Real User Monitoring script into responses
- Session 14 cache state: `cdn-cache: MISS` → origin returned empty 200 → Akamai added 1280B RUM → curl saw 1280B total  
- Session 15 cache state: `cdn-cache: HIT` → Akamai serves cached 403 for same paths
- There was NEVER real OpenAPI spec content at `/openapi.json` — it was an empty origin response padded by Akamai

**Conclusions:**
- **M011 ci-propertyconversionportal: CLOSED** — Akamai WAF fully blocks all API/actuator paths. SPA serves only auth-gated index.html. No origin IP to bypass with. No external attack surface.
- **M001 esupplier: CLOSED** — All accessible documents are Microsoft Word/Office XML artifacts from 2014. No live application code, no API, no useful attack surface beyond the already-OOS PeopleSoft app at extranet.marriott.com.

**Next session:** M013 (CT wildcard subdomain enum — `*.apigwc`, `*.apigatewayc`, `*gateway-apc`, `*uat.marriott.com`) + M009 (OWA NTLM autodiscover) + efast.marriott.com (401/6834B — check auth type).

---

### Session 16 — COMPLETE (2026-06-22)

**Goal:** CT wildcard enum (M013) + OWA NTLM (M009) + efast auth fingerprint + APC cluster probe.
**Runbook:** `runbooks/PI-RUNBOOK-session16-wildcard-enum-owa.sh`
**Status:** COMPLETE. CT enum failed (crt.sh 502); OWA confirmed internal; efast fingerprinted; auth-apc `/login` live 137KB — NEW HIGH LEAD.

**Session 16 Results:**

| Phase | Finding | Conclusion |
|-------|---------|-----------|
| A — CT enum | crt.sh returned 502 Bad Gateway for all wildcard queries; `*.apigatewayc` returned 0 results | **CT enum failed — retry needed.** No subdomain data obtained. |
| B — DNS brute force | 0 resolved hosts for all prefix combinations against `*.apigwc`, `*.apigatewayc`, `*uat.marriott.com` | No live subdomains found via brute force. Prefix list may not cover Marriott naming conventions. |
| D — OWA | Root 302 → `/owa/` with `Server: BigIP` (F5 LB). Autodiscover/EWS/ActiveSync all timeout (000) | **PARKED** — OWA is internal-facing behind corporate network. BigIP LB handles the redirect but blocks all actual Exchange paths. |
| E — efast | `server: Tomcat`, CloudFront (`x-cache: Error from cloudfront`), `SessionIDCookie` (custom session), NO `WWW-Authenticate` header. Root 401/6834B, `/efast` 401/6839B. All other paths 404/0B (CloudFront 404). | **ACTIVE — form-based auth (custom app-level 401). 6834B body is the login form. Read body next session.** |
| F — APC cluster | `auth-apc.marriott.com` → `000` (all paths except `/login`). **`/login` → 200/137KB** — live SSO login application! | **NEW HIGH LEAD M020 — auth-apc /login is a live 137KB SSO portal** |
| Scope bug | `gateway-apc.marriott.com` incorrectly returned OUT-OF-SCOPE (no-dot wildcard `*gateway-apc.marriott.com` not handled) | **FIXED in scope-check.sh** — added PASS 3 (wildcard in_scope beats wildcard out_of_scope); also fixes `*uat.marriott.com`. Verified: both now IN-SCOPE. |

**auth-apc.marriott.com /login (M020) analysis:**
- All paths except `/login` timeout (000) — only `/login` exposed externally
- 137KB = full SSO application (login form, CSS, JS — not a redirect page)
- Pattern matches PingFederate, ForgeRock Access Manager, or custom SAML/OAuth IDP
- `apc` = Asia Pacific & Caribbean cluster; `auth-apc` is the APC cluster's authentication entry point
- **Potential findings: SAML RelayState open redirect, OAuth redirect_uri bypass, username enumeration, weak crypto in SAML assertions**
- Session 17 priority: download + fingerprint + test auth bypass vectors

**scope-check.sh critical fix:**
- `*gateway-apc.marriott.com` and `*uat.marriott.com` (no-dot wildcards) were incorrectly blocked by `*.marriott.com` catch-all
- New 4-pass algorithm: (1) exact in_scope > any, (2) exact out_of_scope > wildcard in_scope, (3) wildcard in_scope > wildcard out_of_scope, (4) wildcard out_of_scope as catch-all
- All existing tests pass; Google VRP unaffected

**Next session:** auth-apc.marriott.com `/login` deep analysis (M020) + efast body read + CT enum retry.

---

### Session 17 — COMPLETE (2026-06-22)

**Goal:** auth-apc.marriott.com deep fingerprint + efast body read (login form / SAML form) + graphql-chunk JS mining start.
**Runbook:** `runbooks/PI-RUNBOOK-session17-auth-apc-efast.sh`
**Status:** COMPLETE. auth-apc identified as Marriott Bonvoy Next.js + PingFederate SSO portal. efast confirmed as SAML SP routing to `extranetcloud.marriott.com` (OUT-OF-SCOPE IdP). graphql-chunk downloaded but not yet mined.

**Session 17 Results:**

| Phase | Finding | Conclusion |
|-------|---------|-----------|
| A — auth-apc fingerprint | `X-Powered-By: Next.js`, build version `mi-account-renderer/web-rel-26.6.1-5d80cc6-11089`, 27 JS chunks in `_next/static/chunks/`. `PR_INFORMATION: PR_EXECUTED:;PR_EXECUTED_RULE:` response header = PingFederate identity broker confirmed. Dynatrace OneAgent: `X-OneAgent-JS-Injection: true` + `X-ruxit-JS-Agent: true`. | **auth-apc is Marriott Bonvoy APC cluster login portal: Next.js SPA frontend → PingFederate IdP backend** |
| B — JS bundle inventory | 27 chunks total; 5 downloaded this session. `graphql-chunk-793e1a2cf24c51e7.js` (chunk #14, high priority) not yet mined. `nodeForgeVendor-4e937f79b0795bc3.js` present (client-side RSA/crypto — suggests client-side key operations, possibly PKCE or JWT signing). | **graphql-chunk mining deferred to Session 18** |
| C — Python URL regex error | A3 URL extraction phase: `re.PatternError: unterminated character set at position 39` — backslash before `]` inside character class in URL regex pattern. URL extraction failed; other phases unaffected. | **Fix regex in Session 18 runbook** |
| D — crt.sh | Still returning 502 Bad Gateway for all wildcard queries. CT enum (M013) still blocked. | **Need alternative CT source (Certspotter / wayback CDX API)** |
| E — efast body read | `/tmp/s17/efast-body.html` saved. efast auto-submits SAML2 AuthnRequest (HTTP POST binding) to `extranetcloud.marriott.com/marrsso/idp/startSSO.ping?PartnerSpId=clr-saml2-efast.marriott.com`. SAMLRequest base64 captured (truncated in Pi output): `PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOkF1dGhuUmVxd...` | **efast SP entity ID = `clr-saml2-efast.marriott.com`. ACS URL unknown — decode SAMLRequest to find it.** |
| F — Scope check | `extranetcloud.marriott.com` → **OUT-OF-SCOPE** (`*.marriott.com` catch-all applies; not in explicit in_scope list). OWA `/tmp/s17/owa-autodiscover.txt` not created (all paths timeout — confirmed internal-only). | **Cannot probe PingFederate IdP at extranetcloud. Focus: efast SP surface + auth-apc OIDC endpoints** |

**Key technical discoveries:**
- **auth-apc SAML/PingFederate**: `PR_INFORMATION` header = PingFederate Policy Runtime executed; `PR_EXECUTED_RULE:` (empty rule name = no rule fired = pre-auth). This is the standard PingFederate reverse proxy header injected into responses. Testing target: auth-apc login form parameters (redirect_uri, RelayState, error handling).
- **efast SAML SP**: efast is a ClearTrust/RSA Access Manager → migrated to PingFederate integration. SP entity ID `clr-saml2-efast.marriott.com` prefix `clr-` = ClearTrust (legacy RSA product). ACS URL embedded in SAMLRequest XML at `AssertionConsumerServiceURL` attribute. Once decoded, can probe whether ACS accepts unauthenticated POST.
- **node-forge**: Client-side crypto library in auth-apc. May implement PKCE code_verifier locally, or encrypt credentials client-side before sending. Mine for key material, hardcoded secrets, or crypto misuse.

**Lead M021 — efast SAML Surface:**
- efast.marriott.com = SAML SP with visible SAMLRequest (base64, non-signed request per POST binding)
- ACS URL unknown pending SAMLRequest decode
- Potential: ACS accepts unsigned SAML response (broken SP validation) → auth bypass
- Potential: RelayState open redirect (OOS per Marriott policy unless chains to auth bypass)
- Test priority: decode → find ACS URL → probe ACS for unsigned POST acceptance

### Session 18 — PARTIAL (2026-06-22)

**Goal:** SAMLRequest decode + graphql-chunk mining + auth-apc OIDC probe + CT retry + CVE probe.
**Runbook:** `runbooks/PI-RUNBOOK-session18-saml-graphql.sh`
**Status:** PARTIAL — Phase A complete (ACS URL found). Phases B partially complete (bundles downloaded). B3 script crashed (backtick-in-heredoc bash bug). Phases C, D, E, G did NOT run.

**Session 18 Results:**

| Phase | Finding | Conclusion |
|-------|---------|-----------|
| **A — SAMLRequest decode** | **ACS URL = `https://efast.marriott.com/home`** (IN-SCOPE). ProtocolBinding = HTTP-Artifact. SP signs its requests (RSA-SHA1, SHA1 digest — deprecated). Issuer = `clr-saml2-efast.marriott.com`. X509 cert: CN=`Claresco.eFASTTProd.SSO.marriott.com`, issued by MarriottSubCA2 (Entrust), valid 2024-11-21 → 2026-11-20. | **ACS is on efast.marriott.com (in-scope) — probe for unsigned POST acceptance in Session 19** |
| A — Cert SAN | Three employee emails in SAN: `sally.chaupiz@marriott.com`, `preston.anderson@marriott.com`, `amy.klein@marriott.com`, `ops@claresco.com` | Informational only — not submittable standalone |
| A — RelayState | `https://efast.marriott.com/` (RelayState sent to IdP) | Normal SP behavior |
| B1/B2 — Bundle download | `graphql-chunk-793e1a2cf24c51e7.js` = 330KB; `nodeForgeVendor-4e937f79b0795bc3.js` = 281KB. Both downloaded to Pi `/tmp/s18/apc-chunks/`. | **Bundles ready — mine in Session 19** |
| B3 — Mining CRASHED | Bash error: backtick character in Python regex inside unquoted heredoc interpreted as command substitution. `re.findall(r'gql\`...\`', ...)` caused `unexpected end of file`. Script exited at B3. | **Fix: use `\x60` hex escape for backtick. Session 19 restarts from B3.** |
| C, D, E, G | DID NOT RUN — script exited at B3 | All four phases queued for Session 19 |

### Session 19 — COMPLETE (2026-06-22)

**Goal:** Fixed JS mining + efast ACS probe + auth-apc CVE + CT enum.
**Runbook:** `runbooks/PI-RUNBOOK-session19-mining-acs-cve.sh`
**Status:** COMPLETE. All phases run. ACS probe closed M021. CT enum yielded UAT hosts (M023). CVE-2025-29927 confirmed not externally reachable.

**Session 19 Results:**

| Phase | Finding | Conclusion |
|-------|---------|-----------|
| **B3 — graphql-chunk** | **67 `phoenixAccount*` GraphQL operations** including: GetPersonalInformation, GetProfileDetails, GetWalletPaymentInfo, GetOrderDetailsByOrderId, GetOrdersByCustomerId, **LookupCustomerProfiles**, GetUpcomingTripsBasicInfo, GetMemberStatusDetails, GetAirlineTransactionDetail + mutations: UpdateCustomerPaymentMethod, AddGiftCard, ManageGiftCard, RegisterPromotion, UpdateCustomerConsents. `revisionToken` used for write operations. | **Phoenix GraphQL API operations confirmed. No endpoint URL in this chunk — it's in a different bundle. `*gateway-apc.marriott.com` is the likely backend.** |
| B4 — nodeForge | Pure crypto library. `forge.pki.rsa.publicKeyValidator` + `forge.prng` present. No embedded keys, no PEM blocks. | auth-apc likely encrypts credentials client-side with RSA via node-forge before submit. Server public key must be in another chunk. |
| C1 — login page | 131KB page. AEM + Next.js hybrid confirmed. Build ID NOT found via regex (custom basePath blocks standard extraction). | Build ID in script src tags, not __NEXT_DATA__. Need to grep script src attributes (fixed in Session 20 runbook). |
| C2/C3 — manifests | SKIPPED (Build ID empty) | Session 20 fixes extraction — grep `_buildManifest.js` from script src attributes. |
| C4–C6 — OIDC/PF/API | ALL 000 (timeout) — auth-apc only exposes `/login` externally. ALL other paths firewalled. | CVE-2025-29927 not exploitable externally (confirmed in Phase G). |
| **C7 — __NEXT_DATA__** | AEM path: `/content/mi-account/na/en-us/eaa/login/jcr:content`. Component: `mi-aem-account/components/content/signin`. `forgotPwrdCtaPath: /forgotPassword`, `activateOnlineAccountCtaPath: /activate`. `lastModifiedDate: 1760628112496` (≈Nov 2025). hreflang links → `www.marriott.com/{locale}/eaa/login.mi` = APC cluster member login. | auth-apc.marriott.com = Marriott Bonvoy member login portal for Asia-Pacific & Caribbean cluster. Post-login GraphQL API calls hit a different host. |
| **D1 — GET /home** | HTTP 401, 6838B. `SessionIDCookie` set. `Location: /home` (redirect to SAML form auto-submit). | Normal SP behavior: unauthenticated GET triggers SAML redirect. |
| **D2 — POST /home (empty)** | HTTP 401, 6838B — identical to D1 baseline. | Empty POST treated same as GET: no SAMLResponse → SAML redirect again. |
| **D3 — POST /home (unsigned SAMLResponse, correct Issuer)** | **HTTP 400, 27829B** — `<!--Begin: /usr/local/webapps/efast/java/templates/Claresco/GenericError.ctp-->` — ClearTrust/Claresco SP error page. | **SP rejects unsigned SAMLResponse. Validation is enforced.** |
| **D4 — POST /home (malformed SAMLResponse, wrong Issuer)** | **HTTP 400, 27821B** — same Claresco GenericError.ctp error page (8B smaller = shorter issuer string in error). | **SP correctly validates issuer + signature. M021 = NO AUTH BYPASS.** |
| D — Path disclosure | `/usr/local/webapps/efast/java/templates/Claresco/GenericError.ctp` exposed in HTTP 400 response body. | Informational — absolute server path. Not submittable standalone per Hard Rejection List §3. |
| **E — CT enum (%.uat.marriott.com)** | wayback CDX returned HTTP 200 with **6 hosts**: `micmt.uat.marriott.com`, `micommissionmanagementtool.uat.marriott.com`, `uat.marriott.com`, `www.micmt.uat.marriott.com`, `www.micommissionmanagementtool.uat.marriott.com`, `www.uat.marriott.com`. crt.sh still 502 for apigwc/apigatewayc/artifactory. | **M023 NEW — MI Commission Management Tool UAT environment. Both primary and www-prefixed hosts confirmed. In-scope via `*uat.marriott.com` wildcard.** |
| **G — CVE-2025-29927** | ALL auth-apc paths return 000/0B with baseline headers AND with `x-middleware-subrequest: middleware` bypass header. `/dashboard`, `/profile`, `/wallet`, `/account`, `/settings`, `/admin` — all 000. | **NOT EXPLOITABLE EXTERNALLY — auth-apc firewall blocks all non-`/login` paths. CVE cannot reach protected routes from outside.** |
| F — Decision gate | M021 CLOSED. M022 active (GraphQL endpoint unknown). M023 new (UAT hosts). CVE-2025-29927 irrelevant. | Session 20: gateway-apc.marriott.com GraphQL probe + UAT host fingerprint. |

**M021 — CLOSED (no auth bypass)**
- SP correctly validates SAMLResponse signature: unsigned POST → HTTP 400 + ClearTrust GenericError.ctp
- Wrong-issuer POST → same 400 (issuer validation also enforced)
- HTTP-Artifact binding means SP expects artifact token from IdP, not POST binding — additional enforcement layer
- Path disclosure (`/usr/local/webapps/efast/java/templates/Claresco/GenericError.ctp`) is informational only
- **Status: CLOSED — not reportable**

**M022 — ACTIVE (Phoenix GraphQL IDOR)**
- 67 named operations confirmed. Endpoint URL not yet found (not in graphql-chunk).
- Primary hypothesis: `gateway-apc.marriott.com/graphql` (in-scope via `*gateway-apc.marriott.com`)
- Session 20 mines remaining auth-apc chunks (app, main, webpack) + probes gateway-apc directly.

**M023 — NEW (UAT Commission Management Tool)**
- `micmt.uat.marriott.com` = "MI Commission Management Tool" UAT environment
- `micommissionmanagementtool.uat.marriott.com` = same app, verbose hostname
- Both in-scope via `*uat.marriott.com` wildcard
- UAT environments: typically weaker auth, debug endpoints active, test data, Spring Boot actuators exposed
- Session 20 adds Phase H to fingerprint these hosts.

**B3 backtick fix (for future reference):**
```
# BROKEN (bash expands backticks in unquoted heredoc):
gql_docs = re.findall(r'gql`([^`]{20,500})`', js, re.DOTALL)
# FIXED (chr() generates backtick at runtime):
BT = chr(0x60); gql_docs = re.findall(r'gql' + BT + r'([^' + BT + r']{20,500})' + BT, js, re.DOTALL)
```

---

## Lead Status

| ID | Class | Surface | HTTP Result | Status | Priority |
|----|-------|---------|------------|--------|----------|
| ~~M001~~ | ~~esupplier — static Word docs only~~ | `esupplier.marriott.com` | Root + all sub-paths = Microsoft Word 14 HTML documents (2014). filelist.xml = Office manifest. Real app at `extranet.marriott.com/psfin` OUT-OF-SCOPE. Email: `mercuryworkflowadministrator@marriott.com` (informational). No API, no live code. | **CLOSED — static Word docs, no attack surface** | — |
| M002 | **Salesforce Aura Guest User API Exposure — 7 sObject schemas, 873 fields confirmed** | `cpp.marriott.com/s/sfsites/aura` | getObjectInfo(User) 203F + getObjectInfos(Profile 517F, Org 41F, Network 10F, ContentDocument 27F, ContentVersion 47F, FeedItem 28F) + getPicklistValues SUCCESS + getConfigData 187-object inventory | **SUBMITTED — HackerOne #3817499. Medium (5.3). 2026-06-22.** | **MEDIUM** |
| M003 | Payment endpoint IDOR / logic bypass | `psp.marriott.com` | Meta-refresh → PingFederate SAML2 (`extranet.marriott.com/2FAmarrsso`); PartnerSpId=Marriott-SAML2-SP-EverestRCD-PROD | **BLOCKED — requires Marriott employee SAML2 auth. Inaccessible externally.** | — |
| M004 | Financial portal IDOR | `marriottfranchisetransactions.marriott.com` | **200 / 12595B**, raw EC2 | ACTIVE — session 2 probe | CRITICAL |
| ~~M005~~ | ~~SAP DEV gateway — actuator/swagger/debug~~ | `gatewaydsapdev2.marriott.com` | Akamai WAF uniform 404/261B on all paths (root, actuator, swagger-ui, SAP OData, Spring Boot, backup files). No path visibility. | **CLOSED — WAF-locked, no path accessible** | — |
| M006 | CVE-2022-23855 ambiguous (500 not 200) | `ssm-marriottms.saviyntcloud.com` | `forgotpasswordstep1` → HTTP 500 | ACTIVE — try GET+query, form-encoded POST | HIGH |
| ~~M007~~ | ~~mgs.marriott.com — employee intranet~~ | `mgs.marriott.com` | CrafterCMS, all 78 paths 404/387B. Title: "Marriott Global Source — Intranet and eTool Gateway." AWSALB = ALB not raw EC2. Requires employee creds. | **PARKED — employee intranet, no external surface** | — |
| M008 | Host-header routing attack | APC cluster: auth-apc + apcgateway + gateway-apc | 000 / 503 | PENDING — probe with explicit paths | HIGH |
| ~~M009~~ | ~~OWA NTLM — internal-facing~~ | `owa.marriott.com` | 302→/owa/ (Server: BigIP F5). Autodiscover/EWS all timeout 000. Internal-facing behind corporate network, unreachable externally. | **PARKED — inaccessible externally** | — |
| ~~M010~~ | ~~Employee identity app IDOR~~ | `eidhelp.marriott.com` | Static S3+CloudFront. All dropdowns → same `/help/index.html`. No API. Headers leak `x-amz-meta-user-agent-id: jblaney@...` (informational). | **CLOSED — static site, zero API surface** | — |
| ~~M011~~ | ~~ci-propertyconversionportal — Akamai-locked SPA~~ | `ci-propertyconversionportal.marriott.com` | Akamai WAF fully blocks all `/api/**`, `/actuator/**`, `/openapi.json`, etc. (cdn-cache: HIT 403). Session 14 "1280B differentials" were empty origin responses padded with 1280B Akamai mRUM script (cache MISS → MISS carries RUM; now HIT blocks). No origin IP accessible. | **CLOSED — Akamai WAF fully blocks all API surface** | — |
| M012 | BPA2 portal auth bypass / IDOR | `bpa2.marriott.com` | CPWS allowlist routing: only `/Login/Login.css` (7835B) accessible; all other paths → 403/5125B "not configured." Login SQLi test incomplete (cookie-check redirect loop blocked B3-B5). | **PARKED — CPWS locked, minimal accessible surface** | LOW |
| M013 | CT wildcard enum (apigwc, apigatewayc, uat) | `*.apigwc`, `*.apigatewayc`, `*uat.marriott.com` | crt.sh 502 in S16, DNS brute 0 results | ACTIVE — retry CT enum; expand prefix list | HIGH |
| **M020** | **SSO portal live — auth-apc.marriott.com /login** | `auth-apc.marriott.com` | **200/137KB** on `/login`; all other paths 000. Next.js + PingFederate confirmed (`PR_INFORMATION` header). 27 JS chunks; `graphql-chunk-793e1a2cf24c51e7.js` + `nodeForgeVendor` not yet mined. | **ACTIVE — graphql-chunk mining + OIDC probe + redirect_uri bypass** | **HIGH** |
| **M022** | **Phoenix GraphQL API IDOR — 67 operations, endpoint unknown** | `*gateway-apc.marriott.com` (likely) | 67 `phoenixAccount*` GraphQL operations mined from auth-apc graphql-chunk (330KB). LookupCustomerProfiles, GetPersonalInformation, GetWalletPaymentInfo, GetOrderDetailsByOrderId. No endpoint URL in chunk. Mutations require `revisionToken`. | **ACTIVE — find GraphQL endpoint (mine remaining chunks + probe gateway-apc) → test unauthenticated access + customerId IDOR** | **CRITICAL** |
| ~~M021~~ | ~~efast SAML ACS probe — SP validates correctly~~ | `efast.marriott.com` | D3: POST unsigned SAMLResponse → HTTP 400 + Claresco GenericError.ctp. D4: Wrong-issuer POST → HTTP 400. Path disclosure: `/usr/local/webapps/efast/java/templates/Claresco/GenericError.ctp` (informational). | **CLOSED — SP correctly validates signature + issuer. No auth bypass. Path disclosure informational only.** | — |
| **M023** | **UAT hosts — MI Commission Management Tool** | `micmt.uat.marriott.com`, `micommissionmanagementtool.uat.marriott.com` | wayback CDX confirmed both hosts + www-prefixed variants. In-scope via `*uat.marriott.com`. Not yet probed. | **ACTIVE — fingerprint UAT env, probe for actuator/swagger/debug endpoints (Session 20 Phase H)** | **HIGH** |
| M014 | AirWatch MDM console | `mdmconsole.marriott.com` (via device.marriott.com redirect) | **SCOPE GAP** | BLOCKED — need scope confirmation | — |
| **M018** | **Auth Bypass + Path Disclosure on /ajax.php (Franchise Portal)** | `marriottfranchisetransactions.marriott.com/ajax.php` | `module=user&function=list` → 431B PHP Fatal Error w/ MysqliDb stack trace | **SUBMITTED — HackerOne #3816825. Medium (6.1). 2026-06-22.** | **MEDIUM** |
| M015 | Partner privileges IDOR | `mipartnerprivileges.marriott.com` | 403 | PENDING — try with auth | MEDIUM |
| M016 | SSO endpoint discovery | `sso.marriott.com` NXDOMAIN — auth moved | 000 | PENDING — find new auth hostname | HIGH |
| ~~M017~~ | ~~lawmanager internal~~ | 000 timeout | Zscaler internal, inaccessible externally | PARKED | — |
| ~~M019~~ | ~~Salesforce LWC wire endpoints~~ | `/s/sfsites/lwr/*` | 200 + JS login redirect to `/s/login?ec=302` — properly auth-gated | **CLOSED — requires authentication** | — |
