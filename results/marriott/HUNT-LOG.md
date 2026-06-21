# Hunt Log — Marriott Bug Bounty Program

**Program:** Marriott Bug Bounty (HackerOne — hackerone.com/marriott)
**Platform:** HackerOne
**Started:** 2026-06-21
**Status:** SESSION 1 — Recon + Initial Probe
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

## Lead Status

| ID | Class | Surface | HTTP Result | Status | Priority |
|----|-------|---------|------------|--------|----------|
| M001 | IDOR / missing auth on supplier portal | `esupplier.marriott.com` | **200 / 54985B**, raw EC2 no WAF | ACTIVE — session 2 probe | **CRITICAL** |
| M002 | **Salesforce Aura Guest User API Exposure — 203 fields confirmed** | `cpp.marriott.com/s/sfsites/aura` | POST→`"state":"SUCCESS"` + 203-field User schema | **REPORT-READY — Medium (5.3). Session 6 confirmed.** | **MEDIUM** |
| M003 | Payment endpoint IDOR / logic bypass | `psp.marriott.com` | **200 / 4853B** | ACTIVE — endpoint enum | CRITICAL |
| M004 | Financial portal IDOR | `marriottfranchisetransactions.marriott.com` | **200 / 12595B**, raw EC2 | ACTIVE — session 2 probe | CRITICAL |
| M005 | SAP DEV gateway — actuator/swagger/debug | `gatewaydsapdev2.marriott.com` | 404 on `/` — probe sub-paths | ACTIVE — specific path probe | CRITICAL |
| M006 | CVE-2022-23855 ambiguous (500 not 200) | `ssm-marriottms.saviyntcloud.com` | `forgotpasswordstep1` → HTTP 500 | ACTIVE — try GET+query, form-encoded POST | HIGH |
| M007 | Messaging portal auth bypass / IDOR | `mgs.marriott.com` | **200 / 19501B**, raw EC2 | ACTIVE — endpoint enum | HIGH |
| M008 | Host-header routing attack | APC cluster: auth-apc + apcgateway + gateway-apc | 000 / 503 | PENDING — probe with explicit paths | HIGH |
| M009 | OWA NTLM hash disclosure | `owa.marriott.com` | **302→/owa/** confirmed | ACTIVE — autodiscover probe | MEDIUM |
| M010 | Employee identity app IDOR | `eidhelp.marriott.com` | **200 / 7767B** small app | ACTIVE — endpoint enum | HIGH |
| M011 | Property conversion portal bugs | `ci-propertyconversionportal.marriott.com` | **200 / 5939B** | ACTIVE — 1 prior report | HIGH |
| M012 | BPA2 portal auth bypass / IDOR | `bpa2.marriott.com` | **302→/Login/Login** | ACTIVE — test auth paths | HIGH |
| M013 | CT wildcard enum (apigwc, apigatewayc, uat) | `*.apigwc`, `*.apigatewayc`, `*uat.marriott.com` | — | ACTIVE — Session 2 Phase 1 | HIGH |
| M014 | AirWatch MDM console | `mdmconsole.marriott.com` (via device.marriott.com redirect) | **SCOPE GAP** | BLOCKED — need scope confirmation | — |
| **M018** | **Auth Bypass + Path Disclosure on /ajax.php (Franchise Portal)** | `marriottfranchisetransactions.marriott.com/ajax.php` | `module=user&function=list` → 430B PHP Fatal Error w/ MysqliDb stack trace | **REPORT-READY — Medium (5.3). Session 6 confirmed.** | **MEDIUM** |
| M015 | Partner privileges IDOR | `mipartnerprivileges.marriott.com` | 403 | PENDING — try with auth | MEDIUM |
| M016 | SSO endpoint discovery | `sso.marriott.com` NXDOMAIN — auth moved | 000 | PENDING — find new auth hostname | HIGH |
| ~~M017~~ | ~~lawmanager internal~~ | 000 timeout | Zscaler internal, inaccessible externally | PARKED | — |
