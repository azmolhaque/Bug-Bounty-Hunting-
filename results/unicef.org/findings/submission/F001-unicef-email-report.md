# F001 — Ready-to-Send Email Report
# Send to: infosecurity@unicef.org
# Subject: Vulnerability Report: Unauthenticated Bulk Disclosure of 13,112 Staff Email Addresses via Drupal JSON:API on ram.unicef.org
# -------------------------------------------------------------------------------

---

**To:** infosecurity@unicef.org  
**Subject:** Vulnerability Report: Unauthenticated Bulk Disclosure of 13,112 Staff Email Addresses via Drupal JSON:API on ram.unicef.org

---

Dear UNICEF Information Security Team,

I am writing to report a vulnerability discovered during authorized security research on
the UNICEF responsible vulnerability disclosure scope (`*.unicef.org`). This report is
submitted in accordance with UNICEF's responsible disclosure policy.

**Researcher:** zahinshahriar3@gmail.com  
**Discovery Date:** 2026-06-17  
**Severity:** High (CVSS 3.1 Base Score: 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

---

## 1. Vulnerability Summary

The `ram.unicef.org` Drupal 8 platform exposes **13,112 real `@unicef.org` staff email
addresses** to any unauthenticated internet visitor. This is not generic username
enumeration — it is bulk disclosure of email addresses caused by two compounding
misconfigurations.

**Root cause (two independent issues):**

1. **Usernames set to email addresses.** UNICEF configured accounts on this platform
   so that each user's Drupal username equals their `@unicef.org` email address.
   Drupal's `display_name` field — which the JSON:API returns publicly by design —
   therefore resolves to a real staff email inbox, not a non-PII handle.

2. **JSON:API `/user/user` collection unauthenticated and unrate-limited.** The user
   collection endpoint requires no credentials and imposes no rate limiting, making
   the full 13,112-account directory downloadable in a single scripted session.

Neither issue alone would reach this severity. Together they produce unauthenticated
bulk export of the platform's entire staff email directory.

**Endpoint:** `https://ram.unicef.org/en/jsonapi/user/user`  
**Authentication required:** None  
**Rate limiting:** None  
**Total accounts confirmed:** 13,112 (across 263 paginated pages)  
**Field exposed:** `display_name` = `@unicef.org` email address

---

## 2. Proof of Concept

No special tools or accounts are required. The following single HTTP request reproduces
the issue:

```
GET /en/jsonapi/user/user HTTP/1.1
Host: ram.unicef.org
Accept: application/vnd.api+json
```

**Response (HTTP 200, excerpt — first 5 of 13,112 records):**
```json
{
  "data": [
    { "id": "0007cc8e-fcdf-43d2-bb0b-a6f11328f129", "attributes": { "display_name": "fmelese@unicef.org" } },
    { "id": "000af50c-c2be-4d29-9c31-ab2a49a4e393", "attributes": { "display_name": "yara@unicef.org" } },
    { "id": "0019e329-3b78-4d72-a65e-2a63bdea455f", "attributes": { "display_name": "apopa@unicef.org" } },
    { "id": "0020ff55-a212-44ed-8b1b-6cfa014d19fd", "attributes": { "display_name": "fawde@unicef.org" } },
    { "id": "00219ee1-c585-4486-884d-c1b246ee3ca5", "attributes": { "display_name": "aosorio@unicef.org" } }
  ],
  "links": { "next": { "href": "http://ram.unicef.org/en/jsonapi/user/user?page%5Boffset%5D=50&page%5Blimit%5D=50" } }
}
```

Pagination was confirmed through all 263 pages (50 records each, final page 12 records)
yielding **13,112 total accounts**. I stopped at the count and did not retain the full
dataset beyond the first-page sample above.

**Note on Drupal's standing policy re: username exposure:** The Drupal security team has
previously stated that usernames and user IDs returned via JSON:API are not considered a
vulnerability, because usernames are typically non-sensitive public handles. That policy
does not apply here: the `display_name` field on this platform resolves to each user's
`@unicef.org` email address — not a public handle. The disclosure of 13,112 staff email
addresses is the outcome Drupal's own hardening guidance explicitly identifies as the
risk to prevent (see: https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module/security-considerations).

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

1. **Complete global staff directory exposed (13,112 accounts):** The entire user
   database of the RAM 3.0 platform is readable by any unauthenticated attacker in
   under 5 minutes with no rate limiting. This represents UNICEF's global operational
   staff across all country offices and headquarters.

2. **Spear-phishing at scale:** 13,112 validated `@unicef.org` email addresses sourced
   directly from an official UNICEF system. An adversary (including nation-states
   targeting humanitarian operations) can build a complete contact list for highly
   personalized attacks against UNICEF personnel worldwide, including those operating
   in conflict zones.

3. **Credential stuffing enablement:** This email list can be paired with breached
   credential databases and tested against UNICEF's SSO portal, Outlook 365, VPN
   gateways, or any service using unicef.org email as an identity. With 13K+ accounts
   the statistical likelihood of finding at least one reused/breached password is high.

4. **UUID-based follow-on enumeration:** Each user's stable Drupal UUID is returned,
   enabling targeted requests to other JSON:API endpoints for user-specific data
   relationships without authentication.

---

## 6. CVSS 3.1

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
Base Score: 7.5 (High)
```

C:H is assigned because the entire user table (13,112 records) is exposed without
restriction — all records in the impacted component are readable by any unauthenticated actor.

---

## 7. Recommended Remediation

Two independent fixes are needed — patching only one leaves the other exposure path open:

**Fix 1 — Stop resolving display_name to email for anonymous users.**  
Implement `hook_user_format_name_alter` to return a non-PII identifier (e.g., initials or
opaque handle) for anonymous/unprivileged requests, or enable the
`username_enumeration_prevention` module. This ensures even if JSON:API remains accessible,
it cannot be used to harvest email addresses.

**Fix 2 — Restrict the JSON:API user collection endpoint to authenticated users.**  
The fastest approach via contributed module:
```bash
drush en jsonapi_extras -y
drush cr
# Then configure /admin/config/services/jsonapi/extras:
# Disable the user--user resource type, or restrict it to authenticated roles only.
```
Alternatively, restrict via Drupal's routing access check or a custom
`EventSubscriber` that returns 403 for anonymous requests to `/jsonapi/user/user`.

**Short-term:**
- Migrate from Drupal 8 (EOL) to Drupal 10 or 11
- Upgrade PHP to 8.2+ (7.4 receives no security patches)
- Audit all 60+ JSON:API entity endpoints for unintended anonymous access
- Specifically review: `oauth2_server_client`, `oauth2_server_token`, `config_pages/api_config`

**References:**
- Drupal JSON:API security considerations: https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module/security-considerations
- Preventing enumeration attacks: https://www.hashbangcode.com/article/drupal-9-preventing-enumeration-attacks

---

## 8. Researcher Notes

- I am not affiliated with any threat actor or competing organization.
- I confirmed the total count (13,112) via pagination counting only. I retained only the
  first-page sample (10 addresses) as proof. The full list was not stored or transmitted.
- I did not attempt to authenticate to any UNICEF system using the exposed credentials.
- I did not test any OAuth2 or API endpoints beyond confirming their presence in the schema.
- Disclosure timeline: I am reporting immediately upon confirmation (same day).

I would be glad to provide any additional technical details or assist with verification.
If UNICEF wishes to acknowledge this finding, I'd appreciate credit in your Hall of Fame.

Best regards,  
zahinshahriar3@gmail.com
