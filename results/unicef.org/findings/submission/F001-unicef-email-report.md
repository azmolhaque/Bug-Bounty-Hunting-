# F001 — Submission Email (ready to send)
# ─────────────────────────────────────────────────────────────
# To:      infosecurity@unicef.org
# Subject: Vulnerability Report: Unauthenticated Bulk Disclosure of 13,112
#          Staff Email Addresses via Drupal JSON:API on ram.unicef.org
# ─────────────────────────────────────────────────────────────
# Copy everything between the === lines into your email client.
# Attach: poc-F001-unicef-jsonapi-disclosure.py
# ─────────────────────────────────────────────────────────────

===========================================================================

Dear UNICEF Information Security Team,

I am writing to report a confirmed vulnerability discovered during authorized
security research on the UNICEF Responsible Vulnerability Disclosure scope
(*.unicef.org). This report is submitted in accordance with your disclosed
policy. I am reporting immediately upon confirmation.

  Researcher   : zahinshahriar3@gmail.com
  Discovery    : 2026-06-17
  Severity     : High — CVSS 3.1 Base Score 7.5
                 AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N
  CWE          : CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
  Attachment   : poc-F001-unicef-jsonapi-disclosure.py (standalone Python 3 PoC)


────────────────────────────────────────────────────────────────────────────
1. EXECUTIVE SUMMARY
────────────────────────────────────────────────────────────────────────────

The RAM 3.0 platform (ram.unicef.org) exposes the complete staff email directory
— 13,112 real @unicef.org addresses — to any unauthenticated internet visitor
via an unprotected Drupal JSON:API endpoint. No credentials, tokens, or special
tools are required. A single HTTP request returns 50 records; repeated pagination
returns them all.

This is not generic username enumeration (which Drupal treats as working-as-intended).
The distinguishing factor is that UNICEF configured usernames to equal email
addresses on this platform, so the `display_name` field — publicly readable by
Drupal's design — resolves to each staff member's actual inbox. Drupal's own
hardening documentation identifies this specific outcome as the risk to prevent.


────────────────────────────────────────────────────────────────────────────
2. ROOT CAUSE
────────────────────────────────────────────────────────────────────────────

Two independent misconfigurations combine to produce bulk PII disclosure:

  ISSUE 1 — Username equals email address
  ────────────────────────────────────────
  Drupal accounts on ram.unicef.org are provisioned with each user's @unicef.org
  email as the Drupal username. Consequently, `display_name` — which Drupal's
  security model permits returning to anonymous API consumers — resolves to a real
  staff email inbox rather than an opaque, non-PII handle.

  ISSUE 2 — JSON:API user collection accessible without authentication
  ────────────────────────────────────────────────────────────────────
  The /en/jsonapi/user/user endpoint accepts anonymous requests, returns paginated
  results with no credential requirement, and imposes no rate limiting. The entire
  user table is bulk-exportable in a single automated session of approximately
  4–5 minutes.

Neither issue in isolation produces this severity. Together they allow any
unauthenticated actor to download the complete staff email directory.

  Platform EOL note: The server stack is fully end-of-life and unpatched:
    • Drupal 8   — EOL November 2021
    • PHP 7.4.33 — EOL December 2022
    • Apache 2.4.54 — superseded


────────────────────────────────────────────────────────────────────────────
3. PROOF OF CONCEPT
────────────────────────────────────────────────────────────────────────────

A standalone Python 3 script (stdlib only, no pip installs) is attached as
poc-F001-unicef-jsonapi-disclosure.py. It can be reproduced manually with:

  Request:
  ─────────────────────────────────────────────────────────────
  GET /en/jsonapi/user/user?page%5Blimit%5D=50 HTTP/1.1
  Host: ram.unicef.org
  Accept: application/vnd.api+json
  ─────────────────────────────────────────────────────────────

  Response (HTTP 200 — excerpt, first 5 of 13,112 records):
  ─────────────────────────────────────────────────────────────
  {
    "data": [
      {
        "type": "user--user",
        "id":   "0007cc8e-fcdf-43d2-bb0b-a6f11328f129",
        "attributes": { "display_name": "fmelese@unicef.org" }
      },
      {
        "id": "000af50c-c2be-4d29-9c31-ab2a49a4e393",
        "attributes": { "display_name": "yara@unicef.org" }
      },
      {
        "id": "0019e329-3b78-4d72-a65e-2a63bdea455f",
        "attributes": { "display_name": "apopa@unicef.org" }
      },
      {
        "id": "0020ff55-a212-44ed-8b1b-6cfa014d19fd",
        "attributes": { "display_name": "fawde@unicef.org" }
      },
      {
        "id": "00219ee1-c585-4486-884d-c1b246ee3ca5",
        "attributes": { "display_name": "aosorio@unicef.org" }
      }
    ],
    "links": {
      "next": {
        "href": "http://ram.unicef.org/en/jsonapi/user/user?page%5Boffset%5D=50..."
      }
    }
  }
  ─────────────────────────────────────────────────────────────

  Scale confirmation:
  Pagination continues uninterrupted across 263 pages (50 records each; final
  page 12 records) yielding 13,112 accounts in total. No authentication challenge
  or rate limit was encountered at any point.

  Key evidence — display_name IS an email address:
  The `display_name` attribute contains @unicef.org email addresses, confirmed
  across all sampled records. This is the critical distinction from username
  exposure: the field that Drupal permits returning publicly happens to contain PII
  because UNICEF set username = email on this platform.

  Note on Drupal's standing policy:
  The Drupal security team has stated that username and UID disclosure via JSON:API
  is not considered a security vulnerability, because usernames are typically
  non-PII public handles. That policy does not apply here: the display_name on this
  platform is each staff member's @unicef.org inbox. Drupal's own security
  hardening documentation explicitly identifies this outcome — email addresses
  readable by anonymous users — as the risk to prevent:
  https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module/security-considerations


────────────────────────────────────────────────────────────────────────────
4. ADDITIONAL EXPOSURE SURFACE
────────────────────────────────────────────────────────────────────────────

The unauthenticated schema endpoint (/en/jsonapi) lists 60+ entity resource types,
including several that should not be accessible anonymously:

  /en/jsonapi/oauth2_server_client/oauth2_server_client
  /en/jsonapi/oauth2_server_token/oauth2_server_token
  /en/jsonapi/oauth2_server_scope/oauth2_server_scope
  /en/jsonapi/consumer/consumer
  /en/jsonapi/config_pages/api_config
  /en/jsonapi/config_pages/api_modules

OAuth2 client UUID disclosure (confirmed):

  When the oauth2_server_client endpoint is probed anonymously, the server returns
  HTTP 200 with an empty data array but leaks the internal UUID of each registered
  OAuth2 client in the meta.omitted section — a Drupal partial-result mechanism
  that discloses the existence and UUID of resources that cannot be read directly.

  Response excerpt:
  ─────────────────────────────────────────────────────────────
  HTTP/1.1 200 OK

  {
    "data": [],
    "meta": {
      "omitted": {
        "detail": "Some resources have been omitted because of insufficient authorization.",
        "links": {
          "item--5PGyAhH": {
            "href": "http://ram.unicef.org/en/jsonapi/oauth2_server_client/
                     oauth2_server_client/8cf614c1-7422-477b-952b-bcf1642439c5",
            "meta": {
              "detail": "The current user is not allowed to GET the selected resource.
                         The 'administer oauth2 server' permission is required."
            }
          }
        }
      }
    }
  }
  ─────────────────────────────────────────────────────────────

  Confirmed leaked OAuth2 client UUID: 8cf614c1-7422-477b-952b-bcf1642439c5

  The oauth2_server_token and config_pages endpoints were confirmed present in
  the schema. Their content was not probed beyond presence — the platform team
  should audit these as a priority given the OAuth2 client UUID disclosure above.


────────────────────────────────────────────────────────────────────────────
5. IMPACT
────────────────────────────────────────────────────────────────────────────

  A. Complete global staff directory (13,112 accounts)
     ────────────────────────────────────────────────
     The entire user database of the RAM 3.0 platform is readable by any
     unauthenticated actor in under 5 minutes with no tooling beyond curl.
     RAM 3.0 is UNICEF's Results Assessment Module — a global platform used by
     staff across all country offices and headquarters. The exposed accounts
     represent a near-complete enumeration of UNICEF's global operational staff.

  B. Targeted spear-phishing enablement
     ────────────────────────────────────
     13,112 validated @unicef.org email addresses sourced from an official UNICEF
     system provide an adversary — including nation-states targeting humanitarian
     operations — with a complete, verified contact list for personalized attacks
     against UNICEF personnel worldwide, including staff operating in conflict zones.
     Unlike scraped or guessed addresses, these are confirmed active accounts.

  C. Credential-stuffing attack surface
     ─────────────────────────────────────
     The validated email list, when combined with publicly available breach
     databases, can be used for large-scale credential stuffing against UNICEF's
     SSO portal, Outlook 365, VPN gateways, and any other service using unicef.org
     email as the account identifier. At 13,000+ accounts, statistical probability
     of at least one credential overlap with a prior breach is high.

  D. UUID-based follow-on enumeration
     ────────────────────────────────────
     Each account's stable Drupal UUID is returned alongside the email. These UUIDs
     enable targeted requests to other JSON:API endpoints for user-specific content
     and relationship traversal without authentication, and may expose documents,
     workspace memberships, or function assignments on the platform.


────────────────────────────────────────────────────────────────────────────
6. RECOMMENDED REMEDIATION
────────────────────────────────────────────────────────────────────────────

Two independent fixes are required. Applying only one leaves the other exposure
path intact.

  FIX 1 (Immediate) — Decouple username from email address
  ────────────────────────────────────────────────────────
  Implement hook_user_format_name_alter() to return a non-PII identifier
  (e.g., initials or an opaque token) to anonymous/unprivileged contexts,
  or enable the username_enumeration_prevention contributed module:
  https://www.drupal.org/project/username_enumeration_prevention

  This severs the display_name-to-email link for anonymous API consumers
  without changing how authenticated users identify one another.

  FIX 2 (Immediate) — Restrict /jsonapi/user/user to authenticated users
  ────────────────────────────────────────────────────────────────────────
  Option A — via jsonapi_extras (recommended):
    drush en jsonapi_extras -y
    drush cr
    # Navigate to /admin/config/services/jsonapi/extras
    # Disable or restrict the user--user resource type to authenticated roles only.

  Option B — via custom route access subscriber:
    Register a Symfony EventSubscriber on KernelEvents::REQUEST that returns
    AccessResult::forbidden() for anonymous requests matching /jsonapi/user/user.

  Additionally, restrict the oauth2_server_client, oauth2_server_token, and
  config_pages endpoints from anonymous schema listing.

  MEDIUM TERM — Platform upgrade
  ────────────────────────────────
    • Migrate from Drupal 8 (EOL Nov 2021) to Drupal 10 or 11
    • Upgrade PHP from 7.4.33 (EOL Dec 2022) to PHP 8.2+
    • Audit all 60+ JSON:API entity types for unintended anonymous access

  References:
    Drupal JSON:API security hardening:
      https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module/security-considerations
    Preventing Drupal enumeration attacks:
      https://www.hashbangcode.com/article/drupal-9-preventing-enumeration-attacks


────────────────────────────────────────────────────────────────────────────
7. RESPONSIBLE DISCLOSURE NOTES
────────────────────────────────────────────────────────────────────────────

  • I am not affiliated with any threat actor, competitor, or third party.
  • I retained only 10 email addresses as evidence. The total count (13,112)
    was obtained by iterating pagination counters only — no bulk data was
    stored, copied, or transmitted.
  • I did not authenticate to any UNICEF system, attempt login with any
    exposed address, or access any content requiring authentication.
  • I did not probe the oauth2_server_token or config_pages endpoints beyond
    confirming their presence in the schema.
  • This report is being submitted on the day of discovery.

I am happy to provide additional technical detail, assist with verification,
or answer questions. If UNICEF wishes to acknowledge this finding, a Hall of
Fame credit would be appreciated.

Sincerely,
zahinshahriar3@gmail.com

===========================================================================
