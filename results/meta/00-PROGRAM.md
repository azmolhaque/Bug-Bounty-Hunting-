# Meta Bug Bounty — program card

Source: operator-supplied overview, scope, payout guidelines and education centre pages
(saved 2026-09-25). Submission is via the official "Report a Security Vulnerability" form
only — one issue per report, no contacting staff through other channels.

## Rules of engagement (hard)

- **Test accounts only.** The program ships a Test Accounts tool. A real account may be
  used only if the issue cannot be reproduced on a test account, and **never** for
  automated testing. Never touch an account belonging to anyone else.
- No DoS. No spam or social engineering. No content injection (out of scope unless
  significant risk is clearly demonstrated).
- Sandboxed domains are out of scope — `fbsbx.com`, `fbrell.com`. Use
  `alert(document.domain)` to confirm the real origin before reporting anything script-related.
- Third-party apps integrating with Meta are out of scope except under passive observation.
  **Do not manipulate requests to them.** SQLi/XSS/open redirect/IDOR against third parties
  is explicitly excluded.
- Out of scope surfaces named: `investor.fb.com`, `accountkit.com`, `alpha.whatsapp.com`,
  `media.whatsapp.com`, `communityforums.atmeta.com`, `github.com/facebookarchive/`.
- Minimum bounty $500. Duplicates go to first reporter, decided at Meta's sole discretion
  with no obligation to show prior reports.
- Payouts expire 6 months after the award message. Claim promptly.

## Published payout table — the categories that matter to us

Ranked by fit with a terminal-based API authorization tester, not by headline number.

| Category | Sub-tier | Max |
|---|---|---|
| **Ads Audience** | **use audiences outside of shared relationships between businesses** | **$7.5k** |
| Ads Audience | identifying audience composition across businesses | $5k |
| Ads Audience | leak multiple PII on behalf of any user via Ads Audience | $30k |
| **Developer platform privacy assertions** | **read or modify more information than granted through app permissions** | **$25k** |
| Developer platform privacy assertions | infer which apps a user has logged into with Facebook | $5k |
| Developer platform privacy assertions | find the global Facebook ID for a user logging into your app | $1k |
| Account take-over | **business & page take-overs** | $50k |
| Contact point deanonymization | identify a contact matching a known user ID | $10k |
| Contact point deanonymization | identify a user ID matching a known contact point | $7.5k |
| Contact point deanonymization | point query confirming user A has contact point X | $5k |
| Contact point deanonymization | contact point matching a known first + last name | $3k |
| Meta Coupons | unrestricted creation/usage of promo codes | $20k |
| Meta Coupons | bypass Meta Ad credits restrictions | $10k |
| **Page admin disclosure** | — | **$5k** |
| Cross-site leaks | search bar / identification / page role | $5k / $3k / $1.25k |
| SSRF | production, reading the response | $40k |
| 2FA bypass | — | $20k |
| Impersonation | comment as another user | $10k |

Out of our reach, recorded so we stop being tempted: Muse ($300k), WhatsApp Private
Processing ($300k, **invitation only**), mobile RCE ($300k), Meta hardware ($45k),
mobile deep link / intent redirection ($130k).

Meta AI tops out at $130k but the accessible half is excluded: **prompt smuggling is
capped at $5k**, and jailbreaks / risky output route to a *non-bounty* feedback form. The
paying tiers require accessing private user content or internal Meta data.

## Why the axis is Business-to-Business authorization

Two separate published categories pay specifically for crossing a business boundary:

- Ads Audience — *"being able to use audiences outside of shared relationships between
  businesses"*, $7.5k, and *"identifying audience composition across businesses"*, $5k.
- Account take-over — *"business & page take-overs"*, $50k.

"Shared relationships between businesses" is Business Manager **partner sharing**: business
A grants business B per-asset, per-permission access to its Pages, ad accounts, catalogs,
pixels and audiences. That is a fine-grained cross-tenant grant layered over a Graph API
that predates it — the same construct shape as the Exoscale `parameters.bucket` CEL binding
work, but on a surface that is not a security vendor's own product, and with a published
price attached.

A published sub-tier means the class is **accepted, scored and paid**. No arguing about
whether it counts.

## Program tools (all terminal-friendly)

| Tool | Use |
|---|---|
| **Test accounts** | Provision the A and B identities. Gate 2 solved by the program itself |
| **FBDL** | Builds test environments programmatically. Has an **API and an open-source MCP server** per the education centre — this is how we build two businesses with a sharing relationship without clicking through a UI on a phone |
| **Graph API Explorer** | Mint and scope access tokens |
| **Access token debugger** | Verify exactly which scopes and which app a token carries — our positive control |
| **SSRF validator** | Meta-hosted callback target. Use this instead of our own OOB rig if SSRF ever comes up |

The Access Token Debugger matters more than it looks. Half of authorization testing is
proving *what the token actually was* when the request succeeded. It gives us that for free,
which is the control discipline the Exoscale runlog was built on.
