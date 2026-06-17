# Hunt Plan — UNICEF (unicef.org)
# Program: UNICEF Responsible Vulnerability Disclosure
# Contact: infosecurity@unicef.org
# Researcher: zahinshahriar3@gmail.com
# Started: 2026-06-17

---

## Target Archetype

Wildcard large-surface (`*.unicef.org`) + Drupal CMS multi-site.  
→ Recon-heavy first. Asset sprawl is the lever. Forgotten country-office and campaign
  microsites, orphaned dev environments, and unprotected partner portals are the
  highest-probability paths to a confirmed finding.

---

## Hunt Thesis

**Primary hypothesis:** UNICEF runs hundreds of country-office subdomains across a
shared Drupal infrastructure. The central `www.unicef.org` is well-hardened, but
peripheral microsites (campaigns, country offices, partner portals, staging instances)
are operated by regional teams with less security oversight. The fastest path to a
valid finding is a combination of:

1. **Subdomain takeover** on an orphaned campaign microsite (Netlify/GitHub Pages/
   Azure/Heroku CNAME dangling).
2. **Drupal JSON:API unauthenticated data exposure** — Drupal 8+ enables JSON:API
   by default. An insufficiently locked-down instance may expose `/jsonapi/user/user`
   (leaking staff emails/UIDs), `/jsonapi/node/*` (draft content), or internal
   taxonomy/entity relationships.
3. **Partner/extranet portal authentication weakness** — supply.unicef.org,
   agora.unicef.org, partner portals, and emergency-response systems may have
   weaker auth than the main site.

---

## Attack Chain #1 (Highest Confidence)

```
Orphaned *.unicef.org subdomain
  → CNAME points to Netlify / GitHub Pages / Azure Static Sites / Heroku
  → CNAME target unclaimed
  → Claim the service, host attacker page
  → Subdomain shares cookies with *.unicef.org OR appears in UNICEF OAuth redirect list
  → Session theft / account takeover chain
```

Verdict gate: Confirm CNAME is claimable + cookie scope before writing report.

---

## Attack Chain #2 (Drupal JSON:API)

```
*.unicef.org Drupal instance
  → /jsonapi/user/user returns user list without auth (name, email, UID)
  → OR /jsonapi/node/article?filter[status]=0 returns draft/unpublished content
  → Information disclosure of staff PII or embargoed content
```

Verdict gate: Must return non-public data. Staff email directory alone may qualify
if combined with role disclosure (confirming internal users).

---

## Attack Chain #3 (Partner Portal Auth)

```
Extranet / partner portal (e.g., supply.unicef.org, agora.unicef.org)
  → Missing auth on API endpoint or admin route
  → IDOR on partner/beneficiary records
  → OR unauthenticated access to sensitive documents
```

---

## Priority Targets (Pre-recon Hypothesis)

| Host (guess) | Priority | Rationale |
|---|---|---|
| `supply.unicef.org` | P0 | Supply chain portal — procurement data |
| `agora.unicef.org` | P0 | Learning platform — user accounts |
| `partner.unicef.org` | P0 | Partner portal — auth target |
| `extranet.unicef.org` | P0 | Internal/partner access |
| `data.unicef.org` | P1 | Open data portal — API auth |
| `jobs.unicef.org` | P1 | Recruitment — PII exposure |
| `api.unicef.org` | P1 | API surface |
| `dev-*.unicef.org` | P0 | Any dev/staging = relaxed auth |
| `staging-*.unicef.org` | P0 | Staging instances |
| Country-office microsites | P1 | Orphaned = takeover candidates |

---

## Hard Constraints (CLAUDE.md binding)

- No DoS, no brute force, no social engineering
- No real user data exfiltration — prove impact with own test data
- Rate: ≤ 20 req/sec on active probing
- No third-party services (Salesforce, Zendesk, etc.)
- OOB interaction only for SSRF/injection proof

---

## Phase Checklist

- [ ] Phase 1: Subdomain enumeration complete (`01-assets/`)
- [ ] Phase 2: httpx live hosts probed, Drupal instances identified (`02-surface/`)
- [ ] Phase 3: Subdomain takeover check, JSON:API probe, admin discovery
- [ ] Phase 4: Verification + minimal PoC for any candidates
- [ ] Phase 5: Triage, dedup
- [ ] Phase 6: Report to infosecurity@unicef.org

---

## Phase Checklist (Updated)

- [x] Phase 1: Subdomain enumeration complete — 263 subdomains, 190+ live hosts
- [x] Phase 2: httpx live hosts probed; 11 Drupal instances identified; ram.unicef.org JSON:API = 200
- [x] Phase 3: JSON:API user enumeration confirmed — staff emails exposed; takeover scan = 0 hits
- [ ] Phase 4: Full PoC pending (OAuth2 probe + user count on Pi — see F001 Section 6)
- [x] Phase 5: Triage complete — F001 Medium/High; no duplicates found
- [ ] Phase 6: Report drafted; submission pending Pi verification

---

## Session Log

| Date | Phase | Summary |
|---|---|---|
| 2026-06-17 | 0 | Plan written. Scope: unicef.org + all subdomains. |
| 2026-06-17 | 1-3 | Recon complete. 263 subdomains, 190+ live. Confirmed F001: ram.unicef.org JSON:API user enum. Takeover: 0 hits. |
| 2026-06-17 | 5-6 | F001 triaged (Medium 5.3 / High 7.5). Report drafted. Pending: OAuth2 probe on Pi before submit. |
