# Personio — program card

Intigriti, public. **First target chosen from the numbers rather than by accident.**

## Why this one

Ranked from all 59 open bounty programs on the operator's Intigriti dashboard by
**accepted-per-researcher**, the metric the rubric calls most predictive and that had never
once been used.

```
Personio        1.48   (351 accepted / 237 researchers)   EUR 50 - 5,000
--
Adobe           0.73    <- three clean negatives here
Exoscale        0.16    <- five axes, zero findings
```

Programs that scored higher were rejected on the gates, not the number: UCB Biopharma (4.89)
is application-only; WP Engine (1.98) and DigitalOcean (1.00) are hosting/cloud, which the
rubric names as the archetype to avoid and which Exoscale already proved; Axel Springer and
DPG Media have EUR 15-25 floors on media sites with little API surface; Yahoo (1.96) is
decades-hunted and its bug classes do not match this operator's capability.

## Six hard gates — 6/6 PASS

| # | Gate | Evidence |
|---|---|---|
| 1 | Free self-serve account | 14-day free trial, `personio.com/free-trial` |
| 2 | Two accounts obtainable | **The program instructs it**: `sec-test-<handle>-01` … `-99` |
| 3 | Multi-tenant construct | each trial is a separate tenant on its own subdomain |
| 4 | Authenticated API in scope | `api.personio.com`, Tier 2 |
| 5 | **Broken access control in scope** | **cross-tenant explicitly in scope** — see below |
| 6 | Not a security/infra vendor | HR SaaS for SMEs |

## The thing that blocked the last two engagements is solved here

Coveo: both orgs owned by one identity, so the user token legitimately saw both and the
negative control was weak. Meta: a second identity could not be created at all — API refused,
UI drew an integrity restriction, program test accounts disabled.

Personio hands over the environment by design:

> *"Testers must create their own instances … Register with your @intigriti.me address …
> name your company in format `sec-test-<intigriti handle>-<nn>` … The environments come
> **preloaded with realistic user data**"*

So: two genuinely separate tenants, each with a **known, predictable URL**, each **already
populated**. No empty-org problem, no shared-owner problem, no canary-planting needed before
a comparison means anything.

Operator handle is `gorib`, so the tenants are:

```
https://sec-test-gorib-01.personio.de/
https://sec-test-gorib-02.personio.de/
```

Register both with `gorib@intigriti.me`.

## Scope

| Asset | Tier |
|---|---|
| `*.app.personio.com` | 2 |
| `api.personio.com` | 2 |
| `https://*.personio.de` | 2 |
| `https://sec-test-<handle>-<nn>.personio.de` | 2 |
| `*.app.personio-dev.com`, `api.personio-dev.com` | 2 |
| `*.personio-internal.de`, `*.personio.tools` | 2 |
| `https://*.personiowhistleblowing.com` | 2 |
| `hug.personio.com` | 2 |
| `community.personio.com`, free-trial pages, other Personio assets | 3 |

**Out of scope:** `www.personio.com`, `www.personio.de`, `www.personio.es`,
`support.personio.de` (Zendesk), `statuspage.personio.de`, `personio.slack.com`,
careers pages. The **Conversations product** is entirely out of scope.

## What they pay for — the severity table is the target list

| Severity | Examples, verbatim |
|---|---|
| Exceptional | RCE · access to AWS keys |
| **Critical** | **Access to all users or accounts · account takeover · multi-tenant PII access** |
| **High** | **Stored XSS (cross-tenant only) · access to one user or account · privilege escalation within the same account with account takeover or similar (making yourself admin, gaining access to salary info)** |
| Medium | Stored XSS single-tenant · reflected XSS ≤1 step · privilege escalation exposing GDPR data |
| Low | Reflected XSS with interaction · full path disclosure |

This is HR software: the data is salaries, addresses, national identifiers, contracts,
documents. **There will be no argument about whether the impact is concrete** — the failure
mode that killed the Google VRP reports and AppSheet.

## Broken access control — read the exclusion carefully

Out of scope is **only**:

> *"Broken Access Control issues via uncommon Access Rights setups **that do not cross tenant
> boundaries** and don't affect sensitive information; firstname / lastname / email address of
> employees **in the same tenant** are not considered sensitive."*

Their own examples of what does **not** count: hidden employee list but coworker's name found
via an API endpoint (not cross-tenant); survey visible in another area after access removed;
terminated employee's name still findable.

**Every exclusion is qualified "not cross-tenant" or "same tenant".** Cross-tenant access
control is the thing they are asking for, and it is the exact capability built across the
Exoscale, Coveo and Meta work.

## Constraints

- **14-day trial limit.** Instances expire; new ones must be created. Plan sessions around it
  and record tenant names and creation dates.
- Register with `@intigriti.me`, and use the naming format — instances are pre-registered
  against the tester's address before bounty activity counts.
- Trial may default to German. Language switch documented in their FAQ.
- **No DoS**, and DoS/CPDoS is in scope *only* on `*.app.personio.com` under strict
  conditions. Volumetric attacks strictly forbidden, must not be tested.
- No credential stuffing, no brute force, no rate-limit testing (explicitly out of scope).
- Real users must not be affected — use cache busters and isolated parameters.

## Standing traps to carry in

- A 200 is not access; confirm the other tenant's **data** in the body (Adobe H10).
- Schema and field names are not data (Salesforce N/A).
- Never guess or enumerate identifiers belonging to anyone but our two tenants (FO-14).
- **The positive control must pass before any negative means anything** (FO-19) — this cost
  five invalid tests on Coveo in one night.
- Environment setup is testing, and the target is watching it (FO-20) — build at human pace.
