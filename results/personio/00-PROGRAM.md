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

## Rules of engagement — operational, read before any request

```
@intigriti.me            Required
User agent               Not applicable
Automated tooling        max. 2 requests / sec
Request header           X-Intigriti-Username: gorib      <- on EVERY request
```

Same shape as Exoscale. The header is not optional and the rate cap is explicit — 2 req/s,
which rules out any of the sweep scripts written for Coveo without re-pacing them.

Also: no disclosure without written consent, including PoC videos on YouTube or Vimeo.
Safe harbour applies.

## Bounty table

| Severity | CVSS | **Tier 2** | Tier 3 |
|---|---|---|---|
| Low | 0.1–3.9 | €175 | €50 |
| Medium | 4.0–6.9 | €350 | €100 |
| **High** | 7.0–8.9 | **€1,125** | €450 |
| **Critical** | 9.0–9.4 | **€3,000** | €1,000 |
| Exceptional | 9.5–10.0 | €5,000 | €2,000 |

All our targets sit on Tier 2 assets (`*.app.personio.com`, `api.personio.com`).

## Environment status — 2026-09-30

**Tenant A: LIVE.** `sectestgorib01.app.personio.com`, identity `CANARY-TENANT-A`,
registered `gorib@intigriti.me`, **1152 preloaded employee records**. Trial expires
~14 Oct 2026.

**Tenant B: BLOCKED.** Personio refuses a second trial on the same address, and
**strips plus-addressing** — `gorib+02@intigriti.me` was normalised to `gorib@intigriti.me`
and rejected with *"You already have a Personio trial account"*. The Intigriti relay
forwarded it correctly, so the normalisation is Personio's.

This contradicts their own FAQ, which instructs researchers to create `sec-test-<handle>-01`
through `-99`. **Ask the program how a second instance is provisioned** — do not improvise
with a non-`@intigriti.me` address, since the RoE requires that domain.

## Consequence for the test plan

The cross-tenant axis (Critical, €3,000) is **blocked pending the program's answer**.

The **within-tenant privilege escalation axis is not blocked** and pays High (€1,125). From
their severity table, verbatim:

> **High** — *"Privilege escalation within the same account with account take-over or similar
> (making yourself admin, gaining access to salary info)"*

Tenant A already has 1152 employees and a full roles system. Next session:

1. Create a low-privilege employee in tenant A (own data only).
2. Log in as that employee — **this is the positive control**: confirm it sees its own record.
3. Attempt to reach other employees' **Salary**, **Payroll information**, **Bank details**,
   **Documents**.
4. Attempt self-escalation to admin.

Note their out-of-scope exclusion carefully: within-tenant access control is excluded only
where it "does not affect sensitive information", and they name firstname/lastname/email as
*non*-sensitive. **Salary, payroll, bank details and documents are not on that list** — and
the severity table prices salary access explicitly. So the axis is live, but the finding must
reach genuinely sensitive data, not a name in an API response.
