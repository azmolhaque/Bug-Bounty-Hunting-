# Program selection rubric — 2026-08-26

Written after closing Exoscale with five clean negatives. The purpose is to stop choosing
targets by *interest* and start choosing them by *fit against a demonstrated capability*.

---

## What the operator is actually good at

Evidenced across the Exoscale sessions, not asserted:

- Building a request signer from vendor SDK source (EXO2 HMAC, AWS SigV4)
- Enumerating a full API surface from generated client code rather than from docs
- Designing controls before attacks — positive control, negative baseline, catch-all sentinel
- Isolating one variable (deny-rule policy to test parameter binding, not defaults)
- Testing the operations others skip — copy-source binding, presigned-URL redemption

**That is a systematic API authorization tester.** Target selection should serve that, and
nothing else.

## What has repeatedly gone wrong

24 Google VRP reports closed mostly *informational* / *intended behaviour*. Wiz: no self-serve
tenant. Exoscale: 5 axes, 0 findings. The pattern is **target hardness**, not testing quality.

---

## Hard gates — fail any one, skip the program

| # | Gate | Why |
|---|---|---|
| 1 | **Free self-serve account** | No card. Non-negotiable — the operator funds this personally |
| 2 | **Two accounts obtainable** | Cross-tenant work needs an A and a B. `@intigriti.me` wildcards or `+` addressing |
| 3 | **Multi-tenant construct** — orgs, teams, workspaces, projects | This is the entire attack surface being targeted |
| 4 | **Authenticated API in scope** | REST or GraphQL, documented or discoverable |
| 5 | **Broken access control IN scope** | Read the out-of-scope list. If IDOR/BOLA is excluded, walk away |
| 6 | **Not a security or infrastructure vendor** | Wiz, Exoscale, Aikido, Intigriti itself. Their product *is* this |

## Scoring — rank what survives the gates

| Signal | Weight | Good | Bad |
|---|---|---|---|
| **Accepted per researcher** | ★★★ | > 0.6 | < 0.3 (Exoscale was **0.16**) |
| Bounty floor | ★★ | Low tier ≥ €250 | "Swag" or €50 |
| High/Critical tier | ★★ | ≥ €1,500 / ≥ €4,000 | < €1,000 |
| Scope breadth | ★★ | Wildcard domains **plus** API | One host |
| RBAC richness | ★★ | Roles, permissions, invites, sharing | Single user type |
| Programme responsiveness | ★ | Recent payouts, fast triage | Stale, long queues |
| Age | ★ | Under ~2 years, or recently widened scope | Open 5+ years, heavily mined |

> **Accepted-per-researcher is the single most predictive number** and it is the one that was
> available before we started Exoscale and used incorrectly. A low ratio means *hard*, not
> *untouched*. Never read it the optimistic way again.

## Target archetypes that fit

Ordered by expected fit with the capability above:

1. **B2B SaaS with workspaces** — project management, HR, CRM, marketing automation,
   analytics. Rich RBAC, free tier, big API, and the vendor is not a security company.
2. **E-commerce / marketplace platforms** — merchant accounts are tenants; order, payout and
   catalogue objects cross tenant boundaries.
3. **Developer tooling that is not infrastructure** — CI, docs, feature flags, error tracking.
   Free tiers, org/team models, real APIs.
4. **Fintech with sandbox** — high bounties, strong RBAC. Verify a sandbox exists and that
   testing it is permitted.

## Archetypes to avoid

- **Security vendors.** Their authorization layer is the product.
- **Cloud / infrastructure providers.** Exoscale proved the point at our expense.
- **Anything requiring payment to reach the interesting surface.**
- **Single-tenant products.** No cross-tenant boundary means the strongest capability is unused.

---

## Data to collect from the Intigriti programme list

The platform shows these behind login; they cannot be searched publicly. For each candidate:

```
Program name
Researchers          (count)
Accepted submissions (count)     -> ratio = accepted / researchers
Bounty tiers         (low .. critical)
Scope                (wildcards? API? mobile?)
Out-of-scope         (is broken access control excluded?)
Signup               (free? card required? invite only?)
Last activity        (recent payouts?)
```

Sort by ratio descending, then apply the gates. **Three to five survivors is a good outcome** —
then pick one and commit a full engagement to it rather than sampling.

---

## Engagement rules carried forward

- **Timebox first.** Name the number of sessions before starting, and the drop condition.
- **Controls before attacks.** Positive control, negative baseline, catch-all sentinel — every time.
- **A precondition is not a finding** (FO-9). A 500, a verbose error, a schema dump: not reports.
- **Log negatives honestly** (FO-7). A documented negative has real value; a padded report costs
  platform signal, which is the scarcer resource.
- **Name the stop point in advance** and honour it on the result, as was done with Exoscale H5.
