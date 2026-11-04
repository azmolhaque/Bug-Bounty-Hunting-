# Program assessment — Meta Bug Bounty (bugbounty.meta.com)

Date: 2026-09-25
Source: operator-supplied program overview + program scope pages (saved MHTML).
Assessed against `PROGRAM-SELECTION-RUBRIC.md`.

## Verdict

**Conditional yes — on exactly one axis, not as a general hunt.**

Meta is the first program this year to pass all six hard gates. It also fails the single
signal the rubric calls most predictive, harder than any target we have touched. Both of
those are true at once and the recommendation has to hold both.

---

## Hard gates — 6/6 PASS

| # | Gate | Result | Evidence |
|---|---|---|---|
| 1 | Free self-serve account | **PASS** | Consumer accounts free; no card anywhere |
| 2 | Two accounts obtainable | **PASS** | Program *ships* a Test Accounts tool. Better than plus-addressing |
| 3 | Multi-tenant construct | **PASS** | Business Manager, Pages, Ad accounts, Groups, Workplace, Apps |
| 4 | Authenticated API in scope | **PASS** | Graph API, with official Graph API Explorer + Access Token Debugger |
| 5 | Broken access control in scope | **PASS** | Not excluded. "Page admin disclosure" is a *named $5K payout category* |
| 6 | Not a security/infra vendor | **PASS** | Consumer social platform |

Gate 5 deserves emphasis. The out-of-scope list is spam/social engineering, DoS, content
injection, third-party apps, sandboxed domains (`fbsbx.com`, `fbrell.com`), and stale mobile
crashes. **Authorization and privacy bugs are not excluded — they are the program's
headline categories.** That is the opposite of Exoscale, where the interesting surface was
the vendor's own product.

## Scoring signals — mixed, with one disqualifying-grade weakness

| Signal | Weight | Meta | Read |
|---|---|---|---|
| **Accepted per researcher** | ★★★ | **not published — but inferred terrible** | $31.4M paid since 2011; among the most-hunted programs on earth |
| Bounty floor | ★★ | $500 | GOOD |
| High/Critical tier | ★★ | $130K ATO, $300K mobile RCE / WhatsApp PP | EXCELLENT on paper |
| Scope breadth | ★★ | facebook.com, instagram.com, threads.com, whatsapp.com, messenger.com, meta.ai, oculus.com, mapillary.com, github.com/facebook/* | EXCELLENT |
| RBAC richness | ★★ | Business Manager asset assignment, Page roles, system users, partner sharing | EXCELLENT |
| Responsiveness | ★ | high volume, slow queue, aggressive dup/NA | POOR |
| **Age** | ★ | **open since 2011 — ~15 years** | **WORST possible** |

The rubric exists because our losses came from **target hardness**, not testing quality.
Meta is the hardest target in existence by researcher density. Choosing it as a general
hunt would be repeating the Exoscale mistake at larger scale. The rubric's own warning
applies with full force: *a low accepted ratio means hard, not untouched.*

---

## Where an opportunity genuinely exists

Not "Meta" — one axis inside Meta.

### Primary: Business Manager authorization via Graph API

Fits the one capability the rubric says to select for — *systematic API authorization
testing* — better than anything else available to us.

- Business Manager is a real multi-tenant RBAC system: businesses own ad accounts, Pages,
  catalogs, pixels, datasets; roles include admin / employee / finance analyst / finance
  editor; **system users** carry their own tokens; **partner sharing** grants a *second*
  business access to a *first* business's assets.
- Partner sharing is the interesting part. It is a cross-tenant grant with per-asset,
  per-permission granularity, layered over an API that predates it. That is exactly the
  shape of construct where authorization checks get missed — analogous to the
  `parameters.bucket` CEL-binding work on Exoscale, but on a surface that is not the
  vendor's own security product.
- Named payout category already exists: **Page admin disclosure, $5K**. A published
  category means the class is accepted, scored and paid — no arguing about whether it
  counts.
- Works entirely from a terminal. Graph API is HTTP + a bearer token. This runs from
  Termux on the phone, which matches the operator's actual constraints.

### Secondary: contact point deanonymization ($10K named category)

Linking an account to a phone number or email that should not be exposed. Solo hunters do
still land these, they need no compute, and they are testable with two provided test
accounts and privacy settings set to maximum restriction.

### Explicitly NOT worth our time

- **Mobile RCE ($300K)** — exploit development. Not our capability.
- **WhatsApp Private Processing ($300K)** — invitation only. Cannot access.
- **Meta AI** — looks tempting after the Adobe and gemini-cli work, but read the scope
  carefully: they want *training data extraction / model inversion*, which is research-grade
  and compute-hungry. Jailbreaks and risky output are explicitly routed to a **non-bounty**
  feedback form. The accessible half of this surface is excluded by design.
- **XSS / IDOR on facebook.com core** — mined continuously since 2011.
- **Anything on `fbsbx.com` / `fbrell.com`** — sandboxed, explicitly out of scope.

---

## Honest odds

Low. Higher than Exoscale, Adobe or Google OSS VRP were, because for the first time the
surface is large, free, API-driven, and the bug class we are good at is *in* scope rather
than adjacent to it. But Meta has had fifteen years and thousands of full-time researchers,
and duplicates are decided at Meta's sole discretion with no obligation to show prior
reports.

The reason to go is not that it is soft. It is that it is the first target where our one
demonstrated capability is pointed at an accepted, published, paid bug class.

## Operating constraints to carry in

- **Test accounts only.** Real accounts are permitted only if the issue cannot be reproduced
  on a test account, and never for automated testing. Never touch another person's account.
- No DoS. No social engineering. No content injection.
- One issue per report, via the official form only. Do not contact staff through other
  channels.
- Third-party apps integrating with Meta are out of scope except under narrow passive-
  observation conditions — do not manipulate requests to them.
