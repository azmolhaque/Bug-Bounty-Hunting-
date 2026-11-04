# Target selection — 2026-08-26

Exoscale closed (5 axes, 0 findings, 0.00 CHF). Selecting the next engagement against
`PROGRAM-SELECTION-RUBRIC.md`.

---

## Recommendation: **Adobe, on Intigriti, from 1 September 2026**

### The timing argument

Adobe's programme moves from HackerOne to Intigriti on **1 Sep 2026**. Every new report goes to
Intigriti from that date. Adobe ran a largely **reputation-only** programme on HackerOne for
years; migrating to a platform whose proposition is paid bounties is a strong signal the reward
table is now real.

**Why timing beats "softness":** the number that matters is *researcher-hours per asset*, and
the reliable way to improve it is to be early on scope that has just changed hands or just
opened. We cannot make Adobe weaker; we can arrive before the Intigriti researcher population
has worked through it.

### Gates (all six pass — the first candidate that does)

| Gate | Status |
|---|---|
| Free self-serve account | ✅ Adobe ID · Express free tier · Behance |
| Two accounts obtainable | ✅ plus-addressing |
| Multi-tenant construct | ✅ Creative Cloud **Teams**, Experience Cloud **orgs**, Admin Console, shared libraries |
| Authenticated API in scope | ✅ large documented API surface |
| Broken access control in scope | ✅ central to what they reward |
| **Not a security / infrastructure vendor** | ✅ — the gate that should have stopped Wiz and Exoscale |

### Where to aim — this matters more than the company name

**Adobe is not a target, it is ~100 products.** Aim selection decides the outcome.

| Avoid | Why |
|---|---|
| Photoshop · Acrobat · legacy Creative Cloud | Hunted for a decade. Brutal duplicate risk |
| Desktop application binaries | Wrong capability — we are an API authorization tester |
| Marketing sites | Informational-close territory |

| Pursue | Why |
|---|---|
| **Adobe Express** — sharing, team spaces, template publishing | Newest surface, rich sharing semantics |
| **Firefly / AI surfaces** — generation history, asset ownership, credit accounting | Newest code in the estate |
| **Teams / Admin Console** — invites, role assignment, product profiles, entitlement transfer | Exactly the RBAC shape H4 was built for |
| **Shared Libraries / CC Libraries** — cross-org asset sharing | Cross-tenant object access, our strongest class |
| **Behance** — teams, drafts, private projects | Old but far less hunted than the paid products |

### Risks, stated honestly

- **Duplicate risk is the main threat**, not difficulty. Mitigation: hunt the newest surfaces,
  and check Adobe's HackerOne hacktivity for the class before investing.
- Adobe has a mature product-security team. This is not an easy target — it is a **big** one,
  which is different and better suited to us: big scope means under-tested corners exist.
- Migration does not reset Adobe's own knowledge of past bugs. Anything reported on HackerOne
  is still a duplicate.

---

## Authorization — Phase 0, non-negotiable (CLAUDE.md §0)

- Until **1 Sep 2026**, the live programme is on **HackerOne**. Active testing before that date
  is only authorised under HackerOne's programme terms and requires an account there.
- **Plan: no active testing before 1 Sep.** Until then: read documentation, map the product
  surface, and create ordinary user accounts (normal product use, not testing).
- From 1 Sep, test under the Intigriti programme terms — **read the new scope and rules of
  engagement in full on day one**, including any required identifying header. Do not assume the
  HackerOne rules carry over.
- Update `config/scope.yaml` from the Intigriti programme page before the first active request.

---

## Six-day preparation plan (no active testing)

| Day | Work |
|---|---|
| 1 | Create the Intigriti-side prerequisites. Create Adobe accounts **A** and **B** (free tier), each in its own org/team where possible |
| 2 | Map the product surface: which products have orgs/teams, what roles exist, what can be shared and with whom |
| 3 | Pull the API surface from Adobe's public developer docs and any JS bundles served by the products we hold accounts on |
| 4 | Review Adobe HackerOne hacktivity for previously-rewarded classes — dedup intelligence before we start, not after |
| 5 | Write the H1 procedure: the cross-tenant sharing test, with controls (positive, negative, catch-all sentinel) |
| 6 | Rig: request capture, two-account credential separation (the `.keys.sh` pattern), canary discipline |

**1 Sep:** read the Intigriti scope, update `scope.yaml`, run the gates, then hunt.

---

## Open item — better options may exist behind the login

Programme statistics (researchers, accepted submissions, bounty tiers) are visible only to a
logged-in Intigriti user; this environment cannot reach `intigriti.com` at all. A **mid-size
B2B SaaS** with a free tier and a workspace model would likely beat Adobe on
accepted-per-researcher, even though Adobe wins on scope and timing.

**Ask:** paste the Intigriti programme list with `Program · Researchers · Accepted · Bounty
tiers · Scope · Signup type`. Ranking by accepted/researcher takes minutes and may change this
recommendation. Adobe is the best call from public information — not necessarily the best call
that exists.

---

## Engagement terms — set in advance (the Exoscale lesson)

- **Timebox: 4 sessions.** Drop condition: no confirmed boundary crossing on the chosen surface
  by session 4 → reassess target, do not extend on hope.
- Controls before attacks, every time.
- A precondition is not a finding (FO-9). Log negatives honestly (FO-7).
- **Duplicate check before writing anything** — Adobe's public hacktivity is a real dedup source.
