# H12 — Meta: cross-business authorization over the Graph API

Hypothesis: Business Manager **partner sharing** grants business B per-asset,
per-permission access to business A's assets. The Graph API predates that model. Somewhere
an edge checks *"is this token's business related to the asset's business?"* instead of
*"was this specific asset shared, with this specific permission, to this business?"*

Target categories (published, priced): Ads Audience cross-business $7.5k / $5k,
developer platform privacy assertions $25k, page admin disclosure $5k, business & page
take-over $50k.

**Everything below runs from a terminal.** No laptop required.

---

## Gate 0 — before any request

- [ ] Read the *detailed* guideline pages for the three target categories. The summary
      table is not the rules; each page lists mitigating factors that reduce payout.
- [ ] Confirm test-account provisioning works and record which identities are test accounts.
- [ ] Record the external IP (`curl ifconfig.me`) and the date for every session.
- [ ] Re-read `00-PROGRAM.md` rules of engagement. In particular: **test accounts only**,
      and **never manipulate requests to a third-party app**.

## Phase 1 — build the environment (operator, browser or FBDL)

The goal is an A/B pair with an *asymmetric, explicitly scoped* sharing relationship, so
that any access beyond what was granted is unambiguous.

- [ ] Test account **A** → Business **BA**. Test account **B** → Business **BB**.
- [ ] Inside BA create: one Page (`PA`), one ad account (`AA`), one custom audience (`CA`),
      one catalog (`KA`), one pixel (`XA`).
- [ ] From BA, share **only `PA`** to BB, with the **narrowest role available**
      (e.g. Page analyst, not advertiser, not admin).
- [ ] Share **nothing else**. `AA`, `CA`, `KA`, `XA` stay unshared. **These are the
      negative controls — the whole hunt is "can B touch any of them?"**
- [ ] Record every ID: `BA`, `BB`, `PA`, `AA`, `CA`, `KA`, `XA`, both user IDs.
      IDs from our own console only — never guessed, never enumerated (FO-14).

Prefer **FBDL** for this. It has an API and an open-source MCP server, so the environment
becomes reproducible and re-buildable from the phone instead of a one-off click-through.
A reproducible environment is what lets a triager rebuild the finding in five minutes.

## Phase 2 — establish controls before attacking

Same discipline as the Exoscale runlog. Without these, a 200 proves nothing.

- [ ] **Positive control.** Token for B reads `PA` (the asset that *was* shared). Must
      succeed. If it fails, the sharing relationship is not actually live and every
      subsequent negative is meaningless.
- [ ] **Negative baseline.** Token for B reads `AA` (never shared). Must fail. Record the
      exact error code and message — that is what a bypass has to differ from.
- [ ] **Token provenance.** Run every token through the **Access Token Debugger** and record
      app ID, user ID, scopes and expiry. Paste this into the report. Half of authorization
      triage is proving what the token actually was.
- [ ] **Catch-all sentinel.** One request that must always fail (a random unrelated business
      we own nothing in). If it ever succeeds, the test harness is broken, not Meta.

## Phase 3 — the actual attack surface

Work these in order. Each is a separate hypothesis, tested one variable at a time.

1. **Permission granularity.** `PA` was shared with the narrowest role. Enumerate every
   Graph edge on a Page and find one that the narrow role should not reach but does —
   roles list, insights, lead data, linked ad accounts, messaging.
   → *page admin disclosure, $5k*.

2. **Asset traversal from a shared asset.** `PA` is shared. `PA` has edges pointing at
   things that were *not* shared — the owning business, connected ad accounts, catalogs,
   pixels, audiences. Walk every edge outward from `PA` with B's token and see where the
   check stops being per-asset and starts being per-relationship.
   → *the core hypothesis.*

3. **Audience objects across the sharing boundary.** `CA` was never shared. Can B's token
   reference it in an ad set, read its size/composition, or use it as a seed for a
   lookalike? Meta pays for exactly this twice over.
   → *Ads Audience, $7.5k / $5k.*

4. **App permission scope enforcement.** Register an app, grant it a deliberately narrow
   scope set, then attempt reads and writes that exceed the granted scopes. This is a
   different boundary from business sharing and has the highest published price of the
   realistic set.
   → *developer platform privacy assertions, $25k.*

5. **Revocation.** Share `KA` to BB, mint B a token, then unshare `KA`. Does the existing
   token still work? Stale-authorization-after-revocation is a clean, easily-demonstrated
   class. (Note the Adobe lesson: prove revocation against the **API**, not against a page
   that returns 200 because it is a JS shell.)

## Phase 4 — the bar before anything is written up

From `CLAUDE.md` §2 and §6. A finding here means **data of the other business returned to
the wrong token**, not a reachable endpoint and not an error-message difference.

The one-sentence test: *what did B actually GET?* If the answer is "a different error
code", "an object ID we already knew", or "a 200 on an HTML shell" — drop it.

Then: minimal curl, verbatim response bytes, status + size, before/after differential
against the negative baseline, token debugger output, terminal screenshot, first-person
voice. `CLAUDE.md` §9.8.

---

## Known traps, carried from earlier hunts

- **A 200 is not access.** Confirm a JSON body with the other business's data in it.
  (Adobe H10 — a curl that could only ever return 200 on a SPA shell.)
- **Schema is not data.** Field names, object IDs and counts are not a finding. Salesforce
  "873 fields" closed N/A. The record contents are the finding.
- **Never enumerate IDs.** Only IDs visible in our own console. Meta is multi-tenant and
  live — guessing an ID means touching a real person's data, which is both a rules
  violation and the end of the account.
- **Do not write a rule or a report from an in-flight signal.** FO-15: rules get written
  from closed outcomes only.
- **Run the cheap repro before writing the report.** FO-17, earned the hard way today.

---

## BLOCKED — environment could not be built. 2026-09-30

Three routes to a two-identity test environment, all closed in one session.

### 1. Business creation via Graph API — failed

Developer app `h12-research` created (Marketing API use case). Token minted through Graph
API Explorer with `business_management`, `ads_management`, `pages_show_list` — **all three
confirmed `granted`** via `/me/permissions`.

```
POST /v23.0/me/businesses  name=… vertical=OTHER
  -> "Business email address not provided"          (useful, named the missing field)
POST /v23.0/me/businesses  name=… vertical=OTHER email=…
  -> {"message":"An unknown error has occurred.","code":1}
```

`code 1` carries no information, so there was nothing left to fix by inspection. Meta appears
not to allow a first business portfolio to be created through the API.

### 2. Business creation via UI — worked, then got restricted

`business.facebook.com` accepted the portfolios, though it rejected the names `h12-a` /
`h12-b` as not reflecting a real business. Created as `Azmol Haque Consulting` and
`Rony Digital Services`.

Within minutes, the second was restricted:

> **We restricted your business** — Rony Digital Services, Business ID 1171981801830096
> *"It looks like this account was created or used with an automation that doesn't follow our
> rules. This goes against our Advertising Standards on Account Integrity."*
> Effects: cannot create or run ads, cannot use or share audiences (6 restrictions total).

**Cause, honestly: the testing pattern, which I directed.** Two failed API creation attempts
followed immediately by two rapid UI creations reads as automation to Meta's integrity
systems. Not the operator's error.

Operator's personal profile checked immediately after: **in good standing**, with
Recommendations, Monetization and Marketplace all Active, and the real Page
(55 followers, live engagement) unaffected. Damage contained to the throwaway business.

### 3. Program test accounts — disabled by Meta

`facebook.com/whitehat/accounts` → **Create New Account**:

> **Test account creation is temporarily disabled.** Please try again later.

This was the correct route from the start, and it is unavailable.

## Decision

**Meta is parked, not abandoned.** The surface map, the seven ranked targets and the
single-request T1 all remain valid and cost nothing to hold. Resume when program test
account creation is re-enabled.

**Do not rebuild this environment on the operator's real account.** Their profile carries an
active monetized Page with real followers. Meta's own rules require test accounts, the one
attempt on the real account already drew an integrity restriction, and a speculative bounty
does not justify risking a live income source. That trade was mine to flag earlier and I
flagged it late.

### Rule earned

**FO-20 — Environment setup is testing, and the target is watching it.**
Rate limits, integrity systems and abuse detection apply to account and resource creation
exactly as they apply to probing. Two failed API calls plus two rapid UI actions were enough
to trigger an account-integrity restriction before a single security test had run. Build test
environments at human pace, on credentials that can be lost.
