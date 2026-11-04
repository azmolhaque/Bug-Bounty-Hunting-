# Adobe H10 — Express sharing: authorization boundaries

**Target:** `new.express.adobe.com` — **Tier 2** ($100 low … $2,500–5,000 critical).
**Class:** Broken access control on shared objects.
**Cost:** free tier. **Tooling:** none required — every test below is doable in a browser,
phone included. Canary run: `4dc09wuc`.

> Scope note: `express.adobe.com` and `express-embed.adobe.com` are **out of scope**.
> Only `new.express.adobe.com`.

---

## Why this and not more AI work

The AI thread is closed: Acrobat's tools are paywalled, Express's assistant has no
boundary-crossing action. But Express's **real** sharing feature is free, multi-tenant, and
exactly the class the operator has tested well before (Looker H3, Exoscale H2/H5).

**And the strongest tests here need no DevTools** — they are sequences of UI actions across two
accounts, which is precisely what a phone-only session can do properly.

---

## The boundary that must be crossed (FO-9)

A finding exists **only** if:

> **Account B reads or modifies a project that A never shared with it — or that A shared and
> then revoked** — evidenced by **A's canary appearing in B's session**, or by a change B made
> being visible to A.

**Not a finding:** a share link working as designed · a project A deliberately made public ·
an odd error · a URL that loads an empty editor · B seeing a *thumbnail* with no content access.

---

## PHASE 0 — setup and gates

**Two separate sessions.** Account A in your normal browser, account B in a private/incognito
window (or a second browser). If both share a cookie jar you will "prove" cross-account access
that is really just the same account twice — the failure the Exoscale key-fingerprint rule exists
to prevent. **Screenshot the profile avatar in each window before starting.**

### Setup

As **A**, create two projects:

| Project | Content | Sharing |
|---|---|---|
| `alpha-4dc09wuc` | text `ALPHA-4dc09wuc-SECRET` | **never shared with anyone** |
| `bravo-4dc09wuc` | text `BRAVO-4dc09wuc-SECRET` | used for the sharing tests below |

Record each project's **URL** — that is the object reference.

### Gates — screenshot each

| Gate | Test | Required result |
|---|---|---|
| **0A** positive control | A opens `alpha` | 200, canary visible. Proves the object and the URL are right |
| **0B** negative baseline | **B** opens `alpha`'s URL | **Denied.** B's avatar must be visible in the same frame |
| **0C** catch-all (FO-2) | B opens a **syntactically valid but non-existent** project URL (alter one character of a real ID) | Should error. If it returns a working editor, the app is a catch-all and every later "hit" is meaningless |

**0B is the whole experiment.** Without a clean denial there, nothing after it means anything.

---

## The tests, in priority order

### H10a — REVOCATION ⭐⭐ best test available without DevTools

> **A shares `bravo` with B, then revokes. Does B still have access?**

Share indexes and cached grants are frequently written once and never re-checked when sharing
changes. "Access removed but still usable" is high-impact, easy to demonstrate, and not what a
crowd of researchers is looking at.

1. As A, share `bravo` with B (invite, or link-with-access)
2. As B, **open it and confirm the canary is visible** — this is the positive control
3. As A, **remove B's access** (unshare / revoke / turn the link off)
4. As B, **reload the same URL** — do **not** open a new one

| B sees | Meaning |
|---|---|
| Still the full project, canary readable | 🎯 **Finding.** Revocation not enforced |
| Still loads but empty / placeholder | Partial. Record it; not submittable alone |
| Denied | Correctly enforced. Log and move on |

**Then push once more:** close the tab, wait ~5 minutes, reopen. A grant that survives a reload
but dies on a fresh session is a caching bug; one that survives both is an authorization bug.

### H10b — ROLE DOWNGRADE ⭐

> **A shares with edit rights, B opens, A downgrades to view-only. Can B still edit?**

1. A shares `bravo` with B as **editor** (or "can edit")
2. B opens it and makes a small edit — confirm it saves
3. A changes B's access to **view only**
4. B, **without reloading**, edits again and lets it save

If B's edit persists and A can see it, the write authorization was decided at grant time and
never re-checked. Same family as revocation, different verb.

### H10c — LINK SHARING vs INVITE

> **Does a "view only" link actually prevent writes at the server?**

1. A creates a **view-only** share link for `bravo`
2. B opens it — confirm read-only in the UI
3. Attempt an edit anyway (the UI may block it; the question is what the **server** does)

A UI that hides the edit button while the backend accepts the write is a real finding. Without
DevTools this is hard to prove — **defer the deep version to a laptop session**, but note whether
the UI ever lets an edit through.

### H10d — PUBLIC / PUBLISHED assets

> **Does publishing or a template share expose a project A never intended to publish?**

If Express offers "publish as template" or a public gallery, check whether that action exposes
*other* assets in A's account (brand kits, folders, uploads) rather than only the published one.

---

## Reading results

| Observation | Meaning |
|---|---|
| B's session renders **A's canary** on an object never shared, or after revocation | 🎯 Finding |
| B sees a title or thumbnail only | Metadata. **Not submittable alone** — same reason the Salesforce field-name case closed N/A |
| B's edit persists after downgrade | 🎯 Finding (integrity) |
| Denied everywhere | Correct. Log the negative (FO-7), move to Behance |

**Proof is A's canary inside B's session, with B's identity visible in the frame.** A status code
is not proof. A screenshot without the avatar is not proof.

---

## Evidence checklist (CLAUDE.md §9.8)

- [ ] Date/time · **testing IP `180.148.212.32`** (Adobe requires it for bounty and Safe Harbour)
- [ ] 0A: A reads `alpha`, canary visible
- [ ] 0B: **B denied on `alpha`, B's avatar in frame**
- [ ] 0C: catch-all control recorded
- [ ] The share action, the revoke action, and B's post-revocation view — **all three screenshotted**
- [ ] Differential: expected (denied after revocation) vs observed
- [ ] Both accounts ours; no third-party project ever opened
- [ ] First-person plain voice, real screenshots (FO-10)

## Safety

- **Only our own two accounts.** Never open a project URL that is not ours; never alter an ID to
  go hunting for someone else's project. The 0C control uses one deliberately-invalid ID and
  stops there (FO-14).
- No destructive action on anything shared or collaborative.
- If any view ever shows a **third party's** content: stop, do not save it, report that fact.

---

# H10 RESULT — **CLEAN NEGATIVE. Closed 2026-09-25.**

Accounts A/B · canary `4dc09wuc` · phone browser + Pi terminal.

## Gates

| Gate | Test | Result |
|---|---|---|
| **0A** | A opens `alpha-4dc09wuc` | 200, canary visible ✅ |
| **0B** | B opens A's never-shared project URL | **404 "Page not found"** ✅ |
| 0C | one-character-altered project ID | error |

**0B is better than a plain denial.** A `404` rather than "access denied" gives no existence
oracle — an unauthorised visitor cannot distinguish a real project from a fabricated ID.

## Embed link — the main test

Express offers **Share / Publish / Embed**. Embed was badged *NEW*, so it got priority.

**Controls Adobe got right, all recorded as negatives:**

1. **Email verification required** before an embed link can be created at all.
2. **Separate URN.** The embed URN (`77bd9b83-…`, then `88c978cd-…`) is *not* the project URN.
   The private document's identifier is never exposed.
3. **No identity leakage.** The embed page HTML contains **no** URN of any kind, no owner e-mail,
   no account name, no canary. Content is fetched client-side after the URN is parsed from the path.
4. **Revocation is enforced server-side.** After *Delete embed link*, the same URL returns:

   > **"File unavailable — The linked file was removed and can't be restored."**

   The backend distinguishes *removed* and refuses. The product's stated promise —
   *"Links can be deleted anytime"* — holds.

## A methodological trap this run walked into

The terminal probe of the embed URL returned **`200 303747`** both before *and* after deletion —
**byte-identical**. That is the static SPA bundle, which serves for any `/embedLink/<anything>`
path whether the link exists or not.

> **A 200 on a JavaScript application's shell is not evidence the resource exists.** Identical
> response sizes across a state change prove the response is static. The real state lived in the
> rendered view, not the status code.

Read off `curl` alone, the conclusion would have been the exact opposite of the truth.

**Positive control never obtained, stated honestly.** The embed link is a *"Smart embed link
(supported platforms)"*, designed to be unfurled by a host site or loaded in the supplied
`<iframe>`. Opened directly in a mobile browser it produced a guest sign-in flow and
*"Can't save — You no longer have access to Adobe Express"* — for the **live** link and the
deleted one alike. So the canary was never watched rendering through a live embed.
**The negative rests on the server-side "File unavailable" response, not on an inferred
comparison.** A fuller run would host the supplied iframe on the Tailscale Funnel rig and view it
anonymously.

## Not pursued, and why

**An embed link serving content publicly is intended** — *"Embed your design anywhere on the
web."* The owner opts in explicitly. Reporting that would close WAI exactly as the AppSheet
connector SSRF did. The only question worth asking was whether the advertised *revocation* works,
and it does.

## Verdict

**No finding.** Express's sharing surface enforced every boundary tested.
