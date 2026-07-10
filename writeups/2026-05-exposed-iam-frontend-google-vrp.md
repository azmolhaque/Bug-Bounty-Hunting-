# Anatomy of an Exposed IAM Frontend

**A total authentication bypass on a Google-acquisition asset — and a precise account of why it was fixed in nine days but rewarded $0.**

![Program](https://img.shields.io/badge/Program-Google_VRP-4285F4)
![Status](https://img.shields.io/badge/Status-Fixed-success)
![Triage](https://img.shields.io/badge/Triage-P2_%2F_S2-orange)
![Reward](https://img.shields.io/badge/Reward-Credit_%2F_Honorable_Mention-lightgrey)
![Disclosure](https://img.shields.io/badge/Disclosure-Coordinated-blue)

> **CWEs:** CWE-287 (Improper Authentication) · CWE-1188 (Use of Default Credentials) · CWE-319 (Cleartext Transmission)
> **Asset class:** Google acquisition (Photomath), Tier-1 per `external_domains_acquisitions.asciipb`

**TL;DR** — An administrative IAM interface sat exposed on the public internet on a Google-acquisition subdomain. The login accepted default credentials, then accepted *any* password, and the API behind it answered unauthenticated requests — a complete failure of the authentication layer. Google's product team triaged it P2/S2 and decommissioned it in nine days. The VRP reward panel, separately, awarded credit and no cash. This writeup breaks down the exposure, then does the harder and more useful thing: it explains, at a mechanism level, **why those two decisions are both correct and not in conflict** — and what evidence would have moved it across the reward bar. Calibrating that gap is the real skill.

---

## Contents
- [Why I'm writing this](#why-im-writing-this)
- [1. Discovery — and how to find this class on purpose](#1-discovery--and-how-to-find-this-class-on-purpose)
- [2. The authentication weakness](#2-the-authentication-weakness)
- [3. The API layer behind it](#3-the-api-layer-behind-it)
- [4. Remediation](#4-remediation)
- [5. Root cause, precisely: edge-fronted ≠ Google-operated](#5-root-cause-precisely-edge-fronted--google-operated)
- [6. Why this was correctly not rewarded — and what would have changed that](#6-why-this-was-correctly-not-rewarded--and-what-would-have-changed-that)
- [7. If I were defending this](#7-if-i-were-defending-this)
- [8. Lessons I'm carrying forward](#8-lessons-im-carrying-forward)
- [Timeline](#timeline)

## Why I'm writing this

Most bug-bounty writeups stop at "I found X, here's the payout." The more useful story is usually the gap between how severe a finding *looks* and how severe it *is* — because judging that gap correctly is the actual job, on both sides of a triage queue and on any security team.

This finding looked critical on the surface: an unauthenticated administrative Identity-and-Access-Management (IAM) interface, exposed on the public internet, on a domain belonging to a Google acquisition. Google's product team agreed it was worth fixing (P2/S2) and remediated fast. The VRP reward panel decided, separately, that it did not merit a monetary reward — and after working through the evidence I think their reasoning was exactly right.

So this does two things: it dissects the technical anatomy, and it explains — honestly, and at the level of *why the systems behaved this way* — why "fix fast" and "pay nothing" were both the correct calls. The second half is the part I'd want a hiring manager to read.

## 1. Discovery — and how to find this class on purpose

The asset was `rip.photomath.net`, a subdomain tied to a Google acquisition (Photomath). This did not surface by luck; it surfaced from a repeatable method for the highest-yield corner of a large acquisition-heavy scope — **stale, un-migrated infrastructure from recently acquired companies**:

1. **Enumerate the acquisition scope, not just the flagship.** Google's own scope file `external_domains_acquisitions.asciipb` classifies acquisition domains by tier. `*.photomath.net` is in there at Tier 1. Acquisition subdomains are where integration debt lives.
2. **Passive subdomain expansion** (certificate-transparency logs + historical DNS) surfaces hosts like `rip.` that never appear in the product's own navigation.
3. **Resolve-and-fingerprint every host**, then filter hard for the tells of un-migrated infra rather than hardened production:

| Observation | How it was determined | Why it matters |
|---|---|---|
| Served an admin UI (`GestionUsersRolesFrontend`) | Direct browser load | A privileged users/roles management surface |
| **Plain HTTP only; TLS failed on `:443`** | `unexpected eof` on the HTTPS handshake | A host outside the acquirer's standard TLS-terminating edge policy — a migration tell (CWE-319) |
| **Fronted by Google infrastructure** | `Via: 1.1 google` header; GCP IP on resolution | Routes through Google's edge — but, as Section 5 shows, edge-fronted is **not** the same as operated-by-Google |
| Non-English admin strings (`Bienvenue administrateur`), placeholder text (`users works!`) | UI inspection | Source-company build, likely dev/sandbox, carried over unchanged in the acquisition |

The pattern that should make an experienced hunter stop and look: **a users/roles admin panel, reachable over plain HTTP, with no SSO / identity-aware proxy in front of it, on an acquisition-tier domain.** Every one of those adjectives is a symptom of infrastructure that was inherited and never folded into the acquirer's security perimeter.

## 2. The authentication weakness

The login screen (`Bienvenue administrateur`) accepted the textbook default pair:

```
email:    admin@photomath.net
password: admin
```

That alone is CWE-1188 (default credentials). But probing further revealed something more fundamental: the portal accepted *any* arbitrary password string for the admin account. That moves it from "weak credentials" to **CWE-287 (broken authentication)** — the frontend performed no meaningful credential validation against a backend at all. The login was decorative.

I confirmed this deliberately (login with random characters) rather than assuming it, because "default creds work" and "auth is entirely absent" are different severities and I wanted to claim only the one I could prove.

## 3. The API layer behind it

A UI-level bypass is a weak finding if the backend still enforces authorization independently. So the next question — the one that separates a screenshot from an actual finding — was: **does the API behind this UI check auth on its own?** It did not.

```http
GET /api/roles HTTP/1.1
Host: rip.photomath.net
# no auth headers, no session cookie

HTTP/1.1 200 OK
[]
```

An unauthenticated GET returned a valid (empty) JSON array, not a `401`/`403`. An `OPTIONS` probe advertised `GET, POST, HEAD` — the endpoint was built to accept writes as well as reads. Whitelabel error pages identified the backend as Java Spring Boot.

So two independent controls — frontend authentication and backend authorization — were both absent on the same surface. That is the architecturally interesting part, and it is why the finding was *complete*: I didn't stop at "the login is fake," I demonstrated the data layer itself was open.

![Authenticated admin dashboard showing the Roles section and an open "Create role" form, with "Welcome, administrator" in the header](./images/rip-photomath-dashboard.png)

*The admin dashboard, reached without valid credentials. Note the empty "Create role" form (a write surface) and the complete absence of real user data — consistent with a non-production/sandbox instance.*

**Scope of testing.** I confirmed read reachability and the advertised method set. I did **not** issue writes, create roles, or modify any state. Demonstrating reachability was sufficient to prove the control failure, and stopping there is what safe-harbor expectations require. Claiming the write path *worked* without exercising it would have been overclaiming; noting it was *advertised* is fact.

## 4. Remediation

Google's handling was fast and clean:

- **Accepted within ~24 hours** and filed to the responsible product team.
- **Marked Fixed nine days after acceptance** — the endpoint was decommissioned and the hostname began returning `NXDOMAIN`. I independently re-verified the `NXDOMAIN` and reported back.
- Triaged internally as **P2 / S2**.

Note *how* it was fixed: not a code patch, not an auth middleware change — the record was pulled and the host stopped resolving. That detail is the whole key to the reward decision, and it's the subject of the next section.

## 5. Root cause, precisely: edge-fronted ≠ Google-operated

This is the part most writeups skip, and it's the part that actually explains everything.

`rip.photomath.net` resolved to an address behind Google's edge and returned `Via: 1.1 google`. It is tempting — and I initially leaned this way — to read "traffic flows through Google's edge" as "this is a Google-operated production system." **It isn't the same thing**, and the difference is the entire finding:

- A **DNS record inherited from the acquisition** still pointed at a deployment that was spun up by Photomath before the acquisition and never decommissioned or migrated. It was an **orphaned frontend**, not an integrated Google service.
- Because it was never folded into the acquirer's perimeter, it sat **outside the identity-aware proxy** (no BeyondCorp/SSO gate) and **outside standard edge TLS policy** (plain HTTP, failed `:443`). Those weren't separate bugs — they're all the same symptom: *this box was never brought inside the fence.*
- The application was almost certainly a **dev/sandbox build** — French UI strings, `users works!` placeholder, and an empty `/api/roles`. There were no real users, credentials, or records behind it.
- The fix being **"pull the DNS record"** rather than **"patch the app"** confirms the root cause: there was no owned, operated application to patch. The vulnerability lived in a **dangling artifact that merely resolved through Google's infrastructure.**

This is the standard shape of **acquisition-integration risk**: when a company is acquired, its DNS zones, cloud projects, and half-forgotten deployments get migrated on a timeline, and stale records survive in the gap. They are absolutely worth finding and worth fixing — but their root cause is *inventory and hygiene*, not a defect in the acquirer's application code.

## 6. Why this was correctly not rewarded — and what would have changed that

It's easy to write "unauthenticated admin access + broken auth + exposed write API on a Tier-1 Google asset" and call it critical. I framed it strongly at first. But **severity is realized impact on systems and data that actually matter**, and the reward panel's rationale was precise (quoting their decision):

> *"…not located within a Google application, but was instead the result of stale DNS records. Because the vulnerability did not affect a system under our direct operational control, it does not qualify for a monetary reward…"*

Three things cut against the dramatic reading, and all three follow directly from Section 5:

- **(a) Non-production.** Placeholder text and an empty `/api/roles` — an exposed admin panel over an empty sandbox is a genuine hygiene problem, not a data breach.
- **(b) Hygiene, not application vulnerability.** The fix was decommissioning a dangling endpoint. VRP rewards defects in systems Google operates, not orphaned artifacts that happen to resolve through its edge.
- **(c) My strongest impact claim was speculative.** In my appeal I leaned on a **brand/phishing vector** — that an attacker could harvest credentials from staff who recognized the trusted interface. That's a *hypothetical secondary* impact, not demonstrated harm, and it was adjectives, not a new fact. The panel reconsidered and upheld the original decision, correctly.

### The distinction that decided it: severity track ≠ reward track

A P2/S2 **"Fixed"** is an *engineering* signal — the team judged it worth cleaning up. It is **not** a *reward* signal. The product team optimizes for "should this be cleaned up?"; the reward panel optimizes for "did this expose real risk in a system we operate?" Those are different questions with different answers, and conflating them is a common early mistake — one I made in the appeal.

### What *would* have crossed the reward bar (the useful counterfactual)

Knowing precisely what was missing is more valuable than the finding itself. Any **one** of these would likely have changed the outcome — and each is a concrete next test, not a wish:

| If I had proven… | Why it crosses the bar |
|---|---|
| `/api/roles` returned **real user records** (actual PII, not `[]`) | Data exposure Google is responsible for — impact realized, not hypothetical |
| The **write path** (`POST /api/roles`) created a role that **federated into an authenticated, Google-operated system** (shared SSO/session) | Privilege escalation from a husk into production — pivot proven |
| The host **shared a cookie domain** (`.photomath.net`) or an **OAuth `redirect_uri` allowlist** with a *live, authenticated* production app | Session/token theft against real users — the classic dangling-subdomain chain |

None applied here: empty sandbox, no shared authentication surface, no reachable production pivot. Recognizing that *before* escalating the appeal is exactly the calibration the second decision was testing for — and where I could have saved my own credibility.

## 7. If I were defending this

The finding is more useful to a security team as a detection-and-prevention lesson than as a war story. If I owned this perimeter:

**Detect**
- Continuous **certificate-transparency monitoring** for every acquisition domain (`*.photomath.net` and siblings) — new and forgotten hosts both show up in CT.
- A scheduled **resolve-and-classify sweep** of every subdomain in the acquisition-tier scope file, flagging: plain-HTTP admin UIs, hosts *not* behind the identity-aware proxy, and any `2xx` on an unauthenticated `/api/*`.
- **Dangling-DNS reconciliation**: diff the live DNS zone against the inventory of *intentionally operated* deployments; anything resolving without an owner is a finding by definition.

**Prevent**
- Put **all** acquisition assets behind the identity-aware proxy (BeyondCorp-style) **before** the DNS cutover, so an un-migrated box fails closed instead of open.
- Enforce **HTTPS-only at the edge** and deny plain HTTP — the failed `:443` here was a free early-warning signal that went unheeded.
- Treat **acquisition off-boarding** as a checklist item: decommission source-company infra and records on a deadline, not "eventually."

The single control that would have prevented the entire exposure is the identity-aware proxy: with it, an orphaned admin panel is unreachable regardless of how broken its own auth is.

## 8. Lessons I'm carrying forward

- **Prove impact; don't infer it from labels.** "Tier 1" describes a domain's *potential* sensitivity, not the severity of any given finding on it. The data actually at risk is what counts.
- **Distinguish hygiene from vulnerability — before writing.** Dangling DNS, sandbox exposure, and stale endpoints are frequently valid-but-credit-only. Setting that expectation up front keeps the report honest and the appeal disciplined.
- **Two-layer reasoning beats one-layer.** Checking whether the backend independently enforced auth — not just the login form — is what made this complete. Always ask what the next control down is doing.
- **Appeals need a new fact, not louder adjectives.** If I can't add concrete, new evidence, escalating the language only erodes credibility with triagers. Restating impact in stronger words is exactly why my appeal didn't (and shouldn't have) changed the outcome.
- **Edge-fronted is not operated-by.** Where a request routes tells you nothing about who owns the risk. That one distinction is the difference between a rewardable finding and a hygiene note.
- **Calibration is the skill.** Anyone can find something that looks alarming. The professional move is stating accurately how much it matters — including, and especially, when the honest answer is "less than it first appeared."

## Timeline

| Date | Day | Event |
|---|---|---|
| 2026-05-05 | 0 | Reported to Google VRP; automated acknowledgement |
| 2026-05-06 | +1 | **Accepted**; bug filed to the product team |
| 2026-05-15 | +10 | **Marked Fixed** — endpoint decommissioned, `NXDOMAIN`; I re-verified and confirmed |
| 2026-05-29 | +24 | Reward panel: **does not meet the bar** → credit / Honorable Mention |
| 2026-05-29 | +24 | I appealed for reconsideration |
| 2026-06-02 | +28 | Appeal reviewed and **upheld** — credit-only confirmed (stale-DNS rationale) |

---

*Reported through the Google Bug Hunters program (Issue 509594209). The affected endpoint was remediated and decommissioned (`NXDOMAIN`) by Google prior to publication. No data was accessed or modified beyond what was strictly necessary to confirm the exposure. This writeup reflects my own analysis and is not affiliated with or endorsed by Google.*
