# Google VRP portfolio review — 2026-07-28

Source: `bughunters.google.com` My Reports (24 reports total, 18 visible on page 1).
Profile: **Leaderboard rank 2368 · 4 Awards · 0 public reports** · joined Aug 2025.
Reporting volume: **24 reports in ~10 weeks** (May 12 – Jun 20, 2026).

---

## Full status tally (18 visible)

| Status | Count | Reports |
|---|---|---|
| **closed** | **9** | VT SSRF · Fitbit CORS · AppSheet V2 API PII · Elastifile tenant hijack · Cameyo Nginx host-header · Fitbit corp NS takeover · dtranslator.photomath takeover · /about GCLB topology · IIS short-name + ASP.NET errors |
| **duplicate** | 2 | Cameyo host-header telemetry · pring.jp admin dashboard |
| **triaged** | 3 | Fitbit `*.corp.fitbit.com` takeover + OAuth · `pbvpn.looker.com` AWS EIP takeover · photomath.net systemic tenant hijack |
| **accepted** | 1 | `support.pring.jp` takeover |
| **submitted** (pending) | 3 | AppSheet systemic SSRF (×2 listings) · Wiz `win-test.wiz.io` takeover |

Plus, outside this list: `rip.photomath.net` exposed IAM (#509594209) — **Fixed P2/S2, credit-only**.

**Positive outcomes: 4** (3 triaged + 1 accepted) — which matches the **4 Awards** on the profile.
**Negative outcomes: 11** (9 closed + 2 duplicate).
**Reward-paying outcomes: 0 observed.**

---

## The finding: this is a *class-selection* problem, not an execution problem

Group the 18 by bug class:

| Class | Count | Share | Outcomes |
|---|---|---|---|
| **Subdomain takeover / dangling DNS / tenant hijack** | **8** | **44%** | 3 triaged, 1 accepted, 4 closed |
| SSRF (connector / crawler) | 3 | 17% | all closed or pending-toward-WAI |
| Host-header / perimeter bypass | 2 | 11% | 1 closed, 1 duplicate |
| Info disclosure (`/about`, IIS 8.3, verbose errors) | 2 | 11% | both closed |
| CORS reflection | 1 | 6% | closed |
| Auth/PII exposure | 1 | 6% | closed |
| Admin-panel exposure | 1 | 6% | duplicate |

**Nearly half the portfolio is one class — subdomain takeover — and the whole
infrastructure/hygiene family (takeover + host-header + info-disclosure + CORS) is 13 of 18,
i.e. 72%.**

That family is precisely what CLAUDE.md §3 Hard Rejection List already rules out by name:
- *"Subdomain takeover on a host with no user traffic, no shared cookies, no OAuth redirect use"*
- *"Subdomain takeover claimed on PRECONDITION only … without actually claiming the host and serving a benign canary"*
- *"Diagnostic / health / `/about` endpoints leaking hostname / uptime / clock (informational — Cameyo `/about` → Won't-Fix)"*
- *"CORS permissive on endpoints returning no sensitive data"*
- *"Software version disclosure / stack traces with no exploitable data"*
- *"SSRF that … reaches IMDS/internal hosts but reads NOTHING sensitive"*

Every single closed report maps to a line already written on our own reject list.

### What the 4 positives have in common
The 3 triaged + 1 accepted are all **takeovers on Tier-1 corporate or acquisition scope**
(`*.corp.fitbit.com`, `pbvpn.looker.com`, systemic `photomath.net`, `support.pring.jp`) —
i.e. the subset where the *asset itself* carried obvious organisational weight. Even those
produced **awards, not rewards**.

---

## Honest read

The execution is strong. The recon is genuinely good — finding 8 dangling-DNS/tenant-hijack
candidates across Fitbit, Looker, Photomath, pring, Elastifile and Wiz in ten weeks is real
skill, and the VT clarification that earned a **reopen from a closed state** is a rare thing
to pull off.

The problem is upstream of all that: **the class being hunted mostly cannot pay.**
Infrastructure reachability — a dangling CNAME, an open `/about`, a reflected CORS origin, a
crawler that fetches a URL — is *discovery*, not *impact*. Google's bar is a crossed boundary,
and 72% of these reports stop one step before it.

Volume made it worse, not better. 24 reports in 10 weeks with 11 negative outcomes is a
signal-damaging ratio; CLAUDE.md §2 says stop and rebuild after **two** closes on a program.

---

## What changes from here

1. **Stop submitting the hygiene family.** Takeover, host-header, `/about`, CORS, version
   disclosure, IMDS-reachable-but-nothing-read. Not "submit fewer" — *stop*, unless the chain
   step is already proven.
2. **A takeover is only submittable with the claim actually executed** — host claimed, benign
   canary served — **and** a proven shared-cookie / OAuth-allowlist consumer. Otherwise it is a
   precondition (this is exactly why Wiz `win-test` is the weakest of the three pending).
3. **Ship far fewer, far better.** One report per month that crosses a boundary beats eight
   that don't. The 11 negatives cost more in triager trust than the 4 awards returned.
4. **Hunt classes that can only succeed by crossing:** cross-tenant IDOR, auth bypass,
   privilege escalation, another user's data in hand. Those have no "informative middle state"
   to mistake for success.

The 2026-07-25 session is the model: two hunts (Gemini AI-VRP, Looker H1), both taken to a
definitive answer, both defended, **both correctly not submitted.** Under the old pattern both
would have been written up and both would now be closing. That restraint is the single highest-
value behaviour change available.
