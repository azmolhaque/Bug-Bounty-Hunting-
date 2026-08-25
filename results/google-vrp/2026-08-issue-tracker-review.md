# Issue-tracker review — 6 open reports, 2026-08

Analysed from live IssueTracker threads. **Net result: exactly ONE legitimate action across
all six.**

| # | Report | ID | Status | Last activity | Class |
|---|---|---|---|---|---|
| 1 | **Looker XFF IP-allowlist bypass** | 509911655 | **P2/S4 · New** | **May 11** — *~3 months silent* | **Security control bypass** |
| 2 | `support.pring.jp` takeover | 513801445 | **P3/S3 · In Progress (Accepted)** | Jun 16 | Takeover — **decided: credit-only** |
| 3 | `pbvpn.looker.com` takeover | 514079192 | P2/S4 · New | **Jul 31** | Takeover — unclaimed |
| 4 | `win-test.wiz.io` takeover | 524181553 | P2/S4 · New | Jun 24 | Takeover — unclaimed |
| 5–6 | AppSheet systemic SSRF (2 listings) | — | P4/S4 · New | Jun 20 / Jul 6 | SSRF — class dead |

---

## 1. Looker XFF bypass (509911655) — **the only actionable one, and the best report in the portfolio**

Submitted May 5. Cloud VRP queue notice May 6. Operator posted a substantial manual-validation
supplement **May 11**. **No triager response since.** ~3 months of silence at **P2**.

### Why this one is different from everything else
It is **not** the infrastructure-hygiene class. It is a **security control bypass with a proper
differential**, and it satisfies the Body-Diff Rule that most of the portfolio fails:

| Element | Evidence |
|---|---|
| **Baseline (blocked)** | No custom headers → **302 redirect** to the `no-ip-whitelist` page — the firewall is demonstrably active and blocking |
| **Bypass (allowed)** | `X-Forwarded-For: 127.0.0.1` → **200 OK**, login portal served |
| **Real content, not just a status code** | Valid session state issued (`rack.session`, `CSRF-TOKEN`, `XSRF-TOKEN`); `/api/4.0/swagger.json` → **200 + 1021 KB** of live API schema |
| **Impact** | A perimeter control enterprises *rely on* to keep tenants unreachable is nullified: login portal exposed to credential stuffing, API blueprint extractable unauthenticated |

This clears the bar the other reports miss: the control is supposed to block, and it doesn't —
proven with a before/after differential and returned content, not a theory.

### Action: **ONE short status ping. Not an appeal.**
Google's own acceptance template says *"If you don't hear back from us in 2-3 weeks… let us
know."* Three months qualifies. The ping must add **no new argument** — purely a status
request. Re-arguing would convert a legitimate nudge into an FO-12 violation.

### ⚠️ One thing to verify before pinging
The report says *"Locate a Looker tenant with an active IP Allowlist (e.g.
`09a2ceda-8736-4308-941f-1fa63a87f960.cloud.looker.com`)"*. **Confirm that tenant is our own
trial instance.** If it belongs to a third-party customer, we tested someone else's data
environment — that is a scope problem, and the correct action becomes disclosing that, not
chasing a reward. Do not send the ping until this is confirmed.

---

## 2. `support.pring.jp` (513801445) — **decided. No action.**

Full arc: **Won't Fix (Intended Behavior)** May 16 → operator's rebuttal (correctly arguing the
flaw is the *first-party dangling CNAME in Google's own DNS zone*, not Zendesk) → **reopened**
May 19 → **Accepted** May 29, bug filed to product team → **Jun 16 panel: credit-only, no
financial reward.**

Panel rationale: *"subdomain takeover… caused by a stale CNAME record. We determined that this
finding qualifies for credit in our program."*

This is closed business. **Do not comment.** Note it as the **third successful reopen**
(VT, `/about`, pring) — the rebuttal skill is real and repeatedly effective.

---

## 3. `pbvpn.looker.com` (514079192) — no action

Touched **Jul 31** (status set to New), so a triager is active on it. Nothing has gone stale.

**The outcome is already predictable from our own comment on the thread:**
> *"I have not claimed this IP, as I strictly adhere to the VRP Safe Harbor guidelines. My
> intent is purely to highlight a perimeter risk that **could lead to** subdomain takeover."*

That is an on-record statement that this is a **precondition, not a demonstrated takeover** —
exactly the Hard Rejection List item. Expect credit-only or close, on the same rationale pring
received. **Do not comment.**

## 4. `win-test.wiz.io` (524181553) — no action

Same class, same weakness (claimability never proven by claiming + serving a canary). Wait.

## 5–6. AppSheet SSRF — no action

P4/S4. Class already closed WAI twice externally (bugs 377539803, 374568427). Waiting on the
human review that replaced the retracted AI note. Do not comment, do not extend to F004.

---

## Summary of actions

| Report | Action |
|---|---|
| **Looker XFF 509911655** | ✅ **Verify tenant ownership, then send ONE status ping (no new argument)** |
| pring 513801445 | ❌ None — decided credit-only |
| pbvpn 514079192 | ❌ None — active triager, precondition-only |
| win-test 524181553 | ❌ None — wait |
| AppSheet ×2 | ❌ None — class dead |

**One action out of six.** That ratio is the point: most of the queue is in a state where any
comment costs signal and gains nothing.
