# Adobe — programme analysis, 2026-08-26

Source: HackerOne programme pages (bounty policy, scope, hacktivity, updates, safe harbour),
captured by the operator 2026-08-26. **No requests have been made to any Adobe asset.**

---

## Vitals

| Metric | Value |
|---|---|
| Bounty launched | March 2015 (11 years) |
| Reports resolved | **8,906** |
| Hackers thanked | **2,132** |
| **Resolved per hacker** | **≈ 4.18** — vs Exoscale's 0.16, and our rubric threshold of 0.6 |
| Total paid | **> $2,630,000** |
| Paid, last 90 days | $310,000 – $315,000 |
| **Reports received, last 90 days** | **1,078 ≈ 12/day** |
| Assets in scope | 68 |
| Response efficiency | 83–84% |
| Avg time to first response | 5 days 16 h · triage 4 weeks · bounty ~1 month |
| Average bounty range | $560 – $810 |

**Read this honestly.** The 4.18 ratio clears our bar comfortably — Adobe pays, and pays a lot of
people. But 12 reports a day is a crowded program, and **duplicate risk is the dominant threat
here**, not difficulty. Their own rules are explicit: if the underlying vulnerability *or* the
resulting impact chain was already reported, ours is a duplicate.

That single fact should drive every targeting decision below.

---

## THE ECONOMIC FACT THAT DECIDES OUR TARGET

| Tier | Low | Medium | High | Critical |
|---|---|---|---|---|
| Tier 1 | $100–200 | $200–1,000 | $1,000–5,000 | $5,000–10,000 |
| Tier 2 | $100 | $100–500 | $500–2,500 | $2,500–5,000 |
| **Tier 3 — AI Bonus** | **$150–300** | **$300–1,500** | **$1,500–7,500** | **$7,500–15,000** |

> **A *High* in Tier 3 ($1,500–7,500) pays more than a *Critical* in Tier 2 ($2,500–5,000).**

Tier 3 pays 1.5–3× the others at every severity. And Tier 3 assets are the **newest code in the
estate** — which is also where duplicate risk is lowest. Highest pay and lowest saturation are,
unusually, the same place.

---

## Timing

- **20 Aug → 31 Aug:** HackerOne accepts **Critical severity only**. ATO reports must show
  cross-tenant/cross-organisation impact; single-tenant ATO is not reviewed.
- **1 Sep 2026:** programme moves to **Intigriti**. Full severity range resumes there.

**Consequence:** a Tier 3 High — our most likely outcome — cannot be submitted before 1 September.
Use the intervening days for setup, surface mapping and rig building. Hunt from 1 September.

---

## Tier 3 (AI) assets — the target list

| Asset | Host | Why it matters |
|---|---|---|
| **Acrobat PDF Spaces** | acrobat.adobe.com | RAG hub ingesting **user files AND links**. Best delivery surface in the programme |
| Acrobat AI Assistant | acrobat.adobe.com | Document-grounded chat |
| Acrobat Create Presentations | acrobat.adobe.com | Doc → generated artifact pipeline |
| Acrobat Create Podcast | acrobat.adobe.com | Doc → audio pipeline |
| Express AI Assistant | new.express.adobe.com | Creation/editing by prompt |
| Firefly Image / Video / **Custom Models** | firefly.adobe.com | Custom models = training data as an input surface |
| Lightroom AI Edits · Edit suggestions (tech preview) | lightroom.adobe.com | "Tech preview" = newest |
| Photoshop AI Assistant | photoshop.adobe.com | |
| Stock AI Studio | stock.adobe.com | |
| Behance AI Freelance Job creation | net.s2stagehance.com | |

## What Adobe explicitly asks for (their wording)

- **XPIA** — *"embeds adversarial instructions within third-party content that the AI system
  retrieves and processes."* Their own example: **a logo with manipulated EXIF/IPTC metadata.**
- **Agentic** — unauthorised API calls, tool chaining, parameter injection, authN/authZ. Their
  example: *"an agent with file read, file write and web request tools manipulated to read
  sensitive files, encode them, and POST to external servers."*
- **MCP** — including **cross-tenant access**.
- **Desired impact:** data exfiltration, privilege escalation, credential theft, unauthorised
  actions through tool use, content manipulation.

## What is auto-closed — the traps

- **Prompt influence without backend impact.** Must bypass backend authorization, access
  restricted data, or alter enforced behaviour.
- Role confusion / role-play without disclosure of system prompts, policies, secrets.
- Model deviation, hallucination, or safety divergence with no control bypass.
- LLM reasoning/interpretation limitations with no demonstrated exploitability.
- **Firefly: ACL control in backend APIs is out of scope.** Firefly IDORs on UUID4 job IDs are
  out of scope (random, 72 h TTL).
- Photoshop: AI usage-limit issues on the free tier.

> This is the **same bar as Google AI VRP**: prompt injection on its own earns nothing; the
> report must show a crossed boundary. Our `AI-VRP-1-PROCEDURE.md` was written against exactly
> that bar and transfers directly.

---

## Non-AI assets worth knowing

**Tier 1:** Adobe Commerce / Magento · CAI Content Credentials & c2patool · Acrobat Web
(`*.acrobat.adobe.com`) · Adobe Stock · Firefly · ColdFusion · Lightroom Web · mobile apps.

**Tier 2:** Learning Manager (stage) · ColdFusion Admin · Photoshop Web · **Behance**
(`net.s2stagehance.com`) · **Adobe Express** (`new.express.adobe.com`) · Portfolio ·
Fonts · **Adobe IMS** (`ims-na1.adobelogin.com`, `account.adobe.com`, `auth.services.adobe.com`,
`federatedid-na1.services.adobe.com`) · Commerce web properties.

**Temporarily out of scope — do not spend time here:** IMS **OAuth** · Learning Manager custom
roles, social learning and OAuth · ColdFusion **XXE** · `express.adobe.com` and
`express-embed.adobe.com` (only `new.express.adobe.com` is in scope) · `www.behance.net`
production · `*.adobesign.com`.

## Their CVSS ceilings — set expectations before writing

- **IDOR / incorrect authorization (CWE-863):** C:H (PII, source, credentials) → **7.5 High**.
  I:H (privilege escalation, changing security config) → **7.5 High**. It does not reach Critical
  on its own in their scheme.
- **SSRF:** no sensitive endpoint 5.8 · sensitive internal endpoint reached **8.6**.
- **XSS:** 6.1 plain · **9.3** with demonstrated token exfiltration to an attacker server.
- **IDOR with unpredictable UUIDs is scored AC:H** — lower severity by design.

---

## Rules of engagement (binding)

1. **Register Adobe accounts with the platform e-mail alias.** HackerOne requires
   `<user>@wearehackerone.com`; the Intigriti programme will require its own — **confirm on
   1 Sep before creating anything that must be eligible.**
2. **Testing IP address must be provided** to receive a bounty and to fall under Safe Harbour.
3. **Only interact with accounts you own.** Never test another merchant's store or another
   customer's environment.
4. No social engineering. No DoS — *"any DoS testing will likely result in an auto-IP block."*
5. Do not view unauthorised data or corrupt data. **On encountering PII: stop, purge, contact Adobe.**
6. One vulnerability per report unless chaining is needed for impact.
7. **Ineligible residents:** Venezuela, Mainland China, Hong Kong, Russia, Belarus, Ukraine, Cuba,
   Iran, North Korea, Crimea, Sudan, Syria. **Bangladesh is not listed — we are eligible.**

## Duplicate rules — read twice

- First reporter only. Later reports of the same vulnerability *or* the same impact chain are
  duplicates, **even on a different endpoint or flow**.
- **ATO specifically:** the first confirmed ATO technique takes the full bounty; later reports
  using the same or a similar technique are reduced *regardless of endpoint, flow or user type*.
- Multiple bugs from one underlying issue = one bounty. A pattern of weakness pays only the
  first two reports.
