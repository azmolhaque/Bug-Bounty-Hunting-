# Hunt Research — 2026-07-25 restart: where the value moved

**Context:** ~6-week gap since the last active hunt. Two things changed the board.
Programs: Google VRP + Google **AI VRP** (new surface). Rig unchanged: Android/Termux,
browser + curl, two free Google accounts (A=gorib, B=gorib2). No desktop Burp.

---

## 1. What changed while we were away

### (a) Looker Studio got carpet-bombed — H1 EV dropped
Tenable published **"LeakyLooker"** (March 2026): 9 cross-tenant vulns in Looker Studio,
including **TRA-2025-29 "Sticky Credential"** — the *Copy Report retains owner credentials*
logic error. **Google has since fully remediated all nine.**

Our `H1-PROCEDURE.md` targets precisely that flow. Consequences:
- The core primitive (copy retains A's creds) is **the patched bug**, not a new one.
- The surrounding code has just been hardened + reviewed by Google's team.
- Anything we find here risks **duplicate / already-fixed**.

**Revised call:** H1 is no longer the headline. Keep it as a **45-min timeboxed** check of
the one variant Tenable did *not* publish — the **repoint-after-copy** step (Phase 3).
If Phase 2 shows creds reset on copy → drop immediately, do not narrativize (FO-9/FO-11).

### (b) Google launched an **AI VRP** — new, under-picked, and it fits our rig exactly
Rewards up to **$20K (S1 rogue actions)** / **$15K (S2 sensitive data exfiltration)**,
**up to $30K** with novelty bonus. In-scope: **Gemini Apps + Workspace core (Gmail, Drive,
Docs, Sheets, Calendar), Google Search.**

Two facts that matter more than the dollar figures:
1. **Prompt injection alone is explicitly OUT of scope.** Only injection that **chains to a
   real state change or data exfiltration** counts. This is FO-9 (boundary-cross proof)
   written into the program rules — exactly the discipline we already run.
2. Google publicly said it is **re-weighting VRP toward flaw classes that are hard for AI
   tools to find** — i.e. multi-account logic and agent-permission bugs, not scanner output.
   That is the opposite end of the spectrum from the dangling-DNS/hygiene class that got us
   credit-only on Photomath (FO-13).

Prior art defining the shape: SafeBreach **"Invitation Is All You Need"** — indirect prompt
injection embedded in a **Google Calendar invite description**, triggered when the victim
later asks Gemini "what's my schedule?", achieving 15 exploits (exfil, calendar deletion,
device control). **That specific vector is patched.** The *class* is wide open.

---

## 2. The attack model we can actually test

Every valid S1/S2 finding has the same three-part shape. A finding needs **all three**:

```
[1] DELIVERY: attacker-controlled text reaches a resource the victim's Gemini will read
        ↓
[2] TRIGGER: victim performs an ordinary Gemini action ("summarize", "what's my schedule")
        ↓
[3] SINK: Gemini performs a state change (S1) or leaks data off-account (S2)
```

Missing [3] = out-of-scope prompt injection. **That is the drop condition.** Injection that
only makes Gemini say something silly is not a finding — do not submit it.

### Delivery vectors (the under-tested ones — calendar description is burned)
| # | Vector | Why it may be missed |
|---|--------|----------------------|
| D1 | Calendar **title / location / attachment filename** (not description) | Sanitizer likely targeted the description field specifically |
| D2 | **Doc comments & suggested edits** | Comments are a separate content path from body text |
| D3 | **Sheet cell content**, incl. formula-produced strings (`=CONCAT(...)`) | Text generated at render time may bypass a static content scan |
| D4 | **Drive file/folder names** | Filenames are metadata, often not run through content classifiers |
| D5 | **Form responses** landing in victim's response sheet | Attacker needs no account and no share — fully unauthenticated delivery |
| D6 | Contact fields (name/notes) in Google Contacts | Rarely modelled as attacker-controlled |
| D7 | Email in a **thread the victim asks Gemini to summarize** | Classic; heavily defended — test last |

**D5 is the most interesting**: a public Google Form gives an *unauthenticated* attacker a
write primitive into the victim's Workspace data. Lowest attack prerequisite = highest
severity multiplier (Phase 4: "can attack work with 0–1 clicks?").

### Sinks — this is what makes it a finding
| # | Sink | Class | Why it's strong |
|---|------|-------|-----------------|
| **S-1** | Gemini **changes sharing permissions** on a victim's private Drive file (adds attacker) | **S1 rogue action** | Cleanest possible proof: A's Drive suddenly lists B's private doc. Binary, screenshotable, no ambiguity |
| **S-2** | Gemini renders/auto-fetches an **attacker URL with victim data in the query string** | **S2 exfil** | The classic AI exfil primitive; proof = our own server log |
| **S-3** | Gemini **sends or drafts mail** as the victim | S1 | State change + phishing enablement |
| **S-4** | Gemini **creates a Gmail filter / forwarding rule** | S1 | Persistence — high severity |
| **S-5** | Gemini **deletes** calendar events / files | S1 | Integrity; destructive — test on our own throwaway data ONLY |

---

## 3. Ranked plan

| Rank | Test | Prereq | EV | Effort |
|---|---|---|---|---|
| **1** | **D5 → S-1**: public Form response injection → Gemini shares victim's private Drive file with attacker | 2 accounts (have) | **$20K–$30K** | 2 hr |
| **2** | **D5/D3 → S-2**: same delivery, exfil via auto-fetched URL to our listener | + OOB listener | $15K | 1 hr |
| **3** | **D2 → S-1/S-2**: Doc comment injection, victim summarizes doc | 2 accounts | $15K–$20K | 1 hr |
| 4 | **D1**: calendar title/location variant of the patched SafeBreach vector | 2 accounts | $15K–$20K | 45 min |
| 5 | Looker Studio H1 Phase 0–3, **timeboxed 45 min**, drop fast | 2 accounts | Reduced (dup risk) | 45 min |
| 6 | AppSheet connector SSRF F004 | none | $7K–$13K | 30 min/connector |

---

## 4. Validity discipline (non-negotiable, per CLAUDE.md + bb-methodology)

- **Both accounts are ours.** A = attacker, B = victim. **No third-party data, ever.**
- **Phase 0 validity gate (FO-3)** before every test: prove the boundary exists first
  (e.g. screenshot A being unable to open B's private doc) — otherwise a later "A got it"
  proves nothing.
- **Unique markers (Marker Discipline):** canary strings ≥8 chars, random, no English words
  (`zk7q2m4x`), never `test`/`secret`/`payload`. Grep the baseline response for the marker
  before claiming a hit.
- **Destructive sinks (S-5) only on our own throwaway data.** Never on anything shared.
- **Drop condition:** injection fires but no state change and no off-account data movement
  → **out of scope by program rules. Do not submit.** (FO-11)
- Record honest negatives — a proven "defended here" is coverage, not failure (FO-7).

---

## 5. Open items to confirm with the operator

- Status of **VT F001 #523823039**, **Wiz F001 #524181553** (was P2/TRIAGING),
  **AppSheet F003** — 6 weeks elapsed, triage has likely moved.
- Marriott **M002 #3817499** / **M018 #3816825** — evidence supplement + appeal were
  drafted and ready to post; were they posted?

## Sources
- Tenable LeakyLooker — https://www.tenable.com/blog/leakylooker-google-cloud-looker-studio-vulnerabilities
- SafeBreach, Invitation Is All You Need — https://www.safebreach.com/blog/invitation-is-all-you-need-hacking-gemini/
- Google AI VRP launch — https://www.bleepingcomputer.com/news/google/googles-new-ai-bug-bounty-program-pays-up-to-30-000-for-flaws/
- Google VRP re-weighting — https://www.securityweek.com/google-adjusts-bug-bounties-chrome-payouts-drop-as-android-rewards-rise-amid-ai-surge/
