# Open Google VRP reports — status review 2026-07-25

Analysed from live IssueTracker snapshots. **Net conclusion: no action on any of the
three. All are in a legitimate wait state; commenting again would violate FO-12.**

---

## 1. VirusTotal SSRF — #523823039 → **CLOSED: Won't fix (Intended behavior)** (final, 2026-07-28)

| Date | Event |
|---|---|
| Jun 14 | Submitted |
| Jun 18 | **Won't Fix (Intended Behavior)** — standard "our crawler fetching a URL is a feature" close |
| Jun 18 | Operator posted a clarification answering the triager's *exact stated standard* |
| **Jun 24** | **Status: New (reopened)** |
| Jun 30 | Generic notice: sitting in the Google Cloud VRP queue |

**The rebuttal worked, and it is a textbook FO-12 execution.** It did not re-argue with the
same evidence — it produced *new* facts against the triager's own test ("the server performs
actions the user couldn't perform on their own"):
- `169.254.169.254` is RFC-3927 link-local → timeout from a residential ISP (user cannot reach)
- `x-cloud-trace-context` on the inbound fetch → VT's scanner is a **native in-GCP service**
- Two HTTP 200s with **SHA256-verified IMDS body content** in VT's public corpus
- 6 of 7 IP encodings bypass the filter, while `metadata.google.internal` is explicitly 400'd
  → proves the access was *never intended*
- **Honest ceiling stated up front:** no `Metadata-Flavor: Google`, so `/v1/` paths return 403
  and **no credentials were extracted**

**Realistic outcome:** the reopen is the win; the reward ceiling stays low. Our own FO-11 gate
says SSRF that reaches IMDS but reads nothing sensitive is Low. P4/S4 is consistent with that.

### FINAL OUTCOME (confirmed from thread, close dated 2026-07-28 02:06)

| Date | Event |
|---|---|
| Jun 24 | Reopened after the clarification |
| Jun 30 | Google Cloud VRP queue |
| **Jul 28 02:06** | **Status: New → Won't fix (Intended behavior).** Closed by `as...@google.com`. No further comments. Final metadata: P4/S4. |

Cloud VRP's stated rationale:
> *"Our team has analyzed this report and decided not to track it as a security bug… the
> security risk described in this report does not meet the threshold that we require for this
> type of escalation on behalf of the security team."*

Note what is **not** contested: the link-local unreachability, the `x-cloud-trace-context`
in-GCP scanner identity, the SHA256-verified IMDS bodies, the 6-of-7 encoding bypasses. The
facts stood. **The impact did not clear the bar**, because nothing sensitive was ever read —
`Metadata-Flavor` is absent, so every credential path returned 403.

**Action: NONE. Do NOT appeal (FO-12).** The clarification already earned one reopen — that
was the single legitimate rebuttal and it was spent well. A second appeal on the same evidence
would cement the label and cost standing. Accept and move on.

### The lesson — we predicted this ourselves and submitted anyway

CLAUDE.md §3 Hard Rejection List, written *before* this submission:
> *"SSRF that only reaches attacker-owned infrastructure, or reaches IMDS/internal hosts but
> reads NOTHING sensitive (no creds/token/data — VT IMDS-root → Low ceiling)."*

The class was on our own reject list, by name, with this exact target as the example. The
report was submitted regardless, and the honest ceiling (403, no credentials) was stated
inside the report itself. **The failure was not triage; it was the decision to submit a
finding we had already classified as below the bar.**

That is precisely the discipline that held on 2026-07-25, when the Gemini and Looker hunts
both came back defended and neither was written up.

---

## 2. AppSheet systemic connector SSRF (F003) — **class is dead** (P4/S4, New)

| Date | Event |
|---|---|
| Jul 4 | An **AI triage assistant** posted a full WAI/disqualify analysis |
| Jul 6 | Google **retracted** it: "configuration error… AI-generated note does not represent a final decision… still being actively reviewed by our human security engineering team" |

The note was retracted *procedurally*, but its **substance cites two real prior bugs by ID**,
and those don't evaporate:

| Prior bug | Subject | Outcome |
|---|---|---|
| **377539803** | "Cloud Risk: IP and DNS Leakage via AppSheet's `ApigeeAuthInfo` request" | **Closed WAI, no reward** — this is our Surface 2 |
| **374568427** | "Exploiting SSRF Vulnerabilities for Virtual Host Discovery on AppSheet" | Closed — virtual-host discovery / TCP reachability without IMDS access ≠ vulnerability |

It also confirms AppSheet **strips `Metadata-Flavor: Google`**, which caps the IMDS path.

**This matches our own Hard Rejection List verbatim** (CLAUDE.md §3): *"Connector / webhook
fetching a user-supplied URL and forwarding user-supplied creds to it (intended connector
behavior — AppSheet SSRF → WAI)."* We had already written this class off; the duplicates
confirm it.

### Consequence — KILL Session C (F004 connector sweep)
`NEXT-SESSION.md` ranked "AppSheet connector SSRF F004 — $7K–$13K, 30 min/connector" as live
work. **It is not.** Testing REST/Salesforce/MySQL connectors would reproduce a behavior that
has now been closed WAI **three times** (two external + ours pending). Per CLAUDE.md §2:
*"After 2+ closes on a program, STOP and rebuild with a single clean, high-impact finding."*

**Action: NONE on the report. Do not submit F004. Do not test more connectors.**

---

## 3. Wiz `win-test.wiz.io` subdomain takeover — #524181553 (**P2**/S4, New)

| Date | Event |
|---|---|
| Jun 18 | Assigned to a triager |
| Jun 24 | Status: New |

P2 priority is a positive routing signal; S4 severity and 5 weeks at "New" are not.

**Known weakness (ours, honestly recorded):** claimability was **precondition-only** —
`DEPLOYMENT_NOT_FOUND` + dangling CNAME, **without** actually claiming the host and serving a
benign canary. CLAUDE.md §3 calls this out by name. Modern Vercel/Netlify block claiming a
domain still bound to another team, so the claim is *assumed*, not proven.

**Action: NONE. Do not comment.** The only thing that would strengthen this is *new* evidence
(an actual claim + served canary), and attempting that on a live third-party-bound host is not
something to do casually. Wait for the triager.

---

## Portfolio read

Three reports, three "wait" states, zero actions. That is the correct posture — and it means
**hunting time is fully free.**

The pattern across all three is the same lesson, now paid for three times: **infrastructure
reachability is not a finding.** SSRF that reaches IMDS but reads nothing; a connector that
fetches a URL by design; a dangling CNAME never actually claimed. Each stops one step short of
a crossed boundary.

The next finding must **land on the far side of the boundary**: another account's data in our
hands, or a state change we were never authorised to make. That is what the AI VRP work
(`results/_research/2026-07-25-restart-attack-vectors.md`) is designed to produce.

---

## AppSheet systemic SSRF — CLOSED, no reward. 2026-09-21

**Issues 525815004 / 525815219** — *"AppSheet: Systemic SSRF — 3 surfaces (OData, Apigee
OpenAPI Spec, Cloud Database)"*. Filed 2026-06-20.

**Final: `Status: Duplicate of 1469` · P4 · S4 · no reward, no credit.**

### Timeline

| Date | Event |
|---|---|
| Jun 20 | Filed |
| **Jul 04** | **AI VRP Agent** posts disqualification rationale: `WAI`, `DUPLICATE of 377539803`, severity **LOW**, *"recommend disqualifying"* |
| Jul 06 | Google retracts — *"a configuration error in our internal tooling… accidentally published… disregard… still open and actively reviewed by our human security engineering team"* |
| Aug 25 | Priority swept to **P2** — read at the time as a positive signal |
| **Sep 21** | Closed **Duplicate of 1469**. Final priority **P4**, severity **S4** |

**The accidentally-published AI note predicted the outcome exactly.** Human review took three
months and landed in the same place, citing a different duplicate ID.

### Google's reasoning, verbatim (worth keeping)

- *"AppSheet connectors are explicitly designed to integrate with external, user-supplied data
  sources. Initiating an outbound network request to a provided URL/hostname and transmitting
  the configured credentials … is the fundamental, intended purpose of these endpoints."*
- Template/credential chain → *"requires the victim to voluntarily install an untrusted template
  and manually input their own credentials. This is a social engineering/phishing vector…
  it falls under the customer's purview."* (Shared Responsibility)
- *"they explicitly confirmed that no GCP Metadata Service (IMDS) token could be extracted…
  This successfully mitigates the critical risk of IMDS exploitation and privilege escalation."*
- Port scanning / egress IP+DNS leakage → *"repeatedly evaluated by the Cloud VRP team and
  deemed to have insufficient security impact"*, citing **377539803** (Apigee IP/DNS leakage,
  WAI, no reward) and **374568427** (vhost discovery via AppSheet SSRF, closed for lack of impact).

### What this settles

1. **The original assessment was right.** This file recorded the AppSheet SSRF class as dead
   on the strength of 377539803 and 374568427. It was. Reversing that on a P2 label was the error.
2. **Systemic framing did not defeat WAI.** Three surfaces, four network clients and two
   documented prior point-fixes did not move a behaviour that is the product's stated purpose.
   `METHODOLOGY.md` FO-15 has been rewritten accordingly.
3. **SSRF at Google is Low unless IMDS data is actually extracted.** Cross-scheme redirects are
   blocked and `Metadata-Flavor: Google` is not injectable on these paths. Without extraction the
   class is permanently closed.
4. **Google VRP screens with an AI triage agent at L2** that cross-references historical VRP data
   for duplicates and WAI patterns. **Search prior VRP IDs for the behaviour, not the endpoint,
   before writing anything.**

### Portfolio effect

Another N/A-equivalent close. Running total on this programme remains heavily weighted to
*intended behaviour* / *informational* / *duplicate*. The corrective is unchanged and now has one
more data point behind it: **only submit a crossed boundary with data in hand.**

### The twin ticket — an accidental controlled experiment

The report was filed twice by Google's own intake. As of 2026-09-21:

| Issue | Comments | Status | Priority | Severity |
|---|---|---|---|---|
| **525815004** | 5 — ack, AI note, retraction, closure | **Duplicate of 1469** | **P4** | S4 |
| **525815219** | 1 — acknowledgement only | **New** (never worked) | **P2** | S4 |

**Identical content, two different priority labels.** The one that was actually analysed ended
at P4 with no reward; the one nobody read still carries P2.

This is the cleanest possible evidence for FO-13: **priority is queue metadata, not a verdict.**
The August reversal was driven by a P2 that had no assessment behind it whatsoever.

**Action on 525815219: none.** Do not comment, do not nudge. The content is identical to a report
already analysed and closed; Google's dedup will reach it. A ticket sitting at `New` for months
carries no signal in either direction.
