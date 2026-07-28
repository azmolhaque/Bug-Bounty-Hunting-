# Open Google VRP reports — status review 2026-07-25

Analysed from live IssueTracker snapshots. **Net conclusion: no action on any of the
three. All are in a legitimate wait state; commenting again would violate FO-12.**

---

## 1. VirusTotal SSRF — #523823039 → **CLOSED: Intended Behavior** (final, 2026-07-26)

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

### FINAL OUTCOME (update 2026-07-26)

| Date | Event |
|---|---|
| Jun 24 | Reopened after the clarification |
| Jun 30 | Google Cloud VRP queue |
| **Jul 26** | **Status: New → Intended Behavior.** Closed. |

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
