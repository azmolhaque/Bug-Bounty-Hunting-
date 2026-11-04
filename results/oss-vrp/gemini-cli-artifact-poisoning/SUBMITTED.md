# SUBMITTED — Google OSS VRP

- **Report ID:** 581568993
- **Title:** Fork pull request achieves code execution in a privileged workflow_run job
  in google-gemini/gemini-cli (artifact-poisoning) exposing GEMINI_API_KEY
- **Submitted:** 2026-11-04 (UTC)
- **Program:** Google Bug Hunters — OSS VRP
- **Target:** google-gemini/gemini-cli (.github/workflows/chained_e2e.yml + trigger_e2e.yml)
- **Vulnerability type:** Remote Code Execution (RCE)
- **Disclosure:** private; notifying Google only
- **Tracker:** https://issuetracker.google.com/issues/581568993 (or bughunters dashboard)

## Claimed (demonstrated)
- ACE in privileged workflow_run job via fork PR (pinned actions/checkout@v4.3.0)
- GEMINI_API_KEY reachable to attacker code (PoC-SECRET-REACHABLE, len=18, sha256_prefix=5526dde5807f)

## Flagged, NOT claimed
- Build-cache poisoning serve (Legit Build did not restore poisoned layer)
- Self-hosted-runner persistence (ephemerality untested)

## Evidence attached
- 01-chained3-checkout-v5-REFUSED-fork-pr.png
- 02-chained5-checkout-v4.3.0-SUCCESS-PoC-SECRET-REACHABLE.png
- 03-lab-chained-yml-pin-v4.3.0.png

## Next
- Await triage. Do NOT re-argue if closed; respond to triager questions with evidence in hand.
- Cleanup: delete lab repos (azmolhaque/ap-victim, zahin24/ap-victim) + revoke throwaway PATs.

---

## OUTCOME — Closed as DUPLICATE (2026-11-04 02:12 UTC)

Google Security Bot: closed as a duplicate "of an existing bug that we've already
received." No reward (duplicates don't qualify). Marked against a shared canonical bug.

### Reading this correctly
- **The bug was VALID.** Duplicate (not WAI / Not-Applicable / Spam) means Google
  confirmed the issue is real and already tracked internally — our analysis, repro,
  and verification were all correct. We were just not first.
- **No reputation damage.** Per CLAUDE.md §2, the reputation-lowering closes are
  N/A / WAI / Spam. Duplicate is neutral — a well-formed, correct, in-scope report.
- **Dedup was done; the dup was unknowable.** We found NO public report (verified).
  A prior private/internal report is impossible to see from outside — exactly the
  residual risk flagged in VERDICT.md.

### Action
- Do NOT re-argue (CLAUDE.md FO-12). Duplicate is final. An optional one-line thanks
  is fine; no dispute, no demand for credit.
- Lesson: google-gemini/gemini-cli is extremely high-profile and heavily scanned ->
  high duplicate risk. For reward, prefer less-trafficked targets or novel variants,
  and move fast on fresh config changes.
- Reusable assets kept: detector approach, faithful lab harness, methodology.
