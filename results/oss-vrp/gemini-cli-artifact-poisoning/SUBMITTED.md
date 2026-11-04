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
