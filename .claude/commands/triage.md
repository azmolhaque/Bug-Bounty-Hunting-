---
description: Score, deduplicate, and prioritize verified findings (Phase 5)
argument-hint: "<target>"
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task
---

# /triage — Decide what to report and in what order

Target: `$ARGUMENTS`. Execute Phase 5 from `methodology/METHODOLOGY.md` over
`results/<target>/04-verified/`.

## Steps

1. **Load** all verified findings from `results/<target>/04-verified/`.

2. **Score severity.** For each: CVSS 3.1 base vector + business-context
   adjustment (what data/funds/control is at risk). Map to the program's reward
   tiers if known.

3. **Deduplicate** ruthlessly:
   - Against the program's published known-issues / out-of-scope-known list.
   - Against prior findings in `results/` history.
   - Against public CVEs/changelogs (already-known issue?).
   Mark each as `novel | possible-dup | known`.

4. **Prioritize.** Rank by impact × PoC-cleanliness × duplicate-risk (first valid
   report wins, so clean high-impact novel bugs go first).

5. **Write** `results/<target>/05-triage/triage.md`: a ranked table with
   `finding | severity | CVSS vector | dedup status | report-ready? | notes`.

6. **Update** `HUNT-LOG.md` and recommend the report order. For complex programs,
   delegate scoring/dedup of large finding sets to the **triage-agent** subagent.
