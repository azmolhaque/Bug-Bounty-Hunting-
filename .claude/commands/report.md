---
description: Generate triager-grade vulnerability reports (Phase 6)
argument-hint: "<target> [finding-name | --all]"
allowed-tools: Read, Write, Edit, Glob, Grep, Task
---

# /report — Communicate impact so it gets rewarded fast

Target: `$ARGUMENTS`. Execute Phase 6 from `methodology/METHODOLOGY.md`.

## Steps

1. **Select findings.** Read `results/<target>/05-triage/triage.md`. Report the
   named finding, or all report-ready ones with `--all`, highest severity first.

2. **For each finding**, generate a report from `templates/report.md` containing:
   - **Title** — bug class + impact + location, one line.
   - **Summary** — what/where/why-it-matters in 2–3 sentences.
   - **Severity** — CVSS 3.1 vector + business impact.
   - **Steps to reproduce** — numbered, copy-pasteable, from a clean state.
   - **Proof** — minimal request/response or screenshots, **sanitized** (no real
     secrets, tokens, cookies, or PII).
   - **Impact** — concrete attacker capability, affected users/data.
   - **Remediation** — specific fix tied to root cause.
   - **References** — CWE, OWASP, relevant docs.

3. **Write** to `results/<target>/findings/<finding>.md`. Keep evidence sanitized;
   never commit secrets to git.

4. **Quality check.** Re-read as a busy triager: can they reproduce it in under
   five minutes from the steps alone? If not, tighten the repro steps.

For batches, delegate per-finding drafting to **report-writer** subagents, then
you do the final quality pass. End with the list of generated reports and a
recommended submission order.
