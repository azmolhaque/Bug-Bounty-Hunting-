---
description: Run the end-to-end agentic bug bounty hunting pipeline
argument-hint: "<target> [--phase 0-6] [--background]"
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task
---

# /workflow — Orchestrate the full hunt

You are the **orchestrator** of an autonomous, multi-agent bug bounty hunt
targeting `$ARGUMENTS`. Drive the pipeline end-to-end, delegating breadth to
subagents and reserving your own cognition for prioritization, chaining, and
verification.

## Hard preconditions (do these first, every time)

1. Read `CLAUDE.md` and `methodology/METHODOLOGY.md` if not already loaded.
2. Parse the target and flags from `$ARGUMENTS`. Determine the target root.
3. **Scope gate:** confirm the target is in `config/scope.yaml` and passes
   `./scripts/scope-check.sh <target>`. If not IN-SCOPE → STOP and report.
4. Create/resume the workspace: `results/<target>/`. If a `HUNT-LOG.md` exists,
   read it and **resume** from the last completed phase instead of restarting.

## Pipeline (run in order; honor `--phase` to start/stop at a phase)

### Phase 0 — Plan
Write `results/<target>/00-plan.md`: archetype classification + hunt thesis.

### Phase 1+2 — Recon & Surface Mapping  → delegate
Launch the **recon-agent** subagent (`Task` tool) to run asset discovery and
attack-surface mapping per the methodology. It writes `01-assets/` and
`02-surface/` and returns a ranked priority target list. On the Pi, prefer
`--background` for long scans and poll their output.

### Phase 3 — Vulnerability Discovery  → delegate (fan-out)
For each cluster of high-priority targets, launch **vuln-hunter** subagent(s) in
parallel (resource-capped for the Pi — see `config/tools.yaml`). Each runs
automated breadth (`nuclei`) + hypothesizes and tests the 2–3 most plausible bug
classes per endpoint. They append to `03-candidates/candidates.jsonl`.

### Phase 4 — Verify & Chain  → you (the orchestrator)
Do this yourself. Reproduce each candidate from a clean state, minimize PoCs,
prove impact safely, and look for **chains**. Write `04-verified/`.

### Phase 5 — Triage  → delegate
Launch the **triage-agent** to score (CVSS 3.1 + business), dedup against
known-issues and `results/` history, and rank. Writes `05-triage/triage.md`.

### Phase 6 — Report  → delegate
For each report-ready finding, launch the **report-writer** to produce a triager-
grade writeup from `templates/report.md` into `results/<target>/findings/`.

## Orchestration rules

- **Persist after every phase.** Update `results/<target>/HUNT-LOG.md` with what
  was done, what was found, and the next action. This survives context resets.
- **Re-plan between phases** (the intelligence loop): new assets → reopen recon;
  a confirmed bug pattern → test it everywhere; a leaked hostname → expand scope
  *only within authorized bounds*.
- **Stay polite & in scope.** Enforce rate caps. Re-run the scope check on any
  newly discovered host before touching it.
- **Be honest.** Label leads vs. verified findings. Surface anything ambiguous.

## Final output

End your turn with a status summary: phases completed, assets found, candidates
generated, findings verified, and the single most promising lead to pursue next.
Point the operator to the artifacts in `results/<target>/`.
