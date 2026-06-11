---
description: Run the end-to-end agentic bug bounty hunting pipeline
argument-hint: "<target> [--phase 0-6] [--background] [--dry-run] [--force] [--status]"
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task
---

# /workflow — End-to-End Intelligent Hunt Pipeline

You are the **master orchestrator** of an autonomous, multi-agent bug bounty
hunt targeting `$ARGUMENTS`. Drive the pipeline end-to-end.

## Hard Preconditions (every time, no exceptions)

1. Read `CLAUDE.md` (operating constitution) and `methodology/METHODOLOGY.md`.
2. Run `./scripts/scope-check.sh <target>` — if not IN-SCOPE, STOP.
3. Load or create workspace: `results/<target>/`. If `HUNT-LOG.md` and
   `.orchestrator-state.json` exist, **resume** from last completed phase.
4. Check Pi resources: `./scripts/pi-resource-guard.sh --report`.

## Deployment Command (what to run on the Pi)

```bash
./run.sh <target>                     # full pipeline, resume-aware
./run.sh <target> --phase 3           # Phase 3 only
./run.sh <target> --phase 3-4         # Phases 3-4
./run.sh <target> --background        # Phase 1+2 recon in background
./run.sh <target> --status            # status dashboard
```

## The 7-Phase State Machine

### Phase 0 — Scope & Plan
- Scope gate; create `00-plan.md` with hunt thesis and attack chain hypotheses.
- State: `phase_status.0 = DONE`

### Phase 1+2 — Recon & Surface Mapping → `recon-agent`
Delegate to **recon-agent** subagent (or `./scripts/recon.sh` directly on Pi).
Output: `01-assets/`, `02-surface/`, `02-surface/priority.md` (ranked target list).

After completion, run the **intelligence re-plan**:
- Update hunt thesis in `00-plan.md` with discovered assets
- Identify: dev/staging/RDE hosts, GraphQL/webhook endpoints, dangling CNAMEs
- These reshape Phase 3 priorities

### Phase 3 — Vulnerability Discovery → `vuln-hunter` fan-out

**Fan out ≤ 3 parallel** `vuln-hunter` subagents (Pi resource cap).
Each runs `nuclei` (curated templates) + manual depth on 2-3 most plausible
bug classes per endpoint. Appends to `03-candidates/candidates.jsonl`.

**Lead Qualification Gate (automatic, <60s per candidate):**
Every candidate goes through the 5-question gate before Phase 4 work:
```bash
./scripts/lead-qualify.sh <class> <confidence> <impact> <evidence>
```
- Score ≥ 4 → PURSUE:HIGH
- Score 3   → PURSUE:MARGINAL (verify fast)
- Score < 3 → AUTO_CLOSE (logged, no further work)

Or delegate to **lead-qualifier** subagent for batches.

### Phase 4 — Verification, PoC & Chain Elevation  ← you (orchestrator)

For each PURSUE candidate:

1. **Dead-end check**: if probe count ≥ 3 with no confirmation → AUTO_CLOSE.
2. **Reproduce from clean state** (fresh session/account/IP) — twice.
3. **Minimize PoC** to smallest reproducing request.
4. **Prove impact safely** (read-only, your account, OOB DNS only).
5. **Chain elevation** for every confirmed finding:
   ```bash
   ./scripts/chain-graph.sh add <target> <id> <class> <base-severity>
   # Automatically queues all known chain tests as PENDING
   ```
   Then delegate to **chain-analyst** subagent to work through PENDING tests.
6. Write confirmed bugs to `04-verified/<id>/` with verification.txt + chain-queue.txt.

### Phase 5 — Triage → `triage-agent`

Delegate to **triage-agent** to:
- Score CVSS 3.1 vectors + business context
- Dedup against program known-issues and `results/` history
- Check all pre-submission gate boxes (CLAUDE.md §2)
- Rank: impact × PoC-cleanliness × low-duplicate-risk

Writes `05-triage/triage.md`.

### Phase 6 — Reporting → `report-writer`

For each report-ready finding, delegate to **report-writer** to produce a
triager-grade writeup from `templates/report.md` into `findings/`.

**Submit immediately** when report passes all gates — first valid report wins.
Target: bughunters.google.com → search "wiz.io" → TIER1.

## Intelligence Loop (after every phase)

```
discover → qualify → verify → chain → submit
    ↑                                    |
    └──── re-plan from new signals ──────┘
```

After each phase, re-plan:
- New asset found → expand recon (scope-check first)
- Confirmed SSRF → immediately probe IMDS + internal services (Chain 3)
- Confirmed IDOR pattern → test ALL object types (connector, issue, project)
- Confirmed subdomain takeover → test CSP + OAuth redirect chain immediately

## Pi Resource Management

- Always call `./scripts/pi-resource-guard.sh --wait` before launching agents
- Cap parallel agents at 3 (`config/tools.yaml: max_parallel_subagents: 3`)
- Run Phase 1+2 with `--background` on Pi; poll `results/<target>/recon.log`
- If temperature > 78°C, pause 120s before next launch

## Orchestration Rules

- **Persist after every phase.** Update `HUNT-LOG.md` + `.orchestrator-state.json`.
- **Label honestly.** Leads vs. verified. Dead-ends vs. auto-closed. Chains pending.
- **Speed > polish.** If a finding passes all gates, submit today. Do not wait.
- **Never guess scope.** Run scope-check.sh on every new hostname before touching it.

## Final Output

Status summary: phases done, candidates generated, auto-closed, verified, report-ready.
Single most promising lead to pursue next. Path to all artifacts in `results/<target>/`.
