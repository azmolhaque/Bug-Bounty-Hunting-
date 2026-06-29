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

## Step 0 — Pre-Flight State Check (run before every session)

Before writing a single probe, audit open work across both programs:

```bash
# Google VRP — submitted reports awaiting triage
grep -r "SUBMITTED\|Status: New\|awaiting triage" results/*/HUNT-LOG.md 2>/dev/null

# HackerOne (Marriott) — open reports, appeals, supplement comments
grep -r "OPEN\|APPEAL\|supplement\|#38" results/marriott/HUNT-LOG.md 2>/dev/null

# Active chains — STILL LIVE items that need a trial account or specific setup
grep -r "STILL LIVE\|needs trial\|PURSUE" results/*/HUNT-LOG.md 2>/dev/null | head -20
```

Triage the pre-flight output before picking this session's target:
- Any open report needing a response or additional evidence → handle FIRST
- Any STILL LIVE chain with its prerequisite now met → pick THAT chain
- Only then pick a fresh target from the priority list

### Target-Selection EV Gate (METHODOLOGY FO-1 — apply before committing a session)
Rank candidate targets by realistic conversion, not by prestige. Empirically,
mature programs' reachable surfaces are hardened; the cheap bugs are gone. Order:
1. **Soft VDP / smaller program** — highest solo-remote conversion (default).
2. **Recently-acquired / newly-shipped product or feature** — fresh code (look for
   2024–2026 launches, new subdomains, new API versions).
3. **Self-service multi-tenant SaaS (email/Google signup)** — IDOR with 2 accounts.
4. **Mature consumer/core unauth surface** — LOWEST EV; only with a specific fresh
   hypothesis, never a breadth-scan-for-easy-wins.
Record the chosen target's EV tier + rationale in `00-plan.md`. If the only
candidates are tier-4 husks, switch programs rather than grind low-EV ground.

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

Kick off **subdomain-monitor** in parallel (background) on the root target —
it establishes the baseline on first run and, on every subsequent `/workflow`
invocation for the same target, surfaces new subdomains and CNAME takeover
candidates before the rest of the pipeline starts. New/changed assets feed
straight back into `02-surface/priority.md`.

For every host `priority.md` marks live and worth depth (not just breadth),
delegate to **js-hunter** before Phase 3 starts. JS bundles routinely expose
API routes, GraphQL operations, internal hostnames, and connector/feature
config that never appear in an httpx/katana crawl alone — this is attack
surface Phase 3 cannot hypothesize about until it exists in `02-surface/js/`.
Merge `js-findings.md` discoveries into `02-surface/priority.md` and
`02-surface/endpoints.md` before fanning out vuln-hunters.

After completion, run the **intelligence re-plan**:
- Update hunt thesis in `00-plan.md` with discovered assets
- Identify: dev/staging/RDE hosts, GraphQL/webhook endpoints, dangling CNAMEs
- These reshape Phase 3 priorities

### Recurring-Pattern Lens (run before Phase 3 prioritization)

Before picking Phase 3 bug classes, check whether this target (or its product
family) has a **confirmed history** of a bug class recurring across multiple
independent components — this is the highest-signal prior available, stronger
than a fresh hypothesis:

1. Grep `results/<target>/HUNT-LOG.md` and `results/<target>/findings/` for
   every confirmed class to date.
2. Search public disclosures (Google Bug Hunters writeups, blogspot/twitter
   writeups, `awesome-google-vrp-writeups`) for the same product/acquisition
   for the same class on a *different* component.
3. If a class recurs ≥2 times across different components of the same
   product (e.g. AppSheet's connector framework: Workflows webhook SSRF (2021,
   fixed) → Apigee account-source connector SSRF (fixed, separate report) →
   OData connector SSRF (this engagement, F002) — three independently
   vulnerable HTTP clients, no shared SSRF-safe library across connector
   types), treat every *other* untested instance of that component type as a
   **priority hypothesis, not a fresh guess.** For AppSheet specifically:
   every remaining data-source/connector type (REST API, Salesforce, Box,
   Dropbox, MySQL/Postgres/CloudSQL, BigQuery, Smartsheet, Google
   Sheets-external, etc.) is an unreviewed instance of the same systemic root
   cause until proven otherwise.
4. Log the pattern and the prioritized instance list in `00-plan.md` before
   Phase 3 fan-out — this is what separates "shotgunning every class" (banned
   by CLAUDE.md §6) from "testing the one class most likely to pay out."

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

**False-positive / false-negative gates (METHODOLOGY FO-2, FO-3 — run FIRST, every candidate):**
- **Catch-all 200 control (FO-2):** for any "exposure" returning 200, re-request a
  guaranteed-bogus path with the same method. If the bogus path also returns 200
  with the same body, it's an IAP/SPA/LB catch-all → FALSE POSITIVE → AUTO_CLOSE.
  Only the actual artifact bytes (`[core]`, `KEY=VALUE`) count.
- **Negative-test validity gate (FO-3):** before recording "no IDOR / authorized",
  prove your own auth works — baseline self-read MUST be 200. A 401/403 on a
  cross-account/cross-object request is meaningless if your own baseline is also
  401 (rejected/expired token). Baseline-200 first, THEN interpret.
- **Live-vs-husk (FO-6):** confirm the target is a live app (real SPA build stamp,
  clean JSON 401 on protected endpoints, distinct per-path responses) before
  investing authenticated effort; husks (redirects to *.google.com, "use the app",
  closed Google Form, uniform catch-all) get AUTO_CLOSED.

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

**Evidence gate (mandatory — CLAUDE.md §9 #8):**
Before calling `report-writer`, confirm all 7 evidence items exist in `04-verified/<id>/`:

| # | Item | Required |
|---|------|---------|
| 1 | Researcher metadata (date, UTC time, external IP, tool version) | ✓ |
| 2 | Verbatim copy-pasteable reproduction command | ✓ |
| 3 | Verbatim HTTP response body (actual bytes, not described) | ✓ |
| 4 | HTTP status code + response size | ✓ |
| 5 | Before/after differential (expected vs. actual) | ✓ |
| 6 | Terminal screenshot or equivalent visual | ✓ |
| 7 | SHA256 hash of key evidence files | ✓ |

If ANY item is missing: go back to Phase 4 and collect it. Do not write the report without it.

For each report-ready finding, delegate to **report-writer** to produce a
triager-grade writeup from `templates/report.md` into `findings/`.

See `results/<target>/REPORTING-STANDARDS.md` for the per-program template (HackerOne
vs. Google VRP have different submission fields and attachment requirements).

**Submit immediately** when report passes all gates — first valid report wins.
- Google VRP: bughunters.google.com → Find your product → Submit
- Marriott HackerOne: hackerone.com/marriott → New Report

## Intelligence Loop (after every phase)

```
discover → qualify → verify → chain → submit
    ↑                                    |
    └──── re-plan from new signals ──────┘
```

After each phase, re-plan:
- New asset found (via recon-agent or a fresh subdomain-monitor diff) → expand
  recon (scope-check first)
- Confirmed SSRF → immediately probe IMDS + internal services (Chain 3), AND
  check the Recurring-Pattern Lens: does this product have other connector/
  data-source types implementing their own outbound HTTP client?
- Confirmed IDOR pattern → test ALL object types (connector, issue, project)
- Confirmed subdomain takeover → test CSP + OAuth redirect chain immediately
- A confirmed finding on one component → re-run subdomain-monitor + js-hunter
  on sibling components of the same product before moving to a new target;
  the cheapest next bug is usually the same root cause in a neighboring
  feature, not a new attack surface

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
