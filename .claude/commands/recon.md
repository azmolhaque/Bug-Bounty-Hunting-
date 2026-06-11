---
description: Asset discovery + attack-surface mapping (Phases 1-2)
argument-hint: "<target-root> [--passive-only] [--background]"
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task
---

# /recon — Map everything they own and every input they expose

Target: `$ARGUMENTS`. Execute Phases 1 (Asset Discovery) and 2 (Attack-Surface
Mapping) from `methodology/METHODOLOGY.md`.

## Steps

1. **Scope gate.** Run `./scripts/scope-check.sh <target>`. Abort if not
   IN-SCOPE. Re-check every newly discovered host before active probing.

2. **Run the recon pipeline.** Use `./scripts/recon.sh <target>` which chains
   the ARM64 toolchain (subfinder, amass passive, dnsx, httpx, naabu, katana,
   gau, nuclei-light). On the Pi, run long scans with `--background` and poll.
   Respect `config/tools.yaml` rate/concurrency caps.

   For heavy targets, delegate to the **recon-agent** subagent via `Task` so the
   orchestrator stays responsive.

3. **Classify & prioritize (cognition).** From the raw output:
   - Dedup and resolve all subdomains; cluster live hosts by response similarity.
   - Flag anomalous hosts (`dev/staging/internal/legacy/admin/api/git/jenkins`).
   - Mine JS for hidden endpoints, keys, and internal hostnames.
   - Inventory parameters and APIs (Swagger/GraphQL).
   - Identify endpoints touching **auth, money, files, user-data, or admin**.

4. **Write artifacts** to `results/<target>/`:
   - `01-assets/` → `subdomains.txt`, `resolved.txt`, `cidrs.txt`, `cloud.txt`
   - `02-surface/` → `live.txt`, `tech.json`, `endpoints.txt`, `params.json`,
     `js-findings.md`, `apis.md`
   - `02-surface/priority.md` → **ranked target list** with one-line rationale
     per entry (the input to `/hunt`).

5. **Update** `results/<target>/HUNT-LOG.md` and end with a short summary: counts
   discovered, the top 5 most interesting targets, and why.
