# Quick Start — Deploying the Bug Bounty Agent on Raspberry Pi 5

This guide gets you from a fresh Pi 5 (Raspberry Pi OS 64-bit or Ubuntu 24.04
arm64) to a running autonomous hunt in four steps.

---

## Step 1 — Provision the toolchain

```bash
git clone https://github.com/azmolhaque/bug-bounty-hunting-.git ~/Bug-Bounty-Hunting-
cd ~/Bug-Bounty-Hunting-
chmod +x scripts/*.sh
./scripts/setup-pi.sh
source ~/.bashrc

# Verify:
./scripts/setup-pi.sh --check
```

This installs Go, the ProjectDiscovery suite (subfinder, httpx, dnsx, naabu,
nuclei, katana, asnmap), gau, waybackurls, ffuf, dalfox, arjun, SecLists.
All tools compile/run natively on arm64. Estimated time: 10–20 min on Pi 5.

---

## Step 2 — Configure your scope

```bash
$EDITOR config/scope.yaml
```

Fill in **at minimum**:
- `program`: the bug bounty program name.
- `handle`: your researcher handle.
- `in_scope`: the domains/wildcards/IPs the program authorizes.
- `out_of_scope`: any explicit exclusions from the brief.
- `rules.max_requests_per_second`: lower if the program requires it.

**The agent will refuse to hunt with an empty scope. This is intentional.**

Test it:
```bash
./scripts/scope-check.sh api.example.com
# → IN-SCOPE: api.example.com matches '*.example.com'
```

---

## Step 3 — Start Claude Code and load the agent

```bash
cd ~/Bug-Bounty-Hunting-
claude                    # starts Claude Code CLI
```

On first load, Claude reads `CLAUDE.md` (the operating constitution). Then
you have two entry points:

```
/methodology              → study the playbook and plan a hunt
/workflow example.com     → kick off the full automated + agentic pipeline
```

For phased execution:
```
/recon example.com        → Phases 1+2: asset discovery + surface mapping
/hunt example.com         → Phases 3+4: discovery + verification
/triage example.com       → Phase 5:   score, dedup, prioritize
/report example.com --all → Phase 6:   generate triager-grade reports
```

---

## Step 4 — Results

All output goes to `results/<target>/`. Structure:
```
results/example.com/
  00-plan.md          → hunt thesis and prioritized action list
  HUNT-LOG.md         → running decision log (survives context resets)
  01-assets/          → subdomains, resolved hosts, cidrs, cloud assets
  02-surface/         → live hosts, tech map, endpoints, JS findings, priority.md
  03-candidates/      → candidates.jsonl (leads)
  04-verified/        → confirmed bugs with PoCs
  05-triage/          → ranked, deduplicated findings table
  findings/           → final sanitized reports ready for submission
```

---

## Pi 5 performance tips

- Use active cooling. Long nuclei/amass runs will load all 4 cores.
- For very large programs (`*.big.com`): run `./scripts/recon.sh --passive-only`
  first, then run `/hunt` on subsets.
- Background long scans: the scripts support `--background`; check
  `config/tools.yaml` for resource caps.
- All raw evidence stays local; the `.gitignore` blocks it from being pushed.

---

## Safety reminder

The `scope-check.sh` gate is always live. If you discover a new host during
hunting, it is automatically re-checked before any active test. Do not disable
or bypass the scope check. Being out-of-scope is not a bug, it is a violation.
