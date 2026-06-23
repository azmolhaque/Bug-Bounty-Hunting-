---
description: Vulnerability discovery + verification (Phases 3-4) with lead qualification and chain elevation
argument-hint: "<target-or-priority-file> [--class idor|ssrf|auth|injection|logic|xss] [--qualify-only] [--chain <finding-id>]"
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task
---

# /hunt — Find, Qualify, Prove, Chain

Input: `$ARGUMENTS` — a target domain, a `priority.md` from `/recon`, or a
specific finding ID for chain elevation. Runs Phase 3 (Discovery) and Phase 4
(Verification + Chain Elevation) from `methodology/METHODOLOGY.md`.

## Parse Arguments

- `--class <X>`: focus only on this bug class in Phase 3
- `--qualify-only`: run Phase 3 + lead qualification, stop before Phase 4
- `--chain <id>`: skip Phase 3, jump to chain analysis for finding `<id>`
- `--phase 3` or `--phase 4`: run that phase only

## Step 1 — Scope Gate

```bash
./scripts/scope-check.sh <target>
```
Abort on OUT-OF-SCOPE. Re-check every discovered host before probing it.

## Step 2 — Resource Check

```bash
./scripts/pi-resource-guard.sh --wait
```

## Step 3 — Automated Breadth (Phase 3)

If `--class` specified, focus nuclei templates on that class. Otherwise:

```bash
nuclei -u https://<target> \
  -severity critical,high,medium \
  -exclude-tags dos,fuzz,intrusive \
  -include-tags cve,misconfig,exposure,takeover,default-login,tech \
  -c 25 -rl 100 -bs 25 \
  -o results/<target>/03-candidates/nuclei-<target>.txt
```

For high-priority clusters from `priority.md`, fan out up to 3 parallel
`vuln-hunter` subagents. Cap at `config/tools.yaml: max_parallel_subagents`.

## Step 4 — Lead Qualification Gate (every candidate, <60s)

For EVERY signal from nuclei or manual testing, run qualification BEFORE
investing verification time:

```bash
./scripts/lead-qualify.sh <class> <confidence> <impact> <evidence>
```

| Verdict | Action |
|---------|--------|
| `PURSUE:HIGH` | Proceed to Phase 4 immediately |
| `PURSUE:MARGINAL` | Verify fast — max 2 probes, then drop if no confirmation |
| `AUTO_CLOSE` | Log reason, move on. Do not revisit unless class changes. |

**If batch processing candidates**: delegate to **lead-qualifier** subagent.

Record each decision in `03-candidates/candidates.jsonl`:
```json
{"id":"C001","target":"...","class":"SSRF","qualify":"PURSUE:HIGH:5/5","status":"PURSUING"}
```

## Step 5 — Agentic Depth (manual Phase 3)

For each PURSUE target, hypothesize the 2-3 most plausible bug classes given
tech and behavior — do NOT shotgun every class:

| If you see... | Hypothesize first... |
|--------------|---------------------|
| Webhook/URL-fetch | SSRF → IMDS → internal services |
| Multi-tenant GraphQL | IDOR/BOLA → cross-tenant object access |
| OAuth/SSO login | redirect_uri bypass → account takeover |
| Dangling CNAME | Subdomain takeover → CSP/OAuth chain |
| JWT in headers | alg:none, weak secret, iss confusion |
| File upload | Path traversal, stored XSS, SSRF |
| Admin panel | Broken access control, default creds |

Use OOB canaries (interactsh) for blind detection. Benign payloads only.

## Step 6 — Verification (Phase 4)

For each PURSUING candidate:

1. **Dead-end check**: count probes in `.orchestrator-state.json`.
   If probes ≥ 3 and no confirmation → mark DEAD_END, stop.

2. **Reproduce twice** from a clean state (fresh session/account).
   If it doesn't reproduce twice → downgrade to UNVERIFIED candidate.

3. **Minimize PoC** to the smallest reproducing sequence.

4. **Prove impact safely**:
   - Read-only evidence only
   - Your own test account data only
   - OOB DNS/HTTP for blind SSRF
   - No real user data, no destructive operations

5. **Collect evidence (mandatory — CLAUDE.md §9 #8):**
   Before writing the verified finding, capture ALL of the following:
   - `date -u` + `curl -s ifconfig.me` → researcher metadata
   - Verbatim reproduction command (curl or numbered steps, copy-pasteable)
   - Verbatim response body (paste actual bytes, not a summary)
   - HTTP status + response size (`wc -c`)
   - Before/after differential (what a secure endpoint returns vs. what you got)
   - Terminal screenshot covering the key request/response
   - `sha256sum` of key evidence files → `SHA256SUMS.txt`

   A finding without all 7 items is a **lead**, not a verified finding.
   See `results/<target>/REPORTING-STANDARDS.md` for the per-program template.

6. Write to `results/<target>/04-verified/<id>/`:
   - `verification.txt` with VERDICT: CONFIRMED | NOT_CONFIRMED
   - `poc.txt` with minimal request/response
   - `evidence/` folder with all 7 checklist items
   - `chain-queue.txt` (auto-populated in step 7)

## Step 7 — Chain Elevation

For every CONFIRMED finding:

```bash
./scripts/chain-graph.sh add <target> <id> <class> <base-severity>
# Automatically queues all chain tests as PENDING
```

Then work through PENDING tests — or delegate to **chain-analyst** subagent:

| Confirmed class | Immediately test... |
|----------------|---------------------|
| subdomain-takeover | CSP script-src, OAuth redirect_uri, cookie domain |
| SSRF-blind | IMDS v1/v2, GCP metadata, internal Grafana, internal auth |
| IDOR-read | Write escalation, cross-tenant enum, connector ID |
| XSS-stored | Admin panel delivery, session theft PoC |
| credential-exposure | Validity check, privilege level |
| default-creds | Datasource list, sensitive dashboards, internal pivot |

Record each chain test result:
```bash
./scripts/chain-graph.sh link <target> <id> <test-name> PASS|FAIL
```

If any chain link passes → severity elevates → report immediately.

## Step 8 — Update State

```bash
./scripts/chain-graph.sh report <target>
```

Update `HUNT-LOG.md`: candidates found, qualified, verified, chains tested,
strongest finding, next action.

End your turn with: candidates (total / pursuing / auto-closed / dead-ends),
verified count, strongest finding + chain status, most promising next probe.

Be skeptical. If it does not reproduce twice cleanly, it is a lead — label it
honestly. One confirmed High beats one hundred uncertain candidates.
