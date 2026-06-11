---
description: Vulnerability discovery + verification (Phases 3-4)
argument-hint: "<target-or-priority-file> [--class idor|ssrf|auth|injection|logic|xss]"
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task
---

# /hunt — Find, then prove, real bugs

Input: `$ARGUMENTS` (a target, or a `priority.md` from `/recon`). Execute Phase 3
(Discovery) and Phase 4 (Verification) from `methodology/METHODOLOGY.md`.

## Steps

1. **Scope gate** on every target via `./scripts/scope-check.sh`. Abort
   out-of-scope. Honor permitted test types and rate caps.

2. **Automated breadth.** Run `nuclei` (curated templates, Pi-tuned severity &
   rate) and exposure checks (`.git`, `.env`, backups, takeover, default creds).
   Stream output to `results/<target>/03-candidates/`.

3. **Agentic depth (the real work).** For each high-priority endpoint, do NOT
   shotgun every payload. Instead:
   - **Hypothesize:** given the tech, behavior, and data it handles, what are the
     2–3 most plausible bug classes? (If `--class` was passed, focus there.)
   - **Test those first**, prioritizing the high-value classes: Broken Access
     Control / IDOR / BOLA, SSRF, auth/OAuth/JWT, injection, business-logic /
     race conditions, then XSS/CSRF/CORS, file handling, misconfig.
   - Use OOB confirmation for blind cases. Use benign, non-destructive payloads.
   - For breadth fan-out, delegate clusters to **vuln-hunter** subagents in
     parallel (resource-capped per `config/tools.yaml`).
   - Record each lead to `03-candidates/candidates.jsonl` as
     `{target, class, evidence, confidence, why_it_matters}`.

4. **Verify (Phase 4).** For each candidate worth it:
   - Reproduce from a **clean state** (fresh session/account) — kill false
     positives.
   - **Minimize** the PoC to the smallest reproducing request/steps.
   - **Prove impact safely** (read-only, your-own-account, OOB) — never
     destructive, never real-user data.
   - **Chain:** ask "what does this unlock?" Combine low-severity issues into
     high/critical narratives.
   - Write confirmed bugs to `results/<target>/04-verified/<bug>/` with sanitized
     evidence, PoC, and a CVSS 3.1 vector + impact note.

5. **Update** `HUNT-LOG.md`. End with: candidates found, verified count, the
   strongest finding, and the most promising chain to pursue next.

Be skeptical of your own hits. If it does not reproduce twice, it is a lead, not
a bug — label it honestly.
