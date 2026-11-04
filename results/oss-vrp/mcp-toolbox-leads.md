# googleapis/mcp-toolbox — CI leads (real but MARGINAL, not submitted)

Date: 2026-11-04. Read-only analysis.

## Lead 1 — conformance.yml (pwn-request, ACE) — MARGINAL (WAI risk)
- `on: pull_request` + `pull_request_target: types:[labeled]`; top perms `read-all`,
  job perms `issues: write, pull-requests: write`.
- checkout `ref: ${{ github.event.pull_request.head.sha }}`,
  `repository: ${{ github.event.pull_request.head.repo.full_name }}` (FORK code).
- Steps: setup-go -> `go build -o toolbox` -> `./toolbox --config tests/conformance/tools.yaml &`
  -> runs conformance action. => the fork's compiled binary EXECUTES in the privileged
  pull_request_target context => ACE. Secret in reach: only GITHUB_TOKEN (issues/PR write);
  possibly stealable from .git/config if persist-credentials default.
- Caveats that make it marginal:
  - Human gate: a maintainer must apply the `tests: run` label; an external attacker
    cannot self-apply it.
  - File carries `# zizmor: ignore[dangerous-triggers]` -> maintainers KNOWINGLY suppressed
    the scanner finding -> high chance Google closes as intended/WAI (reputation risk).
- Verdict: valid pwn-request, but gated + explicitly-accepted + only GITHUB_TOKEN. Do not
  submit without a stronger impact (e.g., prove a higher-value secret is reachable).

## Lead 2 — docs_preview_deploy_cf.yaml (artifact-poisoning) — LOW impact
- `on: workflow_run` ("CF: Build Docs Preview", completed) + workflow_dispatch; perms
  `contents: read, pull-requests: write`.
- Downloads artifact `cf-preview-data` (run-id = workflow_run.id) built from fork PR
  content; deploys `downloaded-artifact/public` to Cloudflare Pages project `toolbox-docs`
  `--branch pr-N` using `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID`.
- No fork guard (no head_repository check). Auto-fires (no human gate).
- But: attacker code does NOT execute in CI (wrangler deploys static files); token not
  stolen. Impact = attacker controls content (and potentially `_worker.js`) on a
  `pr-N.toolbox-docs.pages.dev` PREVIEW origin -> content injection / stored XSS on an
  untrusted preview subdomain. Likely Low/informational unless that origin is trusted/shared.
- Verdict: clean missing-fork-guard, but impact too low to submit standalone.

## Status: logged as leads; continuing to scan for a cleaner, higher-impact finding.
