================================================================================
TITLE  (short summary field, if asked)
================================================================================
Fork pull request achieves code execution in a privileged workflow_run job in
google-gemini/gemini-cli (artifact-poisoning), exposing GEMINI_API_KEY


================================================================================
FIELD 1 — "The problem" (paste everything below into the technical-details box)
================================================================================

## Summary

`google-gemini/gemini-cli` has a GitHub Actions artifact-poisoning ("pwn request")
misconfiguration. An unprivileged workflow (`trigger_e2e.yml`, `on: pull_request`)
writes two attacker-controlled strings — a fork PR's head repository and head SHA —
into a build artifact. A privileged workflow (`chained_e2e.yml`, `on: workflow_run`)
reads them back and uses them, with no validation, as the `repository:` and `ref:` of
`actions/checkout`, then runs `npm ci` / `npm run build` / `npm run test:integration…`
on the checked-out tree. Those npm scripts come from the **attacker's** `package.json`,
so a fork PR gets **arbitrary code execution in the privileged `workflow_run` job**,
where `secrets.GEMINI_API_KEY` is in the step environment.

## Affected files (branch `main`, verified 2026-11-03/04)

- `.github/workflows/trigger_e2e.yml` — untrusted source
- `.github/workflows/chained_e2e.yml` — privileged sink

## The untrusted data flow

**Source — `trigger_e2e.yml`** (`on: pull_request`; runs for fork PRs):

```yaml
env:
  REPO_NAME: '${{ github.event.inputs.repo_name || github.event.pull_request.head.repo.full_name }}'
  HEAD_SHA:  '${{ github.event.inputs.head_sha  || github.event.pull_request.head.sha }}'
run: |
  echo "${REPO_NAME}" > ./pr/repo_name
  echo "${HEAD_SHA}"  > ./pr/head_sha
# ./pr uploaded as artifact "repo_name"
```

On a fork PR both are attacker-controlled (the fork's `full_name` and the attacker's
commit SHA).

**Sink — `chained_e2e.yml`** (`on: workflow_run`; top-level
`permissions: contents: read, statuses: write`):

```yaml
# download_repo_name: actions/download-artifact with
#   github-token: ${{ secrets.GITHUB_TOKEN }}, run-id: ${{ github.event.workflow_run.id }}
# parse_run_context (if: "... == 'google-gemini/gemini-cli' && always()"), no validation:
REPO: '${{ needs.download_repo_name.outputs.repo_name || github.repository }}'
SHA:  '${{ needs.download_repo_name.outputs.head_sha  || github.event.inputs.head_sha || github.event.workflow_run.head_sha || github.sha }}'

# e2e_linux / e2e_mac / e2e_windows / evals:
- uses: 'actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955' # = v4.3.0
  with:
    ref:        '${{ needs.parse_run_context.outputs.sha }}'
    repository: '${{ needs.parse_run_context.outputs.repository }}'
- run: npm ci
- run: npm run build
- name: 'Run E2E tests'
  env:
    GEMINI_API_KEY: '${{ secrets.GEMINI_API_KEY }}'
  run: npm run test:integration:sandbox:none
```

`download_repo_name` passes `github-token: GITHUB_TOKEN`, so the cross-run download
succeeds even without `actions: read`; `repository` resolves to the fork and `ref` to
the fork's head SHA straight from the attacker's artifact (there is also a
`workflow_run.head_sha` fallback). The `if: github.repository == 'google-gemini/gemini-cli'`
guards do not help — in a `workflow_run` run `github.repository` is always the base
repo, so they are always true.

## Why the pinned `actions/checkout` does not block it

`actions/checkout` added a built-in refusal of fork-PR checkout under
`pull_request_target`/`workflow_run` (`assertSafePrCheckout`, opt-out input
`allow-unsafe-pr-checkout`) in **PR #2454, merged 2026-06-16** (shipped v7.0.0,
backported to v6/v5/v4). The pinned SHA `08eba0b…` is **v4.3.0 (2025-08-11)**, which
predates this: its `action.yml` has **no `allow-unsafe-pr-checkout` input at all**
(v4.4.0 is the first v4 release that has it). So the pinned version cannot refuse the
checkout, and the workflow sets no `allow-unsafe-pr-checkout`. The config is still
present at `main` HEAD; the latest change to `chained_e2e.yml` (PR #26897, 2026-05-12)
only added `persist-credentials: false`.

## Proof — isolated lab reproduction (no contact with Google systems)

I reproduced the exact three-workflow shape in my own throwaway repos, with a fake
secret `FAKE_SECRET` in place of `GEMINI_API_KEY`, on free GitHub-hosted runners, using
the same `permissions: contents: read` and the same checkout pin. One controlled
variable — the checkout version — flips the outcome, driven by a real fork PR from a
second account:

- **`actions/checkout@v5` (current, patched)** → the privileged job **refused**:

```
Error: Refusing to check out fork pull request code from a 'workflow_run' workflow.
This workflow runs with the base repository's GITHUB_TOKEN, secrets, default-branch
cache scope, and runner access... "pwn request" vulnerabilities... set
'allow-unsafe-pr-checkout: true' on the actions/checkout step.
```

(repository resolved to the attacker fork; `allow-unsafe-pr-checkout: false`.)

- **checkout pinned to `08eba0b…` (= v4.3.0, what gemini-cli uses)** → the same fork PR
  **executed**; the attacker npm script ran in the privileged job and the secret was in
  reach:

```
> poc-attacker-fork@1.0.0 test:integration:sandbox:none
> node poc.js exfil && node poc.js poison
##[notice]PoC-SECRET-REACHABLE :: FAKE_SECRET reachable by attacker code (len=18, sha256_prefix=5526dde5807f); transmitted NOWHERE. In prod this is GEMINI_API_KEY.
```

The payload is benign: it prints only the secret's length and a short hash, never the
secret, and transmits nothing. In the real job this env var is `GEMINI_API_KEY`, and
nothing stops attacker code from exfiltrating it.

## Suggested fix

- Don't derive `checkout`'s `repository:`/`ref:` from a downloaded artifact; pin the
  trusted repo + a verified SHA, or gate the privileged jobs on
  `github.event.workflow_run.head_repository.full_name == 'google-gemini/gemini-cli'`.
- Treat everything crossing `pull_request` → `workflow_run` as untrusted; validate
  against an allow-list.
- Don't expose `GEMINI_API_KEY` to a step that runs code from an attacker-controllable
  checkout; put secret-bearing steps behind an `environment:` approval gate.
- Bump `actions/checkout` to a current release (and do **not** set
  `allow-unsafe-pr-checkout: true`) so the built-in refusal also applies.
- Prefer ephemeral, isolated runners for anything reachable by fork PRs.

I tested only against repositories I own; I did not run anything against
`google-gemini/gemini-cli` or any Google runner, and no Google-side output is included.


================================================================================
FIELD 2 — "Impact analysis" (paste everything below into the impact box)
================================================================================

## What an attacker gains (demonstrated)

- **Arbitrary code execution** in a privileged `workflow_run` job of a high-profile
  Google repository, reachable by a fork pull request.
- **Disclosure of `secrets.GEMINI_API_KEY`** — a billable Google API credential — to
  attacker code that can exfiltrate it (the secret is set in the `env:` of a step that
  runs an attacker-defined npm script).

GitHub's own refusal message (quoted in the repro) independently enumerates the trust
handed to fork code here: the base repo's **`GITHUB_TOKEN`**, **secrets**,
**default-branch cache scope**, and **runner access**.

## Flagged but NOT demonstrated (stated honestly, not claimed)

- **Build-cache poisoning:** attacker code can write to the `type=gha` cache, but in my
  lab a later trusted build did **not** restore the poisoned layer, so I do not claim a
  build-integrity compromise.
- **Self-hosted-runner compromise:** the e2e jobs target self-hosted runners
  (`gemini-cli-ubuntu-16-core`, `gemini-cli-windows-16-core`) on a public repo; if those
  runners are non-ephemeral, ACE would additionally enable runner persistence and theft
  of other jobs' secrets. Runner ephemerality is internal to Google and I did not test
  it.

## Exploitability

Under GitHub's default fork-PR policy, a first-time contributor's CI needs a maintainer
"approve and run" (which authorizes *running CI*, not reviewing the payload); a
returning contributor (one merged PR) needs no approval — so the realistic path is to
land one trivial legitimate PR, after which every later fork PR runs the full chain with
no human in the loop. If the repo requires approval for all outside collaborators, each
fork PR needs a click — a higher bar, but the workflow config is still unsafe.

## Not a duplicate of CVE-2026-12537

`GHSA-wpqr-6v78-jr5g` / `CVE-2026-12537` is a **different** bug — the gemini-cli *agent*
trusting attacker workspace config in headless mode. This report is a plain **GitHub
Actions configuration** bug in `chained_e2e.yml` (artifact-derived strings into
`actions/checkout`); no gemini-cli agent is involved. I found no public report
describing this specific `chained_e2e.yml` checkout data flow, and the configuration is
still live at `main` HEAD.
