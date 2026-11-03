# Artifact-poisoning in `google-gemini/gemini-cli` — a fork pull request achieves code execution in a privileged `workflow_run` job, disclosing `GEMINI_API_KEY` and poisoning the default-branch build cache

**Program:** Google OSS VRP · **Category:** Supply chain → *Vulnerabilities in
Google OSS GitHub Actions configuration* · **Repo:** `google-gemini/gemini-cli`

## Summary

`google-gemini/gemini-cli` has a GitHub Actions misconfiguration of the
**artifact-poisoning / `workflow_run`** class. An **unprivileged** workflow
(`Trigger E2E`, `on: pull_request`) writes two **attacker-controlled** strings —
the fork PR's head repository and head SHA — into an artifact. A **privileged**
workflow (`Testing: E2E (Chained)`, `on: workflow_run`) downloads that artifact
and uses those strings **unvalidated** as the `repository:` and `ref:` of
`actions/checkout`, then runs `npm ci` / `npm run build` / `npm run
test:integration…` on the attacker-controlled tree.

Because those npm scripts are defined in the **attacker's** checked-out
`package.json`, a fork pull request achieves **arbitrary code execution in the
privileged `workflow_run` context**, where the step env holds
`secrets.GEMINI_API_KEY` and where `--cache-to type=gha,mode=max` runs in the
**default-branch cache scope**.

## Demonstrated impact (proven in an isolated lab reproduction)

1. **Arbitrary code execution** in the privileged `workflow_run` job (×4:
   `e2e_linux/mac/windows`, `evals`), driven entirely by data an unprivileged fork
   PR placed in the artifact (a classic TOCTOU between the two workflows). No
   `environment:` approval gate exists on these jobs.
2. **Disclosure of `secrets.GEMINI_API_KEY`** — a billable Google API credential —
   to attacker code (the `Run E2E tests` step sets it in `env:` and runs an
   attacker-defined npm script). The attacker can exfiltrate it.
3. **Default-branch build-cache poisoning → build integrity.** The ACE job runs in
   the `workflow_run` context (`GITHUB_REF` = default branch) with
   `--cache-to type=gha,mode=max`, so an attacker-written layer lands in the
   **default-branch gha cache scope**, which every later build can restore. A
   trusted build that does `--cache-from type=gha` restores the attacker-produced
   layer — i.e. attacker-controlled content enters Google's build outputs.

All three are reproduced end-to-end on free GitHub-hosted runners with a **fake**
secret, in attacker/victim repos the reporter owns, with zero contact with Google
infrastructure. (Evidence: Actions-log canaries `PoC-ACE`,
`PoC-SECRET-REACHABLE`, and matching `PoC-CACHE-WRITTEN` / `LEGIT-BUILD-PROVENANCE`
provenance strings.)

## Potential impact — NOT demonstrated, stated for the triager's assessment

- The jobs run on **self-hosted runners** (`gemini-cli-ubuntu-16-core`,
  `gemini-cli-windows-16-core`) attached to a **public** repository — the exact
  configuration GitHub's own documentation explicitly warns against, because any
  fork PR can execute code on them. **If** these runners are non-ephemeral, ACE
  additionally enables runner persistence, theft of *other* jobs' secrets
  (`GEMINI_CLI_ROBOT_GITHUB_PAT`, other runs' `GITHUB_TOKEN`), and lateral movement
  from the runner's network position. Runner ephemerality is internal to Google
  and was **not** tested; this is flagged, not claimed.

## Scope of the claim — what the attacker does NOT get (verified)

To keep the assessment precise:
- `permissions: write-all` appears only on **other** jobs (`set_pending_status`,
  the final status job), not on the e2e ACE jobs — those inherit only
  `contents: read, statuses: write`.
- `GEMINI_CLI_ROBOT_GITHUB_PAT` is referenced only in `merge_queue_skipper` /
  `download_repo_name`, **never** in the e2e job env, so attacker code does not
  obtain it directly (only via the undemonstrated non-ephemeral-runner path).
- `GITHUB_TOKEN` is not placed in the ACE step env, so `statuses: write` is not
  directly actionable by the attacker. Not claimed.

## Root cause — the untrusted data flow (pinned)

Commit `0ac57c029b848d109eef940afe0db4b5a0c3dad0` (branch `main`); re-confirm at
filing time.

**Untrusted source — `trigger_e2e.yml`** (`on: pull_request`, runs for fork PRs):
```yaml
env:
  REPO_NAME: '${{ github.event.inputs.repo_name || github.event.pull_request.head.repo.full_name }}'
  HEAD_SHA:  '${{ github.event.inputs.head_sha  || github.event.pull_request.head.sha }}'
run: |
  echo "${REPO_NAME}" > ./pr/repo_name
  echo "${HEAD_SHA}"  > ./pr/head_sha
# uploaded as artifact "repo_name"
```

**Trust-boundary crossing — `chained_e2e.yml`** (`on: workflow_run`, privileged):
```yaml
# download_repo_name: reads the two strings back from the artifact
core.setOutput('repo_name', ...); core.setOutput('head_sha', ...);
# parse_run_context: NO validation / allow-list
REPO: '${{ needs.download_repo_name.outputs.repo_name || github.repository }}'
SHA:  '${{ needs.download_repo_name.outputs.head_sha  || github.event.workflow_run.head_sha }}'
```

**Sink — `e2e_linux` (and `e2e_mac`, `e2e_windows`, `evals`):**
```yaml
- uses: actions/checkout@v5
  with:
    ref:        '${{ needs.parse_run_context.outputs.sha }}'        # attacker SHA
    repository: '${{ needs.parse_run_context.outputs.repository }}' # attacker repo
    persist-credentials: false
- run: npm ci           # attacker lifecycle scripts -> code exec
- run: npm run build    # attacker "build" script   -> code exec
- name: 'Run E2E tests'
  env:
    GEMINI_API_KEY: '${{ secrets.GEMINI_API_KEY }}'                              # secret present
    BUILD_SANDBOX_FLAGS: '--cache-from type=gha --cache-to type=gha,mode=max'   # default-branch cache
  run: npm run test:integration:sandbox:none          # attacker-defined script
```

The `if: github.repository == 'google-gemini/gemini-cli'` guards do not mitigate:
in a `workflow_run` run `github.repository` is always the base repo, so the guards
are always true; they only prevent forks from running the workflow on themselves.

## Exploitability

For a **first-time** external contributor, the `pull_request` CI (`Trigger E2E`)
requires a maintainer to click "approve and run" — which authorizes *running CI*,
not review of the payload. A **returning** contributor (one prior merged PR) needs
no approval, so the realistic path is: submit one trivial legitimate PR to become a
recognized contributor, after which **every** subsequent fork PR runs the full
chain with no human in the loop.

## Suggested remediation

- In `chained_e2e.yml`, never derive `checkout`'s `repository:`/`ref:` from a
  downloaded artifact; pin to the trusted repo and a verified SHA, or gate the
  privileged job on
  `github.event.workflow_run.head_repository.full_name == 'google-gemini/gemini-cli'`.
- Treat everything crossing the `pull_request` → `workflow_run` boundary as
  untrusted; validate artifact contents against an allow-list before use.
- Do not expose `GEMINI_API_KEY` to a step that executes code from an
  attacker-controllable checkout; move secret-bearing steps behind an
  `environment:` approval gate (as `eval-pr.yml` already does).
- Scope or disable `type=gha` cache writes from the `workflow_run` context; do not
  share a build cache between attacker-reachable and release builds.
- Prefer ephemeral, isolated runners for any workflow reachable by fork PRs.

## Evidence attached

- `Detect-ArtifactPoisoning.ps1` output (read-only, public API) — 10/10 chain
  present at the pinned/current SHA.
- Own-lab reproduction logs: `PoC-ACE`, `PoC-SECRET-REACHABLE`, and matching
  `PoC-CACHE-WRITTEN` / `LEGIT-BUILD-PROVENANCE` provenance.
- No output from the real repo or Google runners is included.
