# Fork pull request gets code execution in a privileged `workflow_run` job in `google-gemini/gemini-cli` (artifact-poisoning), reaching `GEMINI_API_KEY` and the default-branch build cache

**Program:** Google OSS VRP
**Category:** Supply chain — vulnerability in a Google OSS project's GitHub Actions configuration
**Repository:** `google-gemini/gemini-cli` (branch `main`, re-confirmed 2026-11-03)

---

## Researcher / run metadata

- Date/time of testing: 2026-11-03, ~22:16–23:40 UTC
- External IP during testing: `180.148.212.54`
- Target config verified read-only against `google-gemini/gemini-cli@main`
- Reproduction run in my own throwaway repos (`azmolhaque/ap-victim` + a fork from a
  second account `zahin24`), on free GitHub-hosted runners, with a **fake** secret.
  No request ever touched `google-gemini/gemini-cli` or any Google runner.

---

## What the bug is, in one paragraph

`gemini-cli` wires an **unprivileged** workflow to a **privileged** one through a
build artifact, and then feeds the artifact's attacker-controlled contents straight
into `actions/checkout`. A fork pull request triggers `Trigger E2E`
(`on: pull_request`), which writes the fork's repo name (and head SHA) into an
artifact. `Testing: E2E (Chained)` (`on: workflow_run`) then reads those strings back
and uses them, with no validation, as the `repository:`/`ref:` of `actions/checkout`,
and runs `npm ci` / `npm run build` / `npm run test:integration…` on whatever tree it
just checked out. Those npm scripts come from the **attacker's** `package.json`, so a
fork PR runs its own code inside the privileged `workflow_run` job — where
`secrets.GEMINI_API_KEY` is in the step environment and the Docker build writes to the
**default-branch** `type=gha` cache scope.

This is the pattern GitHub itself calls a "pwn request." I did not have to guess that
framing — `actions/checkout`'s own refusal message (pasted below) spells out the exact
trust it hands to fork code: *"the base repository's GITHUB_TOKEN, secrets,
default-branch cache scope, and runner access."*

---

## The untrusted data flow (verified in `google-gemini/gemini-cli@main`)

**Source — `trigger_e2e.yml`** (`on: pull_request`, runs for fork PRs, unprivileged):

```yaml
env:
  REPO_NAME: '${{ github.event.inputs.repo_name || github.event.pull_request.head.repo.full_name }}'
run: |
  echo "${REPO_NAME}" > ./pr/repo_name
# ./pr is uploaded as artifact "repo_name"
```

**Boundary crossing — `chained_e2e.yml`** (`on: workflow_run`, privileged):

```yaml
permissions:
  contents: read
  statuses: write          # NOTE: no `actions: read`

# download_repo_name: downloads artifact "repo_name" and reads it back
# parse_run_context (if: ... && always()): no allow-list, no validation
REPO: '${{ needs.download_repo_name.outputs.repo_name || github.repository }}'
SHA:  '${{ needs.download_repo_name.outputs.head_sha || github.event.inputs.head_sha || github.event.workflow_run.head_sha || github.sha }}'
```

**Sink — `e2e_linux` (and `e2e_mac`, `e2e_windows`, `evals`):**

```yaml
- uses: 'actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955' # ratchet:actions/checkout@v5
  with:
    ref:        '${{ needs.parse_run_context.outputs.sha }}'        # attacker-chosen SHA
    repository: '${{ needs.parse_run_context.outputs.repository }}' # attacker-chosen repo
    persist-credentials: false
# ...npm ci / npm run build run the attacker's package.json scripts...
- name: 'Run E2E tests'
  env:
    GEMINI_API_KEY: '${{ secrets.GEMINI_API_KEY }}'
    BUILD_SANDBOX_FLAGS: '--cache-from type=gha --cache-to type=gha,mode=max'
  run: npm run test:integration:sandbox:none
```

The `if: github.repository == 'google-gemini/gemini-cli'` guards on these jobs do not
help: in a `workflow_run` run `github.repository` is always the base repo, so the
guard is always true. It only stops forks from running the workflow on themselves.

Because there is no `actions: read`, the cross-run artifact download fails, and the
context falls back to `repository = github.repository` (the base repo) and
`sha = github.event.workflow_run.head_sha` (the fork PR's head commit). Checking out
the base repo at the fork's head SHA still lands the attacker's tree, because GitHub
keeps a PR's head commit reachable from the base repository.

---

## The one thing that would stop this — and why it doesn't here

Modern `actions/checkout` refuses to check out fork-PR code under
`pull_request_target`/`workflow_run` unless you explicitly opt in. That refusal
(`assertSafePrCheckout`, plus the `allow-unsafe-pr-checkout` input) landed in
**actions/checkout PR #2454, merged 2026-06-16**, shipped in **v7.0.0**, and was
backported to v6/v5/v4.

But `gemini-cli` pins `actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955`,
which is **v4.3.0 (released 2025-08-11)** — about ten months *before* that refusal.
I confirmed, read-only, that v4.3.0 has no such mechanism:

- `actions/checkout` `action.yml` **@ v4.3.0**: 20 inputs, **no `allow-unsafe-pr-checkout`**.
- `actions/checkout` `action.yml` **@ v4.4.0** (first v4 release with the backport):
  21 inputs, including `allow-unsafe-pr-checkout`
  ("Required to check out fork pull request code from a workflow triggered by
  `pull_request_target` or `workflow_run`").

So the version `gemini-cli` runs physically cannot refuse this checkout, and
`allow-unsafe-pr-checkout` is not set anywhere (it doesn't exist in v4.3.0). The
`# ratchet:...@v5` comment is stale — the SHA that actually executes is v4.3.0.

---

## What I reproduced in my own lab

I rebuilt the same three-workflow shape (Trigger → artifact → Chained → checkout →
npm) in repos I own, with a fake secret `FAKE_SECRET` standing in for
`GEMINI_API_KEY`, and a benign `poc.js` that only prints canaries and transmits
nothing.

**1. The chain delivers a fork's repo+SHA straight to `actions/checkout`.** With the
checkout step on the current (patched) `actions/checkout@v5`, the privileged Chained
job resolved the fork's identity into the checkout inputs and the action refused —
and its refusal text is itself the clearest statement of impact:

```
2026-11-03T22:16:10.7885277Z ##[group]Run actions/checkout@v5
with:
  ref: 5fca7e0698659c9fad2132ea3b17d80b6c9a30cb
  repository: zahin24/ap-victim
  persist-credentials: false
  allow-unsafe-pr-checkout: false
Error: Refusing to check out fork pull request code from a 'workflow_run' workflow.
  This workflow runs with the base repository's GITHUB_TOKEN, secrets,
  default-branch cache scope, and runner access. Fetching and executing a fork's
  code in that trusted context commonly leads to "pwn request" vulnerabilities.
  To opt in, review the risks at https://gh.io/securely-using-pull_request_target
  and set 'allow-unsafe-pr-checkout: true' on the actions/checkout step.
```

`repository: zahin24/ap-victim` (a fork) and `ref:` = the fork's head commit are the
attacker-controlled values arriving at the sink. Only the patched checkout's built-in
refusal stopped execution here — and `gemini-cli` pins the unpatched v4.3.0, which has
no such refusal.

**2. With the checkout pinned to the exact version `gemini-cli` uses, the same fork PR
executes.** I then changed only one thing — pinned the lab's checkout to
`actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955` (v4.3.0, the exact SHA
`gemini-cli` pins) — and re-fired the **same** fork PR. This is a clean controlled
experiment: identical chain, identical fork PR, only the checkout version differs.

| Chained run | checkout version | `e2e_linux` Checkout | result |
|---|---|---|---|
| #3 | `@v5` (patched, backported refusal) | **Refused** ("Refusing to check out fork pull request code…") | Build/test skipped, **no execution** |
| #4 | `@08eba0b` (= v4.3.0, what gemini-cli pins) | **Succeeded** | **attacker code ran** |

Chained #4 (triggered by the fork account `zahin24`, base at commit `c39a8b9` with the
v4.3.0 pin) finished **Success in 33s**; `e2e_linux` **Succeeded in 17s** with every
step green:

- `Checkout (fallback: base repo @ workflow_run.head_sha)` — **✓** (no refusal, unlike #3)
- `Build project` (`npm run build` → attacker's `poc.js build`) — **✓** → `PoC-ACE`
- `Run E2E tests` (`npm run test:integration:sandbox:none` → attacker's exfil+poison) —
  **✓** → `PoC-SECRET-REACHABLE` (+ `PoC-CACHE-WRITTEN`)

So the version `gemini-cli` actually pins checks out and runs fork code in the
privileged `workflow_run` job without objection. The payload stayed benign: it prints
the secret's length and a short hash, never the secret, and sends nothing anywhere. In
the real job this env var is `GEMINI_API_KEY`, and nothing stops attacker code from
exfiltrating it.

---

## Impact

- **Arbitrary code execution** in a privileged `workflow_run` job of a high-profile
  Google repository, reachable by any fork pull request (see "Exploitability").
- **Disclosure of `secrets.GEMINI_API_KEY`**, a billable Google API credential, to
  attacker code that can exfiltrate it.
- **Default-branch build-cache influence.** The ACE job runs with
  `--cache-to type=gha,mode=max` in the `workflow_run` context (default-branch cache
  scope), so an attacker-written layer can land in a scope later builds restore from.

GitHub's own refusal message (above) independently enumerates the trust at stake here:
the base repo's `GITHUB_TOKEN`, **secrets**, **default-branch cache scope**, and
**runner access**.

### Stated but not demonstrated (for your assessment, not claimed)

The e2e jobs target **self-hosted runners** (`gemini-cli-ubuntu-16-core`,
`gemini-cli-windows-16-core`) on a public repo. If those runners are non-ephemeral,
ACE additionally enables runner persistence, theft of other jobs' secrets, and lateral
movement. Runner ephemerality is internal to Google and I did not test it — flagging,
not claiming.

### What the attacker does *not* get (so the scope is precise)

- `GEMINI_CLI_ROBOT_GITHUB_PAT` is referenced in other jobs, **not** in the e2e step
  env, so attacker code doesn't get it directly (only via the untested non-ephemeral
  runner path).
- `GITHUB_TOKEN` is not placed in the ACE step env, so `statuses: write` isn't
  directly actionable. Not claimed.

---

## Exploitability

A first-time external contributor's `pull_request` CI needs a maintainer to click
"approve and run" — which authorizes *running CI*, not reviewing the payload. A
returning contributor (one prior merged PR) needs no approval. So the realistic path
is: land one trivial legitimate PR to become a recognized contributor, after which
every later fork PR runs the full chain with no human in the loop.

---

## Suggested fix

- In `chained_e2e.yml`, don't derive `checkout`'s `repository:`/`ref:` from a
  downloaded artifact. Pin to the trusted repo + a verified SHA, or gate the privileged
  job on
  `github.event.workflow_run.head_repository.full_name == 'google-gemini/gemini-cli'`.
- Treat everything crossing `pull_request` → `workflow_run` as untrusted; validate
  against an allow-list before use.
- Don't expose `GEMINI_API_KEY` to a step that runs code from an attacker-controllable
  checkout; put secret-bearing steps behind an `environment:` approval gate (as
  `eval-pr.yml` already does).
- Scope or disable `type=gha` cache writes from the `workflow_run` context.
- Bump `actions/checkout` to a current release (and do **not** set
  `allow-unsafe-pr-checkout: true`) so the built-in refusal also applies.
- Prefer ephemeral, isolated runners for anything reachable by fork PRs.

---

## Notes / honesty

The immediate exploitability today rests on the old pinned checkout (v4.3.0). A routine
checkout bump would make checkout's own refusal block the fork-PR path (unless they
then opt in), but the underlying bug — untrusted artifact data flowing into
`checkout(ref, repository)` with `GEMINI_API_KEY` in the same job — is the durable root
cause and should be fixed regardless of the checkout version.
