# H11 — Google OSS VRP: GitHub Actions supply-chain audit

Date: 2026-09-25
Scope: OT0/OT1 repositories, `.github/workflows/*` only.
Method: read-only. Sparse clone of `.github/`, static reading of YAML.
**No pull requests, issues or comments were created against any Google repository.**

Reward bar being tested against (from `00-PROGRAM.md`): a supply-chain finding pays
only if it lets an outsider get code execution / secret access **without bypassing a
human approval step**. "Requires a maintainer to click something first" = insider
risk = credit, no money.

Every candidate is judged on three questions:

1. Does it run without maintainer approval?
2. Is the untrusted value genuinely attacker-controlled?
3. Does the path reach a secret or a write token?

---

## C1 — `bazelbuild/bazel-central-registry` :: `update_requirements.yml` (OT0, scanner score 8)

```yaml
on:
  pull_request_target:
    paths: ['tools/requirements_lock.txt']
jobs:
  update-requirements:
    if: github.event.pull_request.user.login == 'dependabot[bot]'
        && github.repository == 'bazelbuild/bazel-central-registry'
    permissions: { contents: write }
    steps:
      - uses: actions/checkout@v7
        with:
          ref: ${{ github.head_ref }}
          token: ${{ secrets.BCR_PR_REVIEW_HELPER_TOKEN }}
      - run: bazel run //tools:requirements.update
      - run: git commit … && git push
```

**Verdict: NOT A FINDING.**

- Q2 fails. `github.event.pull_request.user.login` is the authenticated PR author
  from GitHub's own payload. It is not spoofable, and no account can be registered
  as `dependabot[bot]` — square brackets are not legal in GitHub usernames.
- With the gate holding, `github.head_ref` is a Dependabot branch, and Dependabot
  branches live **in the base repository**, not in a fork. Pushing to one requires
  write access. So the checked-out ref is not outsider-controlled either.
- Residual risk is real but is not a BCR bug: `bazel run //tools:requirements.update`
  executes with `BCR_PR_REVIEW_HELPER_TOKEN` persisted in `.git/config`, so a
  compromised upstream Python package in the lock file would reach that token.
  That is a third-party supply-chain compromise, not a vulnerability in this repo.

## C2 — `protocolbuffers/protobuf` :: `test_runner.yml` (OT0, scanner score 5)

**Verdict: NOT A FINDING. This is the reference implementation of the control.**

- Fork PRs hit `pull_request_target` and are hard-stopped:
  `${{ github.event_name != 'pull_request_target' || github.event.label.name == ':a: safe for tests' }} || (… exit 1)`.
  A human must attach `:a: safe for tests`.
- **No stale-label window.** The `remove-tag` job strips the label immediately, so
  every subsequent commit needs its own stamp.
- **No TOCTOU.** `checkout-sha` is taken from `github.event.pull_request.head.sha`
  in the *label event payload*, so it is frozen at the sha the maintainer saw. A
  race push does not change what gets built.
- The scanner's hit on `github.event.pull_request.body` is a **false positive**:
  the body only reaches `!contains(toJson(…), '#test-continuous')`, which renders
  as the literal `true` or `false`. Nothing from the body enters the shell.
- The file cites an internal design doc (`go/protobuf-gha-protected-resources`),
  i.e. this surface has already had internal security review.

## C3 — `tensorflow/tflite-micro` :: `pr_test.yml` (OT1, scanner score 6)

**Verdict: OPEN — one fact outside the YAML decides it.**

Design:

- `pull_request_target` on `synchronize` and `labeled`.
- `gatekeeper` job resolves the PR author's collaborator permission using
  `TFLM_BOT_REPO_TOKEN`. It checks out nothing, so that token is properly isolated.
- `scope` is `none` unless the PR carries `ci:ready` / `ci:full`, **or** the author
  is trusted.
- `approval-gate` sets `environment: ${{ is_trusted == 'false' && 'integration-test' || '' }}`.
  All test jobs `needs: approval-gate`.
- Sink: `test_bazel.yml` checks out `inputs.trigger-sha` (the PR head) with
  `allow-unsafe-pr-checkout: true` and runs `ci_build/${{ matrix.script }}` from the
  PR's own tree, on a custom runner label `linux-x86-n2-16`, with
  `TFLM_BOT_PACKAGE_READ_TOKEN` in scope.

Two weaknesses, both conditional:

- **Stale-label re-push.** A maintainer labels a benign PR `ci:ready`. The label is
  never removed (unlike protobuf). The attacker then pushes malicious code; the
  `synchronize` event re-runs with `scope: basic` at the *new* head sha. The only
  thing standing between that and code execution is the `integration-test`
  environment.
- **`triage` is treated as trusted.** `trustedRoles = ['admin','maintain','write','triage']`.
  A triage-permission collaborator cannot push code to the repo, but their fork PR is
  marked trusted → `environment: ''` → no approval gate at all, on every push. This is
  a privilege boundary crossing, but it is insider risk and will not pay.

**Blocking question:** does the `integration-test` environment have required
reviewers configured? If it does not exist, GitHub creates it implicitly with no
protection rules and the gate is decorative. Cannot be answered from this container
(the agent proxy blocks `api.github.com`). Answer with one read-only call:

```
curl -s https://api.github.com/repos/tensorflow/tflite-micro/environments | \
  jq '.environments[] | {name, rules: [.protection_rules[].type]}'
```

Look for `required_reviewers` on `integration-test`. Absent ⇒ C3 is live.

The scanner's hit on `github.event.pull_request.body` here is also a **false
positive**: it is passed as the `pr-body` input to `check_tflite_files.yml`, which
declares the input and never uses it.

## C4 — `google-gemini/gemini-cli` :: `eval-pr.yml` (OT1)

**Verdict: NOT A FINDING.** `pull_request_target`, but the `detect-changes` job runs
only trusted code from `main` (`git fetch` of the PR head without checkout, analysed
by `scripts/changed_prompt.js` from the base). Fork code is checked out only in
`pr-evaluation`, which sits behind `environment: eval-gate`. Same environment
dependency as C3.

## C5 — `google-gemini/gemini-cli` :: `release-patch-0-from-comment.yml` (OT1)

**Verdict: REAL GAP, LOW IMPACT.** Worth writing up only if C3 dies.

The job-level gate is only `github.event.comment.user.type == 'User' && … != 'github-actions[bot]'`
— no permission check. Authorisation is delegated to
`peter-evans/slash-command-dispatch` (`permission: write`), but **the steps that
follow do not depend on that step's result**:

- `Get PR Status` → `if: startsWith(github.event.comment.body, '/patch')`
- `Dispatch if Merged` → `if: steps.pr_status.outputs.STATE == 'MERGED'`

Neither condition references `steps.slash_command`. If `slash-command-dispatch`
declines an unauthorised command without failing the job (it is written to degrade
gracefully across high comment volume), then **any** GitHub user commenting `/patch`
on a merged PR reaches `createWorkflowDispatch` of `release-patch-1-create-pr.yml`
with `environment: 'prod'`, and makes the bot post release-status comments with a
`contents: write` / `actions: write` token.

Impact ceiling is set by `release-patch-1-create-pr.yml`, which is itself
`environment: "${{ github.event.inputs.environment || 'prod' }}"`. So the realistic
outcome is: unauthorised users can queue prod-approval requests and puppet bot
comments. Nuisance-grade. Unverified precondition: the exact failure semantics of
`slash-command-dispatch@40877f7` on permission denial.

## C6 — `google-gemini/gemini-cli` :: `gemini-automated-issue-triage.yml` (OT1)

**Verdict: DELIBERATELY HARDENED — clean negative on the obvious XPIA.**

Fires on `issues: opened/reopened` with **no author gate**, so any outsider controls
the model's input. But:

- `GITHUB_TOKEN: ''` is passed explicitly to the Gemini step, with the comment
  *"Do not pass any auth token here since this runs on untrusted inputs."* The agent
  has no GitHub access.
- Untrusted text never enters the prompt. It is written to `issue_context.md` and the
  model reads it with `read_file`.
- Tool surface is two entries: `run_shell_command(echo)` and `read_file`.
- Output is re-parsed as JSON by a separate step running under the real token, which
  rejects anything that is not exactly one label.

Residual, very low: the emitted label is **not** validated against the `allowedLabels`
list the workflow itself computed. `newAreaLabel = labelsToAdd[0]` goes straight to
`issues.addLabels`. A prompt injection can therefore set an arbitrary label — but on
the attacker's own issue, with `ISSUE_NUMBER` fixed from the event payload, not from
the model. No pivot found to a label-triggered workflow.

The interesting sub-question — whether `run_shell_command(echo)` can be widened to
arbitrary execution (which would expose the runner's Workload Identity credentials) —
is a **product** question about gemini-cli, not a workflow one. `packages/core/src/utils/shell-utils.ts`
is 1197 lines built on a tree-sitter bash parser with `splitCommands`, `getCommandRoots`,
`detectCommandSubstitution`, `hasRedirection` and `hasPromptCommandTransform`. The naive
`echo x; curl evil` bypass is not going to work; this has been hardened, almost certainly
in response to earlier reports. Duplicate risk is high and it is a research project, not
a session's work.

---

## Standing conclusion

Six top-ranked candidates across four OT0/OT1 repos. Five are properly defended and
two of the scanner's three "untrusted input in `run:`" hits were false positives
(`contains()` and an unused reusable-workflow input).

**The OT0/OT1 GitHub Actions surface is hardened.** These repos show explicit,
deliberate control design — label-stripping, payload-frozen shas, isolated token jobs,
`zizmor` ignore-comments, empty tokens passed to AI steps with rationale comments in
the file. Somebody has already done this audit from the inside.

Only one live thread remains (C3's environment config) and it is answerable with a
single read-only API call. If that comes back with `required_reviewers`, this axis is
closed and the class should be abandoned rather than ground further.

### Lesson (candidate for METHODOLOGY.md)

A scanner that flags `github.event.*` inside `run:` cannot tell interpolation from
evaluation. `${{ contains(toJson(body), 'x') }}` renders as `true`/`false` and is
inert; an input declared and never consumed is inert. Score is triage. Two of three
top hits died on the first honest read — count a candidate only after reading what the
value actually becomes.
