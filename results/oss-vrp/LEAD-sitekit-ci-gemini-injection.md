# LEAD — site-kit-wp CI: prompt injection into an agent running with `--approval-mode=yolo`

**Status: lead, not a finding.** Every mechanical link below is verified. The
one link that is *not* verified is the model's susceptibility, and until that is
demonstrated this does not go anywhere near a report (CLAUDE.md § 4: a chain
with no working PoC at the critical step is an invalid chain).

**Why this channel:** OSS VRP stopped accepting product vulnerabilities on
2026-10-01 but still accepts **supply chain** issues, and `google/site-kit-wp`
is OT1 ($1,337–$13,337). This is the repository's build infrastructure, not the
plugin — the category that is still open.

Target commit: `8cf47de` (1.190.0). Date: 2026-10-29.

---

## The flow, as the repository's own files define it

`.github/workflows/gemini.yml` — "Gemini Implement Issue":

```yaml
on:
  workflow_dispatch:
    inputs:
      issue_number: { description: GitHub issue number to implement, type: number }

jobs:
  implement:
    permissions: { contents: read, issues: read }
    steps:
      …
      - run: npm install -g @google/gemini-cli@0.42.0
      - run: gemini --approval-mode=yolo --model=gemini-3-pro-preview "/implement ${{ inputs.issue_number }}"
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
          GITHUB_MCP_PAT: ${{ secrets.GITHUB_TOKEN }}
      - run: git add . && git diff --staged --binary > implementation.patch
      - uses: actions/upload-artifact@…   # implementation.patch

  create-pr:
    needs: implement
    permissions: { contents: write, pull-requests: write, issues: write }
    steps:
      - uses: actions/download-artifact@…
      - run: git apply implementation.patch
      - uses: peter-evans/create-pull-request@…   # pushes gemini/issue-N, opens a DRAFT PR
```

`/implement` is `.agents/skills/implement-issue/SKILL.md`, and its front matter
is `allowed-tools: Bash, Read, Grep, Glob, Edit, Write`. Its Step 1 instructs
the agent to fetch the issue and extract its sections **verbatim**, and then:

> Collect every issue referenced anywhere in the Feature Description,
> Acceptance criteria, Implementation Brief and Test Coverage — `#12345`, a full
> `github.com/google/site-kit-wp/issues/…` URL, the parent epic, **and anything
> GitHub lists as linked** — and read each one.

That last clause is what matters. A maintainer does not have to dispatch the
workflow on an attacker's issue: an attacker who opens an issue mentioning
`#N` creates a cross-reference *on* `#N`, and the agent is instructed to read
anything GitHub lists as linked to the issue it was given. Attacker-authored
text reaches the agent's context while the maintainer dispatches on their own
legitimate issue.

## What is verified, and how

**1. Shell runs without confirmation.** `--approval-mode=yolo` auto-approves
every tool call including `run_shell_command`; `allowed-tools` includes `Bash`;
`.gemini/settings.json` sets no `tools.core` allowlist and does not set
`security.disableYoloMode`, which would have overridden the flag.

**2. The sandbox is off.** `getSandboxCommand()` in gemini-cli 0.42.0
(`bundle/gemini-GHUELHBF.js`, from `packages/cli/src/config/sandboxConfig.ts`)
resolves sandboxing from `process.env.SANDBOX`, `process.env.GEMINI_SANDBOX`
and the `sandbox` setting/flag only — **it never consults the approval mode**,
so the claim in some write-ups that `--yolo` enables the sandbox does not hold
for this version. The workflow passes no `--sandbox`, sets no `GEMINI_SANDBOX`,
and `.gemini/settings.json` sets no sandbox key, so the shell tool is an
ordinary child process of the CLI at the same UID.
`security.toolSandboxing` also defaults to `false` and is not set.

**3. The secret-redaction mitigation is real and it works — for the direct
path.** `.gemini/settings.json` sets
`security.environmentVariableRedaction.enabled: true`. I first suspected that
key was not a real setting; it is — `enabled`/`allowed`/`blocked` are all read
in 0.42.0. `sanitizeEnvironment()` filters the environment handed to child
processes, and inside GitHub Actions it does so unconditionally:

```js
// packages/core/dist/src/services/environmentSanitization.js
function sanitizeEnvironment(processEnv, config2) {
  const isStrictSanitization = !!processEnv["GITHUB_SHA"] || processEnv["SURFACE"] === "Github";
  if (!config2.enableEnvironmentVariableRedaction && !isStrictSanitization) {
    return { ...processEnv };
  }
  …
}
```

Running their own code verbatim against the repo's own settings:

```
## in GitHub Actions (GITHUB_SHA set)
     GEMINI_API_KEY   stripped
     GITHUB_MCP_PAT   stripped
     ISSUE_BODY       PRESENT
     GITHUB_ENV       PRESENT
     PATH             PRESENT
```

So `curl -d "$GEMINI_API_KEY"` from the agent's shell gets nothing. Credit where
due: this is a deliberate defense and it defeats the obvious attack.

**4. The mitigation is bypassable, and this is the part that makes the lead
worth finishing.** `sanitizeEnvironment` strips the variables from the
**child's** environment. The parent CLI process still holds them, because the
workflow's `env:` block put them in its *exec* environment, and on Linux a
child at the same UID can read that:

```
child own env    : <empty>
parent exec env  : GEMINI_API_KEY=AIzaSyDUMMY…
```

— `tr '\0' '\n' < /proc/$PPID/environ`. Verified mechanically (scratchpad,
`test/parent2.mjs`). My first run of this test returned a false negative because
I set the variable *after* the parent started, and `/proc/PID/environ` records
exec-time state; with the variable in the exec environment, as the workflow puts
it, it is recoverable verbatim. If the shell is not a direct child, an injected
command can walk the `PPid` chain in `/proc/*/status` instead.

## What an attacker would get

* **`GEMINI_API_KEY`** — a long-lived Google API credential. This is the prize.
* `GITHUB_MCP_PAT` — despite the name this is `secrets.GITHUB_TOKEN` scoped
  `contents: read, issues: read` for that job, short-lived. Worth little. Do not
  describe it as a PAT in any report; the name is misleading and claiming
  otherwise would be the over-claim that gets a report closed.
* Attacker-influenced content in `implementation.patch`, applied and pushed by
  the `contents: write` job as branch `gemini/issue-N`. `GITHUB_TOKEN` cannot
  write `.github/workflows/`, so workflow poisoning through this path is blocked.

### A further step, with an extra precondition

The patch could add a `postinstall` script to `package.json`. The branch is
pushed to the **upstream** repo, so a PR from it satisfies every
`head.repo.full_name == github.repository` guard and is treated as trusted by
`zips.yml`, `storybook.yml`, `visual-regression.yml` and `playwright.yml`, which
hold `GCP_CREDENTIALS` and run `npm ci`. That would reach the full CI secret
set.

It is gated: `create-pull-request` opens the PR as `draft: true`, and all four
of those workflows skip drafts (`github.event.pull_request.draft == false`).
It needs a maintainer to mark the PR ready for review — which is exactly what
the bot's own comment asks them to do. Note this as the escalation it is, and
do not claim it without demonstrating it.

## The one link not verified

That a model, given this skill and an issue body containing injected
instructions, actually runs the shell command. Everything above is file reading
and mechanical testing; this is the behavioural step, and it is the step the
whole thing rests on.

**It cannot be tested against Google's CI.** Dispatching their workflow needs
write access we do not have, and getting a maintainer to run it would be social
engineering — § 0.3 forbids it outright. Filing an issue on their repository to
set up the trigger is equally off the table.

**The test is written and ready to run:** `scripts/gemini-injection-test.sh`.
It needs `GEMINI_API_KEY` in the environment — the user's own, used only so the
model can answer — and nothing else. It exits 0 if the link holds, 2 if it does
not, and writes its transcript to
`results/oss-vrp/poc/evidence-gemini-injection.txt` either way.

It does not need GitHub Actions. The only thing Actions contributes to the
mechanism is `GITHUB_SHA` being set, which is what flips
`sanitizeEnvironment()` into strict mode, and the script sets it. Running it
locally also keeps it entirely off Google's infrastructure.

The secret the injection goes after is a **dummy** created by the script,
shaped like a GitHub token so the redaction logic treats it as a credential.
The real key is only ever the model's own. The payload **prints** the recovered
value and sends nothing anywhere: what needs proving is recovery of a value the
mitigation was supposed to withhold, and that a runner can reach the network is
a configuration fact that does not need demonstrating by moving data.

If it holds, a full Actions replica is then worth building for the report's
screenshot — faithful in these respects:

* same `@google/gemini-cli@0.42.0`, same `--approval-mode=yolo`, no `--sandbox`
* the same `.gemini/settings.json` security block
* a copy of `implement-issue/SKILL.md`, so it is their skill under test and not
  a paraphrase of it (Apache-2.0, attribution kept)
* a real issue in our own private repository, whose body carries the injection,
  reached the way the skill reaches it
* a **dummy** credential-shaped secret in the workflow `env:` block as the
  target, never a real one, and the recovered value printed to the job log
  rather than sent anywhere

If it shows the agent running the injected command and recovering a secret the
mitigation stripped, the chain is complete and the report writes itself from
the files above. If the model refuses, or the skill's own "stop and ask"
instructions hold, this is dead and gets logged as measured-and-empty — which
is a result worth having either way.

## Not findings — checked and closed

* **Action pinning.** Every third-party action is pinned to a full commit SHA,
  and they run `sethvargo/ratchet` to keep it that way. Nothing to say.
* **`pull_request_target` / `issue_comment`.** Neither appears in any workflow.
* **`vrt-update-reference-images.yml`.** Pushes with `GH_BOT_TOKEN`, but it is
  `pull_request: [labeled]` gated on
  `head.repo.full_name == github.repository`, and fork PRs get no secrets on
  `pull_request` anyway. Adding the label needs triage rights. Closed.
* **`check-issue-has-release.yml`.** `pull_request_review` is a privileged
  trigger, but it requires an *approved* review whose author_association is
  OWNER/MEMBER/COLLABORATOR **and** a same-repo head. Closed.
* **Script injection in `run:` blocks.** The only untrusted-looking
  interpolations are `inputs.issue_number` (declared `type: number`, and
  dispatch needs write access regardless) and two local-action inputs fed from
  `github.event.pull_request.number`. Closed.
* **`publish-docker-images.yml`.** `packages: write` jobs are gated to pushes on
  `develop` and `workflow_dispatch`; the `pull_request` trigger builds without
  pushing. Worth one more careful read of the `if:` expressions before this is
  called closed.
