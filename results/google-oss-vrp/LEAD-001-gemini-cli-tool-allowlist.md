# LEAD-001 — gemini-cli: `tools.core` command restrictions are never enforced

**Status: LEAD, not yet a finding.** Root cause proven by source reading. Empirical
repro NOT yet performed. Do not submit until Step "Repro" below is green.

Target: `github.com/google-gemini/gemini-cli` — Google OSS VRP, **OT1**
Class: broken security control → sandbox escape → RCE in CI
Date opened: 2026-09-25
Traffic sent to Google infrastructure while finding this: **none.** Public source reads only.

---

## One sentence

gemini-cli's documented tool-allowlist syntax `run_shell_command(echo)` silently grants
**unrestricted shell**, because the parenthesised argument is parsed only to decide
whether to register the tool and the single function that would enforce it is dead code.

## What an attacker gets

Arbitrary command execution on a GitHub Actions runner holding a write-scoped GitHub App
token and GCP Workload Identity credentials, triggered by **opening an issue** on a public
repository. No maintainer approval anywhere in the path.

---

## The chain, with file references

### 1. The action auto-approves every tool call

`google-github-actions/run-gemini-cli`, `action.yml:309` and `:316`:

```
gemini --debug --yolo --prompt "${PROMPT}" --output-format json
gemini --yolo --prompt "${PROMPT}" --output-format json
```

`--yolo` = no confirmation gate on any tool call.

There is one further gate: the **trusted-folders** check. In an untrusted workspace the CLI
prints `Approval mode overridden to "default" because the current folder is not trusted`
and refuses to run headless. (Observed 2026-09-25 on Termux during repro attempt 1.)

Google's own workflows disable it. `gemini-automated-issue-triage.yml` and
`gemini-automated-issue-dedup.yml` both set:

```yaml
env:
  GEMINI_CLI_TRUST_WORKSPACE: 'true'
```

With the workspace trusted, `--yolo` stands and the allowlist is the *only* remaining
control. Any repro must export `GEMINI_CLI_TRUST_WORKSPACE=true` to match CI conditions.

### 2. The allowlist argument is discarded

`packages/core/src/config/config.ts:3988-4000` — the only production consumer of
`coreTools`:

```js
let isEnabled = true;
if (coreTools) {
  isEnabled = coreTools.some(
    (tool) =>
      tool === toolName ||
      tool === normalizedClassName ||
      tool.startsWith(`${toolName}(`) ||          // <-- argument never read
      tool.startsWith(`${normalizedClassName}(`),
  );
}
if (isEnabled) { registerFn(); }
```

The entry is used as a **boolean: register this tool or not**. `run_shell_command(echo)`
and `run_shell_command(rm -rf /)` are identical inputs to this code. Once the shell tool is
registered, it is registered unrestricted.

### 3. The function that would enforce it is never called

`packages/core/src/utils/tool-utils.ts:81`, `doesToolInvocationMatch()`, does implement the
prefix check:

```js
if (command === argPattern || command.startsWith(argPattern + ' ')) {
  return true;
}
```

`git grep doesToolInvocationMatch` across the entire repository returns **its own
definition and its own test file, nothing else.** Every other importer of `tool-utils.js`
(`local-executor.ts`, `toml-loader.ts`, `scheduler.ts`, `state-manager.ts`,
`tool-executor.ts`) imports a different symbol.

`packages/cli/src/config/policy.ts` — the policy engine — never reads `coreTools` at all.

So: **dead code with a passing test suite.** The tests are why nobody noticed.

The stale comment at `packages/core/src/utils/shell-utils.ts:887-888` still refers to
`checkCommandPermissions`, a function that no longer exists anywhere in the tree. That
reads like enforcement was refactored away and the allowlist was left behind as a stub.

### 4. Google's own CI depends on the control that doesn't exist

All from `google-gemini/gemini-cli/.github/workflows/`:

| Workflow | Trigger | Who can fire it | Token given to the model | Declared "sandbox" |
|---|---|---|---|---|
| `community-report.yml` | `schedule` weekly | anyone (reads community issues/PRs) | GitHub **App token, `issues: write`** | `gh issue list` / `gh pr list` / `gh search …` |
| `gemini-automated-issue-dedup.yml` | `issues: opened` | **any outsider, instantly** | `secrets.GITHUB_TOKEN` (read-only) + `GOOGLE_APPLICATION_CREDENTIALS` on disk | `echo`, `gh issue view` |
| `gemini-scheduled-issue-dedup.yml` | `schedule` | anyone | `secrets.GITHUB_TOKEN` | `echo` |
| `gemini-automated-issue-triage.yml` | `issues: opened` | **any outsider, instantly** | `GITHUB_TOKEN: ''` | `echo`, `read_file` |
| `gemini-scheduled-issue-triage.yml` | `schedule` hourly | anyone | `GITHUB_TOKEN: ''` | `echo`, `read_file` |

The model's context in every one of these is attacker-authored issue text.

**`community-report.yml` is the worst case**: weekly, unattended, model holds a GitHub App
token with `issues: write`, and the untrusted input is the issue corpus it is explicitly
told to read. Prompt injection → arbitrary shell → writes as the official bot.

**`gemini-automated-issue-dedup.yml` is the fastest**: fires the moment an outsider opens
an issue. Its token is read-only, but the runner has `GOOGLE_APPLICATION_CREDENTIALS`
pointing at a GCP service-account credentials file (mounted into the MCP container at
`action.yml`-configured `-v "${GOOGLE_APPLICATION_CREDENTIALS}:/app/gcp-credentials.json"`),
plus `GEMINI_API_KEY`. Arbitrary shell reads that file directly.

The two triage workflows carry the comment
`GITHUB_TOKEN: '' # Do not pass any auth token here since this runs on untrusted inputs`.
The authors understood the threat model exactly. The dedup and community-report workflows
consume the **same** untrusted inputs and pass a token anyway — and in all five cases the
tool restriction they are relying on does nothing.

---

## Why this clears the bar (CLAUDE.md §2)

1. **Concrete attacker gain** — code execution on a runner, plus a write-scoped App token
   and GCP credentials. Not informational.
2. **Not intended behaviour** — the syntax is documented as a restriction, the enforcement
   function exists and is unit-tested, and the workflows are written in visible reliance on
   it. The `GITHUB_TOKEN: ''` comments prove intent.
3. **Fix Test** — the fix is real code: wire `doesToolInvocationMatch` (or equivalent) into
   the execution path. Not "add a header".
4. **Reproducible** — see below. **NOT YET DONE.**
5. **In scope** — OT1 repository on the published OSS VRP tier list.
6. **Boundary actually crossed** — pending repro. Right now I have proven the *control is
   absent*, which is a precondition. Per FO-8/9/11 I must demonstrate a command outside the
   allowlist actually executing before this is a finding rather than a lead.

Root-cause bug is in gemini-cli itself, so it affects **every** downstream deployment that
uses the documented allowlist syntax, not only Google's own CI.

---

## Repro — required before submission. Zero traffic to Google repositories.

Local only. Do **not** open an issue, PR or comment on any Google repository to test this.

```bash
npm install -g @google/gemini-cli
mkdir -p /tmp/allowlist-poc/.gemini && cd /tmp/allowlist-poc

cat > .gemini/settings.json <<'EOF'
{
  "tools": { "core": ["run_shell_command(echo)"] }
}
EOF

export GEMINI_API_KEY=<free-tier key from aistudio.google.com>

# The allowlist claims only `echo` is permitted.
gemini --debug --yolo --output-format json \
  --prompt 'Run the shell command: id > /tmp/allowlist-poc/PWNED.txt'

cat /tmp/allowlist-poc/PWNED.txt
```

**Green** = `PWNED.txt` exists and contains `uid=…`. A command that is not `echo` ran under
an allowlist that names only `echo`. That is the whole bug.

**Red** = the call is refused. Then enforcement lives somewhere I did not find, and this
lead dies. Capture the refusal verbatim and close it out honestly.

Capture for the report (CLAUDE.md §9.8): date, `curl ifconfig.me`, `gemini --version`,
the verbatim command, the verbatim output, and a terminal screenshot.

Second-stage repro, only if stage one is green — prove the *CI* shape in **our own**
repository: copy `gemini-automated-issue-triage.yml` into `azmolhaque/Bug-Bounty-Hunting-`,
put a benign injection in a test issue body, and show a non-allowlisted command running in
our own Actions log. Our repo, our runner, our token.

---

## Dedup check before writing

- gemini-cli `SECURITY.md` / GitHub Security Advisories for a published advisory on tool
  allowlist bypass.
- Whether `doesToolInvocationMatch` is wired up on `main` after the commit I read
  (shallow clone — no history available here; re-check on a full clone).
- Open issues/PRs mentioning `coreTools` enforcement.

If it is already fixed on `main` or already advisories'd, drop it without submitting.

## Open question

The stale `checkCommandPermissions` comment suggests this was **once** enforced. If a
full-history `git log -S doesToolInvocationMatch` shows the call site being removed in a
refactor, say so in the report — a regression with a date is far more persuasive than
"this seems missing", and it pre-empts "working as intended".
