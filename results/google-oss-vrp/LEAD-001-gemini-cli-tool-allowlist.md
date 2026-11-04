# LEAD-001 — gemini-cli: `tools.core` command restrictions are never enforced

**STATUS: CLOSED — FALSE ALARM. 2026-09-25. Do not submit. See "Closure" at the bottom.**

The repro came back RED. The allowlist **is** enforced, by the policy engine, and my
analysis below reached the opposite conclusion from an incomplete grep. The chain
reasoning is kept as a record of the error, not as a live lead.

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

---

# Closure — 2026-09-25. RED. Lead is dead.

## The repro output

Termux, `~/allowlist-poc`, `.gemini/settings.json` confirmed written as
`{ "tools": { "core": ["run_shell_command(echo)"] } }`, `GEMINI_CLI_TRUST_WORKSPACE=true`,
`gemini --debug --yolo --output-format json --prompt 'Run the shell command: id'`.

The model did emit the tool call (`"command":"id"`, `"approvalMode":"yolo"`), and it was
denied before execution:

```
[PolicyEngine.check] toolCall.name: run_shell_command, stringifiedArgs: {"command":"id",...}
[PolicyEngine.check] MATCHED rule: toolName=*, decision=deny, priority=4.24, argsPattern=none
[PolicyEngine.check] Validating shell command: 1 parts
...
"response": {"error": "Tool execution denied by policy."}
"errorType": "policy_violation"
```

Final answer: `"The command could not be executed because it was denied by security policy."`
Tool stats: `totalCalls: 1, totalSuccess: 0, totalFail: 1`.

The catch-all `toolName=*, decision=deny` rule is exactly the "narrowing" deny that gets
installed when an allowlist entry carries an argument. `id` matched no ALLOW rule, so it
fell through to that deny. The control works as documented.

## Where the enforcement actually lives

`packages/core/src/policy/config.ts:445`, `mapToolsToRules`:

```js
const match = tool.match(/^([a-zA-Z0-9_-]+)\((.*)\)$/);
if (match) {
  const [, rawToolName, args] = match;
  const toolName = SHELL_TOOL_NAMES.includes(rawToolName) ? SHELL_TOOL_NAME : rawToolName;
  if (toolName === SHELL_TOOL_NAME) {
    toolsWithNarrowing.add(toolName);
    const patterns = buildArgsPatterns(undefined, args);
    for (const pattern of patterns) {
      if (pattern) {
        rules.push({ toolName, decision: PolicyDecision.ALLOW, priority,
                     argsPattern: new RegExp(pattern), source, modes });
      }
    }
  }
  ...
```

The parenthesised argument **is** read. It becomes an `argsPattern` regex on an ALLOW rule,
plus a default deny for that tool. `policy-engine.ts:215` applies the pattern at check time.

## What I got wrong, precisely

Three claims in the analysis above, in the order they failed:

1. **"`config.ts:3994` is the only production code that reads `coreTools`."** False. It is
   the only code that reads it *for tool registration*. `packages/core/src/policy/config.ts`
   reads it for *enforcement*. Registration and authorisation are two different layers and I
   collapsed them.

2. **"The policy engine never reads `coreTools`."** This is the error that mattered. I
   grepped exactly one file — `packages/cli/src/config/policy.ts` — found no `coreTools`,
   and generalised to "the policy engine". The real conversion is in a *different file of
   the same name* in a *different package*: `packages/core/src/policy/config.ts`. I searched
   for a concept by guessing a filename instead of by following the data.

3. **"`doesToolInvocationMatch` is dead code, therefore nothing enforces the prefix."** The
   dead-code observation was correct and verified. The inference from it was not. Dead code
   at one call site says nothing about whether the control exists elsewhere — and here it
   had simply moved to the policy engine. Absence of evidence in the place I looked.

The `--yolo` finding and the `GEMINI_CLI_TRUST_WORKSPACE: 'true'` observation were both
accurate. They just don't matter, because the layer underneath them holds.

## What was actually good here

The workflow reading in `H11-ACTIONS-RUNLOG.md` stands. So does the scanner blind spot —
filtering on trigger name does miss `schedule`-triggered jobs that ingest issue text, and
that remains a real gap in the tooling. The specific bug it pointed at was not a bug.

## Rules earned (fold into METHODOLOGY.md)

**FO-16 — A negative grep is not a negative. It is one place you looked.**
"Function X is never called" and "setting Y is never read" are claims about *your search*,
not about the program. Before building a finding on an absent control, follow the data
forward from where it is *defined* to every place it is *consumed* — do not search for the
control by guessing the filename it ought to live in. Same-named files in different
packages (`cli/src/config/policy.ts` vs `core/src/policy/config.ts`) are exactly how this
goes wrong.

**FO-17 — Run the repro before writing the report, not after.**
LEAD-001 was written up at length, committed, pushed, and presented to the operator on
static reading alone, with the repro left as a to-do. The repro took ninety seconds and
killed it. When a claim is cheaply testable, test it *first*; a write-up produced ahead of
its own verification will rationalise toward the exciting answer. The lead was correctly
labelled LEAD rather than FINDING and nothing was submitted — that part of the process
worked. The effort ordering did not.
