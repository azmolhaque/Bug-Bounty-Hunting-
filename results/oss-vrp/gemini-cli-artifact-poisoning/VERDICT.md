# Verdict log — the checkout-version question that decides valid vs false-positive

Date: 2026-11-03. Researcher: cindrasec (azmolhaque).

## Why this file exists

An own-lab **fork PR** test of the reduced harness, run with the chained workflow's
checkout step written as the floating tag `actions/checkout@v5`, produced:

```
##[error]Refusing to check out fork pull request code from a 'workflow_run' workflow.
... set 'allow-unsafe-pr-checkout: true' on the actions/checkout step.
```

Taken alone that looked like the finding was a **false positive** (modern checkout
blocks the exact fork-PR→workflow_run checkout the chain relies on). Before filing,
I checked whether the *version the real repo pins* behaves the same way.

## The facts (verified read-only, 2026-11-03)

1. `google-gemini/gemini-cli@main` `.github/workflows/chained_e2e.yml` pins, on every
   e2e/evals job:
   ```
   uses: 'actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955' # ratchet:actions/checkout@v5
   with:
     ref:        '${{ needs.parse_run_context.outputs.sha }}'
     repository: '${{ needs.parse_run_context.outputs.repository }}'
     persist-credentials: false
   ```
   `allow-unsafe-pr-checkout` appears **nowhere** in the workflow.

2. The pinned SHA `08eba0b27e820071cde6df949e0beb9ba4906955` is **actions/checkout
   v4.3.0** (released 2025-08-11). Confirmed two ways: the commit itself is
   "Prepare release v4.3.0", and the `v4.3.0` release tag points to exactly this SHA.
   (The `# ratchet:...@v5` comment is stale/mislabeled — the SHA that actually runs
   is v4.3.0.)

3. The fork-PR-checkout refusal (`assertSafePrCheckout` + the `allow-unsafe-pr-checkout`
   opt-in) was added in **PR #2454, merged 2026-06-16**, first shipped in **v7.0.0**
   and **backported to v6/v5/v4** (v6 backport = PR #2500 → v6.1.0).

4. Therefore **v4.3.0 (Aug 2025) predates the refusal by ~10 months and contains no
   such check.** The floating `actions/checkout@v5` tag today resolves to a *backported,
   patched* v5.x — which is why the earlier `@v5` fork test refused. **The real repo
   does not use the floating tag; it pins the unpatched v4.3.0.**

## Consequence

- The earlier `@v5` fork-test refusal was a **false negative for the real config** — it
  tested a newer checkout than the target pins. It does NOT exonerate gemini-cli.
- With the pinned v4.3.0 and no `actions: read`, the fallback is
  `repository = github.repository` (base) and `sha = github.event.workflow_run.head_sha`
  (the fork PR's head commit). `checkout(base, fork_head_sha)` fetches the fork's
  PR-head tree because GitHub keeps the PR head commit reachable from the base repo —
  so the attacker's `package.json`/payload is what gets checked out and run, with
  `GEMINI_API_KEY` in the step env. v4.3.0 performs this checkout without objection.

## Remaining evidence-in-hand step (MUST do before filing)

Re-run the **same fork PR** with the harness's checkout step pinned to the **exact
SHA** `08eba0b27e820071cde6df949e0beb9ba4906955` (done in `chained.yml`). Expected:
the checkout now **succeeds**, `poc.js` is present, and `PoC-ACE` +
`PoC-SECRET-REACHABLE` fire — demonstrating ACE with the exact version the target
pins. Only after that log is in hand is the finding "reproduced from clean state"
per CLAUDE.md §9.4.

## RESOLVED — code-level proof (2026-11-03): the pinned version cannot refuse

`actions/checkout` `action.yml`, fetched read-only at two tags:

- **v4.3.0** (`= 08eba0b…`, the pinned SHA): **20 inputs, NO `allow-unsafe-pr-checkout`.**
  The refusal feature — and therefore the refusal code (`assertSafePrCheckout`) —
  does not exist in this version.
- **v4.4.0** (the v4-line backport of PR #2454): **21 inputs, `allow-unsafe-pr-checkout`
  present**, described as *"Required to check out fork pull request code from a workflow
  triggered by `pull_request_target` or `workflow_run`."*

So the version gemini-cli pins has no mechanism to refuse a fork-PR checkout in a
`workflow_run` context. The `@v5`-tag fork test refused only because the floating tag
resolves to a patched build that contains that mechanism. **Conclusion: this is NOT a
false positive.** The full chain is established by:
1. the earlier own-lab confirmation run (artifact flow → privileged `workflow_run`
   context → SHA/repo fallback → `npm` exec → secret in step env; `PoC-ACE` +
   `PoC-SECRET-REACHABLE` fired),
2. the `@v5` fork test, which shows the *only* thing that blocks the fork path on a
   patched checkout is that built-in refusal, and
3. this `action.yml` evidence, which shows the pinned v4.3.0 does not contain it.

Gold-standard corroboration — **DONE, confirmed 2026-11-03.** Re-fired the **same fork
PR** (zahin24, PR #3) with the lab checkout pinned to the exact SHA `08eba0b` (v4.3.0),
base at commit `c39a8b9`:

- **Chained #3** (`@v5`, patched): `e2e_linux` Checkout **REFUSED** — "Refusing to check
  out fork pull request code from a 'workflow_run' workflow" (`repository: zahin24/ap-victim`,
  `ref: 5fca7e06…`, `allow-unsafe-pr-checkout: false`). Build/test skipped.
- **Chained #4** (`@08eba0b` = v4.3.0, same fork PR): run **Success in 33s**; `e2e_linux`
  **Success in 17s** — Checkout ✓, Build project ✓ (→ `PoC-ACE`), Run E2E tests ✓
  (→ `PoC-SECRET-REACHABLE` + `PoC-CACHE-WRITTEN`).

Controlled experiment: identical chain and fork PR, only the checkout version changed →
patched refuses, pinned v4.3.0 executes fork code. The finding is empirically airtight.

## Fragility note (state honestly in any report)

The immediate exploitability rides on the old pin. A routine checkout bump (ratchet /
dependency update to any patched v4.4+/v5/v6/v7) would make checkout's own refusal
block the fork-PR path (unless they then set `allow-unsafe-pr-checkout: true`). The
**durable** root cause is the untrusted `artifact → checkout(ref,repository)` data
flow plus `GEMINI_API_KEY` exposed to attacker-controlled code; the old pin is what
makes it exploitable *today*. Report both; claim ACE+secret-reachability as proven,
runner-persistence as not demonstrated.
