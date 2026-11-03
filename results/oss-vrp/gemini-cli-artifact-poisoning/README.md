# gemini-cli artifact-poisoning — lab harness + report (কেমনে কি করবো)

Everything here runs **only in your own throwaway repos**, with a **fake** secret,
with **zero** contact with `google-gemini/gemini-cli` or any Google system. It
proves the mechanism end-to-end so the report claims only what you have shown.

What you will demonstrate, in order of certainty:
1. **ACE** — attacker-defined code runs in the privileged `workflow_run` job.
2. **Secret disclosure** — `FAKE_SECRET` (mirrors `GEMINI_API_KEY`) is reachable by that code.
3. **Cache poisoning → build integrity** — a later *trusted* build restores an
   attacker-produced layer from the default-branch gha cache.

Claim 1 and 2 are rock-solid. Claim 3 is proven **iff** your run shows the two
provenance strings match (see step 5); if it doesn't cleanly match in your lab,
drop it to the "potential" section of the report rather than overclaiming.

---

## Prerequisites
- A **throwaway** GitHub account. Classic PAT with scopes `repo`, `workflow`.
- `gh` CLI, or just the GitHub web UI.
- Nothing else — jobs run on free GitHub-hosted runners.

## Step 1 — create the victim repo (the privileged chain)
```bash
# in a scratch dir
mkdir victim && cd victim && git init -b main
cp -r <this-dir>/repro-harness/. .
# include the attacker payload on the default branch too, so a same-repo PR can run it
cp <this-dir>/attacker-fork/package.json <this-dir>/attacker-fork/poc.js .
git add . && git commit -m "harness"
gh repo create <you>/ap-victim --private --source=. --push
```

## Step 2 — add the fake secret (mirrors GEMINI_API_KEY)
```bash
echo "poc-fake-$RANDOM" | gh secret set FAKE_SECRET --repo <you>/ap-victim
```

## Step 3 — fire the chain with a PR
Faithful mode is a **cross-fork** PR (head repo = a *fork*). The fullest repro:
- From a **second** throwaway account, fork `<you>/ap-victim`, change `poc.js`
  (e.g. add another `notice(...)`), and open a PR against `<you>/ap-victim`.
- `Trigger` runs unprivileged on the fork PR and uploads the `repo_name` artifact
  carrying the **fork's** repo/sha.
- `Chained` then fires on `workflow_run`, checks out the **fork**, and runs its
  `poc.js`.

Single-account fallback (still exercises trigger→artifact→workflow_run→checkout→exec):
```bash
git checkout -b poc && git commit --allow-empty -m "poc" && git push -u origin poc
gh pr create --repo <you>/ap-victim --base main --head poc --title "PoC" --body "benign"
```

## Step 4 — read the Chained run log
Look for, in order:
- `PoC-ACE` — ACE confirmed.
- `PoC-SECRET-REACHABLE :: ... len=.. sha256_prefix=..` — secret disclosure confirmed.
- `PoC-CACHE-WRITTEN :: attacker layer provenance="built-at-<X>"` — note `<X>`.

Screenshot this log. It is your demonstrated-execution evidence.

## Step 5 — prove the cache poisoning (the escalation)
Run the victim legit build, which shares the default-branch gha cache scope:
```bash
gh workflow run "Legit Build (victim)" --repo <you>/ap-victim
# then open the run and read the log
```
Find `LEGIT-BUILD-PROVENANCE :: built-at-<Y>`.
- **`<Y>` == `<X>`** → the *trusted* build restored the **attacker-produced** cache
  layer. Build-integrity compromise proven — claim it.
- **`<Y>` != `<X>`** (fresh value) → buildx did not serve the poisoned layer in your
  lab (cache scope/key difference). Do **not** claim it as proven; cite it as the
  documented potential instead.

## Step 6 — confirm the live config is still present (read-only)
On a networked machine, run `Detect-ArtifactPoisoning.ps1`, paste the 10/10 table
and the **current** HEAD SHA into the report. (Independently verified present at
`0ac57c029b848d109eef940afe0db4b5a0c3dad0` on 2026-11-03; re-confirm at filing time.)

## Step 7 — clean up
```bash
gh repo delete <you>/ap-victim --yes
# delete the fork repo too, then revoke the throwaway PAT in GitHub settings
```

---

## Do NOT
- Do not open a PR against `google-gemini/gemini-cli` or run anything on Google's
  runners. The real jobs are gated `if: github.repository == 'google-gemini/gemini-cli'`,
  so a plain fork can't run them anyway; attempting live exfil of Google's secret
  would breach the rules and void Safe Harbor. The reduced harness proves the
  mechanism without any of that.
- Do not attach any output from the real repo/runners to the report — only the
  read-only detector output and this own-lab reproduction.
