# RESUME HERE

**State at 2026-10-30.** Read this block first; everything below it is an older
thread, still open but not where today ended.

---

## What happened on 2026-10-29/30

Two confirmed findings in `google/site-kit-wp` 1.190.0 (`8cf47de`), both
unrefuted, both currently unpayable:

| | finding | class | status |
|---|---|---|---|
| 01 | Site Goals: a view-only Dashboard Sharing user writes a site-wide option | CWE-862 | filed to OSS VRP, closed `Won't fix (Infeasible)` |
| 02 | `admin_action_googlesitekit_go` has no nonce; one link re-enables the Analytics tag | CWE-352 | never filed |

Report 01 is `issuetracker.google.com/issues/579506120`. It was **not** closed on
merit — Google paused OSS VRP product-vulnerability intake on 2026-10-01 and
takes supply-chain reports only, until at least Q1 2027. The technical question
was never reached. Report 02 was held rather than filed into the same wall.

**Every channel for these two is closed:**

* OSS VRP — product vulnerabilities not accepted until Q1 2027 at the earliest.
* Wordfence — barred three times over: *All Google Products* is on the
  out-of-scope asset list, *Cross-Site Request Forgery* and *Missing
  Authorization* are both named in the out-of-scope class list, and finding 01's
  Contributor requirement is excluded again as mid-level authentication. No CVE
  either. Submitting would spend the New Researcher throttle budget for nothing.
* Patchstack — unchecked. Get their out-of-scope lists **before** writing
  anything; the same two classes are what such programmes exclude.

**The CI supply-chain lead is closed, measured and empty.**
`results/oss-vrp/LEAD-sitekit-ci-gemini-injection.md` has the full reasoning.
Short version: `gemini.yml` runs an agent with `--approval-mode=yolo`, but
`security.folderTrust.enabled` defaults to `true` in gemini-cli 0.42.0 and
nothing in that workflow disables it, so the checkout is untrusted, yolo is
overridden, and the step cannot run at all. Confirmed by running it on a host
with no `~/.gemini/settings.json`, outside `$HOME` — matching a clean runner on
both counts. The rest of the CI surface is measured too: no
`pull_request_target`, no `issue_comment`, every action SHA-pinned with
`ratchet` enforcing it, fork guards throughout, and
`publish-docker-images.yml` never logs in to the registry on a pull request.

## The two things left to do

1. **Upstream disclosure, unpaid — drafts not yet written.** Send findings 01
   and 02 through the channel `SECURITY.md` names (Google's own close also
   invited a public GitHub issue). Source-verified write-ups to build from:
   `results/oss-vrp/wordfence/01-missing-authorization.md` and
   `02-csrf-module-activation.md` — every specific in them was re-checked
   against `8cf47de` on 2026-10-30 and five errors from earlier drafts were
   corrected. Include, separately and as a hardening note rather than a claim,
   that `gemini.yml` cannot work as written and that both obvious fixes
   (`--skip-trust`, `GEMINI_CLI_TRUST_WORKSPACE=true`) would hand an agent with
   yolo, shell access and `GEMINI_API_KEY` a task built from attacker-authored
   issue text.

2. **A new target for supply-chain work.** It is the only open paying channel.
   Work down `oss-repository-tier/README.md` for OT0/OT1 repositories that have
   a real release pipeline, and look where site-kit-wp was strong — SHA
   pinning, fork guards, folder trust — because that is what most repositories
   get wrong.

## Carry-overs, still not done

* `intrinsic.dev` was never enumerated (crt.sh 502, certspotter 429 twice).
  That is **not** "no subdomains".
* The Gemini CLI `GEMINI.md` test on the phone: PoC at `~/gcli-md-poc/GEMINI.md`.
  Note the hazard recorded on 2026-10-28 — the phone's
  `~/.gemini/trustedFolders.json` trusts all of `$HOME`, so any trust test
  under `~` answers a different question. Run it outside `$HOME`.
* `scripts/gemini-injection-test.sh` phase B never reached the model (API
  returned `402`, no credits). Moot for the closed lead, but if that half is
  ever wanted, it needs billing on the key.

## One habit worth keeping

My harness twice reported "the agent did not run the injected command" when the
model had never been reached — once folder trust, once the 402. Both times the
bug was reading absence of positive evidence as a negative result. A test must
prove its subject was actually exercised before it is allowed a verdict.

---

# (earlier thread) RESUME HERE — the one test left, and exactly how to finish it

**State at 2026-10-08 05:07 +06.** Everything below is set up; only one step is missing.

---

## The question, in one line

Does Fitbit check the `aud` claim of a Google ID token before trusting it?

If it does not, then any website with "Sign in with Google" can take a visitor's ID token and replay
it into Fitbit's `social` grant — authenticating with the client secret published on
`accounts.fitbit.com` — and receive that visitor's Fitbit token. That is account takeover, and the
published secret is the link that makes it reachable from outside.

## What is already established

```
social grant reached with the published secret   ->  "Social account not linked to email"
```

That is **not** an audience rejection. Fitbit accepted the token, parsed it, read the email out of
it, and stopped at account linkage — a step that comes *after* token validation. A server verifying
the ID token properly (signature + `aud` + `iss` + `exp`, the standard library call) would have
refused before ever looking at the email.

So there is still **no evidence** the `aud` claim is checked, and the Playground-issued token's
`aud` is `407408718192.apps.googleusercontent.com` — Google's Playground, not Fitbit.

## Why it stalled

The Fitbit test account (`azmol01717534550@gmail.com`) was created with **email and password**, not
with Google. So no social link exists for the grant to find. Fitbit's web settings expose no
"Connected accounts" control, so the link cannot be added to the existing account.

## The missing step

A Fitbit account that **is** Google-linked, created by signing up with "Continue with Google" using a
Google account that has no Fitbit account yet.

---

## Resume checklist

```
1. Fitbit: log out.  accounts.fitbit.com -> "Continue with Google"
   Use a Google account you own that has NO Fitbit account yet.
   Finish signup. Confirm fitbit.com/dashboard loads as that account.

2. developers.google.com/oauthplayground
   Step 1 -> "Input your own scopes" box -> openid email profile
   -> Authorize APIs -> sign in AS THAT SAME GOOGLE ACCOUNT
   -> Exchange authorization code for tokens
   NOTE: the code is single use. If it says invalid_grant, go back to Step 1 and
   press Authorize APIs again rather than Exchange.

3. cd ~/bbh && bash scripts/g-social.sh
   Paste the whole response, Enter, Ctrl+D.
```

### Reading the result

```
access_token returned
    -> Fitbit accepted a token issued for a DIFFERENT OAuth client.
       STOP. Run nothing else, call no API with it. That one response is the
       whole proof, and the report is rewritten as account takeover.

"invalid token" / "audience" / "client mismatch"
    -> the audience IS validated. Path A closes by test, not by assumption.
       Record the exact wording; it goes in the write-up as a checked bound.

"not linked" again
    -> the signup did not actually link Google. Redo step 1.
```

## Rules that still apply

Only accounts we own, on both sides. One request. No second password, no other person's identifier,
no list, no retry. If the token is accepted, it is never used.

## If this closes negative

Then `G-F001` stays PARKED exactly as written, and the night's conclusion stands: the published
secrets are a real misconfiguration that Fitbit's own documentation forbids, but they unlock nothing
an attacker could not already attempt, so there is no payable impact. That is a finished answer, not
a loose end.
