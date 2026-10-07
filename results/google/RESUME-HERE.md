# RESUME HERE — the one test left, and exactly how to finish it

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
