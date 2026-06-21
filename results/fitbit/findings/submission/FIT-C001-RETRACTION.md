# FIT-C001 — RETRACTED (Duplicate of WAI Closure)

**Date retracted:** 2026-06-21
**Reason:** Already submitted and closed as Intended Behavior. Do not resubmit.

---

## What happened

FIT-C001 (CORS origin reflection + `credentials: true` on `accounts.fitbit.com`) was
**already submitted as Issue 518912931 on 2026-06-02** and **closed by Google VRP as
"Won't Fix (Intended Behavior)", P4.**

A later automated scan (deep-recon-orchestrator) re-surfaced the same CORS headers on
2026-06-20 and the local triage marked it "PASS — SUBMIT" **without dedup-checking the
submission history.** This is the exact failure CLAUDE.md §6 ("Dedup ruthlessly. Check
program known-issues, your own `results/`, and public CVE/changelogs") is meant to prevent.

## The triager's verdict (Issue 518912931, comment #3)

> "These endpoints are actually designed for legitimate cross-origin access, which is why
> they explicitly set those CORS headers. The presence of these headers alone, even with
> origin reflection, doesn't automatically mean it's a security flaw. To prove an issue here,
> you'd need to show a concrete attack scenario where an attacker can actually exploit this
> to compromise sensitive user data or perform actions on a victim's behalf. Simply changing
> the Origin header usually isn't enough."

Both `accounts.fitbit.com` and `dev.fitbit.com` were named in the original report and both
were covered by the WAI closure.

## Why the finding never cleared the bar

For a credentialed-CORS reflection to be valid, you must demonstrate **all** of:

1. Reflected arbitrary origin + `Access-Control-Allow-Credentials: true` — ✅ confirmed (headers)
2. An endpoint that returns **sensitive, session-gated data** — ❌ never confirmed
3. That endpoint **actually returning that data** cross-origin with the victim's cookies — ❌ failed
4. Attacker JS reading it — ❌ not demonstrated

The browser PoC (`fetch('https://accounts.fitbit.com/api/1/user/-/profile.json', {credentials:'include'})`)
returned an **HTML login page** (`SyntaxError: Unexpected token '<'`), not profile JSON.
The curl "Endpoint 3" test returned HTTP 200 with a **fake** session cookie — a strong
signal that the path is a catch-all serving the login HTML, not a real authenticated data
endpoint. Fitbit's actual data API is on `api.fitbit.com`, not `accounts.fitbit.com`.

The two endpoints where CORS is definitively confirmed both serve non-sensitive or
non-cookie-gated data:
- `/.well-known/openid-configuration` → public by design
- `/oauth2/token` → gated by an authorization code in the request body, not by cookies

This lands on CLAUDE.md §3 hard-reject: "CORS permissive on endpoints returning no
sensitive data."

## The ONLY revival path (low expected value)

Find an endpoint on `accounts.fitbit.com` or `dev.fitbit.com` that, when called
cross-origin with a real active session cookie, returns **real session-gated sensitive
JSON** (a developer's OAuth app client secrets on dev.fitbit.com would be the highest-value
candidate). Then the cross-origin read is a concrete data-exfil scenario meeting the
triager's stated bar.

**However:** Google has already declared the CORS config on both hosts intended. Even a
data-returning endpoint would have to be argued as *unintended* against an explicit WAI.
Expected value is low. Recommend pivoting to a fresh target unless a session-gated JSON
endpoint on dev.fitbit.com is found quickly.

## Process fix

Before any future submission, grep `results/**` and the issue tracker for the host +
vulnerability class. Automated re-discovery is NOT a new finding until dedup passes.
