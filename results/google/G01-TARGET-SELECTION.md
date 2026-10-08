# G01 — Google VRP target selection, from Google's own tier list

**Date:** 2026-10-08 · **Source:** `github.com/google/bughunters` (cloned and read, not summarised
from memory or from an AI answer).

---

## The headline: the tier list is worth more than synthid.com

Google publishes `domain-tiers/external_domains_google.asciipb` (2,346 lines) and
`external_domains_acquisitions.asciipb` (4,144 lines) — every domain they consider sensitive, with
its tier. That is a map of **where Google pays**, published by Google. It is the single best target
selector we have had in this engagement, and it is better than anything we could have enumerated
ourselves.

```
GOOGLE          TIER0  39   TIER1  69   TIER2 272   TIER3 109   TIER4 101
ACQUISITIONS    TIER0  52   TIER1 145   TIER2 223   TIER3 388   TIER4 220
```

## First consequence: synthid.com is a reward risk, not just a scope question

`synthid.com` appears in **neither** list. That matters more than it first looks, because two rules
bite:

- Google VRP: *"applications on TIER4 domains are not in scope for Google VRP."*
- AI VRP "Other" product tier **explicitly excludes** *"Tier3 or Tier4 acquisitions"* and
  *"other Tier 3 or Tier 4 applications"*.
- And the tier README: *"Acquisition domains... If the domain is not explicitly tiered, TIER4 is
  assumed."* SynthID is a DeepMind (acquisition) product.

The published lists are redacted and update weekly, so absence is not proof. But the asymmetry is
ugly: a valid, well-written bug on an untiered domain can pay **nothing**. The rules themselves give
the remedy — *"If in doubt, talk to us first!"* — and asking costs an email and no research time.

**Do not invest hours in synthid.com before its tier is confirmed.**

## Second consequence: the AI VRP reward table makes the class choice for us

```
Category                              Flagship   Standard   Other
S1 Rogue Actions                      $20,000    $15,000    $10,000
S2 Sensitive Data Exfiltration        $15,000    $15,000    $10,000
A1 Phishing Enablement                 $5,000       $500    credit
A4 Access Control Bypass (limited)     $2,500       $250    credit
A5 Unauthorized Product Usage          $1,000       $100    credit
```

On a non-Flagship product, everything below S1/S2 pays **credit only**. So on an AI target the only
classes worth the time are *rogue action* and *sensitive data exfiltration* — both of which require
a cross-account victim. Google states the method itself: *"try to exfiltrate non-shared data from
your second test account isolated from the first one."*

## Third consequence: Google's IDOR rule kills ID-guessing before we start

> *"there also needs to be a clear path for the attacker to DISCOVER the needed ID... reports
> describing vulnerabilities based on guessing complex random IDs are almost always not eligible."*

This is the Tesla `InstallationGUID` wall as written policy. On any upload or object surface the
**first** observation must be the shape of the id. Long random → drop in minutes.

---

## Candidate targets, ranked — tiered (so the payout is defined), small, self-serve

Nothing below has been touched. These are selection candidates, to be liveness-checked first.

### A. Acquisition TIER0 infrastructure hosts — highest value, cheapest to check

`photomath.net` carries a cluster of **TIER0** operational hosts:

```
metabase.photomath.net          dpcapi-admin.photomath.net     daportal.photomath.net
argocd-platform-eu-dev          argocd-gke-app-eu-prod         argocd-gke-app-us-prod
argocd-dwh-eu-dev               argocd-gke-app-eu-test         argocd-gke-app-us-test
taportal / lapi / tlapi / baja / cuvar / mankey / zuja .photomath.net
```

ArgoCD and Metabase are named products with a history of authentication-bypass CVEs, and Google
tiers these TIER0 — the tier where *"a critical vulnerability could lead to a compromise of a user's
account or execution of code"*. Most are probably VPN-bound, which is exactly why a liveness sweep
is the right first move: it is cheap, non-touching, and the downside is a tidy negative.

Also TIER0 and self-serve: `online.cameyo.com`, `marketplace.cameyo.com`, `cameyo.com`,
`www.appsheet.com`, `api.appsheet.com`, `eu.appsheet.com`.
Note we have already worked both Cameyo and AppSheet and both closed — but both closed on the
*class* (informational `/about`, intended connector behaviour), not on the target. TIER0 says a real
boundary break on either pays well.

### B. Google TIER1, small products with free signup and shared objects

```
threadit.app / threadit.area120.com    Area 120 video messaging — threads are shared between
                                       users, so objects cross an account boundary by design
enexpress.app                          Area 120, unknown, worth one probe
signals.area120.com                    Area 120
orionwifi.area120.com                  Area 120
baseline.google.com                    has a separate admin.baseline.google.com AND a
admin.baseline.google.com              baseline.sandbox.google.com — admin + sandbox + prod is
baseline.sandbox.google.com            the shape where tenant separation goes wrong
connected.google.com                   TIER1, little-known
businessmessages.google.com            TIER1, free developer signup
hume.google.com                        TIER1, little-known
```

Caveat: several Area 120 products were shut down in 2023. Liveness first, always.

### C. Google TIER0, small surface

```
googlecloudcheatsheet.withgoogle.com   TIER0 on a tiny app — unusual pairing, worth a look
flash.android.com                      Android Flash Tool, WebUSB, free
console.actions.google.com             free developer console
remotedesktop.google.com               free, cross-device by design
```

### Not now
`wiz.io` is TIER1 in Google's own list, but the acquisition blackout (*"newly acquired companies are
subject to a six-month blackout period"*) may still apply, and we have prior history there.

---

## Eligibility, checked

Bangladesh is not on the VRP sanctions list (Cuba, Iran, North Korea, Syria, Crimea, DNR/LNR,
plus Russia and Belarus for administrative reasons). Participation requires age 18+. Rewards can be
paid. **He is eligible.**

## Next action

A liveness sweep over the candidates above — status, size, redirect target, server — nothing more.
No paths invented, no scanning, no volume. The sweep decides which of these is a real application
before a single hour goes into any of them.

---

## Liveness sweep — 2026-10-08, run from Termux

```
HOST                                   IP                RESULT
metabase.photomath.net                 NO-DNS
dpcapi-admin.photomath.net             NO-DNS
daportal.photomath.net                 NO-DNS
taportal.photomath.net                 NO-DNS
argocd-platform-eu-dev.photomath.net   NO-DNS
argocd-dwh-eu-dev.photomath.net        NO-DNS
argocd-gke-app-eu-prod.photomath.net   34.149.138.245    302 -> Google IAP (client_id 867278860234-g77td6ok…)
argocd-gke-app-us-prod.photomath.net   34.149.22.195     302 -> same IAP client_id
lapi.photomath.net                     34.149.49.67      404  21b
tlapi.photomath.net                    35.190.29.4       403 134b
threadit.app                           172.217.26.110    301 -> threadit.area120.com
threadit.area120.com                   142.250.182.238   200 12866b   <title>Threadit</title>
signals.area120.com                    8.232.133.29      200   965b   <title>Demand Signals</title>
orionwifi.area120.com                  172.217.26.46     404 1561b
baseline.google.com                    NO-DNS
admin.baseline.google.com              NO-DNS
connected.google.com                   192.178.177.113   404 1561b
hume.google.com                        192.178.158.113   307 -> accounts.google.com ServiceLogin
googlecloudcheatsheet.withgoogle.com   192.178.177.141   302 -> cloud.google.com/products/
zzz-canary-does-not-exist.photomath.net  NO-DNS                        <- SENTINEL
zzz-canary-does-not-exist.area120.com  142.250.122.100   404 1561b     <- SENTINEL
```

### The area120 sentinel is what makes this readable

`*.area120.com` has **wildcard DNS**, and a hostname that does not exist answers `404 1561b`. So:

```
orionwifi.area120.com   404 1561b   identical to the canary  -> no application
connected.google.com    404 1561b   same shape               -> no application
threadit.area120.com    200 12866b  nothing like the canary  -> real application
signals.area120.com     200   965b  nothing like the canary  -> real application
```

Without the canary, `orionwifi` and `connected` would have been read as "deployed but protected" and
chased. `photomath.net` has **no** wildcard (its canary is NO-DNS), so `lapi` and `tlapi` genuinely
exist.

### Both TIER0 photomath hosts are closed — killed in two minutes

```
lapi   body: "default backend - 404"      (text/plain, 21 b)
tlapi  body: "<title>403</title>403 Forbidden"  (GFE-style minimal HTML, 134 b)

path         lapi            tlapi
/            404 21b         403 134b
/zzz-canary  404 21b         403 134b     <- CONTROL: identical
/health      404 21b         403 134b
/api         404 21b         403 134b
/v1          404 21b         403 134b
```

`default backend - 404` is the GKE ingress default backend: the hostname resolves to a load
balancer, but **no ingress rule routes it**, so there is no application behind it. `tlapi`'s 403 is
identical on every path including a canary path, so it is a blanket edge rule, not an app. Neither
is the T04 "shadow API" shape — there is nothing deployed to find. **Dropped.**

### Survivors

```
threadit.area120.com   TIER1   live, 12.8 KB, "Threadit" (Area 120 async video messaging)
signals.area120.com    TIER1   live, 965 B,  "Demand Signals"
hume.google.com        TIER1   Google sign-in, unexamined
```

Two live TIER1 applications on obscure Area 120 hostnames is exactly the profile the target filter
was looking for: small, tiered (so a reward is defined), and far off the path most hunters walk.
Open question before any effort goes in: does either still accept a free self-serve signup, and does
either hold objects shared between users? Area 120 wound down several products in 2023, and a title
tag does not prove a working product.

---

## Both survivors are closed. The filter was applied in the wrong order.

### threadit.area120.com — dead product

The page says it in red: *"Threadit.app is no longer in service. The Threadit Area 120 team has been
acquired by Google Workspace to help support async video efforts."* The HTML is a static memorial
page — images only, no bundle, no signup. **Dropped.**

### signals.area120.com — allowlist, and a paid one

Live Angular SPA. The JS says what it is:

```
/js/firebase.js  /js/bundle.js  /js/papaparse.js
endpoints:  identitytoolkit + securetoken.googleapis.com     <- Firebase AUTH only
            apis.google.com/js/client.js                      <- gapi
            staging-dot-signals-public.appspot.com            <- GAE backend, project "signals-public"
clientId:   27895279838-2u1sfrbmv0cu7t58c1ihq5eouimp8oo6.apps.googleusercontent.com
            708042167689-s01vdaf0j8m12ugub9lig6jjeoe3n0u5.apps.googleusercontent.com
```

No `firebaseio.com`, no `firestore`, no `collection(...)` anywhere in 578 KB of bundle. Firebase is
used **for authentication only**, so the "loose Firestore rules" hypothesis does not apply here and
was dropped before any time went into it.

Signing in with a dedicated test Google account returns:

```
User not authorized. Contact the Demand team to get access.
```

and the footer reads *"to manage your subscription to Signals or delete your account, use the GCP
Marketplace console"*. It is an allowlisted, paid GCP Marketplace product. **Dropped** — this is the
Tesla `InstallationGUID` / Marriott confirmation-number wall again: access obtainable only by being
a paying customer.

One angle was considered and rejected: the "not authorized" message is rendered by the SPA, so the
server may or may not enforce it, and a client-only check would be a clean authorisation bypass.
Testing it means driving the GAE backend directly with a captured OAuth token — and `*.appspot.com`
is on the VRP's own non-qualifying list. Not worth it on a phone, and not worth it against an
explicitly excluded host.

### The process lesson

Liveness was checked first and the access model second. That is backwards. Of the twenty-two hosts
swept, the ones that died did so for three reasons, and only one of them needed a network request:

```
no DNS / wildcard-identical     12   needs a sweep
dead product                     1   needs one page load
allowlist or paid access         1   needs one sign-in      <- cheapest signal, checked last
behind IAP / Google sign-in      3
```

**Access model first, liveness second.** A host that cannot be signed into by a free account is
useless to us however alive it is, and that is one page load to find out.

## Next queue — filtered on access model first

From Google's TIER2 list (272 entries, far less contested than TIER0/1), the candidates that take a
free self-serve Google account, hold objects the user creates, and share them between users:

```
code.earthengine.google.com     free signup; user scripts, assets and sharing ACLs; genuinely
signup.earthengine.google.com   off the usual path
datastudio.google.com           Looker Studio: reports and data sources with sharing ACLs, free
cse.google.com                  Programmable Search Engine: own search engines, own ids, free
merchants.google.com            Merchant Center: free, multi-tenant, self-minted product ids
crowdsource.google.com          free, user contributions
recorder.google.com             free, recordings shared by link
classroom.google.com            classes, assignments, submissions — real cross-role multi-tenancy
```

Known dead or sunset, do not sweep: `poly`, `fusiontables`, `appmaker`, `aboutme`, `plus`,
`profiles`, `optimize`, `jamboard`.

Before touching Colab, read `bughunters/articles/learn/invalid-reports/ai-products/
ai-first-colab-known-issues.md` — Google publishes a known-issues page for it, which is a dedup list
handed to us for free.

---

# Addendum — terminal-only avenues, 2026-10-08 05:30

Three things were testable without a browser. Two closed; one strengthened the write-up.

## The second client unlocks the same grants — and it has no excuse

`227ZG3` is "Social Feed Moderation Application", a staff tool, not a sign-in page.

```
[SENTINEL] zzz_not_a_real_grant   unsupported_grant_type
           password               invalid_grant  "Invalid username/password"
           social                 invalid_request "Missing required parameter googleAccessToken"
           mfa_sms                invalid_token   "MFA token invalid"
```

Identical to `228TQD`. This matters for the argument: Fitbit can say a sign-in page necessarily
carries a browser-side credential. **A staff moderation console cannot make that claim**, and its
published secret opens the same password, social and MFA grants.

## Internet Archive over the acquisitions — the Tesla technique, run and closed

Ten apexes, CDX, filtered for config-shaped paths. The script checks for CDX returning an HTML error
page rather than data, because that silently corrupted a count during the Tesla engagement.

```
fitbit.com     40000 urls    0 config-shaped      looker.com    40000   16
nest.com       40000           6                  mandiant.com  40000    0
nestlabs.com    2649           0                  cameyo.com    26367    9
waze.com       40000           0                  pring.jp        800    0
appsheet.com   40000           3                  photomath.net  8023    0
```

Twelve candidates re-fetched live. Everything 301/302 except two:

```
https://adpc.cameyo.com/.env              200  16236b
https://bhisd.cameyo.com/custom/.env      200  16236b
```

Identical byte counts on different hosts and paths — which is the tell, not the find. The canary
settles it:

```
https://adpc.cameyo.com/zzz-canary-7x2            200  16236b   <- IDENTICAL
https://bhisd.cameyo.com/custom/zzz-canary-7x2    200  16236b   <- IDENTICAL
body: "<!DOCTYPE html> ... <meta name=\"author\" content=\"Cameyo\">"
```

Catch-all routing serving Cameyo's own HTML page for any unknown path. No `.env` exists. `cameyo.com`
is TIER0, so a real one would have mattered; this is not one. **Closed.**

Tesla's archive technique did not repeat here. Running it was still correct — it is cheap, it is
non-touching, and the alternative was assuming.

## Where the night ends

```
G-F001   PARKED. Two live OAuth client secrets, verified, Fitbit's own docs forbid
         the practice, and both clients' full grant surface mapped. No payable
         impact demonstrated: every grant still needs a key the secret does not give.

OPEN     One test, in results/google/RESUME-HERE.md — whether Fitbit validates the
         aud claim of a Google ID token. Blocked only on needing a Fitbit account
         that was created through "Continue with Google".
```

Nothing was submitted. Fourteen probes, and the ones that mattered most were the ones that killed a
conclusion rather than supported one.

---

# Addendum — the Google-owned half of the tier list, 2026-10-08

Google publishes two tier lists. The Fitbit secrets came out of the acquisitions half; this is the
other half, 380 TIER0/1/2 Google-owned domains plus 26 per-apex sentinels, 406 rows.

Fifty-two answered 200. All fifty-two scanned for credentials in page source **and** in up to four
same-origin JS bundles each, with URL-encoded config blobs decoded.

```
>>> accounts.fitbit.com          CONTROL   LEAKS   basicToken -> 228TQD:7659f9…744a
>>> feed-moderation.fitbit.com   CONTROL   LEAKS   clientId   -> 227ZG3:458dd4…196d

    bughunters.google.com        TIER0     clean       remotedesktop.google.com  TIER0  clean
    gemini.google.com            TIER0     clean       flash.android.com         TIER0  clean
    www.google.com               TIER1     clean       m.youtube.com             TIER1  clean
    messages.google.com          TIER1     clean       myactivity.google.com     TIER1  clean
    legalretrievals.google       TIER1     clean       partners.cloud.google.com TIER1  clean
    clients3.google.com          TIER1     clean       signals.area120.com       TIER1  clean
    threadit.area120.com         TIER1     clean
    … 39 more TIER2 hosts, all clean
```

**The controls lighting up is what makes "clean" mean anything here.** The same scanner, in the same
run, finds both known secrets. So the fifty-two negatives are real negatives, not a repeat of
probe7's broken pattern-match.

**Google's own properties are clean. The leak is confined to Fitbit.** That is worth knowing for the
report: it is not a Google-wide build convention, it is two Fitbit applications — which is both a
narrower claim and a more credible one.

## State of play

```
DONE     acquisitions tier list swept, credentials found (G-F001, parked)
DONE     Google-owned tier list swept, nothing found
DONE     Internet Archive over 10 acquisition apexes, nothing found
OPEN     one test: does Fitbit validate the aud claim of a Google ID token?
         results/google/RESUME-HERE.md — needs a Fitbit account created via
         "Continue with Google". Fifteen minutes, and the only remaining path
         from "misconfiguration" to "account takeover".
```
