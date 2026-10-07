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
