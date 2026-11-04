# T04 — `api-test.solarcity.com` PowerGuide: an authorisation filter missing on three routes

**Date:** 2026-10-06 · **Target:** `*.solarcity.com` (in scope, Bugcrowd Tesla)
**Verdict: PARKED — not submitted.** A real control failure, no demonstrated data access.

---

## What was proven

Three routes on `api-test.solarcity.com` execute application logic for an **unauthenticated**
caller. The same routes on production require authentication, and the other fourteen routes on
the same test host require it too.

```
                                              prod            api-test
v1.0/installations/{GUID}                     401             404  128b  {"Message":"installation not found for key: …, errorid …"}
v1.0/measurements/{GUID}?Period&Start&End     401             404   82b  same shape
v1.0/grid_transfer/{GUID}?Period&Start&End    401             404   82b  same shape

v1.0/customers?IsDetailed&Size&Page           401             401   61b  {"Message":"Authorization has been denied for this request."}
v1.0/installations?Size&Page                  401             401   61b
v1.0/devices?Size&Page                        401             401   61b
v1.0/groups?Size&Page                         401             401   61b
v1.0/customers/{GUID}                         401             401   61b
v1.0/devices/{GUID}                           401             401   61b
v1.0/groups/{GUID}                            401             401   61b
v1.0/installations/{GUID}/appliances          401             401   61b
v1.0/installations/{GUID}/billing?…           401             401   61b
v1.0/installations/{GUID}/summary?…           401             401   61b
v1.0/installations/{GUID}/weather?…           401             401   61b
v1.0/installations/{GUID}/weather/{date}      401             401   61b
v1.0/consumption/{GUID}?…                     401             401   61b

v1.0/installations/stats/pollutionoffset      200             200  174b  fleet aggregates, no identifiers
v1.0/__canary__/{GUID}                        404            404 1245b  IIS error page — route does not exist
```

Four controls, and the conclusion survives all of them:

1. **The canary differs.** A nonexistent route returns IIS's own 1245-byte HTML 404. The three
   routes return a 128/82-byte **application JSON** 404 with a trace `errorid`. The app ran.
2. **Siblings on the same host require auth.** Fourteen routes answer `401`, so this is not an
   unauthenticated host or a WAF gap.
3. **Production enforces it.** Identical paths, identical parameters, `401`.
4. **It is not an edge artefact.** The response is ASP.NET Web API's own error body.

### The three routes are also the three that are undocumented on the test host

```
api-test /powerguide/Help   14 routes, 11697 bytes
api     /powerguide/Help    17 routes, 13048 bytes

comm -13  (in prod's Help, absent from test's):
  v1.0/grid_transfer/{}
  v1.0/installations/{}
  v1.0/measurements/{}
```

Exactly the three that bypass authentication. They are reachable in routing but missing from the
deployed help registry — a shadow API on an older or divergent build, carrying no authorisation
filter.

---

## Why it was NOT submitted

CLAUDE.md §2.6: *"A precondition … is NOT a finding — you must have evidence in hand of the actual
cross."*

The one-sentence answer to **"what did the attacker actually GET?"** is **nothing**.

Reading any record needs a valid `InstallationGUID`, and:

- The route rejects integers. `installations/1`, `/2`, `/1000` all return the 1245-byte IIS 404,
  i.e. the route constraint requires GUID format. **So the "incrementing a numeric parameter"
  exception in Tesla's brief does not apply here.**
- A GUID is 122 bits of randomness. Searching for one is brute force, which the Tesla RoE forbids
  without prior written approval.
- The Internet Archive's 32,887 `solarcity.com` URLs yielded 563 GUIDs — **all of them
  AjaxControlToolkit script-bundle cache keys** (`_TSM_CombinedScripts_=…`), not installation
  identifiers. All 15 tested returned the same `404 128b` as the all-zero GUID. Bodies were
  written to `/dev/null`: status and size alone would have shown a crossing, and no customer byte
  was ever read.

Submitting this would mean claiming an authentication bypass whose impact I could not show, on a
**test** environment, while F001 is still in triage on the same program. A second report closed
"no impact demonstrated" would cost more in signal than the report could earn.

---

## The exact condition that would un-park it

**One valid `InstallationGUID`, obtained legitimately** — from a consenting Tesla Energy /
SolarCity customer's own account, or from Tesla itself during triage.

With one, this becomes a single request:

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}b\n' \
  "https://api-test.solarcity.com/powerguide/v1.0/installations/<GUID>"
```

`200` with a body larger than 128 bytes, against the `404 128b` baseline, proves unauthenticated
read of another party's installation record — and proves it without reading the body. That would
be a High, and the report is already three-quarters written above.

Until then it is a lead, labelled honestly as one.

## Also closed in this pass

- **`/deals/`, `/milestones/`, `/sources/` on api-test — closed.** Their `403 26b` responses
  looked like deployed-but-protected applications. The control I had never run settles it:
  `/__canary__/swagger/` and `/zzzznotanapp/swagger/` return the **same** `403 26b`. It is a
  blanket rule on the literal `/swagger/` path segment, not evidence of anything. My earlier note
  claiming those three apps were deployed there was wrong.
- **`/solarproposalapi/`, `/employee/Help` on api-test — closed.** Byte-identical 1245-byte IIS
  404s, the same as the canary. Not deployed.
- **`teslainsuranceservices.com` — closed.** `www` and `stage` both return Akamai's
  *Service Unavailable - DNS failure*. Akamai holds a config for the hostnames but the origin does
  not resolve. No application, no impact.
- **`tesla.services` — deprioritised.** 6,029 archived hostnames, overwhelmingly numeric and
  VPN/speed-test shaped (`01.fast.test.me.openvpn.asg.tesla.services`); every one sampled had no
  DNS. Not worth an hour of probing without a reason to expect anything live.
- **crt.sh — unusable today.** It returned 0 for `tesla.com` itself, which is impossible, so every
  other 0 it gave was rate limiting rather than data. Only `solarcity.com` (85 names) came back
  before the limit hit. Do not trust a crt.sh zero without the `tesla.com` positive control.
