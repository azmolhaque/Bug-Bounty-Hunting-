# T03 — Mining the archive: SolarCity's legacy API estate

2026-10-06, from Termux. A deliberately different method: **no scanning**.

## Why this, and not more subdomain enumeration

Certificate transparency plus HTTP probing is what every one of the programme's 528 recent
researchers runs, usually with better tooling and a better connection. There is no edge there.

The Internet Archive is a different dataset. It holds twenty years of URLs that were *linked*
at some point — paths that no longer appear anywhere on the live site, so no crawler finds them
today. And it costs Tesla nothing: **not one request reaches their infrastructure.**

```
web.archive.org/cdx/search/cdx?url=<domain>&matchType=domain&fl=original&collapse=urlkey
```

```
tesla.com 40,000 · teslamotors.com 40,000 · tesla.cn 40,000 · solarcity.com 25,864
145,864 unique URLs
112 solarcity.com hosts, many absent from the CT-derived set
```

Hosts the archive knew and certificate transparency did not: `admin`, `customercare`, `dynamo`,
`designpro`, `hives`, `flannel`, `employeereferral`, `gw-test`, `go-int`, `backup-vpn.scfs`,
`api.nc`, `hpp`, `isapi`. Of 112 archived hosts, **8 still answer**:

```
api.solarcity.com         401        api-test.solarcity.com    403
isapi.solarcity.com       500        solarguard.solarcity.com  403
login.solarcity.com       302 -> its own sign-in
secure{,-test}.solarcity.com  302 -> www.tesla.com
warp.solarcity.com        200  (a jQuery redirect stub)
```

## What the archive handed over

Full ASP.NET Help documentation for SolarCity's internal APIs, including endpoint names that
describe exactly what they return:

```
/employee/Help/Api/     GET api/info/contact/{contactid} · info/details/{userId}
                        info/details_email · info/employee/{employeeId}
/solarproposalapi/Help/ GET Utility/BillImage/DealId/{dealId} · proposal/summary/{proposalId}
                        deals/{dealGuid}/loan/applications/primary · milestones/credit
/powerguide/Help/       GET v1.0/customers?IsDetailed&Size&Page      <- paginated customer list
                        v1.0/customers/{CustomerGUID}
                        v1.0/installations?Size&Page
                        v1.0/installations/{GUID}/billing?StartDate&EndDate
                        v1.0/devices?Size&Page · measurements · consumption · groups
```

A paginated customer list and per-installation billing is the most sensitive shape this
engagement has found anywhere.

## The differential that made it worth testing

`api.solarcity.com` answers **401 with a two-byte body to everything**, including a nonexistent
path. That is a blanket edge refusal and normally means there is nothing to see. Except:

```
/__canary__                401      2b
/powerguide/               200  6,135b
/powerguide/Help           200 13,048b     <- live, and outside whatever returns the 401
/powerguide/healthcheck    404  1,917b
```

PowerGuide is reachable past the edge, and its documentation is public. Documentation alone is
not a finding — it is the map. The question is whether the endpoints it maps are guarded.

## The sweep, and the hole in the first pass

Eighteen documented paths, each called with an all-zero GUID that can belong to nobody:

```
customers · customers/{guid} · devices · devices/{guid} · groups · groups/{guid}
installations · installations/{guid} · installations/{guid}/appliances · …/weather
                                                       -> 401 Authorization has been denied
installations/stats/pollutionoffset                    -> 200
grid_transfer · billing · summary · measurements       -> 404 No HTTP resource was found
```

The four 404s were **not** a result. "No HTTP resource matches this URI" means routing failed
before authorisation was ever consulted — those endpoints take mandatory query parameters
(`Period`, `StartTime`, `EndTime`, `StartDate`) and without them the request never reaches the
handler. Reading them as "protected" would have been wrong.

Re-run with the documented parameters, plus the list endpoints and a sentinel:

```
consumption/{guid}?Period&StartTime&EndTime&IncludeCurrent      401
grid_transfer/{guid}?…                                          401
installations/{guid}/billing?StartDate&EndDate                   401
installations/{guid}/summary?…                                   401
installations/{guid}/weather?…                                   401
measurements/{guid}?…                                            401
customers?IsDetailed=false&Size=1&Page=1                         401
installations?Size=1&Page=1                                      401
v1.0/__canary__/{guid}?…                                         404   <- sentinel differs
```

**Every data endpoint enforces authentication, consistently.** The sentinel answers differently,
so the 401s are the application speaking rather than the edge.

### The one unauthenticated endpoint, and why it is not a report

```
GET /powerguide/v1.0/installations/stats/pollutionoffset   200
{"TotalGenerationkWh":53313533381.094,"ConservedGallonsOfWater":15748929000.15, …}
```

Fleet-wide aggregates — total generation, water conserved. No customer, no installation, no
identifier. Tesla publishes figures of this kind itself. Recorded and dropped.

## Still open from this dataset

The archive also documents `/employee/` and `/solarproposalapi/` — contact, user and employee
lookup by id, utility bill images by deal id, loan applications. On `api.solarcity.com` those
paths return the blanket 401 and on `api-test` they 404, so they are not deployed where we can
reach them. `api-dev.solarcity.com` has no DNS.

`api-test.solarcity.com` is worth one more pass: its canary answers 404 while `/deals/swagger/`,
`/milestones/swagger/` and `/sources/swagger/` answer **403 with a 26-byte body** — a different
response, so those three applications are deployed there behind something. The archive holds
real paths for them (`/deals/values`, `/milestones/healthcheck`) that have not been tried.

## Chasing the escalation, and where it topped out — 2026-10-06

The archive's module listing under `/sites/all/modules/custom/` (8,237 URLs, 27 custom Drupal
modules) named four files worth more than the config ones: `tesla_careers/js/lib/keys.js`,
`tesla_findus_map/proxy.php`, `tesla_login/sso/auth.php` and `tesla_gatekeeper/sso/d6.php`.

```
keys.js            404 on .com and .cn        gone
d6.php             404                        gone
proxy.php          200 on .com and .cn        live
auth.php           200, "no key supplied"     live
```

### `proxy.php` is not SSRF, and is not being reported as one

A PHP proxy inside a maps module is the right thing to look at, so it was looked at properly.
The parameters came from archived URLs rather than guesswork — `?address=` and `?ip=true` — and
the module's Angular scripts named the rest (`lat`, `lng`, `type`, `bounds`, `place`, `radius`).

```
?__canary__=1       200   0 bytes      <- sentinel: unrecognised mode, silent
?address=Austin     200   "false"
?lat=&lng=          200   0 bytes
?ip=true            200   208 bytes    ipinfo JSON
```

It takes **modes, not URLs**. The upstream host is fixed in the code and nothing in the request
reaches it, so the precondition for SSRF — control of the destination — is absent. Closed.

What it did establish is worth keeping: `?ip=true` performs a server-side ipinfo lookup, which
means the token leaked in `config_web.json` is **in current production use**, not a leftover. That
went into F001.

### `auth.php` — open, and deliberately not pursued

`tesla_login/sso/auth.php` answers `no key supplied`. Finding the key it wants would mean guessing
values against an authentication endpoint, which is brute force: forbidden by the programme's
rules of engagement and excluded from scope. Noted and left alone.

## Exhausting the root cause — the full module sweep, 2026-10-06

`config_web.json` leaked two credentials, which raises the obvious question: is that one careless
file, or a habit? The archive listed 118 distinct `.js`/`.json` paths under
`/sites/all/modules/custom/` across 27 modules. **82 are still live** and all 82 were pulled and
searched.

```
credential-shaped assignments   none        (only MozPrintableKey and React internals)
cloud key formats               none        AKIA · ASIA · LTAI · AIza · sk_live · xox* · gh*_ · JWT
internal hostnames              none
```

The modules that looked most promising were checked by hand rather than left to the regex:

- **`tesla_payment_forms`** — `tesla_payment_forms.stripe.js` reads its key from
  `Drupal.settings.tesla.stripe[region][country]` and passes it to `Stripe.setPublishableKey()`.
  A *publishable* key belongs in the browser; there is no `sk_live_` anywhere in the module.
- **`jsencrypt.js`** contains the strings `BEGIN PRIVATE KEY` and `BEGIN RSA PRIVATE KEY`. Those
  are the library's own PEM parsing constants, not a key. Reporting them would have been a
  self-inflicted spam close.
- **`tesla_five_minute_credit`**, **`apple_pay.js`**, **`solarroof_order_form`** — no endpoints,
  no identifiers beyond `merchantCapabilities: ['supports3DS']` and a `validationURL` read from
  the Apple Pay event, which is how Apple Pay is meant to work.

So the two credentials in `config_web.json` are what there is. The habit is not widespread, and
F001 should claim exactly those two and nothing more.

---

## 2026-10-06 — archive sweep of the full `/sites/all/modules/` tree (CLOSED, no new credential)

CDX query `url=tesla.{com,cn}/sites/all/modules/*` → **4442** archived URLs.
Filtered to config-shaped extensions (`json|ya?ml|ini|env|conf|txt`) → **30** candidates,
all on `www.tesla.cn`. Fetched each live with a browser UA, 1s apart.

**Result: no second credential. The sweep is closed.**

| Outcome | Count | Verdict |
|---|---|---|
| `config_web.json` + 6 cachebuster variants | 7 | 200, 329052 b, the **already-reported** ipinfo token. Nothing new. |
| `config_locale_strings.json` + 13 variants | 14 | 200, 407459 b, zero secret-shaped matches. Locale strings only. |
| `.json` paths under 8 other modules | 8 | **404** — all of them. |
| `99bill/province_city_district_map.json` | 1 | 301 (http→https). Not re-fetched over https yet. |

This answers the open thread in F001's remediation ("sweep the other configurator config
files for the same pattern"): `config_web.json` is the only one carrying a credential.
That is a point in F001's favour, not against it — the finding is specific, not a pattern
of sloppiness I failed to bound.

### DROPPED: `theme_token` on the 404 pages — Drupal per-request token, not a secret

My grep matched `"theme_token":"…"` on all 8 of the 404 responses (433 KB Drupal error pages).
It is **noise**, and the proof is in the data itself: **every single request returned a
different value** —

```
tesla_corporate_form   theme_token  -Qq25hZjkcILB_YYEwikrlC2CVrJElWSna8KOMwaYRo
tesla_findus_map       theme_token  3hyM2aI808RUtbFHYa2x0QNly7B0WM-DTck8HoD6xxE
tesla_findus_mobile    theme_token  rF6IDFQkY9klD6yLBPlDMNvr0l8iSckOeNJ1nacHGq0
tesla_get_updates      theme_token  qQjZ-rdq0nD7T2YakPtARUUGQpsAaccK3Xs58Copi-k
tesla_payment_forms    theme_token  hgenrn2uAofTXsQxRGqjy2FD-M0I8_PPDDKNjQHJ20I
tesla_rsvp_event       theme_token  eXri8oQ7-xgLq8CFEheeekZ6oN0XF-XXHEeSs5yLvZ0
tesla_test_drive       theme_token  26R0ve3Hg1-0rxxDFZA8H5S4VOjIkayIMt3OFZrY06s
tesla_test_drive (kr)  theme_token  AI714xRbtkb3et1BLeHR3s5kSo2T4BIequL5s_6VwpI
```

A leaked static credential does not change per request. This is Drupal 7's
`Drupal.settings.ajaxPageState.theme_token` — a per-request anti-tamper token that ships in
every Drupal 7 page, including the generic 404. It is the *mitigation* for arbitrary-theme
rendering, not a hole. Public by design. **Do not report.**

Same for `"m3ConfigurationKey":"app-find-my-tesla.configuration"` — a configuration *name*,
not a value. Object-name enumeration with no record read: Hard Rejection List §3.

This is the second time a `token`/`key`-shaped grep has produced a false positive on this
target (first was `BEGIN PRIVATE KEY` inside `jsencrypt.js`). Rule for next time: before
believing any matched secret, **request it twice**. If it differs, it is a session or request
token, not a credential.

### My filter was too narrow — real remaining lead

4442 → 30 threw away every `.js` and `.php` path in the tree. The `.php` files are the
server-side endpoints that take parameters (actual bug surface, unlike static JSON), and the
archive revealed a **`99bill`** module — 99bill / 快钱 is a Chinese payment processor. That
directory was never examined. Next step, not a finding.

### CLOSED: `stage.tesla.com`

From `config_web.json`'s `staging_envs`. Scope is `*.tesla.com` / `*.tesla.cn`, so
`stage2.teslamotors.com` and `qa.teslamotors.com` are **out of scope — not touched, zero
packets sent**. `stage.tesla.com` is in scope, but:

```
curl -s -o /dev/null -w '%{http_code} %{size_download}b %{remote_ip}' https://stage.tesla.com/
000  0b          <- empty remote_ip: no public DNS resolution
```

`000` with no `remote_ip` means curl never connected — the name does not resolve publicly.
Internal-only hostname. Dead end, closed.
