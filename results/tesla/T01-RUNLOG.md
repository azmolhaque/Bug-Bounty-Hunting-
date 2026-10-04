# T01 — Tesla recon runlog

Started 2026-10-04. Toolset: Termux + Kiwi on one Android phone.

## Passive discovery

`crt.sh` returned **502 Bad Gateway** for every domain — their server, not ours. Recovered with
three independent passive sources that need no Tesla traffic: certspotter, hackertarget and
AlienVault OTX.

```
in scope after exclusions   511 hosts
flagged as non-marketing    112

tesla.services   167     solarcity.com                16
tesla.com        186     teslainsuranceservices.com    2
tesla.cn          75     teslamotors.com              58
```

`tesla.services` holding 167 hosts — almost as many as `tesla.com` — is the finding of this
stage. The names are infrastructure, not marketing: `airflow.dev.ap`, `airflow.stage.ap`,
`jobqueue.dev.ap`, `apviz.{dev,stage}.ap`, `eval.stage.ap`, `data.dev.ap`,
`token-dispenser-api-{dev2,prod}.data.*.ap`, `splunk-es.dev.audit`, `xsoar-secops-dev.prd.audit`,
`ttel-grafana.apwww.antivirus`. `ap.` reads as Autopilot.

## Probing — 112 hosts, one GET each, 0.5s apart, redirects not followed

```
404 × 22    403 × 11    200 × 9    302 × 3    401 × 1    307 × 1    301 × 1
rest: DNS present, no service
```

Every `ap.tesla.services` host — including both Airflow instances — failed to answer. The
interesting names are real but not externally reachable.

### Dropped immediately, with the reason

- Akamai `403 Access Denied` (`bettertime-stage`, `exp-zcp-cloud-*-itmfg-staging`, `stage.tesla.cn`)
  — WAF/geo, and **WAF bypass is out of scope**.
- `quality-uat.teslamotors.com` → redirects into Tesla's zero-trust portal.
- `vehicle-files.*` → 403 from AmazonS3 / TencentEdgeOne. Bucket listing denied, which is correct.
- `extconfluence.teslamotors.com` → `/rest/api/content` answers `401 Client must be authenticated`;
  `/rest/api/space` is 403. Anonymous access is off. Closed.

### An error of mine, recorded

I fetched `/.well-known/openid-configuration` on `auth-stage.tesla.com` and `auth.tesla.com`
expecting an OIDC document and a staging/production differential. All three responses were the
SPA's HTML shell — `auth.tesla.com` is a React app and `.well-known` falls through to its
catch-all route. **A 200 on a JS shell is not access**, which is the trap I had written down
after Adobe and then walked into. No differential exists to read.

Two further tooling errors, both corrected:
- `getent hosts` reports NO DNS for everything on Termux; it does not resolve. Host liveness must
  be decided by curl's `remote_ip`, not by getent.
- A probe loop reused a stale output file when curl failed, so dead hosts printed the previous
  host's title and size. Every `[000]` line in that run was meaningless.

## What survived: the CUA test-drive application

`cua-test-drive-ui.tesla.cn` and `cua-test-drive-ui.tesla.com` both serve a Vite SPA titled
**Test Drive Retail App** ("Schedule a Demo Drive"). It is **completely unauthenticated** — anyone
can book a demo drive.

Its bundle `/assets/retail.RQ3gJsGt.js` (601 KB) gave up the whole estate and the API:

```
/cuaverse/api/drive/get-drive-configs
/cuaverse/api/drive/get-demo-drive-locations
/cuaverse/api/drive/getNearbySlots
/cuaverse/api/drive/submit            <- write. Never called: RoE forbids spamming forms.
/cua-api/drive/get_schedule           <- different prefix, likely an older API
```

Parameter frequency in the bundle: `mobile` 403, `country` 236, `locale` 31, `email` 26,
`phone` 20. Constants `retail-kiosk` and `@nomail.com`. **The booking identity is a mobile
number**, and e-mail is optional enough to have a placeholder domain.

Hosts named in the bundle, all checked: `cuaverse-bff{,-stage}.tesla.{com,cn}`,
`cua-test-drive-ui-{dev,qa,stage}.tesla.{com,cn}`, `cua-burst-app-{dev,qa}.tesla.com` — **all ten
resolve to nothing externally**. Internal DNS only. The API paths return nginx 404 on the UI
origin, so the SPA's backend is reached some other way.

## Where this stands

The surface worth the time is the one application: unauthenticated, booking real customers'
name, mobile and location, with a read endpoint (`get_schedule`) whose parameters are not yet
known. If that endpoint returns a booking for an identifier the caller does not own, it is the
exact class Tesla's brief keeps in scope:

> *"Exceptional cases may still be in scope (e.g. ability to enumerate email addresses via
> incrementing a numeric parameter)"*

Next: capture the app's real API host and query shape from the running page, rather than guessing
paths — guessing is both fuzzing and against the rules of engagement.

## Full sweep and application reading — 2026-10-04, second half

### The sweep, corrected

My first probe covered only 112 of 511 hosts, filtered by keywords I had invented. That filter
was the only reason the rest were skipped, so the whole set was swept. Two tooling corrections
on the way: Termux has no `/tmp` (curl silently wrote nothing), and a sequential run with 15s
timeouts would have taken an hour, not the five minutes I estimated — dead hosts cost the full
timeout. Reworked to 4-way parallel, one GET per host, 3s connect / 6s total.

**170 of 511 answered**, in about three minutes.

### Applications found, as opposed to infrastructure

```
fleetview.{,prd.}{america,europe,}.fn.tesla.com   x5   "Tesla Fleetview"
live-data.{,prd.}{america,europe,}.fn.tesla.com   x5   200, no title
mfs-supplier{,-eng}.mo.tesla.cn                   x2   "MFS Supplier Portal"
tripx{,-alpha}.*.vn.cloud.tesla.com               x3   "Tesla | TripX"
billing.tesla.com · cx.tesla.cn · service.tesla.cn · warp.solarcity.com
extissues.teslamotors.com  401 "Unauthorized (401)"   (external Jira)
```

The `auth-stage` pattern — one app, two environments, differing only in config — repeats three
times here: `mfs-supplier-eng` vs `mfs-supplier`, `tripx-alpha` vs `tripx`, and fleetview's five
regions.

### What the bundles gave up

**Fleetview / live-data** call Tesla's Fleet API: `/api/1/vehicles/`, `/vehicle_data`,
`/oauth2/v3/token`, with `client_id` read from `window.UI_CONFIG.oauth_client` and
`scope=device_data email energy_cmds energy_device_data offline_a…`. `live-data` names
`fleet-api-files-stg.tesla.com` — a staging host referenced from a production app.

`UI_CONFIG` is **not** in the HTML we are served; the server injects it only for a real session.
So the client id could not be read, and nothing was guessed.

**MFS Supplier (the eng host runs an older build** — `main.607a352fb2dee6e1.js` with a separate
`runtime.js`, against prod's `main-TZVR5XI4.js`) names a large surface:

```
/auth/adfs  /auth/badge  /auth/callback  /auth/login
/authentication/refreshtoken  /authentication/useteslaaccess
/oauth2/v1/{authorize,logout,userinfo}
/{supplier,inventory,inventorytx,order,system,external}/v1/api
/hostler/userlist  /userrole  /usernav  /userfav  /userwarehouse/username/
```

and leaks internal hostnames: `github.tesla.com`, `hub.tesla.com`, `teamchat.tesla.com`,
`workbench.tesla.com`, `sandbox-workbench.tesla.com`, `dataviz{,-stage}.tesla.com`,
`mfs-supplier-uat.{mo.tesla.services,tesla.com}`, `warehouse-uat.mo.tesla.services`.
Hostname disclosure alone is explicitly out of scope, so it is noted and not pursued.

### The test that looked promising, and why it is a negative

Six API prefixes are named in one bundle. If five were guarded and one was not, that would be an
authentication gap worth reporting. Tested all six on the eng host:

```
/supplier/v1/api      401    14b     Jwt is missing
/inventory/v1/api     200  28201b    Angular index
/inventorytx/v1/api   200  28201b    Angular index
/order/v1/api         200  28201b    Angular index
/system/v1/api        200  28201b    Angular index
/external/v1/api      200  28201b    Angular index
```

The five "200"s are **byte-identical to the SPA shell**. They are not unguarded APIs; they are
routes that do not exist on this host and fall through to Angular's catch-all. Only
`/supplier/v1/api` is proxied to a backend, and it refuses without a JWT. Correct behaviour.

Reading a 200 as access here would have produced exactly the kind of report that closes as
spam. The size comparison is what settled it.

### State at the end of the session

Nothing reportable. One lead (LEAD-001). Closed with evidence: the CUA kiosk app, two Google
Maps keys, external Confluence, the `ap.tesla.services` estate, the CUA dev/qa/stage hosts, and
the MFS API prefixes.

The method that produced the only lead was reading two configurations of the same application
side by side — not scanning. `tripx-alpha` vs `tripx` and the five fleetview regions are the
same shape and have not been read yet.

## Reading the remaining applications — same session, later

### billing.tesla.com — enforced

A Next.js **static export** (`nextExport: true`), so there are no `/_next/data/` server endpoints
to abuse. But `_buildManifest.js` — which the app serves to every visitor — hands over its entire
route table:

```
/   /404   /_error   /tnc   /account   /history   /payment/[id]
__rewrites afterFiles: { source: "/api/billing/:path*" }
```

`/payment/[id]` is the IDOR shape, and the page chunk shows exactly how the id is used:

```js
var e = useRouter().query.id,
    n = useAuth().isAuthenticated,
    t = useSWR(`${o.mb.PAYMENTS}/${e}`).data;
```

The URL's `id` goes straight into the API call, and `isAuthenticated` is a **client-side** check.
The endpoint map came out of a shared chunk:

```js
var r="/api/billing", o={ PROFILE:r+"/profile", SETTINGS:r+"/settings", PAYMENTS:r+"/payments",
                          STATEMENTS:r+"/statements", PAYMENT_ACCOUNTS:r+"/payment-accounts", … }
```

Tested the **collections first**, deliberately, so that no individual record had to be touched if
the door turned out to be shut:

```
/api/billing/profile           403  {"detail":"Authentication credentials were not provided."}
/api/billing/settings          403  same
/api/billing/payments          403  same
/api/billing/statements        403  same
/api/billing/payment-accounts  403  same
/api/billing/__canary__        503  HTML
```

The sentinel is what makes this readable. Had the nonexistent path answered with the same 403,
the refusals would have been the edge talking and would have proved nothing. It answers
differently, so the 403s are the application — Django REST Framework, enforcing. `/payments/<id>`
was never requested; there was no need.

### accounts.tesla.com — enforced

The EDR bundle (1.3 MB) names `/account/api/userSearch`, `/account/api/search/C360Search`,
`/account/api/configs/*`, `/account/api-doc`, `/api/reports`. On `accounts.tesla.com`:

```
/account/api-doc                 307 -> /oauth2/auth-login?redirect_url_path=…auth.tesla.com/oauth2/v1/authorize…
/account/api/configs             404  {"error":"Invalid Request"}
/account/api/userSearch          404  {"error":"Invalid Request"}
/account/api/search/C360Search   404  {"error":"Invalid Request"}
/api/reports                     404  {"error":"Invalid Request"}
```

The documentation endpoint is behind OAuth; the rest are not routed on that host. A customer
search API would have been the most serious thing available, and it is not reachable there.

### Closed in passing

```
api.solarcity.com          401, no WWW-Authenticate  — token auth, nothing to work with
extissues.teslamotors.com  401 on /rest/api/2/serverInfo — anonymous Jira access off
fleet-api-files-stg        no DNS
am-i-online-prd            "ok"  — health check, out of scope by the brief
x1.ap.tesla.services       "server date … hash … ver:" — version disclosure, out of scope
warp.solarcity.com         jQuery 3.0.0 page — out-of-date software, out of scope
```

### Session total

Roughly 250 authorised requests. **Nine surfaces closed with evidence**, one lead, no findings
and nothing claimed that was not shown. Every closure has either a control or a sentinel behind
it, and two results that looked like findings — the five "200" API prefixes on MFS, and the five
403s on billing — were only readable because the response *size* and a *nonexistent path* were
checked alongside the status code.

Not yet read: the EDR bundle in full, TripX, `charging-transparency.tesla.com`, `cx.tesla.cn`.
Not yet resolved: LEAD-001, which needs Bugcrowd identity verification and a `bugcrowdninja.com`
account before it can be settled.
