# F001 — Publicly readable Tesla config exposes two working third-party credentials

**Status:** ready to submit · Bugcrowd, Tesla · targets `*.tesla.com`, `*.tesla.cn`
**Found:** 2026-10-05 · **Researcher:** Gorib (`gorib@bugcrowdninja.com`) · **IP:** 180.148.212.54

## The point in one sentence

Two Tesla assets that anyone can read without logging in — the `/api/findus/env` endpoint and the
`config_web.json` configurator file — publish **two live third-party credentials**: a Baidu Maps
key with no referrer or IP restriction on it, and an active ipinfo.io API token. Both files are
served from **`www.tesla.com` as well as `www.tesla.cn`**, so this is not a regional artefact.

A browser-side map key being *visible* is normal; this one being *unrestricted* is not, and
Tesla's own Google Maps keys prove they know the difference. The ipinfo token has no excuse at
all — ipinfo has no referrer restriction to apply, so that token was never meant to leave the
server.

Both are billable. I verified both work from my own machine with no Tesla account.

## What the endpoint returns

```
GET https://www.tesla.com/api/findus/env        200, application/json, no auth, 5799 bytes
    …"baiduMapAk":"qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z",
      "gioConfig":{"GIO_ACCOUNT_ID":"","GIO_DATA_RESOURCE_ID":"","GIO_HOST":""}}}
    (the complete 5799-byte response is attached as env.json)

GET https://www.tesla.cn/api/findus/env         200, application/json, no auth
    …"baiduMapAk":"qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z",
      "GIO_ACCOUNT_ID":"b0e25bc027704bfe",
      "GIO_DATA_RESOURCE_ID":"93d9fb8b42c30cc0",
      "GIO_HOST":"akamai-apigateway-gio-analytics.tesla.cn"
```

The `.com` response leaves the GrowingIO fields blank; **the `.cn` response fills them in**. Both
hand out the same Baidu key.

(`curl` to `www.tesla.com` is refused by Akamai with 403 — including with a full Chrome
User-Agent, so it is fingerprinting below the UA string. A browser is served normally; the
screenshot and the complete saved response are both attached. `www.tesla.cn` answers `curl`
directly.)

## The demonstrated issue: the Baidu key is unrestricted

Used from my own machine in Bangladesh, no `Referer` header, no account:

```
curl "https://api.map.baidu.com/geocoding/v3/?address=%E5%8C%97%E4%BA%AC&output=json&ak=qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z"

{"status":0,"result":{"location":{"lng":116.4133836971231,"lat":39.910924547299568},
 "precise":0,"confidence":20,"comprehension":100,"level":"城市"}}
```

`HTTP 200`. `"status":0` is Baidu's success code. **Five** Baidu services accept it:

```
geocoding/v3            status 0   coordinates returned
place/v2/search         status 0   "特斯拉(北京朝阳合生汇城市展厅)" and more POIs
place/v2/detail         status 0   full record for a single POI
location/ip             status 0   resolved my own IP
reverse_geocoding/v3    status 0   full street address for a Shanghai coordinate
```

Four do not, which is worth stating so the scope is not overstated:

```
direction/v2/driving       status 240  "APP 服务被禁用"
weather/v1                 status 240  "APP 服务被禁用"
geodata/v3/geotable/list   status 240  "APP 服务被禁用"   (cloud data storage)
yingyan service/list       status 1    internal error     (vehicle tracking)
```

So the key cannot read stored Tesla data and cannot reach the priciest routing APIs — it consumes
the five metered services above and nothing more. I tested the other four specifically to
establish the ceiling rather than leave it implied.

## Credential 2 — ipinfo.io API token, active

The configurator config file is served with no authentication (200, 329 KB) and contains:

```json
"use_ip_lookup_service": true,
"ip_lookup_service_token": "47216944bba1aa",
"apiNames": {"ipInfo": "https://ipinfo.io/geo", …}
```

**It is published on both the `.cn` and the `.com` site, at the same path:**

```
https://www.tesla.cn/sites/all/modules/custom/tesla_configurator/js/config/config_web.json
https://www.tesla.com/sites/all/modules/custom/tesla_configurator/js/config/config_web.json
```

`curl` gets the file from `.cn` directly (200, 329052 bytes). I have also saved the `.com` copy
from a browser: it is **329052 bytes as well — byte-for-byte the same length** — and contains the
same `"ip_lookup_service_token": "47216944bba1aa"`, the same `"use_ip_lookup_service": true`, and
the same `"ipInfo": "https://ipinfo.io/geo"`. Both files are attached.

On `.com` I cannot give you a terminal reproduction, and I would rather say that than imply one
exists. Akamai returns 403 to `curl` on these paths **even with a full Chrome User-Agent**
(`Reference #18.65a5c117…`), so it is fingerprinting past the UA string. A browser is served
normally: I opened the `.com` URL in Chrome, searched the response for `ip_lookup_service_token`,
and got **1 of 1** match — the same token, `47216944bba1aa`, next to the same
`"apiNames": {"ipInfo": "https://ipinfo.io/geo", …}` block. That screenshot is attached and I have
saved the `.com` copy of the file.

Independent corroboration that this is a real `.com` URL and not a mistake on my part: the
Internet Archive's CDX index lists it directly.

```
curl -s "https://web.archive.org/cdx/search/cdx?url=tesla.com/sites/all/modules/*&fl=original&collapse=urlkey"
…
https://www.tesla.com/sites/all/modules/custom/tesla_configurator/js/config/config_web.json
```

So this is not a China-only config artefact. The same token is readable from Tesla's main
`www.tesla.com` site, which is the significant part of the spread: the asset with the global
audience publishes the credential too.

The token is live. ipinfo marks unauthenticated responses with a `readme` field and omits it when
a token is accepted, which makes this a one-request check:

```
curl "https://ipinfo.io/8.8.8.8?token=47216944bba1aa"
{"ip":"8.8.8.8","hostname":"dns.google","city":"Mountain View", … ,"anycast":true}

curl "https://ipinfo.io/8.8.8.8"
{"ip":"8.8.8.8", … ,"readme":"https://ipinfo.io/missingauth","anycast":true}
```

The `readme` line is present without the token and gone with it. The token is authenticating the
request against Tesla's ipinfo account.

Unlike a maps key, an ipinfo token **cannot** be referrer-restricted — ipinfo offers no such
control. It is a server-side credential, and publishing it in a client-side config file is the
whole problem.

### The token is an account credential, not just a lookup key

`https://ipinfo.io/me` returns the state of the account the token belongs to:

```
curl "https://ipinfo.io/me?token=47216944bba1aa"

{"token":"47216944bba1aa",
 "requests":{"day":4,"month":66,"limit":50000,"remaining":49934},
 "features":{"core":{"daily":2147483647,"monthly":50000},
             "hostio":{"daily":2147483647,"monthly":1000, …}}}
```

Without the token the same path refuses:

```
curl "https://ipinfo.io/me"
{"error":"API token required to view token details. Did you mean to visit /my instead?"}   400
```

So the leaked token exposes Tesla's ipinfo **account**: the plan (50,000 core lookups a month,
plus a 1,000/month `hostio` allowance), this month's consumption, and the remaining balance. That
is account state, not merely the ability to run a lookup.

**On the money question, to be accurate rather than dramatic:** 50,000 lookups a month is ipinfo's
free allowance, so I am not claiming this runs up a bill. The consequence is the other way round —
a free plan has no overage headroom. When the 50,000 are gone the account stops answering until
the month rolls over.

Tesla had used **66** of the 50,000 when I checked. Anyone holding this token can burn the
remaining 49,934 in minutes, and at that point the lookup below stops working for real visitors.

### The token is in live production use on `www.tesla.com`, not only on `www.tesla.cn`

This is the part that matters most, and it is reproducible in any browser:

```
https://www.tesla.com/sites/all/modules/custom/tesla_findus_map/proxy.php?ip=true

{ "ip": "205.234.27.201", "city": "San Jose", "region": "California", "country": "US",
  "loc": "37.3394,-121.8950", "org": "AS40913 Quality Technology Services, LLC",
  "postal": "95110", "timezone": "America/Los_Angeles" }
```

That is an ipinfo.io lookup performed **server-side by `www.tesla.com`** — the IP returned is the
egress address of the machine that made the call, not mine (I am in Bangladesh; this is San Jose).
So the leaked token is being spent by the main `.com` site's own production code path right now.

*I am not reporting the returned IP itself — infrastructure/internal IP disclosure is out of scope
by your brief. It appears here only because it is what proves the call is server-side.*

### The configurator file itself, on `.com`

`/sites/all/modules/custom/tesla_findus_map/proxy.php?ip=true` is reachable on `www.tesla.cn`
and returns an ipinfo lookup performed **server-side**:

```
curl "https://www.tesla.cn/sites/all/modules/custom/tesla_findus_map/proxy.php?ip=true"
{"ip":"103.222.41.40","city":"Shanghai","region":"Shanghai","country":"CN",
 "loc":"31.2222,121.4581","org":"AS138421 China Unicom", …}
```

An unknown parameter on the same script returns an empty body, so this is the script acting on a
recognised mode rather than echoing anything back. The configurator's IP lookup is therefore a
live path that consumes the ipinfo plan this token belongs to — the credential is current, not an
artefact of an old build.

The same file also lists Tesla's staging hostnames:

```json
"staging_envs": ["stage.tesla.com", "stage2.teslamotors.com", "qa.teslamotors.com"]
```

`stage2.teslamotors.com` resolves (118.214.134.54) and is behind Akamai. Hostname disclosure is
out of scope by the brief, so it is noted only as part of what this file publishes, not claimed.

## The differential — why this is an oversight, not a decision

Tesla's Google Maps keys, taken from the Fleetview and CUA app bundles, refuse the same shape of
call:

```
curl "https://maps.googleapis.com/maps/api/geocode/json?address=Austin&key=AIzaSyBleO1VLDr7rDuIey2SMG-P3qdXXL76WK4"

{"error_message":"API keys with referer restrictions cannot be used with this API.",
 "results":[],"status":"REQUEST_DENIED"}
```

I checked three of Tesla's Google keys; all three behave this way. Same company, same class of
credential, same class of request — restricted. The Baidu key is the one that was missed.

## Where the credentials are exposed — the full spread I checked

| Host | Path | Result | Credential present |
|---|---|---|---|
| `www.tesla.cn` | `/api/findus/env` | 200 (curl) | Baidu key, GrowingIO ids |
| `www.tesla.com` | `/api/findus/env` | 403 to curl even with a Chrome UA; 200 in a browser | Baidu key |
| `www.tesla.cn` | `/sites/all/.../config_web.json` | 200, 329052 b (curl) | ipinfo token |
| `www.tesla.com` | `/sites/all/.../config_web.json` | 403 to curl even with a Chrome UA; 200 in a browser | **ipinfo token** |
| `www.teslamotors.com` | both paths | 301 → `tesla.com` | — (redirect) |

Every 403 above is Akamai refusing an automated client, not the file being absent. Setting a full
Chrome User-Agent does not get past it, so the refusal is on something below the UA string; each
of those URLs was then opened in a normal browser session and the credential was there. Nothing here needed an
account, a cookie, or a guessed path: both paths come from Tesla's own code.

## Impact

Both credentials are metered per call, and both are reachable by anyone who reads a public URL.

Baidu Maps bills per call above a free allowance, and four billable services accept this key.
Anyone who reads one unauthenticated endpoint can:

- run geocoding, reverse geocoding, place search and IP location on Tesla's account, from
  anywhere, at any rate;
- drive Tesla's Baidu spend up, or exhaust the daily quota — at which point Tesla's own China
  "Find Us" map stops resolving locations for real customers.

That second effect is what gives this impact beyond disclosure: the key powers a customer-facing
feature, so burning its quota degrades that feature.

The ipinfo token is worse than the maps key in one respect: it reads the account as well as
spending it. An attacker learns Tesla's plan and usage, and can burn a 50,000-call monthly
allowance of which Tesla itself had used 66. Because the plan has no overage, that is not a bill —
it is an outage: the configurator's IP-based region detection stops working for real visitors
until the month resets, and the server-side path below is what breaks.

The GrowingIO account and data-resource ids are the identifiers a client uses to post analytics
events. Writing a fabricated event would have demonstrated more, and I deliberately did not: that
would modify Tesla's data, which the rules of engagement forbid. The ids are reported as exposed;
what could be done with them is not claimed.

And because the token is published on `www.tesla.com` as well as `www.tesla.cn`, the audience that
can read it is Tesla's global one, not only visitors to the China site.

I kept my own volume deliberately small: ten Baidu calls, one per service, to establish which are
accepted and which are not, and a handful of ipinfo calls — enough to show the token authenticates
and to read `/me` with and without it. I did not probe quota limits on either account. The usage
counter is the receipt for that: it read `day: 4, month: 66` at 18:33 UTC and `day: 7, month: 69`
at 19:35 UTC, so my entire engagement cost Tesla seven lookups out of 50,000.

## Remediation

- **Rotate the ipinfo.io token** and move it server-side. It cannot be restricted, so removing it
  from `config_web.json` and proxying the lookup is the only fix.
- Apply a referrer and/or IP whitelist to the Baidu key, as Tesla already does for its Google
  Maps keys, and rotate it since it has been publicly readable.
- If the key is consumed by a native app where a referrer cannot be set, move it server-side and
  proxy the calls rather than publishing it.
- Review what else `/api/findus/env` returns per region — the `.cn` response carries credentials
  the `.com` response does not, which suggests the endpoint returns whatever the regional config
  happens to hold.
- Sweep the other configurator config files for the same pattern; `config_web.json` was found
  from an Internet Archive record, not from any current link.

## Neither credential appears in public code

Before writing this up I checked whether either value is already published, so that this is not a
report about something already in the open:

```
github.com/search?q="47216944bba1aa"&type=code                    0 files
github.com/search?q="qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z"&type=code  0 files
github.com/search?q="ip_lookup_service_token"&type=code           0 files
```

No repositories, commits, issues or packages either. Both values appear to be reachable only
from the Tesla assets named above.

## Scope and conduct

- `www.tesla.com` and `www.tesla.cn` fall under `*.tesla.com` / `*.tesla.cn`, both listed in the
  brief. Nothing in the out-of-scope list covers third-party API keys or their restrictions.
- No Tesla account, no customer data, no other user, and no automated tooling were involved.

## Reproduction — copy-pasteable, four commands

```bash
# 1. read the Baidu key, unauthenticated
curl -s "https://www.tesla.cn/api/findus/env" | grep -o '"baiduMapAk":"[^"]*"'

# 2. read the ipinfo token, unauthenticated
curl -s "https://www.tesla.cn/sites/all/modules/custom/tesla_configurator/js/config/config_web.json" \
  | grep -o '"ip_lookup_service_token": *"[^"]*"'
#    (same file on www.tesla.com — open in a browser; Akamai 403s curl's User-Agent)

# 3. prove the Baidu key is unrestricted — no Referer, no account
curl -s "https://api.map.baidu.com/geocoding/v3/?address=%E5%8C%97%E4%BA%AC&output=json&ak=qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z"

# 4. prove the ipinfo token is a live account credential
curl -s "https://ipinfo.io/me?token=47216944bba1aa"     # returns the account
curl -s "https://ipinfo.io/me"                          # 400, token required
```

Final verification run: **2026-10-05 19:35:23 UTC**, external IP `180.148.212.54`,
`curl 8.21.0 (aarch64-unknown-linux-android)`.

```
curl "https://ipinfo.io/me?token=47216944bba1aa"
{"token":"47216944bba1aa",
 "requests":{"day":7,"month":69,"limit":50000,"remaining":49931},
 "features":{"core":{"daily":2147483647,"monthly":50000},
             "hostio":{"daily":2147483647,"monthly":1000, …}}}

curl "https://ipinfo.io/me"
{"error":"API token required to view token details. Did you mean to visit /my instead?"}   400
```

### Expected vs observed

| | Expected (secure) | Observed |
|---|---|---|
| Baidu key off-origin | `REQUEST_DENIED` / referrer error, as Tesla's Google keys give | `status:0`, data returned, from Bangladesh with no `Referer` |
| ipinfo token location | server-side only; ipinfo has no referrer control | published in `config_web.json` on `.cn` **and** `.com` |
| `ipinfo.io/me` with the leaked token | should not resolve to an account | returns Tesla's plan, month-to-date usage and remaining balance |

## Evidence held locally

- Browser screenshots of `tesla.com/api/findus/env` and `tesla.cn/api/findus/env` with the
  credentials visible, and of `tesla.cn/.../config_web.json`.
- **Browser screenshot of `www.tesla.com/.../config_web.json` with `ip_lookup_service_token`
  searched and highlighted — 1 of 1 match — and a saved copy of that file.** This is what
  establishes that the exposure is not China-only.
- Terminal screenshot of the ipinfo token check, with and without the token, showing the
  `readme` field appear and disappear.
- Terminal screenshot: `2026-10-05 18:33:28 UTC`, IP `180.148.212.54`,
  `curl 8.21.0 (aarch64-unknown-linux-android)`, the Baidu call succeeding and the Google call
  being refused in one frame.
- `~/tesla/EVIDENCE.txt` — the full final run, timestamped, including the host-by-host spread
  sweep in the table above.
