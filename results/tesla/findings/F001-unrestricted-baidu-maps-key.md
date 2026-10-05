# F001 — Publicly readable Tesla config exposes two working third-party credentials

**Status:** ready to submit · Bugcrowd, Tesla · targets `*.tesla.com`, `*.tesla.cn`
**Found:** 2026-10-05 · **Researcher:** Gorib (`gorib@bugcrowdninja.com`) · **IP:** 180.148.212.54

## The point in one sentence

Two Tesla assets that anyone can read without logging in — the `/api/findus/env` endpoint and the
`config_web.json` configurator file — publish **two live third-party credentials**: a Baidu Maps
key with no referrer or IP restriction on it, and an active ipinfo.io API token.

A browser-side map key being *visible* is normal; this one being *unrestricted* is not, and
Tesla's own Google Maps keys prove they know the difference. The ipinfo token has no excuse at
all — ipinfo has no referrer restriction to apply, so that token was never meant to leave the
server.

Both are billable. I verified both work from my own machine with no Tesla account.

## What the endpoint returns

```
GET https://www.tesla.com/api/findus/env        200, application/json, no auth
    …"baiduMapAk":"qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z",
      "gioConfig":{"GIO_ACCOUNT_ID":"","GIO_DATA_RESOURCE_ID":"","GIO_HOST":""}

GET https://www.tesla.cn/api/findus/env         200, application/json, no auth
    …"baiduMapAk":"qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z",
      "GIO_ACCOUNT_ID":"b0e25bc027704bfe",
      "GIO_DATA_RESOURCE_ID":"93d9fb8b42c30cc0",
      "GIO_HOST":"akamai-apigateway-gio-analytics.tesla.cn"
```

The `.com` response leaves the GrowingIO fields blank; **the `.cn` response fills them in**. Both
hand out the same Baidu key.

(`curl` to `www.tesla.com` is refused by Akamai with 403; a browser is served normally, and the
screenshot is attached. `www.tesla.cn` answers `curl` directly.)

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

`https://www.tesla.cn/sites/all/modules/custom/tesla_configurator/js/config/config_web.json`
is served with no authentication (200, 329 KB) and contains:

```json
"use_ip_lookup_service": true,
"ip_lookup_service_token": "47216944bba1aa",
"apiNames": {"ipInfo": "https://ipinfo.io/geo", …}
```

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

### The token is in live production use, not a leftover

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

I made ten calls in total: six to Baidu, one per service, to establish which are accepted, and
four to ipinfo — two to show the token authenticates and two against `/me` with and without it. I
did not probe quota limits on either account, and the usage counter above shows the cost of my
testing: four calls on the day.

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

## Evidence held locally

- Browser screenshots of `tesla.com/api/findus/env` and `tesla.cn/api/findus/env` with the
  credentials visible, and of `tesla.cn/.../config_web.json`.
- Terminal screenshot of the ipinfo token check, with and without the token, showing the
  `readme` field appear and disappear.
- Terminal screenshot: `2026-10-05 18:33:28 UTC`, IP `180.148.212.54`,
  `curl 8.21.0 (aarch64-unknown-linux-android)`, the Baidu call succeeding and the Google call
  being refused in one frame.
