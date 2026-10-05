# F001 — Unauthenticated config endpoint exposes third-party credentials, one of them unrestricted

**Status:** ready to submit · Bugcrowd, Tesla · targets `*.tesla.com`, `*.tesla.cn`
**Found:** 2026-10-05 · **Researcher:** Gorib (`gorib@bugcrowdninja.com`) · **IP:** 180.148.212.54

## The point in one sentence

`/api/findus/env` is readable with no authentication on both `www.tesla.com` and `www.tesla.cn`
and hands out third-party service credentials — including a **Baidu Maps key that carries no
referrer or IP restriction**, so anyone can spend Tesla's Baidu quota from anywhere.

A browser-side map key being visible is normal. **The bug is that this one is unrestricted**, and
the proof that Tesla knows better is their own Google Maps keys, which are correctly locked down.

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

`HTTP 200`. `"status":0` is Baidu's success code. **Four** Baidu services accept it:

```
geocoding/v3            status 0   coordinates returned
place/v2/search         status 0   "特斯拉(北京朝阳合生汇城市展厅)" and more POIs
location/ip             status 0   resolved my own IP
reverse_geocoding/v3    status 0   full street address for a Shanghai coordinate
```

Two do not, which is worth stating so the scope is not overstated:

```
geodata/v3/geotable/list   status 240  "APP 服务被禁用"   (cloud data storage disabled)
yingyan service/list       status 1    internal error     (vehicle tracking not enabled)
```

So the key cannot read stored Tesla data — it can only consume paid API calls. I tested those two
specifically to establish the ceiling rather than to leave it implied.

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

Baidu Maps bills per call above a free allowance, and four billable services accept this key.
Anyone who reads one unauthenticated endpoint can:

- run geocoding, reverse geocoding, place search and IP location on Tesla's account, from
  anywhere, at any rate;
- drive Tesla's Baidu spend up, or exhaust the daily quota — at which point Tesla's own China
  "Find Us" map stops resolving locations for real customers.

That second effect is what gives this impact beyond disclosure: the key powers a customer-facing
feature, so burning its quota degrades that feature.

The GrowingIO account and data-resource ids are the identifiers a client uses to post analytics
events, so they also allow fabricated events to be written into Tesla China's analytics. I did
not test that, and I am not claiming it — it is noted because it comes from the same endpoint and
the same root cause.

I made exactly six calls in total, one per Baidu service, purely to establish which are accepted.
I did not probe quota limits.

## Remediation

- Apply a referrer and/or IP whitelist to this Baidu key, as Tesla already does for its Google
  Maps keys, and rotate it since it has been publicly readable.
- If the key is consumed by a native app where a referrer cannot be set, move it server-side and
  proxy the calls rather than publishing it.
- Review what else `/api/findus/env` returns per region — the `.cn` response carries credentials
  the `.com` response does not, which suggests the endpoint returns whatever the regional config
  happens to hold.

## Scope and conduct

- `www.tesla.com` and `www.tesla.cn` fall under `*.tesla.com` / `*.tesla.cn`, both listed in the
  brief. Nothing in the out-of-scope list covers third-party API keys or their restrictions.
- No Tesla account, no customer data, no other user, and no automated tooling were involved.

## Evidence held locally

- Browser screenshots of `tesla.com/api/findus/env` and `tesla.cn/api/findus/env` with the
  credentials visible.
- Terminal screenshot: `2026-10-05 18:33:28 UTC`, IP `180.148.212.54`,
  `curl 8.21.0 (aarch64-unknown-linux-android)`, the Baidu call succeeding and the Google call
  being refused in one frame.
