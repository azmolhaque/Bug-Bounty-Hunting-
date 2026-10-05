# F001 — Unrestricted Baidu Maps API key served from `www.tesla.com/api/findus/env`

**Status:** ready to submit · Bugcrowd, Tesla · target `*.tesla.com`
**Found:** 2026-10-05 · **Researcher:** Gorib (`gorib@bugcrowdninja.com`) · **IP:** 180.148.212.54

## The point in one sentence

`https://www.tesla.com/api/findus/env` returns a Baidu Maps API key with **no referrer or IP
restriction on it**, so anyone can spend Tesla's Baidu Maps quota and bill from anywhere.

The key being visible is not the bug — browser-side map keys are necessarily public. **The bug is
that this one is unrestricted**, and the proof that Tesla knows this is their own Google Maps
keys, which are correctly locked down.

## Reproduce

No account, no authentication, two requests.

```
1.  Open https://www.tesla.com/api/findus/env in a browser.
    (curl is refused by Akamai with 403; a browser is served normally.)
    The JSON ends with:

      "baiduMapAk":"qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z",
      "gioConfig":{"GIO_ACCOUNT_ID":"","GIO_DATA_RESOURCE_ID":"","GIO_HOST":""}

2.  Use the key from any machine, with no Referer header:

    curl "https://api.map.baidu.com/geocoding/v3/?address=%E5%8C%97%E4%BA%AC&output=json&ak=qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z"
```

### Response, verbatim

```json
{"status":0,"result":{"location":{"lng":116.4133836971231,"lat":39.910924547299568},"precise":0,"confidence":20,"comprehension":100,"level":"城市"}}
```

`HTTP 200`, 145 bytes. `"status":0` is Baidu's success code. A second service accepts it too:

```
curl "https://api.map.baidu.com/place/v2/search?query=tesla&region=%E5%8C%97%E4%BA%AC&output=json&ak=<key>"
{"status":0,"message":"ok","result_type":"poi_type","results":[{"name":"特斯拉(北京朝阳合生汇城市展厅)", …}]}
```

Both from 180.148.212.54, Bangladesh, with no Referer set.

## The differential — why this is a mistake and not a decision

Tesla's Google Maps keys, taken from Fleetview's and the CUA app's bundles, refuse the same kind
of call:

```
curl "https://maps.googleapis.com/maps/api/geocode/json?address=Austin&key=AIzaSyBleO1VLDr7rDuIey2SMG-P3qdXXL76WK4"

{"error_message":"API keys with referer restrictions cannot be used with this API.",
 "results":[],"status":"REQUEST_DENIED"}
```

Same company, same kind of credential, same kind of request — restricted. I checked three of
Tesla's Google keys and all three behave this way. The Baidu key is the one that does not.

## Impact

Baidu Maps bills per call above a free allowance. Anyone who reads one unauthenticated endpoint
can:

- run geocoding and place-search on Tesla's account, from anywhere, at whatever rate they like;
- drive Tesla's Baidu spend up, or exhaust the daily quota, at which point Tesla's own China
  "Find Us" map stops resolving locations for real customers.

The second effect is the one that matters: the key is used by a customer-facing feature, so
burning its quota degrades that feature.

I did not test the limits of the quota and I made exactly two calls, one per service, to show
the key is accepted.

## Remediation

- Apply a referrer (and/or IP) whitelist to this key in the Baidu Maps console, as Tesla already
  does for its Google Maps keys.
- Rotate it, since it has been publicly readable.
- If the endpoint is consumed by anything other than the browser, move the key server-side and
  proxy the calls.

## Notes

- Target `www.tesla.com` falls under `*.tesla.com`, which the brief lists in scope. Nothing in
  the out-of-scope list covers third-party API keys or their restrictions.
- No Tesla account, no customer data and no other user was involved at any point.

## Evidence held locally

- Browser screenshot of `tesla.com/api/findus/env` with the key visible.
- Terminal screenshot: date `2026-10-05 18:33:28 UTC`, IP `180.148.212.54`,
  `curl 8.21.0 (aarch64-unknown-linux-android)`, the Baidu call succeeding and the Google call
  being refused, in one frame.
