# PASTE THIS INTO BUGCROWD — final submission text for F001

Everything between the two `=====` rules goes in the **Description** box, as-is.
Fields above it go in their own boxes.

---

**Title**

```
Unauthenticated config files on www.tesla.com and www.tesla.cn expose an unrestricted Baidu Maps key and a live ipinfo.io account token
```

**VRT Category**

```
Sensitive Data Exposure  >  Disclosure of Secrets  >  Pay-Per-Use Abuse
```

**bug_url**

```
https://www.tesla.com/sites/all/modules/custom/tesla_configurator/js/config/config_web.json
```

=====================================================================

## Summary

Two files that anyone can read without logging in publish two live third-party credentials:

- `https://www.tesla.com/api/findus/env` — a Baidu Maps key with no referrer or IP restriction
- `https://www.tesla.com/sites/all/modules/custom/tesla_configurator/js/config/config_web.json` —
  an active ipinfo.io API token

Both files are served from **`www.tesla.com` and `www.tesla.cn`**. I verified both credentials
work from my own machine in Bangladesh, with no Tesla account and no `Referer` header.

## Why this is not intended behaviour

A client-side map key being *visible* is normal. This one being *unrestricted* is not, and your own
Google Maps keys are the proof that the difference is understood internally. The same shape of
call against three of Tesla's Google keys is refused:

```
curl "https://maps.googleapis.com/maps/api/geocode/json?address=Austin&key=AIzaSyBleO1VLDr7rDuIey2SMG-P3qdXXL76WK4"

{"error_message":"API keys with referer restrictions cannot be used with this API.",
 "results":[],"status":"REQUEST_DENIED"}
```

Same company, same class of credential, same class of request — restricted. The Baidu key was
missed.

The ipinfo.io token has no such defence available at all. **ipinfo offers no referrer or origin
restriction**, so a token is a server-side credential by definition. Publishing it in a
client-side JSON file is the entire issue, and there is no configuration that makes it safe where
it currently sits.

## Reproduction

```bash
# 1 — read the Baidu key, unauthenticated
curl -s "https://www.tesla.cn/api/findus/env" | grep -o '"baiduMapAk":"[^"]*"'
"baiduMapAk":"qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z"

# 2 — read the ipinfo token, unauthenticated
curl -s "https://www.tesla.cn/sites/all/modules/custom/tesla_configurator/js/config/config_web.json" \
  | grep -o '"ip_lookup_service_token": *"[^"]*"'
"ip_lookup_service_token": "47216944bba1aa"

# 3 — the Baidu key works off-origin: no Referer, no account, from Bangladesh
curl -s "https://api.map.baidu.com/geocoding/v3/?address=%E5%8C%97%E4%BA%AC&output=json&ak=qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z"
{"status":0,"result":{"location":{"lng":116.4133836971231,"lat":39.910924547299568},
 "precise":0,"confidence":20,"comprehension":100,"level":"城市"}}

# 4 — the ipinfo token is a live ACCOUNT credential, not just a lookup key
curl -s "https://ipinfo.io/me?token=47216944bba1aa"
{"token":"47216944bba1aa",
 "requests":{"day":7,"month":69,"limit":50000,"remaining":49931},
 "features":{"core":{"daily":2147483647,"monthly":50000},
             "hostio":{"daily":2147483647,"monthly":1000, …}}}

# 5 — negative control: the same path without the token
curl -s "https://ipinfo.io/me"
{"error":"API token required to view token details. Did you mean to visit /my instead?"}    HTTP 400
```

`"status":0` is Baidu's success code. Step 5 is there so you can see the difference is the token
and nothing else.

**On `www.tesla.com`, use a browser rather than curl.** Akamai returns 403 to curl on these paths
even with a full Chrome User-Agent (`Reference #18.65a5c117…`), so it is fingerprinting below the
UA string. In a browser both URLs load normally — screenshots and the complete saved responses are
attached.

## What the Baidu key can and cannot do

I tested the boundaries deliberately so the scope is not overstated. **Five** services accept it:

```
geocoding/v3            status 0    coordinates returned
reverse_geocoding/v3    status 0    full street address for a Shanghai coordinate
place/v2/search         status 0    "特斯拉(北京朝阳合生汇城市展厅)" and further POIs
place/v2/detail         status 0    full record for a single POI
location/ip             status 0    resolved my own IP
```

**Four refuse it**, which bounds the finding:

```
direction/v2/driving        status 240   "APP 服务被禁用"
weather/v1                  status 240   "APP 服务被禁用"
geodata/v3/geotable/list    status 240   "APP 服务被禁用"    (cloud data storage)
yingyan service/list        status 1     internal error       (vehicle tracking)
```

So the key cannot read stored Tesla data and cannot reach the routing APIs. It consumes the five
metered services above and nothing more.

## The ipinfo token is in live production use on www.tesla.com

This is the part I would most like a triager to check, and it takes one click:

```
https://www.tesla.com/sites/all/modules/custom/tesla_findus_map/proxy.php?ip=true

{ "ip": "205.234.27.201", "city": "San Jose", "region": "California", "country": "US",
  "loc": "37.3394,-121.8950", "org": "AS40913 Quality Technology Services, LLC",
  "postal": "95110", "timezone": "America/Los_Angeles" }
```

The address returned is the **calling machine's** egress, in San Jose — not mine, in Bangladesh.
`www.tesla.com` performs this ipinfo lookup server-side, which means the leaked token is being
spent by the main global site's production code path right now. It is not a stale value left in an
old build.

(The `.cn` site does the same thing and returns a Shanghai address, `103.222.41.40`.)

I am not reporting the returned IP itself — infrastructure IP disclosure is out of scope by your
brief. It appears here only because it is what proves the call is server-side.

## Where the credentials are exposed

| Host | Path | Credential |
|---|---|---|
| `www.tesla.com` | `/api/findus/env` | Baidu key |
| `www.tesla.cn` | `/api/findus/env` | Baidu key |
| `www.tesla.com` | `/sites/all/modules/custom/tesla_configurator/js/config/config_web.json` | ipinfo token |
| `www.tesla.cn` | same path | ipinfo token |

The `.com` and `.cn` copies of `config_web.json` are both **329,052 bytes — byte-for-byte the same
length** — and carry the same token. Both files are attached.

Nothing here needed an account, a cookie, or a guessed path. Both paths come from Tesla's own code.

## Impact

Both credentials are metered per call and reachable by anyone who reads a public URL.

**Baidu key:** anyone can run geocoding, reverse geocoding, place search, place detail and IP
location on Tesla's account, from anywhere, at any rate. Beyond the spend, the key powers the China
"Find Us" map — exhausting its quota degrades a customer-facing feature.

**ipinfo token:** this one also *reads* the account, not just spends it. `/me` returns Tesla's
plan, month-to-date consumption and remaining balance. To be accurate rather than dramatic: 50,000
lookups a month is ipinfo's **free** tier, so I am not claiming a bill. The consequence runs the
other way — a free plan has no overage headroom, so when the allowance is gone the account simply
stops answering until the month rolls over. Tesla had used **69** of 50,000 when I checked; anyone
holding this token can burn the remaining 49,931 in minutes, and the `proxy.php` lookup above then
fails for real visitors on both sites.

Because the token is published on `www.tesla.com`, not only on the China site, the population that
can read it is the global one.

## Conduct — what I did and did not do

- No Tesla account, no customer data, no other user's data, no automated scanning.
- I did **not** probe quota limits on either account. My usage counter is the receipt: ipinfo read
  `day: 4, month: 66` at 18:33 UTC and `day: 7, month: 69` at 19:35 UTC. My entire engagement cost
  seven lookups out of 50,000.
- The `config_web.json` file also contains GrowingIO analytics identifiers. I did **not** write a
  test event with them, because that would modify Tesla's data. I report them as exposed and claim
  nothing further about them.
- Neither credential appears in public code — `47216944bba1aa`, `qAt8bB6YfSE69wpL9zPMcSVCdkjQO94Z`
  and `ip_lookup_service_token` each return 0 results on GitHub code search, with no repositories,
  commits, issues or packages either.

Verification run: **2026-10-05 19:35:23 UTC**, external IP `180.148.212.54`,
`curl 8.21.0 (aarch64-unknown-linux-android)`.

## Remediation

1. **Rotate the ipinfo.io token and move it server-side.** It cannot be restricted, so removing it
   from `config_web.json` and proxying the lookup is the only fix. `proxy.php` already performs the
   lookup server-side, so the token does not need to be in the client file at all.
2. **Restrict and rotate the Baidu key** — apply a referrer and/or IP whitelist, as is already done
   for Tesla's Google Maps keys. Rotate it, since it has been publicly readable.
3. **Review what `/api/findus/env` returns per region.** The `.cn` response carries analytics
   credentials the `.com` response leaves blank, which suggests the endpoint emits whatever the
   regional config holds rather than a vetted allowlist.
4. **Sweep the remaining configurator config files.** I checked the 4,442 archived URLs under
   `/sites/all/modules/` and `config_web.json` is the only one carrying a credential — but it was
   reachable from an Internet Archive record rather than from any current link, so files no longer
   referenced are still being served.

=====================================================================

## Attachments — attach exactly these six

| # | File | Why |
|---|---|---|
| 1 | `env.json` (5,799 b) | The complete unauthenticated `tesla.com/api/findus/env` response |
| 2 | `config_web_com.json` (329,052 b) | The `.com` copy with the token |
| 3 | `config_web_cn.json` (329,052 b) | The `.cn` copy — same length, same token |
| 4 | Screenshot: `tesla.com/.../proxy.php?ip=true` → San Jose | Strongest single item: the token is spent server-side by `.com` |
| 5 | Screenshot: `tesla.com/.../config_web.json`, token highlighted 1/1 | The exposure is global, not China-only |
| 6 | Screenshot: terminal, Baidu success beside Google `REQUEST_DENIED` | The differential that kills "intended behaviour" |

**Do not attach** the `Expired or invalid token` screenshot. That belongs to a separate lead I
dropped; including it invites questions about an issue this report does not claim.

## Two things to resist after submitting

1. **Do not argue the severity up.** If it lands P4, take P4. Pay-Per-Use Abuse is the honest
   category for a metered third-party credential.
2. **Do not re-argue a rejection with the same evidence.** If it is closed, the next move is a new
   finding, not a longer version of this one.
