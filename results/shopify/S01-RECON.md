# S01 — Shopify unauthenticated recon (2026-10-06)

**Verdict: the unauthenticated infrastructure surface is closed. The value here is authenticated,
multi-tenant testing, which needs two development stores.**

---

## Method

Internet Archive CDX over `shopifycloud.com`, `shopify.io`, `shopifycs.com` — the same
non-touching discovery that produced the one Tesla finding. No subdomain brute force, no path
guessing.

```
h-cloud.txt    1,779 hostnames   (shopifycloud.com, limit raised to 200,000 after the first
                                  pull truncated at 40,000)
h-other.txt      718 hostnames   (shopify.io, shopifycs.com)
ALLHOSTS.txt   2,497 unique
HOT.txt          755 filtered on kibana|elastic|alertmanager|prometheus|grafana|jenkins|
                     artifact|vault|consul|icinga|appsec|dashboard|internal|metrics|graphql|
                     swagger|admin|investigate|secret|config
ALIVE.txt         52 responded
```

## The 52, grouped by what is actually guarding them

| Response | Count | Guard |
|---|---|---|
| `302` → `minerva.shopifycloud.com/auth/minerva` → `shopify.okta.com` | ~24 | Okta SSO |
| `302` → `accounts.google.com` → `iap.googleapis.com` (`hd=shopify.com`) | 2 | Google Cloud IAP |
| `401` `missing client certificate` | ~16 | **mTLS** |
| `404` 0–9 b | 5 | app answers, no discoverable paths |
| `503` 12,193 b | 4 | service down |
| `301` → `*.quick.shopify.io` | 2 | another layer |

Names behind those guards include `appsec-dashboard`, `infrasec-dashboard`,
`incident-dashboard`, `vault`, `vault-staging`, `vaultbot`, `alertmanager-*` (14 regions),
`*.kibana.*`, `*.secure-elasticsearch.*`, `admin-investigate-api-production`,
`customer-data-platform-admin`. Every one of them is gated. **Shopify's internal tooling is
properly locked down** — this is not the Tesla situation where a decommissioned Drupal tree was
still serving config files.

### SENTINEL — the control that makes the above meaningful

```
zzz-canary-does-not-exist.shopifycloud.com   no DNS (curl never connected)
zzz-canary-does-not-exist.shopify.io         no DNS
```

No wildcard DNS, so the hosts that answered are genuinely distinct and the response classes above
mean what they appear to mean.

## The one lead that looked real, and the control that killed it

`minerva.shopifycloud.com/auth/minerva?request=<uuid>&rd=<url>` carries a **redirect-destination
parameter** inside an SSO flow. An unvalidated `rd` there would not be a routine open redirect —
it could carry auth material off-origin.

```
[1] rd=https://appsec-dashboard.shopify.io/              302 -> okta, redirect_uri=minerva callback
[2] rd=https://example.com/                              302 -> identical
[3] rd=https://appsec-dashboard.shopify.io.example.com/  302 -> identical
[4] rd=//example.com/                                    302 -> identical
[5] NO rd AT ALL                                         302 -> identical
```

`[5]` is what settles it. With **no `rd` whatsoever** the response is the same, so `rd` has no
effect on this hop at all. The OAuth `redirect_uri` is hardcoded to
`https://minerva.shopifycloud.com/auth/okta/callback` in every case, and `state` is a fresh UUID —
`rd` is held server-side against that state, never carried in the URL.

Without `[5]` I would have read `[2]` as "example.com accepted" and chased a finding that is not
there. Whether minerva honours a stored `rd` *after* a successful Okta login is untestable without
Shopify employee credentials, which we do not have and will not attempt. Precondition, not a
crossing — dropped under §2.6.

## The five hosts with no identity gate, and why they stop here

```
404  0b   pay-internal-admin.shopify.io              (no server header)
404  9b   bcldb-integration-internal.shopifycloud.com          "Not Found", Google Frontend
404  9b   bcldb-integration-production-internal.shopifycloud.com
404  9b   bcldb-integration-staging-internal.shopifycloud.com
404  9b   bcldb-integration-dev-internal.shopifycloud.com
```

These answer directly — no SSO redirect, no 401 — so an application is deployed and reachable.
But the archive holds **exactly one URL for each**, the bare `/`. There are no app-derived paths,
and paths will not be invented. Parked, not dropped: if a path for any of them ever surfaces from
Shopify's own code or a future archive capture, this is a live starting point.

## Scope note carried forward

`*.shopify.io` is in scope but the policy warns it "may include developer test or third party
applications". Anything found there needs confirmation that it is Shopify's own before a report.
`*.shopifycloud.com` is clean.

## Conclusion, stated plainly

Unauthenticated recon against Shopify's infrastructure is exhausted and produced nothing
reportable. That was the predicted outcome — it was run because the operator wanted terminal work
before creating accounts, and it was worth the thirty minutes to establish rather than assume.

**The money on this program is behind a free signup**, in the class that needs two development
stores: cross-store object access, staff-role permission bypass, Storefront API over-exposure, app
OAuth scope escalation. Shopify GIDs embed real database ids rather than 122-bit randomness, and
every identifier would be one we minted ourselves in a store we own — which is precisely the wall
that killed Tesla T04 and Marriott M025.

Next action: `partners.shopify.com` → two development stores → Admin API tokens → the four-way
cross-tenant test (positive control, cross attempt, sentinel token) already drafted.

## Final piece — `*.quick.shopify.io` is a wildcard behind Google IAP

```
vaultscope.quick.shopify.io    302 -> accounts.google.com ... client_id=503582027637-7jii1kpb...
artifact.quick.shopify.io      302 -> identical
zzz-canary.quick.shopify.io    302 -> identical        <- SENTINEL, same client_id
```

The canary — a hostname that does not exist — gets the same IAP redirect with the same client id.
So the whole namespace is wildcard-routed behind Google Cloud IAP, and subdomain existence leaks
nothing either. Closed.

**Recon on this program is now complete and produced nothing reportable.** Every live host is
behind Okta SSO, Google IAP or mTLS; the five ungated hosts have no discoverable paths. The
unauthenticated surface is genuinely well built.
