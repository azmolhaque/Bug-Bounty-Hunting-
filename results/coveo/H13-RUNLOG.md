# H13 — Coveo: cross-organization authorization

Program: Coveo Public Bug Bounty (Intigriti), `*.cloud.coveo.com` **Tier 2, in scope**.
Bounty $100–$5,500, average payout $664.
Coveo's own stated bar: *"proven cross-tenant data access using two separate test organizations."*

## Environment, 2026-09-25

Identity: `gorib@intigriti.me` (Intigriti alias, Provider: Email).

Three organizations created via the program's documented endpoint, all owned by the same
identity:

```
bugbountygoriba9hyg0ttn    bugbounty-gorib-a
bugbountygoribbcsq3h50g    bugbounty-gorib-b
bugbountygoribb2ics0l883   bugbounty-gorib-b2
```

### The `owner` parameter is normalised to the caller

`?owner=gorib+b@intigriti.me` and `?owner=gorib%2Bb@intigriti.me` both produced organizations
owned by `gorib@intigriti.me`. Plus-addressing does not create a distinct identity here.

**This changed the test design, and for the better.** The original plan needed two human
owners so that org B was unreachable by definition. That is not available — but it is also
not the right boundary. Coveo's real product boundary is the **API key, which is issued per
organization**. A key minted in org A must not work against org B *regardless of who owns
either*, because Coveo's customers depend on exactly that scoping. Testing the key's scope
is both achievable with one identity and closer to what the product actually promises.

User token: short-lived, **~4 hours** (`{"token":…,"expiration":…}` in localStorage under
`coveo-access-token`). Test sessions have a clock on them, so runs must be scripted and
repeatable rather than exploratory.

## Control rig — established and verified

API key minted in org A with `{"owner":"PLATFORM","targetDomain":"ORGANIZATION","type":"VIEW","targetId":"*"}`.

| # | Test | Expected | Actual |
|---|---|---|---|
| 1 | org-A key → `GET /rest/organizations/{ORGA}` | 200 | **200**, org A returned |
| 2 | org-A key → `GET /rest/organizations/{ORGB}` | deny | **403** `ACCESS_DENIED` |
| 3 | org-A key → `GET /rest/organizations/{ORGB2}` | deny | **403** `ACCESS_DENIED` |
| 4 | org-A key → `GET /rest/organizations/zzznotarealorgzzz999` | deny | **403** `ACCESS_DENIED` |
| 5 | org-A key → `GET /rest/organizations` | org A only | **200**, org A only |

All five behaved correctly. **No finding on the base endpoint** — expected, it is the most
obviously guarded route in the platform.

### Baselines banked

- **Denial signature:** `403` + `{"message":"Access is denied.","errorCode":"ACCESS_DENIED","requestID":…}`
- **No existence oracle.** A nonexistent organization returns the *same* 403 as a real one the
  key cannot see. Coveo deliberately refuses to distinguish them. Therefore **any deviation —
  a 404, a different `errorCode`, a different body shape — is signal before any data is
  returned.**
- **Key scope is genuine.** Listing organizations with the org-A key returns org A alone, so
  the key is not silently treated as the owning user.

Key `uic7hiwqndpceyfunafgnbka54` deleted after the test (`204`).

## Where the hunt goes next

The base `/rest/organizations/{organizationId}` route enforces properly. The surface worth
sweeping is everything else: the Swagger lists **37 service groups** — Activity, Analytics,
Admin, AuthorizationServer, Catalog Management, Commerce, Connectivity, Context, Customer
Service, Document Logs, Event, Extension, Field, Index, Knowledge, Generative AI, Machine
Learning (×3), Migration, Notification, Organization, Platform, PushApi, Schema, Search API,
Search Interface, Search Pages, Search Usage Metrics, SecurityCache, SocialProof, Source,
Source Logs, Tailgate, Usage Analytics Read/Write, Workspace.

These are **separate backend services**, several on different hostnames (`search.cloud`,
`analytics.cloud`, `api.cloud`). The platform API enforcing correctly says nothing about
whether a downstream service does. Every endpoint in the Swagger publishes its required
privilege as a structured object, which gives a machine-readable authorization matrix to
sweep against.

**Sweep design:** for every path containing `{organizationId}`, issue a **GET only**, with the
org-A key, substituting org B's ID. Report anything that is **not** the 403 denial signature.
Read-only; no writes against any organization during the sweep.

---

## Sweep result — 196 paths, 25 services. CLEAN NEGATIVE. 2026-09-25

Org-A API key against org B's ID, GET only, across every path whose sole placeholder is
`{organizationId}`. 32 of 34 specs fetched (`DocumentLogs` and `SocialProof` 404 — slugs
unresolved).

The filter reported 111 "anomalies", but that was **my filter being too narrow**: it
recognised only `403 ACCESS_DENIED`, and Coveo uses three denial formats —
`ACCESS_DENIED` (platform), `MissingPrivilegesException` (most services), and
`AccessDeniedException` (SearchApi). Reclassified:

| Code | Count | What it is |
|---|---|---|
| 405 | 63 | path exists, GET unsupported — noise |
| 403 | 26 | correct denial in one of the other two formats |
| 412 / 422 / 400 | 18 | missing or invalid query parameter |
| 404 | 3 | routing |
| **200** | **1** | `/members/privileges` — investigated below |

**True anomaly count: zero.** Every response resolves to correct behaviour.

### The three follow-ups, all closed

**A — `/rest/organizations/{id}/members/privileges` returned `200 []` against org B.**
It returns *the caller's own privileges in the named organization*:

```
org A  + keyA  -> [{"type":"VIEW","targetDomain":"ORGANIZATION","targetId":"*","owner":"PLATFORM"}]
org B  + keyA  -> []
FAKE   + keyA  -> []          <-- identical to org B
org B  + user  -> [ …full list… ]
```

A real organization the key cannot see and an organization that does not exist return the
**same** empty array. No existence oracle, no data. "Your privileges here: none" rendered as
`200 []` rather than `403`. A design inconsistency with zero attacker gain — and explicitly
on Coveo's out-of-scope list as *"low impact inconsistencies between documentation and
actual platform/api privileges."* Dead.

**B — `salesforce/trial/licenseStatus` echoing the org ID** is plain string interpolation.
The fake org gets the same sentence with the fake ID in it. No oracle. Dead.

**C — parameter validation before the authorization check.** `access/apikeys` returns an
identical `412 MISSING_PARAMETER` for org B and for the nonexistent org. The ordering is
real (same pattern as Meta's `generatepreviews`) but it discriminates nothing. Dead.

### Verdict on the path-scoped surface

**Coveo's path-based organization scoping is sound.** 196 endpoints across 25 backend
services, all correctly denying a cross-org key, with no existence oracle anywhere and no
response that distinguishes a hidden organization from an imaginary one.

This is a real result rather than an absence of one: it says where *not* to keep looking.

## Phase 2 — the query-parameter surface

The sweep deliberately covered the easier half. The large specs contributed almost nothing:

```
SearchApi            563 KB  ->  5 paths
UsageAnalyticsRead   368 KB  ->  0 paths
PushApi              400 KB  ->  0 paths
SearchPagesService   144 KB  ->  0 paths
```

Not because they are small, but because **they take the organization as a query parameter**
(`?organizationId=`, `?org=`) or live on other hostnames (`search.cloud`, `analytics.cloud`,
`api.cloud`). My filter only matched `{organizationId}` in the path.

That is the more promising half, and for a structural reason: when the tenant ID is a path
segment, the router sees it and a framework-level check can cover every route at once. When
it is a query parameter, **the check has to be written by hand in each handler** — so it is
exactly the kind of place where one handler gets missed.

This is also the same shape as the Exoscale `parameters.bucket` work: a tenant identifier
carried as a parameter rather than as part of the resource path.

Next: extract every endpoint taking an org-ish query parameter across the 32 specs, plus the
non-platform hostnames, and sweep those with the org-A key against org B.
