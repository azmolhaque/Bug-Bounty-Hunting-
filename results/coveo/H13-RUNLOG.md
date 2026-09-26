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

---

## Phase 2 result — query-parameter surface. CLEAN NEGATIVE. 2026-09-26

72 candidates after the extractor fixes (org as a query parameter, GET, no other path
placeholders), each called twice — once with org B's id, once with an id that cannot exist.

**2 flagged, both resolved to nothing.**

### `featureActiveState` — closed

`/rest/search/admin/pipelines/featureActiveState?organizationId=` was the one endpoint of
128 that returned `200` for a foreign org *and* for a nonexistent one, with no denial.

Sorted comparison settles it:

```
org A                    -> 20 features
org B                    -> 20 features   identical
zzznotarealorgzzz999     -> 20 features   identical
```

Byte-for-byte the same list, including the same `active` values, for an org the key owns, an
org it does not, and an org that does not exist. It is a **static default feature list** that
reads no organization state whatsoever. Nothing is disclosed.

My comparator fired only because the JSON array comes back in **nondeterministic order** —
the same trap as the Meta version-liveness result, where the interesting-looking thing was an
artifact of the measurement rather than the system. Two orderings of an identical set read as
a difference until you sort.

### `strictValidationTest` — closed

`/v15/admin/account/strictValidationTest?org=` returns `{"dimensionName":null,
"validationTestResults":[]}` identically for org B and for the fake org. Empty, no
discrimination, no data.

### Verdict

**Coveo's cross-organization authorization holds on the query-parameter surface too.**

Combined with phase 1 that is **~270 endpoints across 25 backend services**, covering both
the path-segment and query-parameter shapes, with no cross-org read and no existence oracle
anywhere. The `UnauthorizedOrg` denials on the analytics tier were correct enforcement my
detector had miscategorised.

The structural hypothesis — that a hand-written per-handler check would be missed somewhere —
did not pay out. Coveo appears to enforce org scope centrally on both shapes.

## Phase 3 — where the remaining surface actually is

Two directions, neither covered so far, in priority order.

### 3a — Search token minting · the highest-value remaining test

Coveo's search tokens are how customers grant scoped search to end users:
`POST /rest/search/v2/token` with `userIds`, `filter`, `searchHub`.

The question: **can an API key scoped to org A mint a search token for org B?** If it can,
that is cross-tenant *data* access — the token then queries org B's index — which is exactly
the bar Coveo named. The boundary under test is the key's org scope, not ownership, so the
fact that both orgs belong to the same identity does not weaken it.

Also worth testing on the minted token: whether a supplied `filter` can be widened or
bypassed, and whether `userIds` can be set to an identity the minter should not speak for.

Coveo's own out-of-scope text calls anonymous search tokens for demo orgs "public by design",
which implies this surface is understood — so check known-issues carefully before writing
anything up.

### 3b — Resource-level identifiers

Everything so far tested *organization*-level checks. Resource-level checks (a specific
source, report, field, catalog) are typically written per handler and are where BOLA usually
survives.

Requires org B to actually contain resources — a fresh `BugBountyCoveo` org is empty. So:
create a source and a report **in org B** using the user token, take their IDs, then attempt
to read them **with org A's key**. Both orgs are ours, so nothing touches another tenant.

This is also what unlocks the endpoints skipped in phases 1 and 2 for carrying extra path
placeholders.

---

## Phase 3a — search credentials. Privilege model mapped; core test still BLOCKED. 2026-09-26

### Coveo's privilege model, learned from rejections

Five privileges are a **"public" class** that a hand-built key may not carry. Verbatim:

```
custom api key cannot have public privileges:
  SEARCH_API      / IMPERSONATE
  SEARCH_API      / EXECUTE_QUERY
  SEARCH_API      / VIEW_ALL_CONTENT
  USAGE_ANALYTICS / IMPERSONATE
  USAGE_ANALYTICS / EDIT ANALYTICS_DATA
```

Two more are rejected outright on custom keys: `SEARCH_API/QUERY_PIPELINE_PREVIEW` and
`SEARCH_API/REPLAY_ANY_QUERY`.

`privacyLevel` is **not** a field on `ApiKeyCreationRequest` — it appears only in responses
and on templates. A key's privacy is therefore derived, not requested. Public keys come from
**templates**: `POST /rest/organizations/{orgId}/apikeys?apiKeyTemplateId=<id>`.

Org A exposes **20 templates**; `AnonymousSearch` and `AnonymousCaseAssist` are
`privacy: PUBLIC` and `canGenerate: true` for this account.

### `overrideTemplatePrivileges` — CLEAN NEGATIVE

`ApiKeyCreationRequest.overrideTemplatePrivileges` is documented as *"the privileges that
will be used to override the privileges of the template"*. The hypothesis: generate from a
PUBLIC template while overriding with administrative privileges, yielding an
anonymously-usable key holding elevated rights — a credential meant to sit in a public web
page, carrying `ORGANIZATION:EDIT`.

Rejected:

```
The following privileges are not allowed:
  [PLATFORM/SOURCE:EDIT, PLATFORM/API_KEY:EDIT, PLATFORM/ORGANIZATION:EDIT]
```

The wall between the public and custom privilege classes is enforced in the override path
too. **Closed.**

### The public key generated cleanly

`AnonymousSearch` with no override produced exactly the credential customers embed in public
web pages:

```
privacy: PUBLIC
privileges: SEARCH_API/EXECUTE_QUERY, USAGE_ANALYTICS/EDIT ANALYTICS_DATA,
            USAGE_ANALYTICS/IMPERSONATE
```

### The core test is BLOCKED, not negative

`POST /rest/search/v2?organizationId=…` returned **503 SERVER_UNAVAILABLE for all three**
targets — org A included. A fresh `BugBountyCoveo` organization has no sources, therefore no
index, therefore nothing for the search service to answer with.

**The positive control failed, so [2] and [3] prove nothing.** Recorded as blocked.

This is the fifth invalid control in phase 3, each for a different legitimate reason: the
first key lacked `IMPERSONATE`; the full-privilege key was refused for carrying public
privileges; then for two more disallowed ones; `KEYA` could not read templates; and now no
index exists. Every one was caught by insisting the positive control pass first. Without
that rule, four of the five would have been written down as clean negatives.

### Unblocking it — populate the organizations

Both orgs need a source with at least one document before any search-scoping question can be
asked. Push API, in organizations we own:

1. Create a push source in org A and in org B.
2. Push one benign document into each, with distinguishable content so a cross-org read is
   unambiguous in the response body.
3. Re-run: org-A public key queries org A (control), then org B, then the fake org.

Populating also unblocks **phase 3b** — resource-level identifiers. Every endpoint skipped in
phases 1 and 2 for carrying a second path placeholder (`{sourceId}`, `{reportId}`,
`{fieldId}`) becomes testable once real IDs exist in org B.

### Live keys in org A (housekeeping)

```
se5lbkepjegleygxgkhfp4smh4  PRIVATE  h13-sweep
u3ee7e3ytbr6tspxifzyixsnxm  PUBLIC   h13-anon-base
```

Delete both once phase 3 concludes.
