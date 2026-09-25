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
