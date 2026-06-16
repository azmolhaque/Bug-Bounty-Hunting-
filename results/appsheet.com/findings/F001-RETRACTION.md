# F001 — Retraction & Disproof

**Status:** RETRACTED — false positive. Not submitted to Google VRP.
**Date:** 2026-06-16
**Verified by:** live re-test from Raspberry Pi (direct internet, region BD)

---

## Original claim (now disproven)

F001 claimed an authentication bypass on `api.gcp-staging.appsheet.com`: that **production**
rejected unauthenticated requests with `"The ApplicationAccessKey is missing from the HTTP
header."` while **staging** skipped auth and returned `"App … not found"`. The "App not found"
on staging was interpreted as proof the key check was absent.

## Disproof — prod and staging are identical

Re-tested 2026-06-16 ~11:36 UTC, unauthenticated, zero-UUID
(`00000000-0000-0000-0000-000000000001`), across three endpoints/methods:

| Method / path | `api.appsheet.com` (PROD) | `api.gcp-staging.appsheet.com` (STAGING) |
|---|---|---|
| `GET /api/v2/apps/{z}/tables` | 400 — `App with id … not found` | 400 — `App with id … not found` |
| `POST /api/v2/apps/{z}/tables/Table1/Action` | 400 — `App with id … not found` | 400 — `App with id … not found` |
| `POST /api/v2/apps/{z}/tables/Table1/data` | 400 — `App with id … not found` | 400 — `App with id … not found` |

**Production never returned `"ApplicationAccessKey is missing"` on any method.**
Raw responses were captured (distinct live `traceId`s per call, e.g. prod GET
`00-f6c9cdba683444516ac39150b85c655c-…`, staging GET
`00-777baa8d7a67629963d7fc1db2703b99-…`) — both are genuine, current server responses.

## Why this is not a vulnerability

- **No differential:** prod and staging respond identically. There is no staging-specific
  gap to exploit.
- **Normal ordering:** both environments perform application lookup before the access-key
  check. For a nonexistent app, the API returns `"App not found"` first — on both. This is
  expected behavior, not an authentication bypass.
- **No access gained:** the response for a zero/nonexistent UUID discloses nothing and grants
  no data. Demonstrating a real bypass would require a valid app where staging skips the key
  while prod enforces it — there is no evidence of that, and it is untestable without a valid
  app UUID (which we will not use against assets we do not own).

## Root cause of the false positive

The original "ApplicationAccessKey is missing" observation on production could not be
reproduced — most likely a misread or a transient state during a deploy. A non-reproducible
differential is not a finding. Per the operating constitution (§"Verify before you believe",
§Definition of Done), this is retired as a lead that failed verification.

## Disposition

- Removed from the submission package (report banner-marked **WITHDRAWN**).
- F002 (OData SSRF) is unaffected and proceeds to live verification independently.
