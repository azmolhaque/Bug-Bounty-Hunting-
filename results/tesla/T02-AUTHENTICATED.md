# T02 — Tesla, authenticated testing with two accounts

2026-10-05. The first session on this programme in which we had identities at all.

## Environment

The thing that blocked Wiz, Meta and Personio's cross-tenant axis — a second identity — cost
nothing here. Bugcrowd's relay accepts plus-addressing, which the recovery-email flow proved
before it was needed:

```
A   gorib@bugcrowdninja.com      "GoribA Tester"   userId 134935810
B   gorib+2@bugcrowdninja.com    "GoribB Tester"   userId 134937530
```

Both US region, both with MFA. Registered with the `bugcrowdninja.com` address the brief
requires. Desktop Chrome, so testing runs from the Console in the live session rather than by
moving tokens around.

## The empty-account problem, and how it was solved

Two fresh accounts own nothing: no vehicle, no order, no payment method. There is no object to
request, so there is nothing to test. This is the same wall written up in the IoT assessment.

The way through was to **create objects that cost nothing**. A mailing address is free and, as it
turns out, is issued a sequential numeric id:

```
A  address id 63087769 -> 63087866 (after edit)   createdByUserId "134935810"
B  address id 63087955                            createdByUserId "134937530"
```

Both ids numeric, both close together. That is the shape the brief keeps in scope by name:

> *"Exceptional cases may still be in scope (e.g. ability to enumerate … via incrementing a
> numeric parameter)"*

## What the account API actually looks like

```
PUT  /api/accountUpdate   {"countryCode","firstName","lastName","localeCode","middleName"}
POST /api/addressCreate   {"city","country","postalCode","state","street1"}
PUT  /api/addressUpdate   {"city","country","postalCode","state","street1"}
     /api/delete-account  ·  /api/oauth2/logout
```

**None of them carries a user or object identifier.** The server resolves who you are, and which
address is yours, from the session — the JWT in `auth_access_token`, whose `sub` is the account.
There is no id in the request to tamper with, which is the correct design and removes the
obvious IDOR surface by construction.

## The real test: mass assignment on `addressUpdate`

If the identifier is absent from the body, the question becomes whether the server will accept
one that it never asked for. From **A's** session:

```js
PUT /api/addressUpdate
{"id":63087955,                      // <- B's address id
 "city":"AUSTIN","country":"US","postalCode":"78725","state":"TEXAS",
 "street1":"999 CANARY RD"}          // <- canary, so the result is unambiguous
```

Checked in three places afterwards:

```
A's page   999 CANARY RD   <- A's own address changed
B's page   2 TESLA RD      <- untouched
```

**The injected `id` was ignored and the session's own address was updated.** Clean negative, and
a well-controlled one: two real accounts, a distinctive value, and both ends inspected.

## Ownership injection — RESOLVED, negative

Same idea against create: from A, with `createdByUserId` and `userId` set to **B's** user id.

```
POST /api/addressCreate  -> 400  {"reason":"Error occurred in address update","status":"ERR_BAD_REQUEST"}
```

A 400 looks like a refusal, but it has two possible causes: the injected fields were rejected, or
A already has a primary mailing address and a second create fails regardless. The control — the
same request **without** the injected fields — settled it:

```
POST /api/addressCreate  (no injection)  -> 400  same error
```

**The 400 had nothing to do with the injection.** A simply cannot hold two mailing addresses, so
the request never got far enough for the extra fields to matter. The first run was not a test of
anything, and reading it as a negative would have been wrong. The UI offers no way to delete an
address either — the edit page has only Update and Cancel — so `addressCreate` could not be
emptied for a clean run.

The question was therefore asked through `addressUpdate`, which does work for A, with **all three**
identifiers injected at once:

```js
PUT /api/addressUpdate
{"id":63087955,                     // B's address
 "userId":"134937530",              // B
 "createdByUserId":"134937530",     // B
 "street1":"888 OWNER RD", …}
```

Response:

```json
{"id":63089761,"name":"GoribA Tester","street1":"888 OWNER RD",
 "createdByUserId":"134935810","isPrimary":true, …}
```

```
A's page   888 OWNER RD     <- A's own record, A's own owner id
B's page   2 TESLA RD       <- untouched
```

**All three injected identifiers ignored.** The owner came back as `134935810` — A — not the
`134937530` we sent, and the record written was A's own. Both identity and target are resolved
from the session alone. Conclusive negative.

## Closed in this session

- `billing.tesla.com` — it is the **Energy** billing portal. The Tesla account completes OAuth
  against it (`token` 200) but `profile` returns 403: it needs an energy product, which we do
  not have. Not reachable.
- `accountUpdate` — no identifier in the request, nothing to tamper with.
- `addressUpdate` — injected identifier ignored, proven with a canary and both accounts.

## Next

1. ~~Finish the addressCreate ownership test~~ — done, negative.
2. **Refer and Earn.** Referral codes are shareable identifiers tied to an account, Tesla attaches
   real credit to them, and referral systems are a common place for logic flaws. It is the one
   remaining account feature that both creates identifiable objects and carries value.
