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

## `addressCreate` with an injected owner — INCONCLUSIVE, redo

Same idea against create: from A, with `createdByUserId` and `userId` set to **B's** user id.

```
POST /api/addressCreate  -> 400  {"reason":"Error occurred in address update","status":"ERR_BAD_REQUEST"}
```

A 400 looks like a refusal, but it has two possible causes: the injected fields were rejected, or
A already has a primary mailing address and a second create fails regardless. **Those are
different conclusions and the response does not distinguish them.**

The control — the same request without the injected fields — returned:

```
401  {"message":"INVALID_SESSION"}
```

A's access token had expired between the two requests (it lives about an hour). **So the control
never ran, and this test is unresolved.** Recording it as inconclusive rather than reading the
400 as a negative: the whole point of the control is that without it the 400 means nothing.

**To finish it:** sign in to A again, delete A's existing mailing address, then run the control
first and the injection second, within the same token lifetime.

## Closed in this session

- `billing.tesla.com` — it is the **Energy** billing portal. The Tesla account completes OAuth
  against it (`token` 200) but `profile` returns 403: it needs an energy product, which we do
  not have. Not reachable.
- `accountUpdate` — no identifier in the request, nothing to tamper with.
- `addressUpdate` — injected identifier ignored, proven with a canary and both accounts.

## Next

1. Finish the `addressCreate` ownership test properly, with a live control.
2. **Refer and Earn.** Referral codes are shareable identifiers tied to an account, Tesla attaches
   real credit to them, and referral systems are a common place for logic flaws. It is the one
   remaining account feature that both creates identifiable objects and carries value.
