# G-F002 — Fitbit's token introspection endpoint does not bind tokens to the requesting client

**Program:** Google and Alphabet VRP · **Target:** `api.fitbit.com/1.1/oauth2/introspect`
**Found:** 2026-10-08 · **Tester IP:** 180.148.212.54 · curl 8.21.0 (aarch64-android)
**Status:** CLOSED — Won't Fix (Intended Behavior), P4/S4, three minutes after submission.

---

## The finding in one line

Any holder of a valid Fitbit access token can introspect **any other** token — including one issued
to a different OAuth client — and Fitbit answers with its status, the client it belongs to, its scope
and its validity window. The endpoint authenticates the caller but never checks that the caller owns
the token being asked about.

## Why this is independent of G-F001

G-F001 is about two client secrets being published. This is not. **Any party holding credentials for
two Fitbit OAuth applications can reproduce this**, and until recently anyone could register them
freely at `dev.fitbit.com/apps/new`. The published secrets are how *I* happened to have two sets of
credentials; they are not a precondition of the flaw.

That makes this the broader issue: it affects every client on the platform, not two.

## Proof

Two application tokens were minted, one per client, each via `client_credentials` with that client's
own credentials. Then client `228TQD` was asked to introspect the token belonging to `227ZG3`.

```
[CONTROL]  228TQD introspects its OWN token
           200 {"active":true,"scope":"{}","client_id":"228TQD","token_type":"access_token",
                "exp":1791468533000,"iat":1791439733000}

[CROSS]    228TQD introspects 227ZG3's token
           200 {"active":true,"scope":"{}","client_id":"227ZG3","token_type":"access_token",
                "exp":1791468531000,"iat":1791439731000}
                                ^^^^^^^^ a DIFFERENT client, and Fitbit names it in the reply

[SENTINEL] 228TQD introspects a fabricated token
           200 {"active":false}
```

The control proves the endpoint works for a client's own token. The sentinel proves it genuinely
validates tokens rather than answering `active:true` to anything. Between them, the cross result is
real: **Fitbit knew the token belonged to `227ZG3`, said so, and answered anyway.**

## How much authority is actually required — tested, and it is wider than "another client"

The first proof used Basic client credentials. That turns out to be only one way in.

```
[BASELINE] Basic 228TQD, reads 227ZG3's token
           200 {"active":true,"scope":"{}","client_id":"227ZG3","exp":…,"iat":…}

[NO AUTH]  no Authorization header
           401 {"code":401,"status":"UNAUTHENTICATED","message":"Request is missing required
                authentication credential…"}

[BEARER]   Authorization: Bearer <228TQD's token>, reads 227ZG3's token
           200 {"active":true,"scope":"{}","client_id":"227ZG3","exp":…,"iat":…}     <-- WIDER

[BEARER]   Authorization: Bearer <the same token being introspected>
           200 {"active":true,…,"client_id":"227ZG3",…}

[FAKE]     Basic with fabricated credentials
           401 {"errorType":"invalid_client","message":"… Client id invalid."}

[SENTINEL] Basic 228TQD, fabricated token
           200 {"active":false}
```

**Any valid access token can introspect any other token.** The bar is not "hold credentials for two
OAuth applications" — it is "hold one access token of any kind", which includes the token a user's
own device obtains for any third-party Fitbit app they have connected.

Every control behaved: authentication **is** required (401 without it), fabricated credentials **are**
rejected (401 `invalid_client`), and the endpoint **does** validate tokens (`active:false` for a
fabricated one). So the boundary is measured rather than assumed, and the flaw sits precisely at one
place: **the endpoint authenticates the caller but never checks that the caller owns the token it is
asking about.**

That is also the cleanest way to say what the fix is: authenticate as now, then compare the token's
`client_id` to the caller's — exactly what `revoke` already does.

## Fitbit enforces this binding elsewhere, which is what makes it look like an oversight

The same experiment against the revocation endpoint is refused:

```
[CROSS] 228TQD revokes 227ZG3's token
        403 {"errorType":"insufficient_permissions",
             "message":"API client is not authorized by the resource owner to access the resource requested."}

verify: 227ZG3 introspects its own token afterwards
        200 {"active":true, ...}        <- the token survived
```

A `200` from a revocation endpoint would have meant nothing on its own — RFC 7009 has them return
`200` for unknown tokens — so the verification line is what settles it. The token was untouched.

**So Fitbit has the concept of client-token binding and enforces it on `revoke`, but not on
`introspect`.** That inconsistency is hard to explain as intended design, and it is the strongest
argument in this report.

Fitbit's own authorization guide documents neither endpoint, so there is no published statement that
cross-client introspection is expected.

## What an attacker gets, stated exactly

With a token string belonging to another application, a client learns:

```
whether the token is live          active:true/false
which application it belongs to    client_id
its validity window                iat / exp
its granted scopes                 scope
```

Tokens leak in referrer headers, server logs, crash reports, browser history and shared devices. An
attacker holding a leaked string currently cannot tell whether it is worth anything. This endpoint
tells them — for free, from any client, including one they registered themselves.

## The limit I could not pass

Both tokens tested were **application** tokens, whose `scope` is empty. Introspection of a **user**
token normally also returns the user id and the real granted scopes, which would make this a
disclosure about a named person rather than about an app token's expiry.

I could not test that. Minting a user token needs `grant_type=password`, and the Fitbit accounts I
can create use Google sign-in and have no native Fitbit password — confirmed by attempting it and
receiving `Invalid username/password`. New app registration is also closed
(`dev.fitbit.com/apps/new` has its fields disabled), so I could not approach it from a second app
either.

**This is a limit, not a negative result.** Whether cross-client introspection of a user token
discloses the user id and scopes is something Fitbit can check internally in seconds, and if it does,
the severity is higher than what I demonstrated.

## Remediation

Scope the introspection response to the requesting client: return `active:false`, or an error, when
the token was issued to a different `client_id` — the behaviour already implemented on `revoke`.

## Reproduction

```bash
A=$(printf '<clientA_id>:<clientA_secret>' | base64 -w0)
B=$(printf '<clientB_id>:<clientB_secret>' | base64 -w0)

TOKEN_A=$(curl -s -X POST https://api.fitbit.com/oauth2/token -H "Authorization: Basic $A" \
  -d 'grant_type=client_credentials' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# client B reads client A's token
curl -s -X POST https://api.fitbit.com/1.1/oauth2/introspect -H "Authorization: Basic $B" \
  --data-urlencode "token=$TOKEN_A"
```

## Honest outcome estimate, recorded before the result

| Outcome | Estimate | Why |
|---|---|---|
| Accepted, low severity | ~40% | A genuine cross-client authorization flaw with control and sentinel, but what leaks from an app token is thin. |
| Informational | ~30% | "No sensitive data disclosed" is a fair reading of the app-token case. |
| Duplicate | ~20% | Two client credentials used to be free to obtain, so others could have tried this. |
| Accepted, medium | ~10% | Only if user-token introspection leaks the user id, which I could not test and do not claim. |


---

## SUBMITTED — 2026-10-08 07:19 UTC

Google VRP, report `571371934`. Type **Permissions Bypass**. Attachments: `evidence.txt` and
`2026-10-08_0658UTC_fitbit-introspect-cross-client.png`. Disclosure: private, Google only.

One detail worth keeping. The review page initially carried an automated banner:

```
info_outline  Intended Behavior
The reported behavior appears to be intended. Please check the documentation.
```

It disappeared after the 200-character summary was rewritten to end with
`oauth2/revoke refuses the same request.` The classifier had read the first version as describing
expected behaviour; naming Fitbit's own inconsistency in the summary line removed that reading.

**Lesson for the next report: put the strongest anti-"intended-behaviour" fact in the first line a
triager reads, not in a section further down.** The argument existed in the Impact analysis all
along and the banner was still there.

### Rule for the wait

Do not add to the submission — Google decides the reward on what is available **prior to triage**.
Do not chase it. Do not re-argue a close with the same evidence (FO-12). The correct use of the
waiting period is the next finding.

---

## Follow-up: the rest of Fitbit's own endpoint map, and why it closed

After submitting, the full constants map was pulled from `accounts.fitbit.com`'s bundle — the same
place `introspect` came from — on the reasoning that one ownership-check mistake is rarely alone.

The map named two endpoints never touched before:

```
GET_DELEGATE_TOKEN    oauth2/delegate
DELEGATE_TOKEN_LOGIN  oauth2/delegate/token
DELEGATE_LOGIN_FAILURE          (+ a delegateLogin action in the UI)
```

Delegation means acting for someone else, so it is exactly where an ownership check goes missing.
It does not here:

```
[SENTINEL] POST /oauth2/zzz_not_a_path_7x2   HTML error page      <- real paths look different
GET  /oauth2/delegate          Basic 228TQD  403
POST /oauth2/delegate          Basic 228TQD  403
POST /oauth2/delegate          no auth       401 UNAUTHENTICATED
POST /oauth2/delegate          Basic 227ZG3  403
POST /oauth2/delegate/token    Basic 228TQD  400 (empty body, with and without parameters)
POST /oauth2/delegate/token    no auth       401
```

`oauth2/delegate` answers **403** to both of our clients. Fitbit checks authorisation there and our
clients do not hold it — correct behaviour. `delegate/token` answers 400 with an empty body, naming
no parameter, so going further would mean **guessing parameter names**, which is the thing this
engagement does not do.

**Lead closed.** And it strengthens the submitted report rather than weakening it: `revoke` enforces
the ownership check, `delegate` enforces authorisation, and `introspect` is the one that does
neither. The outlier argument is now backed by two siblings instead of one.

The rest of the map was left alone deliberately. The `1/user/-/mfa/*` endpoints resolve `-` from the
token, so they cannot be tested without a user token, which no account we can create will produce.
`1/account/resetPassword.json` would send mail. Neither is worth the traffic.


---

## OUTCOME — Won't Fix (Intended Behavior), 2026-10-08 07:25 UTC

Report `571371934`. Created 01:22 PM, closed 01:25 PM local. Three minutes.

```
Status    Won't fix (Intended behavior)
Priority  P4        Severity  S4
```

> "According to our assessment, querying the endpoint relies on knowing a valid access token or
> random identifier that cannot be guessed in any practical way. If you find a reliable method or
> side-channel to leak or predict target tokens, please let us know by updating this report."

## This was predictable, and I had already written the rule that predicts it

From `config/scope-google.yaml`, committed the day before this report, quoting Google's own
"Understanding secrets in URLs and IDORs":

> "If an attacker can access a sensitive private resource simply by knowing its ID, it *might* be an
> IDOR vulnerability. However, and this is vital, there also needs to be a clear path for the
> attacker to **DISCOVER** the needed ID... reports describing vulnerabilities based on guessing
> complex random IDs are almost always not eligible for reward or credit."

And the consequence I wrote under it, in my own words:

> "CONSEQUENCE: this is the Tesla InstallationGUID wall, written down as policy. The FIRST
> observation on any upload or object surface must be the SHAPE of the object id."

Attacking the introspection endpoint requires **already holding the victim's token string** — 205
characters of randomness. By the rule in my own scope file, this was dead before it was written.

I ran controls and sentinels on every technical claim and never once ran the finding against the
program's own eligibility rule. The rigour was aimed entirely at "is this true?" and never at "does
this qualify?".

## The filter that must run before anything is submitted

**Does the attack require the attacker to already know an identifier they cannot obtain or predict?**

```
Tesla T04       needs an InstallationGUID        -> would have closed. Correctly parked.
Marriott M025   needs a confirmation number      -> would have closed. Correctly parked.
G-F001          needs the victim's password      -> correctly parked.
G-F002          needs the victim's token string  -> SUBMITTED ANYWAY. Closed in three minutes.
```

Three of the four were parked for exactly this reason. The fourth was submitted because the
technical work around it was good, and good technical work on an ineligible class is still
ineligible.

## What Google said WOULD change it

> "If you find a reliable method or side-channel to leak or predict target tokens, please let us
> know by updating this report."

That is a real door, and it is the only one. A way to obtain or predict another user's token turns
this from Won't Fix into a chain with a demonstrated entry point. We do not have one, and nothing
tested so far suggests one exists. Not re-argued, per FO-12 — the close is accepted.
