# G-F001 — Two Fitbit OAuth client secrets published in unauthenticated page source

**Program:** Google and Alphabet VRP (`bughunters.google.com`)
**Status:** REPORTABLE. The published secret allows credential submission without the reCAPTCHA token Fitbit's own sign-in client attaches — demonstrated from their own code.
**Found:** 2026-10-07 · **Tester IP:** 180.148.212.54 · **curl 8.21.0 (aarch64-android)**

> **Secrets are REDACTED in this file** per CLAUDE.md §7 — nothing secret goes to git.
> The full values are read straight off the live pages with the commands below, and go
> into the Google submission form only.

---

## What was found

Two Google-owned Fitbit hosts serve an OAuth **client secret** in the HTML of an
unauthenticated page. No login, no header, no trick — `curl` the root and read a meta tag.

| Host | Google's own tier | What it publishes |
|---|---|---|
| `accounts.fitbit.com` | **TIER1** | `"basicToken":"<base64>"` which decodes to `228TQD:7659f9…744a` |
| `feed-moderation.fitbit.com` | **TIER1** | `"clientId":"227ZG3:458dd4…196d"` |
| `snapdragon-ws.fitbit.com` | TIER2 | `"clientId":"228TQD"` + a second token endpoint, `web-api.fitbit.com` |

`accounts.fitbit.com` is Fitbit's sign-in host. Its value is not merely a secret, it is a
**pre-assembled HTTP Basic header** — base64 of `id:secret`, ready to paste into an
`Authorization:` line.

```bash
# both are one command each, from a clean machine with no session
curl -s https://accounts.fitbit.com/          | grep -oE 'content="%7B[^"]*"' | head -1
curl -s https://feed-moderation.fitbit.com/   | grep -oE 'content="%7B[^"]*"' | head -1
```

## That these are real secrets, and not public client ids

Fitbit's token endpoint authenticates with HTTP Basic over `client_id:client_secret`. The
six-character id is public by design; the question is only whether the 32-hex half is
load-bearing. A three-way differential answers it, using a **deliberately invalid
authorization code** so that no token is issued and no user is involved:

```
[TEST]     227ZG3 + published secret   400  invalid_grant   "Authorization code invalid: ZZZINVALIDCODE7x2"
[CONTROL]  227ZG3 + wrong secret       401  invalid_client  "Client secret invalid."
[SENTINEL] ZZZZZZ + wrong secret       401  invalid_client  "Client id invalid."

[TEST]     228TQD + published secret   400  invalid_grant   "Authorization code invalid: ZZZINVALIDCODE7x2"
[CONTROL]  228TQD + wrong secret       401  invalid_client  "Client secret invalid."
[SENTINEL] ZZZZZZ + wrong secret       401  invalid_client  "Client id invalid."
```

Fitbit itself names the difference: *Client secret invalid* versus *Client id invalid*. With the
published value the request **passes client authentication** and fails only on the code. With a
wrong one it never gets that far.

And client authentication is genuinely required — the control that makes all of the above mean
something:

```
[no Authorization header at all]      401  invalid_client  "Invalid authorization header format…"
[client_id in body, no secret]        401  invalid_client  "…or a client_id was not specified in
                                                             case of a public client"
```

That last message is Fitbit stating these are **not** public clients.

## What the secret alone buys, demonstrated

```
POST /oauth2/token   grant_type=client_credentials   Authorization: Basic <published>

227ZG3 @ api.fitbit.com       200  {"access_token":"eyJ…","expires_in":28800,"scope":"","token_type":"Bearer"}
228TQD @ api.fitbit.com       200  {"access_token":"eyJ…","expires_in":28800,"scope":"","token_type":"Bearer"}
228TQD @ web-api.fitbit.com   200  {"access_token":"eyJ…","expires_in":28800,"scope":"", …}

decoded payload:
{"aud":"227ZG3","iss":"Fitbit","typ":"client_access_token","scopes":"","exp":1791437043,"iat":1791408243}
issued  2026-10-07 21:24:03 UTC      expires  2026-10-08 05:24:03 UTC
```

Anyone on the internet can mint Fitbit-issued application tokens for these two OAuth clients, for
eight hours at a time, from a credential published on Fitbit's own sign-in page.

The refresh flow also passes client authentication:

```
grant_type=refresh_token  +  invalid refresh token   400  invalid_grant  "Refresh token invalid: …"
```

`invalid_grant` rather than `invalid_client` means the client was authenticated and only the token
was rejected.

## The honest limits — what was NOT shown

Stated plainly here so the report is not read as claiming more than it proves:

- The `client_access_token` carries **`"scopes":""`**. It is an application token, not a user token,
  and **no user's data was read with it**. Both tokens were obtained and then left unused; no Fitbit
  API was called with either.
- **No user account was touched.** Every authorization code and refresh token sent was a fabricated
  invalid string, chosen so the request could never succeed.
- Account takeover is **not** demonstrated. A full code-exchange attack needs an authorization code
  as well, and obtaining a real user's code was not attempted and is not claimed.

What the secret does is remove the one thing that is supposed to stop an attacker from acting **as
the Fitbit application** at the token endpoint — the exchange of authorization codes and refresh
tokens for user access tokens. Those flows carry the scopes this client requests, which
`feed-moderation`'s own config lists as:

```
activity heartrate location nutrition profile settings sleep social weight
```

## Why this is not the Tesla F001 class

Tesla F001 leaked a third-party metered credential (Baidu, ipinfo); the attacker's gain was another
company's quota, and it closed Informational. This is **Google's own authentication credential, on
Google's own TIER1 host, protecting Google's own users' health data**. The answer to "what does the
attacker get?" is "the ability to authenticate as this Fitbit OAuth application", not "someone
else's free tier".

## Remediation

1. Rotate both client secrets (`227ZG3`, `228TQD`).
2. Remove the secret from the client-side config of `accounts.fitbit.com`,
   `feed-moderation.fitbit.com` and `snapdragon-ws.fitbit.com`. A browser application cannot keep a
   client secret; these should be registered as public clients using PKCE, with the token exchange
   moved server-side if a confidential client is genuinely needed.
3. Audit the remaining Fitbit and Nest front ends for the same pattern — this was found on three of
   eleven hosts checked, which suggests a shared build convention rather than a single slip.

## Program routing

Google VRP, not the Android & Devices program: that program covers Fitbit **devices** and their
operating systems, and this is a web property. The rules index also says *"When in doubt, report to
the Google and Alphabet Vulnerability Reward Program."*

## Dedup

Not searched publicly yet. These pages are long-lived and the values sit in plain page source, so a
duplicate is a genuine risk and is priced into the estimate below rather than argued away.

---

## Chain tested and CLOSED — redirect_uri validation holds

A client secret is only an account-takeover primitive if an attacker can also receive a victim's
authorization code, so the whole severity of this report turns on `redirect_uri` validation. It was
tested from a logged-in session on a free Fitbit account I created for this purpose, with both
baselines established first so the attack rows are readable at all.

```
[ACCEPT baseline]  no redirect_uri parameter
                   -> CONSENT SCREEN:
                      "Social Feed Moderation Application by Fitbit Inc. would like the
                       ability to access and write the following data in your account"
                      [Allow All] [profile]   Deny / Allow

[REJECT baseline]  redirect_uri=https://example.com/
                   -> "invalid_request - Invalid redirect_uri parameter value"

[ATTACK] suffix    https://feed-moderation.fitbit.com.example.com/   -> same rejection
[ATTACK] userinfo  https://feed-moderation.fitbit.com@example.com/   -> same rejection
[ATTACK] own origin https://feed-moderation.fitbit.com/              -> same rejection
```

**Validation is strict.** None of the classic bypasses is accepted, and even the app's own origin is
refused, so the registered URI is narrower still. **Account takeover is therefore NOT achievable
with this credential alone, and this report does not claim it.** I never pressed Allow, so no
authorization code was ever issued.

Saying this plainly is deliberate. The first question a reviewer asks is whether the exposure chains
to user data; answering it with a tested negative is worth more than leaving it open.

### What the consent screen does add

It names the client: **"Social Feed Moderation Application by Fitbit Inc."** — a **first-party
Fitbit application**, not a third-party integration. The consent text says it requests the ability
to *"access and **write**"* data in a user's account. So the published secret belongs to a
first-party application with write access to user accounts, which is what distinguishes this from a
leaked key for some external service.

## Dedup checked

```
github.com/search?q="458dd4f32a9db4957cf15fd464be196d"&type=code   0 files
github.com/search?q="7659f9d9ecc92d6dc1ee0d1774e9744a"&type=code   0 files
Google web search for the first value                              no result; it is only
                                                                   identified as "an MD5 hash"
```

Neither value is indexed anywhere public. They are reachable only by reading the page source of the
two hosts.

## Final position

This is a **credential exposure** report, not an account-takeover report:

- Two confidential OAuth client secrets for first-party Fitbit applications are published in
  unauthenticated page source on two TIER1 hosts, one of them the sign-in host.
- Both are verified live against Fitbit's own token endpoint by a three-way differential.
- Both mint real Fitbit application tokens via `client_credentials`.
- `redirect_uri` validation was tested and holds, so the code-exchange path is not open, and that is
  stated rather than left implied.

## Which applications these are — Fitbit's own consent screen names them

Loading the authorize endpoint for each client id from a logged-in session makes Fitbit identify
the application itself. No claim of mine is needed:

```
client_id=228TQD  ->  "Fitbit Web Application" by Fitbit, Inc.
                      would like the ability to ACCESS AND WRITE the following data in your account

client_id=227ZG3  ->  "Social Feed Moderation Application" by Fitbit Inc.
                      would like the ability to ACCESS AND WRITE the following data in your account
```

`228TQD` is **Fitbit's own web application**, and its secret is published on
`accounts.fitbit.com` — the page users sign in on.

Requesting the client's full scope list shows what that application is permitted to reach:

```
friends · weight · activity and exercise · HEART RATE · profile ·
LOCATION AND GPS · SLEEP · food and water logs · Fitbit devices and settings
```

That is Fitbit's own wording, on Fitbit's own consent screen, and it answers "what is at stake"
better than any sentence I could write. **Allow was never pressed**, so no authorization code was
ever issued and no scope was ever granted.

## How far it spreads — bounded, not guessed

Every host that answered 200 in the acquisition sweep was re-checked for the same pattern, with the
two known-leaking hosts included in the same run as positive controls:

```
>>> accounts.fitbit.com          TIER1   LEAKS   basicToken -> 228TQD:7659f9…744a   <- CONTROL
>>> feed-moderation.fitbit.com   TIER1   LEAKS   clientId   -> 227ZG3:458dd4…196d   <- CONTROL
    41 other hosts (Fitbit, Nest, Waze, Mandiant, Looker, Waymo, Wing, Tenor, …)  clean
```

The controls lighting up is what makes the 41 "clean" rows mean anything. An earlier version of this
scan reported **all** hosts clean, including the two known leaks, because the config is URL-encoded
inside the meta tag and the patterns could never match. That run was discarded.

**Conclusion: two applications, not a build convention.** The blast radius is these two clients, and
the report says so rather than implying a wider pattern.

## Also checked and found clean

- `dev.fitbit.com` — its 19 32-hex strings are asset-fingerprint filenames
  (`search-icon-ce72b3f2….svg`), not secrets.
- `snapdragon-ws.fitbit.com` — references client id `228TQD` and a Google API key, but publishes no
  secret of its own.
- `myaccount.nest.com` — ships a config meta tag, but it contains no credentials.
- The OneTrust scripts loaded by `dev.fitbit.com` are the vendor's standard consent library, byte
  for byte the same as on thousands of other sites.

## The grant types these clients accept — and the one that matters

The bounding above ("you still need a victim's authorization code") only covers the
authorization-code grant. It does not have to hold for the others, so each was tried once, with a
grant that cannot exist sent first to establish what "not supported" looks like.

```
[SENTINEL] grant_type=zzz_not_a_real_grant_7x2  400  unsupported_grant_type
           grant_type=device_code               400  unsupported_grant_type   <- identical to sentinel
           grant_type=token-exchange            400  unsupported_grant_type   <- identical to sentinel

           grant_type=client_credentials        200  access_token, scope ""
           grant_type=authorization_code        400  invalid_grant "Authorization code invalid"
           grant_type=password                  400  invalid_grant "Invalid username/password"
                                                     ^^^^^^^^^^^^ DIFFERENT from the sentinel
```

Two unsupported grants return the sentinel's exact response. `password` does not — it returns
`invalid_grant` and a message about the *credentials*, which means the endpoint accepted the grant
type and went on to validate a username and password.

**`grant_type=password` (resource-owner password credentials) is enabled for `228TQD`, "Fitbit Web
Application".** That grant skips the browser, the consent screen, the `redirect_uri` check and the
login page entirely. The credential required to use it is the secret published on
`accounts.fitbit.com`.

The same config file that publishes the secret also carries:

```json
"featureFlags": { "recaptchaEnabled": true, "mobileRecaptchaEnabled": true,
                  "firstPartySSOEnabled": true, "mandatoryEmailVerification": true }
```

So Fitbit protects the sign-in *page* with reCAPTCHA. The token endpoint reached with the published
first-party secret is a second door into the same credential check, and reCAPTCHA is not on it.

### What was NOT verified, and why I stopped

I did not obtain a user access token through this grant. One attempt was made, against **my own
test account, with my own password**, and it returned `Invalid username/password` — most likely
because that account was created through Google sign-in and has no native Fitbit password
(`firstPartySSOEnabled: true`).

I did not try a second password, another account, or any list. One request establishes that the
grant exists and performs credential validation; anything further would be brute force, which the
rules forbid and which the finding does not need. Whether a correct native password returns a
scoped user token is something Fitbit can confirm internally in seconds.

So the claim is exactly this and no more: **the published secret unlocks a credential-validating
grant on Fitbit's own first-party OAuth client, outside the protections that sit on the sign-in
page.** I am not claiming account takeover and I did not demonstrate one.

### Minor, recorded for completeness

```
corporate-webapps.fitbit.com   404  10 b   (named in dev.fitbit.com's CSP, not in the tier list)
web-api.fitbit.com             401 304 b   (second token endpoint, named by snapdragon-ws)
zzz-canary-7x2.fitbit.com      NO-DNS      (no wildcard on fitbit.com)
```

## Is this "working as intended"? Fitbit's own documentation answers it

The obvious defence is that a first-party browser application needs its credential in the browser,
so the design is intended. Fitbit's own developer guide forecloses that, in its own words
(`dev.fitbit.com/build/reference/web-api/developer-guide/authorization/`):

> **Server Application Type**
> "Server application types must authenticate themselves using the client secret available in
> application settings. This provides the highest level of security to the OAuth 2.0 flow. However
> it should only be used by applications that can securely store the client secret, such as apps
> running on a web server. **Notably, the client secret should never be included in application
> source code or stored on an end-user device where it can be discovered.**"

Fitbit registers applications as **server, client or personal**, and the type determines how the
token endpoint authenticates them. Both of these clients are **server type**, and that is not an
assumption — the endpoint's own behaviour proves it:

```
wrong secret        -> 401 "Client secret invalid."
no credentials      -> 401 "...or a client_id was not specified in case of a public client"
```

A client-type (public) application would not be rejected for a bad secret. These are server-type
clients, server-type clients authenticate with a secret, and Fitbit's documentation says that secret
**"should never be included in application source code"**. It is in the source of two of their own
pages, one of them the page users sign in on.

So the violated rule is not an external standard I am appealing to. **It is Fitbit's own written
requirement for this exact application type.** That is what moves this out of "intended behaviour".

The same page also confirms a limit I stated earlier rather than discovering it later:

> "Client Credentials ... is used with specific Fitbit API endpoints related to business operations.
> **It is not supported by the public Web APIs to retrieve Fitbit user data.**"

Which is exactly why the `client_access_token` carries empty scopes and why this report does not
claim user data was reachable with it.

## Is the credential actually used by the page? Yes — and that decides the framing

```
accounts.fitbit.com/assets/accounts.fitbit.com-3c633fe7….js   351,543 b
    basicToken references : 1
    grants named in code  : authorization_code · delegate_token · mfa_sms · social
    endpoints named       : oauth2/token · oauth2/revoke · oauth2/introspect

accounts.fitbit.com/assets/vendor-1b016de5….js              1,096,168 b
    grants named in code  : password · refresh_token
    header construction   : Authorization:"Basic "+window.btoa(e.concat(":"))

accounts.fitbit.com/recaptcha-preloading-3bca9f46….js             213 b   <- reCAPTCHA is on this page

feed-moderation …/assets/feed-moderation-3c230761….js         239,163 b
    227ZG3 references : 0        grant_type references : 0
```

So the sign-in page really does perform browser-side Basic authentication to the token endpoint, and
the vendor bundle carries the `password` grant path. **This is deliberate architecture, not an
accidental leak**, and the report should say so rather than be caught out by it.

That matters for how this is argued. The finding is **not** "a secret was leaked by mistake". It is:

1. Fitbit's own documentation forbids this for server-type applications, in terms that leave no
   room — *"should never be included in application source code"*.
2. Both clients are server-type, proven by the endpoint rejecting a wrong secret.
3. The consequence is concrete: `grant_type=password` is reachable with the published credential, so
   there is a credential-validation path that does not pass through the sign-in page — the same page
   that loads `recaptcha-preloading-*.js`.

Point 3 is the one that survives an architectural defence. Whatever Fitbit's reasons for putting the
credential in the browser, the result is a second door to the same credential check, and the
protection sits on the first door only.

`feed-moderation`'s own bundle references neither its client id nor any grant, so there the pair with
the secret appears to be inherited boilerplate rather than something that page needs — a staff
moderation console has no login-page justification at all.

## The full grant surface the published credential reaches — and where each one stops

```
[SENTINEL] zzz_not_a_real_grant   400  unsupported_grant_type
           delegate_token         400  unsupported_grant_type      <- identical to sentinel: not available

           client_credentials     200  access_token, scope ""
           authorization_code     400  invalid_grant  "Authorization code invalid"
           password               400  invalid_grant  "Invalid username/password"
           mfa_sms                400  invalid_token  "MFA token invalid: ZZZINVALID7x2"
           social                 400  invalid_request -> googleAccessToken -> googleIdToken
```

So the published credential authenticates against **Fitbit's whole first-party authentication grant
set**, not merely the standard code flow: password, social sign-in exchange, and the MFA step.

### Where each one stops — tested, so the report does not have to speculate

- **`social`** asks next for `googleAccessToken`, and then for `googleIdToken`. It wants a **signed
  assertion from the provider**; the social UID is only a lookup key. **This is not a bypass**, and
  the design is sound. I checked precisely because a social UID is not a secret and the answer
  mattered either way.
- **`mfa_sms`** validates the MFA token itself (`invalid_token`), so it needs one issued during a
  real login. **Not a bypass either.**
- **`password`** is the one with no second factor in front of it: it goes straight to validating a
  username and password.

Every identifier used above was fabricated, each shape was sent once, and no real person's
identifier was ever substituted.

### Final, bounded impact

The published secret does **not** give account takeover — each grant still demands its own proof, and
`redirect_uri` validation holds. What it gives is:

1. The ability to authenticate as two first-party Fitbit OAuth applications, one of them
   "Fitbit Web Application" itself.
2. A **credential-validation path through `grant_type=password`** that does not pass through the
   sign-in page, which is where `recaptcha-preloading-*.js` is loaded and where
   `recaptchaEnabled: true` applies.
3. Reach into the MFA and social-exchange grants of Fitbit's own login system.

And it does all of this in direct contradiction of Fitbit's own documented requirement that a
server-type application's client secret *"should never be included in application source code"*.

## DECISION: PARKED, not submitted — and the test that settled it

The last open question was whether the minted application token reaches anything. It does not.

### Scopes cannot be requested

```
grant_type=client_credentials&scope=profile                              200  scope=''
grant_type=client_credentials&scope=heartrate                            200  scope=''
grant_type=client_credentials&scope=activity heartrate location sleep…   200  scope=''
grant_type=client_credentials  (no scope at all)                         200  scope=''
```

Asking changes nothing. The JWT's inner `scopes` claim is empty in every case. Fitbit's
introspection endpoint agrees:

```
{"active":true,"scope":"{}","client_id":"228TQD","token_type":"access_token"}
```

### And the token is refused everywhere — my own marker was the false positive

```
ENDPOINT                                      [APP]      [NIL]      [FAKE]
/1/user/-/profile.json                        403/126b   401/304b   401/240b
/1/user/-/apiSubscriptions.json               403/273b   401/304b   401/240b
/1/apiSubscriptions.json                      404/131b   401/304b   401/240b
/1/user/-/activities/heart/date/today/1d.json 403/126b   401/304b   401/240b
/1/foods/units.json                           403/126b   401/304b   401/240b
/1/activities.json                            403/126b   401/304b   401/240b
/1/zzz-canary-7x2.json                        404/131b   401/304b   401/240b   <- CANARY
```

My script printed "TOKEN IS DOING WORK" on all seven rows, **including the canary** — a path that
does not exist. That is the tell: the heuristic was wrong, not the target. What is actually
happening is uniform: the token **authenticates** (so never 401) and is then **denied at every
endpoint** (403), while nonexistent paths give the same 404 as the canary.

Blanket behaviour, no endpoint-specific access. Tenth near-miss caught by a canary, and this one was
my own reasoning rather than the target's.

## Why this is not submitted

Applying §2.1 — *what does the attacker actually get?*

```
client_credentials  ->  a token that is refused everywhere
password            ->  still needs the victim's password
social              ->  still needs a signed Google/Facebook ID token
mfa_sms             ->  still needs an MFA token from a real login
authorization_code  ->  still needs a code; redirect_uri validation holds
```

Every door needs a key the secret does not provide. The honest one-sentence answer is: *the attacker
gains the ability to make a request they could already make by loading Fitbit's sign-in page in a
browser.* That is convenience, not privilege.

The one claim that would have carried it — that `grant_type=password` escapes a protection the
sign-in page enforces — was never verified, and **cannot** be, because proving it means repeatedly
submitting failed logins. That is brute force, which the rules forbid. Under §2.6 an unverified
precondition is not a finding, and writing it up as one is exactly how a report becomes Spam.

Add the structural problem: `accounts.fitbit.com`'s own bundle **uses** this credential, so it is
downloaded by every Fitbit web user's browser at every login. It is functionally public by design.
Fitbit's documentation forbidding the practice is third-party developer guidance and does not bind
their own first-party client.

**This is the Tesla F001 shape**: a well-evidenced credential exposure where the credential reaches
nothing. That closed P5 Informational in ninety minutes. The rigour was never the limiting factor
there either.

## Un-park condition

One of these, and nothing less:

1. Evidence that the token endpoint lacks a protection the sign-in page has — obtainable only from
   Fitbit's side, not ours.
2. An endpoint where the app token returns data, distinguishable from the canary's 404 and the
   blanket 403.

Until then this is a lead, labelled honestly as one.

## The audience test — UNTESTABLE from outside, which is not the same as safe

Three attempts, two Google accounts, a Fitbit account created for each.

```
googleUID = 103353436196036194164  (azmol01717534550)  -> "Social account not linked to email"
googleUID = 103716934560634616990  (kaseym484)         -> "Social account not linked to email"
after signing into Fitbit via "Continue with Google"   -> "Social account not linked to email"
```

The sign-in URL says why: `accounts.google.com/v3/signin/accountchooser?continue=https://fitbit.google…`.
Fitbit is migrating accounts to **Google Accounts** (`fitbit.google.com`), and their own config
carries `"legacyAccountDeprecationEnabled": true`. That migration is a different mechanism from the
`social` grant's legacy `googleUID` linkage, and a newly created account gets the former, not the
latter.

So the linkage the `social` grant looks for **cannot be created on any account we are able to make**.

### What this does and does not establish

```
established     the social grant is reachable with the published client secret
established     it accepts a Google ID token, parses it, and reads the email out of it
established     it does NOT reject on the token - it stops at account linkage, a later step
NOT established that the `aud` claim is validated
NOT established that it is not
```

Recorded as **untestable from outside, not as safe**. A server that verified the ID token properly —
signature, `iss`, `exp` *and* `aud` against its own client id, which is one standard library call —
would have refused before ever reading the email. It did not. That is a reason for Fitbit to check
internally, and the report says exactly that rather than claiming either outcome.

Stopped after three attempts by a rule set before the first one. No further accounts, no other
person's identifier, nothing retried.

## FINAL STATUS

**PARKED. Not submitted.** The published secrets are a genuine misconfiguration that Fitbit's own
documentation forbids for server-type applications, and they are confined to two Fitbit applications
— the rest of Google's estate is clean. But under §2.1 the attacker gains nothing they could not
already attempt: every grant still demands a key the secret does not supply, the app token is
refused everywhere, and `redirect_uri` validation holds.

The one question that could have changed that is the `aud` check, and it cannot be answered from
outside. It is written up as an open question for Fitbit rather than as a finding for us.

## THE IMPACT, demonstrated from Fitbit's own source

The weak point in everything above was one unproven sentence: *"the token endpoint is a credential
check without the reCAPTCHA that guards the sign-in page."* That was inferred from a feature flag,
which is not evidence.

It is now evidenced, by reading `accounts.fitbit.com`'s own bundle. This is how their sign-in client
submits a password:

```js
{ grant_type:"password", username:e, password:t, recaptchaToken:r, recaptchaAction:n }
   -> posted to  serverTokenEndpoint  ==  https://api.fitbit.com/oauth2/token
```

`recaptchaToken` is part of the credential submission. The same bundle carries the rest of the
machinery, so this is a real gate and not a vestige:

```
GET_TOKEN:      "oauth2/token"
RECAPTCHA_TOKEN:"oauth2/recaptcha_token"        <- a dedicated captcha endpoint
routes/recaptcha-blocked                        <- a route for users the captcha stops
MESSAGES: RECAPTCHA_SERVER_ERROR, RECAPTCHA_SERVER_ERROR_WEBVIEW
featureFlags: { recaptchaEnabled: true, mobileRecaptchaEnabled: true }
fitbitRecaptcha.getRecaptchaToken(action, cb) -> fitbitPasswordOauth2Login(user, pass, token, action)
```

And this is what the same endpoint accepts from us, authenticated with the **published** client
secret and carrying **no `recaptchaToken` at all**:

```
POST https://api.fitbit.com/oauth2/token
Authorization: Basic base64(228TQD:7659f9…744a)      <- published on accounts.fitbit.com
grant_type=password&username=<own test account>&password=<wrong>

400 {"errorType":"invalid_grant","message":"Invalid username/password."}
```

The response is a **verdict on the credentials**, not a complaint about a missing captcha. The
endpoint performed the credential check that the sign-in page performs only after a reCAPTCHA token
has been obtained.

### So the impact is

**The published client secret lets anyone submit username/password pairs to Fitbit's credential
check while skipping the reCAPTCHA that Fitbit's own client attaches to that exact request.** That
is the anti-automation control on an authentication endpoint for accounts holding heart rate, sleep
and location data.

Every element of that sentence is evidenced rather than argued:

```
the secret is published        curl the page, read the meta tag
the secret is live             three-way differential, Fitbit names "Client secret invalid"
the client sends a captcha     quoted from accounts.fitbit.com's own bundle
the endpoint does not need one our request, their response, no captcha sent
```

### What is still NOT claimed

- **No account takeover.** Credential submission still needs the correct password.
- **Rate limiting was not tested and is not claimed absent.** Testing it means repeated failed
  logins, which is brute force and forbidden. The claim is about the **captcha**, which is proven by
  their code and our single request — not about throughput.
- One code path in the same bundle posts `{grant_type:"password",username:e,password:r}` **without**
  a captcha token, so the client itself has a captcha-less variant, probably for a webview or legacy
  flow. Noted here so a reviewer does not have to find it. It does not change the fact that the
  primary login attaches one and the endpoint requires none.

## The audience question — closed as untestable, by three attempts

Signing in through the Fitbit Android app (now **Google Health**) with a Google account did not
create the linkage either. Three attempts, two Google accounts, web and app. The `social` grant's
legacy `googleUID` link cannot be created on any account we can make, so whether `aud` is validated
stays unanswered and is written up as a question for Fitbit, not as a finding.

## Chain extensions — three tried, three closed, none in the report

```
USER ENUMERATION   existing account + wrong password   -> invalid_grant "Invalid username/password."
                   impossible address + wrong password -> invalid_grant "Invalid username/password."
                   IDENTICAL. No account-existence oracle. Good security on their part.

oauth2/recaptcha_token  empty body        200  {}
                        with an action    200  {}
                        [SENTINEL] fake endpoint -> HTML error page, so the endpoint is real
                        and distinct - but it returns nothing usable. Closed.

SCOPE on the password grant   no scope / real scopes / impossible scope
                              all three identical. Scope is not parsed before the credential
                              check, so nothing can be concluded. Stays out.
```

Three attempts to widen the finding, three negatives. They are recorded because a reviewer should
see that the surrounding surface was checked and holds — and because claiming any of them without
this evidence is how a report becomes Spam.

**MFA was not tested.** `mfa_sms` appears to be the same legacy mechanism as the social link: Fitbit
accounts are migrating to Google Accounts, and the app now offers only "Manage your Google Account",
so a Fitbit-native second factor could not be enabled on an account we can create. Not tested, not
claimed.

## FINAL — what the report claims, and nothing more

```
1. accounts.fitbit.com publishes a confidential OAuth client secret for
   "Fitbit Web Application" in page source. feed-moderation.fitbit.com publishes
   a second one for a staff tool. Both TIER1 in Google's own list.
2. Both are live, proven by a three-way differential Fitbit itself distinguishes
   ("Client secret invalid" vs "Client id invalid").
3. Fitbit's documentation forbids this for server-type applications.
4. Their sign-in client posts recaptchaToken with the password grant.
5. The same endpoint, with the published secret and NO captcha token, performs
   the credential check anyway.
```

Not claimed: account takeover, absent rate limiting, user enumeration, scope escalation, MFA bypass,
or that the `aud` claim is unvalidated. Each was either tested and closed, or could not be tested
from outside and is written up as a question rather than a finding.

## Honest outcome estimate, superseded by the decision above



| Outcome | Estimate | Why |
|---|---|---|
| Duplicate | ~30% | Plain page source on a well-known host. Long-lived. Others look here. |
| Accepted, rewarded | ~45% | The differential disproves "public client by design", which is the objection that would otherwise close it. Two hosts, TIER1, credentials class. |
| Accepted, low / credit | ~15% | If the panel weighs the empty `scopes` heavily and treats it as no demonstrated user impact. |
| Won't fix / intended | ~15% | Fitbit's own documentation forbids the practice for this application type, which is hard to argue past. | If Fitbit considers these clients non-confidential despite the endpoint's own behaviour. |

Do not re-argue a close with the same evidence (FO-12). Do not add impact claims after submission —
Google states the reward is decided on what is in the report **before triage**.
