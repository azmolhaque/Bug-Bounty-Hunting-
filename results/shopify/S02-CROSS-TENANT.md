# S02 — Shopify cross-tenant isolation: four code paths, all solid

**Date:** 2026-10-06/07 · **Verdict: honest negative. Nothing reportable, and the harness now exists.**

---

## The rig

Two development stores created under one partner account registered with the HackerOne alias
`azmolhaque95@wearehackerone.com`, as the program requires. Both on **Shopify Plus App Development**,
both preloaded with Shopify's own test data. Every object touched is one we own.

```
gorib-a.myshopify.com    Admin API token (store-scoped)
gorib-b.myshopify.com    Admin API token (store-scoped)
API version 2026-10
scopes: read/write_products, read_orders, read_customers, read/write_draft_orders, read_files
```

This is the structure that was missing everywhere else this week. Tesla T04 needed an
`InstallationGUID` only a customer has; Marriott M025 needed a `confirmation_id` only a paying
guest has. Here **we mint every identifier ourselves**, so a crossing — if one existed — would be
provable without touching a single third party's data.

## Object identifiers are sequential, not random

```
gorib-a  Product/15405711655048, 15405711687816, 15405711720584    (+32768 each)
gorib-b  Product/10342785679585, 10342785712353, 10342785745121    (+32768 each)
```

Shopify GIDs embed real database ids. That is the opposite of a 122-bit GUID and is why this
target was chosen: if an authorisation check were missing anywhere, the ids to prove it are
guessable *within our own stores* and obtainable *for free*.

## What was tested, and what every path returned

Every test ran with four controls: a positive control, the cross attempt, the reverse cross, and a
sentinel. Nothing below is a conclusion drawn from a single observation.

### 1. `node(id:)` — the generic interface

| | A's token → B's object | B's token → B's object |
|---|---|---|
| Product | `null` | data |
| ProductVariant | `null` | data |
| Collection | `null` | data |
| Customer | `null` | data |
| DraftOrder | `null` | data |
| MediaImage | `null` | data |

Sentinel: a forged token returns
`{"errors":"[API] Invalid API key or access token (unrecognized login or wrong password)"}`.
Reverse cross (B's token → A's object): `null`.

### 2. Type-specific resolvers — a different resolver per type

`product(id:)`, `productVariant(id:)`, `collection(id:)`, `customer(id:)`, `draftOrder(id:)` all
return data for the owning token and `null` for the foreign one. Worth testing separately from
`node()` because each carries its own authorisation code; they do not share a single check that
could be missed in one place.

### 3. Write path — `draftOrderCreate` referencing a foreign variant

The most promising class, because ownership validation on write paths is historically weaker than
on reads.

```
[1] CONTROL   A's token, A's own variant   -> DraftOrder #D11 created, "The Draft Snowboard", 2629.95
[2] CROSS     A's token, B's real variant  -> userErrors: "Product with ID 50770962055393 is no longer available."
[3] SENTINEL  nonexistent id 9999...       -> "Product with ID 99999999999999 is no longer available."
[4] SENTINEL  nonexistent id 1111...       -> "Product with ID 11111111111111 is no longer available."
```

`[1]` proves the mutation works, so `[2]` is a real refusal rather than a broken request. And
`[2]`, `[3]`, `[4]` are **word-for-word identical**: a real foreign id and a fabricated one produce
the same message. **No existence oracle** — Shopify is deliberately generic here.

### 4. REST Admin API — a separate stack

```
CONTROL  A's token -> A's product        200
CROSS    A's token -> B's product        404
CROSS    A's token -> B's customer       404
CROSS    A's token -> B's draft_order    404
SENTINEL A's token -> nonexistent id     404
```

Cross-tenant and nonexistent are indistinguishable. No oracle here either.

## Two near-misses the controls caught

1. **An existence-oracle false positive.** `node()` returns `null` for a foreign object. It also
   returns `null` for an id that exists nowhere. Without testing the second case, "null for B's
   object" could have been read as "it knows the object exists but hides it". It does not.

2. **A broken REST harness read as a finding.** The first REST run returned `303` for *everything*
   — including the control, A's own product. The cause was a stray `\;` appended to the URL by the
   shell, not Shopify. Had the control been skipped, "REST blocks all cross-tenant reads" would
   have been recorded as a result when in fact no request reached the API. Run directly, the same
   endpoint returns `200`.

Both were caught by the same rule: **a positive control and a sentinel accompany every conclusion.**

## Verdict

**Shopify's tenant isolation is well built.** Four distinct code paths, seventeen checks, zero
leaks. This is not a failure of the hunt; it is the answer, and it is worth knowing.

## What this session actually produced

The **harness**, which does not need building again:

- two stores we own, with tokens, on the same plan, both with test data
- a `q()` helper and JSON payload files for arbitrary GraphQL against either store
- a four-way test shape (positive · cross · reverse · sentinel) that any new object type or API
  surface drops straight into

Any future idea on this program is now minutes of work rather than an evening of setup.

## Next, in priority order

| Surface | Why it is worth a look |
|---|---|
| **Storefront API** | A different token type, public by design. Unpublished products, draft content, customer objects — a separate authorisation model from the Admin API. |
| **Staff-role permissions** | Within one store: a limited staff account reaching owner-only data (payouts, customers, app credentials). Not cross-tenant, and a different check entirely. |
| **Metafields / Metaobjects** | Newer surface, less trodden than products. |
| **Files / `cdn.shopify.com`** | Are asset URLs access-controlled, or does possession of a URL grant access regardless of store? |
| **Bulk operations** | Results land at a fetchable URL; worth checking who may fetch it. |

Scopes beyond the current six will be needed for some of these. Adding them takes two minutes in
each store's app configuration and does not change the tokens.

## Housekeeping

A draft order `#D11` was created in `gorib-a` by the control test. It is in our own store and
harmless, but delete it when convenient so the store stays clean for later tests.

---

# Addendum — Storefront API, bulk operations, and two more object types

Continued the same night. Same rig, same four-way discipline.

## Shop and BulkOperation — two object types `node()` had not seen

```
                               B's token -> B's object     A's token -> B's object
Shop/85890007265               name, email, currencyCode   null
BulkOperation/8579090153697    status + signed url         null
nonexistent BulkOperation      —                           null   (sentinel: same as cross)
```

`Shop` was worth testing separately because it is a singleton and singletons often take a
different code path. It does not leak.

## Bulk operations — a different infrastructure entirely

A bulk query in store B completes and hands back a **Google Cloud Storage signed URL**:

```
storage.googleapis.com/shopify-tiers-assets-prod-us-east1/
  bulk-operation-outputs/9c50690e387149cb29978fe32a01
  ?GoogleAccessId=assets-us-prod@shopify-tiers.iam.gserviceaccount.com
  &Expires=1791915081&Signature=...
```

Fetched with **no authentication header at all**: `HTTP 200`, 1467 bytes of B's product data.

That is a pure capability URL, and it is intended design: the object path is 28 random hex
characters, the signature is required, and the expiry is roughly seven days. The question that
matters is not "does the URL work without auth" — it is **"can another tenant obtain the URL"**,
and the answer is no: `node()` on B's BulkOperation id returns `null` to A's token, and the
sentinel returns `null` too. Noted and dropped.

## Storefront API — a genuinely different authorisation model

The Admin API's default is "show everything to a secret token". The Storefront API's default is
the opposite: a **public** token, embedded in themes and readable by anyone, which must expose
only published data. That inversion is where filtering mistakes live.

Store A's own test data supplies four objects that must stay hidden:

```
15405711720584  The Draft Snowboard       DRAFT      publishedAt null   handle the-draft-snowboard
15405712015496  The Archived Snowboard    ARCHIVED   publishedAt null   handle the-archived-snowboard
15405711982728  The Hidden Snowboard      ACTIVE     publishedAt null   handle the-hidden-snowboard
15405711753352  The Minimal Snowboard     ACTIVE     publishedAt null   handle the-minimal-snowboard
```

Three separate resolvers tested, each its own code path:

| Resolver | Hidden four | Control (`gift-card`, ACTIVE, published) |
|---|---|---|
| `products(first: 50)` | absent — exactly 13 of 17 returned | present |
| `product(id:)` | all four `null` | data |
| `productByHandle(handle:)` | all four `null` | data |

`productByHandle` is the one that would have mattered most. An id is a 64-bit number nobody
outside the store knows, but a handle is human-readable and guessable — `the-hidden-snowboard`,
or in a real store `summer-2027-collection`. A leak there is directly exploitable by a competitor;
a leak via id is not. It does not leak.

## Final tally for the night

| Surface | Checks | Result |
|---|---|---|
| `node()` | 8 object types | isolated |
| Type-specific resolvers | 5 | isolated |
| Write path (`draftOrderCreate` with a foreign variant) | 4 | rejected, no oracle |
| REST Admin API | 5 | isolated |
| Bulk operations + GCS | 3 | isolated |
| Storefront API publish filtering | 3 resolvers × 5 | correct |

**Six surfaces, thirty-plus controlled checks, zero leaks.** Shopify is well built. That is the
answer, and it is worth more than a guess either way.

## For the next session

Untested, and each a different kind of boundary rather than more of the same:

- **Staff-role permissions** inside one store — a limited staff account reaching owner-only data.
  Not cross-tenant at all; an entirely different check.
- **Customer access tokens** (`unauthenticated_read_customers`) — can one customer's token read
  another customer's orders or addresses?
- **Metaobjects / metafields** — newer surface, less trodden.
- **Content objects** — unpublished pages, blogs and articles via the Storefront API's
  `unauthenticated_read_content`. Same publish-filtering class as above but a different resolver
  family; needs `read_content` on the Admin side to establish ground truth first.

The rule that earned its keep tonight, twice: **a positive control and a sentinel accompany every
conclusion.** Once it caught a null that would have read as "it knows this exists but hides it",
and once it caught a REST harness that returned 303 to everything — including the control — where
no request ever reached the API.

---

# Addendum 2 — access-scope enforcement, and the lead the documentation killed

A different boundary from everything above: not "can tenant A read tenant B", but **"can a token
read data it has no scope for"**. Shopify's app permission model *is* access scopes, so this is
the same class a staff-permission test would cover, and it runs entirely from a terminal.

## Scope enforcement works, with one apparent gap

Our main app held eight scopes. Direct queries for resources outside them were refused cleanly:

```
locations               ACCESS_DENIED
staffMembers            ACCESS_DENIED
giftCards               ACCESS_DENIED  (read_gift_cards)
shopifyPaymentsAccount  ACCESS_DENIED  (read_shopify_payments)
priceRules              field no longer exists on QueryRoot
inventoryItems          DATA RETURNED        <- the anomaly
```

Nested traversal was also refused — `Product → variants → inventoryItem → inventoryLevels` returns
`ACCESS_DENIED: Required access: read_inventory`, with the path reported correctly. The classic
"top-level resolver checks the scope, nested field forgets" bypass does not apply here.

Writes are refused too: `inventoryItemUpdate` returns
`Access denied ... Required access: write_inventory`.

## The lead, built properly

`unitCost` — the merchant's cost of goods, from which margin follows — is a field on
`InventoryItem`. On Shopify's own test data it is `null`, so I set a real value through the admin
UI (`Cost per item: 1234.56`; the UI itself then displayed `Profit +$1,395.39, Margin +53.1%`,
which is exactly the sensitivity in question) and read it back.

Then, rather than claim anything from the eight-scope token, I built the control that the claim
actually needs: **a second app in the same store holding exactly one scope.**

```
[1] accessScopes            [{"handle":"read_products"}]         <- one scope, verified
[2] inventoryLevels         ACCESS_DENIED "Required access: `read_inventory`"
[3] unitCost                {"amount":"1234.56","currencyCode":"USD"}
```

One token. Same object. Shopify names `read_inventory` as required for one field and hands over
the cost price on another. That looked like a genuine gap in its own authorization model.

## Why it is NOT a finding

The documentation settles it, and against us. `InventoryItem`:

> **Requires `read_inventory` access scope OR `read_products` access scope.**

So the object is *documented* as readable with `read_products`. The apparent inconsistency is the
design: the **object** opens to either scope, while certain **fields** (`inventoryLevels`,
`locationsCount`) demand the narrower one. `unitCost` is not an escapee from that gate; it was
never behind it.

§2.2: *"does the vendor's documentation explain this behavior? If yes, it will be marked
'intended behavior' and closed."* It does. **Dropped before a word of the report was written.**

The check was committed to in advance — "I will not write a word until I see the docs" — which is
the only reason this cost twenty minutes instead of an evening and a closed submission.

## Recorded, not claimed: REST and GraphQL disagree

```
GraphQL, read_products only   ->  unitCost returned
REST,    read_products only   ->  {"errors":"[API] This action requires merchant approval for read_inventory scope."}
```

The same data under two APIs under two rules. Not reportable: the GraphQL behaviour is the
documented one, so REST being stricter is conservatism, not a vulnerability. It would be worth a
second look only if the asymmetry ran the other way.

## Where this leaves the program

Seven surfaces now, all clean:

```
node() · typed resolvers · write paths · REST · bulk operations + GCS
Storefront API publish filtering · access-scope enforcement
```

Still untouched, and still a different kind of boundary each:

- **Staff accounts proper** — a real limited-permission staff user in the admin UI, not an app
  token. The app-scope model turned out to be well enforced; the human-role model is separate code.
- **Customer access tokens** — one customer's token against another customer's orders or addresses.
- **Metaobjects / metafields.**
- **Unpublished pages, blogs and articles** via `unauthenticated_read_content` — the same
  publish-filtering class that products passed, on a different resolver family.

---

# Addendum 3 — app-to-app isolation, and authorization on the async path

Two more boundaries, neither of them tenant-vs-tenant.

## App vs app, inside one store

`gorib-a` now hosts two apps: `recon` (eight scopes) and `minimal` (one). Shopify lets an app
write metafields into a reserved namespace of its own, and in the wild apps keep API keys, OAuth
tokens and licence data there. So: **can one app read another app's reserved metafields in the
same store?**

`recon` wrote one, and Shopify resolved `$app:private` into its real namespace:

```
namespace  app--432303570945--private
key        secret_config
value      RECON-ONLY-9f3a2b7c
GID        gid://shopify/Metafield/190778229686408
```

Three read paths, each a different resolver, each with its control:

| Path | `recon` (owner) | `minimal` (other app) |
|---|---|---|
| `product.metafields(first: 20)` listing | the metafield | `[]` |
| `product.metafield(namespace:, key:)` — literal namespace | the value | `null` |
| `node(id: <Metafield GID>)` | the value | `null` |

Sentinel: `minimal` asking for a fabricated app namespace also gets `null`, identical to the real
one, so there is no existence oracle.

Note the third row. The metafield's GID is a plain sequential integer, and knowing the namespace
is not required to address it — but it is still refused. Isolation holds.

## Authorization on the asynchronous path

Everything tested so far was synchronous: one request, one check, one answer. **Bulk operations
are not.** The query is queued and executed later, in a different context, by a different worker.
Deferred execution is a classic place for authorization to be weaker, on the assumption that
"it was already checked when it went into the queue".

Using `minimal`, which holds only `read_products`:

```
sync    orders                -> ACCESS_DENIED, immediately
bulk    products   (in scope) -> CREATED -> COMPLETED, objectCount 17, url present
bulk    orders     (no scope) -> CREATED, userErrors [] -> FAILED, ACCESS_DENIED, objectCount 0, url null
bulk    customers  (no scope) -> CREATED, userErrors [] -> FAILED, ACCESS_DENIED, objectCount 0, url null
```

There is a real asymmetry here: the **mutation accepts the query into the queue without checking
the scope at all** — `userErrors: []`, `status: CREATED` — where the synchronous API refuses the
same query outright. But the worker checks, the operation ends `FAILED / ACCESS_DENIED`, and
**objectCount is 0 and url is null**. Nothing is produced, nothing leaks.

§2.6: what did the attacker actually get? Nothing. A validation inconsistency with no data behind
it is not a finding. Recorded, not claimed.

The in-scope bulk control is what makes the two failures meaningful: bulk works perfectly for this
token when the scope is present, so the failures are about authorization rather than about bulk
being broken for it.

## Running total

```
node()  ·  typed resolvers  ·  write paths  ·  REST  ·  bulk operations + GCS
Storefront publish filtering  ·  access-scope enforcement  ·  app-to-app metafields
asynchronous execution
```

Nine surfaces. Every one enforced correctly, every conclusion carrying a control and a sentinel.

---

# Addendum 4 — unpublished content, and the Storefront write path

## Content objects — the same publish-filtering class, a different resolver family

Products passed; pages and articles are separate code. A page was created in `gorib-a` with
**Visibility: Hidden**:

```
Page/166194512008   "Secret Internal Page"   handle secret-internal-page   body SECRET-PAGE-CANARY-7x4k
```

Page ids are sequential — `166188351624` (Contact), `166188384392` (Privacy), `166194512008`
(ours) — so an attacker who cannot guess the handle can still count. Four read paths:

| Path | Hidden page | Control (`contact`, visible) |
|---|---|---|
| `pages(first: 30)` | absent | present |
| `pageByHandle(handle:)` | `null` | data |
| `node(id:)` | `null` | data |
| `nodes(ids: [...])` | `null` in the array | data in the array |

Sentinel: a nonexistent handle and a nonexistent page id both return `null`, identical to the
hidden page, so there is no existence oracle.

`nodes()` was worth testing separately from `node()`: it is a different resolver, and a batch
endpoint is exactly the kind of place a per-object visibility check gets applied once instead of
per element. It is applied per element — the array came back `[contact, null]`.

## The Storefront write path — carts

Every Storefront test so far was a read. A cart is a **mutation**, and today's work has shown
repeatedly that read and write paths carry separate checks. The question: can an unpublished
variant be put into a public cart, and from there into a checkout?

The first attempt had a **broken control** — the published product chosen was Gift Card, whose
inventory is 0, so it came back `quantity: 0` just like the hidden ones and proved nothing. Redone
with a published, in-stock product:

```
[1] CONTROL  Collection Snowboard: Liquid (ACTIVE, published, 50 in stock)
             cartCreate -> totalQuantity 1, cost 749.95, line present
[2] TEST     Hidden Snowboard (ACTIVE, publishedAt null, 50 in stock)
             cartCreate -> totalQuantity 0, cost 0.0, lines []
[3] TEST     cartLinesAdd of the hidden variant onto the working cart
             -> cart unchanged, totalQuantity still 1, only the Liquid line, userErrors []
```

Both cart mutations drop the unpublished variant. They do it **silently** — `userErrors` is empty
and the line simply vanishes — which is a UX wart, not a security failure: nothing enters the cart
that should not, and nothing leaks.

Note the broken control nearly cost a wrong reading for the third time today. "Hidden product gives
quantity 0" meant nothing until a published in-stock product was shown to give quantity 1.

## Eleven surfaces

```
node()  ·  typed resolvers  ·  Admin write paths  ·  REST  ·  bulk operations + GCS
Storefront product filtering  ·  Storefront content filtering  ·  Storefront cart mutations
access-scope enforcement  ·  app-to-app metafields  ·  asynchronous execution
```

Every one enforced correctly. Across the whole engagement the controls caught four would-be
findings that were not there: a null that looked like concealment, a REST harness that returned
303 to everything including the control, a `unitCost` read that the documentation turned out to
authorise, and a cart quantity of 0 that was inventory rather than filtering.

---

# Addendum 5 — customer vs customer

The last boundary available without a second human identity: two shoppers in one store, each with
their own login, orders and addresses. Created through the Storefront API after adding
`unauthenticated_write_customers` and `unauthenticated_read_customers`:

```
c1  Customer/31262891868296   address MailingAddress/43777503527048   "111 ALPHA St"
c2  Customer/31262891901064   address MailingAddress/43777503592584   "222 BRAVO St"
```

Both id pairs are sequential — customers 32,768 apart, addresses 65,536 apart.

`customerAddressUpdate(customerAccessToken:, id:, address:)` is the right shape to attack: the
object id is a **separate argument** from the token that establishes who is asking. That is exactly
where ownership checks get forgotten.

```
[1] CONTROL   c1's token, c1's own address      -> updated
[2] TEST      c1's token, c2's full address id  -> customerUserErrors NOT_FOUND "Address does not exist"
```

## The sentinel was wrong, and it hid the real test

`[3]` used `MailingAddress/9999999999` and came back `Invalid id` — but a real address id is not a
bare number. It carries a query string:

```
gid://shopify/MailingAddress/43777503592584?model_name=CustomerAddress&customer_access_token=VWWuh6xt...
```

**The id embeds an access token.** So `[3]` was malformed rather than nonexistent, and the
comparison was meaningless. Worse, it concealed the question that actually mattered: what happens
with the bare numeric id, without the embedded token?

```
[4] TEST      c1's token, c2's address, bare number   -> Invalid id, RESOURCE_NOT_FOUND
[5] CONTROL   c1's token, c1's OWN address, bare num  -> Invalid id, RESOURCE_NOT_FOUND
[6] SENTINEL  well-formed, nonexistent number         -> Invalid id, RESOURCE_NOT_FOUND
```

`[5]` settles it: **c1 cannot address even its own address without the embedded token**, so `[4]`
fails on format, not on ownership. All three responses are identical, so there is no oracle either.

The address id is a signed capability. The numeric half is sequential and guessable; the token
half is not. And `[2]` shows that holding another customer's complete id — token included — still
does not work, because the mutation's own `customerAccessToken` must match. Two independent locks.

Had I stopped at `[2]` I would have recorded "customer isolation holds" for the right reason by
luck, on the strength of a sentinel that tested nothing.

## Twelve surfaces

```
node()  ·  typed resolvers  ·  Admin write paths  ·  REST  ·  bulk operations + GCS
Storefront product filtering  ·  Storefront content filtering  ·  Storefront cart mutations
access-scope enforcement  ·  app-to-app metafields  ·  asynchronous execution
customer-vs-customer
```

Five would-be findings caught by controls across the engagement: a null read as concealment, a
REST harness returning 303 to everything, a `unitCost` read the docs authorise, a cart quantity of
0 that was inventory, and a malformed-id sentinel that hid the real ownership question.

**Shopify's authorization is, on this evidence, genuinely well built.** Twelve independent
surfaces, every one enforced, no oracles anywhere.

---

# Addendum 6 — the in-scope assets never touched

## `*.shopifycs.com` — Card Services

Named in scope and never probed. The sentinel ran first, and it was the right call:

```
zzz-canary-nope.shopifycs.com   "missing client certificate"   <- mTLS on the wildcard
checkout.us.shopifycs.com       403, server: UploadServer, <Error><Code>AccessDenied</Code>
deposit.shopifycs.com           403, same — Google Cloud Storage
cs.us.shopifycs.com             403
cardsinkone.apps.shopifycs.com  403
```

The wildcard sits behind client-certificate auth; the real hosts resolve to GCS buckets that
refuse anonymous reads. Payment infrastructure, properly closed.

## `*.shopifykloud.com` — never enumerated at all

147 hostnames from the archive, and the names are the most interesting of the night:

```
flower.*.airflow.shopifykloud.com                  Apache Airflow Flower — ships with NO auth by default
druid-druid-router-api-ingress-...k8s-exp          Apache Druid router API
conductor.shopify-data-presto-global               Netflix Conductor
etl-a / etl-b.shopify-data-presto-global           ETL
console.alumina / console.magnesia                 consoles
datagrip-license-server.apps                       JetBrains licence server
canada.vpnify                                      VPN
amp-*.flink                                        Apache Flink
```

Exactly the class of internal data tooling that gets left exposed. Probed all 147 in parallel:

```
sentinel  zzz-canary-nope.shopifykloud.com   000   (no wildcard DNS)
alive     0 of 147
```

**None resolve publicly.** The whole domain is internal DNS — the same shape as Tesla's
`tesla.services`, where 6,029 archived hostnames produced nothing live. Suggestive names,
no surface.

## The Partner API — a separate API, a separate token type

Untouched all night, and structurally the most promising thing left: the **organization id sits in
the URL path** while the token sits in a header. That split is where ownership checks get missed.

```
https://partners.shopify.com/<org_id>/api/2026-10/graphql.json
```

A Partner API client was created on our own organization (`5235914`) with all four permission sets,
deliberately — if a cross-org read fails even at maximum permission, the conclusion is not muddied
by "perhaps the scope was too narrow".

A control problem surfaced first and is worth recording: our organization is new, so
`transactions` returns `edges: []` and `app` returns `null`. **With no data of our own, a cross-org
empty result would have been unreadable** — "denied" and "empty" look identical. So the question
was narrowed to one that does not need data: *is the org id in the path validated against the
token at all?*

```
[3] own org 5235914        -> version list returned
[4] nonexistent 99999999   -> 401 "Invalid access token"
[5] neighbour  5235913     -> 401 "Invalid access token"
```

The token is bound to the organization in the path. A valid token with another org id is refused,
and a nonexistent org is **indistinguishable from a real one that is not ours** — so there is no
existence oracle for partner organizations either.

Exactly one request was sent to a non-owned organization id, and the rule was fixed before it went:
one request, stop at the first sign of foreign data, no enumeration. None appeared.

## Thirteen surfaces

```
node()  ·  typed resolvers  ·  Admin write paths  ·  REST  ·  bulk operations + GCS
Storefront product filtering  ·  Storefront content filtering  ·  Storefront cart mutations
access-scope enforcement  ·  app-to-app metafields  ·  asynchronous execution
customer-vs-customer  ·  Partner API organization scoping
```

Plus two in-scope infrastructure domains closed on their own terms: `shopifycs` behind mTLS and
GCS, `shopifykloud` behind internal DNS.
