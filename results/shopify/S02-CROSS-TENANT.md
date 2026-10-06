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
