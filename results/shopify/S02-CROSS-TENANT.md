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
