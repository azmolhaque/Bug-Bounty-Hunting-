# Magento Open Source — white-box review for the Adobe public program (Intigriti)

**Date:** 2026-11-02
**Researcher:** Md. Azmol Haque Rony (`cindrasec`)
**Target:** `magento/magento2`, branch `2.4-develop` @ `b0a747142` (cloned fresh)
**Program:** Adobe Public Bug Bounty (Intigriti) — Adobe Commerce / Magento Open
Source, Tier 2. Local self-hosted install, as the program's test plan requires.

## Bottom line

**No valid finding.** Nothing reviewed clears the §2 submission bar. Recorded
here so the same ground is not re-walked, and so the one unresolved lead is
handed over honestly rather than overclaimed.

## Method

White-box review of the authorization-sensitive surfaces:

- All first-party REST routes (`app/code/Magento/*/etc/webapi.xml`, 348 routes),
  flagging `self`/`anonymous` routes that take an `:id`-style URL parameter with
  no `force="true"` binding to the session.
- All GraphQL root resolvers (`*/etc/schema.graphqls`), flagging mutations/queries
  that take an identifier (`uid`, `id`, `cart_id`, …).
- Admin controller ACLs (`ADMIN_RESOURCE`, `_isAllowed`, `_forward('denied')`).
- 2026 security-flavored commits on `2.4-develop`, read as fix-patterns to
  variant-hunt.

## Dispositions

| Candidate | Why it is not a finding |
|---|---|
| **GiftMessage guest-cart item access** (`ItemRepository::get/save`) | Loads the quote by `cartId` first, then `getItemById($itemId)`; the item must belong to that cart's quote. Guest `cartId` is a masked token, not a sequential id. Correctly scoped. |
| **GraphQL `updateCustomerAddressV2` / `deleteCustomerAddressV2`** | `GetCustomerAddress::execute` enforces `address.getCustomerId() === context.getUserId()` and throws `GraphQlAuthorizationException` otherwise. Correctly scoped. |
| **Backup Rollback missing ACL** (`Backup/Controller/Adminhtml/Index/Rollback.php`) | A genuine missing-`ADMIN_RESOURCE` class — but **already fixed** in this tree (commit `8d90eae1`, which adds `ADMIN_RESOURCE = 'Magento_Backup::rollback'`). Instance patched. |
| **Address file-upload frontend-input validation** (`Customer/Controller/Address/File/Upload.php`) | **Already fixed** (commit `bf5e194c`, restricts uploads to `file`/`image` frontend input types). Sibling admin uploaders checked; no unpatched variant. |
| **Unreturned `_forward('denied'/'noroute')` guards** | Swept every occurrence. The deny-style guards all either `return`/`return $this` immediately after, or are benign `NewAction → edit` forwards. No controller continues past a failed guard. |
| **Storefront UI-render → admin data provider** (`Ui\Controller\Index\Render` → `customer_form` → `DataProviderWithDefaultAddresses`) | **Unresolved lead, low confidence.** `customer_form.xml` lives in `view/base/ui_component/` (in the frontend theme fallback), and its `getData()` has no per-customer filter in the method body. BUT `customer_form` is an adminhtml form with no frontend layout handle, and whether the frontend render controller will instantiate an admin component at all is area-registration-dependent and was **not** confirmed. Source reading leans toward *not reachable*. Needs a live local instance to settle. |

## The one open lead — handed to the researcher

The `customer_form` frontend-render question can only be settled on a running
local instance (the program mandates self-hosted testing and researcher
self-validation anyway). The test is a single request:

- Install Magento Open Source locally.
- As a guest / low-priv session, request the storefront UI render endpoint for
  the `customer_form` namespace.
- **If** it returns another customer's data → real missing-authorization finding,
  worth writing up. **If** it 404s / returns nothing / requires admin → confirmed
  non-bug, close it.

Per Adobe's program rules, unvalidated AI output is closed N/A and risks a ban,
so this step is deliberately left for manual, human validation.

## Environment notes (for a future run)

- A full local Magento needs MariaDB + OpenSearch; both run fine as Docker
  containers in the cloud session (`dockerd` starts; Docker Hub is reachable
  through the proxy, whereas `artifacts.opensearch.org` / `elastic.co` are not).
- `composer install` works via authenticated git-source fallback; the pre-seeded
  `auth.json` placeholder `"proxy-injected"` must be replaced with a
  character-valid dummy or composer aborts before the proxy can inject real auth.
- `php8.3-bcmath` and `php8.3-soap` must be apt-installed; `ext-redis` platform
  req must be ignored at install time.

## Honest assessment

Magento's `2.4-develop` is heavily audited (the Adobe program shows 1,297
submissions, 8% accepted). The easy access-control bugs are already found and
fixed. A valid finding here, if one exists, will come from deep business-logic
or a genuinely novel variant — not from a quick authz sweep. This review did
not surface one.
