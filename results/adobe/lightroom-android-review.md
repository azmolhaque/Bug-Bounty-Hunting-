# Adobe Lightroom (Android) — static review for the Adobe program (Intigriti)

**Date:** 2026-11-03
**Researcher:** Md. Azmol Haque Rony (`cindrasec`)
**Target:** `com.adobe.lrmobile`, pulled from device, apktool + jadx.
Tier 2 mobile asset; photo/album/sharing surface (in-scope: user photos/account data).

## Bottom line

**No client-side finding.** The deep-link router was fully traced. One path
(`/app/shares/`) leads to a genuine **server-side** authorization question on
`photos.adobe.io` that static analysis cannot resolve — a live, in-scope test
left for the researcher.

## Manifest triage

- **`CrossAppContentProvider`** (`com.adobe.lrmobile.commonid`, exported) = the
  **same class already proven signature-gated** in the Acrobat review. Same code,
  same verdict. Not re-traced.
- All other providers (`contentprovider`, FileProvider, messaging, firebase,
  facebook, picasso) are `exported="false"`. Not reachable.
- **NSC is solid:** `cleartextTrafficPermitted="false"` (only localhost), user-CA
  trust debug-only. Not reportable.

## Deep-link router (`fd/c.java`) — fully traced

Entry `AppLinkReceiverActivity` (handles `https://lightroom.adobe.com`,
`adobelightroom://open`, `lightroom.app.link`) → ViewModel `applink/a` →
`fd.c.c(uri)` builds an Intent to `StorageCheckActivity` by path:

- `/upsell`, `/app/settings`, `/app/onboarding`, `/learn/*`, `/community/*`,
  `/u/*`, `/emailweblink` → internal Cooper/learn/upsell/content screens keyed by
  content IDs. Community/learn content; not a cross-user data surface (and
  Community is explicitly out of scope).
- **`/openurl?show=<URL>&hashedguid=<…>`** → handler `m.z2()` **host-pins** the
  URL: `startsWith("https://www.adobe.com/go/")` or it's rejected
  ("Incorrectly formatted show url"). Not an arbitrary-URL open redirect or
  WebView injection; residual would be an `adobe.com/go` open redirect, which is
  Adobe-side, not in the in-scope asset list, and the excluded low-impact class.
  **Safe.**
- **`/app/shares/<id>`** → extracts `space_id` + `account_id` (`jt.a.c()`) →
  `StorageCheckActivity`. Opens a shared space by ID.

## The one live, in-scope test (server-side — researcher to run)

The `/app/shares/` flow forwards `space_id`/`account_id` to `photos.adobe.io`
(`/v2/catalogs/<catalogId>/`, base `https://photos.adobe.io`). Whether a
**private / non-shared** space or asset can be read cross-account is decided by
Adobe's backend — the APK only forwards the ID. Static analysis cannot answer it.

**Live test (Lightroom Web is the efficient surface — same API, no cert pinning,
in-scope):**
1. Account A: create a private, non-shared album; capture the
   `photos.adobe.io/v2/catalogs/<A>/…` fetch (DevTools), note catalogId + asset IDs.
2. Account B: replay with B's token, A's IDs.
3. A's private asset returns to B → in-scope cross-account IDOR. 403/404 → intended.

RoE: `X-Intigriti-Username` header + UA tag, ≤20 req/s, record testing IP,
minimal PoC only. IDs are UUIDs (not enumerable) — this tests *authorization*
with IDs legitimately held from Account A.

Honest expectation: `photos.adobe.io` is mature/hardened; prior on a clean
cross-account read is low. But it's a real, live, self-validatable in-scope test —
the first in this engagement that isn't a client-side dead end.

## Honest assessment

Lightroom's client-side deep-link surface is clean (host-pinned openurl,
signature-gated provider, server-authorized shares). No submission from static
analysis. The productive remaining work is the live `photos.adobe.io` IDOR test,
which only the researcher can run (own accounts, program self-validation rule).
