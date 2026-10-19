
## 2026-10-19 — Mobile VRP, Android 15 / SDK 35, moto g stylus 5G 2024

| # | surface | verdict | why |
|---|---|---|---|
| S24 | `fitbit-stage.com` in Fitbit's production intent-filter | DROP | MarkMonitor registrar, googledomains NS. Google's own domain, not claimable. 10s to kill. |
| S25 | safetyhub `DEVICE_SUPERVISION` orphaned permission | DROP | Guard permission genuinely undeclared on device — but the component is `android:enabled="false"` and names the abstract `android.content.BroadcastReceiver`. A disabled stub; no app can enable another app's component. Tool gap found and fixed (`mvrp_surface.py` now skips `enabled=false`). |
| S26 | tycho `CarrierServicesHvContentProvider`, guard `...ACCESS_DATA` declared with no `protectionLevel` (= `normal`, auto-granted) | DROP | Real weak-guard config, but Google Fi is unavailable in BD, the app ships `enabled=2` (disabled) and `pm enable` is refused to shell. Sentinel and target returned the SAME result (`Could not find provider`), so the run proves nothing about the guard. Even enabled, a non-Fi account yields an empty provider — that is a precondition, not a crossing. Mobile VRP pays on actual, not potential, impact. |

**Live lead:** `fitbit://webview` → `com.fitbit.webview.deeplink.WebviewGateway` →
`com.google.apps.tiktok.nav.gateway.GatewayActivity`. All 31 Fitbit deeplink gateways
are aliases onto that one activity, so the question is Fitbit's own routing config:
does the WebView destination take its URL from the deeplink, and is the host validated?

**Structural note:** exported providers are essentially closed across these apps
(Fitbit: 6 providers, 0 flagged). The surface has moved to deeplinks.

| S27 | Fitbit `fitbit://webview?authenticated=&url=` → `WebFrameActivity` | DROP | Correctly built. `UrlValidator.isTrusted` is an exact `Set.contains(host)` plus an https check — no `endsWith`/`contains` bypass. `WebFrameActivity:221` applies it precisely when `AUTHENTICATED` is set, and `slw` registers the `WebViewJsInterface` bridge *and* constructs `DelegateTokenGenerator` only on that same flag. So: unauthenticated → arbitrary URL but no bridge and no credentials; authenticated → bridge and credentials but Fitbit hosts only. Credentials, bridge and validation are all gated on one flag, consistently. |

**Strategic update after S27.** Fitbit's webview stack is well maintained — the
obvious deeplink/WebView classes are handled correctly. Depth-first on a flagship
app is unlikely to pay. Switch to breadth: only 16 of the 50 pulled in-scope
packages have been swept. The remaining 34 include the low-attention ones
(labs.whisk, labs.language.tailwind, scone, cbrsnetworkmonitor, carrier.carrierwifi,
mapslite, photosgo, cultural), which is where a first-party app is likelier to
have an unguarded component than Gmail or Fitbit.

### Tooling correction, 2026-10-19 — the NPE was a denial all along

Every FileProvider read came back as

    Error while accessing provider:<auth>
    java.lang.NullPointerException: ... String.contains(...) on a null object reference

and I read that as "the provider ran our input and crashed, so nothing blocked
us". Wrong. With the output no longer truncated, the same failure shows:

    Caused by: android.os.RemoteException: Remote stack trace:
      at ContentProviderHelper.checkContentProviderPermission(...)
      at ContentProviderHelper.checkAssociationAndPermissionLocked(...)

The `content` CLI mis-renders a permission denial: it reads the remote
exception's null message and throws its own NPE over it. So every one of those
reads was DENIED. The provider/FileProvider surface across safetyhub,
chromecast.app and docs is closed, not open.

Fixes: both probe scripts now classify `checkContentProviderPermission` /
`checkAssociationAndPermission` as DENIED, add an UNSUPPORTED state, and raise
the output head so the `Caused by` block is never cut off — the truncation is
what hid the cause in the first place.

| S28 | docs `storage` (MANAGE_DOCUMENTS) vs `storage.legacy` (no permission) | PARTIAL | The guarded one denies. The legacy one is reachable without permission but `queryRoots` and `/document/root` both return `No result found`. Reachable + empty is a precondition, not a crossing. |
| S29 | docs `statesyncer` (CrossAppStateProvider, exported, no permission) | PARTIAL | Reachable, returns no rows. |
| S30 | safetyhub `suggestionstateprovider` (exported, no permission) | PARTIAL | Reachable, but `query()` throws UnsupportedOperationException — not a query surface. |
| S31 | all FileProviders in safetyhub / chromecast.app / docs | DROP | Denied; see the correction above. |

| S32 | messaging `BugleContentProvider` (exported, no permission) | DROP | `query()` throws `IllegalStateException: unimplemented` for every URI — the canary table name and `/conversations`, `/messages`, `/participants`, `/parts` all return byte-identical errors. It is an empty stub; the real one, `BugleContentProviderInternal`, is DENIED. Every other messaging provider denied except `MediaScratchFileProvider` and `rcs.client.businessinfo` (both EMPTY) and `SharedStorageProvider` / `AvatarContentProvider` (query unimplemented). |
| S33 | photos — Mars (Locked Folder), Memories, Partner, BackupStatus, FreeUpSpace | DROP | `mars.contentprovider.local_locked_media` and `libraries.photos.api.mars` both DENIED — Locked Folder holds. Memories and BackupStatus reachable but EMPTY; Partner and FreeUpSpace unimplemented. |
| S34 | restore — `settingscard`, `pixelmigrate.provider` | DROP | Unimplemented / empty. |

### Where the provider surface stands, 2026-10-19

Probed across the eight highest-scoring non-Tier-1 packages. Uniformly closed:
every provider holding real data denies, and the handful that answer are stubs
(`unimplemented`) or return no rows. Google has hardened this systematically —
manifest `exported=true` with no `android:permission` is routinely backed by an
in-code check, as `camerapreviewprovider` showed first.

Two vectors remain genuinely unprobed:

1. **Exported services** (never touched — binding needs a PoC app, not adb).
   Loudest names: restore `CredentialRecoveryService`; clouddpc
   `OemCommandEndpointService`, `LocalPolicyHandlerEndpointService`,
   `PlayEnterpriseManagementEndpointService`; Fitbit `HealthDataSdkService`,
   `GPayMseService`; tycho `CarrierServicesTestService`, `AudioService`.
2. **`call()` on the providers whose `query()` is unimplemented.** A provider
   can expose its real API through `call()` while `query()` stays a stub —
   SharedStorageProvider, AvatarContentProvider, freeable_space,
   partnercontentprovider, settingscard, suggestionstateprovider. Method names
   come from jadx, then `content call --uri X --method Y`.

Both point at the same next tool: a permissionless PoC app. It also closes the
control gap admitted earlier — adb shell (uid 2000) is not a faithful stand-in
for a malicious app — and Mobile VRP asks for an APK in a good-quality report
anyway.

| S35 | photos `partnercontentprovider`, `freeable_space` — call() | DROP | Sentinel method itself DENIED. call() boundary holds. |
| S36 | wellbeing `.api` — call() | OPEN LEAD | A random nonexistent method returns `Bundle[{success=false, tts_config=<bytes>}]`; the bytes decode to the ASCII string `wellbeing_tts_invalid_arguments`. That is an error payload, not data — but the rejection is on ARGUMENTS, not permission, so an unprivileged caller (uid 2000) reaches method dispatch. The presence of a `success` field implies a successful call returns `success=true` plus a payload. Blocked only on not knowing the real method names. |
| S37 | messaging `SharedStorageProvider` — call() | OPEN LEAD | Same shape: `Bundle[{result_error_key=2}]` for an arbitrary method. Error, not data; reached, not denied. |

### Second tooling correction — a populated Bundle is not necessarily data

mvrp-call.sh aborted on both of the above because its sentinel returned a
populated Bundle, and its rule was "sentinel returns a Bundle => comparison is
meaningless, stop". That rule was too blunt in a way that would have blocked
the most promising targets permanently: these Bundles contain only a refusal
(`success=false`, `result_error_key`), and a real data response would look
obviously different from them. A refusal is a perfectly good baseline.

The classifier now separates BUNDLE_ERR (populated refusal — a valid sentinel
baseline, run proceeds) from BUNDLE (actual payload — abort if the sentinel
produces one). It also prints the sentinel's bytes before any abort, since a
control failure invalidates the comparison, not the observation.
