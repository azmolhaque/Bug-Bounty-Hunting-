
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

| S38 | wellbeing `.api` call() — missing access check on two methods | DROP (real defect, empty payload) | See below. |

### S38 in full — the gap is real, what is behind it is not

`WellbeingSettingsProvider` registers each call() method with a package
allowlist (`a2.m("com.google.android.googlequicksearchbox")` …) and each API
implementation also carries its own `gau.b(callingPackage)` check. Two
implementations return unconditional `Boolean.TRUE` from that check:

    gcu  get_wind_down_status   ->  san.E(Boolean.TRUE)
    gcy  update_wind_down       ->  san.E(Boolean.TRUE)

Predicted from the code, then confirmed empirically from `adb shell`, whose
calling package `com.android.shell` is on no allowlist:

    canary_not_real                           success=false, wellbeing_tts_invalid_arguments
    get_wind_down_status                      Bundle[{lastUpdateMs=0, state=0, version=0, zenRuleState=0}]
    update_wind_down                          Bundle[{result=-1}]
    get_wind_down_data                        SecurityException: Access not allowed for app: com.android.shell
    screenTimeSummary                         SecurityException
    get_app_usage_and_sleep_intervals         SecurityException
    get_auto_dnd_text                         SecurityException
    get_auto_dnd_configuration                SecurityException
    set_wind_down_schedule_enabled_in_bedtime SecurityException
    get_all_apps_usage / get_app_usage / get_app_usage_millis   SecurityException
    start_screen_effects_override / stop_...  SecurityException

A clean three-way differential: sentinel refuses, guarded methods name the
caller and refuse, two methods answer. The access-control inconsistency is
real and precisely located.

**Dropped anyway.** What the attacker actually GETS is bedtime-mode state —
four zeroes — which appears nowhere in the Mobile VRP sensitive-data list, and
a write that returned `result=-1`, i.e. nothing changed. The data-bearing
methods (`screenTimeSummary`, `get_app_usage_and_sleep_intervals`, the usage
APIs) are exactly the ones that enforce the allowlist. Even a working
`update_wind_down` would amount to "an app can toggle your bedtime mode",
which is not a security impact, and routing that to "DND could suppress
security notifications" is the speculative chain CLAUDE.md section 3 forbids.

Worth recording because of what it would have looked like without the kill
list: "Access control bypass in Google Digital Wellbeing, unauthenticated app
reads and writes user settings." True sentence, N/A close.

`com.google.android.apps.search.assistant.surfaces.voice.devapp` is in two
allowlists and is NOT installed on this device, so the package name is
unclaimed - but it only gates `get_all_apps_usage` and `get_app_usage`, and
whether the allowlist verifies signature as well as name is untested. That is
the one thread here worth pulling if the service surface comes up empty; it
needs the PoC app, since the package name must be claimed by a real APK.

### 2026-10-20 — first crossing: three services bind from a permissionless app

The PoC app (`poc/mvrp-probe`, no `<uses-permission>` at all, uid 10563 —
not shell) binds to these, with a nonexistent service as the control:

    com.google.android.apps.restore/.osmigration.data.credentials.importer
        .recovery.CredentialRecoveryService                      BOUND
    com.google.android.apps.work.clouddpc/.vanilla.oemconfig.command
        .services.OemCommandEndpointService                      BOUND
    com.google.android.apps.work.clouddpc/.vanilla.policy
        .services.LocalPolicyHandlerEndpointService              BOUND

    com.google.android.apps.restore/.canary.NotARealService       false  (control)
    com.fitbit.FitbitMobile/androidx.health.platform.client.impl
        .sdkservice.HealthDataSdkService                          false

`getInterfaceDescriptor()` is empty on all three, so these are not AIDL stubs
but plain Binders — the naming and the tiktok framework around them point at
gRPC-over-binder endpoints with custom transaction codes.

**This is a precondition, not a finding.** Google's endpoints of this shape
normally authenticate the caller per transaction rather than at bind time, so
a successful bind is expected and proves nothing on its own. The question is
what a transaction returns. Reading the decompiled service first rather than
firing blind: an empty parcel at an unknown code on a device-policy command
service is an unknown action, and CLAUDE.md section 7 forbids that.

Why these matter if a transaction does work: `CredentialRecoveryService` sits
in the migration path that imports credentials, which is High Impact Data; the
clouddpc endpoints are Android Device Policy's OEM command and local policy
handlers.

| S39 | restore `CredentialRecoveryService`, clouddpc `OemCommandEndpointService` / `LocalPolicyHandlerEndpointService` | PARKED — precondition only | Bind succeeds from a permissionless app, but no byte was obtained. See below. |

### S39 — four layers deep, still a precondition

The chain, read out of the decompiled source:

    CredentialRecoveryService.onBind()
      -> ((ptd) a().b.a()).a()            ptd = com/google/frameworks/client/data/
                                                android/server/Endpoint
      -> grpc-over-binder server transport (rvk)
      -> rvk handshake:  int callingUid = Binder.getCallingUid();
                         poe a = rvkVar.a(callingUid);   // SecurityPolicy, async
                         // failure path: "Could not evaluate SecurityPolicy"
      -> rvk.a(int): policy is field `b` (type rvf); which implementation the
         DI graph binds for THIS endpoint is not yet traced.

So a per-connection policy exists and is evaluated against the calling UID;
the transport even tags same-UID and cross-UID callers with different trust
levels. What is NOT established is which policy instance applies here. Going
further needs either the dagger binding for `rvf` traced, or a real
grpc-binder client handshake built to test empirically.

Correction to an earlier reading in this session: `rqp` is not the security
policy. It is `abstract tut a(String)` — a service-name registry.

Prior probability is low. These endpoints are shared across many Google apps,
so a permissive policy would be a broad and well-trodden bug.

### The useful result of tonight: a better filter than names

All three services that bound returned an EMPTY interface descriptor. Empty
means a framework grpc endpoint, where the check lives in the transport's
SecurityPolicy — little room for a developer to forget it.

A NON-empty descriptor means a hand-written AIDL Stub, where the caller check
is the developer's own to write, or to forget. That is where the bugs are.

We have been choosing targets by how promising their names sound
(CredentialRecoveryService, OemCommandEndpointService). Descriptor shape is a
far better filter, and `scripts/mvrp-services.sh` now sweeps every exported
unguarded service across all decoded apps and sorts them on exactly that.
