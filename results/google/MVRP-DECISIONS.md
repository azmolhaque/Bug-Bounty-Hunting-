
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

| S40 | wellbeing `IWellbeingService` (the Chrome bridge) | DROP — auth enforced, proven empirically | See below. |

### S40 — the experiment that finally had a clean yes/no

`WellbeingService.onBind` hands out the AIDL stub with no check; the check is
in `lrg.b()`:

    uid -> getPackagesForUid -> must be exactly one package   (rejects null,
           empty, and the classic multi-package-UID ambiguity)
        -> must be in lpw.a: com.google.android.apps.chrome, com.chrome.canary,
           com.chrome.dev, com.chrome.beta, com.android.chrome
        -> and `this.h.b(str)`: signed with a Google certificate,
           unless `this.i` skips it

Tested without building a valid request proto, by reading which stage rejects:
the service's own status codes distinguish 7 (any auth refusal) from 3/5
(malformed or null request). A deliberately null request therefore answers the
auth question on its own.

    probe as com.cindrasec.mvrpprobe        -> callback 08 06 28 01  => status 7
    probe as com.google.android.apps.chrome -> callback 08 06 28 01  => status 7

(`lrg.c(i)` sets field 1 to i-1, so 6 means 7.)

The second run held an allowlisted package name — `com.google.android.apps.chrome`
is the one of the five absent from this device — and was still refused. So the
signature check is live and `this.i` is off in production.

That also disposes of a suspicion I raised from the decompiled control flow:
the signature rejection appeared to set its result without returning, which
would have let the later request handling overwrite it. It does not; the
status stayed 7.

Four of the five allowlisted names are absent from an ordinary phone, so the
name really is claimable — the name is simply not sufficient. Worth recording
as the shape of a bug that would have worked had the signature check been
flagged off.

### 2026-10-20 — AIDL transaction sweep, 30 services

Sent transaction 1 with the correct interface token to every AIDL service that
was safe to touch (9 skipped: clouddpc, FRP, provisioning, telecom, onboarding,
tether — anything whose effect cannot be undone). 30/30 entries accounted for.

Refusals, once the classifier was fixed to read refusal text and not only
SecurityException:

    IGoogleHttpService        "Uid is not Google Signed"
    INearbyDirectService      "Illegal package [com.cindrasec.mvrpprobe]"
    IWellbeingService         status 7 (S40)
    IAdvertisingIdService     00000000-0000-0000-0000-000000000000
                              — designed to be callable by any app; zeroes
                                mean the user opted out. Working as intended.

Reached the method body with no caller check visible at that layer:

    IGoogleAccountDataService   "the name must not be empty: null"
      (GMS, com.google.android.gms.auth.firstparty.dataservice)
    android.os.IMessenger       NPE on Message.sendingUid  (AGSA SsbService)
    android.content.ISyncAdapter  accepted, no reply — four services:
      docs DocsSyncAdapterService, gm GmailImapSyncAdapterService,
      tachyon contacts SyncService, gms subscribedfeeds SyncService

**Sync adapter note.** Android's own guidance is that a sync adapter service
carries `android:permission="android.permission.BIND_SYNC_ADAPTER"`. These four
carry none, and an unprivileged app binds and calls them. The ceiling is low —
`startSync` triggers a sync and `ISyncContext` reports counts, not data — so
this is a configuration defect in search of an impact, not a finding. Recorded
because the same omission across four first-party apps is a pattern.

**Honest state of the two live leads.** Both sit in Tier 1 (GMS, AGSA), the
most heavily hunted Android surface there is, and reading `IGoogleAccountDataService`
properly means decompiling GMS — 13 APKs. High ceiling, low probability.

### 2026-10-20 — deeplink canary sweep: INCONCLUSIVE, not negative

142 deeplinks across 8 data-heavy apps, 19 candidate URL parameters each,
canary served over `adb reverse` so nothing left the device. Zero hits.

That result carries no information, because the sweep never had a positive
control. Chrome reaching the canary proves `adb reverse` works; it does not
prove the sweep can detect an *app* fetching a URL.

The obvious positive control — `fitbit://webview?url=...`, whose handler we
read in S27 and which loads an unvalidated URL when `authenticated` is absent
— does not fire:

    Displayed .../WebviewGateway for user 0: +158ms
    numActivities=0   type = CLOSE
    determineRescueAppAfterAppFinishItself ... com.fitbit.FitbitMobile
    VRI[WebviewGateway]: visibilityChanged oldVisibility=true newVisibility=false

GatewayActivity starts, matches nothing, and finishes itself. No WebView is
created, so `smd.d()` is never reached. In S27 I assumed host `webview` routed
to that handler; `smd.c()` returns a singleton set I never actually read, so
the assumption was never checked.

Two unresolved confounds, either of which would also produce zero hits:
  - the deeplink routing needs a form we have not found
  - the apps may not be signed in, which was never established before the run

Also unverified: whether a canary over cleartext http is reachable at all from
apps carrying a networkSecurityConfig — Fitbit ships one.

**So: not a negative result. An untested instrument.** Recorded so it is not
later miscounted as a closed surface.

### Instrument failure confirmed — the canary had to be HTTPS

`fitbit://webview?url=https%3A%2F%2Fwww.fitbit.com%2Fhelp` lands on
`com.fitbit.webviewcomms.impl.ui.WebFrameActivity` and tries to load the URL.
So deeplink routing works, `onj.M = new onj("WEBVIEW", 38, "webview")` is the
right host, and WebFrameActivity really does load an externally supplied URL
without validating it when `authenticated` is absent — which S27 read in the
source and this confirms on screen.

What stopped the sweep was the canary, not the targets:

    net::ERR_CLEARTEXT_NOT_PERMITTED

Android 9+ blocks cleartext, so an `http://127.0.0.1:8777/...` canary can
never load inside an app WebView. Every one of the 142 deeplinks was measured
with an instrument that could not register a hit, and "0 hits" was one step
away from being written up as "deeplink surface closed".

Next: an HTTPS canary. `adb reverse` to a local server cannot work — a
self-signed cert is rejected by WebView, and a user-installed CA is not
trusted by apps unless their networkSecurityConfig says so, which Fitbit's
does not. So the canary has to be a real HTTPS endpoint: either
cindrasec.com with a valid certificate, or an OOB interaction service, which
CLAUDE.md section 7 explicitly sanctions for benign canaries.

Also observed in passing, not ours: `https://www.fitbit.com/help` redirects to
`http://help.fitbit.com/` — a server-side HTTPS-to-HTTP downgrade on Fitbit's
own site. Out of scope for Mobile VRP.

### Correction — the deeplink sweep was never validated

I reported "app control passed, the instrument is validated at app level". It
was not. The control compared hit counts before and after; late interactions
from the browser control raised the number, and it printed POSITIVE while the
canary log contained no APPCTL at all. Caught only because the user ran
`grep -c APPCTL` himself.

Re-tested with a marker-based check: `fitbit://webview?url=<https canary>`
produces **no** canary hit (FBTEST = 0), while `url=https://www.fitbit.com/help`
earlier did reach WebFrameActivity and attempted a load.

So the known-good case is not known-good. Either WebFrameActivity validates
the host after all — S27 read `if (this.x && !UrlValidator.isTrusted(uri4))`
and concluded no validation when `authenticated` is absent, but never read
`smq.a(...)`, which builds the Intent and could validate there — or the
deeplink did not reach the activity on this attempt. Follow-up logcat was
empty for WebFrame/UrlValidator/DWB, so neither is established.

**Standing state of the deeplink work: no validated instrument, therefore no
usable result.** The 142-deeplink negative across 8 apps means nothing. Not
recorded as a closed surface.

### Session tally, 2026-10-19/20

Surfaces examined: 40+. Valid bugs: zero. Tool defects found and fixed: seven,
every one of which produced a false negative or, in the last case, a false
validation. The target never once lied; the instruments did.

### Static sweep round 1 — four leads, four closed

First run over the 7 apps decompiled so far. Raw counts were 99 PendingIntent,
34 IntentRedirect, 4 ZipTraversal — mostly noise until two filters were added:
requiring `PendingIntent` in the file (the bare constant 33554432 is 2^25 and
appears in desugared java.util concurrency code), and cross-referencing each
candidate class against the exported, permission-less components in its
manifest. That cut 49 intent-redirection candidates to 5 reachable ones.

| lead | verdict |
|---|---|
| fitbit `FastPairLandingActivity` | FALSE — pulls a `BluetoothDevice`, not an Intent. The grep matched `getParcelableExtra` and `startActivity` in one file with no relation between them. |
| photos `AlbumActivity` | DROP — lines 820-880 are `onNewIntent`: if the new intent differs from the current one it finishes and relaunches itself **with that same intent**, which the caller was already entitled to send. |
| messaging `ShareIntentActivity` | DROP — the `EXTRA_STREAM` Uri goes only into a structured log field; the forwarded intent comes from the app's own builder with its component set. |
| photos `EditActivity` | DROP — the `output` Uri from the caller is validated. `adtj.c()` runs it through `bpqk.i()`, unwraps the data Uri via `yny.b()`, checks the scheme against the allowlist `adtj.a` with `cuak.ab()`, re-checks with `ccgq.d()`, and handles the `file` scheme explicitly. |

The two filters are the lasting result: without them this round would have
been 137 files to read by hand instead of 5.

**Standing: zero valid bugs.** Decompile of the remaining 21 packages is still
running; the static sweep has never been run against any of them, and those
three rewarded classes have never been examined there.

| S41 | docs `ProjectorActivity` — intent redirection | DROP — unreachable path | See below. |

### S41 — the best-shaped lead of the session, and why it still fails

`com.google.android.apps.viewer.ProjectorActivity`, inside
`com.google.android.apps.docs` (Tier 2), is `android:exported="true"` with no
`android:permission`, reachable by any app via `android.intent.action.QUICK_VIEW`.
And it contains, verbatim:

    startActivity((Intent) intent.getParcelableExtra("next_activity_result_key"));

An unvalidated Intent taken from an extra and started — textbook intent
redirection, the class the rules name.

It is not reachable. That line sits in

    public final void onActivityResult(int i, int i2, Intent intent)

so the Intent carrying the extra is a *result* returned by a child activity
that ProjectorActivity started, not anything an outside app can hand it. The
chain would need the attacker to become that child, which needs the viewer to
launch something implicit. It never launches anything: the whole
`com/google/android/apps/viewer/` package contains no `startActivityForResult`,
and no `registerForActivityResult` / `ActivityResultLauncher` / `.launch(`
either — checked separately, because the modern API would not have matched the
first grep and closing on a name mismatch is exactly the error made repeatedly
today.

So `onActivityResult` cannot be driven from outside, and the redirection cannot
be reached.

### Static sweep — five exported leads, five closed

fitbit FastPairLandingActivity (BluetoothDevice, not an Intent), photos
AlbumActivity (relaunches itself with the caller's own intent), messaging
ShareIntentActivity (Uri only logged; forwarded intent built internally),
photos EditActivity (output Uri validated in adtj.c()), docs ProjectorActivity
(unreachable onActivityResult path).

Still zero valid bugs. 14 of 28 packages decompiled; the sweep has never run
against the other 14.

| S42 | tasks `TrampolineActivity` | DROP | See below. |

### S42 — the loudest name of the session, and nothing behind it

`com.google.android.apps.tasks.common.TrampolineActivity` is
`android:exported="true"` with no permission — "trampoline" is literally the
word for this bug class — and it has two paths worth reading.

The redirect path constructs its own destination:

    intent2.setComponent(new ComponentName(
        intent.getComponent().getPackageName(),      // the package WE targeted = tasks
        getString(R.string.task_list_class_name)));  // class from a string resource

Neither half is attacker-controlled, so the redirect stays inside Tasks.

The second path is reachable directly — action
`com.google.android.apps.tasks.notification.OPEN_LINK_ACTION`, sent explicitly
to the exported component — and pulls a URI out of an attacker-supplied proto
in `LINK_EXTRA`, with no validation, into:

    ldh.b(Context, Uri):
        Intent intent = new Intent("android.intent.action.VIEW", uri);
        intent.addFlags(FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);

No scheme check. Still not a finding: an implicit ACTION_VIEW resolves only to
exported components, so no non-exported component is reachable; no
FLAG_GRANT_*_URI_PERMISSION is added, so a `content://` URI conveys no grant;
and opening `https://evil` is something the attacker could do directly. The
answer to "what did the attacker get" is nothing.

That is six exported static leads, six closed.

| S43 | docs `GetMetadataActivity` | DROP | `getParcelableExtra("entrySpec.v2")` is a Drive identifier, not an Intent; `setResult(0)` returns RESULT_CANCELED with no data; the `startActivityForResult` target comes from the app's own builder. Asking for someone else's doc by EntrySpec runs straight into Google's own rule — "a clear path for the attacker to DISCOVER the needed ID" — the rule that closed G-F002. |
| S44 | tasks `TaskListsActivity` | DROP | The GoogleHelp intent is `setPackage("com.google.android.gms")` and its Uri comes from an object the app built; the remaining `startActivity(data)` carries a hardcoded `https://support.google.com/android/answer/7431795`. |

### Static sweep, final: seven exported leads, seven closed

    fitbit     FastPairLandingActivity   BluetoothDevice, not an Intent
    photos     AlbumActivity             relaunches itself with the caller's own intent
    photos     EditActivity              output Uri validated in adtj.c()
    messaging  ShareIntentActivity       Uri only logged; forwarded intent built internally
    docs       ProjectorActivity         real redirection, unreachable onActivityResult path
    docs       GetMetadataActivity       identifier not Intent; returns no data
    tasks      TrampolineActivity        unvalidated URI, but ACTION_VIEW crosses nothing
    tasks      TaskListsActivity         hardcoded support URL

Three of these had genuinely promising shapes and failed for three different
reasons: validation present, path unreachable, nothing gained on arrival.

## Session close — 2026-10-19/20

Surfaces examined: 47. Valid bugs: zero.

Google's first-party Android apps held at five distinct layers, each time with
the check somewhere other than where the manifest suggested: manifest,
bindService, the binder itself, the gRPC transport's SecurityPolicy, and the
source. That is no longer a guess — it is what 47 surfaces showed.

Seven tool defects were found and fixed along the way, every one of which
produced a false negative or, once, a false validation. The targets never lied;
the instruments did. Nothing was submitted, so no reputation was spent.

What remains and keeps working: eleven scripts, a permissionless PoC app, a
Gradle-free APK build chain, 29 decompiled packages, and a static pipeline that
takes 74 raw candidates down to 7 reachable ones. It runs on a new app, or a
new version of an old one, in a single command.

| S45 | tachyon `CseRedirectUriReceiverActivity` | DROP | Exported, no permission, and it handles the client-side-encryption OAuth redirect — but it overrides `startActivity` to `intent.setClass(this, CseAuthorizationManagementActivity.class)` before calling super, pinning every destination to its own class. The AppAuth RedirectUriReceiverActivity pattern, deliberate and safe. |
| S46 | tachyon `GoogleGuideContentProvider` | DROP | Exported with no manifest permission, and reachable (EMPTY, not DENIED). Closed twice over in code: the UriMatcher accepts only `duo_setup_done`, and `query()` requires `getCallingPackage()` to equal `com.google.android.gms`. Behind it is a single boolean — whether registration is PN_ONLY/GAIA_SINGLE_PN — which would be kill-list even unguarded. |

| S47 | restore/pixelmigrate `AppDataReaderService` / `AppDataWriterService` | DROP | Exported with no manifest permission, named for reading and writing other apps' data — the shape the rewarded path-traversal class needs. The binder (`djd`) defends it properly: `c(getCallingUid())` resolves the UID to a package, `d(uid, pkg)` authorizes it (`AppDataWriterService.b(int)` reads `signingInfo`, i.e. signature verification), `isIosAppAllowed()` checks an allowlist, and every path argument is rejected if it contains `../` **or** `..\`. Unauthorized callers get `SecurityException("UNAUTHORIZED")`, bad paths `SecurityException("BAD_ARGUMENTS")`. |

### 2026-10-20 batch 2 — seven never-probed apps, three reachable providers, all closed

Probed voiceaccess, carrierwifi, dynamite, maestro.companion, ar.core, ar.lens
and scone — none of which had been touched before. Everything denied or
unsupported except three EMPTY (reachable, no rows at the root URI):

| S48 | dynamite `NotificationSettingsContentProvider` | DROP | `query()` requires `getCallingPackage()` to be `com.google.android.gm` *and* passes a second check, and returns one boolean column, `chat_standalone_device_notification_settings`. Guarded, and kill-list even unguarded. |
| S49 | carrierwifi `GwpDebugContentProvider` | DROP | Exported, but every reachable method is a no-op: `query()` returns null, `insert()` null, `delete()`/`update()` 0, `getType()` null. The only method with data is `dump()`, which reads the `gwp_persistent_logs` directory — and `ContentProvider.dump()` requires `android.permission.DUMP`, signature level. Not reachable by an unprivileged app. |
| S50 | ar.lens `StickersAvailabilityProvider` | DROP | Sticker availability; a boolean by construction. Not worth reading. |

scone's two providers returned NOPROVIDER — the app is not registered on this
device, same situation as tycho. Undecidable, not closed.

### 2026-10-20 — tooling correction 3: the logcat oracle was reading graphics noise

`mvrp-payload.sh` decided whether a deeplink's URL had loaded by grepping
logcat for `WebFrameActivity|WebViewClient|chromium`. That pattern matches

    BufferQueueProducer: [com.fitbit.FitbitMobile/...WebFrameActivity...] disconnect

which Android emits whenever the activity opens or closes, whether or not any
URL was ever fetched. Consequence: the accept control (`fitbit.com/help`) and
the reject control (`example.org`) both returned `WEBVIEW_ACTIVE`. An
instrument that cannot separate two known-different states has no verdict
worth printing — so every `WEBVIEW_ACTIVE` in that script's history means only
"the string WebFrameActivity appeared in the log".

This is the eighth tool defect in this effort and the third of the same
species: confident conclusions drawn from noise. The pattern across all eight
is that the control was either absent, or built so it could pass without the
measurement working.

**Fix.** The noise branch is deleted from `mvrp-payload.sh` (its only honest
outputs are now the app's own strings: `Cannot load ... in this WebView`,
`net::ERR_*`). The replacement oracle is `scripts/mvrp-screen.sh`, whose
reading is `uiautomator dump` — the text actually rendered on screen. A
directory listing, `net::ERR_ACCESS_DENIED`, and an app's own UI are three
different strings; graphics logs are not among them.

Two pieces of discipline are built into the new script rather than left to me:

1. **STAGE 0 aborts the run.** It fingerprints three screens — HOME, a known
   accepted URL, a known rejected URL — and exits 2 before any payload fires
   if `H1 == H0` (the deeplink never routed) or `H1 == H2` (the instrument
   cannot discriminate). The failure message says the result is *inconclusive,
   not negative*, which is the distinction the previous 142-deeplink zero lost.
2. **A nested control inside the payload.** STAGE 2 pushes a canary HTML that
   prints `MVRP-CANARY` as a heading and then attempts an XHR to the app's own
   `shared_prefs`. If the heading is absent, `file://` never loaded and a
   read-failure means nothing; only with the heading present does
   `MVRPREAD-FAIL` carry information. The canary writes its result to its own
   screen, so nothing leaves the device.

Classifier verified against eight fixtures, including the exact log line that
fooled the old oracle — it now classifies as `SCREEN` (unnamed) rather than
as a positive.

STAGE 1 also stops guessing filenames: it mines `getSharedPreferences("...")`
out of the decompiled source so the file:// probes name files that exist.

Note on what STAGE 1 can and cannot earn: a directory listing is a
**precondition**, not a crossing (CLAUDE.md 2.6). The crossing is STAGE 2 —
an outside document reading the app's private file contents. Only that is
Theft of Sensitive Data, and only if what it reads is a credential.

### 2026-10-20 — first screen-oracle run on Fitbit, and the ninth control gap

First run of `mvrp-screen.sh` against `fitbit://webview?url=` on moto g stylus
5G / Android 15. The instrument worked — it produced five distinguishable
screens where the logcat oracle had produced one undifferentiated verdict:

| fingerprint | produced by |
|---|---|
| `94e116a4` | HOME baseline, and `https://example.org/` |
| `88ea95f5` | `https://www.fitbit.com/help` → `net::ERR_CLEARTEXT_NOT_PERMITTED`, top activity `com.fitbit.webviewcomms.impl.ui.WebFrameActivity` |
| `c2349611` | six payloads, every one of whose host *begins* with `www.fitbit.com` |
| `3efead3d` | six payloads whose host is `example.org` or malformed |
| `a42dd6b1` | `content://` and `intent://` |

Two things are established. The deeplink **does** route: `fitbit.com/help`
brought `WebFrameActivity` to the front, and the cleartext error proves the URL
reached the network stack rather than being dropped. And the six
`www.fitbit.com`-prefixed hosts — `www.fitbit.com.evil.example`,
`evilwww.fitbit.com`, `www.fitbit.com@example.org`, `www.fitbit.com%2f@...`,
`www.fitbit.com../`, `www.fitbit.com.example.org` — all landed on one screen
distinct from both baselines, consistent with a prefix- or substring-based host
comparison accepting all of them. Consistent with; not yet shown.

**The control gap.** `https://example.org/` left the launcher on screen, while
`https://example.org/?x=...` and `https://example.org/#...` produced a third
screen. Same host, same decision expected. The likely explanation is that the
plain reject control simply did not open in time — a missed measurement, not a
demonstrated rejection — and STAGE 0 passed it anyway, because the gate only
required `H1 != H2` and treated `H2 == H0` as informative. It is not: a genuine
rejection and a timed-out launch look identical from one sample.

This is the same species as the previous eight: a control that can pass without
the measurement having worked.

**Fixes, both in the script rather than in my discipline:**

1. **Replication.** Each control now fires `REPS` times (default 2) and the run
   aborts with `UNSTABLE` unless the fingerprint repeats. One sample with an
   8-second wait is not a measurement.
2. **A second, unambiguous oracle.** Acceptance is now read from
   `topResumedActivity` — whether an activity belonging to the target package
   came to the front — not from screen text. `APP_OPENED` / `DROPPED` /
   `OTHER_APP` has no noise term, and STAGE 0 aborts if the accept control does
   not yield `APP_OPENED`.
3. **A distinct-screens table.** The run now prints, for every unique
   fingerprint, the resumed activity, the first five lines of screen text, the
   app's own logcat lines, and every URL that produced it. Its absence is what
   left me holding five fingerprints with no idea what was on any of them.

Also recorded: `getSharedPreferences` mining found nothing because Fitbit has
never been decompiled here (it was not in `mvrp-decompile.sh`'s priority list),
so STAGE 1's file:// paths were guesses and that stage is weak by construction.
The script now says so instead of reporting a quiet zero.

**Where the value is, and it is not in STAGE 3's fingerprints.** From the
earlier read of the decompiled WebView stack, `WebFrameActivity:221` is
`if (this.x && !UrlValidator.isTrusted(uri4))`, where `x` is the
`...AUTHENTICATED` boolean extra, and the `slw` constructor attaches both the
JavaScript bridge and `DelegateTokenGenerator` behind that same flag. So the
design is: untrusted URL allowed only when no bridge and no token are attached.
The chain that would break it is a URL that satisfies `isTrusted` while being
attacker-controlled, launched with `AUTHENTICATED` true — then the attacker's
page receives the bridge and the delegate token, which is Theft of Sensitive
Data rather than an informational redirect.

That is a question about `UrlValidator.isTrusted`'s comparison, and it is
answered by reading the method, not by fingerprinting error pages. Decompiling
Fitbit is therefore the next step, and the host-validation sweep is on hold
until that read says whether the prefix behaviour is real.

### 2026-10-20 — S51 Fitbit `fitbit://webview?url=` CLOSED, and two more tool defects

| S51 | Fitbit `fitbit://webview?url=` deeplink → `WebFrameActivity` | DROP | Under a validated instrument, every payload was dropped: all six `file://` paths, the universal-file-access canary, all eleven host-validation bypasses (suffix, subdomain-lookalike, userinfo `@`, encoded slash, trailing dot, scheme-relative, backslash, fragment and query reflection), `javascript:`, `content://` and `intent://`. The only URL the app accepted was its own host. This is a negative result, not an inconclusive one: the accept control demonstrated the instrument registers acceptance (`WebFrameActivity` resumed and the URL reached the network stack), and under that same instrument nothing else opened the app at all. |

Incidental, not reportable: `https://www.fitbit.com/help` redirects to
`http://help.fitbit.com/` — plain HTTP — and the platform blocks it with
`net::ERR_CLEARTEXT_NOT_PERMITTED`. Their own host, blocked by the OS, no
attacker gain. CLAUDE.md §3 (TLS/transport without a demonstrated downgrade
attack).

**Defect 9 — the fingerprint counted the clock.** The four "distinct screens"
from the first run were one screen:

    94e116a4 -> 12:37 AM      c2349611 -> 12:39 AM
    ed84ed78 -> 12:38 AM      a42dd6b1 -> 12:41 AM

all of them the launcher, with `0%`, `78°`, `92%`, `2 MPH` and a ticking clock.
`sig()` hashed the raw screen text, so one minute of wall-clock made a new
"screen".

The consequence was worse than a missed signal. STAGE 3 fires its payloads in
array order, so the groups fell along minute boundaries — and the first six
entries in that array happen to be the six `www.fitbit.com`-prefixed hosts. I
read a temporal artifact as "the host check accepts anything starting with
www.fitbit.com", built a table out of it, and presented it. Time mistaken for
cause.

Fixed by masking every digit before hashing (`tr '0-9' '#'`). Verified on the
real failure data: the two launcher snapshots now hash identically, while
launcher vs. WebView-error and launcher vs. directory-listing still differ, so
it is not over-masking.

**Defect 10 — the evidence files overwrote each other.** In the first version
`fire()` was called as `t=$(fire ...)`, i.e. in a subshell, so `N=$((N+1))`
never persisted and every payload wrote `01-s1.txt` / `01-s3.txt`. Only the
last dump of each stage survived. The per-payload evidence for that run is
gone; the fingerprints in `report.txt` are all that remains of it. Already
fixed when `fire()` was changed to set globals instead of echoing, but worth
recording: a subshell silently discarding state destroyed the evidence the run
existed to collect.

**Also added:** `am start`'s own output is now captured and classified. A
dropped intent and an app that opened and immediately finished both leave the
launcher on screen, but they are different findings — `INTENT_ERROR` means the
intent was never deliverable, `DROPPED` means the app received it and refused.

Scope confirmed from the file, not memory: `config/scope-mobile-vrp.yaml:18`
lists Fitbit LLC among `in_scope_developers`.

**Remaining Fitbit lead.** The deeplink path is closed, but it is not the only
way into `WebFrameActivity`. `WebFrameActivity:221` is
`if (this.x && !UrlValidator.isTrusted(uri4))` with `x` the `...AUTHENTICATED`
boolean extra, and the `slw` constructor attaches the JavaScript bridge and
`DelegateTokenGenerator` behind that same flag. If the activity can be launched
directly from another app with `AUTHENTICATED` true, the question becomes
whether `isTrusted` can be satisfied by an attacker-controlled host — and the
prize is the bridge plus a delegate token, which is Theft of Sensitive Data.
That is settled by the manifest (is it exported) and by reading `isTrusted`,
not by fingerprinting error pages. jadx is running on Fitbit now.

### 2026-10-20 — S52 Fitbit webview surface closed in source, matching the device

| S52 | Fitbit `UrlValidator` + `amxu` gateway (the code behind S51) | DROP | Both validation paths are exact set membership, not pattern matching. `UrlValidator.isTrusted(URL)` is `getFitbitHosts().contains(url.getHost()) && protocol == "https"`. The gateway `amxu.b(str, z)` falls back, when `z` is false, to `f = {"support.google.com", "policies.google.com"}` compared with `bpvv.bO(set, host.toLowerCase(Locale.ROOT))`, and only after rejecting any URI with `getRawUserInfo() != null` and requiring an https scheme. No `endsWith`, no `startsWith`, no `contains` on the host string. `amxu.a()` is the entry point, matching `scheme == "fitbit" && host == "webview"`, so this is exactly where every payload in S51 died. |

`WebFrameActivity` is declared with no `intent-filter` and no
`android:exported`, so on Android 12+ it defaults to not exported; the extra it
reads is
`com.fitbit.webviewcomms.impl.ui.WebFrameActivity.AUTHENTICATED` (line 213) and
line 221 is `if (this.x && !UrlValidator.isTrusted(uri4))`. There is no path
from another app to set that extra. The design holds: `sln.java` attaches the
auth headers (`this.d.invoke()`) inside the `isTrusted` branch, so the gate and
the reward are bound to the same condition.

Worth recording as method, not just result: the device sweep and the source
read were independent, and they agreed. The device said only the app's own host
was accepted; the source says why. That is the first time in this effort a
surface has been closed twice over by different instruments, and it is the only
kind of zero worth trusting.

It also killed my own hypothesis twice. The "hosts beginning with
www.fitbit.com are accepted" pattern was a clock artifact in the fingerprints,
and the code shows the comparison could never have behaved that way.

### 2026-10-20 — three new Fitbit candidates from the first static sweep

Fitbit had never been decompiled, so `mvrp-static.sh` had never run against it.
With 59,659 java files it reports:

| C1 | `com/fitbit/device/ui/setup/choose/FastPairLandingActivity` | LEAD | Exported, no permission, pulls an Intent out of extras and starts it. This is the named-and-rewarded class, "intent redirections leading to launching non-exported application components". Distinct from S43's `ProjectorActivity`, which had the same shape but whose redirect sat inside `onActivityResult` and was therefore unreachable from outside. A landing activity is more likely to be on the `onCreate` path. Not a finding until the three questions are answered: reachable from outside, the started Intent actually attacker-controlled, and the destination actually non-exported. |
| C2 | `defpackage/nbd`, `defpackage/rmk` | LEAD | Zip extraction into `new File(...)` with no `getCanonicalPath` / `startsWith` check — the "path traversal leading to arbitrary file write" class. Open question is who supplies the archive; if an attacker can, overwriting a `.so` would raise it from Other ($2,250) to ACE ($7,500). |
| C3 | six files with `FLAG_MUTABLE` and `PendingIntent` | LEAD | Needs the manifest cross-reference and a check that the base Intent is implicit. |

### 2026-10-20 — C1 dropped, and the pattern that produced it tightened

| C1 | `FastPairLandingActivity` | DROP | `android:exported="true"` with an `intent-filter` holding only `<category DEFAULT>` and no `<action>`, so it cannot match an implicit intent but can be launched explicitly by another app — question 1 passes. Question 2 fails: what it takes from extras is `(BluetoothDevice) getIntent().getParcelableExtra("android.bluetooth.device.extra.DEVICE")`, not an Intent, and the Intent passed to `startActivity` at line 105 is built internally. No attacker-controlled Intent, no redirection. |

**Defect 11 — the intent-redirection pattern never required the redirection.**
The condition was "file contains `getParcelableExtra(`" AND "contains
`startActivity|startService|sendBroadcast`" AND "imports
`android.content.Intent`". Nothing in that required the extracted parcelable to
*be* the started Intent, which is the entire definition of the class. Any
activity that reads any parcelable and separately starts anything matched. The
earlier 49-to-5 filtering across other apps ran under this same loose
condition, so those five were filtered for reachability, not for shape.

Tightened to the shape jadx actually emits, taken from S43's
`ProjectorActivity`:

    startActivity((Intent) intent.getParcelableExtra("next_activity_result_key"));

so the condition is now an `(Intent)` cast over a `getParcelable*` call, or the
typed `Intent.class` overload, plus a start/bind call in the same file.

Bound by six fixtures checked in the script itself, and the run aborts with
`exit 2` if the pattern flags a negative. Three true shapes are caught — the
cast, the Android 13 typed overload, and the Bundle route — and three false
ones rejected: the `BluetoothDevice` shape from this very candidate, an Intent
extracted but never started, and a `Uri` parcelable alongside an unrelated
`startActivity`. Having a real false positive in hand is what made the fix
testable rather than guessed.

Consequence: the static sweep must be re-run across every app with source,
because its previous intent-redirection output was shape-blind everywhere, not
only on Fitbit.

### 2026-10-20 — the rewarded intent-redirection class is near-absent in this corpus

With the shape requirement in place, the sweep across all 35 apps that have
source returns exactly one exported, permission-less hit:
`com/google/android/apps/viewer/ProjectorActivity.java` — which is S43, already
dropped. Both controls printed POSITIVE first, so the zero carries information:
under the loose pattern this class looked crowded, and almost all of that was
shape-blindness rather than candidates.

**S43 is reopened, with a specific reachability idea rather than a hope.** The
drop reason was "the redirect sits in `onActivityResult`, unreachable from
outside". That is incomplete. `onActivityResult` runs when a *child* activity
returns a result, so if ProjectorActivity starts a child through an implicit
intent that another app can register for — a picker, a chooser, an
`ACTION_GET_CONTENT`-style request — then the attacker's own activity can be
that child and can put `next_activity_result_key` into the Intent it returns.
The sequence is: attacker launches ProjectorActivity, it opens the picker, the
attacker's activity is selected, it returns a result, the redirect fires. Each
step is testable, which is what separates this from the invalid chain in
CLAUDE.md §4. What has to hold: the child is launched with an implicit intent,
the attacker can match its filter, and the redirect's destination is actually
non-exported.

| C2 | `defpackage/nbd` (Fitbit) | DROP | Guarded, and my pattern was wrong. It walks every path component looking for `..`: `for (File f = new File(name); f != null; f = f.getParentFile()) if (f.getName().equals("..")) ...`. That is a valid alternative to a canonical-path check. |

**Defect 12 — absence of one guard read as absence of all guards.** The zip
condition was "does not contain `getCanonicalPath`, `getCanonicalFile` or
`startsWith(`", which treats one idiom as the only way to be safe. Same species
as the previous four: absence mistaken for proof.

The guard list now covers the component walk, `Path.normalize()`, `toPath()`
and any mention of `".."` in the file, and is bound by five fixtures with the
run aborting on a mismatch: two unguarded extractors are caught, while the
component-walk shape from `nbd`, the canonical-path check, and the
`toPath().resolve().normalize()` idiom are not.

Running tally of tool defects this session: 8 through 12, all five found by
reading my own output rather than by being told. Four of the five are the same
error — a conclusion drawn from something not being present.

### 2026-10-20 — S43 closed definitively, with the reason named

Reopened on the idea that `onActivityResult` is reachable if the child activity
can be an attacker app. Followed through; it cannot.

What is true, and is genuinely sloppy: `ProjectorActivity` is
`android:exported="true"` with an `android.intent.action.QUICK_VIEW` filter, and
its redirect checks neither argument —

    public final void onActivityResult(int i, int i2, Intent intent) {
        ...
        if (intent.hasExtra("next_activity_result_key") && num != null) {
            startActivity((Intent) intent.getParcelableExtra("next_activity_result_key"));

no requestCode, no resultCode, so any result carrying that extra fires it. The
branch twenty lines above does check both (`if (i == 256 && i2 == -1)`), so the
file itself shows they know how. And a non-exported destination exists in the
same package: `com.google.android.apps.viewer.drive.InternalProjectorActivity`,
`exported="false"` — exactly what the rules ask for.

What is missing is the only thing that matters: a way for an outside app to
deliver a result to that activity.

- The only two producers of `next_activity_result_key` in the whole app are
  `DetailsPanelActivity:157` and `DoclistActionsMenuWrapperActivity:340`. Both
  are `android:exported="false"`.
- In both, the Intent is not taken from incoming extras. It arrives as the
  parameter of an internal interface callback (`defpackage.nqr.s(Intent)`),
  which only an internal caller invokes.
- `grep` for `createChooser|ACTION_VIEW|ACTION_GET_CONTENT|ACTION_SEND|ACTION_OPEN_DOCUMENT`
  across the entire `com/google/android/apps/viewer/` tree returns nothing, so
  the viewer never launches an outside handler and an attacker app cannot be
  the child.

So the exported entry point, the unvalidated redirect and the non-exported
destination are all real, and there is still no crossing. A precondition is not
a finding (CLAUDE.md 2.6) — this is the shape that killed G-F002 and the Wiz
subdomain report, and the honest move is to drop it rather than write it up as
"an attacker who could return a result would be able to…".

Two things worth keeping as method. Reopening a closed surface on a specific,
testable reachability idea was right — the first drop reason ("it's in
`onActivityResult`") was incomplete reasoning, and incomplete reasoning deserves
a second look. And the follow-up was cheap: four greps settled it, where a PoC
attempt would have cost hours and produced the same answer.

### 2026-10-20 — defect 13: `Intent.class` matched `PendingIntent.class`

The sweep's second exported intent-redirection hit was Photos
`envelope/AlbumActivity`, and the reason was my regex. `getParcelableExtra\([^)]*Intent\.class`
matches

    getIntent().getParcelableExtra("EXTRA_NATIVE_SHARESHEET_RELAUNCH_INTENT", PendingIntent.class)

because `PendingIntent.class` ends in `Intent.class`. And a PendingIntent taken
from extras is the opposite of the dangerous pattern: it executes with its
*creator's* identity, i.e. the attacker's, so forwarding one gains the attacker
nothing. The class that pays is an app handing out a mutable PendingIntent, not
an app receiving one.

Fixed by requiring a non-letter before `Intent`, and the negative fixture set
now includes this exact line. Eight fixtures: the cast, the typed overload, the
Bundle route and the ArrayList overload are caught; the `BluetoothDevice` shape,
`PendingIntent.class`, an Intent extracted but never started, and a `Uri`
parcelable are not.

Also corrected: I told the user the sweep found one exported hit. It found two —
the summary line reads `IntentRedirect: 43 ফাইল (exported: 2)`. I had grepped
the log while it was still being written.

`AlbumActivity` stays interesting for an unrelated reason worth noting before
moving on: it is `exported="true"` with an `autoVerify` VIEW/BROWSABLE filter for
`https://photos.google.com/share/.*`, plus two aliases
(`LegacyFdlIntentHandler` for `photos.app.goo.gl/.*`, and
`PrivateAlbumDeepLinkActivity` for `/album/.*`, the latter
`android:enabled="false"` and therefore unreachable). A web-reachable entry
point matters because Mobile VRP scenario 2, "user follows a link", pays
$18,750 for theft of sensitive data against scenario 3's $4,500 — but a web
link cannot set Intent extras, so only the deeplink data path is reachable that
way, not any extras-driven redirect.

### 2026-10-20 — zip traversal: 13 candidates to 1 to 0, and a new class worth more

With the full guard list, the sweep across all 35 apps dropped from 13
zip-traversal candidates to one, all three controls printing POSITIVE first.
The twelve that fell away each had a real guard that the old
`getCanonicalPath`-only condition could not see. `ZipFolderOpener` — the shared
`com.google.android.libraries.mdi.download` library, the one I most wanted to be
broken because a library bug reaches many apps — guards properly:

    if (name.contains("..")) {
        for (File file = new File(name); file != null; file = file.getParentFile())
            if (file.getName().equals("..")) throw new ZipException("Illegal name: " + name);
    }

and the tightened pattern excluded it on its own, without my reading it.

| C4 | voiceaccess `defpackage/jbd` | DROP as traversal | The only survivor, and not a traversal either. It asks for a constant entry, `zipFile2.getEntry("classes.dex")`, and writes to a constant destination, `new File(jauVar.g(), "dex")`. Nothing derives from an entry name, so there is nothing to guard. |

**Defect 14 — the traversal pattern never required the traversal.** It asked for
`ZipEntry` plus `new File(` plus no guard, but never that the written path derive
from an attacker-controlled entry name, which is the definition of the class.
Exactly defect 11's family: the pattern named the ingredients and not the bug.

Now also requires that entry names be attacker-reachable — iteration via
`getNextEntry()` or `.entries()`, or `getEntry()` with a variable rather than a
literal. Six fixtures, run aborts on mismatch: iteration and the variable
`getEntry` are caught; the constant-entry shape from `jbd`, the component walk
and the canonical-path check are not.

**A class the sweep was not looking for at all.** What `jbd` does is more
valuable than what I went looking for: it opens an archive, pulls `classes.dex`
out of it and writes it to a `dex` directory. That is dynamic code loading. If
the archive is attacker-reachable, the result is not a file write but ACE in
Voice Access's process — the top-paying class in the rules ($7,500 at Tier 2
against $2,250 for "other"), and I would have walked past it because my three
categories were copied from the rules' list rather than derived from what the
code does.

Added as a fourth category, `DexFromArchive`: a dex loader
(`DexClassLoader`, `InMemoryDexClassLoader`, `BaseDexClassLoader`, `DexFile`,
`loadDex`, or the literal `"classes.dex"`) in a file that also touches an
archive. Reachability of the archive is still the question that decides it, and
`jbd`'s own archive source is being read now.

| C4 | voiceaccess `defpackage/jbd` | DROP | Not Voice Access's code at all: `Log.e("SplitCompat", "DexPathList.makeDexElement failed")`, `makePathElements`, `dexElements` reflection — this is Play Core's `SplitCompat`, which loads split APKs the Play Store has already placed in the app's own private directory (`file = jbeVar4.a`). Another app cannot write there. Same ground as CVE-2020-8913, fixed upstream in 2020. |

**Defect 15 — a category broad enough to fire on ubiquitous library code.** All
four `DexFromArchive` hits were the same bundled `SplitCompat`. A pattern that
matches a library present in every app in the corpus reports presence, not
candidates. Play Core's markers (`SplitCompat`, `makePathElements`) are now
excluded, so the category only reports app-specific dex loading.

### 2026-10-20 — all four rewarded classes now closed across this corpus

With all five patterns controlled and bound by fixtures, the 35 apps that have
source produce:

- **Intent redirection**: 2 exported candidates, both closed — `ProjectorActivity`
  (no external path to deliver a result) and `AlbumActivity` (a regex artifact;
  `startActivity(r5)` is a self-restart whose component is pinned by delivery).
- **Zip path traversal**: 13 candidates under the old guard list, 1 under the
  full one, 0 after reading it — every extractor in the corpus either guards or
  never derives a path from an entry name.
- **Dex from archive**: 4 hits, all the same bundled Play Core library.
- **Mutable PendingIntent**: 143 files, never cross-referenced against exported
  components, so this is the one class still genuinely unexamined here.

Total surfaces closed in this effort: 52, plus four candidate classes. Reports
submitted: zero.

**The strategic read, stated plainly.** These are mature, heavily-audited apps,
and the pattern across all 52 closures is the same: the check exists, it is
simply never where the manifest implies. That is not a skill gap, it is a
crowding problem — this corpus has been swept by many hunters for years. Four
in-scope developers have never been touched at all: Research at Google, Google
Samples, Developed with Google, Red Hot Labs. Their apps are small, young, and
far less swept, and the whole pipeline — pull, surface, probe, decompile,
static, screen — is now instrumented and fixture-bound, so running it on a new
app is an hour's work rather than a week's.

The remaining work here, in order: the PendingIntent class cross-referenced
against exported components (the only unexamined class in this corpus), then
new targets from those four developers.

### 2026-10-20 — the PendingIntent class, filtered down from 143

The 143 figure was meaningless and the file list said why: `MediaSessionCompat`,
`androidx/compose/material3`, `io/flutter/view`, `com/bumptech/glide`, `expo/`.
Third-party library code, which the scope file's own kill list rules out —
"Non-Google SDK/library -> report to the maintainer first". Counting them was
wrong, not merely unhelpful.

Two further conditions come straight from the class definition and were never
applied: a PendingIntent must actually be *created*
(`PendingIntent.getActivity/getBroadcast/getService/...`, not merely the constant
`33554432` appearing in the file), and the base Intent must not pin a component —
`setComponent`, `setClass`, `setClassName`, `setPackage` or
`new Intent(ctx, Foo.class)` leave the consumer nothing to fill in.

Bound by five fixtures: the mutable-plus-implicit shape is caught; a pinned
component, a pinned `setComponent`, a file carrying the constant as a plain
bitmask (desugared `j$/util` concurrency code), and an otherwise-matching file
under a third-party library path are not.

### 2026-10-20 — target list for the four untouched in-scope developers

Pulled from the Play developer pages, since none of these apps has ever been
touched here. Fifteen packages:

**Research at Google** — `com.google.ai.edge.gallery`,
`com.google.android.apps.vision.switches`,
`com.google.audio.hearing.visualization.accessibility.scribe`

**Google Samples** — `com.android.developers.androidify`,
`com.google.samples.apps.nowinandroid`, `com.google.ar.unity.arcore_depth_lab`,
`com.google.fpl.mechahamster`, `com.google.play.billing.samples.managedcatalogue`,
`com.google.play.billing.samples.onetimepurchases`

**Red Hot Labs** — `com.redhotlabs.bingo`

**Developed with Google** — `com.google.android.apps.location.gps.gnsslogger`,
`com.google.android.apps.location.rtt.wifinanscan`,
`com.google.android.apps.location.rtt.wifirttlocator`,
`com.google.android.apps.location.rtt.wifirttscan`, `com.google.looker`

Ranked by where the rewarded classes could plausibly live, and by tier, since
tier 3 pays $2,250 ACE / $1,350 theft / $675 other against tier 2's
$7,500 / $4,500 / $2,250:

1. `com.google.ai.edge.gallery` — imports and runs local model files, so it
   handles file paths, archives and user prompts, and touches Google services.
   Plausibly tier 2, and new enough (2025) to be unswept.
2. `com.google.android.apps.location.gps.gnsslogger` — writes and exports log
   files to storage, which is where file-write bugs live.
3. `com.android.developers.androidify` — recent, takes user images.
4. `com.google.samples.apps.nowinandroid` — deeplinks, but a sample app that
   handles no user data reads as tier 3.

Caveat to hold onto: a real bug in a sample app or a game still qualifies, but
at tier 3 rates, and "actual impact" judging means a bug in software with no
users is argued down. The AI Edge Gallery is the one target here where a
finding would be worth tier-2 money.

### 2026-10-20 — S53 GnssLogger, the first app from an untouched in-scope developer

First target from the four developers never hunted here ("Developed with
Google"). 8,307 java files, 20 manifest components, small enough to read whole.

The static sweep returned zero on all four rewarded classes, and for once that
zero is worth something: five controls printed POSITIVE first, and the only
`PendingIntent` hit was GMS's own `PendingIntentCompat`.

The manifest looked better than the code turned out to be:

| S53 | gnsslogger `WearChannelClientListenerService` | DROP | `android:exported="true"`, no permission, `com.google.android.gms.wearable.CHANNEL_EVENT`, `wear://*` with `pathPrefix` `/send-zip`. The shape I had failed to find in 35 mature apps, declared in the manifest of a small one. But `onChannelOpened` builds the destination itself — `FileLogUtil.setupBaseDir(...)` + a string resource + `FileLogUtil.getFormattedCurrentDateAndTime()` + `.zip` — so not one character of the path comes from the channel, and the archive is never extracted: it is saved and its path written to SharedPreferences for the user to share. Even with full reachability the attacker gets attacker-supplied *content* at an app-chosen path, with no traversal and no execution. No crossing. |

Two things also noted while reading: `WearableSignatureVerifier` and
`GoogleCertificates` are both in this app's bundled GMS, so the base
`WearableListenerService` almost certainly validates the caller — the same
fifth-layer pattern as the other 52 closures, where the check sits below the
manifest.

Also worth keeping: the sweep was right and my expectation was wrong. I read
`/send-zip` in the manifest and predicted an extractor; the tool said zero and
the tool was correct. That is the first time in this session the instrument
contradicted me and won.

**Tooling note, not a defect.** `./mvrp-src.sh ... 'ZipInputStream|...|extract'`
returned 43 files, nearly all `androidx/compose`'s `extractNestedStates` and
`ExtractedText`. Searching for an English word rather than a shape. Harmless
here because the result was read rather than counted, but worth remembering:
the same looseness as defects 11 and 14, in a hand-typed query instead of a
script.

**Remaining queue.** Eight candidates in the mature corpus, none yet read:
zip in `maps/bmqw`, `maps/bojy`, `messaging/fauv`, `nbu.files/one`; dex-from-archive
in `dynamite/gvs`, `maps/iwn`, `messaging/uif`, `tachyon/hto`
(`androidx/profileinstaller` dropped — baseline profiles, not dex loading, and a
library). First question for all eight is the same and settles most of them in
one line: does the archive come from the app's own private directory?

### 2026-10-20 — the remaining eight candidates, all closed

**Dex from archive — four, none real.**

| | | |
|---|---|---|
| dynamite `gvs` | DROP | Zero once the pattern asks for an actual loader rather than the `"classes.dex"` literal. |
| maps `DynamiteClient` | DROP | `new DexClassLoader(remoteContext.getPackageCodePath(), ...)` — the code path of an installed, GMS-resolved Dynamite module, not an attacker file. |
| messaging / tachyon `org/chromium/base/BundleUtils` | DROP | Chromium, and it only calls `findLibrary`. Also kill-listed: "Chrome on Android -> Chrome VRP, not here". |

**Zip — four, all guarded, and the last one found a defect in the tool.**

| | | |
|---|---|---|
| maps `buyp`, nbu.files `qzy` | DROP | Play Core's native-library extractor. Entry names must satisfy `matcher.matches()` against a fixed pattern, and the archive is a split APK in the app's private directory. |
| maps `kdu` | DROP | Lottie. Takes only `name.split("/")[len-1]`, the basename, and decodes to an in-memory Bitmap — no file is written. Third-party library besides. |
| nbu.files `qdr` | DROP | Enumerates entries without writing. |
| messaging `fauv` | DROP | Structurally identical to seekh's `ZipFolderOpener`, and it *is* guarded: the name comes from `fiae.a(nextEntry)`, and `fiae.java` holds the same `..` component walk, hoisted into a helper. Messages carries the newer refactor of the same library. |

**Defect 16 — the guard can live in another file.** `fauv.java` was flagged
because `".."` does not appear in it; it appears in `fiae.java`. This one is not
a sloppy pattern like 11, 13 and 14 — it is a limit of file-scoped grep, which
cannot follow a value into a helper. Worth separating from the others, because
the fix is different in kind.

Resolved one level: any file containing both `ZipEntry` and `".."` is treated as
a sanitising helper, and a candidate that calls one is considered to receive a
cleaned name. Fixtures extended to four, with the helper split across two files
so the cross-file case is actually exercised: a direct `e.getName()` is caught,
while the helper-sanitised call and the constant-entry shape are not.

**Zip traversal and dex-from-archive are now closed across the whole corpus**,
each candidate read rather than counted. Of the four rewarded classes, only the
filtered PendingIntent list (24 files, down from 143) has not been read
one by one.

What the zip class actually taught: Google ships one shared archive extractor
and it is guarded in every copy found — inline in seekh, hoisted into a helper
in Messages. Finding two copies and diffing them was the right instinct; the
diff just came out the other way.

### 2026-10-20 — defect 17: an unanchored number, and the twin of defect 13

`WalletTileService` appeared in the mutable-PendingIntent list while its actual
call is

    PendingIntent.getActivity(this, 0, a, 67108864)   // FLAG_IMMUTABLE

the opposite of the class. It matched because of the line above it:

    a.addFlags(335544320)   // FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TOP

and `335544320` contains `33554432`. The constant was never anchored, so an
Intent flag was counted as a PendingIntent flag.

Exact twin of defect 13, where `Intent\.class` matched `PendingIntent.class`:
a substring treated as a token. Two of seventeen defects are now this one
mistake, which suggests checking every bare literal in these patterns rather
than waiting for the next one to surface.

Anchored to `(^|[^0-9])33554432([^0-9]|$)` and checked against four lines: the
real flag with and without an OR'd neighbour still match, while `335544320` and
an unrelated `133554432` no longer do.

The 24-file PendingIntent list was produced under the unanchored pattern and is
therefore inflated by an unknown amount — it has to be regenerated before any
of it is read.

### 2026-10-20 — defect 18: the pull filter silently excluded the new targets

`mvrp-pull.sh` selects packages with a fixed pattern list built when only the
mature apps were in play. `com.google.ai.edge.gallery` matches none of it, so
after installing the app the pull reported "65 package টানা হলো" and carried on
— a satisfied report about a set that never contained the target.

Same family as several of tonight's: what is never considered leaves no trace in
the output. The lesson was already built into `mvrp-src.sh`, which counts the
source tree before reporting a zero; it was not built into the pull.

Fixed in two parts. The pattern now covers the remaining in-scope developers —
`com.google.ai.`, `com.android.developers.`, `com.redhotlabs.`, `com.google.fpl.`,
`com.google.looker`, `com.google.play.billing.samples`, `com.google.audio.hearing`
— verified to match seven of a nine-package test list while correctly rejecting
two unrelated apps. And the run now prints how many installed packages were
seen, how many matched and how many were dropped, with `SHOW_SKIPPED=1` listing
the Google-adjacent ones, so a missing target is visible rather than silent.

Passing package names as arguments bypasses the filter entirely, which is the
immediate route for any new target.

### 2026-10-21 — S54 AI Edge Gallery closed; the strongest remaining bet did not hold

The one target among the fifteen untouched packages that could have been worth
Tier 2 money. Pulled (after fixing defect 18), decoded, decompiled, swept.

Static sweep: zero on all four rewarded classes, five controls POSITIVE first.
FileProvider is tight — `<cache-path path="images/">` only, no root-path export.

| S54 | gallery `MainActivity` deeplink | DROP | `MainActivity` is exported with a `com.google.ai.edge.gallery` scheme filter, and reads its deeplink from `getStringExtra("deeplink")` rather than `getData()`. That rules out the browser path — a web page sets data, not extras — so this is scenario 3, not the $18,750 scenario 2. An `http://`/`https://` value is handed to `startActivity(ACTION_VIEW, uri)`, which gains an attacker nothing since any app can open a URL itself. Anything else goes to `intent.setData()` and is consumed in `GalleryNavGraphKt`, where the model is resolved by `getModelByName(lastPathSegment)` against the allowlist — no URL and no path can be supplied — and the `query` parameter is `Uri.encode`d before being placed in the route. What an attacker gets is Gallery opened at an already-downloaded model's chat screen with a prefilled prompt, run by a local model. No data leaves, no code runs, no boundary is crossed. |

| | gallery `BootReceiver` | DROP | Exported without permission, but checks the action and only reschedules notifications. |

My main hypothesis for this app — that a deeplink could choose which model file
gets loaded — was simply wrong. `importModel` is reached only from an
`ActivityResult` carrying the user's own file-picker Uri, which an outside app
cannot supply.

One thing left standing, recorded but not submitted:
`androidx.compose.ui.tooling.PreviewActivity` is exported in **both**
GnssLogger and AI Edge Gallery. Two apps from two different in-scope developers
shipping Compose's developer tooling activity in a release build is a pattern
rather than an accident. It takes a `composable` string extra and reflectively
invokes that composable. Impact is weak on its own — it renders app UI, it does
not read data or run attacker code — so by §2 it does not clear the bar unless
a specific composable can be shown to expose something. That is the one cheap,
concrete test left on this path.

### Standing back: 54 surfaces, 18 tool defects, zero reports

Every rewarded class in Mobile VRP has now been swept across 37 apps with
fixture-bound patterns and five controls: intent redirection, zip traversal,
dex-from-archive and mutable PendingIntent. The mature apps hold at five
layers, and the small apps from the untouched developers have almost no
attack surface to hold.

The honest read is that the tooling is now good and the target is wrong. This
is a crowding problem, not a capability one.

### 2026-10-21 — PreviewActivity: reachable, inert. Mobile VRP path closed for now.

    adb shell am start -n com.google.ai.edge.gallery/androidx.compose.ui.tooling.PreviewActivity \
      -a androidx.compose.ui.tooling.PREVIEW_ACTIVITY
    Starting: Intent { act=... cmp=com.google.ai.edge.gallery/androidx.compose.ui.tooling.PreviewActivity }
    topResumedActivity=ActivityRecord{... com.android.chrome/...Main ...}

No `Permission Denial`, so the activity **is** externally launchable from a
permissionless app — that part is confirmed. But without a `composable` extra it
finishes immediately and the previous app returns to the front, so nothing was
rendered and nothing was proven beyond reachability.

Turning it into a finding would need a fully-qualified composable name that
renders something sensitive. In an obfuscated release build those names are
mangled into `ComposableSingletons$...` forms, and the ceiling even on success
is Tier 3 "other", $675, with a strong chance of a low/informational close.
Reachability without demonstrated impact is a precondition, which is exactly the
shape CLAUDE.md §2.6 exists to stop me submitting. Dropped.

The HuggingFace token lives in a DataStore proto (`AccessTokenData`,
`DefaultDataStoreRepository.saveAccessTokenData`) in the app's private
directory. `allowBackup` is on, but extracting it needs USB debugging and user
consent, which the kill list rules out as unreasonable user interaction.

**Session close.** 54 surfaces across 37 apps, 18 tool defects found and fixed,
zero reports submitted. Every rewarded Mobile VRP class now has a fixture-bound
pattern with controls that abort the run on failure, so this pipeline is worth
re-running whenever a new in-scope app ships — it is an hour's work now.

The conclusion is about targets, not capability. Mature Google apps hold at
five layers because hundreds of hunters have swept them for years; the small
apps from the untouched developers have almost no attack surface to hold. Both
ends return zero for opposite reasons.

Recommendation recorded for the operator: the expected value of further Mobile
VRP time is low, and `business/fb-business-audit/` — built, never started — is
the better use of the next session.

### 2026-10-21 — defect 19, and the first control that caught one *before* a conclusion

The orphaned-permission sweep aborted on its own second control: 2,025
permissions read from the device, but `android.permission.INTERNET` did not
come back as defined.

The cause was a hand-counted offset. `+ permission:` is exactly 13 characters,
so `substr($0,13)` begins at the colon and every parsed name carried a leading
`:`. Every permission on the device would then have read as ORPHANED — a sweep
reporting that *everything* is vulnerable, which is the most dangerous kind of
wrong answer this tool could produce.

Nineteenth defect, and the magic-number family. But the important part is what
did not happen: no list was printed, no candidate was investigated, no claim
was made. Every previous defect tonight was found by reading output that had
already been presented as a result — this one died before the result existed.
That is what the controls were for.

Fixed by removing the offsets entirely (`sub(/^.*permission:/,"",p)`), adding
`protectionLevel` parsing the same way, and taking definedness from the union of
two independent sources — `pm list permissions -f` and plain
`pm list permissions` — so one parser breaking cannot silently decide the
answer. Controls now check two known permissions rather than one, and print the
first parsed names when they fail, so the next breakage is diagnosable from the
output alone.

Parser verified against sample `pm list permissions -f` output: three names,
their defining packages and their protection levels all come back clean.

### 2026-10-21 — defect 20: the right parser asking the wrong question

Second abort of the orphaned-permission sweep, on the control added after the
first one. Names parsed cleanly this time, but `android.permission.CAMERA` was
absent from the device listing — and it is a platform permission, always
defined.

The cause was not parsing. Without `-g`, `pm list permissions` omits every
permission that belongs to a group, which is every dangerous runtime permission:
CAMERA, CONTACTS, LOCATION and the rest. The listing showed
`CAMERA_SEND_SYSTEM_EVENTS` and `MANAGE_CAMERA`, both ungrouped, while `CAMERA`
itself was invisible.

Consequence, had it passed: any component guarded by a grouped permission would
have been reported ORPHANED. A different mistake from defect 19 with the same
shape of damage — a sweep claiming vulnerability everywhere.

Fixed by sourcing from `pm list permissions -g -f`, resetting the current
permission when a `group:` block starts so the group's own `package:` line does
not pair with the previous entry, and taking definedness from the names alone
rather than from the existence of a `package:` line, unioned across three
independent listings.

The control set now checks one ungrouped permission and three grouped ones
(`INTERNET`, `CAMERA`, `READ_CONTACTS`, `ACCESS_FINE_LOCATION`). With only
`INTERNET`, as in the first version, this run would have passed and every
grouped permission would have been counted orphaned.

Parser verified against a `-g -f` sample: both the grouped and the ungrouped
permission come back with their defining package, and the `permission-group:`
line is not mistaken for a permission.

Two aborts, two real defects, no false result published either time. That is
the control set doing exactly the job the previous eighteen defects argued for.

### 2026-10-21 — the orphaned-permission sweep ran: 515 guards, 16 orphans

First clean run after two control aborts. The ratio is itself a sanity signal —
"16 of 515" is the shape of a real result, where "all of them" would have been
the shape of defects 19 and 20.

The orphans fall into two groups with different causes:

**Vendor namespace, definer not installed on this device.**
`com.google.android.apps.nexuslauncher.permission.QSB` is defined by the Pixel
Launcher, absent from a Motorola phone. Same for
`com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER`,
`com.google.android.flipendo.SAVER_STATE_UPDATE` and
`com.android.systemui.permission.SEND_ALERT_BROADCASTS`.

**Platform namespace, newer than this OS.**
`android.permission.BIND_APP_FUNCTION_SERVICE` arrives in API 36; the device is
API 35. Likewise `BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE` and
`BIND_INTRUSION_DETECTION_EVENT_TRANSPORT_SERVICE`.

Two candidates stand out, both guarding Tier 1 components (ACE $15,000 /
theft $9,000):

| L1 | `QSB` → AGSA | LEAD | Guards four `com.google.android.googlequicksearchbox` components, including `...smartspace.trampolineactivity.ExportedSmartspaceTrampolineActivity`. A trampoline activity is the intent-redirection shape I failed to find anywhere in 37 apps, and here the guard on it does not exist on any non-Pixel device. |
| L2 | `BIND_APP_FUNCTION_SERVICE` → GMS | LEAD | Guards `com.google.android.gms.appfunctions.GmsAppFunctionService`, plus the same service in Wellbeing and Maestro. AppFunctions is the API through which apps expose callable functions to the system assistant. |

Still a precondition, and the step that decides it is whether the permission can
actually be claimed — the exact point where the Wiz subdomain report died, with
claimability assumed rather than demonstrated.

Built as an experiment that separates hypotheses rather than confirming one:
`AndroidManifest.orphan.xml` declares all seven orphans at `protectionLevel`
`normal` and requests all seven, so a single install shows whether Android lets
an app define names in the `android.permission.*` namespace, in a vendor
namespace, in both, or in neither. The permissionless manifest is left
untouched, since it is the instrument for a different claim; `build.sh` now
takes a `MANIFEST` override.

### 2026-10-21 — step 1 PROVEN: orphaned permissions can be claimed and are granted

Not assumed. Measured:

    declared permissions:
      com.google.android.apps.nexuslauncher.permission.QSB: prot=normal
      android.permission.BIND_APP_FUNCTION_SERVICE: prot=normal
      ...
    install permissions:
      android.permission.BIND_APP_FUNCTION_SERVICE: granted=true
      com.google.android.apps.nexuslauncher.permission.QSB: granted=true
      com.android.systemui.permission.SEND_ALERT_BROADCASTS: granted=true
      android.permission.BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE: granted=true
      android.permission.BIND_INTRUSION_DETECTION_EVENT_TRANSPORT_SERVICE: granted=true
      com.google.android.flipendo.SAVER_STATE_UPDATE: granted=true
      com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER: granted=true

An ordinary third-party APK, signed with a self-made key, defines all seven
orphaned permissions at `protectionLevel="normal"` and is granted all seven at
install. Android did not reserve the `android.permission.*` namespace against a
third-party definer when the platform itself does not define the name.

The experiment was built to separate hypotheses — vendor namespace versus
platform namespace — and the answer came back "both", which is the stronger of
the two outcomes I had framed.

This is the step the Wiz subdomain report assumed and lost on. Here it is
demonstrated before anything is claimed.

**Step 2 is not yet done, and the first attempt measured nothing.** The probe's
`start` action calls `startService()`, but the AGSA target
`ExportedSmartspaceTrampolineActivity` is an activity, so
`startService() returned null` means "I knocked on the wrong door", not "the
door is shut". Added a `startact` action that calls `startActivity()` and
catches `SecurityException` separately, since that exception is the signature of
a permission boundary and the thing the control build has to differ on.

The GMS attempt returned `bindService() returned false`, which is also not yet
a result: the reason is logged by ActivityManager, not under the probe's own
tag, so the next run has to read unfiltered logcat.

**The control is mandatory before any claim.** A successful reach proves nothing
about the permission unless the same reach fails without it. `PKG=` rename
builds a second, permissionless copy (`com.cindrasec.mvrpctl`) so both can be
installed side by side and the same two attempts run under each. The finding, if
there is one, is the difference — not the success.

### 2026-10-21 — step 2 PROVEN: the differential, with Android naming the reason

Two APKs built from identical source. The only difference is that one declares
`com.google.android.apps.nexuslauncher.permission.QSB` at `protectionLevel`
`normal` and requests it; the other declares nothing. Both call
`startActivity()` on the same component with the same intent.

**With the claimed permission** (`com.cindrasec.mvrpprobe`, uid 10568):

    I MVRP: startActivity() returned, no exception

**Without it** (`com.cindrasec.mvrpctl`, uid 10569):

    W ActivityTaskManager: Permission Denial: starting Intent {
      cmp=com.google.android.googlequicksearchbox/com.google.android.apps.search.assistant
          .verticals.ambient.smartspace.trampolineactivity.ExportedSmartspaceTrampolineActivity }
      from ProcessRecord{... com.cindrasec.mvrpctl/u0a569} (pid=6127, uid=10569)
      requires com.google.android.apps.nexuslauncher.permission.QSB
    I MVRP: SECURITY Permission Denial: ... requires com.google.android.apps.nexuslauncher.permission.QSB

The system names the permission as the reason for the denial, and the only
variable between the two runs is whether that permission was claimed. This is
the cleanest control result of the session: not "it worked", but "it worked
here and failed there, for the stated reason".

So two of the three steps are demonstrated rather than assumed:

1. An ordinary third-party app can define an orphaned permission and is granted
   it at install — shown in `install permissions: granted=true`.
2. A Tier 1 component that Google restricts to the Pixel Launcher is reachable
   with it and refused without it — shown in the differential above.

**Step 3 is not done, and nothing is claimable until it is.** `topResumedActivity`
remained the launcher in *both* runs, so the activity did not come to the front
even when the start was accepted — consistent with a trampoline that forwards
and finishes, or with an early exit on missing extras. What the attacker
actually gets is still unknown.

What exists right now is an access-control bypass on a restriction that does not
exist on any non-Pixel device. By CLAUDE.md §2.6 that is a precondition, which
is exactly the shape that killed G-F002, the Wiz report and S43. The next step
is reading `ExportedSmartspaceTrampolineActivity` to find what it forwards and
whether any of it is attacker-controlled.

### 2026-10-21 — S55: AGSA re-verifies the permission's owner at runtime

Step 3 answered, and the answer closes this target. The activity is a Hilt
shell; the logic lives in its peer, `defpackage.cenk`:

    getPackageInfo("com.google.android.apps.nexuslauncher", 4096)
    ...
    if (permissionInfoArr[i].name.equals("com.google.android.apps.nexuslauncher.permission.QSB")) {
        if (ai != null && (ai.flags & 129) != 0 && this.d.b(pkgInfo.packageName)) { ...proceed... }
    }
    ...
    "#onAccountChanged: QSB permission is not trusted."
    this.b.finish();

AGSA does not trust the permission it is guarded by. At runtime it asks whether
`com.google.android.apps.nexuslauncher` is installed, whether that package is
the one declaring `QSB`, whether it is a system app (`flags & 129` =
`FLAG_SYSTEM | FLAG_UPDATED_SYSTEM_APP`) and whether it passes `this.d.b(...)`.
On a Motorola device the package is absent, `getPackageInfo` throws
`NameNotFoundException`, and control falls straight through to `finish()`.

So the bypass opens the door and AGSA shuts it in the same breath — which is
exactly why `topResumedActivity` stayed on the launcher in both runs. The
observation that looked like a flat result was the defence working.

`fvmq.b()`, the overridden `startActivity` hook, is not a guard: it only acts
when `intent.getPackage()` equals the app's own package.

Worth saying plainly: they anticipated this attack and defended against the
precise thing I demonstrated. The permission check in the manifest is the
advertised boundary; the real one is a runtime check that the permission's
declared owner is an installed, system, Google-signed package.

**S55 closed. The method is not.** Steps 1 and 2 remain proven, and fifteen
other guarded components share the same orphaned-permission weakness — three
more behind `QSB` alone (two activity-aliases and `OneSearchSuggestService`),
two in GMS, plus Wellbeing, turbo, wallpaper and Messages. Whether each has
AGSA's second layer is an empirical question, not an assumption.

Built `mvrp-orphan-test.sh` to answer it in one run: it parses the orphan
report and, for every guarded component, attempts to reach it twice — once from
the permissioned build, once from the permissionless one — and prints the pair.
Only a difference counts; a success in both means the component was open
anyway, and a failure in both means something other than the permission is
holding. A control aborts the run unless the two APKs actually differ in
granted permissions. `broadcast` added to the probe, since six of the targets
are receivers that neither `startact` nor `bind` can touch.

### 2026-10-21 — defect 21, and an explanation I could not reproduce

`mvrp-orphan-test.sh` reported `com.cindrasec.mvrpprobe` not installed
immediately after `adb install` printed `Success` for it.

My first explanation was the `pipefail` + `grep -q` SIGPIPE race — `grep -q`
exits at the first match, the upstream command takes SIGPIPE, and `pipefail`
reports the whole pipeline as failed, so a *successful* match takes the error
branch. That exact bug was fixed earlier tonight in the `android.jar` check,
and I wrote it again in a new script, having fixed the instance instead of the
class.

**But I could not reproduce it.** Five runs with the same construct, including
one with a 200,000-line producer, all matched correctly. So the explanation
fits the symptom and matches a known prior failure, and is still only a
hypothesis — `adb shell` is a much slower producer than `seq`, which changes
the race window, but that is reasoning, not evidence.

Fixed by removing the pipeline entirely (here-string), which eliminates the
class whatever the cause was. More importantly, the failure branch no longer
just asserts: it prints how many lines the package list actually contained, any
`cindrasec` lines in it, and the `pm path` command to check directly. If this
recurs, the next run says why instead of leaving me to theorise.

Recording the honest state: diagnosis unconfirmed, fix sound, diagnostics added
so the next occurrence is self-explaining.

### 2026-10-21 — the orphan differential, and a correction to my own table

The batch run produced nine differentials across five apps and three
permissions. But the labels overstated what happened, and I corrected it before
building on it.

**Defect 23 — a weak fact given a strong name.** The classifier printed `BOUND`
for `bindService() returned true`. That return value means only that the system
*accepted the bind request*; it says nothing about the service responding.
Actual connection is `onServiceConnected`, which the probe logs separately. Of
the five services the table called `BOUND`, exactly one logged a real
connection: `OneSearchSuggestService`, whose interface descriptor came back
**empty** — a raw `Binder`, not an AIDL stub.

Same family as defects 11 and 14: naming the ingredients instead of the thing.
Relabelled to `GATE_OK` (request accepted) versus `CONNECTED` (service
answered), bound by four fixtures.

A second cause is also plausible and was not controlled for: the probe finished
after a fixed 4 seconds, so a service connecting more slowly could not be
distinguished from one never connecting. Added a `hold` extra and made the test
wait longer than the probe lives.

**What survives the correction, stated precisely.** Without the claimed
permission the system refuses the bind outright with `Permission Denial`; with
it, the request is accepted. That differential is real and reproducible across:

| service | app | permission |
|---|---|---|
| `MemoryAppFunctionService` | Find My Device (`apps.adm`) | `BIND_APP_FUNCTION_SERVICE` |
| `BugleAlternativeMessageTransportService` | Google Messages | `BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE` |
| `WellbeingAppFunctionService` | Digital Wellbeing | `BIND_APP_FUNCTION_SERVICE` |
| `MaestroAppFunctionService` | Pixel Buds | `BIND_APP_FUNCTION_SERVICE` |
| `IntrusionDetectionEventTransportService` | GMS (Tier 1) | `BIND_INTRUSION_DETECTION_EVENT_TRANSPORT_SERVICE` |
| `OneSearchSuggestService` | AGSA (Tier 1) | `nexuslauncher.permission.QSB` |

All three `android.permission.BIND_*` names arrive in API 36 and do not exist on
this API 35 device, which is why the hypothesis held here and not for AGSA's
activity: those developers could rely on the framework to enforce the guard, so
they had less reason to write AGSA's own runtime owner-check — and the framework
does not know the name.

Still a precondition. Passing the gate is not a crossing, and "I could bind" is
the report shape dropped three times tonight.

Also worth noting as its own class, defect 22: `set -- $t` returned empty
because zsh does not word-split unquoted expansions, so four of five binds ran
with no class argument. The scripts carry `#!/usr/bin/env bash` and are
unaffected; it is loops typed straight at the user's prompt that break. The
empty `==` lines made it visible immediately, which is the only reason it was
caught in one round.

### 2026-10-21 — S56: the gRPC transport is first-party only. Orphan path closed on AGSA.

Followed the chain to the bottom. `OneSearchSuggestService.onBind` returns
`G().a.b()`, a grpc-binder server. The per-service `SecurityPolicy` is the map
value in `cret` — `gitv.b(context, executor)` → `gitr` → `gitp.a(uid)`:

    public final Status a(int i) {
        if (this.a.c(i)) return Status.OK;
        return Status.h.withDescription("Rejected by (1st-party only) security policy");
    }

with `dcxf.c(uid)` resolving the uid to its packages and checking each for
first-party signing. A self-signed app holds the binder and is refused on every
call.

Six layers in total: manifest permission, bind, binder, the gRPC server's
per-service policy, uid-to-package resolution, signature. The orphaned
permission defeats the first.

Three readings along the way were wrong before the code corrected them, which is
worth recording because all three were name-based guesses: `fvmq.b` looked like
a guard and is instrumentation, `haux` looked like the policy and is server
options, and `gitv.b` looked like the service implementation and is the policy.
Reading one more class each time was cheap; assuming would have produced a false
report in either direction.

**Session totals: 56 surfaces, 23 tool defects fixed, zero reports submitted.**

The orphaned-permission work is the furthest this effort has got: steps 1 and 2
measured with controls, step 3 blocked by a layer below the manifest every time.
Written up in `results/google/ORPHAN-PERMISSION.md` so the next session resumes
at step 3 rather than at zero.

### 2026-10-21 — update-driven hunt begins; defect 24 found on the first run

14 of 66 packages updated since yesterday, including Docs, Messages, Translate,
Wellbeing, Safety Hub, Health Connect, clouddpc and `debugdispatch`
(1.0.1 → 1.1.0). `stale` decided that without pulling anything, by comparing the
stored manifests' `versionName` against the device.

The first `diff` run printed `comm: file 1 is not in sorted order` and then
produced a result anyway. `comm` expects the locale's collation order; the
Python extractor sorts by code point. The orders disagree, so the comparison was
meaningless — and `comm` warned rather than failing, so a wrong answer was
printed next to a `POSITIVE` control line. **"New exported components: 2" cannot
be trusted.**

A species not on yesterday's list: the tool emitted a warning and carried on. A
warning that does not stop the run is a result that looks clean.

Fixed by forcing `LC_ALL=C` on both sorts and on `comm`, and by capturing
`comm`'s stderr — any complaint now drops that package from the report with a
note, instead of letting a corrupt comparison through. Verified on a fixture
pair where the unfixed version both warned and mis-ordered its output.

Rationale for the whole approach, carried over from yesterday's conclusion:
56 surfaces closed because of crowding rather than capability, and a fresh
release lifts that crowd for a few days. Looking only at what changed is the
one place where arriving first is still possible.

### 2026-10-21 — defect 25: the instrument changed what it measures

Today's orphan sweep reported 3 orphans where yesterday's reported 16, and the
drop was my own doing. The probe app is still installed and *declares* all seven
orphaned permissions at `protectionLevel="normal"` — that declaration is the
experiment. So `pm list permissions` now reports them as defined, by the
attacker.

The most deceptive species yet: the new reading looks like the problem went
away, and without noticing I would have written "16 down to 3, Google fixed it".

Fixed by subtracting permissions whose *only* definer matches the probe's
package prefix, with a `NOTE` line in the controls saying how many were
excluded and where the list is. Verified on a fixture: a probe-only permission
is dropped, while a platform permission and one co-defined by GMS are kept.

### 2026-10-21 — a real manifest error in Google Home

Of the three orphans that survive the correction, one is not a
device-configuration artifact but a bug in the app's own manifest:

    *** ORPHANED  android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN
        guarding: [receiver] com.google.android.apps.chromecast.app
                             .remotecontrol.safety.LockProximityReceiver

`android:permission` takes exactly one permission name. The developer wrote two
separated by `|`, apparently intending "either of these". Android reads the
whole string as a single permission name, and no such permission exists — so the
receiver is guarded by a lock whose key was never minted.

Unlike the Pixel-Launcher and API-36 orphans, this does not depend on which
device or OS version is running: it is a manifest error that ships to every
install of Google Home.

The package path is `remotecontrol.safety` and the class is `LockProximityReceiver`,
which points at smart-lock proximity handling. Whether an attacker gains
anything is the usual third question and is not yet answered — yesterday's
differential showed this receiver as ACCEPTED both with and without the
permission, but `sendBroadcast` does not throw and a denial may be logged
outside the capture window, so that measurement is weak for receivers and needs
redoing.

### 2026-10-21 — G-F003: the first demonstrated boundary crossing in this effort

Google Home guards `LockProximityReceiver` with
`android:permission="android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN"`.
The attribute takes one name; two were written joined by a pipe. Android reads
the whole string as one permission name that nothing defines, so the guard fails
closed for every legitimate caller — and opens exclusively for any app that
declares that name itself, which yesterday's work proved is granted at install.

With a control, measured not assumed:

    attacker build: W HomeApp|LockProximityNotificationWorker: Device not found   (pid 6860 = Google Home)
    control build:  nothing

Identical source, identical intent; the permission declaration is the only
variable. Broadcasts fail silently, so the control's *absence* of Google Home's
own log line is the measurement.

This is not a precondition. An app holding no real permissions caused code to run
inside Google Home with its own data, and Google's log says so.

Reading the chain further: the worker resolves the attacker's `hgs_device_id`
against the victim's account, and for a device with a lock trait posts an unlock
notification carrying attacker-chosen `request_id` and `manufacturer_data`, whose
tap target enqueues `LockProximityUnlockWorker` — whose whole body is the unlock
call. `LockProximityUnlockActivity` is not exported, so the unlock needs the
user's tap; that caps the severity and rules out claiming a no-interaction
unlock.

Our canary id returned "Device not found": the server rejected an id not on the
account. So the notification and the unlock are **read, not performed**, and the
report must say exactly that.

Written up as `results/google/findings/G-F003-home-lockproximity.md` with the
verbatim logs, the decompiled chain, repro steps and remediation.

**The open question that decides severity:** whether an attacker can obtain a
valid `hgs_device_id` for a victim's lock. Also noted but untested: a valid and
an invalid id take visibly different paths, which makes the receiver a candidate
id oracle.

### 2026-10-21 — the weak-normal class: two candidates, both closed

Classifying all 517 guards by protection level found 3 at `normal` (anyone gets
them by asking) and 9 at `dangerous` (a consent prompt). Two of the three were
worth reading; both closed.

| | | |
|---|---|---|
| carrierwifi `CarrierWifiTestReceiver` | DROP | A test receiver shipped in release, guarded only by `android.permission.CHANGE_WIFI_STATE` (normal). It reads no extras: two fixed actions, `ACCM_DOWNLOAD_LATEST` → `AccmDownloadWorker` and `GWP_DUMP` → `GwpDumpWorker`. The dump target is `getDir("gwp_persistent_logs", 0)`, i.e. MODE_PRIVATE, and S49 already established that reading it through `GwpDebugContentProvider.dump()` needs signature-level `DUMP`. An attacker can force a server config fetch and a private-directory log write, and gains nothing from either. |
| searchlite `ThirdPartyWidgetBroadcastReceiver` | DROP | The better-looking of the two, and the name was the whole of it. |

The searchlite one deserves its own note because the surrounding facts are real
and only the payoff is not. Confirmed from the device, not from my parser:

    + permission:com.google.android.finsky.permission.DSE
        package:com.android.vending
        protectionLevel:normal

Play Store defines the Default Search Engine permission at `normal`, so any app
is granted it silently at install. Google Go uses that permission as the sole
guard on an exported receiver for `UPDATE_DSE` / `UPDATE_DSE_APP_STATE`, the
channel carrying the DMA choice-screen result.

But the handler reads one boolean:

    boolean isInstall = intent.getBooleanExtra("is_install", true);
    ComponentName cn = new ComponentName(context, "...SearchLiteWidgetProvider");
    b(cn, isInstall ? 1 : 2);   // enable / disable the widget provider

The effect is toggling Google Go's own widget component. No search engine
changes, no data moves, no code runs. CLAUDE.md §2's question answers to
nothing, and the kill list rules out availability-only impact.

Third time today that a promising name did not survive its code —
`/send-zip`, `LockProximity`'s notification path, and now `UPDATE_DSE`. Worth
keeping as a habit rather than a complaint: the name decides what to read next,
never what to claim.

Still unexamined: the 9 `dangerous`-level guards. A consent prompt is a real
obstacle, but a malicious app can ask for one under an ordinary pretext, so the
class is not dead.

### 2026-10-21 — remaining classes closed; G-F003 drafted for submission

`trr.dr()` turned out to build a PendingIntent back to `LockProximityReceiver`
itself — the app registering its own BLE scan callback. An attacker can make
Google Home start a scan, which costs battery and nothing else, and the device
id stays unresolvable. It does not improve G-F003.

The 9 `dangerous`-level guards are closed too: eight are `CALL_PHONE` on Meet's
call activity-aliases, and an app holding `CALL_PHONE` can already place calls
directly, so routing one through Meet is not an escalation. The ninth is
`READ_CONTACTS` on `com.android.exchange.provider.ExchangeDirectoryProvider`,
which is AOSP and kill-listed to the Android and Google Devices SRP.

`finsky.permission.DSE` appears in only one other manifest, AGSA's, and there
only as `<uses-permission>` — AGSA requests it, guards nothing with it.

`debugdispatch` (1.0.1 → 1.1.0, 18,760 java files): all four classes clean, with
the two intent-redirection hits in non-exported components and the dex hit in
`androidx/profileinstaller`.

So every class is now swept across this corpus and one finding survives.

Drafted `results/google/findings/G-F003-SUBMISSION.md` against
`REPORTING-STANDARDS.md`, which exists because M018 was closed as Spam for
reading as polished AI prose with no raw evidence. The draft is first person,
leads with researcher metadata and the device, pastes both runs' verbatim
logcat, and states plainly what was *not* done: no notification was posted and
nothing was unlocked, because the account has no smart lock and the id check is
server side.

Two items left before sending: a terminal screenshot and the exact installed
version string. No CVSS argued upward, and no describing the unlock as
performed.

### 2026-10-21 — defect 26, the worst one, and the finding that survived it

G-F003's evidence was a single observation: Google Home's notification worker
logged 0.77s after the attacker app's broadcast and not after the control's. I
wrote a submission draft on it and told the operator we had a valid bug.

It never reproduced. Google Home does periodic BLE work of its own, and that
line was almost certainly coincidence. A control that runs **once** cannot
separate an effect from background activity — having a control is not the same
as having enough of one.

This is the same error the previous twenty-five defects all taught, made on the
one result I wanted to be true. It was caught before sending, which is the only
thing that makes it recoverable: a report closed as "cannot reproduce" would
have cost more platform signal than the Spam close did.

`mvrp-ble-diff.sh` is the fix: N alternating rounds of attacker, control, and a
**send-nothing baseline**, counting what the target logs in each window. The
baseline is the piece that was missing — if the target writes on its own, it
shows up in all three columns.

Under it, with Bluetooth on, in two independent sessions twenty minutes apart:

    with permission : 5/5 and 5/5
    without         : 0/5 and 0/5
    nothing sent    : 0/5 and 0/5

Thirty windows, ten responses, every one in the column where the permission was
declared. The observable is `BluetoothAdapter: isLeEnabled(): ON` from Google
Home's PID, which is the `trr.ds()` check at the top of `onReceive` — it appears
only when the receiver actually runs.

With Bluetooth off, all three columns read zero, including the attacker's. That
is inconclusive rather than negative: with Bluetooth off the adapter is never
touched, so the observable disappears along with the branch. The worker's own
`Device not found` did not appear either, so the `LIST_SCAN_RESULT` branch is
genuinely not being reached — why, is unresolved, and chasing it would be more
guessing.

**So the finding survives, smaller and solid.** The claim is now exactly what
ten rounds support: the guard is void, an unprivileged app reaches the receiver,
Google Home executes `onReceive`, and an identical app without the declaration
does not. The notification and unlock chain is in the report as code read, with
a sentence saying plainly that I did not reach it.

`G-F003-SUBMISSION.md` rewritten at that claim level. One item outstanding: a
screenshot of a full `mvrp-ble-diff.sh` run.

### 2026-10-21 — defect 27, and the reason the chain stalls

I wrote that the `LIST_SCAN_RESULT` branch never runs because
`"Found %d device"` never appeared. That line is written through
`c.e()`, a low level of Google's logger which release builds suppress; the
worker line that did appear once came through `a.g()` and reached logcat as W.
So the missing line proves nothing. Absence read as evidence, for the third
time today.

Replaced the log with two log-independent observables. `mvrp-work-diff.sh`
watches the target's JobScheduler entries across the same three branches, since
a WorkManager enqueue lands there whatever the logger does. Result over three
rounds: 49 entries before and after, in all three columns. The app already has
five `androidx.work.systemjobscheduler` jobs, so a new enqueue would have shown.

Putting that together with what does not happen:

- The receiver runs — 15/15 on the Bluetooth check.
- `hgs_device_id` is readable inside it, because the next line is
  `stringExtra.getClass()` and a null would NPE and crash the receiver. No crash
  appears, so the extras Bundle arrived intact.
- No worker is enqueued, and no job appears.

That isolates the failure to the one condition in between:
`intent.getParcelableArrayListExtra(...) != null`. Android unparcels extras
lazily per key, so a `ScanResult` the target cannot reconstruct makes that call
return **null with no exception and no log** — which is exactly the silence
observed.

The `ScanResult` was built as `new ScanResult(dev, null, -50, 0L)`, with a null
`ScanRecord`, because `ScanRecord` has no public constructor and
`parseFromBytes` is hidden.

Fixed by writing the Parcel by hand in the order `ScanResult.writeToParcel`
uses and calling `CREATOR.createFromParcel`, which yields a real object with a
real `ScanRecord`. The advertisement bytes carry company id 76 (`0x004C`)
deliberately, because the receiver reads exactly that:
`manufacturerSpecificData.get(76)` feeding `jfl.j("manufacturer_data", ...)`.

The builder logs whether the object came back with a scan record and whether
company 76 is present, and returns null loudly if the field order does not match
this OS version, so a failure there cannot masquerade as a quiet negative.

### 2026-10-21 — the evidence that ends the argument, from ActivityManager

Every instrument I had tried measured what Google Home chose to log, and three
times I read a silence as a negative. `dumpsys activity broadcasts` measures
what the *system* did, and it settles the question in one command.

Attacker app:

    BroadcastRecord{...BLE_SCANNED/u0} to user 0
    caller=com.cindrasec.mvrpprobe ... uid=10568
    DELIVERED scheduled +2ms terminal +8ms (-1) #0: (manifest)
      name=...LockProximityReceiver   exported=true
      permission=android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN

Control app, same intent, same target:

    caller=com.cindrasec.mvrpctl ... uid=10569
    SKIPPED
      reason: skipped by policy at enqueue: Permission Denial: broadcasting Intent {...}
      from com.cindrasec.mvrpctl (pid=24061, uid=10569)
      to ...LockProximityReceiver
      requires android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN

The system names the rule, names the malformed permission, and records both
outcomes side by side in one dump. `terminal +8ms` also settles a separate
question: the receiver did not merely receive, it ran to completion — and the
Bluetooth-off record shows `DELIVERED` too, so the earlier all-zero run was the
observable disappearing, not the delivery failing.

This is better evidence than anything built from logcat. It does not depend on
the app's logging levels, on Bluetooth state, on timing windows, or on my
instrument at all. A triager reproduces it with one command.

Two things that cost hours and are worth keeping:

The hand-written `ScanResult` parcel was wrong on Android 15 — it decoded
`rssi=5046021`, which is `0x004CFF05`, exactly the advertisement bytes, so the
reader had consumed an extra field. Letting `BluetoothDevice.writeToParcel`
write its own portion and validating the decode against `rssi == -50` fixed it
at `pad=0` on the first try. The checksum is what made that safe: a misaligned
layout cannot return the sentinel by chance.

And the broadcast history explains the whole afternoon. The receiver was
running every time; it simply logs nothing on the path it takes. Five separate
observables — worker log, `Found` log, `isLeEnabled` log, JobScheduler, network
counters — were all downstream of someone else's choices. The one that worked
was upstream of all of them.

The report is rewritten around these two records. The notification and unlock
chain stays as code read, with the sentence saying I did not reach it.

### 2026-10-21 — corrected twice, in opposite directions, on the same sentence

The report first said the feature must be broken in production, since nothing
can hold the malformed permission. Looking at screenshots of the broadcast
history I saw `BLE_SCANNED` records every few minutes and corrected it to the
opposite: the app's own deliveries are fine, only outsiders are stopped.

Both were wrong, and `mvrp-bcast.sh` showed why. Every record carrying a
`caller=` line is one of my two test apps, and every dense cluster of
timestamps in those screenshots — 19:08, 19:11, 19:14, 19:18, 19:22, 19:26,
19:33, 19:48, 19:55, 20:02, 20:07, 20:11 — matches a run of my own tooling.
`mvrp-ble-diff.sh` alone sends three broadcasts per round.

So there is no evidence either way. The test account has no smart lock, so a
legitimate delivery was never expected in this window. The code says the app
registers its scan callback as a `PendingIntent`, which would be dispatched
under its own identity, but that is reasoning and not a measurement.

Both claims are now out of the report, replaced by a sentence saying explicitly
that the question was not tested. The finding does not need it: the guard
refusing ordinary apps and not refusing one that declares the name is the whole
claim, and that part is in Android's own records.

Worth naming the pattern, since it is the second time today: I reached for an
explanation of someone else's system from data that was entirely a product of
my own activity. The first was the worker log at 17:44. Both times the fix was
to ask who generated the data before interpreting it.

### 2026-10-21 — a second component, and the honest scope of the typo

`FirstDockActivity` in the same app, guarded by
`com.google.android.settings.setup.dock.RUN_DOCK_SETUP`, behaves exactly like
`LockProximityReceiver`:

    probe : startActivity() returned, no exception
    ctl   : Permission Denial: ... requires com.google.android.settings.setup.dock.RUN_DOCK_SETUP

Reproduced twice, minutes apart. Two components, two different permissions, one
app, one technique. That changes the report's ask from "fix this line" to "audit
this pattern", which is more useful to whoever picks it up.

The two differ in reach, and the difference is worth stating precisely. The
malformed string cannot be held on any device or OS version, because it is not a
permission name. `RUN_DOCK_SETUP` *can* be held on a Pixel, where its defining
package exists — so that guard is void specifically on every non-Pixel device,
which is most of them.

Scope check on the typo itself: 159 distinct `android:permission` values across
66 decoded manifests, exactly one containing `|`. So it is not a widespread
typo, and the report says so rather than implying an epidemic. The orphaned-guard
pattern is the broader finding: 16 guards across the corpus that no installed
package defines.

That is the fourth claim trimmed today rather than inflated, and the pattern in
all four is the same — the temptation was always to generalise from one
observation.

### 2026-10-21 — Google Home's exported surface, walked end to end

The orphan-permission work was a side door. The surface dump showed the front
doors had never been looked at: 290 components, 8 of them exported with no
permission at all. Each one closed, and the pattern is identical every time —
the manifest is permissive and the code is not.

| | | |
|---|---|---|
| `CameraPreviewProvider` | DROP | Exported, no permission, no `grantUriPermissions`, and it builds `new File(base, uri.getPath())` with no canonical check — a traversal waiting behind the door. The door holds: both `query()` and `openFile()` call `a(getCallingPackage(), uri)`, and that method allows only `com.android.systemui`, `com.google.android.apps.wear.companion` past a signature verifier, or the app itself. `getCallingPackage()` is framework-supplied and cannot be spoofed. |
| `DeeplinkActivity` → `aarv` webview handler | DROP | `googlehome://webview?url=` requires `https` and exact membership in `{home.google.com, preview.home.google.com, assistant.google.com}`. Same shape as Fitbit's `UrlValidator`, same correctness. Noted but not pursued: `autologin=1` is attacker-settable, which would matter only given an open redirect on one of those three hosts — a different program's problem. |
| `DeeplinkActivity` → `L(sr)` redirect | DROP, with a real defect inside | Three checks on the redirect intent. Explicit package and explicit component both fall through and block. The third iterates `queryIntentActivities` and, when a result resolves to the app's own package, **only logs** — then `startActivity(a)` runs anyway. The developer wrote the check and forgot to act on it. Unreachable all the same: `L` fires on an activity result, the child is launched by `H()`, and every call to `H()` passes an intent built internally (`bwhnVar.r(intent2)` at 398, `B(...)` at 770 and 782). The attacker's own intent is an input, never the destination. |
| `SetupProxyActivity` | DROP | Takes `android.intent.extra.INTENT` straight out of its intent and launches it with no validation whatsoever — and is `android:exported="false"`. |

So Google Home contains at least two pieces of unguarded redirect logic, both
sitting behind doors that are shut. That is now the single most common shape in
this effort: S43, ProjectorActivity, `SetupProxyActivity`, `L(sr)`. Writing the
check and not returning, or writing no check and not exporting, both look the
same from outside.

Still unexamined in this app: `OAuthHandoffActivity`, `AccountLinkingActivity`
(handles `https`), `MatterSetupProxyActivity`, and the exported
notification-platform receivers. Recorded rather than guessed at.

**Decision: submit G-F003 as it stands.** Two components, two orphaned guards,
control-backed differentials, and evidence written by ActivityManager rather
than by me. Everything else examined today closed, and nothing found today
changes that report's claim either way.

### 2026-10-21 — the API-36 orphans explained, and why that sharpens G-F003

Chased the last plausible route to higher severity: the AppFunction services,
on the theory that Find My Device exposing callable functions would be worth
real money if reachable. Measured instead of assumed, and the answer is clean.

`MemoryAppFunctionService` → `idp` → `idq` → `pj`, and `pj extends
android.app.appfunctions.AppFunctionService`. Messages' transport service →
`drdd extends android.service.messaging.AlternativeMessageTransportService`.
Both base classes decompile to jadx stubs:

    static { throw new NoClassDefFoundError(); }

They are API 36 framework classes, absent on this API 35 device. So those five
services pass the bind gate — their guard permissions are genuinely orphaned —
and then cannot instantiate at all. My earlier assumption that an internal
caller check was refusing them was wrong; nothing was refusing them, they were
never able to run.

That closes the highest-value remaining lead, and it improves the report rather
than diminishing it. There are now two distinguishable kinds of orphaned guard
on this device:

- **API-36 permissions on API-36 components.** Claimable today, harmless today,
  self-resolving on the next OS upgrade. Not worth reporting, and the report now
  says so explicitly.
- **Guards that stay orphaned after any upgrade.** A typo that is not a
  permission name on any Android version, and a permission whose defining
  package is Pixel-only and will never appear on a Motorola. Both guard ordinary
  classes that run today, and one of them I have executing in ActivityManager's
  own record.

Pre-empting that objection in the report is worth more than another day of
probing: "isn't this just forward-compat noise?" is the first thing a triager
would reasonably ask, and the answer is now in the text with the evidence behind
it.

One live thread left unexplored, recorded honestly: GMS's
`IntrusionDetectionEventTransportService` did connect, so its class is present.
It returns a descriptor-less binder behind a Chimera-loaded implementation, and
speaking an unknown protocol blind is a poor bet against a Tier 1 target. Left
for a future session rather than guessed at.

**Final: submit G-F003.**

### 2026-10-21 — three things fixed before submitting

Asked whether more testing was needed. Three gaps, all about credibility rather
than discovery.

**An unverified claim in my own report.** I wrote that
`com.google.android.settings.setup.dock.RUN_DOCK_SETUP` is "defined by a
Pixel-only package" — inferred from the package name, never measured. All I
established is that *no package on this device defines it*. A triager will
likely test on a Pixel; if it resolves there, my second example does not
reproduce for them and the whole report loses trust over a sentence I had no
basis for. Rewritten to say exactly what was measured, and to note that the
first component carries the report on its own because that permission name
cannot be defined anywhere.

That is the fifth unverified assertion cut today, and the only one that was
mine rather than inherited from an instrument.

**The PoC was not clean.** `AndroidManifest.orphan.xml` declares nine
permissions — the investigation harness, built to test every orphan at once.
Shipping that invites "why nine?" as the first question and buries the point.
Added `AndroidManifest.poc.xml` with exactly the two permissions the report
demonstrates, and no real Android permission at all, so the claim that this is
what any ordinary app can do stays intact.

**No record of what was sent.** Hash and version to be captured with the build,
so there is a record of exactly which APK the report refers to.

### 2026-10-21 — the shipped PoC, verified

Built from `AndroidManifest.poc.xml` and confirmed on device:

    install permissions:
      android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN: granted=true
      com.google.android.settings.setup.dock.RUN_DOCK_SETUP: granted=true

Exactly two entries, both of them the report's subject, and no real Android
permission anywhere. That matters for the central claim: the app demonstrating
this holds no capabilities at all, so nothing it does can be attributed to
something it was granted.

sha256 of the attached PoC recorded in the report's metadata, along with the
tested Google Home version (4.33.27.4) and the testing window, so there is a
record of exactly which binary the evidence refers to.

Two small things caught while doing it, both worth noting because both would
have produced a misleading submission:

The control APK had been overwritten in `out/` by later builds — the file named
in the report did not exist. Attaching a stale or missing control would have
been worse than attaching none, since the whole argument is the comparison.

And the differential command's `head -6` was consumed by two duplicate control
records, so the probe's `DELIVERED` line never appeared. The run looked like a
failure and was a display truncation. Same shape as the morning's defects:
reading a window as the world.

### 2026-10-21 — G-F003 submitted: Issue 576322789

https://issuetracker.google.com/issues/576322789 — Mobile VRP, Permissions Bypass,
private, no planned public disclosure. Intake landed at Type Customer Issue, P4/S4,
Status New, unassigned; that is where intake puts everything, not a verdict.

What went in: the two orphaned guards in Google Home, the broadcast differential from
ActivityManager's own history, the activity denial, and the account handed to the
caller's IntentSender. Seven attachments, four of them hashed in the report body.

Three things this last stretch taught me, all of them the same lesson in different
clothes:

**Reachability is not the finding.** I measured that `FirstDockActivity` was reachable
and stopped there, and logged it as a second example of the same bypass. It took the
user asking "is there any way to raise impact" for me to read what the component
actually does once reached — and it hands over the signed-in account. The finding went
from a reachable component to a demonstrated account disclosure on the strength of one
question I had not asked.

**Claims I never measured kept surviving into the report.** A log line I had translated
into English and quoted as verbatim output. A `SECURITY` line the control app does not
print. "No preconditions", when a cold start returns null. "66 decoded manifests" when
the corpus had grown to 132. Tier 1 when Google Home is Tier 2. Each was caught by going
back and measuring, never by re-reading what I had written.

**Silent truncation looks like success.** The form's description field caps at 20,000
characters and cut the paste mid-word, dropping the reproduction steps and the
remediation. Nothing warned. It was visible only because the user sent the saved page
and I counted the characters that had actually landed.

Still open, for a later session: GMS `IntrusionDetectionEventTransportService` (connects,
Chimera-loaded binder, protocol unknown), and `business/fb-business-audit/`, never started.

### 2026-10-22 — 576322789 closed as Duplicate of canonical 1469

Seven minutes from acknowledgement to close. Nobody read the report in that
window; it was bucketed by class. Google's note on the close says 1469 is a
shared canonical used across unrelated reports, which is as much as saying the
class was already filed.

The class is "exported component in a Google app guarded by a permission nothing
defines". Spent. The 16 orphaned guards from that sweep are all presumably the
same bucket, so there is nothing left to mine there no matter how clean the
differential is.

What this changes about how to pick targets:

**Novelty of the class beats quality of the demonstration.** The evidence here
was as good as I know how to make it — the system's own records, a control APK
differing by two manifest rows, a measured precondition, four hashed artifacts.
It bought nothing, because the class was known. Time spent polishing a report in
a known class is time thrown away; the question to ask first is "has anyone
plausibly filed this shape before", not "can I prove this cleanly".

**What was probably novel got bucketed with the rest.** The account hand-back
through FirstDockActivity's IntentSender has a different root cause and a
different fix from the permission typo. It likely never got looked at
separately. Worth one narrow question to the triager, asked once, and then
dropped either way — not a re-argument, a scoping question.

**For mvrp-handback.sh:** deprioritise ORPHAN hits. The value is in NONE and
NORMAL guards, where the weakness is not the permission system at all.
