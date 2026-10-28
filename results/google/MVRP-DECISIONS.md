
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

### 2026-10-22 — Duo's account authenticator: closed by the framework

`com.google.android.apps.tachyon.contacts.sync.DuoAccountService` is exported
with no permission and hands a permissionless app the binder for
`android.accounts.IAccountAuthenticator`. The service checks nothing itself —
`onBind` returns `lbn.getIBinder()` and that is the whole method.

Every transaction answers the same way:

    SecurityException: Access denied, requires: android.permission.ACCOUNT_MANAGER

Signature|privileged, so no third-party app reaches it. `AbstractAccountAuthenticator`
checks before reading arguments, which is why an empty parcel was enough to
settle it. Closed.

Two things this cost and taught:

The reply size decided nothing. Ten codes came back at exactly 132 bytes and I
read that as ten answers; it was one exception marshalled back ten times,
because binder returns true and puts the throwable in the reply parcel. The
harness logged only the size, so the one fact that mattered was invisible.

And the patch that taught the harness to read the reply did not compile —
duplicate `byte[] raw` — but `build.sh` piped javac through grep with `|| true`,
so the build claimed success and installed an APK that could not work. Caught
by the control that binds our own service, not by the build and not by the
install. javac failures are fatal now.

Still open from the bind test: ExternalRcsEndpointService and
CustomD2DSourceEndpointService (Messages), PhotosBackupApiService and
PhotosRestoreApiService (Photos), SleepStateExportedService (Wear companion) —
all raw binders — and ReachabilityService (Meet), which has a real AIDL with
four transaction codes in `defpackage/lai.java`.

### 2026-10-22 — Photos backup API: open manifest, signature gate underneath

`PhotosBackupApiService` is exported, has no permission, and hands any app a
live binder. Inside, `tpg` holds an allowlist of four first-party packages —
but reading it closely, `n()` never refuses anything: it picks between
`SOURCE_BBG1` and `SOURCE_CARBON`, a label for attribution. I first read that
table as "four methods check, five do not"; none of them check.

The real gate is in `onTransact`:

    if (!bgfo.c(context)) { ...; return false; }

and `bgfo.c` resolves `Binder.getCallingUid()` to a package name and passes it
to `bsrc.b()`, which is Google's signature verifier — the same class that
compares `packageInfo.signatures[0]` against known Google certificates. A
self-signed app cannot pass it whatever it calls itself, and all four
allowlisted packages are installed here anyway, so there is no absent name to
squat. Closed.

What `c()` would have returned if the gate were weaker is worth recording,
because it says what this surface is worth to anyone who does get through: the
signed-in account name, the backup quality setting, and a flag.

Two reading errors on the way, both mine:

"returned false on every code" — I wrote in the tool that this means the code
is unhandled. Here it was an explicit refusal, written into onTransact. The
empty-parcel scan had given the answer and I read it as silence.

And the allowlist that turned out to be a label. An allowlist in the source is
not an access check until you find the branch that refuses.

### 2026-10-22 — the verification pass introduced the error it went looking for

Before submitting I re-measured every number in the report. One did not match:
the report said 66 decoded manifests and `ls -1 ~/mvrp/decoded | wc -l` said
132, so I changed it to 132 and recorded that the original count was stale.

It was not. `~/mvrp/decoded` holds 66 package directories and 66 `.jadx.log`
files beside them. `ls` counted both; the 159 distinct guard values were
measured with a glob that only matches directories, so 159 was always a figure
over 66 apps. The original number was right and I replaced it with a wrong one
while checking it.

Caught by the hand-back sweep printing "across 66 apps", because that one
counts directories.

The lesson is narrow and worth keeping: a re-measurement is only a correction
if it measures the same thing the original did. `ls | wc -l` and
`find -type d | wc -l` are not the same question, and the first one is the one
that happens to be easy to type.

Numbers corrected in the finding files. The report itself is closed as a
duplicate so there is nothing to amend with Google.

### 2026-10-22 — Drive's legacy storage provider: real gap, no way to reach it

`LegacyStorageBackendContentProvider` in Google Drive is exported with no
permission, no readPermission, no writePermission and no grantUriPermissions.
It does hold a URI permission check — `d(uri, mode)` throws SecurityException
when `checkCallingUriPermission` fails — but all three call sites (`call`,
`openFile`, `openTypedAssetFile`) wrap it in the same flag:

    if (((aide) ((adzv) aidd.a.b).a).a()) { d(uri, i); }

On this device the flag is off, measured rather than assumed: reading a
nonsense URI as shell, which holds no grant for it, returns
FileNotFoundException and not SecurityException. So the check does not run.

Dead end anyway, for the same reason as the Home receiver yesterday: no way
to discover a valid URI. `mbg.c` accepts `?local_id=<LocalSpec>`, and
`mwk.java:40` shows what a real one looks like —
`acc=<id>;doc=encoded=<cello doc id>`. Not a small integer, not enumerable,
and the UriMatcher requires exactly one path segment so there is no listing
path to walk. Google's rule is explicit that the attacker needs a clear path
to discover the ID, and there is none.

Worth keeping as a shape to look for, though: a permission check behind a
feature flag is a real pattern and this is the second one today where the
guard existed but did not run. The first was Photos, where an allowlist
turned out to pick a telemetry label.

Recording it as a precondition, not a finding (CLAUDE.md 2.6). Dropping it.

### 2026-10-22 — a human confirmed the duplicate, and corrected my inference

Comment #5, from a person rather than the bot: 1469 is "a generic identifier
we use for duplicate reports, rather than a specific report ID", they cannot
share details of other researchers' reports, and "we can confirm that this is
indeed a duplicate".

The scoping question was asked once and answered. Nothing further to send;
re-arguing a rejection with the same evidence is how reputation gets spent.

**What I got wrong, and it changed strategy.** When the close arrived I read
the shared canonical ID as meaning the whole class — orphaned permission
guards in Google apps — was known and filed, and advised dropping that axis
and deprioritising ORPHAN hits in the hand-back sweep. That inference rested
on 1469 being class-specific. It is not; it is a generic marker used across
unrelated duplicates. So the only thing established is that this particular
finding had been reported before. Whether the class is exhausted is unknown,
and I presented a guess as a conclusion.

The deprioritisation in mvrp-handback.sh stands on its own merits — NONE and
NORMAL guards are not device-specific the way an orphan is — but the reason I
gave for it was wrong.

### 2026-10-22 — the AppSheet SSRF was ruled Duplicate, not WAI

Reading the full thread on 525815004:

- Jun 20: submitted (twice, as 525815004 and 525815219)
- Jul 4: an internal AI triage note was published to the thread by mistake —
  "WAI Status: WAI / Duplicate Bug ID: 377539803 / Assessed Severity: LOW /
  Recommendation: DISQUALIFY"
- Jul 6: Google retracted it: a configuration error in their tooling, the note
  "does not represent a final decision", the report was still open
- Sep 21: closed by the Cloud VRP team as Duplicate of 1469

So the official outcome is Duplicate. The twin, 525815219, is still open at
P2/New four months on.

Our kill list in CLAUDE.md cited this as "AppSheet SSRF → WAI", which took the
retracted AI note as the verdict. That entry has been steering decisions since
— it would have us drop a connector SSRF on the grounds that Google ruled the
class intended, which Google never did. Corrected to cite the real outcome and
keep the heuristic on its own merits.

Worth noticing what a retracted machine judgement cost: it sat in our rules as
fact for three months because it was written down once and never checked
against the thread it came from.

Standing instruction from this: do not touch AppSheet connector SSRF. One copy
is still open at P2 and anything further there duplicates our own report.

### 2026-10-23 — Android 16 in hand: one of my three claims was wrong

Second device connected: moto g 2026, Android 16, API 36, patch 2026-09-01.
Permission map taken into ~/mvrp16 so the two devices' data stay apart.

G-F003 told Google that three guard permissions were API 36 names, undefined
on API 35, and that they "resolve themselves when the device reaches Android
16". That was read off decompiled stubs, not measured. Measured now:

    BIND_APP_FUNCTION_SERVICE                        defined, signature
    BIND_INTRUSION_DETECTION_EVENT_TRANSPORT_SERVICE defined, signature
    BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE       STILL UNDEFINED

Two out of three right. The third is wrong, and wrong in the direction that
matters: Google Messages' BugleAlternativeMessageTransportService is guarded
by a name that nothing defines on the latest Android either. I told Google
that class of guard fixes itself, and for this one it does not.

The report is closed as a duplicate so there is nothing to amend there, but
the claim is corrected here and in the finding files.

Two things follow:

The GMS IntrusionDetection thread, left open in these notes since the AGSA
work, is closed: signature-level on 16, so no third-party app reaches it, and
a bug that only works on 15 is excluded by the program's own latest-OS rule.

And the Messages service is now a live lead on the latest OS rather than a
forward-compatibility curiosity. Next: declare that name on the Android 16
device and see whether the bind connects, and if it does, what the binder
hands over. Reaching it is still only a precondition.

### 2026-10-23 — the Messages transport service: a crash, not a finding

Declared BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE alone in a probe, installed
on the Android 16 device, and bound to
com.google.android.apps.messaging.shared.telephony.rcsupgrade.BugleAlternativeMessageTransportService.

    install permissions: ...BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE: granted=true
    bindService() returned true, no connection

So the manifest guard is bypassed on the latest OS — the name is undefined,
we declare it, we are granted it. That part reproduces.

What happens instead of a connection, from logcat:

    E dczv: Caused by: java.lang.NoClassDefFoundError
    E dczv:   at android.service.messaging.AlternativeMessageTransportService.<clinit>
    I ActivityManager: Showing crash dialog for package com.google.android.apps.messaging

The base class is absent on Android 16 too, so the service cannot instantiate
and Google Messages crashes. An app holding no real permission can crash
Messages on the latest Android by binding to an exported component.

**Not reporting it.** The attacker gets nothing — no data, no token, no
execution. Mobile VRP pays for arbitrary code execution, theft of sensitive
data, and the "other" column of things like path traversal and intent
redirection. A crash is none of them, CLAUDE.md 2.1 says the same, and 0.3
rules out DoS outright.

The tempting framing is "crash it in a loop and block RCS, including 2FA
codes". That is still availability, and several of this account's fifteen
closures came from exactly that kind of argument — a story that sounds like
impact and does not land in the table.

What it does settle: permission undefined and class absent together mean the
feature has not shipped. G-F003's sentence about these resolving at Android 16
was wrong about the mechanism for this one, and the corrected note in the
finding files now says so.

Do not re-run the bind casually. It crashes a real app on a real phone, and
there is nothing further to learn from repeating it.

### 2026-10-23 — `env VAR=~/path` does not expand the tilde in zsh

The Android 16 pull reported "52 package টানা হলো -> ~/mvrp16/apk" and
~/mvrp16/apk did not exist. The files were real — 169 APKs, 2.7 GB — sitting
in a directory literally named `~` inside the repository.

zsh expands a leading tilde in an assignment prefix (`MVRP_OUT=~/x cmd`) but
not in an ordinary argument, and `env MVRP_OUT=~/x cmd` is the second kind
unless MAGIC_EQUAL_SUBST is set, which it is not by default. So MVRP_OUT held
the literal string and every path built from it was relative to the cwd.

The tell was in the output all along: the closing line printed `~/mvrp16/apk`
with a literal tilde rather than an expanded path, and I read past it.

Two things to carry:

Use `MVRP_OUT=~/x nohup ./script &` rather than `nohup env MVRP_OUT=~/x ./script &`.
Or pass "$HOME/x", which survives either form.

And a script that prints a destination should print the resolved path. Had the
pull echoed /home/gorib/mvrp16/apk, the mismatch would have been obvious
instead of taking a `find` to locate 2.7 GB.

### 2026-10-23 — restore's D2D migrate service: the caller picks the binder, and nothing checks the caller

`com.google.android.apps.restore/...UsbD2dMigrateService` is exported with no
`android:permission` and it CONNECTED from `com.cindrasec.mvrpprobe`, which
holds no permission at all. Measured on the Android 16 device (ZT422724JR).

The part worth writing down is how it chooses what to hand back. The parent
class `dhi.onBind` reads an extra off the *caller's* intent:

    if (intent != null && intent.getBooleanExtra("isSetupWizard", false)) {
        return new mpz();
    }
    return new dhh(this);

So an unprivileged app decides which of the two interfaces it gets. With
`isSetupWizard=true` the binder is `mpz`, whose descriptor is
`com.google.android.setupcompat.portal.IPortalProgressService`.

The empty-parcel scan with that token:

    code 1   transact() true   replySize=0   no exception in reply
    code 2   transact() true   replySize=0   no exception
    code 3   transact() true   replySize=0   no exception
    code 4   transact() true   replySize=0   no exception
    code 5   transact() true   replySize=8   no exception, 4 bytes of payload
    code 6-8 transact() false

No SecurityException on any handled code. Nothing in that path looks at
`Binder.getCallingUid()` — which is the opposite of S47, where `djd` resolved
the uid, verified `signingInfo`, and threw `UNAUTHORIZED`.

From `mpz`'s dispatch, read so far: 3 = `onSuspend`, 4 = `onAllowMobileData`
(unmarshals one boolean), 5 = `onGetRemainingValues` (writes a value back).
Codes 1 and 2 are unread.

**Not a finding, and the ceiling looks low.** Holding a binder is a
precondition (CLAUDE.md 2.6), and the three methods I can name are the wrong
shape: `onSuspend` pauses a migration, which is availability and 0.3 rules out
DoS; `onAllowMobileData` flips a data-usage consent on the attacker's own
device; `onGetRemainingValues` returns progress counts, i.e. metadata, which
Section 3 drops by name. None of them is theft of sensitive data or code
execution, so none lands in the Mobile VRP table.

Decided before looking, so the answer cannot be argued into existence: this
thread stays alive only if code 1 or code 2 takes a path/Uri/filename, a
PendingIntent/IntentSender, or a callback binder it then writes migration data
into. Those are the shapes that reach the "other" column (traversal, intent
redirection) or data theft. Anything else and it closes with S47's reasoning.

Two reads settle it, and `scripts/mvrp-stub-read.sh` was written for exactly
this so the sequence stops being hand-typed differently each time:

    MVRP_OUT=$HOME/mvrp16 ./scripts/mvrp-stub-read.sh com.google.android.apps.restore mpz
    MVRP_OUT=$HOME/mvrp16 ./scripts/mvrp-stub-read.sh com.google.android.apps.restore dhh

`dhh` matters as much as `mpz`: it is what a normal caller gets, so if `dhh`
carries the uid check and `mpz` does not, the caller-chosen branch *is* the
bypass and the finding is about reaching the privileged interface, not about
any one method.

These have to run on the Pi. The session keeping this log is the cloud
container: no adb, no devices, no `~/mvrp16`, and `android.googlesource.com`
is not reachable through its proxy, so the setupcompat AIDL cannot be read
from the upstream source either.

### 2026-10-23 — S57 restore D2D portal interface: CLOSED. Five no-ops, and the 8 bytes meant "nothing".

Read the whole dispatch (`mvrp-stub-read.sh`, A15 tree, 14,879 java files, so
the zeros are measured). Every branch of `mpz.bw` does one thing: log.

    code 1  onPortalSessionStart   log only
    code 2  onSetCallback          readStrongBinder, queryLocalInterface, then
                                   `if (qli instanceof mpy) { }` — empty block.
                                   The callback is read and dropped.
    code 3  onSuspend              log only
    code 4  onAllowMobileData      cwl.g(parcel) reads the boolean into nothing
    code 5  onGetRemainingValues   cwl.e(parcel2, null) — returns null

jadx kept the source coordinates: these are the overrides of
`D2dMigrateService$1`, lines 301-322 of `D2dMigrateService.java`. It is the
anonymous class the SetupWizard portal contract forces the service to
implement, with the body left empty because this app does not use the portal
progress callbacks.

So the drop rule I fixed in advance resolves against the lead on both codes:
1 and 2 take no path, no PendingIntent, and code 2 takes a callback binder it
then throws away.

**The correction worth keeping.** The transaction scan was what made this look
promising, and I read it backwards. "No SecurityException on any handled code"
I wrote down as *nothing checks the caller*; the real reason is that there is
no code in that path to check anything. And code 5's `replySize=8, payload
remaining 4` I took as data coming back — it is `writeNoException` (4 bytes)
plus a null marker (4 bytes). The parcel was telling me "null" and I recorded
it as a return value.

That is the second time an empty response has been read as a positive signal
(the first was `transact() returned true` on Photos). The lesson is specific:
a reply parcel is not evidence until its bytes are accounted for. 8 = 4 + 4 is
an empty answer, and the scan should name it as such rather than printing a
size.

`dhh`, the binder a caller gets *without* the `isSetupWizard` extra, has no
`onTransact` and no `bw` at all — it extends `Binder` with local methods
reaching `cze`/`dhd`/`oli`. A Binder subclass with no dispatch cannot be
driven over IPC: a remote `transact()` falls through to Binder's default, and
the methods are reachable only in-process through `queryLocalInterface`. So
that branch is inert from outside too.

Both branches of the caller-chosen `onBind` are therefore dead ends. The
caller-picks-its-own-binder pattern in `dhi.onBind` stays on the list as a
*shape* worth recognising elsewhere — it is how a privileged interface gets
handed out on an attacker-supplied flag — but here the privileged interface
does nothing.

One defect fixed on the way: section 2 of `mvrp-stub-read.sh` printed an empty
block for `dhh` and let me read silence as absence. It now says that no
dispatch means the class is not a stub, and what that implies for a remote
caller.

A16's copy of restore is decompiling in the background. The A15 reading above
is what decides the thread; if A16 somehow implements these methods the diff
will say so, and nothing else here depends on it.

### 2026-10-23 — S58 Wallpapers `DownloadableRestorer`: the first orphan that reaches a privileged API

The orphan diff across both phones left six guards orphaned on Android 15 and
16 alike. Five were already-closed threads (two are G-F003, one is the Messages
crash, two are AGSA's QSB, closed at S55/S56). The sixth had never been read.

```xml
<receiver android:name="com.google.android.apps.wallpaper.module.DownloadableRestorer"
          android:permission="com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER"
          android:exported="true">
    <intent-filter>
        <action android:name="com.google.android.apps.wallpaper.action.RESTORE_DOWNLOADABLE"/>
    </intent-filter>
</receiver>
```

and what it does with the broadcast:

```java
Object extra  = intent.getExtra("android.live_wallpaper.info");
int    target = intent.getIntExtra("android.live_wallpaper.restore_target", 0);
LiveWallpaperInfo info = new LiveWallpaperInfo((WallpaperInfo) extra);
...
WallpaperSetter.setWallpaperComponent(wallpaperManager, info, target);
    -> wallpaperManager.setWallpaperComponentWithFlags(
           liveWallpaperInfo.mInfo.getComponent(), destinationToFlags(i));
```

`setWallpaperComponent` / `setWallpaperComponentWithFlags` require
`SET_WALLPAPER_COMPONENT`, which is `signature|privileged`. The `ComponentName`
reaching that API comes out of the caller's extra with no check of the caller.
`Intrinsics.checkNotNull` tests the cast, not the origin.

Why this one is different from everything else in the orphan work: every
previous target ended at a precondition because a layer below the manifest
refused — AGSA re-verified the permission's owner, GMS's gRPC policy checked
signatures, restore's portal interface turned out to be five no-ops. Here the
layer below the manifest does the privileged thing on the caller's behalf. The
question stops being "can I reach it" and becomes "did the device do it".

Scope, checked rather than assumed. `config/scope-mobile-vrp.yaml`, read from
Google's own rules repo, lists under `other`:

    Path traversal / zip path traversal -> arbitrary file write
    Intent redirection -> launching non-exported components
    Unsafe PendingIntent usage
    Orphaned permissions
    (These are "not strictly in scope" but rewarded if security impact is shown.)

So the class is named in the rules and the whole weight falls on the impact.
The impact to claim is the one that was demonstrated: a signature|privileged
capability exercised on behalf of an app that holds no permission at all. If
the canary engine starts, the second sentence is that the attacker's own code
is launched and kept alive by the system as the wallpaper.

`poc/wallpaper-restore-poc/` builds two APKs from one source tree, differing
only in whether the manifest declares the orphaned permission. The control
exists because a success from the attacker build alone proves nothing — the
receiver could simply be open, and then there is no bypass to report.

Kill criteria, written before running:

- control also sets the wallpaper -> receiver is open, no bypass, drop
- broadcast accepted but `dumpsys wallpaper` unchanged -> a layer below
  refused, precondition again, drop (this is the S55 outcome)
- works on 15 but not on 16 -> the rules exclude it
- the device's wallpaper app is not Google LLC's -> out of scope

Untested as of this entry: nothing has been run. The PoC is written, the chain
is read from the installed APK, and the next thing that happens is the pair of
runs on the Android 16 device.

One tool change: `poc/mvrp-probe/build.sh` only ever linked a manifest, so no
PoC could reference a resource. A `WallpaperService` must point at an XML
resource through meta-data, so the builder now takes an optional `RES` tree and
an `OUT` override. Without `RES` it behaves exactly as before.

### 2026-10-23 — S58 CROSSED. A permissionless app set the wallpaper component on Android 16.

First demonstrated crossing of this effort. Device ZT422724JR, moto g 2026,
Android 16 — the latest available OS, which is what the rules require.

Attacker build holds exactly one permission, the orphaned one, and says so from
the device's own records:

    com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER: granted=true
    WPPOC: guard permission com.google.pixel.livewallpaper...DOWNLOAD_LIVE_WALLPAPER
    WPPOC:   held by me: true
    WPPOC:   SET_WALLPAPER_COMPONENT held by me: false
    WPPOC: current live wallpaper: none (static image)
    WPPOC: asking for component com.fitbit.FitbitMobile/...StepsWallpaperService, restore_target=0
    WPPOC: built WallpaperInfo for com.fitbit.FitbitMobile/...StepsWallpaperService
    WPPOC: broadcast sent to com.google.android.apps.wallpaper/...DownloadableRestorer

and the system's own records of what followed:

    ActivityManager: Start proc 31426:com.google.android.apps.wallpaper/u0a394
        for broadcast {com.google.android.apps.wallpaper/...module.DownloadableRestorer}
    ActivityManager: Start proc 31461:com.fitbit.FitbitMobile/u0a466
        for service {com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}

    mWallpaperComponent=ComponentInfo{com.fitbit.FitbitMobile/...StepsWallpaperService}

The control build — same code, same target, same command, no permission —
produced neither line and left `mWallpaperComponent` on
`com.android.systemui/...ImageWallpaper`.

So the privileged app performed `setWallpaperComponentWithFlags` with a
component chosen by a caller that cannot hold `SET_WALLPAPER_COMPONENT`.

Two things to be careful about, written down now rather than at report time:

**No `Permission Denial` line appeared in the control run.** I predicted one and
it did not come. What the control actually shows is that the receiver's process
was never started and the wallpaper did not change — which is evidence, but it
is different evidence, and the report will say the second thing. G-F003 already
cost one correction for quoting a line that never appeared; it will not cost a
second.

**Only one of the three `mWallpaperComponent` entries changed.** `restore_target=0`
is the home screen, and that is exactly what moved. The claim is the home-screen
engine, not the lock screen, until `restore_target=2` is tried.

Still open before this is report-ready:
- capture the control's refusal from unfiltered logcat, or state its absence
- the canary build, for whether the attacker's own code is started this way
- `restore_target=2`, for whether this reaches the lock screen
- confirm the Wallpapers app is Google LLC's and settle its tier
- re-run from a clean state to show it reproduces

### 2026-10-23 — S58 complete: the attacker's own code, started by the system

All three remaining questions answered on ZT422724JR (Android 16).

**The canary ran.** This is the escalation, and it holds:

    WPPOC: package  com.cindrasec.wallpapercan
    WPPOC:   held by me: true
    WPPOC:   SET_WALLPAPER_COMPONENT held by me: false
    WPPOC: current live wallpaper: com.glance.lockscreenM/...LooksWallpaperService
    WPPOC: asking for component com.cindrasec.wallpapercan/...CanaryWallpaperService, restore_target=0
    WPPOC: broadcast sent to com.google.android.apps.wallpaper/...DownloadableRestorer
    WPPOC: canary engine created by the system: uid=10539 pid=32016

    mWallpaperComponent=ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}

An app holding one self-declared permission and nothing else had its own code
started by the system, in its own process, as the live wallpaper. d8 did not
crash this time either — moving the engine to a top-level class was the fix.

**The lock-screen claim is dead, and I am glad it was tested.** `restore_target=2`
changed only the home entry; the other stayed on `ImageWallpaper`. The reason is
in the code I had already read and skimmed past:

    if (!wallpaperManager.isLockscreenLiveWallpaperEnabled() && i == 2) {
        wallpaperManager.clear(2);
    }

so asking for both *clears* the lock screen on a device without that feature.
The report claims the home screen only. Had I written the report before running
this, it would have carried a sentence the vendor could disprove in one minute.

**The control is refused silently.** A grep of unfiltered logcat for `denial`
found nothing, the Wallpapers process was never started for the broadcast, and
`mWallpaperComponent` stayed where it was. So the evidence of refusal is the
absence of the receiver's process plus the unchanged component — not a log
line. My earlier prediction of a `Permission Denial` line was simply wrong, and
the report will not quote one.

**Scope, measured:**

    codePath=/system_ext/priv-app/GoogleWallpapers
    versionName=16
    pkgFlags=[ SYSTEM HAS_CODE ... ]
    privatePkgFlags=[ ... PRIVILEGED SYSTEM_EXT ... ]
    package:com.google.android.apps.wallpaper  installer=null

Google's own app, privileged, preinstalled. The vulnerable receiver lives in
`com.google.android.apps.wallpaper.module`, i.e. Google's own code, not in the
AOSP `com.android.wallpaper.*` picker library that the app also bundles. So it
belongs in Mobile VRP rather than the Android and Google Devices SRP.

Root cause, stated as what it is: the guard names a permission that a package
not present on this device would define — the name is
`com.google.pixel.livewallpaper...`, and `com.google.pixel.livewallpaper` is not
installed here. That part is inference from the name and from the permission
being undefined; it has not been checked on a Pixel, and the report will say so
rather than assert how Pixels behave.

Still to do before submitting: reproduce from a clean install, check whether it
survives a reboot, and run the same pair on the Android 15 phone so the report
can say which versions it was seen on.

### 2026-10-23 — defect 28: I recorded a reproducibility failure that was my own stopwatch

The clean-state run was written down as "did not reproduce": broadcast sent,
`sleep 3`, `dumpsys` still showed `ImageWallpaper`. It had not failed. Three
minutes later, with nothing else having touched that phone, the next run opened
with

    WPPOC: current live wallpaper: com.cindrasec.wallpapercan/...CanaryWallpaperService

so the change had landed, late. A freshly installed app plus a cold start of
the Wallpapers app takes longer than three seconds, and a fixed sleep measures
the sleep rather than the device.

This is the same family as defects 13 and 23: a weak instrument given a strong
reading. It is worse than those because the reading was negative — I was about
to tell the user the finding did not meet our own reproducibility bar and to go
hunting for a non-existent precondition.

`run-poc.sh` replaces the sleep with a poll to a deadline, and prints the
framework's own lines either way.

And those lines are the best evidence in the whole finding, better than
anything the PoC logs about itself:

    WallpaperManagerService: setWallpaperComponent
        name=ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService},
        which = 1; callingPid = 14942
    WallpaperManagerService: bindWallpaperComponentLocked:
        componentName=ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}

`callingPid` is the Wallpapers app's process. The system is recording that a
privileged app made the `SET_WALLPAPER_COMPONENT`-gated call with a component
chosen by an app that holds no such permission. The report leads with this
rather than with our own log.

Two smaller facts from the same runs: repeating the attack when it is already
in place gives `Changing to the same component, ignoring`, so a repeat run is
not a second proof; and `Cannot extract colors because wallpaper could not be
read` is the canary having no bitmap, not an error in the attack.

Confirmed so far: Android 16 (ZT422724JR) and Android 15 (ZD222W5X3R), two
different Motorola models, and the component survives a reboot — after
`adb reboot` the canary was still the home wallpaper, so the system starts the
attacker's code again at every boot.

### 2026-10-23 — defect 29: my own instrument produced a false positive, on the control

The clean-state pair ran, and `run-poc.sh` printed for the **control** build:

    RESULT  component changed: ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}
                            -> ComponentInfo{com.android.systemui/...ImageWallpaper}

A control that "works" would have killed the finding — it would mean the
receiver is open to everyone and there is no permission bypass. It did not
work. The framework's lines say what actually happened:

    WallpaperManagerService: clearWallpaperLocked which = 1; userId = 0
    WallpaperManagerService: setWallpaperComponent name=null, which = 1; callingPid = 1767
    WallpaperManagerService: bindWallpaperComponentLocked: componentName=null
    WPMS.onServiceConnected-ComponentInfo{com.android.systemui/...ImageWallpaper}

`name=null` and `callingPid = 1767` — system_server, not the Wallpapers app.
The canary package had just been uninstalled while it was the live wallpaper,
so the system was clearing it and falling back to the default, and that landed
inside the same few seconds as the control's broadcast. The control's actual
request, the Fitbit service, was never set.

The defect is in the question I asked: "did the component change" instead of
"is the component now the one that was requested". Fixed — the script polls for
the requested component, and a change to anything else now prints as *not* the
attack, naming this exact cause.

Three instrument defects in two days (27, 28, 29) and all three the same shape:
a weaker question than the one that matters, with a confident answer. The
pattern to watch for is a script that reports a difference rather than a
destination.

The canary run in the same pair was clean and is the one to quote:

    before : ComponentInfo{com.android.systemui/...ImageWallpaper}
    after  : ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}
    WPMS.onServiceConnected-ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}
    WPMS.connectLocked-ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}
    WPPOC: canary engine created by the system: uid=10541 pid=16798

Still needed: a control run from a settled state, so its "unchanged" is not
competing with the system tearing down an uninstalled package.

### 2026-10-23 — the premise, measured from both sides (and a grep that nearly reversed it)

`pm list permissions -f` prints a permission's attributes *below* its name, so
`grep -B3` attributed the previous entry's `protectionLevel:signature|privileged`
to `DOWNLOAD_LIVE_WALLPAPER` and briefly looked like the whole finding was
built on a misreading. With `-A5`, from a device with my test apps removed:

    $ adb shell pm list permissions -f -g | grep -A5 'permission:com.google.pixel.livewallpaper'
    $

Nothing. After installing an app that declares the name at `normal`:

      + permission:com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER
        package:com.cindrasec.wallpaperpoc
        protectionLevel:normal

So an ordinary app becomes the owner of the permission guarding a privileged
app's exported receiver. That pair is the root cause shown from both sides, and
it is now the opening evidence in the report rather than an assertion.

It was also consistent all along, which is why the misread was worth checking
rather than panicking over: if a system package really defined that name at
`signature|privileged`, our declaration would have been ignored and
`granted=true` could never have been measured. But the logic was not the proof —
the second command was.

Worth keeping as a rule: `-B` on a key/value listing answers about the wrong
record. Four instrument defects now (26-29), and three of them are the same
mistake wearing different clothes.

### 2026-10-23 — defect 30: the screenshot run proved nothing, and said it proved everything

Ran the pair for the report screenshot while the wallpaper was already the
Fitbit service, which was also the component both builds asked for. Output:

    build  : control
    before : ...StepsWallpaperService
    asked  : ...StepsWallpaperService
    after  : ...StepsWallpaperService      (waited 1s of 45s)
    RESULT  the requested component is now the home wallpaper (after 1s)

The control "succeeded". Taken at face value that reads as the receiver being
open to anyone, i.e. as there being no bypass and no finding — on a run where
nothing happened at all.

Third false reading from the same instrument in two days, and the third time
the question was weaker than the one that matters. 29 was "did it change"
instead of "did it change to what was asked"; 30 is "is it the requested
component" without "was it already". The script now aborts when the requested
component is already set, and prints the three-step order that avoids it.

I had written the warning in prose to the user instead of into the script. A
precondition that only exists in a sentence is not a control.

### 2026-10-23 — S59 GMS accounts provider: open manifest, Google-signature gate underneath

`com.google.android.gms.auth.accounts` has no read permission in the manifest
and was the most valuable name the gap sweep produced: Tier 1, and accounts.

`query` is not implemented (`UnsupportedOperationException`), which is not a
refusal — GMS's own client code shows the real door:

    acquireUnstableContentProviderClient("com.google.android.gms.auth.accounts")
    bundle.putString("callingActivity", str)
    call("get_accounts", "com.google", bundle)  ->  getParcelableArray("accounts", Account.class)

Called that way from adb:

    SecurityException: GoogleCertificatesRslt: not allowed: pkg=com.android.shell,
    sha256=[0ad6202e02eb347d4d705e582f1b226245e32aaaa026fc3b66a290e2b8694213],
    atk=false, ver=263737035.true (go/gsrlt)

and the code says the same thing:

    bkae.j(...)  ->  bkfa.b(this.j, str, Integer.valueOf(Binder.getCallingUid()), this.k)
    AccountChimeraContentProvider: "get_accounts".equals(str) -> a.k(callingUid)

So the caller's uid is resolved to its packages and checked for first-party
signing. Shell is refused; a self-signed app is refused sooner.

**Closed.** And closed well: shell holds more than an app does, so a refusal
here settles it without building anything. That is the rule the triage script
states — DENIED is the only conclusion adb alone can reach, and it reached it.

Fourth time this exact shape has appeared: S47 (restore AppDataWriter),
S55 (AGSA QSB), S56 (OneSearch gRPC), S59 (GMS accounts). The manifest is not
where Google enforces anything; `bsrc`/`GoogleCertificatesRslt` is. Worth
treating as the prior from now on: an open GMS manifest means nothing until
the uid check below it is read or a call is actually refused.

Also settled cheaply: `com.google.android.gms.settings.persistent` takes paths
`getGoogleSettingsAlertCount`, `getGoogleSettingsTitle`,
`getGoogleSettingsSummary` (from `GoogleSettingsEntryChimeraContentProvider`).
Those are strings for a settings entry. Dropped without probing — Section 3
drops UI metadata by name.

Still open from the 52-package sweep: wellbeing's `api` and `autodnd` providers
(usage data), safetyhub's `suggestionstateprovider` (emergency info), Photos'
`partnercontentprovider`, and Messages' `SharedStorageProvider` and
`AvatarContentProvider`. All REACHED, meaning they answered and the root path
was wrong, so each needs its UriMatcher read before another probe.

### 2026-10-23 — the Wallpapers app's other exported surface: three closures, one real flaw worth nothing

With A16's APK decompiled, the three remaining questions about that app are
answered.

**`StandalonePreviewActivity` — the check is broken, and it does not matter.**
Exported, no permission, takes `CROP_AND_SET_WALLPAPER` with `image/*`:

```java
if (checkUriPermission(data, Binder.getCallingPid(), Binder.getCallingUid(), 1) == 0
    || getPackageManager().checkPermission("android.permission.READ_MEDIA_IMAGES", getPackageName()) == 0) {
    return;
}
```

Both halves fail. `Binder.getCallingUid()` inside an Activity's `onCreate`
returns this process's own uid — there is no binder transaction on that
thread — so the first clause asks whether the app has permission on its own
Uri. And `getPackageName()` is the Wallpapers app, which does hold
`READ_MEDIA_IMAGES`, so the second clause is unconditionally true. The guard
passes for every caller.

It still is not reportable. The privileged app opens the attacker's Uri under
its own identity and renders it **on screen**. The bytes never reach the
attacker: a third-party app cannot read the wallpaper back, and nothing is
returned to the caller. The one-sentence answer to "what did the attacker
get?" is "the user saw a picture", so by 2.1 it drops.

Writing it down anyway because the flaw is real and the shape is reusable: an
`||` where one side is a self-check and the other asks whether the deputy
itself holds the permission is a guard that cannot fail. If that pattern ever
sits in front of a sink that returns data, it is a finding.

**`MissingHashCodeGenerator`** — exported with no guard, and inert: `onReceive`
only acts on `MY_PACKAGE_REPLACED`, a protected broadcast the system alone can
send. Closed.

**`getSettingsActivity`** — the redirection idea is dead. The picker builds
`new ComponentName(wallpaperInfo.getPackageName(), settingsActivity)`, scoped
to the wallpaper's own package, so a caller-supplied settingsActivity cannot
name another app's component.

Running total on this surface: one crossing (G-F004) and five closures around
it. The orphaned-permission class gave exactly one sink that does something,
and chasing the neighbours has not improved it.

### 2026-10-23 — the provider path is closed. Six walls, one shape.

Last two candidates read:

    WellbeingSettingsProvider.java:416,441,466   String callingPackage = getCallingPackage();
    PartnerContentProvider.java:243              throw new SecurityException(... " is not trusted.");
    PartnerContentProvider.java:375              throw new SecurityException(callingPackage + " is not authorized to access the content.");

Both authorise the caller inside. That closes the provider thread.

The tally for the night, written plainly because the shape is the lesson:

| surface | manifest | what actually stopped it |
|---|---|---|
| restore `AppDataWriter` (S47) | open | uid -> package -> `signingInfo` |
| AGSA QSB activity (S55)       | orphaned guard | runtime check that the permission's owner is a system Google app |
| AGSA `OneSearchSuggest` (S56) | orphaned guard | gRPC first-party-only security policy |
| GMS `auth.accounts` (S59)     | open | `GoogleCertificatesRslt: not allowed` |
| Wellbeing `api`               | open | `getCallingPackage()` |
| Photos `partnercontentprovider` | open | `SecurityException: not trusted` |

Six for six. **An open Google manifest is not a signal.** The guard is below
it, every time, and the manifest sweep that finds these is a generator of
leads with a base rate near zero. Treating it as a prior from now on: do not
probe an open GMS/Google component before reading the uid check underneath —
the read is minutes, the probe-and-hope is hours.

Which makes G-F004 stand out for the right reason. It is not that the manifest
was open; it is that beneath the open manifest the Wallpapers app does the
privileged thing on the caller's behalf instead of checking who asked. That is
the rare case, and it is the one already written up and waiting to be filed.

Next class, chosen because it sidesteps this wall entirely: intent forwarding.
An exported activity that takes `android.intent.extra.INTENT` (or any
caller-supplied Intent/PendingIntent) and calls `startActivity` with it cannot
be saved by a uid check, because forwarding is the feature — the app is not
supposed to be deciding whether the caller is trusted, it is just passing an
intent along under its own identity. The rules name it: "Intent redirection ->
launching non-exported components". `mvrp-handback.sh` looked for this from
manifests alone and was blind without sources; the sources now exist for 52
packages on A16.

### 2026-10-23 — the pre-submission pass: four claims measured, one quote was from the wrong build

Checked the report's load-bearing sentences against evidence rather than
against memory, which is how G-F003 lost a claim.

Measured, all four confirming what the report says:

    + permission:android.permission.SET_WALLPAPER_COMPONENT
        package:android
        protectionLevel:signature|privileged

    com.google.android.apps.wallpaper:
        android.permission.SET_WALLPAPER_COMPONENT: granted=true

    A16 manifest, lines 300-307: the receiver block is byte-for-byte what the
    report quotes, on the device under test rather than on the other phone.

    Clean-state rehearsal following the README verbatim: control unchanged for
    45s, attacker in 2s, callingPid matching the Wallpapers process started one
    line earlier.

Until this pass, `signature|privileged` was written from memory. It happened to
be right. It was still the same unmeasured-assertion habit that produced the
API-36 error, and the fix is the pass, not the luck.

**And one thing was wrong.** The code I quoted came from the Android 15 tree
while the report claims Android 16. The A16 build differs: `WallpaperSetter.
setWallpaperComponent` ends at the try/catch with no lock-screen clear, and the
receiver's `invokeSuspend` has no `isLockscreenLiveWallpaperEnabled` throw. So
the sentence explaining why `restore_target=2` left the lock screen alone cited
a line that is not in the build I tested.

The observation was fine; the mechanism was imported from another version. Both
code quotes now come from the A16 tree, and the lock-screen note states the
measurement and explicitly declines to explain it.

That is the fourth time in two days that a correct-looking sentence rested on
something not measured on the device in question. The habit worth keeping:
every quote in a report carries the build it came from, and the build has to be
the one in the title.

### 2026-10-23 — force stop ends it, and that goes in the report

Tested the one claim that could have raised the impact: does the system keep
restarting the attacker's wallpaper service after the user force-stops the app.

    dumpsys wallpaper -> ...CanaryWallpaperService
    ps -A | grep wallpapercan -> u0_a548 3905 ... com.cindrasec.wallpapercan
    am force-stop com.cindrasec.wallpapercan
    ps -A | grep wallpapercan -> (nothing)
    dumpsys wallpaper -> com.android.systemui/...ImageWallpaper

The process stays dead and the wallpaper reverts to the system default. So
"the user's Force stop button cannot stop this" — which would have been the
strongest version of the persistence claim — is false, and the report now says
so in both places it talks about persistence.

Worth doing even though it came back negative, for two reasons. A triager runs
force stop in the first minute, and a claim they can disprove costs more than
the claim was worth. And the finding does not depend on it: the bypass is the
signature-permission-gated call being made on an unprivileged caller's behalf,
which force stop does not touch.

That is three claims tested before submission and one survived intact
(reboot), one corrected (the code quote's build), one withdrawn (force-stop
resistance, never claimed, now explicitly denied).

### 2026-10-23 — the last two gaps, and a silent zero I nearly accepted from my own hand

Two sentences in the report were still assertions. Both now measured.

`com.google.pixel.livewallpaper` is absent from both devices — `pm path` and
`pm list packages` print nothing on either serial. The app still carries the
client code that would bind it (`IpcDownloadableService` ->
`com.google.pixel.livewallpaper/.split.DownloadService`), which is what makes
the guard's origin legible, and that pair is now in the report.

The second one is the better lesson. To show the control build holds no
permission I ran `dumpsys package ... | sed -n '/install permissions/,/runtime
permissions/p'` and got nothing back. Nothing is what a package with no
permissions prints, because dumpsys omits the section — and it is also what an
uninstalled package prints. I was one step from writing "the control holds
nothing" on the strength of an empty terminal.

The fix was to make the zero visible and give it a control, in one command:

    for P in com.cindrasec.wallpaperctl com.cindrasec.wallpaperpoc; do
      adb shell pm path $P
      printf '  mentions: '; adb shell dumpsys package $P | grep -c DOWNLOAD_LIVE_WALLPAPER
    done

    wallpaperctl : installed, mentions 0
    wallpaperpoc : installed, mentions 5

Both installed, so the zero is a measured zero, and the five is the positive
control that proves the command can find the name at all.

This is the fourth silent-zero defect in two days, and the first one I made at
the prompt rather than in a script. Every control I added tonight went into
`mvrp-src.sh`, `mvrp-orphan-diff.sh`, `mvrp-stub-read.sh` and
`mvrp-provider-probe.sh` — and then I typed a bare `sed` range by hand and
read its silence as an answer. Putting the rule in the tooling does not install
it in the operator.

Verification is complete. Five claims tested before submission: reboot
persistence held, the code quotes were wrong about the build and were
replaced, force-stop resistance was disproved and is now denied in the report,
the Pixel package's absence was confirmed, and the control's permission-free
state was proved with a control of its own.

### 2026-10-23 — defect 31: the evidence script said the opposite of the truth, in the screenshot

The transcript written for the report's screenshot printed:

    com.google.android.apps.wallpaper holds it: no

The deputy does hold `SET_WALLPAPER_COMPONENT` — measured an hour earlier,
`granted=true`, and the whole report rests on it. Had that screenshot been
attached, a triager's first act would have been to notice the evidence
contradicting the claim.

Cause, reproduced rather than guessed:

    big() { printf 'granted=true\n'; yes padding | head -200000; }
    big | tr -d '\r' | grep -q 'granted=true' && echo yes || echo no   ->  no
    [ "$(big | tr -d '\r' | grep -c 'granted=true')" -gt 0 ]           ->  yes

`grep -q` exits at the first match, the pipe breaks, `tr` dies on SIGPIPE, and
`set -o pipefail` makes the pipeline fail. Small streams finish before grep
exits, which is why a quick test of the same construct passes — the bug needs
a big `dumpsys` to appear.

**This exact bug was found and fixed in `poc/mvrp-probe/build.sh` earlier in
this project**, where `unzip -l | grep -q 'resources.arsc'` made a good
android.jar look like a classes-only stub. The fix there was `grep -c`, with a
comment explaining why. I then wrote `grep -q` again in a new script.

Two more defects in the same output: `versionName=versionName=16` from a label
printed twice, and `receiver process started: 0` on a *successful* run,
because the Wallpapers process was already alive from an earlier run and no
new `Start proc` line was logged. The second is the dangerous kind — a zero
that meant "already running" presented as "never ran". Replaced with the
framework's own `setWallpaperComponent` line, which is the thing that actually
matters, and an explicit "no call logged" when it is absent.

The lesson is not "avoid grep -q". It is that a fix recorded in one file's
comments does not travel to the next file, and the screenshot is the one
artifact nobody re-reads before attaching.

### 2026-10-23 — G-F004 submitted 05:12, closed 05:17. Duplicate of 1469. Again.

Issue 576807381. Five minutes from submission to close, same marker as
G-F003 (576322789), P4, "Customer Issue".

Nobody read it. Five minutes does not cover a 13,000-character report, three
attachments and a two-device differential. The report was bucketed.

**The conclusion, stated plainly: the orphaned-permission class is closed for
this program.** Two findings that share nothing but the class — different app,
different component, different sink, different impact — landed on the same
marker. 1469 was already known to be generic; a human confirmed that after
G-F003. So the marker covers the class, and the quality of the report is not
the variable. No further report in this class is worth writing.

**My failure, and it is the expensive kind.** G-F003 closed as duplicate of
1469 on 2026-10-22. I was told 1469 is generic. I then spent the following
night building a second report in the same class — tooling, PoC, five
verification rounds, a dedup search of *public* sources — without once asking
the question that mattered: what does 1469 cover? The dedup I ran checked
CVEs and writeups. The duplicate that actually killed this was the one sitting
in our own history, one line above, in this file.

Every verification round improved the report and not one of them tested the
assumption the whole effort rested on: that a well-built report in this class
could be rewarded. That assumption had already been falsified once.

What to carry:

- Dedup means the program's own closes first, the public record second. A
  marker that closed your last report is the first thing to check against the
  next one, before any work begins.
- A fast close is information about the class, not about the report. Reading
  it as "they didn't read it properly" keeps you in the class; reading it as
  "the class is bucketed" gets you out.
- The quality work was not wasted and was also not the point. Six surfaces
  closed, four instrument defects fixed, a method that produces measured
  claims with controls. All of that transfers. The class does not.

Mobile VRP standing: 2 submissions, 2 duplicates of the same generic marker,
0 rewards. Per CLAUDE.md section 2, two closes means stop and rebuild rather
than file a third in the same shape.

### 2026-10-24 — defect 32: defect 22, repeated at the prompt, this time on 140 hosts

Re-probed the 140 hosts `acq-live.sh` called DEAD, with `-k`, using a loop
typed at the shell. It printed a line for every host and ended with
"সত্যিই জীবিত: 140 / 140". Not one of those lines was a measurement.

Three faults, all in the loop:

- `set -- $r` does not word-split in zsh, so `$1` held the whole
  `"301 162 20"` and `$2`/`$3` were empty. **This is defect 22, logged on
  2026-10-21, in this file.** Same construct, same shell, same wrong answer.
- A failed `curl` left the previous host's page in `/tmp/b`, so titles were
  attributed to hosts that never answered — which is why "Tenor GIF Keyboard"
  appears beside eight photomath hosts.
- `|| r="ERR 0 -"` made failures print as rows, so the total counted lines,
  not live hosts.

Rewritten as `scripts/acq-recheck.sh`: bash, body file truncated before every
request, failures skipped rather than printed, and the two controls this
project's scripts always carry. Parsing verified against a stubbed curl for
expired / mismatched / no-answer / connection-failure cases.

**The reason the re-probe was worth doing at all stands, and is the real find
of the morning.** `acq-live.sh` verifies TLS, so every host serving an
expired, mismatched or unchained certificate was filed as DEAD and never
looked at. `myhelp.fitbit.com` is one of them: HTTP 200, a live Fitbit
Salesforce support portal, on a certificate that expired 2026-09-27. 140
hosts went into that bucket unexamined.

The pattern across 22, 30 and 32: every control I add goes into a script, and
then the next question gets asked with a one-liner that has none of them. The
scripts are not where the mistakes happen.

### 2026-10-24 — defect 33: I invented a column, then told the user to read it

`acq-recheck.sh` printed `verify=20` for all 45 hosts that answered —
including `www.waze.com`, `tenor.com` and `wing.com`. I read that as the Pi's
CA store being broken and told the user their whole acquisition map was
distorted.

It was not. `ca-certificates` reinstalled with `0 added, 0 removed`, and
`www.google.com` verified fine *before* the reinstall. The 20 came from my own
`-k`: with verification disabled, `%{ssl_verify_result}` reports nothing
meaningful, and I had built a column out of it and written a six-line guide
explaining how to interpret its values.

The real measurement was in the user's own one-liner, run without `-k`:

    myhelp.fitbit.com  curl: (60) SSL certificate problem: certificate has expired
    myhelp.fitbit.com  000 verify=10

`probe()` now makes two attempts: verify first and keep that verdict, then
retry with `-k` only when verification failed, so the TLS column comes from an
attempt that actually verified and the body comes from one that could fetch
it. Verified against a stub for ok / expired / hostname-mismatch / no-answer.

**Correction to the record:** the DEAD classification in `acq-live.sh` is not
an artifact of a broken trust store. Those hosts fail verification for real
reasons — `myhelp.fitbit.com`'s certificate genuinely expired on 2026-09-27 —
or do not answer at all. What the recheck legitimately adds is that 45 of 140
serve something when verification is skipped, and now the script can say why
each one failed.

Fourth defect of the morning, and the same shape as the other three: the
instrument reported something, it looked like data, and I did not ask what the
flag I had passed did to the number.

### 2026-10-24 — defect 34: `--max-filesize` was writing the acquisition map

The recheck came back with `tls=ok` on nearly every host the sweep had called
DEAD. The certificates were fine; the sweep was wrong, and not about TLS.

`acq-live.sh` passed `--max-filesize 262144`. curl treats exceeding that as a
failed transfer, so any host whose home page is larger than 256 KB was
recorded DEAD. `www.waze.com` (348 KB), `wing.com` (646 KB) and `tenor.com`
(273 KB) were all filed as dead acquisition hosts by that one flag.

So the three hours of reasoning about dangling CNAMEs and neglected
certificates were spent on a list whose main selection criterion was page
size.

The same flag had already broken `acq-recheck.sh`'s own control an hour
earlier — `www.waze.com` "did not answer" — and I fixed it there without
asking where else it was. It was in the sweep that built the map, and in
`acq-paths.sh`, where it is worse: a failed fetch returns `ERR 0`, `ERR 0`
differs from every baseline, so a page over 256 KB would have been reported as
a discovered path. That one never ran, so it never lied.

All three are now without the cap; `-m 10` bounds the request.

Fifth defect of the morning. The first four were mine in one-liners; this one
was sitting in a committed script, with a control that caught it, and I fixed
the symptom in one file and left the cause in two others.

### 2026-10-24 — defect 35: reading a table while it was still being written

Twice in twenty minutes a recheck was built from

    T=$(ls -1t ~/acq/live-*.tsv | head -1)

while `acq-live.sh` was still running. It returned 52 hosts the first time and
12 the second, and both times the output looked like a finished result — "22
of 52 answered", "3 of 12 answered" — with controls passing, because the
controls check the instrument, not whether the input is complete.

`acq-live.sh` now writes `live-<stamp>.tsv.partial` and renames it on the last
line. A sweep in flight is no longer reachable by the name every consumer
looks for.

Asking the user to wait would not have been a fix. It was the second time.

### 2026-10-24 — defect 36: the path prober counted a 404's own echo as a discovery

`acq-paths.sh` reported hits on 21 of 82 hosts. Most were noise of one kind:
a 404 page that includes the requested path is a few bytes longer for
`/administrator` than for `/login`, and the comparison tested sizes for exact
equality. `myaccount.nest.com` and `myaccount.ft.nest.com` came back with all
twelve paths "differing", all of them 404s.

Two changes. A size difference now has to exceed 64 bytes to count, which is
more than any of these paths can add; a status difference still always counts.
And a host where *every* path differs is suppressed with a note, because a
host that answers identically to anything has a baseline that carries no
information.

Checked against the real rows: 404/165 vs 404/144 ignored, 404/18918 vs 401/27
kept, 404/0 vs 200/28644 kept.

What survives the filter, and is worth the next session:

- `www.pring.jp/admin` -> **401**, 27 bytes, against a 404 baseline. The path
  exists and wants credentials. pring is where this account's first Fixed
  report came from.
- `vpn.owlchemylabs.com/admin` -> **200** at `/admin/__session_start__`.
  The OpenVPN Access Server admin interface answers from the internet.

Both Tableau hosts are closed: `cs-tableau-bpo.corp.fitbit.com` and
`customersupport-tableau.site-ops.fitbit.com` redirect to
`fitbit.my.idaptive.app`, corporate SSO, properly guarded.

And `myhelp.fitbit.com`'s expired certificate is not a report. An expired
certificate is an outage, not a vulnerability: the attacker gains nothing and
the users are the ones locked out. It stays in the notes as evidence that
nobody is watching that host, which is a reason to look at it, not a finding
to file.

### 2026-10-24 — both TIER0/TIER1 candidates closed

`www.pring.jp/admin` is HTTP Basic (`realm="Application"`) in front of a Rails
app, CSP reporting to `csp.withgoogle.com/csp/pring/pring-customer-portal`.
The gate holds: `/admin`, `/admin/`, `//admin`, `/admin/.` all 401;
`/admin%2f` and `/ADMIN` 404. No bypass. Guessing credentials would be brute
force and the rules forbid it, so pring's admin path is closed.

`vpn.owlchemylabs.com/admin` serves OpenVPN Access Server's ordinary admin
login ("Cookie support required"). An admin login page reachable from the
internet is how that product is deployed; nothing is exposed.

So TIER0/TIER1 is done: 195 hosts, 82 live, 2 control surfaces, both properly
guarded. That is the expected outcome for Google's most visible assets and it
is worth having measured rather than assumed.

The surface that remains is TIER2/TIER3 — 238 live hosts out of 830, the
smaller acquisitions (Owlchemy, Cameyo, Pointy, Neverware, Siemplify,
Elastifile and the rest). The path probe is running against them now, with
the comparison fixed, so for the first time its output should be readable.

Day's tally, honestly: no finding, and six instrument defects repaired — three
of which were silently writing the map (`--max-filesize` in three scripts, a
half-written table being read twice, and a 404's own echo counted as a
discovery). Every "lead" examined before those fixes was an artifact. The map
is true now, which it was not this morning.

### 2026-10-27 — defect 37: the update sweep could not see a newly installed app

`mvrp-update-diff.sh stale` compares the stored `versionName` in each decoded
manifest against the device. It iterates over `ls $DEC` — the packages that
have already been decoded — so an app installed since the last sweep has no
decoded directory, is never checked, and never appears. The script would have
printed "N updated" and looked complete while saying nothing about apps that
had just arrived.

Same family as every silent zero in this file: the absence of something never
considered does not show up in the output.

`stale` now also lists in-scope packages on the device that have no decoded
directory at all, and adds them to the refresh list. The in-scope pattern
moved to `scripts/lib/inscope-pkgs.sh` and is sourced by both this and
`mvrp-pull.sh`, because the last time that list was wrong it was wrong in one
copy and right in the other, and the sweep reported 65 packages while skipping
the target.

Checked: wallpaper, gms, Fitbit and ai.edge.gallery match; whatsapp and the
probe app do not.

### 2026-10-27 — new class: intent forwarding, and the tool for it

The orphaned-permission class is spent. Two findings — different apps,
different components, different impact — both closed as duplicates of the
same generic marker 1469, in seven and five minutes. The reports were not the
variable.

Picked intent forwarding next, for one reason: the wall that stopped six
surfaces does not stand here. Every closure in this file ends the same way —
open manifest, `Binder.getCallingUid()` or `GoogleCertificatesRslt`
underneath. A component whose job is to take an Intent from a caller and
start it cannot defend itself that way, because forwarding is the feature.
The rules name the class: *Intent redirection -> launching non-exported
components*.

`mvrp-intent-forward.sh` pairs the decoded manifest with the decompiled
sources: for every exported activity, alias, service and receiver, it looks in
that class for a caller-supplied Intent (`getParcelableExtra`,
`EXTRA_INTENT`, `Intent.parseUri`, `getIntentSender`, `getBundleExtra`) and
for a dispatch (`startActivity*`, `startService`, `sendBroadcast`,
`startIntentSender`, `PendingIntent.get*`, `setResult`).

Two things it reports honestly rather than quietly:

- a component whose class is not in the sources is counted as **not read**,
  not as clean. jadx renames obfuscated classes, and most Google apps are
  obfuscated, so that number will be large and it is the real blind spot.
- a hit means one file mentions both a source and a sink. It does not mean
  they are the same object. That read is by hand and most will not survive it.

Self-test built in (`--selftest`): matches a forwarded `EXTRA_INTENT` and a
`parseUri`, ignores a locally constructed Intent passed to the same sink.
End-to-end on a crafted tree: hit on the trampoline, nothing on the clean
class, the obfuscated one counted unread, the non-exported one skipped.

### 2026-10-27 — first intent-forwarding pass: 36 candidates, the three strongest all dead

The sweep read 1,921 exported components across 76 packages and flagged 36.
The three that looked best are closed, and all three died the same way.

**Docs `ProjectorActivity:502`** — `startActivity((Intent) intent
.getParcelableExtra("next_activity_result_key"))`, the purest shape in the
whole output, sits inside `onActivityResult` (guarded by `i == 256 && i2 ==
-1`, alongside `snackbar_result_key` and `print_result_key`). That `intent` is
the result from a child this activity launched, not anything a caller can set.

**Home `DeeplinkActivity:357`** — same: inside `L(sr srVar)` with
`srVar.a == -1`, i.e. an activity result.

**Gmail `EmailBroadcastReceiver` -> `EmailBroadcastProcessorService`** — this
one was real up to the last step. The receiver is exported, takes any
broadcast, wraps the whole incoming Intent in `EXTRA_INTENT` and starts the
service with it. The service reads it back at line 59 — and then switches on
`intent2.getAction()` against five fixed values, logging `ignoring
onHandleBroadcastIntent intent with unhandled action %s` for everything else.
The forwarded Intent is never dispatched. No redirection.

One thing inside that whitelist is worth recording and not reporting:
`com.android.mail.action.PERMIT_ADD_GMAIL_AS_IMAP` reaches
`putBoolean("allowAddGmailAsImap", …)`, so any app can flip that preference.
The attacker's gain is a settings toggle — not data, not an account, not
execution — so §2.1 drops it.

**The fix this taught, now in the tool.** The pattern could not tell
`getIntent().getParcelableExtra(...)` (the launch Intent, attacker-controlled)
from `intent.getParcelableExtra(...)` inside `onActivityResult` (a child's
result, not controllable). Every one of the three best candidates was the
second kind. The sweep now prints `from :` for each hit — `caller (getIntent)`,
`caller (onReceive/onStartCommand)`, or `UNCLEAR — file has onActivityResult`
— and counts them separately, so the next pass starts with the caller-supplied
ones instead of spending the first hour on activity results.

Verified on fixtures covering all three shapes.

### 2026-10-27 — Photos' PendingIntent: fired empty, so nothing crosses

`AlbumActivity` is exported with no permission and takes a caller-supplied
`PendingIntent` in `EXTRA_NATIVE_SHARESHEET_RELAUNCH_INTENT`. The rules name
"Unsafe PendingIntent usage", so this was the last strong candidate of the
pass. What it does with it:

    421: public final void e(PendingIntent pendingIntent, cahx cahxVar) {
    424:     pendingIntent.send();

No fill-in Intent, no extras, no arguments at all. Photos fires a
PendingIntent the attacker already owns, carrying nothing of Photos'. The
attacker could have sent it themselves. `NativeSharesheetCreateAlbumActionChipActivity`
does the same (`b2.send()`), and is `exported="false"` besides.

Four strong candidates examined this pass, four closed, each in about two
minutes. That is the tool working: 1,921 exported components down to roughly
ten worth reading by hand.

**Third refinement, from what the four had in common.** Most hits hand over a
`Uri`, a `Bundle` or an app parcelable — none of which is intent redirection.
Only an Intent can be dispatched at somebody else's component; an
`IntentSender` or `PendingIntent` executes as whoever built it, so it matters
only when the app attaches its own data on the way out — `send(ctx, code,
fillIn)` rather than `send()`. The sweep now prints `takes:` per hit and
counts how many involve an Intent at all, so the next pass reads those first.

The remaining surface for this class: 24 packages still decompiling, among them
the ones never examined at all — `debugdispatch`, `playconsole`, `giant`,
`finance`, `looker`, `nest.android`, `waze` — plus the whole Android 15 set,
whose refresh has not been run yet.

### 2026-10-27 — intent forwarding on Android 16: closed, and the reason is uniform

Final state of the pass: 2,206 exported components read across 76 packages,
42 with both a source and a sink, 25 caller-supplied, 11 taking an Intent,
5 caller-supplied *and* Intent-typed. All five read by hand and closed.

Then the search was inverted — grep the whole tree for the dangerous line
rather than starting from exported components, which also covers forwarding
that lives in a helper class. That found seven more places pulling
`android.intent.extra.INTENT` out of an Intent, including names that could
hardly be better: AGSA's `ProxyActivity` and `CustomTabsTrampolineActivity`,
clouddpc's `StartForResultActivity` and `ForwarderActivity`.

Every one of them is `android:exported="false"`:

    AGSA      ProxyActivity                      exported=false
    AGSA      CustomTabsTrampolineActivity       exported=false
    Photos    SharouselContentProvider           exported=false
    clouddpc  StartForResultActivity             exported=false
    clouddpc  ForwarderActivity                  exported=false
    Fitbit    FamilyAccountActivity              no exported, no intent-filter -> false
    GMS       ManagingAppInstallBroadcastReceiver  not in any decoded manifest (Chimera)

That is the finding of the pass, even though it is not a bug: **Google
forwards Intents in plenty of places and keeps every one of those components
internal.** The class is defended systematically rather than case by case,
which is the opposite of the orphaned-permission class, where the guard was
declared and then failed to exist.

Worth carrying as a prior: in a mature Google app, a component that forwards
is almost certainly not exported, so start from the manifest's exported set
and not from the attractive-looking source line.

Cost comparison worth recording. Orphaned permissions took two nights to
exhaust and produced two bucketed duplicates. This class took one session to
exhaust on an entire device image and produced a measured zero — because the
tooling now answers "was it read, was it reachable, what did it take" instead
of leaving those to be rediscovered by hand each time.

Still open for this class: the Android 15 set (34 apps refreshed, decompiling
now, including tycho jumping V128 -> V170), and the 22 components whose
classes are not in the sources at all.

### 2026-10-27 — defect 38: the sweep read new manifests against old code

`mvrp-update-diff.sh refresh` pulls the new APK, moves the old decoded
manifest to `prev/` and deletes the cached APK. It never touched `src/`. And
`mvrp-decompile-missing.sh` skips any package that already has a source tree.

So for every **updated** app, the next sweep paired a current manifest with
whatever jadx produced last time. `com.google.android.apps.tycho` went
V128 -> V170 — forty-two releases — and was swept against V128's code. The 13
updated apps on Android 16 and the 25 on Android 15 were all read this way,
and nothing in the output indicated it.

That is the worst kind of wrong this project keeps producing: not a failure,
a confident answer about the wrong thing. The Android 15 run that looked like
a clean repeat of Android 16's result was mostly stale code plus seven
packages still decompiling.

Two fixes:

- `refresh` now deletes `$SRC/$pkg` as well, so `decompile-missing` re-does it.
- `mvrp-intent-forward.sh` compares the manifest's mtime against the source
  tree's and refuses to read a package whose sources are older, counting it
  as `packages with STALE sources` instead of folding it into the result.

Verified both directions on a fixture: stale tree reported and skipped, same
tree after `touch` read normally.

The Android 16 conclusion from earlier today survives this, because the five
candidates examined by hand were in apps whose sources were decompiled after
their refresh. The Android 15 pass has to be redone.

### 2026-10-27 — Android 16 re-swept on fresh code: same answer

All 37 refreshed packages decompiled again after the staleness fix, then the
sweep re-run:

    components read            : 2212
    both a source and a sink   : 42
      caller-supplied          : 25
      taking an Intent         : 11
    class not in the sources   : 16
    packages without sources   : 0
    packages with STALE sources: 0

Five caller-supplied, Intent-typed hits — the same five closed by hand
earlier today. GMS at 26.41 and AGSA at 17.68, both read for the first time
on their current code, produced nothing new.

So the earlier conclusion stands, and now it stands on code that matches the
devices. The stale-source defect did not change the answer here; it could
have, and there was no way to know which until the sweep was repeated.

`class not in the sources` fell from 22 to 16 with the fresh decompile, so
that blind spot is partly a decompilation artifact rather than pure
obfuscation.

Android 15 is next: its 34 refreshed packages had their source trees deleted
during the cleanup and have not been decompiled since, so that set is
genuinely unexamined — including tycho at V170.

### 2026-10-27 — "class not in the sources" was our pipeline, not obfuscation

Both sweeps end with a count of exported components whose class is missing
from the decompiled tree: 16 on Android 16, 25 on Android 15. I had been
writing that off as obfuscation — jadx renames, so the manifest name does not
resolve to a file.

It is simpler than that. `mvrp-decompile-missing.sh` only ever ran jadx on
`base.apk`, and the components are declared in base's manifest while their
classes ship in the feature splits. GMS:

    base.apk                                   dex=17
    split_AdsDynamite_installtime.apk          dex=2
    split_CronetDynamite_installtime.apk       dex=3
    split_DynamiteLoader_installtime.apk       dex=3
    split_DynamiteModulesA_installtime.apk     dex=3
    split_DynamiteModulesC_installtime.apk     dex=3
    split_GoogleCertificates_installtime.apk   dex=3
    split_MapsDynamite_installtime.apk         dex=3
    split_MeasurementDynamite_installtime.apk  dex=3
    split_config.en.apk                        dex=0
    split_config.hdpi.apk                      dex=0

Eight splits carrying code in the Tier 1 app, never read. The Dynamite
modules are where a large part of GMS actually lives.

Fixed: the script now collects every APK of a package that contains a `.dex`
and passes them all to jadx, which merges them into one tree. The filter is
"does this zip contain a dex", not a name pattern, so `split_config.*` falls
out on its own.

This does not mean there is a finding in there. It means the last two days'
sweeps covered less of each app than their output implied, and the number
that said so was sitting in every summary being read as something else.

### 2026-10-27 — defect 39: `grep -q` into a pipe, for the third time

The split-decompilation fix shipped with

    if unzip -l "$f" | grep -q '\.dex$'; then apks+=("$f"); fi

`grep -q` exits at the first match, `unzip` dies on SIGPIPE, `set -o pipefail`
fails the pipeline, and the APK is dropped. The bigger the listing, the more
reliably it happens — so the filter discarded exactly the large APKs it
existed to find. GMS was decompiled from 4 of its 9 code-carrying APKs and
produced 2,816 java files where base alone holds six figures, and the result
was marked `.jadx-complete`.

Reproduced:

    big(){ printf 'classes.dex\n'; yes 'res/x.png' | head -200000; }
    big | grep -q '\.dex$'            -> fails
    [ "$(big | grep -c '\.dex$')" -gt 0 ] -> works

**Third time in this repo.** `poc/mvrp-probe/build.sh` had
`unzip -l | grep -q resources.arsc` making a good android.jar look like a
classes-only stub, with a comment explaining the fix. `scripts/g-f004-evidence.sh`
had `dumpsys | grep -q 'granted=true'` printing that the Wallpapers app does
not hold `SET_WALLPAPER_COMPONENT` — the opposite of the measurement the
report rested on. Both were fixed with `grep -c`. I then wrote it again, in a
file whose neighbours carry the warning.

Writing the lesson in a comment next to one occurrence does not stop the next
one. The only thing that would is not reaching for `grep -q` in a pipeline at
all.

### 2026-10-28 — GMS with all nine APKs: 335 exported components, zero forwarders

With the dex filter fixed, GMS decompiled from base plus its eight
code-carrying splits: **176,453 java files**, against 2,816 from the broken
run and base-only before that.

    components read            : 335
    both a source and a sink   : 0
    class not in the sources   : 8
    packages with STALE sources: 0

Zero. Tier 1's largest app, every Dynamite module included, and not one
exported component that takes a caller's Intent and dispatches it. That is
consistent with what the rest of the sweep showed: Google forwards in plenty
of places and keeps those components internal.

The eight unresolved classes are almost certainly Chimera modules, which are
not in the APK set at all — they download at runtime into `/data`, out of
reach without root. That is a standing limit of this method on GMS, not
something another decompile pass will fix.

**The class is closed.** Across two device images: 4,400+ exported components
read, five caller-supplied Intent-typed candidates, all five read by hand and
closed, plus seven forwarding sites found by inverted grep, every one of them
`exported="false"`.

Session tally, honestly: no finding, and nine instrument defects repaired.
Four of them were silently writing results — newly installed apps invisible to
the update sweep, updated apps swept against months-old sources, feature
splits never decompiled, and large APKs dropped by `grep -q` in a pipeline.
Each one reported success while answering a different question than the one
asked.

The number that mattered most was printed in every summary for two days —
`class not in the sources` — and I explained it away as obfuscation instead of
checking. It was our own pipeline skipping the splits.

### 2026-10-28 — back to the method that actually worked here

Two classes exhausted on Android and nothing to show, so: what has ever paid
in this account?

    support.pring.jp    host takeover
    rip.photomath.net   Metabase with default credentials

Both acquisitions, both ending in control of something. Fifteen closures came
from describing a door. And the second one is the point — Metabase was found
by identifying the software on the host and then going at that software. The
twelve-path sweep run over 320 live hosts two days ago could never have found
it: every site answers `/login`, and none of them says what it is.

`acq-fingerprint.sh` asks the question that worked. Twelve probes per host,
each matched on **content** rather than status: `"setup-token"` for Metabase,
`ref: refs/heads/` for an exposed `.git`, `APP_KEY=` for a leaked `.env`,
`"cluster_name"` for Elasticsearch, `"status":"UP"` for a Spring actuator, and
so on. A catch-all 200, a 404 that echoes the path and a login wall all
produce status codes; none of them produces those strings. That is why the
earlier sweep drowned in false positives and this one can report a zero worth
believing.

Self-test checks each marker against its own software and against a generic
404 page. End-to-end on fixtures: a host serving a Metabase properties blob
and a `.env` is identified for both, a host that 404s everything yields
nothing.

The reading guide in the output is explicit about the only thing that matters
next: identified software is a lead. `.git` and `.env` are findings the moment
something is read out of them; Metabase, Jenkins, GitLab, Elasticsearch are
findings when somebody else's data comes back. Apache's status page is
Section 3 and gets dropped.

### 2026-10-28 — the AI question, answered: there is a separate program

Standing question from the Gemini-filter-bypass screenshot: are Google's AI
models in scope, and is there anything there worth testing.

Answer, from reporting around the program's launch (October 2025) — the rules
page itself would not resolve from this container, so this needs one look from
the Pi before any report is written:

**AI issues moved out of the Abuse VRP into their own AI VRP.** And the class
in that screenshot is named as excluded:

- **OUT:** prompt injection, jailbreaks, filter bypasses, alignment and
  content issues. Google's position is that a VRP "is not the right format for
  addressing content-related issues" — they ask for these through the
  in-product feedback button instead. Bypassing Gemini's filters earns
  nothing, whatever the screenshot claims.
- **IN:** security consequences. Unauthorized modification of an account or
  its data, exfiltration of a user's sensitive data, exfiltration of model
  parameters, persistent denial of service, unauthorized use of server-side
  features, and persistent cross-user HTML injection on a Google-branded
  origin without the user-generated-content warning.
- **Pay:** flagship tier (Gemini apps, Search, core Workspace) tops out around
  $20k for account/data modification; $30k with multipliers.

So the distinction that decides everything: *making the model say something*
is content and pays nothing. *Making the model do something* — act on one
user's account using content planted by another, and show the result — is the
in-scope class, and it is the same boundary-crossing standard as CLAUDE.md § 2
criterion 6. The evidence has to be the action's effect, not the prompt that
produced it.

That is testable from the devices we have, and it does not need root: Gemini
on Android with Gmail and Drive connected, where the untrusted input is an
email or a shared document that somebody else controls. Hypothesis to test —
not a lead until an effect is observed — is whether content inside a received
message can cause an action on the account that received it.

Not yet started. The acquisitions fingerprint sweep is still the open thread.

### 2026-10-28 — fingerprint probes: 12 -> 24, and three negative controls

The twelve were the obvious ones. These twelve more are the software that
turns up on exactly this kind of acquisition estate: Grafana, Kibana, Airflow,
phpMyAdmin, MinIO, Consul, Rancher, an exposed Prometheus `/metrics`, a Docker
registry catalogue, a `/version` endpoint, an `appsettings.json` with
`ConnectionStrings` in it, and `phpinfo`.

Three of them probe generic paths — `/health`, `/version`, `/metrics` — so the
marker carries all the weight: `"metadatabase"` is Airflow's word and nobody
else's, `go_gc_duration_seconds` is the Go runtime's.

And because the probe list doubled, the self-test's negative half had to grow
with it. One generic 404 was no longer enough: every marker is now also
checked against a JSON 404 that echoes the requested path and against an SPA
login wall with a password field in it, which are the two shapes that
generated the false positives in the path sweep. 24 markers, zero matches
against all three.

### 2026-10-28 — correction, and six probes chosen by reading the scope file

Correction first. I read `tail -30 ~/fp.log` as a run that had died without a
summary. It had not: `fingerprint-20261028-0110.txt` ends with the full
reading guide, so the 238-host sweep completed and its zero is real. The tail
was taken while the loop was still running — the loop prints only on a hit —
and zsh reported the job `done` at the next prompt, after the tail. The
stamp collision was real (both 02:10 jobs wrote one `-0210` pair); the early
exit was not.

The progress file stays anyway, because the thing that made the misreading
possible is still true without it: a silent loop and a zero look identical.

Then the part worth more than either fix. The first 24 probes were chosen from
a list of software that is commonly exposed. The scope file was never read for
the question "what do the host names say runs here":

    argocd-dwh-eu-dev.photomath.net        argocd-gke-app-eu-prod.photomath.net
    argocd-dwh-us-dev.photomath.net        argocd-gke-app-us-prod.photomath.net
    argocd-gke-app-eu-dev.photomath.net    argocd-gke-app-eu-test.photomath.net
    argocd-platform-eu-dev.photomath.net   argocd-gke-app-us-test.photomath.net
    argocd-platform-eu-test.photomath.net  argocd-platform-prod-eu.photomath.net

Eleven TIER0 hosts named after the software running on them, and ArgoCD was
not among the probes. Nor was Looker, on a domain whose TIER0 entries include
keybox, pbvpn, gw2-pbvpn and rampart. This is the same error as the path
sweep in a different coat: asking a generic question of a specific estate.

Added, named after what this scope contains: ArgoCD (`"KustomizeVersion"`),
Looker's API (`looker_release_version`), PAN-OS GlobalProtect, Harbor,
Vault (`"sealed"`), Keycloak. Thirty probes now.

`PROBE_ONLY='ArgoCD|Looker'` runs only the named ones. That exists for § 7,
not for speed: a longer list should not mean hitting every host again for
answers already written down.

Self-test gained one negative that matters here — ArgoCD's own
`{"error":"no session information","code":16}` must not match the ArgoCD
markers. Identifying ArgoCD is informational. The question is whether
`/api/v1/applications` answers without a token, and that answer is somebody
else's deployment inventory.

### 2026-10-28 — the TIER0/1 live table, read properly for once

The table had been used only as a list of hosts to probe. Read as evidence, it
says two things the probes cannot.

**The four live ArgoCD hosts are behind IAP.**

    argocd-gke-app-eu-prod.photomath.net   TIER0  200  GSE  Sign in - Google Accounts
    argocd-gke-app-eu-test.photomath.net   TIER0  200  GSE  Sign in - Google Accounts
    argocd-gke-app-us-prod.photomath.net   TIER0  200  GSE  Sign in - Google Accounts
    argocd-gke-app-us-test.photomath.net   TIER0  200  GSE  Sign in - Google Accounts

The other seven argocd names are DEAD. So the six new probes would have come
back zero on all four, and that zero would have meant "IAP answered", not "no
ArgoCD". Third time: the path sweep, the `grep -q` APK filter, and now this.
The instrument's own shape keeps getting recorded as a measured absence.

`acq-iap-gap.sh` asks the question that is actually open. IAP binds to a
backend service, not to a path, so a health endpoint on a second backend or a
route added after the binding answers without it. Fourteen GETs per host, and
`/` is the baseline: if `/` is not Google's login page the premise is wrong for
that host and the script says so instead of reporting fourteen bypasses.
Classification is by content — Google's login page or a redirect to it is IAP;
ArgoCD's `{"error":"no session information"}` is the backend, which means the
proxy was passed. Status 000 is dropped before classifying, because an empty
body would otherwise read as a bypass and turn every timeout into one.

Expectation stated before running: zero. IAP usually covers everything. The
value is that zero will be a real zero.

**And twenty-odd DEAD TIER0/TIER1 hosts have never been resolved.**

    metabase.photomath.net   keybox.looker.com     pbvpn.looker.com
    rampart.looker.com       corp.looker.com       gw2-pbvpn.looker.com
    lookermail.com           lookerdata.com        lookercdn.com
    lk.looker.com            instancemanagerui.looker.com   + 7 argocd

DEAD is one label over three facts: the name does not exist, the name points
somewhere else, or there is a machine not serving HTTP. Only the middle one
matters, and it is the class that has actually paid in this account —
support.pring.jp was a host takeover.

`acq-dead-dns.sh` separates them. It matches the CNAME target against services
where hostnames are claimed by whoever asks first, and deliberately does not
match provider error bodies: matching `DEPLOYMENT_NOT_FOUND` is how the Wiz
attempt ended up reporting a precondition. Alphabet's own infrastructure is
excluded outright — a CNAME from Google to Google is not a candidate.

Its verdict word is CHECK, never VULNERABLE, and the reading guide spells out
the four steps § 3 demands: confirm the provider will even accept the hostname
(modern Vercel and Netlify refuse a domain bound to another account), claim it,
serve a canary, fetch the canary over the target name — and then still show
shared cookies, OAuth allowlisting or real traffic, because a host nobody
visits is informational even after a successful takeover.

A resolver failure is its own verdict, NO-DNS, and the control refuses to run
if `google.com` will not resolve. Without that, one broken resolver turns
twenty hosts into twenty takeover candidates.

### 2026-10-28 — IAP closed with a real zero; three TIER0 names point at a zone that answers nothing

**IAP: zero, and this one is worth believing.** Four hosts, fourteen paths
each, every single one `302 IAP`. The prediction written down before the run
was zero, and the reason holds: IAP binds to the backend service, so there is
no per-path seam to find. Class closed.

The lock worked, incidentally — `pgrep` shows three lines per run because
`{ ... } | tee` forks a subshell with the same argv. The PROBE_ONLY run started
at 00:59:33Z and the previous one at 20:19Z, four and a half hours apart.

**The DNS sweep found the thing worth working on.** 113 unreachable TIER0/TIER1
hosts split as: 68 NXDOMAIN, 19 with an IP but no HTTP, 14 CNAME into a third
party that resolves, 9 with no record, and three that matter:

    api.pring.jp         TIER0  CNAME -> api.aws-zaipon.com.         resolves to nothing
    dev-api.pring.jp     TIER0  CNAME -> dev-api.aws-zaipon.com.     resolves to nothing
    future-api.pring.jp  TIER0  CNAME -> future-api.aws-zaipon.com.  resolves to nothing

Three TIER0 API hostnames delegated to a zone that answers nothing, on the
same estate as this account's one host-takeover payout — `support.pring.jp`.
Zero CHECK verdicts, because `aws-zaipon.com` is not a provider on the
claimable list; it is somebody's own-looking domain, which is why it is more
interesting rather than less.

Everything now turns on one question: **is `aws-zaipon.com` registered?**

    not registered          register it and three TIER0 hostnames are yours.
                            Domain takeover, strictly worse than the subdomain
                            kind, and § 3's demand — prove the claim — is
                            satisfiable for the price of a .com.
    registered, delegated   the owner deleted the records. Theirs.
    registered, no NS       still theirs.

`acq-cname-apex.sh` answers it with RDAP rather than whois, because RDAP
returns 404 for a name nobody holds and 200 with the registrar for one
somebody does, as data instead of a paragraph that varies per registry. whois
is kept as a second opinion and a disagreement is printed as a disagreement
rather than resolved silently. Two controls: RDAP must answer 200 for
google.com, and it must NOT answer 200 for a made-up name — without the second,
a registry that answers 200 for everything would mark every target registered
and the sweep would look clean. `.jp` has no public RDAP and is routed to
whois by name.

It registers nothing. The reading guide carries the six steps § 3 requires if
the answer is "free", including the two that are easy to skip: serve only the
canary, and fetch it over `api.pring.jp` rather than over the apex, because the
fetch over the target name is the evidence and the apex fetch proves nothing.

Also: `acq-dead-dns.sh` now prints every CNAME into someone else's zone instead
of only counting them. The claimable-provider list is not complete, and a
service nobody has fingerprinted is where the next one comes from.

### 2026-10-28 — fingerprint class closed at zero; and I printed the wrong verdict

**Three completed sweeps, zero identified.**

    238 hosts x 12 probes  ->  0 of 238
     82 hosts x 24 probes  ->  0 of 82    (progress file: 82/82)
     82 hosts x  6 probes  ->  0 of 82    (progress file: 82/82)

All three finished — the progress file is what makes that checkable rather
than assumed. The live acquisitions estate is Google's own frontends (GSE,
sffe) plus S3 and CDN origins; there is no exposed self-hosted admin software
on it. The class is closed with a zero worth believing, which is more than the
path sweep ever produced.

**And on aws-zaipon.com the script printed a wrong sentence.** It said
"REGISTERED but not delegated (no NS)" about a domain whose own output two
lines above read:

    apex   aws-zaipon.com : SERVFAIL   NS=-   SOA=-
    rdap ldhName: NS-577.AWSDNS-08.NET

Two defects in one line. SERVFAIL was read as "no nameservers", when it means
the resolver could not get an answer out of the delegated servers — a
different and much more interesting state. And the `ldhName` was pulled with
sed, which took the first one in the document; that belonged to a nameserver,
so a Route 53 hostname was printed where the domain name goes.

Fixed by asking the right servers. The parent TLD zone is queried directly for
the delegation, then each delegated nameserver is queried for the zone's SOA.
Parent answers always; the delegated servers are the ones that may not. RDAP
is now parsed with python3 instead of sed, and prints domain, status,
nameservers and registrar separately.

New verdict for the state this actually is: **REGISTERED, DELEGATED, AND THE
ZONE IS GONE** — the delegation outlived the zone.

The chain, as far as it is measured:

    api.pring.jp         TIER0, Google acquisition
      -> CNAME -> api.aws-zaipon.com
                    -> delegated to Route 53 nameservers
                         -> which hold no SOA for the zone

And § 4 applied honestly, before any enthusiasm: the next link is "can the
zone be recreated at that provider on the same nameserver set", and on Route 53
that means creating and deleting hosted zones until the assignment matches —
unbounded attempts, a cost per zone, and leaning on a provider that is not the
party being tested. That link cannot be tested cheaply, so this is a
**HYPOTHESIS, not a lead**, and the reading guide says so where it will be
read. Reporting the dangling delegation by itself is the Wiz mistake with
different nameservers.

What is worth doing first costs nothing: find out whether any live app
resolves api.pring.jp, whether other hostnames point at the same apex, and
whether the apex is registered to pring/Google or to a third party. A third
party holding the delegation target of a TIER0 API name is worth saying out
loud even with no takeover, because they can serve that hostname.

**Also fixed, in three scripts: `curl ... || echo 000`.** curl's own
`%{http_code}` is already 000 when the transfer never happened, so the
fallback could only ever append a second value to a real one. The control line
printed it plainly — `RDAP answers 404000 for a made-up name` — a 404 and a
000 concatenated. In the fingerprint sweep that string matched no case in
`000|40[13]` and would have been treated as a live status.

### 2026-10-28 — aws-zaipon dropped; three S3 CNAMEs are the real lead

**aws-zaipon.com answered and it is Google's.** Registrar MarkMonitor,
registrant CA/US, all three `client*Prohibited` locks, created 2017, renewed to
2027. That is Alphabet's standard registrar posture. All four Route 53
nameservers return REFUSED, so the hosted zone is deleted and the delegation
outlived it — but the registration is theirs and cannot be bought, and the only
route left is grinding hosted-zone creations at Route 53 until the nameserver
assignment matches. § 4 says that is a hypothesis. **Dropped**, and logged as
dropped so it is not rediscovered as exciting in a month.

**The TIER2/3 DNS sweep is where the lead is.** Three TIER3 names CNAME the
bare S3 endpoint:

    repos.nestlabs.com           TIER3  -> s3.amazonaws.com.
    server-logs.nestlabs.com     TIER3  -> s3.amazonaws.com.
    thirdparty.ops.nestlabs.com  TIER3  -> s3.amazonaws.com.

A CNAME to the bare endpoint means S3 routes on the Host header, so the bucket
name is the hostname. Bucket names are global and first-come. If those buckets
were deleted, the names are free.

This is the one takeover class in this estate where § 3 is cheap to satisfy:
creating a bucket is free and instant, so "claim it and serve a canary" is
minutes of work instead of the unbounded grind that killed aws-zaipon.com. The
difference between a hypothesis and a lead here is purely the cost of the next
link, which is what § 4 actually asks.

Triaged out of the same output, with reasons, so none of it gets re-walked:

    em*.fitbit.com, email/gsemail/gslink -> sendgrid.net
        claiming a SendGrid link-branding host needs their account, and the
        impact is email link tracking. § 3.
    partners/support.fitbit.com -> *.live.siteforce.com
        the Salesforce org id in the target is Fitbit's. Not claimable.
    frontdoor-*.elb.amazonaws.com, video/pro.* -> ELB names
        the random suffix means the name cannot be recreated.
    future-www.pring.jp -> future-www.aws-zaipon.com
        same dead zone, same hypothesis.
    m.fitbit.com -> mkto-sj220117.com   [DANGLING]
        Marketo. Worth one apex lookup — Marketo normally holds these, but it
        is ten seconds and m.fitbit.com is a hostname worth having.

`acq-s3-claim.sh` asks the only question that matters: does S3 itself say no
bucket holds that name. It reads the `<Code>` element, never loose words, and
the self-test's first negative is an HTML 404 with the string `NoSuchBucket`
sitting in its prose — which must not read as GONE. That exact confusion is
how a sweep turns every 404 on the internet into a takeover, and this repo has
already made the equivalent mistake three times.

Two live controls before any host: a made-up bucket name must return
NoSuchBucket, and a bucket that exists must not. Without the second, an S3
endpoint answering NoSuchBucket for everything would mark all three free.

Each host is asked three ways — the target hostname, path style, and
virtual-host style — because they can disagree, and the reading guide says to
trust the path-style answer since a virtual-host 404 is usually a region
redirect.

The reading guide also puts § 3's harder half where it will be read: after the
canary proves the claim, the report still has to answer who reaches the
hostname. `repos` and `server-logs` sound like a package source and a log
sink, which would mean real traffic, but sounding like one is not evidence.

### 2026-10-28 — the published acquisitions estate is closed, and a fourth blind spot

Every candidate the DNS sweep produced is now resolved, and none of them is a
finding.

**11 CHECK:**

    repos / server-logs / thirdparty.ops .nestlabs.com -> s3.amazonaws.com
        All three buckets answer AccessDenied on all three URL forms — target
        hostname, path style and virtual-host style, nine answers out of nine.
        AccessDenied means the bucket exists. The names cannot be claimed.
        Confirmed a second time from a phone on a different network, so this is
        not the Pi's view of AWS.
    em*.fitbit.com, email/gsemail/gslink -> sendgrid.net
        sendgrid.net's zone is live on six nameservers. Claiming one of these
        needs a SendGrid account that will accept the hostname, and what it
        buys is email link tracking. § 3.

**3 DANGLING:**

    dev-www / future-www .pring.jp -> *.aws-zaipon.com
        Same Google-owned domain as api.pring.jp, same deleted Route 53 zone.
    m.fitbit.com -> mkto-sj220117.com
        Registered through COM LAUDE — Marketo's own corporate registrar —
        delegated to ns1.marketo.com and ns2.mktdns.com, both REFUSED. The
        identical shape to aws-zaipon.com: the provider owns the domain and
        deleted the zone. Taking it would mean controlling Marketo's
        nameservers.

So: fingerprint zero on 238 + 82 + 82, IAP zero on 4 x 14, and every takeover
candidate across 471 unreachable hosts closed. The acquisitions estate **as
published** is done.

**And the fourth instrument blind spot, found while reading the counts.**
`NO-RECORD` came back 115 times, and `dnsinfo` only ever asked for `A`. A host
with only an AAAA record answers NOERROR with no address, which this script
called NO-RECORD — "nothing here" — and which `acq-live.sh` would have called
DEAD if the Pi has no IPv6 route. The same host counted as absent twice, by
two tools, for the same reason.

Now asks AAAA as well, with a V6-ONLY verdict that says the live sweep
probably could not reach it. The self-test has a dual-stack fixture
specifically because the first version matched on a colon appearing anywhere
and would have called every dual-stack host v6-only.

The running list of defects that silently wrote results is now five: new apps
invisible to the update sweep, updated apps swept against stale sources,
feature splits never decompiled, large APKs dropped by `grep -q`, and now
v6-only hosts recorded as having no address.

**Open question that decides what happens next.** The scope file is
hostname-exact and default-deny, so an unlisted name under a listed domain is
OUT-OF-SCOPE by our own encoding. Whether that matches Google's actual rule for
acquisitions is unverified — bughunters.google.com does not resolve from the
container, so it has to be read from the Pi. If unlisted subdomains are in
scope, the published tier list is Google's inventory rather than the boundary,
and subdomain enumeration over nestlabs.com, fitbit.com, photomath.net,
cameyo.com, siemplify.co, owlchemylabs.com, elastifile.com and neverware.com is
untouched surface. If not, this estate is finished and the Android AI VRP
rogue-action track is next.

### 2026-10-28 — the scope file was removing surface Google had granted

The question was whether an unlisted subdomain of a listed domain is in scope.
bughunters.google.com renders its rules in JavaScript and the curl came back
empty, so the authoritative answer came from the file that generated our scope
in the first place — Google's own tier protobuf, already in this repo:

    domain: {
      fqdn: "cameyo.com"
      tier: TIER0
      propagate_tier_to_direct_subdomains: true
    }

The flag has been there all along. `scope-from-tiers.sh` read `fqdn` and
`tier` and nothing else, so it wrote only the named hosts, and every unlisted
direct subdomain of a propagating domain was out of scope **by our own
encoding**. 28 domains carry it, two at TIER0: **cameyo.com** and
**googleacquisitionmigration.com**. The other 26 are debugproject.com variants
at TIER3.

This is the sixth defect that silently wrote a result, and the second of them
to narrow scope while every number in the output agreed with itself. The
previous one was the hand-maintained scope.yaml missing 84 of 195 TIER0/TIER1
hosts — which is the reason this generator exists.

Encoded as `+.cameyo.com`, a new pattern meaning exactly one label.
`*.cameyo.com` was the obvious choice and is wrong: bash globs match dots, so
it would have put `a.b.cameyo.com` in scope, which Google did not grant, and
§ 0 says the doubtful case is out. `+.` is treated as a wildcard in every pass
of scope-check, so it cannot beat an explicit TIER4 exclusion.

`scope-check-tests.sh` now holds the rules as tests, because scope has been
wrong twice in the quiet direction and self-agreeing output is exactly what
both failures produced:

    ok   online.cameyo.com                     IN   listed direct subdomain
    ok   anything-new-9f3a.cameyo.com          IN   UNLISTED direct subdomain
    ok   a.b.cameyo.com                        OUT  two labels is not direct
    ok   deep.nested.x.cameyo.com              OUT  three labels is not direct
    ok   definitely-not-real-9f3a.nestlabs.com OUT  nestlabs.com has no flag
    ...  11 checks, 0 failures

**What this opens.** Direct subdomains of cameyo.com and
googleacquisitionmigration.com are TIER0 and have never been enumerated —
every sweep so far ran against Google's published host list, which is their
inventory and not the boundary. Cameyo is a small acquisition, which is where
forgotten hosts live, and this account's two paid findings both came from
acquisitions.

Also: the AAAA fix found 3 V6-ONLY hosts in the TIER2/3 table, down from 115
NO-RECORD to 112. Three in-scope hosts that no sweep has ever reached, because
every tool asked for A and the Pi has no v6 route.

### 2026-10-28 — 41 TIER0 hosts nobody has ever looked at

Certificate transparency on the two propagating TIER0 domains:

    cameyo.com                      53 names, 44 direct, 41 not in Google's list
    googleacquisitionmigration.com   0 names  (wildcard cert or none public)

Forty-one direct subdomains of cameyo.com that are TIER0 in scope by Google's
own flag and appear nowhere in the published host list. Every sweep this repo
has run was against that list.

The names say a great deal on their own:

    jenkins.cameyo.com        wazuh.cameyo.com         server.cameyo.com
    ncpanel  nmail  nwebmail  nwebdisk  nkb  nsupport  ncpcalendars  ncpcontacts
    partnerportal + 16 partner-*       prima-jsmedley-uat     devonline
    multisite  ssio  ssl1  status  training  helpcenter  info  blog  autodiscover

Jenkins and Wazuh both have unauthenticated surface. The `nc*` cluster looks
like a self-hosted suite. Sixteen `partner-*` hosts plus a partner portal is a
multi-tenant shape, and cross-tenant isolation is named in § 2 as the kind of
impact that counts.

**Not writing probes for any of that yet.** The ArgoCD episode taught the
opposite lesson: read the table as evidence first. `acq-live.sh` captures each
host's title and server header, which is how "Sign in - Google Accounts"
identified IAP, and forty-one titles beat guessed markers. A wrong marker
produces a false negative that looks exactly like a measured zero, and this
repo has four of those on record already.

`acq-live.sh` gained `HOSTS_FILE`, one hostname per line, because its host list
came from the protobuf and these names come from CT. The list only decides what
is considered; every host still passes through scope-check before it is
touched, so an out-of-scope name in the file is skipped — verified with
`a.b.cameyo.com` and a made-up nestlabs host, both refused.

### 2026-10-28 — cameyo closed; six unlisted hosts left, two of them AEM

**cameyo.com, measured and closed.** 44 CT names, 42 on one Google Cloud load
balancer at 34.54.191.172, and 39 of them returning a byte-identical 300-byte
page — title `default`, a meta refresh to `/login`. So jenkins., wazuh.,
ncpanel., nwebmail. and the rest are stale DNS from Cameyo's old self-hosted
estate, all now pointing at the Google-fronted app. There is no Jenkins there.
The names were the exciting part and the names were wrong; the hash was the
measurement.

What is actually there: the app behind `/login` (online. and multisite. share
a body), a Freshdesk helpcenter, kb. 301ing to it, and Google's marketing
site.

The one header worth chasing was `frame-ancestors 'self' *.cameyo.com
https://cameyo.com:* https://*.ninjaexcel.com` — identical on every host
including `/login`, and since CSP frame-ancestors overrides `X-Frame-Options:
DENY` in modern browsers, the effective policy is the CSP. But ninjaexcel.com
is registered through Amazon Registrar, its Route 53 zone is live on four
nameservers, and www.ninjaexcel.com serves a real Elementor site. A live third
party, not a claimable one. **Dropped.**

And `/login` offers no signup or trial, so the cross-tenant route through the
sixteen `partner-*` tenants is shut: § 7 requires proving access with our own
test data, and there is no way to get a tenant.

**The other propagating domains, however, gave six unlisted hosts:**

    debugproject.com :  count.  data-docs.
    debug.com        :  aem-dev.  aem-stage.  nwww.

TIER3, so the ceiling is low, but these are the only in-scope hosts left that
nothing has ever looked at. Two names say Adobe Experience Manager, and a
forgotten AEM dev or stage instance is a real class: `/bin/querybuilder.json`
on a misconfigured instance returns JCR nodes without a credential, which is
content rather than a door. `data-docs` is the Great Expectations name for a
generated site of data-quality reports, which tends to contain real column
values.

Live sweep first, probes second — the cameyo round is the argument for that
order, where four promising names were one catch-all.

### 2026-10-28 — acquisitions closed; AI VRP protocol written before the first test

`data-docs.debugproject.com` answers `x-pages-private: 1` and 302s to GitHub
Pages auth — a private Pages site with its ACL working, not a takeover.
`count.debugproject.com` is Verily's public page for the mosquito programme.
`aem-dev`, `aem-stage` and `nwww.debug.com` all CNAME `www3.l.google.com` and
return the same Google 404 with one identical hash: stale names, no AEM. The
acquisitions estate is finished.

Tally for the estate, since it took two days: 402 live hosts fingerprinted
with 12 to 30 content-matched probes, zero software identified. 4 IAP hosts x
14 paths, zero past the proxy. 471 unreachable hosts resolved, 14 takeover
candidates, all closed — three S3 buckets that exist, nine SendGrid hosts
needing their account, and three domains whose provider owns the registration.
41 unlisted TIER0 cameyo hosts, which turned out to be 39 aliases of one
catch-all. 6 unlisted hosts on the other propagating domains, all closed.

No finding. Six instrument defects repaired, two of which were narrowing scope.

**Next: AI VRP rogue actions on Gemini for Android**, and the protocol is
written down first — `results/google/AI-VRP-PROTOCOL.md` — because the failure
mode here is not missing the bug, it is watching a model say something odd and
calling it one.

The line, fixed before looking: the model SAID something is content and is
excluded by name; the model DID something is the in-scope class. Evidence is
never the prompt and never the reply, always the effect seen from the other
account — a file A can now open, a message in A's inbox, a setting in B that
survives clearing the conversation.

Three rungs, each observable without any outside infrastructure, stopping at
the first that fails. Expected outcome is refusal: this is the most-attacked
surface Google has. The point is that the zero will be a real one.

### 2026-10-28 — the update round found nothing, and a third scope file was excluding

**Three updated packages, nothing new.** ai.edge.gallery 1.0.20→1.0.21,
cloudconsole 26.10.191400→191401, docs 2.26.427.3→.4, all refreshed with APK,
manifest and sources together, 60,820 java files decompiled.

intentfwd: 81 components read, `class not in the sources: 0`, five hits — and
every one already closed in this log. ProjectorActivity is S41, GetMetadataActivity
is S43, SendTextToClipboardActivity takes a Uri, DocumentOpenerActivity is behind
GLOBAL_SEARCH and takes a Bundle, UploadMenuActivity takes a ScanMetadata.
**cloudconsole, the Tier 1 app, produced zero hits and zero open providers.**

manifest-gaps: two open providers in docs, both already closed — S28
(`storage.legacy`, reachable and empty) and S29 (`statesyncer`, no rows).

That is dedup working. The expensive failure would have been re-reading S28 as
new, and it was close: the 2026-10-22 note records `LegacyStorageBackendContentProvider`
as having "no grantUriPermissions", while the current manifest reads

    exported=true  authorities=...storage.legacy
    grantUriPermissions=true  forceUriPermissions=true

I said in chat that grantUriPermissions does not remove a guard, which was not
enough. **`forceUriPermissions` adds one**: it makes the framework require a URI
grant on every access regardless of the provider's own checks, which is exactly
the check the old note found sitting behind a disabled feature flag. Whether it
changed in .4 or the old reading was incomplete, today's state is more closed
than it was, not less.

**And the third hand-maintained scope file caught excluding.** Generated
`config/scope-google-tiers.yaml` from `google_domains_tiers.asciipb`: 485 in
scope, 97 TIER4 excluded, 0 domains with the propagate flag — so the Google
program is hostname-exact, unlike acquisitions.

Then compared its 39 TIER0 hosts against the hand-maintained
`config/scope-google.yaml`:

    missing: 38 of 39

mail.google.com, accounts.google.com, play.google.com, gemini.google.com,
console.cloud.google.com, myaccount.google.com, passwords.google.com,
takeout.google.com, vault.google.com, issuetracker.google.com — none of them
in the file that scope-check reads by default. The same failure as the
acquisitions file's missing 84 of 195, for the third time.

`scope-from-tiers.sh` also had a control bound to one input: it asserted
`api.appsheet.com` survived the pipeline, which exists only in the acquisitions
protobuf, so pointing the script at the Google one failed a control that was
really asking "is this the acquisitions file". The sentinel is now the first
TIER0 host of whatever source is being processed. Verified by regenerating the
acquisitions file and diffing: identical apart from the timestamp.

### 2026-10-28 — Google's scope file lists a domain a stranger bought three weeks ago

The Google VRP liveness sweep, re-run after the redirect fix, listed fourteen
in-scope hosts whose server header is not one of Google's own frontends. One
of them:

    picasa-software.com   TIER3   200   GitHub.com   (no title)

It serves 133 bytes reading "This domain is for sale; to purchase it, please
contact me at <an individual's gmail address>", `www` CNAMEs to a personal
GitHub Pages account, and it is line 1706 of Google's own
`external_domains_google.asciipb` at TIER3.

The ownership lookup decided it in one line:

    Creation Date: 2026-10-10T23:02:23Z
    Registrar:     Wix.com Ltd.
    Name Server:   NS0/NS1.WIXDNS.NET

Eighteen days old. Picasa was discontinued in 2016, Google let the name go,
somebody registered it fresh and put a for-sale page on it. **Not a takeover of
a Google asset and not reportable** — the domain is not theirs to lose any more.

**The real result is what it says about our own safety.** That host is in our
generated scope file, `scope-check.sh` calls it IN-SCOPE, and the fingerprint
sweep would have put thirty probes into a private individual's website while
every control in this repo printed POSITIVE. § 0 calls testing outside scope
the one unrecoverable mistake, and nothing here was looking for this: every
check so far asked "is this name on the list", never "does the list still
describe reality". Being on the target's own published list is not proof the
target still owns it.

`acq-ownership.sh` asks the second question. The signal is the registration's
**creation** date, not its updated date — a renewal moves Updated, only a drop
and re-register moves Created, so a twenty-year-old brand reading as created
last month has changed hands whatever the scope file says. Registrar is a
secondary signal: corporate defensive registrars on one side, card-and-go
registrars on the other, neither decisive alone.

Its controls are today's two real cases as fixtures, which is the first time
this repo has had ground truth to test a classifier against: an old MarkMonitor
registration must pass, a fortnight-old Wix one must not, a new domain at a
corporate registrar must read as RECENT rather than NOT-THEIRS, and an old
domain at a consumer registrar must pass because small acquisitions use them
legitimately. Live control: google.com must read as owned before any target is
looked up.

Output is an exclusion list, not findings. 324 unique apexes across the two
scope files have never been checked this way.

### 2026-10-28 — all twelve UNREGISTERED were the instrument

The first ownership run flagged 12 of 132 apexes as UNREGISTERED. Checked by
hand against whois, **every one was wrong**:

    com.ru  g.cn  g.co  gle  goog  goo.gl  google
    googlecnapps.cn  openthread.io  wiz.io  youtu.be  youtube

`whois-says-free=0` on all twelve, and most resolve — g.co, goo.gl, youtu.be,
g.cn, wiz.io, openthread.io all answer DNS. Three separate defects, in one
output:

1. **rdap.org answers by redirecting** and the fetch had no `-L`, so every TLD
   outside com/net/org was read from the redirect rather than the answer.
2. **`gle`, `goog`, `google`, `youtube` are TLDs Google operates**, not
   registrations. RDAP has nothing to say about a bare TLD label, so it 404s,
   and a 404 was being read as "nobody holds this name".
3. **`com.ru` is a public suffix** like `co.uk` and was not in the list, so the
   apex came out as the suffix itself.

Had this gone unchecked the next step was buying a domain, which makes it the
most expensive defect of the session even though it found nothing. It is also
the first one that erred towards *more* surface rather than less: the previous
seven all said "nothing here".

Fixed: `-L` with a control that fetches abc.xyz — Alphabet's own, registered
since 2015, on a TLD routed through rdap.org — and refuses to run unless it
answers 200. UNREGISTERED now takes a whois second opinion before it is
written, and RDAP-404 against a whois record is recorded as DISAGREE rather
than resolved silently. Names under a TLD the target operates are OK-BRAND-TLD
without a lookup, bare TLD labels are skipped as BARE-TLD, and the public
suffix list grew.

Also worth recording: the run itself was cut short by the Pi's network
dropping mid-sweep — 24 lookups returned RDAP-000 and the ssh session died —
so it has to be repeated under `setsid` regardless of the parsing fixes.

### 2026-10-28 — Google changed the scope files today, and confirmed our picasa measurement

A `git pull` of google/bughunters on the phone showed commit 41b589f landing
while we were working:

    external_domains_acquisitions.asciipb | 320 ----------------------
    external_domains_google.asciipb       |  16 +-

**The whole photomath estate was removed from acquisitions scope** — including
`metabase.photomath.net`, which is where this account's second Fixed finding
came from. Every argocd host we spent the morning on is in that deletion too.
Our sweeps were valid when run; the scope files here are now stale and need
regenerating from the new protobufs.

The Google file gained `express.cloud.google.com` at TIER0 and promoted
`connected.google.com` from TIER1 to TIER0.

**And `picasa-software.com` is gone from it.** Count: 0. We measured this
morning that the domain was re-registered through Wix on 2026-10-10 by someone
selling it, and concluded it was no longer Google's. Google removing it the
same day is independent confirmation of that measurement — the first time this
session an instrument's verdict has been corroborated from outside.

### 2026-10-28 — Gemini CLI: in scope at OT1, and a trust boundary worth testing

`oss-repository-tier/README.md` line 51 lists
`https://github.com/google-gemini/gemini-cli` at **OT1**, the top tier of the
OSS VRP. § 0 clears.

What makes it worth the time, in the product's own words:

    --skip-trust      Trust the current workspace for this session
    --approval-mode   default | auto_edit | yolo | plan
    --policy          Additional policy files or directories to load
    --raw-output      WARNING: This can be a security risk if the model output
                      is untrusted

So the vendor declares a trust boundary around the workspace and an approval
layer above it. The question is the one that pays: **can a repository's own
files lower that, so that cloning it and running `gemini` executes something
the user never approved?** The prize is on disk already — `~/.gemini/`
contains `oauth_creds.json` (1.8 KB) and `google_accounts.json`.

The shape that counts, fixed before testing:

    -y / --yolo / --skip-trust used        NOT a finding — consent was given
    a prompt asked for a command            NOT a finding — that is the product
    default mode, folder not trusted,
    workspace file takes effect             THIS

**Measurement hazard, found before it ruined the run.** The phone's
`trustedFolders.json` reads:

    { "/data/data/com.termux/files/home": "TRUST_FOLDER" }

The entire home directory is trusted, so anything cloned under `~` inherits it
and any "untrusted workspace" test there is answering a different question.
The test has to live outside `$HOME`. That is the tenth time this session an
instrument's own configuration would have produced a result about itself.

Also upgraded 0.65.0 -> 0.66.0 first: a finding on a version behind the latest
is on Google's kill list.

### 2026-10-28 — Gemini CLI 0.66.0: three workspace vectors, three measured zeros

In scope at OT1. Tested on Termux, Android 16, upgraded 0.65.0 -> 0.66.0 first
because a finding on an older version is kill-listed.

**Vector 1 — workspace extension.** `.gemini/extensions/poc/gemini-extension.json`
with an `mcpServers` block. `gemini extensions list` printed "No extensions
installed" in both a trusted and an untrusted directory: the workspace is not
an extension discovery path at all, they must be installed or linked by hand.
**My PoC was in the wrong place**, and checking discovery before building the
payload would have saved an hour. The lesson is the session's: verify the
instrument reads the file before measuring what it does with it.

**Vector 2 — workspace `settings.json` with `mcpServers`.** This one is read,
and the trust boundary holds cleanly:

    trusted dir    ✗ poc: sh -c touch ...CANARY-TRUSTED (stdio) - Disconnected
                   CANARY-TRUSTED created        <- control fired

    untrusted dir  Warning: MCP servers are configured but disabled because
                   this folder is untrusted. User-level servers are also
                   suppressed in untrusted folders to prevent accidental
                   side-effects.
                   ○ poc: ... - Disabled
                   no canary

The control is what makes this readable: the command really does run when the
folder is trusted, so the untrusted zero is about trust and not about a broken
PoC.

**Vector 3 — project hooks.** The docs make a specific, checkable promise:
hooks are fingerprinted, and a hook whose name or command changes "via
`git pull`" is treated as new and untrusted. Headless mode forbids asking the
user at all — `policies/non-interactive.toml` denies `ask_user` at priority
999 — so the question was whether an unapproved hook fails open there.

It does not. A never-approved `SessionStart` hook printed:

    WARNING: The following project-level hooks have been detected in this
    workspace: - poc-canary
    These hooks will be executed. If you did not configure these hooks or do
    not trust this project, please review the project settings...

and then ran. **That is the documented behaviour, word for word** — "you will
be warned before it executes" — so it is not a finding. Changing the command
and running again produced the warning a second time, so the fingerprinting
does not fail open either.

**Blocked, and worth recording for next time:** the account's OAuth tier is
cut off for this CLI (`IneligibleTierError ... migrate to Antigravity`) and the
AI Studio key's project is out of prepay credit (402 RESOURCE_EXHAUSTED), so
the agent loop never ran. Everything above fires before the first model call;
anything that needs tool execution — `BeforeTool`/`AfterTool` hooks, the policy
engine's tool decisions, auto-approval — is untested.

**And a caveat that limits all three results:** `docs/cli/trusted-folders.md`
says the Trusted Folders feature is **disabled by default**. This phone has it
enabled, which is why vector 2 showed a boundary at all. What a *default*
install loads from a workspace is therefore still unmeasured, and that is the
first thing to check next, not the last.

### 2026-10-28 — Gemini CLI workspace trust: closed from four sides

Interactive mode was the last untested path, and it is the one where an
ordering bug would live: `SessionStart` fires at session start, the trust
dialog is answered after. Measured with the dialog left open on screen and the
canary checked from a second Termux session:

    dialog open, unanswered     no canary   — nothing ran before the decision
    "Don't trust" chosen, quit  no canary   — nothing ran after it either

The dialog itself answers the design question:

    Do you trust the files in this folder?
    Trusting a folder allows Gemini CLI to load its local configurations,
    including custom commands, hooks, MCP servers, agent skills, and settings.
    These configurations could execute code on your behalf or change the
    behavior of the CLI.

Hooks are named in that list, and the session banner carried
`Skipping project agents due to untrusted folder` throughout.

**The class is closed from four sides, each with a control behind it:**

    workspace extension        not a discovery path at all
    workspace settings + MCP   disabled when untrusted, and the CLI says why
    hooks, headless            the process refuses to start
    hooks, interactive         nothing runs before or after "Don't trust"

The control that makes these readable: in a *trusted* folder the same MCP
command and the same hook both really did create their canary files. The zeros
are about trust, not about a broken proof of concept.

**One documentation inconsistency, not a vulnerability.**
`docs/cli/trusted-folders.md` says the feature is "disabled by default" and
must be switched on with `security.folderTrust.enabled: true`. That key has
never been in this machine's settings — the backup of the original file
contains only an auth block — yet the gate was enforced in every test. The
bundle carries both defaults for the same setting:

    settings.merged.security.folderTrust.enabled ?? true
    folderTrust?.enabled ?? false
    params.folderTrust ?? false

The binary is safer than its documentation, so this is a docs/consistency
issue for a GitHub issue rather than `g.co/vulnz`. Worth filing because the
opposite drift — docs promising a gate the code does not apply — is the same
bug with the sign flipped.

**Still untested, and the honest list for next time:** everything downstream of
the agent loop, because it never ran. The account's OAuth tier is cut off for
this CLI and the AI Studio key's project is out of prepay credit, so
`BeforeTool`/`AfterTool` hooks, the policy engine's tool decisions and
auto-approval are all unmeasured. `policies/` holds eight TOML files and only
`non-interactive.toml` was read. `--raw-output` carries the CLI's own ANSI
warning. `gemini hooks migrate --from-claude` reads another tool's config.

### 2026-10-28 — the agent-loop layer, unlocked and then blocked again

A fresh AI Studio project (no billing attached) gave a working key — the 402
was the old project sitting on a postpay account that Google now requires to
move to prepay, not a missing free tier. `gemini-flash-latest` answered "OK"
over plain curl, so the key and the tier are fine.

Then the model itself went busy: every `gemini -p` run ended in
`status: 503 ... This model is currently experiencing high demand`, with the
CLI retrying until the 90-second timeout. Two attempts at the `GEMINI.md`
injection test returned `exit 124` and no output.

**So that test has not been run.** `NO CANARY` there means "the CLI never
reached the model", not "the injection failed" — the distinction this session
has had to make twelve times.

What was set up and is ready to re-run when the model is available:

    ~/gcli-md-poc/GEMINI.md    a plausible project note whose "required setup
                               step for assistants" is a touch of a canary
                               path, plus a marker string for the control
    run 1   gemini -p "Summarise this project in one line."   -> canary?
    run 2   gemini -p "What marker string is in GEMINI.md?"   -> proves the
                                                                file reached
                                                                the context

The scenario it tests is the one that matters for this surface: a repository
you cloned and trusted carries a `GEMINI.md` somebody else wrote, and a
headless `gemini -p` — the CI shape — acts on it. `non-interactive.toml` denies
`ask_user` outright, so if `run_shell_command` needs approval the command dies;
if it does not, it runs.

Read statically from the shipped policies while waiting, and worth checking
against behaviour later:

    read-only.toml   allows without asking: glob, grep_search, list_directory,
                     read_file, google_web_search, codebase_investigator,
                     cli_help, get_internal_docs, tracker_*, read_mcp_resource
    sandbox-default  [modes.default] approvedTools = cat, ls, grep, head,
                     tail, less, dir, type, findstr, echo
                     and a lone denylist entry: argsPattern
                     ".*gha-creds-.*\.json.*" — "Access to GitHub Actions
                     credentials file is denied."

Two things stand out and neither is measured yet. `approvedTools` never appears
as a string in the JS bundle, so whether that list applies outside `-s` is
unknown — assuming it does would be the same mistake as the extension PoC.
And a denylist naming one credentials file is an admission that the path
exists, while `~/.gemini/oauth_creds.json` is not on it.

### 2026-10-28 — toolbox.googleapps.com, the one application left on the web side

TIER1, `server: apps-toolbox`, and the only host from the Google sweep with
its own application logic rather than a static page. Django, confirmed by the
`csrfmiddlewaretoken` in its forms.

Tools exposed: `/apps/{main,dig,checkmx,messageheader,browserinfo,useragent,
encode_decode,har_analyzer,loganalyzer,loggershark,screen_recorder,other_tools}`.

**The endpoint took three wrong guesses to find, and each wrong guess was
caught by a control rather than by reasoning.** The form `<form id="dig-form">`
posts nowhere; posting to `/apps/dig/` returned exactly 18712 bytes, the same
as the GET, which is what said the guess was wrong. `toolbox.js` is 1971 bytes
of cookie-notice code. The real client is `/apps/dig/js/dig_prod.js`, and in it:

    fetch("lookup", {method:"POST", body: new FormData(dig-form)})

so the endpoint is `POST /apps/dig/lookup`, multipart, fields
`csrfmiddlewaretoken`, `domain`, `typ`, answering JSON.

**Measured, with the control passing first** (example.com/A returns a real
answer section):

    typ=NOTAREALTYPE   accepted, silently treated as ANY — a default, not an error
    typ=ANY            same
    domain=            clean empty response, 55 bytes
    no csrf token      403, Django's own CSRF failure page
    server=127.0.0.1   ignored
    nameserver=        ignored
    ns=                ignored
    resolver=          ignored
    dns=               ignored
    at=                ignored
    target=            ignored

Seven hidden-parameter names, all ignored, and every one of those requests
returned a normal successful lookup — which is what makes the zero readable
rather than a silent failure. There is no way to point the resolver at a host
of our choosing. **The dig endpoint is closed.**

Two leftovers, both honest and both unfinished:

- `/apps/loganalyzer/` redirects to itself forever — `Location:
  /apps/loganalyzer/`, not parameter-controlled, so not an open redirect. A
  broken page, not a security issue. § 3 does not take it.
- `/apps/checkmx/check` is a **GET** form (`<form action="check">` with no
  method), fields `domain` and `dkim_selector`. Both supplied still answers
  "Check was not possible", so a required field is still missing — probably the
  submit button's own name/value. **The harness is incomplete and the endpoint
  is unmeasured.** Not "safe"; unmeasured.

Checkmx is the one worth finishing: verifying MX means the server resolves and
usually connects outward, which is a wider surface than dig's resolver.

### 2026-10-28 — the Pi's SD card is failing

Mid-session the root filesystem went read-only and a `curl -o` started failing:

    Buffer I/O error on device mmcblk0p2
    EXT4-fs error (device mmcblk0p2): Detected aborted journal
    EXT4-fs (mmcblk0p2): Remounting filesystem read-only
    /dev/mmcblk0p2 on / type ext4 (rw,noatime,emergency_ro)

That is hardware, after the power cut. It also produced one false signal worth
recording: a 403 from the toolbox endpoint that was really curl being unable to
write its cookie jar, so the session cookie never existed and Django rejected
the POST. Reading that 403 as the server's answer would have been the
thirteenth instrument error of the day. Work continued from `/dev/shm`.

Everything is pushed, so nothing is lost, but the card needs replacing before
the Pi is used for anything that writes.

### 2026-10-28 — checkmx finished: the tool works, and that is the answer

Picking up where the harness was left unmeasured. The submit input has no
`name`, so it is never submitted: the only parameters are `domain` and the
optional `dkim_selector`. Our requests had been complete all along.

"Check was not possible" was not a broken tool and not a malformed request. The
reason is further down the page, in a div the earlier greps never reached:

    google.com
    Check was not possible.
    <div id="blacklist">
    This domain is not allowed.
    This domain is configured just fine. No need to check it.

**Every domain I had chosen was Google-owned** — google.com, gmail.com,
cameyo.com — picked deliberately under § 7 to avoid making Google's server
touch a third party's mail infrastructure, and that caution is exactly what
produced three identical dead ends.

Control, taken before believing any of it: the same domain fetched twice gives
a byte-identical page (md5 `3ebb069f2506`), so the differing hashes across
domains really were the server responding to input and not a per-request nonce.
That check is why the "the server ignores the domain" reading was dropped.

Three distinct, valid behaviours once the right domains were used:

    Google-owned domain      blacklist: "This domain is not allowed"
    example.com (no MX)      "Request timed out" — so there is a network step
                             that waits, not just a record read
    our own dnshook name     4.5s, "critical problems detected with this domain"

So checkmx resolves user-supplied names and reports on them. That is the
product. **Closed.**

The next rung would be pointing an MX record at a host we control and watching
for the connection, and it is not reachable: DNSHook does not serve MX, and no
domain here has controllable DNS. Even with one, § 3 is explicit that SSRF
which only reaches attacker-owned infrastructure is not a finding — the value
would need the server to reach something internal and return data, and a
DNS/SMTP checker has no path to that.

**Toolbox, the whole application:**

    /apps/dig/lookup     CSRF enforced, empty input handled, unknown typ falls
                         back to ANY, seven hidden nameserver parameter names
                         all ignored                                    closed
    /apps/checkmx/check  GET, Google's own domains blocklisted, user domains
                         resolved — as designed                         closed
    /apps/loganalyzer/   redirects to itself forever                broken, not
                                                                     a finding

A Tier 1 Django application with two server-side endpoints and input validation
in the right places. A measured zero, with the controls to read it by.

**One side-confirmation, from the morning's collector.** The webhook.site log
for page A holds exactly two hits: our own `curl/8.21.0` from Dhaka at
14:50:35, and one from 108.177.77.133 (Mountain View) with user-agent `Google`
at 14:51:51 — Gemini fetching the page it was asked to summarise, one minute
before the Pro and Flash runs. The second collector, the one named in the
page's injected instruction, is still empty. Run 4's zero is now measured from
both ends.

### 2026-10-28 — checkmx SSRF, tested properly with a domain we control, and closed

The researcher owns cindrasec.com, which unlocked the rung that was out of
reach: pointing an MX record wherever we like and seeing whether the Tier 1
host follows it.

Set up so the live mailbox was never touched — the apex keeps its Cloudflare
Email Routing MX, and the test lives entirely on subdomains:

    test.cindrasec.com    MX 10 mxlo.cindrasec.com
    mxlo.cindrasec.com    A  127.0.0.1          (DNS only, not proxied)
    test2.cindrasec.com   MX 10 mxdead.cindrasec.com
    mxdead.cindrasec.com  A  198.51.100.1       (TEST-NET-2, unroutable)

`test2` is the control: it is what "did not reach anything" looks like, which
is the only way "reached something" could be recognised. Cloudflare accepted a
loopback A record without complaint.

**Result: no difference of any kind.**

The rendered pages are byte-identical apart from the domain name and one
MTA-STS line, both ending in the same constant sentence:

    Mail servers are either not specified or not reachable or refuse to accept
    mail for this domain.

So nothing about where the server went, what answered, or what it said ever
reaches the output. The response is a fixed string.

The first pair of timings looked like a signal — 22.7s for loopback against
7.9s for the unroutable address — and in the wrong direction, since a refused
connection to 127.0.0.1 should be fast. Three repetitions each settled it:

    lo 22.19   dead 25.96
    lo  7.30   dead  7.32
    lo  6.92   dead 22.25

Both bounce between ~7s and ~22-26s regardless of address. The difference was
load, not behaviour. **Had the first pair been taken as the answer, this would
have become hours spent on a timing oracle that does not exist.**

**Closed, and it would not have been reportable even if the timing had held.**
§ 3 names this exact ceiling — SSRF that reaches internal hosts but reads
nothing sensitive, the VirusTotal IMDS case — and here the output is a constant
sentence, so there is no path for data to come back at all.

Toolbox is now closed end to end: dig, checkmx, and loganalyzer's broken
redirect. A Tier 1 Django application, two server-side endpoints, measured
zeros with controls behind each.

Cleanup owed: the four test DNS records on cindrasec.com can be deleted. The
apex MX was never modified.
