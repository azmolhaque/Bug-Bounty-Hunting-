
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
