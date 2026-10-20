
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
