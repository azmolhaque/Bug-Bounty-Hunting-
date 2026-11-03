# Google Mobile VRP — Android app static reviews (no findings)

**Date:** 2026-11-03
**Researcher:** Md. Azmol Haque Rony (`cindrasec`)
**Method:** pull from device → apktool + jadx → manifest triage → trace each
exported/sensitive component to its caller/permission check.
**Scope:** Google Mobile VRP (`config/scope-mobile-vrp.yaml`). Attacker model =
scenario 3 (malicious app on device). Qualifying classes hunted: exported-component
data theft, intent redirection, unsafe PendingIntent, FileProvider path traversal.

## Bottom line

**No findings.** Both apps' highest-value surfaces traced to their sinks and
confirmed safe with evidence. Recorded so the ground isn't re-walked.

## 1. Health Connect (`com.google.android.apps.healthdata`) — SAFE (thin UI front-end)

Key realization: this app is the **phone UI / onboarding front-end**; the actual
health-data storage and permission *enforcement* live in the **AOSP framework
module** `android.health.connect` → **out of Mobile VRP scope** (Android & Google
Devices SRP). The in-scope app surface:

- **`GatewayActivity`/`DefaultGateway`** (tiktok nav gateway, exported, no perm):
  routes `androidx.health.ACTION_*` deep links via the tiktok `createPeer()`
  compile-time nav framework. **No** `getParcelableExtra`/`EXTRA_INTENT`/
  `setComponent` anywhere in the gateway package → **not intent redirection**.
  The actions (REQUEST_PERMISSIONS, MANAGE_HEALTH_DATA, REQUEST_EXERCISE_ROUTE)
  are intended public entry points → consent/management UIs.
- **REQUEST_EXERCISE_ROUTE** (location-bearing) is only a consent view
  (`ReadExerciseRoutesPermissionView`); the route data return is framework-enforced.
- Exported `SearchIndexablesProvider` = `READ_SEARCH_INDEXABLES` (system perm),
  serves UI labels not health data. QuickSettings = BIND_QUICK_SETTINGS_TILE.

**Verdict:** in-scope surface is a thin allowlist router; enforcement is in the
out-of-scope framework. No reachable sink.

## 2. Google Authenticator (`com.google.android.apps.authenticator2`) — SAFE

Good baseline: `allowBackup="false"` (no adb-backup seed theft),
`usesCleartextTraffic="false"`, every sensitive screen (AddFirstOtp, EditOtp,
EnterKey, Migration, Settings) is `exported="false"`.

- **`MainActivity`** (exported, `otpauth://`): the *intended* add-account entry.
  An attacker sending `otpauth://` only adds their own seed to the victim's app —
  no exfiltration. Not a theft vector.
- **`TargetEndpointService`** (exported, no manifest permission, `grpc://…/TargetService`):
  the OS-migration endpoint that transfers Authenticator accounts (the **TOTP
  seeds**) — the one jackpot shape. **Signature-pinned in code:** `onBind`
  registers a grpc-binder `SecurityPolicy` restricting the caller to
  **`com.google.android.apps.restore`** with signing-cert hash
  `56BE132B…0622EC87` (`kcj.a`). Every RPC is rejected unless the calling UID
  resolves to that package + cert. A malicious app cannot present Google's
  signing certificate → cannot bind/pull seeds. Correct osmigration security model.

**Verdict:** the highest-value surface (TOTP-seed migration) is signature-gated;
everything else is locked down or intended. No finding.

## 3. Provider sweep — Fitbit + Nest (exported content providers) — SAFE

Pure-ADB scenario-3 sweep (shell UID ≈ malicious app) across the candidate set.

- **Fitbit (`com.fitbit.FitbitMobile`)** — despite a provider literally named
  `ExternalAppsRequestContentProvider` (`…external-apps`), it has **no
  `android:exported`** attribute → defaults to `false` on modern targetSdk.
  Fitbit exports **zero** content providers. Not reachable.
- **Nest (`com.nest.android`)** — `CameraNotificationImageProvider`
  (`…camera_notification_images`) **is** `exported="true"` with no manifest
  permission (home-camera snapshot thumbnails — the strongest-looking lead), but
  its `openFile`→`a(uri)` has two correct in-code guards:
  (1) caller pinned to `com.android.systemui` via `getCallingPackage()`, and
  (2) path-traversal guard — `new File(cacheDir/"notification_previews", path)`
  then `getCanonicalPath()` containment check against the base dir.
  **Empirically confirmed:** `adb shell content query` (non-systemui caller) →
  `SecurityException: Unauthorized access to content provider`. Rejected.
  - **Nest full exported-surface coverage** (not just the provider):
    - `DeepLinkRoutingActivity` → `uh.b` chain-of-responsibility router. `k()` is a
      null-guard passthrough and `nestmobile://` is host-unrestricted, BUT `uh.c.b()`
      normalizes `nestmobile://X` → `https://home.nest.com/X`, and the dangerous-pattern
      grep (`parseUri|setComponent|setClassName|Class.forName`) is **empty across every
      handler** — each builds an Intent to a fixed `…Activity.class`. No intent
      redirection; attacker URL can't name the destination. Safe fallback to HomeActivity.
    - Exported receivers (`UpdateNotificationChannels`, `RegisterGeofencesWithOS`,
      `SecureSunsetNotificationScheduleReset`): all trigger a **fixed internal refresh**
      regardless of broadcast content; `RegisterGeofencesWithOS` reads `intent.getData()`
      only as an equality guard (`== package:com.google.android.gms`), never as a sink.
      No attacker data reaches a sensitive action. Safe.

## 4. Keep (`com.google.android.keep`) — SAFE (strongest leads, chased hard)

Keep was the richest target (data-holding, custom providers). All three closed
with evidence:

- **`AndroidImageContentProvider`** (`…clipboard.image`, exported, **reads open** —
  no readPermission): parent `gus.b(uri)` builds `new File(filesDir/"image",
  uri.getQueryParameter("IMAGE_ID"))` — attacker-controlled — BUT guards it:
  `file.getParentFile().equals(base)` requires a *direct child* of `files/image/`,
  so any `../` fails. **Empirically confirmed:** `content read … IMAGE_ID=../databases/`
  → `SecurityException: Caller does not have permission to access …/files/image/../databases`.
  No traversal.
- **`SourceEndpointService`** (osmigration SOURCE — hands over notes): `onCreate`
  pins the caller to `com.google.android.apps.restore` via the SecurityPolicy
  (confirmed with `--show-bad-code`), same pattern as Authenticator. Not open.
- **`KeepSliceProvider`** (`…slices`, exported, no permission): `onBindSlice`
  (`b(uri)`) returns note content by `note_id`/`account` with no in-provider caller
  check — BUT the androidx base `fda` stubs the generic ContentProvider surface:
  `call()` returns **null**, `query()` returns **null**. So note content is reachable
  **only** via `SliceManager.bindSlice()`, which the platform gates to user-authorized
  slice hosts. A direct `ContentResolver.call()`/`query()` from a malicious app gets
  nothing → no cross-app note leak.

## 5. Waze (`com.waze`) external AIDL/SDK — SAFE (the last distinct surface)

In-scope developer (Waze); three exported, no-permission services built for
third-party partner binding — the surface type most likely to trust callers.

- **`AIDLService`** (`com.waze.IServiceAIDL`, impl `cg`): `dispatchTransaction`
  only returns the caller's own PID (txn 1), *stores* a token + caller package to
  register the caller (txn 2), or *reads* data from the caller (txn 3). It's a
  **one-way caller→Waze channel** — no location/trip ever returned. No theft surface.
- **`SdkService`** (Messenger `bj` + AIDL `aj`): every op requires a non-empty
  `token`, routed through `bd`. Nav/location data (`bd.H(token,…)`) is gated by
  `bd.X(token)`, which requires an **authenticated bound partner session**
  (`f35165e`) whose token matches (`an.ag(token)`); otherwise "Authentication
  failed" and no data. `aj` resolves the caller via `Binder.getCallingUid()`.
  Token-authenticated + connected-session gate — a malicious app isn't the
  authenticated partner, so it gets nothing.

**Verdict: defended.** Location/nav data only reaches an authenticated, bound,
token-matched partner session.

## Conclusion — Mobile VRP static hunt complete

Every exported-surface **type** has now been covered across the in-scope apps —
content providers, bound/AIDL/SDK services, migration endpoints, deep-link routers,
broadcast receivers, slice providers — and **all are correctly defended**, each
proven with code plus an empirical check where the harness allowed (adb `content`
probes returning `SecurityException`/`Unauthorized`, etc.). No valid finding from
the static mobile surface. This is the expected texture of mature, well-maintained
targets. The remaining higher-EV path for an actual finding is live server-side
authz testing the researcher runs (e.g. the Lightroom `photos.adobe.io` shares IDOR),
not further static review of hardened clients.

## Honest assessment

Both are Google-maintained; the dangerous surfaces are correctly defended
(signature pinning, non-exported sensitive screens, framework-enforced data).
This is the expected texture of hardened targets. Across this engagement the
static reviews (Magento, Acrobat ×3, Lightroom, Health Connect, Authenticator)
are all clean — real bug-hunting on mature targets is mostly ruling things out
with evidence. The remaining higher-EV avenue is live/dynamic testing the
researcher runs with their own accounts (e.g. the Lightroom `photos.adobe.io`
shares IDOR), not more static review of hardened apps.
