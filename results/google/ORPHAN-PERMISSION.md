# Orphaned permissions on Android — method, evidence, and where it stands

**Status: two of three steps demonstrated. No boundary crossing yet. Not submitted.**

Date of the work: 2026-10-20 / 21.
Device: moto g stylus 5G (2024), Android 15, API 35, unrooted, stock.
Program: Google Mobile VRP. Scope confirmed from `config/scope-mobile-vrp.yaml`.

---

## 1. What the class is

An app guards an exported component with a permission that a *different* app
defines:

```xml
<service android:name=".SomeService"
         android:exported="true"
         android:permission="com.example.other.PERMISSION"/>
```

If the defining app is not installed, nobody defines that permission. The guard
then looks fail-closed — but it is not. A third-party app can declare the
permission itself at `protectionLevel="normal"`, request it, be granted it at
install, and pass the guard.

Mobile VRP names "orphaned permissions" in its qualifying list.

## 2. Why it is not theoretical here

Two distinct sources of orphans were found on an ordinary retail phone:

**Vendor namespace, definer absent.** `com.google.android.apps.nexuslauncher.permission.QSB`
is defined by the Pixel Launcher. On any non-Pixel device it does not exist.
Likewise `com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER`,
`com.google.android.flipendo.SAVER_STATE_UPDATE`,
`com.android.systemui.permission.SEND_ALERT_BROADCASTS`.

**Platform namespace, newer than the OS.**
`android.permission.BIND_APP_FUNCTION_SERVICE`,
`android.permission.BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE` and
`android.permission.BIND_INTRUSION_DETECTION_EVENT_TRANSPORT_SERVICE` arrive in
API 36. The device is API 35, so the platform does not define them — while apps
already ship services guarded by them.

The second source is the more interesting one: it is not device-specific. Every
Android 15 device running these apps is in the same state, and the apps'
developers could reasonably assume the framework would enforce the guard.

Sweep result across 65 installed packages: **515 guard permissions, 16 orphaned.**

## 3. Step 1 — the permission can be claimed. Demonstrated.

`poc/mvrp-probe/AndroidManifest.orphan.xml` declares all seven orphans at
`protectionLevel="normal"` and requests all seven. Built with `build.sh`, signed
with a self-made key, installed with `adb install`.

```
$ adb shell dumpsys package com.cindrasec.mvrpprobe | grep -A14 'declared permissions'
    declared permissions:
      com.google.android.apps.nexuslauncher.permission.QSB: prot=normal
      com.android.systemui.permission.SEND_ALERT_BROADCASTS: prot=normal
      com.google.android.flipendo.SAVER_STATE_UPDATE: prot=normal
      com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER: prot=normal
      android.permission.BIND_APP_FUNCTION_SERVICE: prot=normal
      android.permission.BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE: prot=normal
      android.permission.BIND_INTRUSION_DETECTION_EVENT_TRANSPORT_SERVICE: prot=normal

$ adb shell dumpsys package com.cindrasec.mvrpprobe | grep -A14 'install permissions'
    install permissions:
      android.permission.BIND_APP_FUNCTION_SERVICE: granted=true
      com.android.systemui.permission.SEND_ALERT_BROADCASTS: granted=true
      android.permission.BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE: granted=true
      com.google.android.flipendo.SAVER_STATE_UPDATE: granted=true
      com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER: granted=true
      android.permission.BIND_INTRUSION_DETECTION_EVENT_TRANSPORT_SERVICE: granted=true
      com.google.android.apps.nexuslauncher.permission.QSB: granted=true
```

All seven granted, including the three in the `android.permission.*` namespace.
Android does not reserve that namespace against a third-party definer when the
platform itself does not define the name.

## 4. Step 2 — the guard is passed. Demonstrated, with a control.

Two APKs built from identical source. One declares and requests the orphans
(`com.cindrasec.mvrpprobe`); the other declares nothing
(`com.cindrasec.mvrpctl`). Both call the same API on the same component.

```
# with the claimed permission
I MVRP: startActivity() returned, no exception

# without it, same code, same intent
W ActivityTaskManager: Permission Denial: starting Intent {
    cmp=com.google.android.googlequicksearchbox/...ExportedSmartspaceTrampolineActivity }
    from ProcessRecord{... com.cindrasec.mvrpctl/u0a569} (pid=6127, uid=10569)
    requires com.google.android.apps.nexuslauncher.permission.QSB
```

The system names the permission as the reason, and the only variable between
the runs is whether it was claimed.

Reproduced across six components in six apps and three permissions:

| component | app | permission | with | without |
|---|---|---|---|---|
| `MemoryAppFunctionService` | Find My Device | `BIND_APP_FUNCTION_SERVICE` | gate passed | denied |
| `BugleAlternativeMessageTransportService` | Google Messages | `BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE` | gate passed | denied |
| `WellbeingAppFunctionService` | Digital Wellbeing | `BIND_APP_FUNCTION_SERVICE` | gate passed | denied |
| `MaestroAppFunctionService` | Pixel Buds | `BIND_APP_FUNCTION_SERVICE` | gate passed | denied |
| `IntrusionDetectionEventTransportService` | GMS (Tier 1) | `BIND_INTRUSION_DETECTION_EVENT_TRANSPORT_SERVICE` | **connected** | denied |
| `OneSearchSuggestService` | AGSA (Tier 1) | `QSB` | **connected** | denied |
| `ExportedSmartspaceTrampolineActivity` + 2 aliases | AGSA (Tier 1) | `QSB` | accepted | denied |

"Gate passed" means `bindService()` returned true — the system accepted the
request. Only the two marked **connected** produced an `onServiceConnected`
callback with a live binder. That distinction cost a defect to learn and must
not be blurred in any report.

## 5. Step 3 — what the attacker gets. NOT demonstrated.

Three outcomes so far, none of them a crossing:

**AGSA's trampoline activity: closed by a second layer.** The peer
`defpackage.cenk` re-verifies at runtime that `com.google.android.apps.nexuslauncher`
is installed, is the package declaring `QSB`, is a system app
(`flags & 129`) and passes a signature check. On a non-Pixel device
`getPackageInfo` throws and the activity calls `finish()`, logging
`"#onAccountChanged: QSB permission is not trusted."` They anticipated exactly
this attack.

**The three AppFunction services: no connection within 15 seconds.** Gate
passed, `onServiceConnected` never fired. Cause not established — an internal
caller check in the AndroidX `AppFunctionService` base class is the obvious
hypothesis, untested.

**The two connected services: binder held, protocol not yet spoken.** Both
return an empty interface descriptor, i.e. a raw `Binder`, not an AIDL stub.
AGSA's path is gRPC-over-binder: `OneSearchSuggestService.onBind` returns
`G().a.b()`, and the peer `cret` registers one service definition
(`...onesearch.OneSearchSuggest`) on a `gize` server with options `haux.a`
(two booleans and a 32 KiB limit — options, not a policy). GMS's
`IntrusionDetectionEventTransportService` is a Chimera wrapper (`bkaf`) whose
implementation loads at runtime from a module, so it is not in `base.apk`.

**Crucially, the gRPC `SecurityPolicy` has not been tested.** In grpc-binder the
policy is evaluated when the client sends `SETUP_TRANSPORT`; the probe only
binds and reads the descriptor. `isBinderAlive = true` therefore means the
binder exists, not that a call would be allowed. Claiming otherwise would be the
same error as calling an accepted bind request a connection.

## 6. What it would take to finish

1. Locate where `gize` is constructed and which `SecurityPolicy` is attached —
   the Hilt binding module, not `cret`.
2. If the policy is permissive, implement a grpc-binder client handshake in the
   probe and issue one `OneSearchSuggest` call. A response containing the user's
   own search history would be Theft of Sensitive Data at Tier 1.
3. If the policy checks UID or signature, this path is closed and the finding
   remains a precondition — which is not submittable.

Reusable beyond this target: grpc-over-binder is widespread across Google apps,
so a working client in the probe would apply to every one of them.

## 7. Tooling produced

- `scripts/mvrp-orphan.sh` — finds orphaned guard permissions. Four controls:
  minimum permission count, two known grouped and one ungrouped permission must
  read as defined, a fabricated one must read as orphaned.
- `scripts/mvrp-orphan-test.sh` — runs every guarded component twice, with and
  without the permission, and prints the pair. Aborts unless the two APKs
  actually differ in granted permissions.
- `scripts/mvrp-class.sh` — decompiles a single class across an app's APKs,
  separating "jadx failed" from "class not present".
- `poc/mvrp-probe/AndroidManifest.orphan.xml` — the claim experiment.
- `poc/mvrp-probe` actions: `startact`, `broadcast`, `hold` added for this work.

## 8. Honest summary

The method works and is measured at every step that has been measured. What is
missing is the only thing that pays: evidence of what an attacker obtains after
passing the gate. Until that exists this is a precondition, and a precondition
submitted as a finding is the shape that closed G-F002, the Wiz subdomain report
and S43.

Next session starts at step 3, not at zero.
