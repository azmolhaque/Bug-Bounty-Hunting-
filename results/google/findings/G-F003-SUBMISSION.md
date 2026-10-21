# Submission draft — Google Home: exported receiver guarded by a permission that cannot exist

Paste target: https://bughunters.google.com/report (Android / Mobile VRP)
Status: READY except for a terminal screenshot.

---

**Title:**
Google Home: `LockProximityReceiver` is exported and guarded by a malformed
permission string, so any app can claim that name and invoke it

---

Testing date: 2026-10-21
Testing time: 13:26 UTC
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

1. Nothing can hold it, so the intended protection never applies to any legitimate
   caller either — including the system's BLE scan delivery, which is what this
   receiver exists to receive.
2. Because no package defines that name, a third-party app can declare it itself at
   `protectionLevel="normal"`, request it, and be granted it at install with no user
   prompt. That app then becomes the only party on the device able to reach the receiver.

## What I demonstrated

An app holding no real permissions can invoke this receiver and cause Google Home to
execute `onReceive`. An otherwise identical app that does not declare the name cannot.

I built two APKs from the same source. The only difference is these two lines in one of
them:

```xml
<permission android:name="android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN"
            android:protectionLevel="normal" />
<uses-permission android:name="android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN" />
```

It is granted at install, silently:

```
$ adb shell dumpsys package com.cindrasec.mvrpprobe | grep -A3 'install permissions'
    install permissions:
      android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN: granted=true
```

Both apps then send the same broadcast: action
`com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED`,
component set to the receiver, extras `hgs_device_id`, `device_name`, `request_id` and a
one-element `ArrayList<ScanResult>` under `android.bluetooth.le.extra.LIST_SCAN_RESULT`.

Broadcasts to an unreachable component fail silently — `sendBroadcast` throws nothing and
returns nothing — so I measured the target side instead. `onReceive` begins by checking
whether Bluetooth is enabled, which makes Google Home's own process log
`BluetoothAdapter: isLeEnabled(): ON`. That line is the observable: it appears only when
the receiver actually runs.

I ran 10 alternating rounds in two independent sessions. Each round has three windows:
one broadcast from the app that declares the permission, one from the app that does not,
and one where nothing is sent at all. The third window is there because Google Home runs
background Bluetooth work of its own, and a single-sample comparison cannot tell an
effect from a coincidence.

Counting lines logged by Google Home's PID in each window:

```
round   with permission        without permission     nothing sent
1       1  isLeEnabled         0  -                   0  -
2       1  isLeEnabled         0  -                   0  -
3       1  isLeEnabled         0  -                   0  -
4       1  isLeEnabled         0  -                   0  -
5       1  isLeEnabled         0  -                   0  -

with permission   : 5/5 rounds
without           : 0/5
nothing sent      : 0/5
```

and again, in a separate session twenty minutes later, 5/5, 0/5, 0/5.

Thirty windows, ten responses, all of them in the column where the permission was
declared. The declaration is the only variable.

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

Separately, the feature itself appears to be broken in production: the system cannot hold
that permission name either, so genuine BLE scan deliveries to this receiver should also
be refused.

## Reproduction

```
# build both APKs from the same source; one declares the malformed permission name
adb install -r probe.apk      # declares and requests it
adb install -r control.apk    # declares nothing

# confirm the grant
adb shell dumpsys package com.cindrasec.mvrpprobe | grep -A3 'install permissions'

# with Google Home running, for each app:
adb logcat -c
adb shell am start -n APPNAME/com.cindrasec.mvrpprobe.MainActivity --es action blescan
sleep 7
adb logcat -d --pid=$(adb shell pidof com.google.android.apps.chromecast.app)
```

The app that declares the name produces a `BluetoothAdapter` line from Google Home's PID
every time; the one that does not produces nothing. Repeat with no broadcast sent at all
to confirm the target is quiet on its own.

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

Take one screenshot of the terminal showing a full `mvrp-ble-diff.sh` run, with the three
columns and the summary visible. That is the whole report in one image.

Do not add a CVSS score argued upward. Do not describe the notification or the unlock as
something that happened. Every sentence above has a log line or a manifest line behind it,
and that is the only reason this is worth sending.
