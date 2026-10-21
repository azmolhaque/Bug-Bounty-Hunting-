# G-F003 — Google Home: exported receiver guarded by an impossible permission

**Status: SUBMITTED 2026-10-21. Issue 576322789 (buganizer).**
https://issuetracker.google.com/issues/576322789
Intake state: Type Customer Issue, P4/S4, Status New, unassigned — the default
landing state, not a triage verdict.

**The open question was answered, and it moved the finding.** Reaching the second
component turned out to be worth something concrete: `FirstDockActivity` hands the
caller the signed-in Google account. See section 9.

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


---

## 9. What reaching the second component is worth (added 2026-10-21, late)

`FirstDockActivity` is one side of a Setup Wizard handoff. `C(sr)` reads an
`IntentSender` out of `android.intent.extra.INTENT` on the intent that started
it, merges an `accountName` extra holding the signed-in account into a
`com.android.wizard.NEXT` intent, and fires it at that IntentSender. The guard
`RUN_DOCK_SETUP` is what should hold that to the Setup Wizard; nothing on this
device defines it.

Measured, with the PoC handing over a PendingIntent of its own and a
non-exported receiver catching the result:

    SINK in com.cindrasec.mvrpprobe got a delivery, action=com.android.wizard.NEXT
      accountName = "a…m" (String, len=22)

73 ms from `startActivity()`, no interaction, no prompt. The control APK is
refused at `startActivity` and receives nothing.

**Precondition, measured rather than assumed:** straight after force-stopping
Google Home the delivery still arrives but `accountName` is null, and retrying
inside twelve seconds does not help — `onCreate` returns early on a recreate.
Launching Home once is enough. So the condition is that Home has been opened
since its process was last killed.

**Not claimed:** the unlock (read from code, never performed), a background
start (untested, Android restricts it), and `RUN_DOCK_SETUP` being absent on
every device (only measured here).

## 10. Severity

CVSS 3.1: **4.0 Medium** — `AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`.
Local vector because the attacker app is installed on the device; no privileges
because the app holds no real permission; no user interaction at the time of the
attack; confidentiality Low because what crosses is an account identifier.

Mobile VRP does not use CVSS. Its matrix applies: Google Home is **Tier 2** (Tier 1
is Google Play Services, AGSA, Google Cloud and Gmail only), scenario 3 (user
installs a malicious app). That puts this in the THEFT column at roughly $4,500 if
the account identifier is accepted as sensitive data, and the OTHER column at
roughly $2,250 if it is not. I had this wrong in conversation as Tier 1.

## 11. Submission package

| | sha256 |
|---|---|
| `mvrp-poc.apk` | `7e7ef501d9be335a1e01acf9996a3c59e7538bdc60bc14870a1667ba58fabf9d` |
| `mvrp-control.apk` | `d59cfc29ab66c850eb3bc7a94685739cd77a4b8700875aa82db99c9756b34346` |
| `lockproximity-poc-src.zip` | `b18ba6420c26b203f499f2653c9b5b8545a2f7ae394527f0f482d69fe675328c` |
| `evidence.txt` | `65cb53fbcc32a41004035b3484087f063236c841be4743f014982baea135959b` |

Plus two terminal screenshots and `reproduction-and-remediation.md`. Body sent in
three parts because the form's description field caps at 20,000 characters:
`G-F003-PROBLEM.md`, `G-F003-IMPACT.md`, and the remainder as that attachment.
