The root cause is a single manifest attribute in each case.

`android:permission` takes exactly one permission name. For `LockProximityReceiver` the
value is two names joined with a `|`, so Android reads the whole string as one name, and
no permission by that name exists or can exist. For `FirstDockActivity` the name is
well-formed but is defined by a package that is not installed on this device.

Either way the result is the same: the guard names a permission nothing defines, so an
app that declares that name itself at `protectionLevel="normal"` is granted it at install
and becomes the only party on the device that passes the check.

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
