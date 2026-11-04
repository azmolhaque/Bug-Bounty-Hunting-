# PoC — Google Home components guarded by permissions nothing defines

Two APKs, one source tree. They differ only in the manifest.

| file | manifest | declares |
|---|---|---|
| `mvrp-poc.apk` | `AndroidManifest.xml` | the two guard permission names, nothing else |
| `mvrp-control.apk` | `AndroidManifest.control.xml` | no permissions at all |

Neither requests a real Android permission, so neither shows anything in the
permission UI and neither prompts at install.

## What it does

```
adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action broadcast
adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action activity
```

`broadcast` sends `…remotecontrol.safety.action.BLE_SCANNED` directly at
`LockProximityReceiver`. `activity` starts `FirstDockActivity`. The control
APK keeps the same class name, so it is driven as:

```
adb shell am start -n com.cindrasec.mvrpctl/com.cindrasec.mvrpprobe.MainActivity --es action broadcast
```

The app's own log lines go to logcat under the tag `MVRP`, but the evidence
in the report is the system's record, not the app's: `dumpsys activity
broadcasts` for the receiver and the `ActivityTaskManager` denial line for
the activity. Both are written by the framework regardless of what either
app logs.

## Build

No Gradle. `javac` → `d8` → `aapt2 link` → `zipalign` → `apksigner`, driven
by `../mvrp-probe/build.sh`:

```
cd ../mvrp-probe
SRC=../lockproximity-poc/src MANIFEST=../lockproximity-poc/AndroidManifest.xml ./build.sh
SRC=../lockproximity-poc/src MANIFEST=../lockproximity-poc/AndroidManifest.control.xml \
    PKG=com.cindrasec.mvrpctl ./build.sh
```

Both are signed with a local debug keystore; the signature carries no
meaning here beyond making the two builds comparable.
