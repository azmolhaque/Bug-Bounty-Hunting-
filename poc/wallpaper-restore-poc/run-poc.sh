#!/usr/bin/env bash
# run-poc.sh — one run, measured rather than timed.
#
# Why this exists: the first clean-state attempt was written down as a failure
# because `sleep 3; dumpsys` showed no change. It had not failed. The component
# changed later — a freshly installed app plus a cold start of the Wallpapers
# app takes longer than three seconds — and a run two minutes afterwards showed
# the canary already in place. A fixed sleep measures the sleep, not the device.
#
# So this polls until the component changes or a deadline passes, and prints
# the framework's own record of the call either way:
#
#   WallpaperManagerService: setWallpaperComponent name=ComponentInfo{...}, which = 1; callingPid = N
#
# That line is the system saying the privileged Wallpapers app made the
# signature-gated call with the component this app asked for. It is better
# evidence than anything the PoC can log about itself.
#
# Usage:
#   ANDROID_SERIAL=ZT422724JR ./run-poc.sh attacker <pkg/cls>
#   ANDROID_SERIAL=ZT422724JR ./run-poc.sh control  <pkg/cls>
#   ANDROID_SERIAL=ZT422724JR ./run-poc.sh canary
set -uo pipefail

VARIANT="${1:-canary}"
TARGET="${2:-}"
DEADLINE="${DEADLINE:-45}"

case "$VARIANT" in
  attacker) PKG=com.cindrasec.wallpaperpoc ;;
  control)  PKG=com.cindrasec.wallpaperctl ;;
  canary)   PKG=com.cindrasec.wallpapercan ;;
  *) echo "usage: $0 [attacker|control|canary] [pkg/cls]"; exit 1 ;;
esac

command -v adb >/dev/null || { echo "!! adb not found"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! no device (set ANDROID_SERIAL)"; exit 1; }

comp() {   # the home-screen wallpaper component, as the framework reports it
  adb shell dumpsys wallpaper 2>/dev/null </dev/null \
    | grep -m1 '^  mWallpaperComponent=' | tr -d '\r' | sed 's/^  mWallpaperComponent=//'
}

echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device : $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r') / Android $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
echo "# serial : $(adb get-serialno 2>/dev/null | tr -d '\r')"
echo "# build  : $VARIANT ($PKG)"
echo

# ---- control: is this build even installed ----
if ! adb shell pm path "$PKG" 2>/dev/null </dev/null | grep -q package:; then
  echo "!! $PKG is not installed — install it first, or the 'no change' below"
  echo "!! would be about a missing app rather than about the permission."
  exit 1
fi

# What this run asked for. Comparing against this, rather than against "did
# anything change", is the difference between a result and a false positive:
# a control run once reported "component changed" because the system was
# clearing an uninstalled package's wallpaper at that moment
# (setWallpaperComponent name=null, callingPid = system_server), which has
# nothing to do with the broadcast and is not the attack working.
if [ -n "$TARGET" ]; then
  EXPECT="ComponentInfo{$TARGET}"
else
  EXPECT="ComponentInfo{$PKG/com.cindrasec.wallpaperpoc.CanaryWallpaperService}"
fi

BEFORE="$(comp)"
echo "before : $BEFORE"
echo "asked  : $EXPECT"

adb logcat -c
if [ -n "$TARGET" ]; then
  adb shell am start -n "$PKG/com.cindrasec.wallpaperpoc.MainActivity" \
      --es action set --es target "$TARGET" >/dev/null 2>&1
else
  adb shell am start -n "$PKG/com.cindrasec.wallpaperpoc.MainActivity" \
      --es action set >/dev/null 2>&1
fi

# ---- poll for the requested component, do not sleep ----
GOT=0
for i in $(seq 1 "$DEADLINE"); do
  AFTER="$(comp)"
  if [ "$AFTER" = "$EXPECT" ]; then GOT=1; break; fi
  sleep 1
done
echo "after  : ${AFTER:-?}      (waited ${i}s of ${DEADLINE}s)"
echo

echo "== what this app logged =="
adb logcat -d -s WPPOC 2>/dev/null | sed 's/^/  /' | tail -12
echo

echo "== what the framework logged =="
FW=$(adb logcat -d 2>/dev/null | grep -E 'WallpaperManagerService|DownloadableRestorer|WallpaperSetter' | tail -12)
if [ -n "$FW" ]; then
  printf '%s\n' "$FW" | sed 's/^/  /'
else
  echo "  (nothing — on a refused broadcast the framework says nothing at all,"
  echo "   which is itself the control's result: no receiver process, no call)"
fi
echo

if [ "$GOT" -eq 1 ]; then
  echo "RESULT  the requested component is now the home wallpaper (after ${i}s)"
  echo "          $BEFORE"
  echo "       -> $AFTER"
  echo
  echo "That is the device's own report, not this script's opinion. What it means"
  echo "depends on the build: from the control it would mean the receiver is open"
  echo "to everyone and there is no bypass to report."
elif [ "$AFTER" != "$BEFORE" ]; then
  echo "RESULT  the component changed, but NOT to what was asked for."
  echo "          $BEFORE"
  echo "       -> $AFTER"
  echo "       asked for $EXPECT"
  echo
  echo "This is not the attack working. Read the setWallpaperComponent line above:"
  echo "name=null with callingPid of system_server is the framework clearing an"
  echo "uninstalled package's wallpaper and falling back to the default, which can"
  echo "land in the same few seconds and look like a result."
else
  echo "RESULT  unchanged after ${DEADLINE}s: $AFTER"
  echo
  echo "For the control build that is the expected outcome. For an attacker build,"
  echo "check the framework lines above before calling it a failure — 'Changing to"
  echo "the same component, ignoring' means it was already set, so the run proved"
  echo "nothing and the wallpaper has to be set to something else first."
fi
