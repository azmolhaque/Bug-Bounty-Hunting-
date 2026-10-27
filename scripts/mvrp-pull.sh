#!/usr/bin/env bash
# mvrp-pull.sh — নিজের ডিভাইস থেকে in-scope APK টেনে আনো (split সহ)
#
# কেন ডিভাইস থেকে, Play Store mirror থেকে না:
#   Mobile VRP বলে "Vulnerabilities that do not work on the latest available
#   operating system version" বাদ। তাই তোমার হাতে ঠিক সেই build থাকতে হবে
#   যেটা তোমার latest-OS ডিভাইসে চলছে, mirror-এর পুরনো কপি না।
#
# ব্যবহার:  ./mvrp-pull.sh                 # scope-এর সব app খুঁজে টানবে
#           ./mvrp-pull.sh com.fitbit.FitbitMobile
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
APKDIR="$OUT/apk"
mkdir -p "$APKDIR"

# in-scope developer-দের package prefix. Play Store-এর developer পাতা থেকে
# আরও package পেলে এখানে যোগ করো।
# scope-mobile-vrp.yaml-এর in_scope_developers ধরে। শেষ চারটে বিভাগ
# (Research at Google, Google Samples, Developed with Google, Red Hot Labs)
# আগে ছাঁকনিতে ছিল না, তাই com.google.ai.edge.gallery নীরবে বাদ পড়ত আর
# স্ক্রিপ্ট "৬৫ package টানা হলো" বলে সন্তুষ্ট রিপোর্ট দিত। যা বিবেচনাই
# করা হয়নি তার অনুপস্থিতি আউটপুটে দেখা যায় না — সেজন্য নিচে বাদ-পড়ার
# গণনাও ছাপা হয়।
. "$(cd "$(dirname "$0")" && pwd)/lib/inscope-pkgs.sh"
PATTERNS="$MVRP_PKG_RE"

command -v adb >/dev/null || { echo "!! adb নেই — install করো"; exit 1; }

echo "== ডিভাইস =="
adb devices -l | sed -n '2,$p' | grep -v '^$' || { echo "!! কোনো ডিভাইস নেই"; exit 1; }
echo "   Android: $(adb shell getprop ro.build.version.release | tr -d '\r')" \
     "(SDK $(adb shell getprop ro.build.version.sdk | tr -d '\r'))" \
     "| $(adb shell getprop ro.product.model | tr -d '\r')"
echo

if [ $# -gt 0 ]; then
  PKGS="$*"
else
  ALL=$(adb shell pm list packages 2>/dev/null | tr -d '\r' | sed 's/^package://' | sort -u)
  PKGS=$(printf '%s\n' "$ALL" | grep -E "$PATTERNS")
  # ছাঁকনি কী বাদ দিল সেটা দেখাও: নইলে লক্ষ্য-app ইনস্টল থাকা সত্ত্বেও
  # "N package টানা হলো" পড়ে মনে হবে সব ঠিক আছে।
  nall=$(printf '%s\n' "$ALL" | grep -c .)
  nsel=$(printf '%s\n' "$PKGS" | grep -c .)
  echo "ডিভাইসে $nall টা package, ছাঁকনিতে মিলেছে $nsel টা, বাদ $((nall-nsel)) টা"
  echo "(নির্দিষ্ট app টানতে ছাঁকনি লাগে না:  $0 <package.name>)"
  if [ -n "${SHOW_SKIPPED:-}" ]; then
    echo "-- বাদ পড়া Google/অংশীদার package:"
    printf '%s\n' "$ALL" | grep -vE "$PATTERNS" \
      | grep -E 'google|fitbit|waze|waymo|nest|redhotlabs|developers' | sed 's/^/   /'
  fi
  echo
fi

COUNT=0
for pkg in $PKGS; do
  ver=$(adb shell dumpsys package "$pkg" 2>/dev/null | tr -d '\r' \
        | awk -F= '/versionName=/{print $2; exit}')
  paths=$(adb shell pm path "$pkg" 2>/dev/null | tr -d '\r' | sed 's/^package://')
  [ -z "$paths" ] && { echo "-- $pkg : path নেই, skip"; continue; }

  d="$APKDIR/$pkg"
  mkdir -p "$d"
  n=0
  for p in $paths; do
    adb pull "$p" "$d/" >/dev/null 2>&1 && n=$((n+1))
  done
  # split APK থাকলে n>1 — manifest base.apk-এ, কিন্তু native .so split-এ থাকতে পারে
  printf '%-45s v%-14s %d apk\n' "$pkg" "${ver:-?}" "$n"
  echo "${ver:-unknown}" > "$d/.version"
  COUNT=$((COUNT+1))
done

echo
echo "== $COUNT package টানা হলো -> $APKDIR"
[ "$COUNT" -eq 0 ] && echo "!! শূন্য। PATTERNS দেখো, অথবা package নাম হাতে দাও।"
echo "পরের ধাপ: scripts/mvrp-surface.sh"
