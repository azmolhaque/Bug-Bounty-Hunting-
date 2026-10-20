#!/usr/bin/env bash
# mvrp-decompile.sh — অগ্রাধিকার ক্রমে সোর্স-সহ decompile, পুনরারম্ভযোগ্য।
#
# কেন: Mobile VRP যে তিনটে শ্রেণি নাম ধরে পুরস্কৃত করে — path traversal,
# intent redirection, অনিরাপদ PendingIntent — সেগুলো bind বা deeplink দিয়ে
# পাওয়া যায় না। কোডের ভেতরের নকশা-ত্রুটি, সোর্স পড়েই ধরতে হয়।
# আমাদের ৬৪টা app-এর মধ্যে সোর্স আছে মাত্র ৪টার। সেটাই আসল ফাঁক।
#
# ব্যবহার:  nohup ./mvrp-decompile.sh > ~/mvrp/decompile.log 2>&1 &
#           tail -f ~/mvrp/decompile.log
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
APK="$OUT/apk"; SRC="$OUT/src"; mkdir -p "$SRC"
JADX="$(command -v jadx || echo "$HOME/bughunters/jadx/bin/jadx")"
[ -x "$JADX" ] || { echo "!! jadx নেই"; exit 1; }

# অগ্রাধিকার: যেখানে ডেটা, আর যেখানে ফাইল/intent হাতানোর সম্ভাবনা বেশি।
# Tier 1 (gms, AGSA, gm) ইচ্ছে করে শেষে — বিশাল, আর ভিড়ও সবচেয়ে বেশি।
PRIORITY=(
  com.google.android.apps.photos
  com.google.android.apps.messaging
  com.google.android.apps.docs
  com.google.android.apps.walletnfcrel
  com.google.android.apps.tachyon
  com.google.android.apps.dynamite
  com.google.android.apps.nbu.files
  com.google.android.apps.safetyhub
  com.google.android.apps.chromecast.app
  com.google.android.apps.maps
  com.google.android.apps.subscriptions.red
  com.google.android.apps.healthdata
  com.google.android.apps.fitness
  com.google.android.apps.kids.familylink
  com.google.android.apps.authenticator2
  com.google.android.apps.credentialmanager
  com.google.android.apps.wear.companion
  com.google.android.apps.wearables.maestro.companion
  com.google.android.apps.tasks
  com.google.android.apps.classroom
  com.google.android.apps.enterprise.cpanel
  com.google.android.apps.playconsole
  com.google.android.apps.finance
  com.google.android.apps.labs.language.tailwind
  com.google.android.apps.labs.whisk
  com.google.android.apps.seekh
  com.google.android.apps.accessibility.voiceaccess
  com.google.android.apps.debugdispatch
)

DONE=0; SKIP=0; FAIL=0
for pkg in "${PRIORITY[@]}"; do
  base="$APK/$pkg/base.apk"
  [ -f "$base" ] || { echo "-- $pkg : apk নেই"; continue; }

  # পুনরারম্ভযোগ্য: আগে শেষ হওয়া থাকলে আবার করবো না। sources/ ডিরেক্টরি
  # আছে কিনা দেখি — jadx অর্ধেক পথে মরলে সেটা থাকে না বা খালি থাকে।
  if [ -d "$SRC/$pkg/sources" ] && [ "$(find "$SRC/$pkg/sources" -name '*.java' -print -quit 2>/dev/null)" ]; then
    echo "== $pkg : আগেই হয়েছে, বাদ"; SKIP=$((SKIP+1)); continue
  fi

  echo "== $pkg : decompile শুরু $(date +%H:%M:%S)"
  if "$JADX" -d "$SRC/$pkg" "$base" > "$SRC/$pkg.jadx.log" 2>&1; then
    n=$(find "$SRC/$pkg/sources" -name '*.java' 2>/dev/null | wc -l)
    echo "   শেষ $(date +%H:%M:%S)  $n টা java ফাইল"
    DONE=$((DONE+1))
  else
    # jadx প্রায়ই "finished with errors" দিয়ে exit 1 দেয় অথচ সোর্স লেখে।
    # তাই ফাইল গুনে সিদ্ধান্ত নাও, exit code দেখে নয়।
    n=$(find "$SRC/$pkg/sources" -name '*.java' 2>/dev/null | wc -l)
    if [ "$n" -gt 100 ]; then
      echo "   ত্রুটিসহ শেষ, কিন্তু $n টা ফাইল লেখা হয়েছে — ব্যবহারযোগ্য"
      DONE=$((DONE+1))
    else
      echo "   !! ব্যর্থ ($n ফাইল) — $SRC/$pkg.jadx.log দেখো"
      FAIL=$((FAIL+1))
    fi
  fi
done

echo
echo "== সারাংশ =="
echo "decompile হয়েছে: $DONE   আগেই ছিল: $SKIP   ব্যর্থ: $FAIL"
echo "পরের ধাপ: ./scripts/mvrp-static.sh"
