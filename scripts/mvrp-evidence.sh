#!/usr/bin/env bash
# mvrp-evidence.sh — G-F003-এর স্ক্রিনশট। দুই app, একটাই broadcast, কাঁচা রেকর্ড।
#
# কেন আলাদা স্ক্রিপ্ট:
#   `dumpsys activity broadcasts` কয়েক হাজার লাইন। আগে একবার `head -6` দিয়ে
#   ছাঁটতে গিয়ে control-এর পুরনো দুটো রেকর্ডই ছয় লাইন খেয়ে ফেলেছিল, আর
#   probe-এর DELIVERED লাইনটা চাপা পড়ে গিয়েছিল — "প্রমাণ নেই" মনে হয়েছিল
#   যখন প্রমাণ ছিল।
#
#   তাই ছাঁটাই গুনে নয়, সময় দিয়ে: প্রতি caller-এর যে রেকর্ডের
#   enqueueClockTime সবচেয়ে নতুন, সেটাই নেওয়া হয়। ক্রম অনুমান করা হয় না —
#   ইতিহাস নতুন-আগে ছাপায়, তাই "শেষ ব্লক" নিলে উল্টো সবচেয়ে পুরনোটা আসত।
#   আর সেই নতুন রেকর্ডটা এই রানের শুরুর আগের হলে স্ক্রিপ্ট BROKEN বলে থামে:
#   অর্ধেক ছবি স্ক্রিনশট করার চেয়ে কিছু না করা ভালো।
#
# ব্যবহার:  ./mvrp-evidence.sh
set -uo pipefail

PROBE="com.cindrasec.mvrpprobe"
CTL="com.cindrasec.mvrpctl"
ACT="com.cindrasec.mvrpprobe.MainActivity"   # control-এ package বদলেছে, ক্লাস নয়
ACTION="com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED"
TMP="${TMPDIR:-/tmp}"
RAW="$TMP/mvrp-evidence-$$.txt"
trap 'rm -f "$RAW"' EXIT

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! device connected নয়"; exit 1; }

# ---- CONTROL ১: দুটো app-ই ইনস্টল আছে তো ----
for p in "$PROBE" "$CTL"; do
  if ! adb shell pm path "$p" </dev/null 2>/dev/null | tr -d '\r' | grep -qF 'package:'; then
    echo "!! BROKEN: $p ইনস্টল নেই — তুলনাটা হবে না"; exit 2
  fi
done

perms() {   # perms <pkg> : install permissions ব্লকের grant করা নামগুলো
  adb shell dumpsys package "$1" </dev/null 2>/dev/null | tr -d '\r' \
    | awk '/install permissions:/{f=1;next} f&&/granted=/{sub(/^[[:space:]]*/,"");print;next} f&&/:$/{exit}'
}

echo "== দুই app-কে ইনস্টলে যা দেওয়া হলো =="
echo "-- POC ($PROBE) --"
perms "$PROBE" | sed 's/^/   /'
echo "-- CONTROL ($CTL) --"
C=$(perms "$CTL" | grep -c . )
if [ "$C" -eq 0 ]; then echo "   (কিছুই নেই)"; else perms "$CTL" | sed 's/^/   /'; fi
echo

# এই রানের শুরু, ডিভাইসের ঘড়িতে, dumpsys যে ফরম্যাটে ছাপায় সেই ফরম্যাটেই
START=$(adb shell date '+%Y-%m-%d %H:%M:%S' </dev/null 2>/dev/null | tr -d '\r')
[ -n "$START" ] || { echo "!! BROKEN: ডিভাইসের ঘড়ি পড়া গেল না"; exit 2; }
echo "রান শুরু (ডিভাইসের ঘড়ি): $START"
echo

fire() {
  adb shell am start -n "$1/$ACT" --es action blescan </dev/null >/dev/null 2>&1
  sleep 3
  adb shell am force-stop "$1" </dev/null >/dev/null 2>&1
}

echo "[1/2] CONTROL পাঠাচ্ছে"
fire "$CTL"
echo "[2/2] POC পাঠাচ্ছে"
fire "$PROBE"
sleep 2

adb shell dumpsys activity broadcasts </dev/null 2>/dev/null | tr -d '\r' > "$RAW"

# ---- CONTROL ২: dumpsys আদৌ পড়া গেল তো ----
LINES=$(grep -c . "$RAW")
if [ "$LINES" -lt 200 ]; then
  echo "!! BROKEN: dumpsys থেকে মাত্র $LINES লাইন — পড়া যাচ্ছে না"; exit 2
fi

# প্রতি caller-এর সবচেয়ে নতুন BLE_SCANNED রেকর্ড-ব্লক।
# প্রথম লাইনে `ET<tab><enqueueClockTime>`, তারপর ব্লকের লাইনগুলো।
best_block() {   # best_block <pkg>
  awk -v act="$ACTION" -v who="$1" '
    function flush() {
      if (has && c == who && et != "" && (bt == "" || et > bt)) {
        bt = et; bn = n
        for (i = 1; i <= n; i++) bb[i] = buf[i]
      }
      n = 0; has = 0; c = ""; et = ""
    }
    /BroadcastRecord\{/ { flush() }
    { buf[++n] = $0 }
    index($0, act) { has = 1 }
    /caller=/ { x = $0; sub(/.*caller=/, "", x); sub(/[\/ ].*/, "", x); c = x }
    /enqueueClockTime=/ {
      x = $0; sub(/.*enqueueClockTime=/, "", x)
      # ফরম্যাট: yyyy-MM-dd HH:mm:ss.SSS — দুই টোকেন, তাই দুটোই রাখি
      split(x, f, " "); et = f[1] " " f[2]
    }
    END {
      flush()
      if (bt == "") exit 0
      printf "ET\t%s\n", bt
      for (i = 1; i <= bn; i++) print bb[i]
    }
  ' "$RAW"
}

show() {   # show <pkg> <label>
  local blk et
  blk=$(best_block "$1")
  if [ -z "$blk" ]; then
    echo "!! BROKEN: $1 -এর কোনো BLE_SCANNED রেকর্ড নেই"
    return 1
  fi
  et=$(printf '%s\n' "$blk" | awk -F'\t' '/^ET\t/{print $2; exit}')
  # ---- CONTROL ৩: এই রেকর্ডটা এই রানেরই তো, পুরনো ইতিহাস নয় ----
  if [ "$et" \< "$START" ]; then
    echo "!! BROKEN: $1 -এর সবচেয়ে নতুন রেকর্ড $et — রান শুরুর ($START) আগের।"
    echo "!!         মানে এই রানে ওর পাঠানোটা কোনো রেকর্ড তৈরি করেনি।"
    return 1
  fi
  echo "---- $2 ----"
  printf '%s\n' "$blk" | grep -vE '^ET\b' | grep -E \
    'BroadcastRecord\{|caller=|enqueueClockTime=|DELIVERED|SKIPPED|^ *reason:|requires ' \
    | sed 's/^[[:space:]]*/   /'
  echo
}

echo "== ActivityManager-এর নিজের broadcast ইতিহাস =="
echo
ok=0
show "$CTL"   "CONTROL  $CTL  (কোনো permission ঘোষণা করে না)" || ok=1
show "$PROBE" "POC      $PROBE  (শুধু ওই দুটো নাম ঘোষণা করে)" || ok=1

if [ "$ok" -ne 0 ]; then
  echo "!! একটা শাখার রেকর্ড নেই — এই আউটপুট স্ক্রিনশট করো না।"
  exit 2
fi

cat <<'NOTE'
== পড়ার নিয়ম ==
একই action, একই কোড, একই সই করা কী — পার্থক্য শুধু manifest-এ দুটো
<permission> সারি। control-এ SKIPPED আর reason-এ Permission Denial,
poc-এ DELIVERED। ওই দুটো সারি বাদে দুই app অভিন্ন, তাই কারণটা অন্য
কিছু হতে পারে না।
NOTE
