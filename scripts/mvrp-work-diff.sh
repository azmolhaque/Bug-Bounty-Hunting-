#!/usr/bin/env bash
# mvrp-work-diff.sh — লগ নয়, কাজের সারি মাপো।
#
# কেন:
#   G-F003-এ আমি ধরে নিয়েছিলাম LIST_SCAN_RESULT শাখা চলে না, কারণ
#   "Found %d device" লাইনটা আসেনি। কিন্তু ওটা লেখা হয় Google-এর logger-এর
#   নিচু স্তরে (c.e()), যা রিলিজ বিল্ডে চাপা পড়ে। worker-এর যে লাইনটা
#   একবার দেখা গিয়েছিল সেটা উঁচু স্তরে (a.g() -> logcat W)।
#
#   অর্থাৎ লগের অনুপস্থিতি কিছুই প্রমাণ করে না। আবার সেই পুরনো ভুল।
#
#   কিন্তু WorkManager যখন কাজ সারিতে দেয়, সেটা JobScheduler-এ গিয়ে বসে —
#   আর `dumpsys jobscheduler` তা দেখায়, logger-এর স্তর নির্বিশেষে।
#   এটাই লগ-নিরপেক্ষ পর্যবেক্ষণ।
#
# তিন শাখা আগের মতোই: PROBE / CTL / BASELINE। পটভূমিতে app নিজেই কাজ
# সারিতে দিলে সেটা তিন কলামেই দেখা যাবে।
#
# ব্যবহার:  ./mvrp-work-diff.sh [রাউন্ড]
set -uo pipefail

ROUNDS="${1:-3}"
WAIT="${WAIT:-9}"
TARGET="${TARGET:-com.google.android.apps.chromecast.app}"
PROBE="com.cindrasec.mvrpprobe"
CTL="com.cindrasec.mvrpctl"
ACT="com.cindrasec.mvrpprobe.MainActivity"
ACTION="${ACTION:-blescan}"
OUT="${MVRP_OUT:-$HOME/mvrp}"; REP="$OUT/workdiff"; mkdir -p "$REP"
LOG="$REP/workdiff-$(date +%Y%m%d-%H%M).txt"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! device connected নয়"; exit 1; }

# লক্ষ্য app-এর জন্য JobScheduler-এ এখন কী আছে
jobs_now() {
  adb shell dumpsys jobscheduler 2>/dev/null </dev/null | tr -d '\r' \
    | grep -F "$TARGET" | sed 's/^[[:space:]]*//' | sort
}
jobs_count() { jobs_now | grep -c . ; }

snap_fire_snap() {   # snap_fire_snap <app|BASELINE> -> "before after"
  local who="$1" b a
  b=$(jobs_count)
  if [ "$who" != "BASELINE" ]; then
    adb shell am start -n "$who/$ACT" --es action "$ACTION" </dev/null >/dev/null 2>&1
  fi
  sleep "$WAIT"
  a=$(jobs_count)
  echo "$b $a"
}

{
echo "# work-queue differential — লগ নয়, JobScheduler"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# target : $TARGET"
echo "# action : $ACTION   wait=${WAIT}s   rounds=$ROUNDS"
echo

# ---- CONTROL: dumpsys আদৌ পড়া যাচ্ছে তো ----
TOTAL=$(adb shell dumpsys jobscheduler 2>/dev/null </dev/null | tr -d '\r' | grep -c . )
if [ "$TOTAL" -lt 50 ]; then
  echo "!! BROKEN: dumpsys jobscheduler থেকে মাত্র $TOTAL লাইন — পড়া যাচ্ছে না"
  exit 2
fi
echo "POSITIVE  dumpsys jobscheduler পড়া গেছে ($TOTAL লাইন)"
BASE=$(jobs_count)
echo "POSITIVE  $TARGET-এর জন্য এখন $BASE টা এন্ট্রি (শুরুর অবস্থা)"
echo

printf '%-7s %-16s %-16s %s\n' "রাউন্ড" "PROBE" "CTL" "BASELINE"
echo "----------------------------------------------------------------"
pd=0; cd=0; bd=0
for i in $(seq 1 "$ROUNDS"); do
  read -r pb pa <<<"$(snap_fire_snap "$PROBE")"
  read -r cb ca <<<"$(snap_fire_snap "$CTL")"
  read -r bb ba <<<"$(snap_fire_snap BASELINE)"
  dp=$((pa-pb)); dc=$((ca-cb)); db=$((ba-bb))
  [ "$dp" -ne 0 ] && pd=$((pd+1))
  [ "$dc" -ne 0 ] && cd=$((cd+1))
  [ "$db" -ne 0 ] && bd=$((bd+1))
  printf '%-7s %-16s %-16s %s\n' "$i" "$pb -> $pa" "$cb -> $ca" "$bb -> $ba"
done

echo
echo "== সারাংশ =="
echo "PROBE-এ সারি বদলেছে    : $pd/$ROUNDS রাউন্ডে"
echo "CTL-এ                  : $cd/$ROUNDS"
echo "BASELINE-এ             : $bd/$ROUNDS"
echo
echo "== এখন সারিতে যা আছে =="
jobs_now | head -20

cat <<'NOTE'

== পড়ার নিয়ম ==
সংখ্যা স্থির থাকা মানে **কাজ সারিতে যায়নি** — কিন্তু সতর্কতা: WorkManager
দ্রুত চলা কাজ সারিতে বসার আগেই শেষ করে ফেলতে পারে, তাই স্থির সংখ্যা
"চলেনি"-র প্রমাণ নয়, "ধরতে পারিনি"-র। WAIT কমিয়ে (WAIT=2) আবার দেখো।
PROBE-এ বদল, CTL ও BASELINE-এ নয় -> তখনই বলা যায় broadcast কাজ সারিতে
দিয়েছে, আর সেটাই লগ-নিরপেক্ষ প্রমাণ।
তিন কলামেই বদল -> app নিজে থেকেই কাজ সারিতে দেয়। তুলনাটা অর্থহীন।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
