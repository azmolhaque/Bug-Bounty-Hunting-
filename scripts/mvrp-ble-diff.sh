#!/usr/bin/env bash
# mvrp-ble-diff.sh — একবারের differential নয়, বহু রাউন্ডের।
#
# কেন এই যন্ত্রটা দরকার হলো:
#   G-F003-এ probe থেকে broadcast পাঠানোর ০.৭৭ সেকেন্ড পরে Google Home-এর
#   worker লগ লিখেছিল, আর control রানে লেখেনি। আমি সেটাকে প্রমাণ ধরে
#   রিপোর্ট লিখে ফেলেছিলাম। পরে দেখা গেল ওই লাইনটা আর কখনো আসে না —
#   Google Home নিজেই periodic BLE কাজ করে, আর ওটা কাকতাল ছিল।
#
#   control থাকা যথেষ্ট নয়। **একবারের** control কিছুই আলাদা করে না, কারণ
#   পটভূমিতে নিজে থেকেই ঘটতে থাকা ঘটনা এক রানে পড়তে পারে, অন্যটায় না।
#
# পদ্ধতি: N রাউন্ড, প্রতিবার দুই app পর্যায়ক্রমে, আর তৃতীয় একটা শাখা —
# কিছুই না পাঠিয়ে শুধু অপেক্ষা (BASELINE)। পটভূমির কোলাহল থাকলে সেটা
# তিন কলামেই দেখা যাবে; আসল পার্থক্য কেবল এক কলামে।
#
# ব্যবহার:  ./mvrp-ble-diff.sh [রাউন্ড সংখ্যা]
set -uo pipefail

ROUNDS="${1:-5}"
WAIT="${WAIT:-7}"
TARGET="com.google.android.apps.chromecast.app"
PROBE="com.cindrasec.mvrpprobe"
CTL="com.cindrasec.mvrpctl"
ACT="com.cindrasec.mvrpprobe.MainActivity"
OUT="${MVRP_OUT:-$HOME/mvrp}"; REP="$OUT/blediff"; mkdir -p "$REP"
LOG="$REP/blediff-$(date +%Y%m%d-%H%M).txt"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! device connected নয়"; exit 1; }

PID=$(adb shell pidof "$TARGET" 2>/dev/null </dev/null | tr -d '\r' | awk '{print $1}')
[ -n "$PID" ] || { echo "!! $TARGET চলছে না — একবার খুলে আবার চালাও"; exit 1; }

# Google Home ওই উইন্ডোতে কিছু লিখল কিনা, আর কী লিখল
observe() {
  adb logcat -d --pid="$PID" 2>/dev/null </dev/null | tr -d '\r' | grep -v '^---------' | grep -c .
}
observe_what() {
  adb logcat -d --pid="$PID" 2>/dev/null </dev/null | tr -d '\r' \
    | grep -vE '^---------' | grep -oE 'Found [0-9]+ device|LockProximity[A-Za-z]*|isLeEnabled' | sort -u | tr '\n' ' '
}

fire() {   # fire <launcher-pkg|BASELINE>
  adb logcat -c </dev/null >/dev/null 2>&1
  if [ "$1" != "BASELINE" ]; then
    adb shell am start -n "$1/$ACT" --es action blescan </dev/null >/dev/null 2>&1
  fi
  sleep "$WAIT"
}

{
echo "# BLE differential — $ROUNDS রাউন্ড, তিন শাখা"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# target : $TARGET (pid $PID)"
echo "# wait   : ${WAIT}s"
echo
echo "# PROBE    = permission ঘোষিত"
echo "# CTL      = কোনো permission নেই"
echo "# BASELINE = কিছুই পাঠানো হয়নি, শুধু অপেক্ষা"
echo "# সংখ্যা = ওই উইন্ডোতে Google Home কত লাইন লিখেছে"
echo
printf '%-7s %-22s %-22s %s\n' "রাউন্ড" "PROBE" "CTL" "BASELINE"
echo "-------------------------------------------------------------------------------"

pn=0; cn=0; bn=0
for i in $(seq 1 "$ROUNDS"); do
  fire "$PROBE";  p=$(observe); pw=$(observe_what)
  fire "$CTL";    c=$(observe); cw=$(observe_what)
  fire BASELINE;  b=$(observe); bw=$(observe_what)
  [ "$p" -gt 0 ] && pn=$((pn+1))
  [ "$c" -gt 0 ] && cn=$((cn+1))
  [ "$b" -gt 0 ] && bn=$((bn+1))
  printf '%-7s %-22s %-22s %s\n' "$i" "$p  ${pw:-—}" "$c  ${cw:-—}" "$b  ${bw:-—}"
done

echo
echo "== সারাংশ =="
echo "PROBE-এ Google Home সাড়া দিয়েছে    : $pn/$ROUNDS রাউন্ডে"
echo "CTL-এ সাড়া দিয়েছে                  : $cn/$ROUNDS"
echo "BASELINE-এ (কিছু না পাঠিয়েও)        : $bn/$ROUNDS"
cat <<'NOTE'

== পড়ার নিয়ম ==
BASELINE > 0  -> পটভূমিতে Google Home নিজেই লেখে। তখন PROBE-এর একটা হিট
                 কিছুই প্রমাণ করে না — ঠিক এই ফাঁদেই G-F003 পড়েছিল।
PROBE ≈ CTL   -> permission অপ্রাসঙ্গিক। finding নেই।
PROBE উচ্চ, CTL ও BASELINE শূন্য  -> তখনই differential বাস্তব, আর তখনই
                 লেখা যায় যে permission-ই দরজা।
"Found N device" -> আমার পাঠানো ScanResult তালিকা ভেতরে পৌঁছেছে। এটাই
                 একমাত্র লাইন যা আমার ডেটা ছাড়া আসতে পারে না।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
