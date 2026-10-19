#!/usr/bin/env bash
# mvrp-services.sh — সব exported, permission-বিহীন service-এ bind করে
#                    descriptor দেখে ছাঁকো।
#
# কেন descriptor:
#   আজ রাতে তিনটে service-এ bind হয়েছে, তিনটেরই descriptor খালি। খালি মানে
#   grpc-over-binder endpoint — নিরাপত্তা transport স্তরে, framework-এর
#   SecurityPolicy-তে। ওখানে ডেভেলপারের ভুল থাকার সুযোগ কম।
#
#   descriptor **খালি নয়** মানে আসল AIDL interface — ডেভেলপারের নিজের লেখা
#   Stub, নিজের লেখা (বা ভুলে না-লেখা) caller যাচাই। ভুল ওখানেই থাকে।
#
#   তাই নাম দেখে লক্ষ্য বাছার চেয়ে descriptor দেখে বাছা ভালো ছাঁকনি।
#
# লাগবে: poc/mvrp-probe ইনস্টল করা থাকতে হবে।
# ব্যবহার:  ./mvrp-services.sh                 # সব decode করা app
#           ./mvrp-services.sh com.google.android.apps.restore
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded"; REP="$OUT/services"; mkdir -p "$REP"
LOG="$REP/services-$(date +%Y%m%d-%H%M).txt"
PROBE="com.cindrasec.mvrpprobe/.MainActivity"
WAIT="${WAIT:-3}"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }
adb shell pm path com.cindrasec.mvrpprobe >/dev/null 2>&1 || {
  echo "!! mvrp-probe ইনস্টল করা নেই — poc/mvrp-probe/build.sh চালাও"; exit 1; }

pkgs=("$@")
[ ${#pkgs[@]} -eq 0 ] && mapfile -t pkgs < <(ls -1 "$DEC" 2>/dev/null | grep -v '\.log$')

probe() {   # probe <pkg> <cls> -> logcat-এর MVRP লাইনগুলো
  adb logcat -c >/dev/null 2>&1
  adb shell am start -n "$PROBE" --es action bind --es pkg "$1" --es cls "$2" >/dev/null 2>&1
  sleep "$WAIT"
  adb logcat -d -s MVRP 2>/dev/null | tr -d '\r'
}

{
echo "# exported service bind sweep"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device : $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
echo "# caller : mvrp-probe, uid=$(adb shell dumpsys package com.cindrasec.mvrpprobe | tr -d '\r' | awk -F= '/userId=/{print $2; exit}')  (permission ছাড়া app)"
echo

echo "== CONTROL =="
co=$(probe "com.cindrasec.mvrpprobe" "com.cindrasec.mvrpprobe.NoSuchService")
if grep -q 'bindService() returned false' <<<"$co"; then
  echo "SENTINEL অস্তিত্বহীন service -> bindService() false  (সঠিক)"
else
  echo "!! CONTROL FAIL: অস্তিত্বহীন service-ও false দেয়নি। এই রানে কিছু প্রমাণ হয় না।"
  sed 's/^/   /' <<<"$co"; exit 3
fi
echo

TOTAL=0; BOUND=0; AIDL=0
for pkg in "${pkgs[@]}"; do
  m="$DEC/$pkg/resources/AndroidManifest.xml"
  [ -f "$m" ] || continue

  # exported + permission ছাড়া + enabled!=false service
  mapfile -t svcs < <(python3 -I - "$m" <<'PY'
import sys, xml.etree.ElementTree as ET
AND="http://schemas.android.com/apk/res/android"
def a(e,n,d=None): return e.get("{%s}%s"%(AND,n),d)
app=ET.parse(sys.argv[1]).getroot().find("application")
for s in app.findall("service"):
    if a(s,"enabled")=="false" or a(s,"permission"): continue
    exp=a(s,"exported")
    if exp=="true" or (exp is None and s.findall("intent-filter")):
        print(a(s,"name"))
PY
)
  [ ${#svcs[@]} -eq 0 ] && continue
  echo "== $pkg  (${#svcs[@]} service)"
  for cls in "${svcs[@]}"; do
    [ -z "$cls" ] && continue
    TOTAL=$((TOTAL+1))
    o=$(probe "$pkg" "$cls")
    if grep -q 'BOUND' <<<"$o"; then
      BOUND=$((BOUND+1))
      d=$(grep -m1 'descriptor =' <<<"$o" | sed 's/.*descriptor = //')
      if [ -n "${d// /}" ]; then
        AIDL=$((AIDL+1))
        printf '  AIDL    %s\n          descriptor = %s\n' "$cls" "$d"
      else
        printf '  grpc    %s   (descriptor খালি)\n' "$cls"
      fi
    elif grep -q 'NULL BINDING' <<<"$o"; then
      printf '  null    %s\n' "$cls"
    elif grep -q 'SecurityException' <<<"$o"; then
      printf '  DENIED  %s\n' "$cls"
    fi
    # false / কিছুই না -> চুপ, এগুলোই সংখ্যাগরিষ্ঠ
  done
  echo
done

echo "== সারাংশ =="
echo "চেষ্টা: $TOTAL   bind হয়েছে: $BOUND   তার মধ্যে AIDL: $AIDL"
cat <<'NOTE'

AIDL    descriptor খালি নয় -> ডেভেলপারের নিজের লেখা interface। caller যাচাই
        তাকেই লিখতে হয়, আর ভুল ওখানেই থাকে। **এগুলোই আগে দেখো।**
        পরের ধাপ: jadx-এ ওই Stub-এর method আর তার ভেতরের
        Binder.getCallingUid() / checkCallingPermission খোঁজো।
grpc    descriptor খালি -> framework endpoint, নিরাপত্তা transport স্তরে
        (SecurityPolicy, প্রতি সংযোগে calling UID যাচাই)। ভুলের সুযোগ কম।
null    onBind null দিয়েছে — পৌঁছেছে কিন্তু কিছু দেয়নি।
DENIED  সীমানা ধরেছে।

মনে রাখো: bind হওয়া = দরজা, finding নয় (CLAUDE.md FO-8)।
"attacker আসলে কী পেল?" — একটাও বাইট না পেলে DROP.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
