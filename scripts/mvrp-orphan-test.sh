#!/usr/bin/env bash
# mvrp-orphan-test.sh — অনাথ-permission তালিকার প্রতিটা লক্ষ্যে differential।
#
# mvrp-orphan.sh বলে কোন permission অনাথ। এই স্ক্রিপ্ট বলে **তাতে কী হয়**:
# প্রতিটা পাহারা দেওয়া component-এ দুবার পৌঁছানোর চেষ্টা হয় —
#   PROBE = com.cindrasec.mvrpprobe   (অনাথ permission গুলো দাবি করা)
#   CTL   = com.cindrasec.mvrpctl     (হুবহু একই কোড, কোনো permission নেই)
# দুটোর মধ্যে পার্থক্যই একমাত্র অর্থবহ ফল। সফল পৌঁছানো একা কিছু প্রমাণ
# করে না — component-টা এমনিতেই খোলা থাকতে পারে।
#
# আগে লাগবে:
#   MANIFEST=AndroidManifest.orphan.xml ./build.sh && adb install -r out/mvrp-probe.apk
#   PKG=com.cindrasec.mvrpctl ./build.sh && adb install -r out/com.cindrasec.mvrpctl.apk
#
# ব্যবহার:  ./mvrp-orphan-test.sh [orphan-report.txt]
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
REPORT="${1:-$(ls -1t "$OUT"/orphan/orphan-*.txt 2>/dev/null | head -1)}"
PROBE="com.cindrasec.mvrpprobe"
CTL="com.cindrasec.mvrpctl"
ACT="com.cindrasec.mvrpprobe.MainActivity"
WAIT="${WAIT:-3}"
LOG="$OUT/orphan/test-$(date +%Y%m%d-%H%M).txt"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }
[ -f "$REPORT" ] || { echo "!! orphan রিপোর্ট নেই — আগে ./mvrp-orphan.sh চালাও"; exit 1; }

# ---------- control: দুটো app-ই ইনস্টল আছে তো ----------
# পাইপের মধ্যে grep -q + pipefail = SIGPIPE দৌড়: grep প্রথম মিলেই বেরোয়,
# উপরের কমান্ড SIGPIPE খায়, pipefail পুরোটাকে ব্যর্থ বলে — আর মিল পাওয়া
# সত্ত্বেও "ইনস্টল নেই" ছাপা হয়। আজ রাতে এই বাগটা একবার android.jar
# যাচাইয়ে সারানো হয়েছিল; সারাইটা সাধারণীকরণ করিনি বলে আবার লিখেছি।
# সমাধান: পাইপ নয়, here-string।
PKGLIST=$(adb shell pm list packages 2>/dev/null </dev/null | tr -d '\r')
NPKG=$(grep -c . <<<"$PKGLIST")
for p in "$PROBE" "$CTL"; do
  if ! grep -qx "package:$p" <<<"$PKGLIST"; then
    # নীরব "নেই" বলব না — তালিকাটা আদৌ পড়া গেছে কিনা সেটাই আগে দেখাও।
    # আগের সংস্করণে এখানে পাইপ+grep -q ছিল আর ইনস্টল সফল হওয়া সত্ত্বেও
    # "নেই" ছাপা হয়েছিল; কারণটা নিশ্চিত হয়নি, তাই প্রমাণ ছাপানো হচ্ছে।
    echo "!! $p তালিকায় পাওয়া গেল না।"
    echo "   pm list packages পড়া গেছে: $NPKG টা লাইন"
    echo "   cindrasec-সংক্রান্ত লাইন:"
    grep -i 'cindrasec' <<<"$PKGLIST" | sed 's/^/     /' || echo "     (একটাও নেই)"
    echo "   সরাসরি যাচাই:  adb shell pm path $p"
    exit 1
  fi
done
# probe-এ permission আছে, ctl-এ নেই — এটাই পুরো পরীক্ষার ভিত্তি
DP=$(adb shell dumpsys package "$PROBE" 2>/dev/null </dev/null | tr -d '\r')
DC=$(adb shell dumpsys package "$CTL"   2>/dev/null </dev/null | tr -d '\r')
NP=$(grep -c 'granted=true' <<<"$DP")
NC=$(grep -c 'granted=true' <<<"$DC")
echo "== CONTROL =="
echo "PROBE granted=true : $NP"
echo "CTL   granted=true : $NC"
if [ "$NP" -le "$NC" ]; then
  echo "!! BROKEN: probe-এর কাছে ctl-এর চেয়ে বেশি permission নেই — differential অর্থহীন"
  exit 2
fi
echo "POSITIVE  দুটো app-এর permission ভিন্ন, তাই পার্থক্য মাপার যোগ্য"
echo

# ---------- একটা চেষ্টা, ফল শ্রেণিবদ্ধ ----------
try() {   # try <launcher-pkg> <action> <target-pkg> <target-cls>
  local app="$1" act="$2" tp="$3" tc="$4" o
  adb logcat -c >/dev/null 2>&1 </dev/null
  adb shell am start -n "$app/$ACT" --es action "$act" \
      --es pkg "$tp" --es cls "$tc" >/dev/null 2>&1 </dev/null
  sleep "$WAIT"
  o=$(adb logcat -d 2>/dev/null </dev/null | tr -d '\r' \
      | grep -E "MVRP|Permission Denial|SecurityException" | tail -20)
  if   grep -q 'Permission Denial' <<<"$o";                  then echo "DENIED"
  elif grep -q 'SECURITY' <<<"$o";                           then echo "DENIED"
  elif grep -q 'bindService() returned true' <<<"$o";        then echo "BOUND"
  elif grep -q 'bindService() returned false' <<<"$o";       then echo "NOBIND"
  elif grep -qE 'startActivity\(\) |sendBroadcast\(\) ' <<<"$o"; then echo "ACCEPTED"
  elif grep -q 'startService() returned null' <<<"$o";       then echo "NOSVC"
  elif grep -q 'startService() returned' <<<"$o";            then echo "STARTED"
  elif grep -q 'THROWN' <<<"$o";                             then echo "THROWN"
  else echo "NOSIGNAL"
  fi
}

kind_action() {
  case "$1" in
    activity|activity-alias) echo startact ;;
    service)                 echo bind ;;
    receiver)                echo broadcast ;;
    provider)                echo query ;;
    *)                       echo startact ;;
  esac
}

{
echo "# orphan differential — PROBE (permission আছে) বনাম CTL (নেই)"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# report : $REPORT"
echo "# ip     : $(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo n/a)"
echo
printf '%-9s %-9s %-11s %s\n' "PROBE" "CTL" "kind" "target"
echo "-------------------------------------------------------------------------------"

pkg=""; perm=""
while IFS= read -r line; do
  case "$line" in
    "== "*) pkg="${line#== }" ;;
    *"ORPHANED"*) perm=$(awk '{print $NF}' <<<"$line") ;;
    *"["*"]"*)
      # "      পাহারা দিচ্ছে: [kind] cls  (attr)"
      kind=$(sed -n 's/.*\[\([a-z-]*\)\].*/\1/p' <<<"$line")
      cls=$(sed 's/.*\] *//; s/ *(.*//' <<<"$line" | tr -d ' ')
      [ -z "$kind" ] && continue
      [ -z "$cls" ] && continue
      a=$(kind_action "$kind")
      p=$(try "$PROBE" "$a" "$pkg" "$cls")
      c=$(try "$CTL"   "$a" "$pkg" "$cls")
      mark=""
      [ "$p" != "$c" ] && mark="   <<< পার্থক্য"
      printf '%-9s %-9s %-11s %s%s\n' "$p" "$c" "$kind" "${cls##*.}" "$mark"
      [ -n "$mark" ] && echo "            $pkg/$cls" && echo "            perm: $perm"
      ;;
  esac
done < "$REPORT"

cat <<'NOTE'

== পড়ার নিয়ম ==
পার্থক্য নেই  -> permission অপ্রাসঙ্গিক। component হয় সবার জন্য খোলা, নয়
                দুজনের জন্যই বন্ধ (অন্য কোনো পাহারা)। finding নয়।
PROBE≠CTL    -> permission-ই দরজা। **এখনো precondition** — S55 দেখাও যে
                AGSA ভেতরে ঢোকার পরেও রানটাইমে আবার যাচাই করে finish() করে।
                পরের প্রশ্ন সবসময় একটাই: ঢুকে **কী পাওয়া গেল**।
NOSIGNAL     -> মাপ হয়নি, নেতিবাচক নয়। WAIT বাড়াও।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
