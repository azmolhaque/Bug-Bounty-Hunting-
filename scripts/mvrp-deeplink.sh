#!/usr/bin/env bash
# mvrp-deeplink.sh — exported deeplink-গুলোতে একটা canary URL গুঁজে দিয়ে
#                    দেখো কোন app সেটা আসলে আনতে যায়।
#
# কেন এটা আলাদা:
#   service দিকটা শেষ। deeplink দিকটা আমরা একবারও ছুঁইনি, অথচ rules-এ
#   "Intent redirections leading to launching non-exported application
#   components" নাম ধরে পুরস্কৃত, আর BROWSABLE deeplink মানে scenario 2
#   ("user follows a link") — Tier 2-তে theft হলে scenario 3-এর চারগুণ।
#
# canary কীভাবে:
#   adb reverse tcp:8777 — ফোনের 127.0.0.1:8777 তোমার মেশিনে আসে। বাইরের
#   ডোমেইন, DNS, OOB পরিষেবা কিছুই লাগে না, আর ট্রাফিক ডিভাইস ছাড়ে না।
#   কোনো app যদি আমাদের দেওয়া URL লোড করে, সার্ভারের লগে তার ছাপ পড়বে,
#   আর path-এ লেখা থাকবে কোন app কোন প্যারামিটারে।
#
# ব্যবহার:  ./mvrp-deeplink.sh [pkg ...]      # না দিলে সব decode করা app
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded"; REP="$OUT/deeplink"; mkdir -p "$REP"
STAMP=$(date +%Y%m%d-%H%M)
LOG="$REP/deeplink-$STAMP.txt"
SRVLOG="$REP/canary-$STAMP.log"
MAP="$REP/map-$STAMP.tsv"
PORT="${PORT:-8777}"
WAIT="${WAIT:-2}"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }

# URL-ধাঁচের প্যারামিটার নাম। আসল নাম কোডে, কিন্তু এই কটাই বাস্তবে
# সংখ্যাগরিষ্ঠ — ৬৪টা app decompile করার চেয়ে সস্তা।
PARAMS=(url link uri target redirect redirect_uri dest destination next
        continue returnUrl return_url callback deeplink deep_link web
        webview page src open)

# ফেরানো যায় না এমন কাজের ইঙ্গিত থাকলে ছোঁবো না (CLAUDE.md §7)
SKIP='delete|remove|reset|wipe|logout|signout|unsubscribe|purchase|pay|buy|checkout|transfer|send'

cleanup() {
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
  [ -z "${CANARY_BASE:-}" ] && adb reverse --remove "tcp:$PORT" >/dev/null 2>&1
}
trap cleanup EXIT

# ---- canary ----
# CANARY_BASE দিলে বাইরের HTTPS endpoint (interactsh ইত্যাদি), আর SRVLOG হবে
# সেই ক্লায়েন্টের লগ ফাইল।
#
# কেন বাইরের: app-এর WebView `http://` লোড করে না — Android 9+ cleartext
# ব্লক করে (net::ERR_CLEARTEXT_NOT_PERMITTED, চোখে দেখা)। আর স্থানীয় HTTPS-ও
# চলে না: self-signed সার্টিফিকেট WebView প্রত্যাখ্যান করে, আর user-installed
# CA app বিশ্বাস করে না যদি না তার networkSecurityConfig বলে দেয়।
# তাই আসল সার্টিফিকেটওয়ালা endpoint ছাড়া উপায় নেই।
if [ -n "${CANARY_BASE:-}" ]; then
  SRVLOG="${CANARY_LOG:?CANARY_BASE দিলে CANARY_LOG-ও দাও (interactsh-এর -o ফাইল)}"
  [ -f "$SRVLOG" ] || : > "$SRVLOG"
  CAN="$CANARY_BASE"
else
  python3 -m http.server "$PORT" --bind 127.0.0.1 >"$SRVLOG" 2>&1 &
  SRV=$!
  sleep 1
  kill -0 "$SRV" 2>/dev/null || { echo "!! পোর্ট $PORT-এ সার্ভার চালু হয়নি"; exit 1; }
  adb reverse "tcp:$PORT" "tcp:$PORT" >/dev/null || { echo "!! adb reverse ব্যর্থ"; exit 1; }
  CAN="http://127.0.0.1:$PORT"
  echo "!! সতর্কতা: cleartext canary। app-এর WebView এটা লোড করবে না।"
  echo "!! প্রকৃত sweep-এর জন্য CANARY_BASE=https://... দাও।"
fi

# grep -c শূন্য ম্যাচে "0" ছাপে **আর** exit 1 দেয়, তাই `|| echo 0` দ্বিতীয়
# একটা 0 ছেপে "0\n0" বানায় — আর তুলনা "integer expression expected" বলে মরে,
# আর সেটা CONTROL FAIL হিসেবে দেখায় যদিও canary ঠিকই কাজ করছিল।
hits() { local n; n=$(grep -c 'GET /c/' "$SRVLOG" 2>/dev/null) || n=0; echo "${n:-0}"; }

{
echo "# deeplink canary sweep"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device : $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
echo "# canary : $CAN/c/<id>"
echo "# skip   : $SKIP"
echo

# ---- CONTROL: পুরো শৃঙ্খলটা কাজ করে কিনা ----
echo "== CONTROL =="
BEFORE=$(hits)
adb shell am start -a android.intent.action.VIEW \
    -d "$CAN/c/CONTROL" >/dev/null 2>&1 </dev/null
sleep 8
AFTER=$(hits)
if [ "$AFTER" -gt "$BEFORE" ]; then
  echo "POSITIVE  ব্রাউজার canary-তে পৌঁছেছে — reverse + সার্ভার দুটোই চলছে"
else
  echo "!! CONTROL FAIL: ব্রাউজারও canary-তে পৌঁছায়নি।"
  echo "!! এই রানে 'কোনো hit নেই' মানে কিছুই না। থামছি।"
  echo
  echo "   adb reverse তালিকা:"
  adb reverse --list 2>&1 </dev/null | sed 's/^/     /'
  echo "   সার্ভার লগ (শেষ ১০ লাইন):"
  tail -10 "$SRVLOG" 2>/dev/null | sed 's/^/     /'
  echo "   পর্দার অবস্থা:"
  adb shell dumpsys power 2>/dev/null </dev/null | grep -E 'mWakefulness=|mScreenOn' | head -3 | sed 's/^/     /'
  echo
  echo "   সবচেয়ে সম্ভাব্য কারণ: ফোনের পর্দা লক/ঘুমন্ত — তখন am start"
  echo "   Activity খোলে না। ঠিক করতে:"
  echo "     adb shell svc power stayon usb"
  echo "     adb shell input keyevent KEYCODE_WAKEUP"
  echo "   তারপর ফোন আনলক করে আবার চালাও।"
  exit 3
fi
adb shell am force-stop com.android.chrome >/dev/null 2>&1 </dev/null

# ---- app-স্তরের positive control ----
# ব্রাউজার canary-তে পৌঁছানো প্রমাণ করে পরিবহন ঠিক আছে — প্রমাণ করে না যে
# একটা *app*-এর fetch আমরা ধরতে পারি। ওই ফাঁকের কারণেই ১৪২টা deeplink-এর
# "০ hit" অর্থহীন ছিল। Fitbit-এর WebFrameActivity যাচাই ছাড়াই URL লোড করে
# (S27, আর চোখে দেখা), তাই সেটাই আমাদের জানা-ভালো কেস।
if adb shell pm path com.fitbit.FitbitMobile >/dev/null 2>&1 </dev/null; then
  B2=$(hits)
  enc=$(printf '%s' "$CAN/c/APPCTL" | sed 's|:|%3A|g; s|/|%2F|g')
  adb shell am start -a android.intent.action.VIEW \
      -d "'fitbit://webview?url=$enc'" >/dev/null 2>&1 </dev/null
  sleep 8
  if [ "$(hits)" -gt "$B2" ]; then
    echo "POSITIVE  Fitbit WebFrameActivity canary এনেছে — app-এর fetch ধরা যাচ্ছে"
  else
    echo "!! APP CONTROL FAIL: জানা-ভালো deeplink-ও canary আনেনি।"
    echo "!! তাই অন্য app-এর '০ hit' কোনো তথ্য দেবে না। থামছি।"
    echo "   শেষ কয়েকটা interaction:"; tail -5 "$SRVLOG" 2>/dev/null | sed 's/^/     /'
    exit 3
  fi
  adb shell am force-stop com.fitbit.FitbitMobile >/dev/null 2>&1 </dev/null
else
  echo "(Fitbit নেই — app-স্তরের control চালানো গেল না। ফলাফল দুর্বল।)"
fi
echo

pkgs=("$@")
[ ${#pkgs[@]} -eq 0 ] && mapfile -t pkgs < <(ls -1 "$DEC" 2>/dev/null | grep -v '\.log$')

: > "$MAP"
ID=0; FIRED=0; SKIPPED=0
for pkg in "${pkgs[@]}"; do
  m="$DEC/$pkg/resources/AndroidManifest.xml"
  [ -f "$m" ] || continue

  mapfile -t links < <(python3 -I - "$m" <<'PY'
import sys, xml.etree.ElementTree as ET
AND="http://schemas.android.com/apk/res/android"
def a(e,n,d=None): return e.get("{%s}%s"%(AND,n),d)
app=ET.parse(sys.argv[1]).getroot().find("application")
seen=set()
for kind in ("activity","activity-alias"):
    for el in app.findall(kind):
        if a(el,"enabled")=="false" or a(el,"permission"): continue
        exp=a(el,"exported")
        ifs=el.findall("intent-filter")
        if not (exp=="true" or (exp is None and ifs)): continue
        for f in ifs:
            acts={a(x,"name") for x in f.findall("action")}
            if "android.intent.action.VIEW" not in acts: continue
            cats={a(x,"name") for x in f.findall("category")}
            if "android.intent.category.BROWSABLE" not in cats: continue
            schemes=[a(d,"scheme") for d in f.findall("data") if a(d,"scheme")]
            hosts=[a(d,"host") for d in f.findall("data") if a(d,"host")]
            paths=[a(d,"path") or a(d,"pathPrefix") for d in f.findall("data")
                   if a(d,"path") or a(d,"pathPrefix")]
            # Maps একই handler-এর জন্য প্রতিটা Google country-ডোমেইন আলাদা
            # করে ঘোষণা করে (maps.google.ao, .je, .jo, .kg, ... শত শত)।
            # সবগুলো একই কোডে যায়, তাই প্রতিটাকে আলাদা লক্ষ্য ধরা মানে ঘণ্টার
            # পর ঘণ্টা একই পরীক্ষা। key হবে (class, scheme, path) — host
            # ভিন্নতার জন্য সর্বোচ্চ দুটো নমুনা।
            for s in schemes:
                for p in (paths[:2] or [""]):
                    key=(a(el,'name'), s, p or "")
                    if key in seen: continue
                    seen.add(key)
                    for h in (hosts[:2] or [""]):
                        base=f"{s}://{h}" if h else f"{s}://x"
                        print(f"{a(el,'name')}\t{base}{p or ''}")
PY
)
  [ ${#links[@]} -eq 0 ] && continue
  # একটা app থেকে সর্বোচ্চ ৪০টা — তার বেশি মানে প্রায় নিশ্চিত host-ভিন্নতা,
  # নতুন কোড পথ নয়।
  CAP=40
  if [ ${#links[@]} -gt "$CAP" ]; then
    echo "== $pkg  (${#links[@]} deeplink -> প্রথম $CAP টা)"
    links=("${links[@]:0:$CAP}")
  else
    echo "== $pkg  (${#links[@]} deeplink)"
  fi

  for row in "${links[@]}"; do
    [ -z "$row" ] && continue
    cls=${row%%$'\t'*}; url=${row#*$'\t'}
    if grep -qiE "$SKIP" <<<"$url$cls"; then
      SKIPPED=$((SKIPPED+1)); continue
    fi
    printf '   %s\n' "$url"
    # সব প্যারামিটার একসাথে একটাই URL-এ, প্রতিটার আলাদা canary id। এক deeplink
    # = এক am start। আলাদা করে ছুড়লে ১৯ গুণ কল, ঘণ্টাখানেক সময়, আর পর্দায়
    # শত শত Activity — অথচ উত্তর একই, কারণ app যে প্যারামিটারটা পড়ে সেটাই
    # আনতে যাবে, আর canary id বলে দেবে কোনটা।
    q=""
    for p in "${PARAMS[@]}"; do
      ID=$((ID+1))
      printf '%s\t%s\t%s\t%s\n' "$ID" "$pkg" "$p" "$url" >> "$MAP"
      sep='&'; [ -z "$q" ] && { [[ "$url" == *\?* ]] && sep='&' || sep='?'; }
      q="$q$sep$p=$(printf '%s' "$CAN/c/$ID" | sed 's|:|%3A|g; s|/|%2F|g')"
    done
    adb shell am start -a android.intent.action.VIEW -d "'$url$q'" \
        >/dev/null 2>&1 </dev/null
    FIRED=$((FIRED+1))
    sleep "$WAIT"
  done
  echo
done

sleep 5
echo "== ফলাফল =="
echo "deeplink ছোড়া হয়েছে: $FIRED   বাদ: $SKIPPED"
H=$(grep -o 'GET /c/[0-9]*' "$SRVLOG" 2>/dev/null | sed 's#GET /c/##' | sort -u)
if [ -z "$H" ]; then
  echo "canary-তে কোনো app পৌঁছায়নি।"
  echo "এর মানে 'বন্ধ' নয় — এর মানে এই ১৯টা প্যারামিটার নামের কোনোটা মেলেনি,"
  echo "অথবা app URL নেয় কিন্তু আনতে যায় না। আসল নাম jadx-এ পাওয়া যাবে।"
else
  echo "!! canary HIT:"
  for id in $H; do
    awk -F'\t' -v i="$id" '$1==i {printf "   %-45s param=%-12s %s\n", $2, $3, $4}' "$MAP"
  done
  echo
  echo "পরের প্রশ্ন: app কি শুধু fetch করল, নাকি WebView-এ **রেন্ডার** করল,"
  echo "আর সেই WebView-এ কি credential/bridge আছে? fetch একা হলে open redirect —"
  echo "kill list। token বা bridge থাকলে তবেই finding।"
fi
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
echo "সার্ভার লগ: $SRVLOG"
echo "map: $MAP"
