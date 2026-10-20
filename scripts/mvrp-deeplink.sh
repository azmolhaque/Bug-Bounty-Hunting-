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
  adb reverse --remove "tcp:$PORT" >/dev/null 2>&1
}
trap cleanup EXIT

# ---- canary সার্ভার ----
python3 -m http.server "$PORT" --bind 127.0.0.1 >"$SRVLOG" 2>&1 &
SRV=$!
sleep 1
kill -0 "$SRV" 2>/dev/null || { echo "!! পোর্ট $PORT-এ সার্ভার চালু হয়নি"; exit 1; }
adb reverse "tcp:$PORT" "tcp:$PORT" >/dev/null || { echo "!! adb reverse ব্যর্থ"; exit 1; }

# grep -c শূন্য ম্যাচে "0" ছাপে **আর** exit 1 দেয়, তাই `|| echo 0` দ্বিতীয়
# একটা 0 ছেপে "0\n0" বানায় — আর তুলনা "integer expression expected" বলে মরে,
# আর সেটা CONTROL FAIL হিসেবে দেখায় যদিও canary ঠিকই কাজ করছিল।
hits() { local n; n=$(grep -c 'GET /c/' "$SRVLOG" 2>/dev/null) || n=0; echo "${n:-0}"; }

{
echo "# deeplink canary sweep"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device : $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
echo "# canary : http://127.0.0.1:$PORT/c/<id>   (adb reverse, ডিভাইস ছাড়ে না)"
echo "# skip   : $SKIP"
echo

# ---- CONTROL: পুরো শৃঙ্খলটা কাজ করে কিনা ----
echo "== CONTROL =="
BEFORE=$(hits)
adb shell am start -a android.intent.action.VIEW \
    -d "http://127.0.0.1:$PORT/c/CONTROL" >/dev/null 2>&1 </dev/null
sleep 4
AFTER=$(hits)
if [ "$AFTER" -gt "$BEFORE" ]; then
  echo "POSITIVE  ব্রাউজার canary-তে পৌঁছেছে — reverse + সার্ভার দুটোই চলছে"
else
  echo "!! CONTROL FAIL: ব্রাউজারও canary-তে পৌঁছায়নি।"
  echo "!! reverse বা সার্ভার ভাঙা — এই রানে 'কোনো hit নেই' মানে কিছুই না। থামো।"
  exit 3
fi
adb shell am force-stop com.android.chrome >/dev/null 2>&1 </dev/null
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
            for s in schemes:
                for h in (hosts or [""]):
                    base=f"{s}://{h}" if h else f"{s}://x"
                    for p in (paths[:2] or [""]):
                        u=base+(p or "")
                        if u not in seen:
                            seen.add(u); print(f"{a(el,'name')}\t{u}")
PY
)
  [ ${#links[@]} -eq 0 ] && continue
  echo "== $pkg  (${#links[@]} deeplink)"

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
      q="$q$sep$p=http%3A%2F%2F127.0.0.1%3A$PORT%2Fc%2F$ID"
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
