#!/usr/bin/env bash
# mvrp-call.sh — provider-এর call() surface। query() স্টাব হলেও call() আসল API হতে পারে।
#
# কেন: আজ ছয়টা provider "UNSUPPORTED" দিয়েছে — query() বাস্তবায়িতই নয়।
#   কিন্তু ContentProvider-এর তিনটে দরজা: query(), openFile(), call()।
#   Slice/settings/API-ধাঁচের provider প্রায়ই পুরো API-টা call()-এ রাখে,
#   আর তখন query() স্টাব থাকাটাই স্বাভাবিক। আমরা একটা দরজা দেখে সরে এসেছিলাম।
#
# ব্যবহার:
#   ./mvrp-call.sh <authority> [method ...]      method না দিলে সাধারণ তালিকা
#   ./mvrp-call.sh com.google.android.apps.wellbeing.api getSettings
#
# method-এর আসল নাম jadx থেকে আসে:
#   grep -rn 'public .*Bundle call(' --include='*.java' ~/mvrp/src/<pkg>/sources
set -uo pipefail

AUTH="${1:?ব্যবহার: $0 <authority> [method ...]}"; shift || true
OUT="${MVRP_OUT:-$HOME/mvrp}"
EV="$OUT/evidence/call"; mkdir -p "$EV"
LOG="$EV/$(echo "$AUTH" | tr '/:' '__')-$(date +%Y%m%d-%H%M).txt"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }

# method না দিলে: provider-এ বহুল ব্যবহৃত নাম। আসল নামের বিকল্প নয় — প্রথম ঝাড়ু।
if [ $# -gt 0 ]; then
  METHODS=("$@")
else
  METHODS=(get getSettings getState getStatus getConfig getData getAll getInfo
           query read load list fetch getToken getAccount getAccounts
           getUser getProfile getCredentials getKeys dump export)
fi

cl() {
  local o="$1"
  if   grep -qiE 'permission denial|securityexception|checkContentProviderPermission|checkAssociationAndPermission' <<<"$o"; then echo DENIED
  elif grep -qiE 'unsupportedoperation|unimplemented|not implemented' <<<"$o"; then echo UNSUPPORTED
  elif grep -qiE 'unknown uri|failed to find provider|could not find provider' <<<"$o"; then echo NOPROVIDER
  elif grep -qE 'Result: Bundle\[\{\}\]|Result: null' <<<"$o"; then echo NULLRESULT
  # ভরা Bundle কিন্তু ভেতরে শুধু "না" — success=false, error key, error code।
  # এটা ডেটা নয়, আর গুরুত্বপূর্ণ: এটা একটা বৈধ sentinel ভিত্তি, কারণ আসল
  # ডেটা-ফেরত এর থেকে স্পষ্ট আলাদা দেখাবে। একে BUNDLE বললে স্ক্রিপ্ট
  # ঠিক সবচেয়ে সম্ভাবনাময় target-এই চলতে অস্বীকার করত।
  elif grep -qiE 'success=false|error_key|_error|error_code|invalid_arguments|errorcode' <<<"$o"; then echo BUNDLE_ERR
  elif grep -qE 'Result: Bundle\[\{' <<<"$o"; then echo BUNDLE
  elif [ -z "${o//[[:space:]]/}" ]; then echo SILENT
  else echo ERROR
  fi
}
call() { adb shell content call --uri "content://$AUTH" --method "$1" 2>&1 | tr -d '\r' | head -30; }

{
echo "# provider call() probe"
echo "# authority : $AUTH"
echo "# when      : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device    : $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
echo "# caller    : adb shell, uid=$(adb shell id -u | tr -d '\r')"
echo

echo "== CONTROL =="
SEN=$(call "canaryMethodThatCannotExist_$RANDOM")
SV=$(cl "$SEN")
echo "SENTINEL canaryMethodThatCannotExist -> $SV"
if [ "$SV" = "BUNDLE" ]; then
  echo "             ----- sentinel যা ফেরত দিয়েছে -----"
  sed 's/^/             /' <<<"$SEN"
  echo "             ------------------------------------"
  echo
  echo "!! CONTROL FAIL (তুলনার জন্য): বানানো method-ও ভরা Bundle দিয়েছে, তাই"
  echo "!! method-ভিত্তিক তুলনা অচল — কোন method কাজ করল তা বলা যাবে না।"
  echo "!!"
  echo "!! কিন্তু উপরের বাইটগুলো নিজেই একটা পর্যবেক্ষণ: একটা unprivileged caller"
  echo "!! (uid 2000, এই app নয়) যা খুশি method নাম দিয়ে ডেটা ফেরত পাচ্ছে।"
  echo "!! পড়ো: ভেতরে token/credential/medical/message আছে কি?"
  echo "!!   হ্যাঁ -> লিড। PoC app দিয়ে নিশ্চিত করো (shell != app)।"
  echo "!!   না   -> setting/বুলিয়ান/খালি হলে kill list।"
  exit 3
fi
if [ "$SV" = "DENIED" ]; then
  echo "   (sentinel-ও DENIED — এই authority-তে call() সীমানা ধরে আছে। বাকিটা দেখার মানে কম।)"
fi
echo "control ঠিক আছে — sentinel দিয়েছে $SV, এখন target।"
echo

echo "== ${#METHODS[@]} method =="
HIT=0
for m in "${METHODS[@]}"; do
  o=$(call "$m"); v=$(cl "$o")
  # sentinel যা দিয়েছে তার সাথে মিলে গেলে সেটা কোনো তথ্য নয় — চুপ থাকো
  [ "$v" = "$SV" ] && continue
  printf '%-12s %s\n' "$v" "$m"
  if [ "$v" = "BUNDLE" ]; then
    HIT=$((HIT+1))
    echo "             ----- ফেরত আসা Bundle -----"
    sed 's/^/             /' <<<"$o"
    echo "             ---------------------------"
  fi
done

echo
if [ "$HIT" -eq 0 ]; then
  echo "কোনো method sentinel-এর চেয়ে আলাদা ভরা Bundle দেয়নি।"
  echo "এর মানে 'বন্ধ' নয় — এর মানে 'আমরা আসল method-এর নাম জানি না'।"
  echo "jadx-এ ওই provider-এর call() override দেখে নাম নিয়ে আবার চালাও।"
fi
cat <<'NOTE'

== পড়ার নিয়ম ==
BUNDLE      একটা unprivileged caller ডেটা ফেরত পেয়েছে। ভেতরে কী?
            token/credential/medical/message -> finding। setting/বুলিয়ান -> kill list।
BUNDLE_ERR  ভরা Bundle কিন্তু ভেতরে "না" (success=false / error key)।
            ডেটা নয় — কিন্তু provider permission-এ আটকায়নি, argument-এ আটকেছে।
            মানে dispatch পর্যন্ত পৌঁছানো গেছে। আসল method নাম পেলে আবার চালাও।
DENIED      সীমানা ধরে আছে।
UNSUPPORTED এই method নেই।
NULLRESULT  method আছে হয়তো, কিন্তু খালি ফিরেছে।
মনে রাখো: sentinel যা দিয়েছে তার সমান ফল কোনো তথ্য নয়।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "evidence: $LOG"
