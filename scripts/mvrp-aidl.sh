#!/usr/bin/env bash
# mvrp-aidl.sh — AIDL service-গুলোতে transaction 1 পাঠিয়ে দেখো কোথায়
#                caller-যাচাই আছে আর কোথায় নেই।
#
# কেন এটা:
#   ২৯টা AIDL interface হাতে। প্রতিটা jadx-এ খুঁড়তে ঘণ্টার পর ঘণ্টা, আর
#   তিনটে গভীর খননের পর প্যাটার্ন বলছে বেশিরভাগই পরিপাটি। তাই আগে প্রস্থ:
#   একটা transaction পাঠিয়ে দেখি কে ফিরিয়ে দেয়, তারপর **যারা ফেরায় না
#   শুধু তাদের** কোড পড়বো।
#
#   descriptor আমরা আগের sweep থেকে জানি, তাই writeInterfaceToken ঠিক দিতে
#   পারি — মানে stub-এর token যাচাই পার হয়ে method dispatch পর্যন্ত পৌঁছাই,
#   আর caller-যাচাই ঠিক ওখানেই থাকে।
#
# পড়ার নিয়ম:
#   SecurityException  -> যাচাই আছে। বন্ধ।
#   অন্য exception     -> method body-তে ঢুকেছি, parcel পড়তে গিয়ে ভেঙেছে।
#                         **ওই স্তরে caller-যাচাই নেই** -> প্রার্থী।
#   reply এসেছে        -> আরও ভালো, পড়ো।
#
# ব্যবহার:  ./mvrp-aidl.sh [services রিপোর্ট ফাইল]
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
REP_IN="${1:-$(ls -1t "$OUT"/services/services-*.txt 2>/dev/null | head -1)}"
REP="$OUT/aidl"; mkdir -p "$REP"
LOG="$REP/aidl-$(date +%Y%m%d-%H%M).txt"
PROBE="com.cindrasec.mvrpprobe/.MainActivity"
WAIT="${WAIT:-4}"

[ -f "${REP_IN:-}" ] || { echo "!! services রিপোর্ট নেই — আগে ./scripts/mvrp-services.sh চালাও"; exit 1; }
adb shell pm path com.cindrasec.mvrpprobe >/dev/null 2>&1 || {
  echo "!! mvrp-probe ইনস্টল করা নেই"; exit 1; }

# ---- নিরাপত্তা: যেগুলো ছোঁবো না ----
# clouddpc-তে নিছক bind-ই Device Policy ক্র্যাশ করিয়েছে। বাকিগুলো এমন কাজ
# করতে পারে যা ফেরানো যায় না — factory reset protection, provisioning,
# নীতি প্রয়োগ, migration, কল করা। CLAUDE.md §7: কোনো destructive payload নয়,
# পরিষেবা নষ্ট করা নয়। সন্দেহ হলে ছোঁবো না।
SKIP='clouddpc|[Ff]rp|[Pp]rovision|[Pp]olicy|[Cc]ommand|[Rr]estore|[Mm]igration|[Tt]ether|[Tt]elecom|[Oo]nboarding|[Ss]etupwizard|[Ww]ipe|[Dd]elete|[Rr]eset'

# </dev/null প্রতিটা adb কলে — load-bearing। adb stdin পড়ে, আর এই ফাংশনটা
# `while read < রিপোর্ট` লুপের ভেতর থেকে ডাকা হয়। stdin বন্ধ না করলে প্রথম
# কলটাই বাকি পুরো ফাইল গিলে ফেলে, লুপ এক ধাপ পরে থেমে যায় — আর সারাংশ
# "পরীক্ষিত: 1" দেখিয়ে সফল হওয়ার ভান করে।
probe() {  # probe <pkg> <cls> <descriptor>
  adb logcat -c >/dev/null 2>&1 </dev/null
  adb shell am start -n "$PROBE" --es action transact \
      --es pkg "$1" --es cls "$2" --es code 1 --es token "$3" >/dev/null 2>&1 </dev/null
  sleep "$WAIT"
  adb logcat -d -s MVRP 2>/dev/null </dev/null | tr -d '\r'
}

{
echo "# AIDL transaction-1 sweep"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# input  : $REP_IN"
echo "# device : $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
echo "# skip   : $SKIP"
echo

echo "== CONTROL =="
# জানা-সীমানা: Wellbeing-এর Chrome bridge। S40-তে প্রমাণিত যে সে auth যাচাই
# করে। এখানে যদি এটাও "যাচাই নেই" দেখায়, তাহলে আমার classifier ভাঙা।
c=$(probe "com.google.android.apps.wellbeing" \
          "com.google.android.apps.wellbeing.web.wellbeing.impl.WellbeingService" \
          "org.chromium.chrome.browser.usage_stats.idl.IWellbeingService")
if grep -q 'transact' <<<"$c"; then
  echo "POSITIVE  WellbeingService -> transact পৌঁছেছে (S40-তে auth প্রমাণিত)"
  grep -E 'transact|THREW' <<<"$c" | sed 's/^.*MVRP *: */   /'
else
  echo "!! CONTROL FAIL: জানা service-এও transact হয়নি। রান অর্থহীন।"
  sed 's/^/   /' <<<"$c"; exit 3
fi
echo

CUR=""; N=0; SKIPPED=0; SEC=0; OPEN=0
while IFS= read -r line <&3; do
  case "$line" in
    "== "*) CUR=$(awk '{print $2}' <<<"$line"); continue;;
  esac
  case "$line" in
    "  AIDL    "*) CLS=$(sed 's/^  AIDL    //' <<<"$line"); DESC=""; continue;;
    *"descriptor = "*) DESC=$(sed 's/.*descriptor = //' <<<"$line");;
    *) continue;;
  esac
  [ -z "${CLS:-}" ] && continue
  [ -z "$DESC" ] && { CLS=""; continue; }

  if grep -qE "$SKIP" <<<"$CUR/$CLS"; then
    printf 'SKIP      %s\n          %s\n' "$CUR" "$CLS"
    SKIPPED=$((SKIPPED+1)); CLS=""; continue
  fi

  N=$((N+1))
  o=$(probe "$CUR" "$CLS" "$DESC")
  t=$(grep -E 'transact\(\) returned|transact THREW|reply ascii' <<<"$o" | sed 's/^.*MVRP *: *//')
  # প্রত্যাখ্যান সবসময় SecurityException হয়ে আসে না। দুটো service উত্তরের
  # *ভেতরে* লিখে পাঠিয়েছে — "Uid is not Google Signed", "Illegal package
  # [com.cindrasec.mvrpprobe]" — আর শুধু exception খুঁজলে ওগুলো ভুল করে
  # "যাচাই নেই" দেখায়। control (Wellbeing, S40-তে auth প্রমাণিত) ঠিক এভাবেই
  # OPEN? দেখিয়েছিল, আর সেটাই ধরিয়ে দিয়েছে।
  if grep -qiE 'SecurityException|not Google Signed|Illegal package|[Nn]ot allowed|[Pp]ermission denied|[Uu]nauthorized|[Uu]nknown (caller|browser|package)' <<<"$o"; then
    SEC=$((SEC+1))
    printf 'DENIED    %s\n          %s\n' "$CUR" "$CLS"
    grep -E 'reply ascii' <<<"$o" | sed 's/^.*MVRP *: */            /' 
  elif grep -q 'transact' <<<"$o"; then
    OPEN=$((OPEN+1))
    printf 'OPEN?     %s\n          %s\n          %s\n' "$CUR" "$CLS" "$DESC"
    sed 's/^/            /' <<<"$t"
  else
    printf 'nobind    %s  %s\n' "$CUR" "$CLS"
  fi
  CLS=""
done 3< "$REP_IN"

echo
echo "== সারাংশ =="
EXPECT=$(grep -c '^  AIDL    ' "$REP_IN")
echo "পরীক্ষিত: $N   SecurityException: $SEC   যাচাই-বিহীন মনে হচ্ছে: $OPEN   বাদ: $SKIPPED"
echo "ইনপুটে AIDL: $EXPECT   স্পর্শ করা: $((N+SKIPPED))"
if [ "$((N+SKIPPED))" -ne "$EXPECT" ]; then
  echo "!! গণনা মেলেনি — লুপ সব এন্ট্রি দেখেনি। ফলাফল অসম্পূর্ণ, বিশ্বাস কোরো না।"
fi
cat <<'NOTE'

OPEN?   transact method body পর্যন্ত গেছে, SecurityException আসেনি।
        মানে **ওই স্তরে** caller-যাচাই নেই। এখন jadx-এ ওই Stub-এর
        বাস্তবায়ন পড়ো — যাচাই আরও ভেতরে থাকতে পারে, অথবা নাও থাকতে পারে।
DENIED  যাচাই আছে। বন্ধ।
SKIP    নিরাপত্তার কারণে ছোঁয়া হয়নি (ফেরানো যায় না এমন কাজ করতে পারে)।

মনে রাখো: OPEN? = দরজা, finding নয়। "attacker আসলে কী পেল?"
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
