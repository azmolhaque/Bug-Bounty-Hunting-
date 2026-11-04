#!/usr/bin/env bash
# mvrp-src.sh — decompile করা সোর্সে প্রসঙ্গ-সহ খোঁজো, আউটপুট সীমিত রেখে।
#
# কেন আলাদা যন্ত্র:
#   ৫৯,৬৫৯টা java ফাইলে কাঁচা grep মানে টার্মিনাল ভেসে যাওয়া, আর তখন
#   কাজের লাইনটা হাজার লাইনের নিচে চাপা পড়ে।
#
#   কিন্তু আসল কারণ অন্য: **শূন্য ফলের দুটো মানে হয়** — সত্যিই নেই, আর
#   পথ ভুল/সোর্স নেই। আগের রানে ঠিক এটাই হয়েছিল: STAGE 1 prefs নাম
#   খুঁজে কিছু পায়নি, কারণ Fitbit কখনো decompile-ই হয়নি, অথচ আউটপুটে
#   সেটা নীরব শূন্য হিসেবে গেছে। এই স্ক্রিপ্ট আগে সোর্স-ট্রি গুনে নেয়,
#   তারপর শূন্য বললে সেটা মানেওয়ালা শূন্য।
#
# ব্যবহার:
#   ./mvrp-src.sh com.fitbit.FitbitMobile 'isTrusted'
#   ./mvrp-src.sh <pkg> '<regex>' [context-lines] [max-files]
set -uo pipefail

PKG="${1:?ব্যবহার: $0 <pkg> '<regex>' [ctx] [max-files]}"
RE="${2:?regex লাগবে}"
CTX="${3:-6}"
MAX="${4:-6}"
OUT="${MVRP_OUT:-$HOME/mvrp}"
S="$OUT/src/$PKG/sources"

# ---- control: শূন্য বলার আগে প্রমাণ করো যে খোঁজার জায়গা আছে ----
if [ ! -d "$S" ]; then
  echo "!! সোর্স নেই: $S"
  echo "   আগে চালাও:  jadx -d $OUT/src/$PKG $OUT/apk/$PKG/base.apk"
  exit 1
fi
NJ=$(find "$S" -name '*.java' 2>/dev/null | wc -l)
if [ "$NJ" -eq 0 ]; then
  echo "!! সোর্স ট্রি আছে কিন্তু একটাও java ফাইল নেই — decompile অর্ধেক পথে মরেছে"
  exit 1
fi

echo "# pkg   : $PKG"
echo "# java  : $NJ ফাইল"
echo "# regex : $RE"

FILES=$(grep -rlE "$RE" --include='*.java' "$S" 2>/dev/null)
C=$(printf '%s\n' "$FILES" | grep -c . )

if [ "$C" -eq 0 ]; then
  echo "# ফল   : শূন্য"
  echo
  echo "(সোর্স ট্রি ঠিক আছে — $NJ টা ফাইল পড়া গেছে। তাই এই শূন্যটা সত্যিই"
  echo " শূন্য, পথ ভাঙার ফল নয়। jadx নাম obfuscate করে, তাই শ্রেণি/মেথডের"
  echo " নাম ধরে না খুঁজে স্ট্রিং, API কল বা ধ্রুবক ধরে খোঁজো।)"
  exit 0
fi

echo "# ফল   : $C টা ফাইলে, প্রথম $MAX টা দেখানো হচ্ছে"
i=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  i=$((i+1)); [ "$i" -gt "$MAX" ] && break
  echo
  echo "===== ${f#"$S"/}"
  grep -nE -B2 -A"$CTX" "$RE" "$f" | head -44
done <<<"$FILES"

if [ "$C" -gt "$MAX" ]; then
  echo
  echo "# আরও $((C-MAX)) টা ফাইল বাকি। সবগুলোর নাম:"
  printf '%s\n' "$FILES" | sed "s|^$S/||" | tail -n +$((MAX+1)) | head -30
fi
