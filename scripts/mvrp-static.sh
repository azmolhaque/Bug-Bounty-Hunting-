#!/usr/bin/env bash
# mvrp-static.sh — decompile করা সোর্সে Mobile VRP-র **নাম-ধরে-পুরস্কৃত**
#                  তিনটে শ্রেণি খোঁজো।
#
# rules থেকে, আক্ষরিক:
#   "Path traversal / zip path traversal vulnerabilities leading to
#    arbitrary file write"
#   "Intent redirections leading to launching non-exported application
#    components"
#   "Vulnerabilities caused by unsafe usage of pending intents"
#
# এগুলো bind বা deeplink দিয়ে ধরা যায় না — কোডের নকশা-ত্রুটি। আমরা এতক্ষণ
# "বাইরে থেকে পৌঁছানো যায় কিনা" খুঁজেছি; এটা ভিন্ন স্তর।
#
# ব্যবহার:  ./mvrp-static.sh [pkg ...]
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
SRC="$OUT/src"; REP="$OUT/static"; mkdir -p "$REP"
LOG="$REP/static-$(date +%Y%m%d-%H%M).txt"

pkgs=("$@")
[ ${#pkgs[@]} -eq 0 ] && mapfile -t pkgs < <(ls -1 "$SRC" 2>/dev/null | grep -v '\.log$')
[ ${#pkgs[@]} -eq 0 ] && { echo "!! $SRC খালি — আগে mvrp-decompile.sh চালাও"; exit 1; }

# PendingIntent ফ্ল্যাগ ধ্রুবক (jadx int হিসেবেই লেখে)
#   FLAG_IMMUTABLE = 67108864   FLAG_MUTABLE = 33554432
IMM=67108864
MUT=33554432

{
echo "# static sweep — Mobile VRP-র পুরস্কৃত শ্রেণি"
echo "# when : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# apps : ${#pkgs[@]}"
echo

# ---- CONTROL ----
# Wellbeing-এ আমরা হাতে পড়ে জানি getCallingUid-ভিত্তিক যাচাই **আছে**
# (lrg.java)। grep যদি সেটাও না পায়, তাহলে পথ/প্যাটার্ন ভাঙা, ফলাফল অর্থহীন।
echo "== CONTROL =="
CTL=0
for c in "$SRC"/*/sources/defpackage/lrg.java; do
  [ -f "$c" ] && grep -q 'getPackagesForUid' "$c" && CTL=1
done
if [ "$CTL" -eq 1 ]; then
  echo "POSITIVE  জানা কোড (wellbeing lrg.java, getPackagesForUid) grep-এ ধরা পড়ছে"
else
  echo "(wellbeing-এর সোর্স নেই — control চালানো গেল না। ফলাফল দুর্বল।)"
fi
echo

TOT_PI=0; TOT_IR=0; TOT_ZIP=0
for pkg in "${pkgs[@]}"; do
  d="$SRC/$pkg/sources"
  [ -d "$d" ] || continue
  N=$(find "$d" -name '*.java' | wc -l)
  echo "== $pkg  ($N java)"

  # ---- ১. অনিরাপদ PendingIntent ----
  # FLAG_MUTABLE স্পষ্টভাবে দেওয়া = ডেভেলপার ইচ্ছে করে mutable চেয়েছে।
  # base Intent implicit (component সেট করা নেই) হলে গ্রাহক সেটা ভরে
  # app-এর পরিচয়ে যেকোনো জায়গায় পাঠাতে পারে।
  PI=$(grep -rln "$MUT" --include='*.java' "$d" 2>/dev/null | head -20)
  if [ -n "$PI" ]; then
    c=$(wc -l <<<"$PI"); TOT_PI=$((TOT_PI+c))
    echo "  [PendingIntent] FLAG_MUTABLE ($MUT) — $c ফাইল"
    sed 's|^.*/sources/|      |' <<<"$PI" | head -8
  fi

  # ---- ২. Intent redirection ----
  # exported component extras থেকে একটা Intent তুলে সেটা start করলে,
  # বাইরের app ভেতরের non-exported component-এ পৌঁছাতে পারে।
  IR=$(grep -rln -E 'getParcelableExtra\(' --include='*.java' "$d" 2>/dev/null \
       | xargs -r grep -ln -E 'startActivity|startService|sendBroadcast' 2>/dev/null \
       | xargs -r grep -ln 'android.content.Intent' 2>/dev/null | head -20)
  if [ -n "$IR" ]; then
    c=$(wc -l <<<"$IR"); TOT_IR=$((TOT_IR+c))
    echo "  [IntentRedirect] extras থেকে Intent + start — $c ফাইল"
    sed 's|^.*/sources/|      |' <<<"$IR" | head -8
  fi

  # ---- ৩. Zip / path traversal ----
  # ZipEntry.getName() সরাসরি new File(dir, name)-এ গেলে ../ দিয়ে
  # ডিরেক্টরির বাইরে লেখা যায় — rules-এ "arbitrary file write"।
  # canonical path যাচাই থাকলে নিরাপদ, তাই সেটাও দেখি।
  ZP=$(grep -rln -E 'ZipEntry|ZipInputStream|TarArchive' --include='*.java' "$d" 2>/dev/null \
       | xargs -r grep -ln -E 'new File\(' 2>/dev/null \
       | xargs -r grep -Ln -E 'getCanonicalPath|getCanonicalFile|startsWith\(' 2>/dev/null | head -20)
  if [ -n "$ZP" ]; then
    c=$(wc -l <<<"$ZP"); TOT_ZIP=$((TOT_ZIP+c))
    echo "  [ZipTraversal] zip + new File, canonical যাচাই নেই — $c ফাইল"
    sed 's|^.*/sources/|      |' <<<"$ZP" | head -8
  fi
  echo
done

echo "== সারাংশ =="
printf 'PendingIntent(MUTABLE): %s ফাইল\nIntentRedirect: %s ফাইল\nZipTraversal: %s ফাইল\n' \
  "$TOT_PI" "$TOT_IR" "$TOT_ZIP"
cat <<'NOTE'

== পড়ার নিয়ম ==
এগুলো **প্রার্থী, finding নয়** — grep নকশা দেখে, প্রসঙ্গ দেখে না।
প্রতিটার জন্য তিনটে প্রশ্ন, ক্রমে:
  ১. যে component এটা ব্যবহার করে সে কি exported আর permission-বিহীন?
     না হলে বাইরের app পৌঁছাবেই না — বাদ।
  ২. PendingIntent-এর base Intent কি implicit (component সেট নেই)?
     setComponent/setClass থাকলে ভরার জায়গা নেই — বাদ।
  ৩. পৌঁছে attacker **কী পায়**? non-exported component চালু করা, বা
     app-এর ডিরেক্টরির বাইরে ফাইল লেখা — তবেই crossing।
     ফাইল লেখা পেলে থেমো না: rules বলে actual impact-এ টাকা, potential-এ নয়।
     .so overwrite করে ACE দেখানোই $2,250 থেকে $7,500-এ তোলে।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
