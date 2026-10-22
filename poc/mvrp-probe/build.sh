#!/usr/bin/env bash
# build.sh — Gradle ছাড়াই APK বানাও: javac -> d8 -> aapt2 -> zipalign -> apksigner
#
# লাগবে:
#   JDK (javac)                       — আছে
#   build-tools (aapt2, d8, zipalign, apksigner)  — ~/tools/android-14
#   android.jar (resources.arsc সহ)   — ~/tools/android.jar
#
# ব্যবহার:  ./build.sh        তারপর  adb install -r out/mvrp-probe.apk
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# কোন manifest দিয়ে বিল্ড হবে। ডিফল্টটা permissionless probe — ওটাই
# "একটা সাধারণ app যা পারে" প্রমাণের যন্ত্র, তাই ওটা অস্পৃশ্য রাখা হয়।
#   MANIFEST=AndroidManifest.orphan.xml ./build.sh    # অনাথ-permission দাবির পরীক্ষা
MANIFEST="${MANIFEST:-AndroidManifest.xml}"
case "$MANIFEST" in /*) ;; *) MANIFEST="$HERE/$MANIFEST" ;; esac
[ -f "$MANIFEST" ] || { echo "!! manifest নেই: $MANIFEST"; exit 1; }
echo "[manifest] $(basename "$MANIFEST")"

# কোন source গাছ। ডিফল্ট এখানকার src/ — তদন্তের যন্ত্র, ৯টা action।
# রিপোর্টে পাঠানো PoC আলাদা গাছে (../lockproximity-poc/src), ইংরেজিতে,
# শুধু দুটো action — triager যা পড়বে সেখানে আমার যন্ত্রপাতির নাম থাকা
# অর্থহীন, আর বাংলা লগ স্ট্রিং dex-এ রয়ে যায়।
SRC="${SRC:-$HERE/src}"
case "$SRC" in /*) ;; *) SRC="$HERE/$SRC" ;; esac
[ -d "$SRC" ] || { echo "!! source গাছ নেই: $SRC"; exit 1; }
echo "[source]   $SRC"
BT="${BT:-$HOME/tools/android-14}"
AJ="${AJ:-$HOME/tools/android.jar}"
OUT="$HERE/out"
KS="$HOME/tools/mvrp-debug.keystore"

# ---- টুল বাছাই: যেটা এই আর্কিটেকচারে আসলে চলে ----
# Google-এর build-tools zip শুধু linux x86_64। ARM64 মেশিনে তার native
# বাইনারিগুলো (aapt2, zipalign) binfmt-এ ভেঙে পড়ে:
#     x86_64-binfmt-P: Could not open '/lib64/ld-linux-x86-64.so.2'
# অথচ d8 আর apksigner জাভা-র‍্যাপার, তাই যেকোনো আর্কিটেকচারে চলে।
# Debian-এর aapt2/apksigner native ARM64 — আগে সেগুলো চেষ্টা করি।
runs() {           # runs <path> : চালিয়ে দেখো, binfmt ত্রুটি হলে না
  [ -n "${1:-}" ] && [ -x "$1" ] || return 1
  local o; o="$("$1" version 2>&1; "$1" --version 2>&1)" || true
  case "$o" in *binfmt*|*ld-linux*|*"cannot execute"*) return 1;; esac
  return 0
}
pick() {           # pick <name> : system আগে, তারপর $BT
  local n="$1" c
  for c in "$(command -v "$n" 2>/dev/null || true)" "$BT/$n"; do
    runs "$c" && { echo "$c"; return 0; }
  done
  return 1
}

AAPT2="$(pick aapt2   || true)"
D8="$(pick d8         || true)"
ZIPALIGN="$(pick zipalign || true)"
APKSIGNER="$(pick apksigner || true)"

for v in AAPT2 D8 APKSIGNER; do
  eval "p=\$$v"
  [ -n "$p" ] || { echo "!! $v পাওয়া গেল না (এই আর্কিটেকচারে চলে এমন কপি নেই)"; exit 1; }
  printf '      %-10s %s\n' "$v" "$p"
done
if [ -z "$ZIPALIGN" ]; then
  echo "      ZIPALIGN   নেই — বাদ দিচ্ছি (adb install-এর জন্য লাগে না,"
  echo "                 শুধু Play-তে আপলোডের জন্য দরকার হতো)"
fi
[ -f "$AJ" ] || { echo "!! android.jar নেই: $AJ   (AJ=... দিয়ে পথ দাও)"; exit 1; }

# android.jar-এ resources.arsc আছে কিনা — aapt2-র জন্য সেটাই লাগে।
# classes-only stub (যেমন Maven-এর android-4.1.1.4.jar) এখানে চলবে না,
# আর সেটা জানা ভালো আগেই, aapt2-র দুর্বোধ্য ত্রুটির চেয়ে।
# grep -q নয়: সে ম্যাচ পেয়েই বেরিয়ে যায়, pipe বন্ধ হয়, unzip SIGPIPE-এ মরে,
# আর `set -o pipefail` সেটাকে ব্যর্থতা ধরে — ফলে ঠিক jar-ও "arsc নেই" দেখায়।
# grep -c পুরো ইনপুট পড়ে, তাই দৌড় নেই।
if [ "$(unzip -l "$AJ" 2>/dev/null | grep -c 'resources\.arsc' || true)" -eq 0 ]; then
  echo "!! $AJ -তে resources.arsc নেই — এটা classes-only stub।"
  echo "!! aapt2-র আসল platform android.jar লাগে। README দেখো।"
  exit 1
fi

rm -rf "$OUT"; mkdir -p "$OUT/classes"

echo "[1/5] javac"
find "$SRC" -name '*.java' > "$OUT/sources.txt"
# `| grep ... || true` ছিল এখানে, আর সেটা javac-এর ব্যর্থতা গিলে ফেলত:
# compile error-এও বিল্ড "সফল" বলে এগোত, d8 পুরনো বা অসম্পূর্ণ class নিয়ে
# APK বানাত, আর ডিভাইসে অকেজো app বসত। একটা duplicate variable ঠিক এভাবেই
# রাতভর টিকে ছিল। এখন javac ব্যর্থ হলে বিল্ড থামে।
if ! javac -source 8 -target 8 -nowarn -bootclasspath "$AJ" -cp "$AJ" \
     -d "$OUT/classes" @"$OUT/sources.txt" > "$OUT/javac.err" 2>&1; then
  grep -v 'bootstrap class path' "$OUT/javac.err" || true
  echo "!! javac ব্যর্থ — উপরের ত্রুটি দেখো। APK বানানো হয়নি।"
  exit 1
fi
grep -v 'bootstrap class path' "$OUT/javac.err" || true

echo "[2/5] d8"
find "$OUT/classes" -name '*.class' > "$OUT/classes.txt"
"$D8" --lib "$AJ" --min-api 24 --output "$OUT" @"$OUT/classes.txt"

echo "[3/5] aapt2 link"
# PKG দিলে manifest-এর package নাম বদলায় (ক্লাসের নাম নয়) — একই কোড ভিন্ন
# পরিচয়ে চালানোর জন্য। allowlist শুধু নাম দেখে না signature-ও, সেটা যাচাইয়ের
# একমাত্র উপায়।
#
# সেটআপটা `if` এর বাইরে: আগে এটা `if !` এর ভেতরে ছিল, আর প্রথম লাইনের `#`
# পুরো লাইনটা মন্তব্য করে দেওয়ায় শর্তটাই ভেঙে গিয়েছিল — বিল্ড [3/5]-এ
# চুপচাপ মরত, কোনো ত্রুটি না দেখিয়ে।
RENAME=()
if [ -n "${PKG:-}" ]; then
  RENAME=(--rename-manifest-package "$PKG")
  echo "      package  $PKG"
fi

if ! "$AAPT2" link -I "$AJ" \
    --manifest "$MANIFEST" ${RENAME[@]+"${RENAME[@]}"} \
    --min-sdk-version 24 --target-sdk-version 34 \
    -o "$OUT/base-unsigned.apk" 2> "$OUT/aapt2.err"; then
  cat "$OUT/aapt2.err"
  if grep -q 'Failed to load resources table\|RES_TABLE_TYPE_TYPE' "$OUT/aapt2.err"; then
    cat <<'HINT'

!! এই aapt2 ওই android.jar-এর resources.arsc পড়তে পারছে না।
!! কারণ: নতুন platform (API 34/35+) কমপ্যাক্ট এনকোডিং ব্যবহার করে, আর
!!        distro-র পুরনো aapt2 সেটা চেনে না।
!! সমাধান: পুরনো একটা platform নামাও — লিঙ্ক করার জন্যই শুধু, manifest-এর
!!        targetSdkVersion এতে বদলায় না।
!!
!!   cd ~/tools
!!   Z=$(curl -s https://dl.google.com/android/repository/repository2-3.xml \
!!        | grep -oE 'platform-33[^<"]*\.zip' | sort -u | tail -1)
!!   curl -L -O "https://dl.google.com/android/repository/$Z" && unzip -q "$Z"
!!   AJ=~/tools/android-13/android.jar ~/Bug-Bounty-Hunting-/poc/mvrp-probe/build.sh
HINT
  fi
  exit 1
fi

echo "[4/5] dex যোগ + align"
( cd "$OUT" && zip -q -u base-unsigned.apk classes.dex )
if [ -n "$ZIPALIGN" ]; then
  "$ZIPALIGN" -f 4 "$OUT/base-unsigned.apk" "$OUT/base-aligned.apk"
else
  cp "$OUT/base-unsigned.apk" "$OUT/base-aligned.apk"
fi

echo "[5/5] sign"
if [ ! -f "$KS" ]; then
  echo "      keystore বানাচ্ছি: $KS"
  keytool -genkeypair -v -keystore "$KS" -storepass android -keypass android \
          -alias mvrp -keyalg RSA -keysize 2048 -validity 10000 \
          -dname "CN=mvrp-probe, O=cindrasec, C=BD" >/dev/null 2>&1
fi
"$APKSIGNER" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
    --out "$OUT/${PKG:-mvrp-probe}.apk" "$OUT/base-aligned.apk"
"$APKSIGNER" verify --print-certs "$OUT/${PKG:-mvrp-probe}.apk" | head -3

echo
echo "তৈরি: $OUT/${PKG:-mvrp-probe}.apk   (package = ${PKG:-com.cindrasec.mvrpprobe})"
echo
echo "  adb install -r $OUT/mvrp-probe.apk"
echo "  adb logcat -c"
echo "  adb logcat -s MVRP &"
echo "  adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action bind \\"
echo "      --es pkg com.google.android.apps.restore \\"
echo "      --es cls com.google.android.apps.restore.osmigration.data.credentials.importer.recovery.CredentialRecoveryService"
