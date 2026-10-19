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
find "$HERE/src" -name '*.java' > "$OUT/sources.txt"
javac -source 8 -target 8 -nowarn -bootclasspath "$AJ" -cp "$AJ" \
      -d "$OUT/classes" @"$OUT/sources.txt" 2>&1 | grep -v 'bootstrap class path' || true

echo "[2/5] d8"
find "$OUT/classes" -name '*.class' > "$OUT/classes.txt"
"$D8" --lib "$AJ" --min-api 24 --output "$OUT" @"$OUT/classes.txt"

echo "[3/5] aapt2 link"
if ! "$AAPT2" link -I "$AJ" \
    --manifest "$HERE/AndroidManifest.xml" \
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
    --out "$OUT/mvrp-probe.apk" "$OUT/base-aligned.apk"
"$APKSIGNER" verify --print-certs "$OUT/mvrp-probe.apk" | head -3

echo
echo "তৈরি: $OUT/mvrp-probe.apk"
echo
echo "  adb install -r $OUT/mvrp-probe.apk"
echo "  adb logcat -c"
echo "  adb logcat -s MVRP &"
echo "  adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action bind \\"
echo "      --es pkg com.google.android.apps.restore \\"
echo "      --es cls com.google.android.apps.restore.osmigration.data.credentials.importer.recovery.CredentialRecoveryService"
