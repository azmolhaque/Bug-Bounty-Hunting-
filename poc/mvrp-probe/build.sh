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

for t in "$BT/aapt2" "$BT/d8" "$BT/zipalign" "$BT/apksigner"; do
  [ -x "$t" ] || { echo "!! নেই: $t   (BT=... দিয়ে পথ দাও)"; exit 1; }
done
[ -f "$AJ" ] || { echo "!! android.jar নেই: $AJ   (AJ=... দিয়ে পথ দাও)"; exit 1; }

# android.jar-এ resources.arsc আছে কিনা — aapt2-র জন্য সেটাই লাগে।
# classes-only stub (যেমন Maven-এর android-4.1.1.4.jar) এখানে চলবে না,
# আর সেটা জানা ভালো আগেই, aapt2-র দুর্বোধ্য ত্রুটির চেয়ে।
if ! unzip -l "$AJ" 2>/dev/null | grep -q 'resources.arsc'; then
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
"$BT/d8" --lib "$AJ" --min-api 24 --output "$OUT" @"$OUT/classes.txt"

echo "[3/5] aapt2 link"
"$BT/aapt2" link -I "$AJ" \
    --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 24 --target-sdk-version 34 \
    -o "$OUT/base-unsigned.apk"

echo "[4/5] dex যোগ + zipalign"
( cd "$OUT" && zip -q -u base-unsigned.apk classes.dex )
"$BT/zipalign" -f 4 "$OUT/base-unsigned.apk" "$OUT/base-aligned.apk"

echo "[5/5] sign"
if [ ! -f "$KS" ]; then
  echo "      keystore বানাচ্ছি: $KS"
  keytool -genkeypair -v -keystore "$KS" -storepass android -keypass android \
          -alias mvrp -keyalg RSA -keysize 2048 -validity 10000 \
          -dname "CN=mvrp-probe, O=cindrasec, C=BD" >/dev/null 2>&1
fi
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
    --out "$OUT/mvrp-probe.apk" "$OUT/base-aligned.apk"
"$BT/apksigner" verify --print-certs "$OUT/mvrp-probe.apk" | head -3

echo
echo "তৈরি: $OUT/mvrp-probe.apk"
echo
echo "  adb install -r $OUT/mvrp-probe.apk"
echo "  adb logcat -c"
echo "  adb logcat -s MVRP &"
echo "  adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action bind \\"
echo "      --es pkg com.google.android.apps.restore \\"
echo "      --es cls com.google.android.apps.restore.osmigration.data.credentials.importer.recovery.CredentialRecoveryService"
