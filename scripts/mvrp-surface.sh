#!/usr/bin/env bash
# mvrp-surface.sh — টানা APK গুলো decode করে আক্রমণ-তল বের করো
#
# ব্যবহার:  ./mvrp-surface.sh            # $HOME/mvrp/apk/* সব
#           ./mvrp-surface.sh com.fitbit.FitbitMobile
#
# নিরাপত্তা: APK হলো untrusted data। jadx-কে পথটা argument হিসেবে দিচ্ছি,
# APK-র ডিরেক্টরির ভেতর থেকে কোনো interpreter চালাচ্ছি না।
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
APKDIR="$OUT/apk"; DEC="$OUT/decoded"; REP="$OUT/surface"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DEC" "$REP"

JADX="$(command -v jadx || echo "$HOME/bughunters/jadx/bin/jadx")"
[ -x "$JADX" ] || { echo "!! jadx পাওয়া যায়নি: $JADX"; exit 1; }

targets=("$@")
[ ${#targets[@]} -eq 0 ] && mapfile -t targets < <(ls -1 "$APKDIR" 2>/dev/null)
[ ${#targets[@]} -eq 0 ] && { echo "!! $APKDIR খালি — আগে mvrp-pull.sh চালাও"; exit 1; }

MANIFESTS=()
for pkg in "${targets[@]}"; do
  base="$APKDIR/$pkg/base.apk"
  [ -f "$base" ] || base=$(ls -1 "$APKDIR/$pkg/"*.apk 2>/dev/null | head -1)
  [ -f "$base" ] || { echo "-- $pkg : apk নেই, skip"; continue; }

  d="$DEC/$pkg"
  if [ ! -f "$d/resources/AndroidManifest.xml" ]; then
    echo "[decode] $pkg"
    "$JADX" --no-src -d "$d" "$base" >"$DEC/$pkg.jadx.log" 2>&1
  fi
  m="$d/resources/AndroidManifest.xml"
  if [ -f "$m" ]; then
    MANIFESTS+=("$m")
  else
    echo "!! $pkg : manifest decode হয়নি — $DEC/$pkg.jadx.log দেখো"
  fi
done

[ ${#MANIFESTS[@]} -eq 0 ] && { echo "!! একটাও manifest নেই"; exit 1; }

echo
echo "== ${#MANIFESTS[@]} টা manifest বিশ্লেষণ =="
python3 -I "$HERE/mvrp_surface.py" "${MANIFESTS[@]}" | tee "$REP/surface-$(date +%Y%m%d-%H%M).txt"

echo
echo "রিপোর্ট: $REP/"
echo "পরের ধাপ: P1 provider গুলোর authority নিয়ে  ./mvrp-probe.sh <pkg>"
