#!/usr/bin/env bash
# push-vrp-attachments.sh — put the OSS VRP attachments on the phone.
#
# The reports are filed from the phone's browser, so the files have to be
# somewhere the file picker can reach. /sdcard/Download is where every Android
# file picker opens.
#
# Nothing here is generated: the bundle lives in the repository, so whatever
# lands on the phone is the same bytes that are committed, and a later question
# about what was sent has an answer.
#
# Usage: ./scripts/push-vrp-attachments.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../results/oss-vrp/attachments"
DEST="/sdcard/Download/sitekit-vrp"

ZIP=0
[ "${1:-}" = "--zip" ] && ZIP=1

command -v adb >/dev/null || { echo "!! adb not found"; exit 1; }
[ -d "$SRC" ]             || { echo "!! no attachments at $SRC"; exit 1; }
[ "$ZIP" -eq 0 ] || command -v zip >/dev/null || { echo "!! --zip needs the zip command"; exit 1; }

# One device, authorised. "unauthorized" means the phone is waiting for the
# "Allow USB debugging" prompt to be accepted.
state="$(adb devices | awk 'NR>1 && NF {print $2}' | paste -sd,)"
case "$state" in
  device) ;;
  unauthorized) echo "!! the phone says 'unauthorized' — accept the USB debugging prompt on it"; exit 1 ;;
  '')     echo "!! no device attached"; exit 1 ;;
  *)      echo "!! device state is '$state'; expected a single authorised device"; exit 1 ;;
esac

echo "== pushing to $DEST =="
adb shell mkdir -p "$DEST" >/dev/null 2>&1
fail=0

if [ "$ZIP" -eq 1 ]; then
  tmp="$(mktemp -d)"
  for d in "$SRC"/*/; do
    name="$(basename "$d")"
    ( cd "$SRC" && zip -q -r "$tmp/$name.zip" "$name" )
    if adb push "$tmp/$name.zip" "$DEST/$name.zip" >/dev/null 2>&1; then
      printf '  ok   %s.zip (%s)\n' "$name" "$(du -h "$tmp/$name.zip" | cut -f1)"
    else
      printf '  FAIL %s.zip\n' "$name"; fail=1
    fi
  done
  rm -rf "$tmp"
else
for d in "$SRC"/*/; do
  name="$(basename "$d")"
  adb shell mkdir -p "$DEST/$name" >/dev/null 2>&1
  for f in "$d"*; do
    if adb push "$f" "$DEST/$name/$(basename "$f")" >/dev/null 2>&1; then
      printf '  ok   %s/%s\n' "$name" "$(basename "$f")"
    else
      printf '  FAIL %s/%s\n' "$name" "$(basename "$f")"; fail=1
    fi
  done
done
fi

# adb push writes the bytes and tells nobody. Android's file pickers read
# MediaStore, not the filesystem, so files pushed this way are invisible in the
# picker — the folder shows up and the files inside do not, which reads like
# the push failed. Scanning each file is what makes them selectable.
echo
echo "== telling MediaStore the files are there =="
scanned=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if adb shell "content call --uri content://media/external/file --method scan_file --arg '$f'" >/dev/null 2>&1 \
     || adb shell "am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d 'file://$f'" >/dev/null 2>&1; then
    scanned=$((scanned+1))
  fi
done < <(adb shell "find $DEST -type f" 2>/dev/null | tr -d '\r')
echo "  scanned $scanned file(s)"

echo
echo "== what is on the phone now =="
adb shell ls -R "$DEST" 2>/dev/null | sed 's/^/  /'

# The check that matters is not "a scan ran" but "the picker can see them".
echo
echo "== what MediaStore can see (this is what the file picker lists) =="
seen=$(adb shell "content query --uri content://media/external/file --projection _data --where \"_data LIKE '%sitekit-vrp%'\"" 2>/dev/null | grep -c "sitekit-vrp" || true)
echo "  $seen row(s) under sitekit-vrp"
[ "${seen:-0}" -gt 0 ] || echo "  !! MediaStore still shows nothing — see the note at the end"

# A push that reports success and leaves nothing behind is the failure mode
# worth checking for, so the listing above is compared against the source.
want=$( [ "$ZIP" -eq 1 ] && find "$SRC" -mindepth 1 -maxdepth 1 -type d | wc -l || find "$SRC" -type f | wc -l )
got=$(adb shell "find $DEST -type f 2>/dev/null | wc -l" 2>/dev/null | tr -d '\r')
echo
printf '%d file(s) in the repository, %d on the phone\n' "$want" "${got:-0}"
if [ "$fail" -eq 0 ] && [ "${got:-0}" -eq "$want" ]; then
  echo "POSITIVE  every file arrived"
else
  echo "!! counts differ or a push failed — check the listing above before filing"
  exit 1
fi

cat <<NOTE

== filing ==
On the phone: bughunters.google.com -> Report a vulnerability -> Open Source
(OSS VRP) -> google/site-kit-wp.

  report body : open report-to-paste.txt from $DEST/<folder>/ and paste it
  attachments : the rest of that folder, plus the terminal screenshot already
                in your gallery

Two separate reports. 01 first.

If the file picker still shows "No items" inside those folders, the picker is
filtering by type rather than missing the files. Two ways round it, in order:

  1. In the picker, open the side menu and choose the phone's name (the
     filesystem root) rather than "Downloads" or "Recent". That view lists
     every file regardless of type.
  2. Run ./scripts/push-vrp-attachments.sh --zip, which puts one .zip per
     report on the phone instead. Every upload form accepts a zip.
NOTE
