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

command -v adb >/dev/null || { echo "!! adb not found"; exit 1; }
[ -d "$SRC" ]             || { echo "!! no attachments at $SRC"; exit 1; }

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

echo
echo "== what is on the phone now =="
adb shell ls -R "$DEST" 2>/dev/null | sed 's/^/  /'

# A push that reports success and leaves nothing behind is the failure mode
# worth checking for, so the listing above is compared against the source.
want=$(find "$SRC" -type f | wc -l)
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
NOTE
