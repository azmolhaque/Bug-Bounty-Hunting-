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
# Usage:
#   ./scripts/push-vrp-attachments.sh                  # the OSS VRP attachment bundles
#   ./scripts/push-vrp-attachments.sh --zip            # ...one zip per bundle
#   ./scripts/push-vrp-attachments.sh --src results/oss-vrp/wordfence
#                                                      # the Wordfence submissions
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../results/oss-vrp/attachments"
DEST="/sdcard/Download/sitekit-vrp"

ZIP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --zip) ZIP=1; shift ;;
    --src) [ -n "${2:-}" ] || { echo "!! --src needs a directory"; exit 1; }
           case "$2" in /*) SRC="$2" ;; *) SRC="$HERE/../$2" ;; esac
           # A flat directory of files has no bundle subdirectories to walk, so
           # it is pushed as one folder named after itself.
           DEST="/sdcard/Download/$(basename "$2")"
           shift 2 ;;
    *)     echo "!! unknown argument '$1'"; exit 1 ;;
  esac
done

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
  # The attachments directory holds one subdirectory per report; a --src
  # directory may instead be flat, in which case its files go straight into
  # DEST rather than into a bundle folder that does not exist.
  dirs=()
  for d in "$SRC"/*/; do [ -d "$d" ] && dirs+=("$d"); done
  [ "${#dirs[@]}" -gt 0 ] || dirs=("$SRC/")

  for d in "${dirs[@]}"; do
    if [ "$d" = "$SRC/" ]; then
      sub=""; target="$DEST"
    else
      sub="$(basename "$d")/"; target="$DEST/$(basename "$d")"
    fi
    adb shell mkdir -p "$target" >/dev/null 2>&1
    for f in "$d"*; do
      [ -f "$f" ] || continue
      if adb push "$f" "$target/$(basename "$f")" >/dev/null 2>&1; then
        printf '  ok   %s%s\n' "$sub" "$(basename "$f")"
      else
        printf '  FAIL %s%s\n' "$sub" "$(basename "$f")"; fail=1
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
leaf="$(basename "$DEST")"
seen=$(adb shell "content query --uri content://media/external/file --projection _data --where \"_data LIKE '%${leaf}%'\"" 2>/dev/null | grep -c "$leaf" || true)
echo "  $seen row(s) under $leaf"
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

== filing: NOT to OSS VRP any more ==
Report 01 went to OSS VRP on 2026-10-29 and came back Won't fix (Infeasible),
P4/S4, on 2026-10-30 — not on merit: Google paused OSS VRP product-vulnerability
intake on 2026-10-01 and is taking supply-chain reports only, until at least
Q1 2027. Report 02 was held for the same reason.

So do not paste these into the OSS VRP form. The bundles are kept because the
findings are unrefuted and still reproduce; where they go instead is Wordfence.

  what is on the phone now : $DEST

  OSS VRP bundles (default run)
    report body : report-to-paste.txt in $DEST/<folder>/
    attachments : the rest of that folder, plus the terminal screenshot already
                  in your gallery
    — kept for the record only; do not file these anywhere as they stand.

  Wordfence submissions (--src results/oss-vrp/wordfence)
    02-csrf-module-activation.md   file this one FIRST — never disclosed anywhere
    01-missing-authorization.md    second, with its disclosure-status section intact
    README.md                      the three checks to run on wordfence.com first
    Each file's "## " headings are the form's fields, in order. Attach the
    matching bundle from the OSS VRP folder if they ask for files.

If the file picker still shows "No items" inside those folders, the picker is
filtering by type rather than missing the files. Two ways round it, in order:

  1. In the picker, open the side menu and choose the phone's name (the
     filesystem root) rather than "Downloads" or "Recent". That view lists
     every file regardless of type.
  2. Run ./scripts/push-vrp-attachments.sh --zip, which puts one .zip per
     report on the phone instead. Every upload form accepts a zip.
NOTE
