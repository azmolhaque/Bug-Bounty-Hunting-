#!/usr/bin/env bash
# mvrp-orphan-diff.sh — which orphaned guards survive on BOTH Android versions.
#
# Why this and not grep. The A15 sweep found 16 orphans and G-F003 came out of
# it; three of those claims rested on "this permission will be defined once the
# device reaches Android 16", and the A16 device showed two of the three were
# defined there and one was not. So the single-version list cannot tell a real
# orphan from a guard that is simply ahead of its OS.
#
# An orphan on both versions is the real class: the permission exists nowhere,
# on either release, so nothing is going to define it and the guard is
# permanently decorative.
#
# The pairing is the part a one-liner gets wrong. An orphan is (package,
# permission), not a permission: the same name can be orphaned in one app and
# properly defined-and-used by another, and comparing bare permission names
# merges those two facts into one wrong answer.
#
# Usage:
#   ./scripts/mvrp-orphan-diff.sh ~/mvrp/orphan/orphan-A.txt ~/mvrp16/orphan/orphan-B.txt
#   ./scripts/mvrp-orphan-diff.sh           # newest log under ~/mvrp and ~/mvrp16
set -uo pipefail

A="${1:-$(ls -1t "$HOME"/mvrp/orphan/orphan-*.txt 2>/dev/null | head -1)}"
B="${2:-$(ls -1t "$HOME"/mvrp16/orphan/orphan-*.txt 2>/dev/null | head -1)}"

for f in "$A" "$B"; do
  [ -n "${f:-}" ] && [ -f "$f" ] || { echo "!! missing orphan log — run mvrp-orphan.sh on each device first"; exit 1; }
done

hdr() { grep -m1 "^# $1 *:" "$2" | sed "s/^# $1 *: *//"; }

DEV_A="$(hdr device "$A")"; DEV_B="$(hdr device "$B")"
SER_A="$(hdr serial "$A")"; SER_B="$(hdr serial "$B")"
SRC_A="$(hdr source "$A")"; SRC_B="$(hdr source "$B")"

echo "# A : $A"
echo "#     ${DEV_A:-(no device line)}   serial ${SER_A:-?}   manifests ${SRC_A:-?}"
echo "# B : $B"
echo "#     ${DEV_B:-(no device line)}   serial ${SER_B:-?}   manifests ${SRC_B:-?}"
echo

# ---- control 1: two logs from the same phone compare nothing ----
# With both devices on one Pi, a forgotten ANDROID_SERIAL is the likeliest
# mistake in this whole pipeline, and its result looks exactly like a clean
# answer.
if [ -n "$SER_A" ] && [ "$SER_A" = "$SER_B" ]; then
  echo "!! BROKEN: both logs came from serial $SER_A."
  echo "!!         Re-run one of them with ANDROID_SERIAL set to the other phone."
  exit 2
fi
if [ -z "$SER_A" ] || [ -z "$SER_B" ]; then
  echo "NOTE  one log predates the serial stamp, so I cannot prove they are"
  echo "      different devices. Check the device lines above by eye before"
  echo "      believing anything below."
fi
if [ -n "$SRC_A" ] && [ "$SRC_A" = "$SRC_B" ]; then
  echo "!! BROKEN: both logs read manifests from $SRC_A, so they describe one"
  echo "!!         APK set. MVRP_OUT was not changed between runs."
  exit 2
fi

# ---- the pairs ----
# Log shape:   == <package>
#              *** ORPHANED  <permission>
pairs() {
  awk '
    /^== / && $2 ~ /\./ { pkg=$2; next }
    /\*\*\* ORPHANED/   { if (pkg!="") { print pkg "\t" $NF } }
  ' "$1" | sort -u
}

PA=$(mktemp); PB=$(mktemp)
trap 'rm -f "$PA" "$PB"' EXIT
pairs "$A" > "$PA"
pairs "$B" > "$PB"

NA=$(grep -c . "$PA" || true); NB=$(grep -c . "$PB" || true)

# ---- control 2: a parser that reads nothing would report "no overlap" ----
if [ "$NA" -eq 0 ] || [ "$NB" -eq 0 ]; then
  echo "!! BROKEN: parsed $NA orphan pair(s) from A and $NB from B."
  echo "!!         A zero here is the parser failing, not a device with no"
  echo "!!         orphans — mvrp-orphan.sh prints a summary count, compare it."
  echo "!!         First ORPHANED lines seen in each file:"
  grep -m2 'ORPHANED' "$A" | sed 's/^/     A: /'
  grep -m2 'ORPHANED' "$B" | sed 's/^/     B: /'
  exit 2
fi
echo "POSITIVE  parsed $NA pair(s) from A, $NB from B"
echo

echo "== orphaned on BOTH — the permanent ones =="
comm -12 "$PA" "$PB" | awk -F'\t' '{printf "  %-52s %s\n", $2, $1}'
NBOTH=$(comm -12 "$PA" "$PB" | grep -c . || true)
[ "$NBOTH" -eq 0 ] && echo "  (none)"
echo

echo "== only on A ($DEV_A) =="
comm -23 "$PA" "$PB" | awk -F'\t' '{printf "  %-52s %s\n", $2, $1}'
echo

echo "== only on B ($DEV_B) =="
comm -13 "$PA" "$PB" | awk -F'\t' '{printf "  %-52s %s\n", $2, $1}'
echo

echo "== summary =="
printf '  both: %s    A only: %s    B only: %s\n' \
  "$NBOTH" "$(comm -23 "$PA" "$PB" | grep -c . || true)" "$(comm -13 "$PA" "$PB" | grep -c . || true)"

cat <<'NOTE'

== reading it ==
BOTH is the list worth working. The permission is defined on neither release,
so the guard cannot start working by itself and the component behind it is
reachable by any app that declares the name.

A-only usually means the newer OS defines it — that is the API-36 pattern that
cost G-F003 one of its three claims. Not a bug; a guard waiting for its
platform.

B-only is the interesting accident: a guard that used to work and is orphaned
on the newer release, i.e. a regression the vendor introduced. Check the
component behind each of those first.

And none of the three is a finding yet. ORPHANED is a precondition
(CLAUDE.md 2.6): declare the name, confirm it is granted at install, reach the
component, and show what crossing it gets you.
NOTE
