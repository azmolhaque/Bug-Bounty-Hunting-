#!/usr/bin/env bash
# mvrp-provider-probe.sh — triage the authorities the gap sweep found.
#
# READ THIS BEFORE BELIEVING ANY OUTPUT.
#
# `adb shell content query` runs as the **shell** user, uid 2000. Shell holds
# permissions no ordinary app has, and providers routinely allowlist it. So a
# row returned here does NOT mean an app can read it, and this script cannot
# produce a finding on its own. What it can do is cut 62 authorities down to
# the two or three worth building an app for.
#
# Every hit has to be re-proven from a permissionless app before it is written
# down anywhere. That rule is not caution, it is the difference between a
# report and a retraction: the whole value of G-F004 is that the control app
# was refused, and no control exists here.
#
# Usage:
#   MVRP_OUT=$HOME/mvrp16 ./scripts/mvrp-provider-probe.sh
#   MVRP_OUT=$HOME/mvrp16 ./scripts/mvrp-provider-probe.sh <gaps-report.txt>
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
REP="$OUT/gaps"
GAPS="${1:-$(ls -1t "$REP"/gaps-*.txt 2>/dev/null | head -1)}"
LOG="$REP/provider-probe-$(date +%Y%m%d-%H%M).txt"

command -v adb >/dev/null || { echo "!! adb missing"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "!! no device (set ANDROID_SERIAL)"; exit 1; }
[ -n "${GAPS:-}" ] && [ -f "$GAPS" ] || { echo "!! no gaps report — run mvrp-manifest-gaps.sh first"; exit 1; }

q() {   # q <uri> -> raw output, one line
  adb shell content query --uri "$1" 2>&1 </dev/null | tr -d '\r' | head -3 | tr '\n' ' '
}

classify() {   # classify <raw>
  case "$1" in
    *SecurityException*|*"Permission Denial"*)        echo "DENIED" ;;
    *"Unknown URI"*|*UnsupportedOperation*|*"Invalid URI"*) echo "REACHED" ;;
    *"could not find provider"*|*"Can't find provider"*)   echo "NO-PROVIDER" ;;
    *"No result found"*)                              echo "EMPTY" ;;
    *Row:*)                                           echo "ROWS" ;;
    *)                                                echo "OTHER" ;;
  esac
}

{
echo "# provider triage — SHELL UID, NOT AN APP"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device : $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r') / Android $(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
echo "# serial : $(adb get-serialno 2>/dev/null | tr -d '\r')"
echo "# from   : $GAPS"
# Which sweep this report came from. `ls -t` picks the newest file, and the
# newest is often a one-package run made while chasing something specific —
# that is how a triage meant for 62 providers silently ran against 18. The
# scope now has to be read, not assumed.
SCOPE=$(grep -m1 'manifest(s)' "$GAPS" || echo "?")
echo "# scope  : $SCOPE"
NMAN=$(printf '%s' "$SCOPE" | grep -oE '[0-9]+' | head -1)
if [ -n "${NMAN:-}" ] && [ "$NMAN" -lt 10 ]; then
  echo "#"
  echo "# NOTE: that report covers only $NMAN manifest(s). If you meant the full"
  echo "#       sweep, pass it explicitly:"
  echo "#       $0 \$(ls -1t $REP/gaps-*.txt | sed -n 2p)"
fi
echo

echo "== CONTROL =="
BOGUS=$(q "content://com.cindrasec.no.such.authority.$RANDOM/x")
case "$(classify "$BOGUS")" in
  NO-PROVIDER|OTHER) echo "NEGATIVE  a made-up authority is refused: ${BOGUS:0:70}" ;;
  *) echo "!! BROKEN: a nonexistent authority answered '$BOGUS'"; exit 2 ;;
esac
KNOWN=$(q "content://settings/system")
case "$(classify "$KNOWN")" in
  ROWS|EMPTY) echo "POSITIVE  a readable provider answers: $(classify "$KNOWN")" ;;
  *) echo "!! BROKEN: settings/system came back '$KNOWN' — the mechanism is broken,"
     echo "!!         so every DENIED below would be about this script."; exit 2 ;;
esac
echo

mapfile -t AUTHS < <(grep -oE 'authorities=[^ ]+' "$GAPS" | sed 's/authorities=//' | tr ';' '\n' \
                     | grep -v '^@' | sort -u)
echo "== ${#AUTHS[@]} authority(ies) from the report =="
echo

nd=0; nr=0; ne=0; nrow=0
for a in "${AUTHS[@]}"; do
  [ -n "$a" ] || continue
  raw=$(q "content://$a/")
  v=$(classify "$raw")
  case "$v" in
    DENIED)  nd=$((nd+1)) ;;
    REACHED) nr=$((nr+1)); printf '  %-10s %s\n' "$v" "$a" ;;
    EMPTY)   ne=$((ne+1)); printf '  %-10s %s\n' "$v" "$a" ;;
    ROWS)    nrow=$((nrow+1))
             printf '  %-10s %s\n' "$v" "$a"
             printf '             %s\n' "${raw:0:160}" ;;
    *)       printf '  %-10s %s   %s\n' "$v" "$a" "${raw:0:60}" ;;
  esac
  sleep 0.2
done

echo
echo "== summary =="
echo "DENIED  (guard holds even for shell) : $nd"
echo "REACHED (answered, wrong path)       : $nr"
echo "EMPTY   (answered, no rows)          : $ne"
echo "ROWS    (data came back to SHELL)    : $nrow"

cat <<'NOTE'

== reading it ==
DENIED is the useful negative: if shell cannot read it, an app certainly
cannot, and the authority is closed.

ROWS is NOT a finding. Shell is not an app. Before any of it is written down,
the same query has to come back from an app holding no permissions, and a
build of that app without whatever permission matters has to be refused —
the same control pair that made G-F004 real.

REACHED means the provider answered but the root path is wrong. The next step
is guessing table names, and that is worth doing only where the data behind it
would be worth reporting: accounts, messages, payments, photos. For the rest,
a reachable provider with no readable table is a precondition and nothing more.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
