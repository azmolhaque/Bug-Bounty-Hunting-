#!/usr/bin/env bash
# mvrp-tx-scan.sh — a live binder is not access. Find out where it stops you.
#
# Binding tells you the manifest let you through. Nothing more. AGSA's suggest
# service hands over a binder and then refuses every call on a first-party
# gRPC policy; the AppFunction services accept the bind and never connect.
# The answer is one transaction away and guessing is not required.
#
# This sends an EMPTY parcel at each transaction code in a range. That is
# enough to learn where the boundary is, because a permission check runs
# before the arguments are read:
#
#   SecurityException ........ a caller check fired. Which permission it names
#                              tells you whether anything could ever reach it.
#   some other exception ..... no caller check; it got as far as reading
#                              arguments that are not there. Worth building a
#                              real call for.
#   returned true, reply>0 ... it answered an empty parcel. Read the reply.
#   returned false ........... unhandled code, OR a refusal written into
#                              onTransact. Photos' backup binder returns false
#                              for every code when its signature check fails,
#                              and reading that as "no such code" cost an hour.
#                              The two are told apart by reading onTransact,
#                              not from here.
#
# Usage:
#   ./mvrp-tx-scan.sh <pkg> <cls> <interface-token> [first] [last]
#
# Example — the framework's account authenticator interface:
#   ./mvrp-tx-scan.sh com.google.android.apps.tachyon \
#     com.google.android.apps.tachyon.contacts.sync.DuoAccountService \
#     android.accounts.IAccountAuthenticator 1 10
set -uo pipefail

PKG="${1:?usage: $0 <pkg> <cls> <token> [first] [last]}"
CLS="${2:?need the service class}"
# A raw binder has no descriptor to enforce, and writing an empty token
# changes the parcel into something the other side was never going to parse.
# Pass "-" for those: the probe then sends no interface token at all.
TOKEN="${3:?need the interface descriptor, or - for a raw binder}"
FIRST="${4:-1}"
LAST="${5:-10}"

PROBE="com.cindrasec.mvrpprobe"
ACT="$PROBE/com.cindrasec.mvrpprobe.MainActivity"
WAIT="${WAIT:-5}"
OUT="${MVRP_OUT:-$HOME/mvrp}"; REP="$OUT/txscan"; mkdir -p "$REP"
LOG="$REP/txscan-$(date +%Y%m%d-%H%M).txt"

command -v adb >/dev/null || { echo "!! adb not found"; exit 1; }
adb shell pm path "$PROBE" </dev/null 2>/dev/null | tr -d '\r' | grep -qF 'package:' \
  || { echo "!! $PROBE not installed"; exit 1; }

one() {   # one <pkg> <cls> <token> <code> -> outcome
  adb logcat -c </dev/null >/dev/null 2>&1
  # BOOLS picks which binder onBind hands back, when it branches on the
  # caller's extras. Same reason as in the bind test.
  local tokarg=() boolarg=()
  [ "$3" = "-" ] || tokarg=(--es token "$3")
  [ -n "${BOOLS:-}" ] && boolarg=(--es bools "$BOOLS")
  adb shell am start -n "$ACT" --es action bind --es pkg "$1" --es cls "$2" \
      --es code "$4" ${tokarg[@]+"${tokarg[@]}"} ${boolarg[@]+"${boolarg[@]}"} \
      </dev/null >/dev/null 2>&1
  sleep "$WAIT"
  local out
  out=$(adb logcat -d MVRP:I '*:S' </dev/null 2>/dev/null | tr -d '\r')
  adb shell am force-stop "$PROBE" </dev/null >/dev/null 2>&1

  if ! printf '%s\n' "$out" | grep -q 'TRANSACT code='; then
    if printf '%s\n' "$out" | grep -qE 'THROWN|SECURITY'; then
      printf 'NO-BIND    %s' "$(printf '%s\n' "$out" | grep -oE '(THROWN|SECURITY).*' | tail -1 | cut -c1-100)"
    else
      printf 'NO-SIGNAL  the probe did not reach the transact'
    fi
    return
  fi
  local thrown ret rep
  thrown=$(printf '%s\n' "$out" | grep -oE 'transact THREW .*' | tail -1)
  if [ -n "$thrown" ]; then
    printf '%s' "${thrown#transact THREW }" | cut -c1-120
    return
  fi
  ret=$(printf '%s\n' "$out" | grep -oE 'transact\(\) returned (true|false) *replySize=[0-9]+' | tail -1)

  # The size on its own decided nothing: ten codes came back at 132 bytes each
  # and that was one exception marshalled back ten times. The harness now
  # reads the reply, so surface what it found rather than the size again.
  local rex
  rex=$(printf '%s\n' "$out" | grep -oE 'REPLY EXCEPTION .*' | tail -1)
  if [ -n "$rex" ]; then
    printf '%s | %s' "${ret:-?}" "$(printf '%s' "$rex" | cut -c1-120)"
    return
  fi
  if printf '%s\n' "$out" | grep -q 'readException()'; then
    local left
    left=$(printf '%s\n' "$out" | grep -oE 'payload [^ ]+ [0-9]+' | tail -1)
    printf '%s | no exception in reply, %s' "${ret:-?}" "${left:-payload size unknown}"
    return
  fi
  printf '%s' "${ret:-no verdict line}"
}

{
echo "# transaction scan"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# target : $PKG/$CLS"
echo "# token  : $TOKEN"
echo "# codes  : $FIRST..$LAST, empty parcel"
echo

# ---- control: our own binder, so a dead result means the target, not us ----
# SelfService returns a plain Binder. It has no onTransact override, so an
# unknown code must come back as a refusal rather than silence. If this does
# not produce a verdict line, the probe is not transacting at all.
CTL=$(one "$PROBE" com.cindrasec.mvrpprobe.SelfService com.cindrasec.mvrpprobe.SelfService 1)
case "$CTL" in
  NO-SIGNAL*|NO-BIND*)
    echo "!! BROKEN: transacting our own binder came back: $CTL"
    echo "!!         Nothing below would be about the target."; exit 2 ;;
  *) echo "POSITIVE  our own binder, code 1 -> $CTL" ;;
esac
echo

c="$FIRST"
while [ "$c" -le "$LAST" ]; do
  printf 'code %-3s %s\n' "$c" "$(one "$PKG" "$CLS" "$TOKEN" "$c")"
  c=$((c+1))
done

cat <<'NOTE'

== reading it ==
A SecurityException naming a signature or privileged permission is the end of
the road: no third-party app will ever hold it, and the binder being reachable
is a precondition, not a finding.

"returned false" on every code is not proof of anything on its own. It is what
an unhandled code looks like, and also what a refusal inside onTransact looks
like. Read onTransact before concluding either.

Any other exception means nothing checked who was asking and it died reading
arguments. That is the case worth building a real call for.

A reply to an empty parcel is the interesting one. Read what came back before
believing it means anything — an empty reply and a status code are not data.
NOTE
} 2>&1 | tee "$LOG"

echo
echo "report: $LOG"
