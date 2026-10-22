#!/usr/bin/env bash
# mvrp-stub-read.sh — read one decompiled binder stub end to end.
#
# Why a script for something grep can do: this exact sequence has now been
# hand-typed for djd, bsrc, bgfo, mpz and dhh, and each time the same two
# questions got answered in a different order and one of them got skipped.
# The questions are:
#
#   1. What interface token does this stub enforce?  (that is what the probe
#      has to write into the parcel, and the wrong one gives
#      "Binder invocation to an incorrect interface", which is NOT a caller
#      check and has been misread as one before)
#   2. Which transaction codes does it handle, and what method name does each
#      one carry?  (the names survive obfuscation because they are logged or
#      passed as strings)
#   3. Does anything in it look at the caller — getCallingUid, getCallingPid,
#      checkPermission, enforce*, signingInfo?  A stub with none of those is
#      open to any app that can bind the service.
#   4. Which other classes does it hand work to?  Those are the next files to
#      read, and listing them here stops the "I forgot the helper" pattern.
#
# A zero from this script only means something if the source tree is really
# there, so the tree and the class file are both proven before anything is
# reported. Same rule as mvrp-src.sh.
#
# Usage:
#   ./scripts/mvrp-stub-read.sh com.google.android.apps.restore mpz
#   MVRP_OUT=$HOME/mvrp16 ./scripts/mvrp-stub-read.sh com.google.android.apps.restore dhh
set -uo pipefail

PKG="${1:?usage: $0 <package> <class-or-file>}"
CLS="${2:?usage: $0 <package> <class-or-file>}"
OUT="${MVRP_OUT:-$HOME/mvrp}"
S="$OUT/src/$PKG/sources"

# ---- control 1: is there a tree to read at all ----
if [ ! -d "$S" ]; then
  echo "!! no source tree: $S"
  echo "   decompile first:  jadx -d $OUT/src/$PKG $OUT/apk/$PKG/base.apk"
  exit 1
fi
NJ=$(find "$S" -name '*.java' 2>/dev/null | wc -l)
if [ "$NJ" -lt 1 ]; then
  echo "!! tree exists but holds no java file — jadx died early, nothing below would be measured"
  exit 1
fi

# ---- control 2: is there this class to read ----
# Accept a bare obfuscated name, a dotted name, or a path.
if [ -f "$CLS" ]; then
  F="$CLS"
else
  base="${CLS##*.}"
  F=$(find "$S" -name "${base}.java" | head -1)
fi
if [ -z "${F:-}" ] || [ ! -f "$F" ]; then
  echo "# pkg  : $PKG   ($NJ java files)"
  echo "!! class '$CLS' not in this tree."
  near=$(find "$S" -name "${CLS##*.}*.java" | head -10)
  if [ -n "$near" ]; then
    echo "   Similar names present:"
    printf '%s\n' "$near" | sed 's/^/     /'
  else
    echo "   Nothing with a similar name either, so this is not a typo:"
    echo "   the class is absent from the decompiled output. jadx drops classes"
    echo "   it cannot parse, so check the package's jadx log before concluding"
    echo "   the app does not contain it."
  fi
  exit 1
fi

echo "# pkg   : $PKG   ($NJ java files)"
echo "# class : $F"
echo "# size  : $(wc -l < "$F") lines"
echo

echo "== 1. interface token =="
# The descriptor is the only string that has to match on the caller side.
if ! grep -nE '"[a-zA-Z0-9_]+(\.[a-zA-Z0-9_$]+)+"' "$F" | grep -E '\.I[A-Z][A-Za-z0-9]*"|DESCRIPTOR|attachInterface|asInterface' | head -5; then
  echo "(none found in this file — the token may be set by the parent class;"
  echo " read the class this one extends, listed in section 4)"
fi
echo

echo "== 2. transaction dispatch =="
# jadx renders the stub dispatch either as onTransact or as the obfuscated
# bw(int, Parcel, Parcel). Print the whole body: these methods are short and
# the argument marshalling is the part that decides whether a code is
# interesting, so a context window around a grep hit loses exactly the lines
# that matter.
awk '
  !inm && /(onTransact|[ \t]bw)[ ]*\(/ && /\(int|\(Parcel|Parcel/ { inm=1; depth=0; seen=0 }
  inm {
    print NR "\t" $0
    n = gsub(/\{/, "{"); m = gsub(/\}/, "}")
    if (n > 0) seen = 1
    depth += n - m
    if (seen && depth <= 0) inm = 0
  }
' "$F" | head -200
echo

echo "== 3. does anything check the caller =="
CALLER=$(grep -nE 'getCallingUid|getCallingPid|checkCallingPermission|checkPermission|enforce[A-Z]|signingInfo|PackageManager|SecurityException' "$F")
if [ -n "$CALLER" ]; then
  printf '%s\n' "$CALLER" | head -30
else
  echo "none in this file."
  echo
  echo "That is a real zero for THIS class ($(wc -l < "$F") lines read), and it is not"
  echo "yet a finding. The check can live one level up, in the class this stub"
  echo "extends, or inside each method body it delegates to. Read those (section 4)"
  echo "before writing down 'no caller check'."
fi
echo

echo "== 4. classes this one hands work to =="
# jadx obfuscated names are short lowercase tokens; the interesting ones are
# the types it extends, implements, constructs, or calls statically.
{
  grep -oE 'extends [A-Za-z0-9_$]+'    "$F" | awk '{print $2}'
  grep -oE 'implements [A-Za-z0-9_$, ]+' "$F" | sed 's/implements //; s/,/ /g' | tr ' ' '\n'
  grep -oE 'new [a-z][A-Za-z0-9_$]{1,6}\(' "$F" | sed 's/new //; s/($//; s/(//'
  grep -oE '\b[a-z][a-z0-9]{2,5}\.[a-z][A-Za-z0-9_]*\(' "$F" | cut -d. -f1
} 2>/dev/null | sort -u | grep -vE '^(this|super|int|void|new|if|for|return|null|true|false|byte|long|char|case|else|java|android|parcel|parcel1|parcel2|intent|intent2)$' \
 | while read -r c; do
     [ -n "$c" ] || continue
     g=$(find "$S" -name "${c}.java" | head -1)
     if [ -n "${g:-}" ]; then
       printf '  %-14s %s\n' "$c" "$g"
     else
       printf '  %-14s (not in this tree)\n' "$c"
     fi
   done
echo

cat <<'NOTE'
== reading it ==
Holding a binder is a precondition, not a finding (CLAUDE.md 2.6). The only
question that decides this surface is what one of these codes lets an
unprivileged caller take or do:

  takes a path / Uri / filename      -> traversal shape, worth pursuing
  takes a PendingIntent/IntentSender -> redirection shape, worth pursuing
  takes a callback binder it writes
    data into                        -> read-someone-else's-data shape, pursue
  returns counts / names / progress  -> metadata, Section 3 drops it
  only pauses or toggles something   -> availability / own-device setting, drop

Decide which of those it is before running another transact.
NOTE
