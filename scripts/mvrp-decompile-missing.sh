#!/usr/bin/env bash
# mvrp-decompile-missing.sh — decompile everything the sweeps could not look at.
#
# The hand-back sweep named 28 apps whose zero meant nothing because they had
# never been decompiled. That list is the whole of tomorrow's blind spot, and
# jadx is slow but needs nobody awake.
#
# Resumable by design: a package that already has java files is skipped, so
# this can be killed and restarted without losing hours. Each package gets its
# own log, and the summary at the end says which produced nothing — jadx exits
# with errors on large apps and still writes usable output, so "finished with
# errors" is not the same as failed and the count of files decides.
#
# Usage:
#   nohup ./scripts/mvrp-decompile-missing.sh > ~/mvrp/decompile-missing.log 2>&1 &
set -uo pipefail

OUT="${MVRP_OUT:-$HOME/mvrp}"
DEC="$OUT/decoded"; APK="$OUT/apk"; SRC="$OUT/src"
JADX="$(command -v jadx || echo "$HOME/bughunters/jadx/bin/jadx")"
mkdir -p "$SRC"

[ -x "$JADX" ] || { echo "!! jadx not found at $JADX"; exit 1; }
[ -d "$DEC" ]  || { echo "!! no decoded manifests at $DEC"; exit 1; }

# How many java files a tree has to hold before it counts as decompiled. A
# handful means jadx died early and the sweep would read almost nothing while
# reporting a measured zero.
MIN_JAVA="${MIN_JAVA:-200}"

javacount() { find "$1" -name '*.java' 2>/dev/null | head -"$((MIN_JAVA+1))" | grep -c . ; }

TODO=()
while IFS= read -r d; do
  pkg="$(basename "$d")"
  tree="$SRC/$pkg/sources"
  if [ -d "$tree" ] && [ "$(javacount "$tree")" -gt "$MIN_JAVA" ]; then continue; fi
  # Prefer base.apk; some pulls land a single apk under another name.
  apk="$APK/$pkg/base.apk"
  if [ ! -f "$apk" ]; then
    apk=$(find "$APK/$pkg" -maxdepth 1 -name '*.apk' 2>/dev/null | head -1)
  fi
  [ -n "${apk:-}" ] && [ -f "$apk" ] || { echo "SKIP $pkg — no apk pulled"; continue; }
  TODO+=("$pkg|$apk")
done < <(find "$DEC" -mindepth 1 -maxdepth 1 -type d | sort)

echo "== ${#TODO[@]} package(s) to decompile, $(date -u +%H:%M:%SZ) =="
printf '%s\n' "${TODO[@]}" | cut -d'|' -f1 | sed 's/^/   /'
echo

n=0
for e in "${TODO[@]}"; do
  pkg="${e%%|*}"; apk="${e#*|}"
  n=$((n+1))
  echo "[$n/${#TODO[@]}] $pkg  ($(date -u +%H:%M:%SZ))"
  # -r skips resources: the manifests are already decoded and resources are
  # most of the wall clock on big apps.
  "$JADX" -r -d "$SRC/$pkg" "$apk" > "$SRC/$pkg.jadx.log" 2>&1
  rc=$?
  c=$(find "$SRC/$pkg/sources" -name '*.java' 2>/dev/null | grep -c . )
  if [ "$c" -gt "$MIN_JAVA" ]; then
    echo "      ok   $c java files (exit $rc)"
  else
    echo "      THIN $c java files (exit $rc) — see $SRC/$pkg.jadx.log"
  fi
done

echo
echo "== done $(date -u +%H:%M:%SZ) =="
for e in "${TODO[@]}"; do
  pkg="${e%%|*}"
  c=$(find "$SRC/$pkg/sources" -name '*.java' 2>/dev/null | grep -c . )
  printf '%8d  %s\n' "$c" "$pkg"
done
echo
echo "Tomorrow: ./scripts/mvrp-handback.sh  — the skip list should be short or empty."
