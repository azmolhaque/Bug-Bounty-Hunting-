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
  # A completion marker, not a file count. Counting cannot tell a finished
  # tree from one jadx was halfway through when the power went out, and the
  # second kind gets skipped on the next run and then read as a measured zero.
  # Trees from before this marker existed are still trusted on their count.
  if [ -f "$SRC/$pkg/.jadx-complete" ]; then continue; fi
  if [ -d "$tree" ] && [ ! -f "$SRC/$pkg/.jadx-started" ] \
     && [ "$(javacount "$tree")" -gt "$MIN_JAVA" ]; then continue; fi
  # Every APK of the package that carries code, not just base.apk.
  #
  # base.apk was all this ever decompiled, and the manifest in base declares
  # components whose classes live in the feature splits. That is where the
  # sweep's "class not in the sources" count came from — 16 components on
  # Android 16, 25 on Android 15, written off as obfuscation. GMS alone ships
  # eight splits with dex in them: DynamiteModulesA and C, GoogleCertificates,
  # Maps, Measurement, Cronet, Ads. None had ever been read.
  #
  # split_config.* (abi, density, language) carry no dex and are skipped, so
  # the filter is "does this zip contain a .dex", not a name pattern.
  apks=()
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    # grep -c, never grep -q. -q exits at the first match, unzip dies on
    # SIGPIPE and `set -o pipefail` fails the pipeline, so the biggest APKs —
    # the ones whose listing takes longest — are the ones silently dropped.
    # GMS came out with 4 of its 9 code-carrying APKs and 2,816 java files
    # instead of six figures. This is the third time this exact pipeline has
    # bitten in this repo: build.sh's `unzip -l | grep -q resources.arsc` and
    # the evidence script's `dumpsys | grep -q granted=true` were the others.
    if [ "$(unzip -l "$f" 2>/dev/null | grep -c '\.dex$')" -gt 0 ]; then apks+=("$f"); fi
  done < <(find "$APK/$pkg" -maxdepth 1 -name '*.apk' 2>/dev/null | sort)
  [ ${#apks[@]} -gt 0 ] || { echo "SKIP $pkg — no apk with code pulled"; continue; }
  # jadx takes several inputs and merges them into one tree.
  TODO+=("$pkg|$(printf '%s\n' "${apks[@]}" | paste -sd'|' -)")
done < <(find "$DEC" -mindepth 1 -maxdepth 1 -type d | sort)

echo "== ${#TODO[@]} package(s) to decompile, $(date -u +%H:%M:%SZ) =="
printf '%s\n' "${TODO[@]}" | cut -d'|' -f1 | sed 's/^/   /'
echo

n=0
for e in "${TODO[@]}"; do
  pkg="${e%%|*}"
  IFS='|' read -r -a apks <<<"${e#*|}"
  n=$((n+1))
  echo "[$n/${#TODO[@]}] $pkg  (${#apks[@]} apk, $(date -u +%H:%M:%SZ))"
  # -r skips resources: the manifests are already decoded and resources are
  # most of the wall clock on big apps.
  mkdir -p "$SRC/$pkg"; : > "$SRC/$pkg/.jadx-started"
  "$JADX" -r -d "$SRC/$pkg" "${apks[@]}" > "$SRC/$pkg.jadx.log" 2>&1
  rc=$?
  c=$(find "$SRC/$pkg/sources" -name '*.java' 2>/dev/null | grep -c . )
  if [ "$c" -gt "$MIN_JAVA" ]; then
    : > "$SRC/$pkg/.jadx-complete"; rm -f "$SRC/$pkg/.jadx-started"
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
