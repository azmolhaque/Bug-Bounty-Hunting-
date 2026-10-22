#!/usr/bin/env bash
# build.sh — three builds from one source tree.
#
#   attacker   declares the orphaned permission. No wallpaper service of its
#              own, so it carries no inner classes and no resources: this is
#              the build that answers the question on its own.
#   control    identical, minus the permission. The differential.
#   canary     attacker plus this app's own wallpaper service, for the second
#              question: is the attacker's code then started by the system.
#
# attacker and control are deliberately the pair that differ in one thing only.
# The canary adds a component, so it is a separate build rather than a third
# leg of the comparison.
#
#   ./build.sh                # attacker
#   ./build.sh control
#   ./build.sh canary
#   ./build.sh pair           # attacker + control
#
# If d8 dies with an internal error on the canary build, retry it as
#   D8FLAGS=--no-desugaring ./build.sh canary
# The toolchain and its ARM64 quirks live in ../mvrp-probe/build.sh.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILDER="$HERE/../mvrp-probe/build.sh"
[ -x "$BUILDER" ] || { echo "!! builder missing: $BUILDER"; exit 1; }

one() {   # one <variant> <manifest> <package> [extra-src] [res]
  local variant="$1" manifest="$2" pkg="$3" extra="${4:-}" res="${5:-}"
  echo
  echo "=== $variant ==="
  MANIFEST="$HERE/$manifest" \
  SRC="$HERE/src${extra:+ $HERE/$extra}" \
  RES="${res:+$HERE/$res}" \
  OUT="$HERE/out/$variant" \
  PKG="$pkg" \
  "$BUILDER"
}

case "${1:-attacker}" in
  attacker) one attacker AndroidManifest.xml         com.cindrasec.wallpaperpoc ;;
  control)  one control  AndroidManifest.control.xml com.cindrasec.wallpaperctl ;;
  canary)   one canary   AndroidManifest.canary.xml  com.cindrasec.wallpapercan \
                         canary/src canary/res ;;
  pair)     one attacker AndroidManifest.xml         com.cindrasec.wallpaperpoc
            one control  AndroidManifest.control.xml com.cindrasec.wallpaperctl ;;
  *) echo "usage: $0 [attacker|control|canary|pair]"; exit 1 ;;
esac
