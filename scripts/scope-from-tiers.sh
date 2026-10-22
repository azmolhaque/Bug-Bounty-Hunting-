#!/usr/bin/env bash
# scope-from-tiers.sh — build a scope file from Google's own tier protobuf.
#
# Why: the liveness sweep skipped 84 of 195 TIER0/TIER1 acquisition hosts as
# out of scope. They are not out of scope — they are in the authoritative tier
# file and missing from our hand-maintained scope.yaml, which says in its own
# header that the protobuf is the source of truth. So we were blind on 43% of
# the surface while believing we had covered it.
#
# The generated file is separate on purpose. scope.yaml is the guardrail and
# stays hand-reviewed; this is a derived artifact, regenerate it whenever the
# upstream tier file is refreshed.
#
# TIER4 is "NEVER IN SCOPE" in Google's own scheme, so it is written into
# out_of_scope rather than merely left out — scope-check tests out_of_scope
# first, so an explicit entry beats any accidental wildcard overlap.
#
# Usage:
#   ./scripts/scope-from-tiers.sh                       # acquisitions
#   PB=config/google_domains_tiers.asciipb OUT=config/scope-google-tiers.yaml \
#     ./scripts/scope-from-tiers.sh
#
# Then hunt with it:
#   SCOPE_FILE=$PWD/config/scope-acquisitions.yaml ./scripts/acq-live.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PB="${PB:-$ROOT/config/acquisitions_domains_tiers.asciipb}"
OUT="${OUT:-$ROOT/config/scope-acquisitions.yaml}"
IN_TIERS="${IN_TIERS:-TIER0 TIER1 TIER2 TIER3}"

[ -f "$PB" ] || { echo "!! no tier file at $PB"; exit 1; }

pairs() {   # fqdn<TAB>tier, one per line
  awk '
    /fqdn:/ { f=$2; gsub(/"/,"",f) }
    /tier:/ { t=$2; if (f!="") { print f "\t" t; f="" } }
  ' "$PB"
}

TOTAL=$(pairs | grep -c .)
[ "$TOTAL" -gt 100 ] || { echo "!! only $TOTAL entries parsed from $PB — the format changed"; exit 2; }

tmp=$(mktemp)
{
  echo "# scope-acquisitions.yaml — GENERATED, do not hand-edit."
  echo "# Source: $(basename "$PB")"
  echo "# Built : $(date -u +%Y-%m-%dT%H:%M:%SZ) by scripts/scope-from-tiers.sh"
  echo "# In scope tiers: $IN_TIERS.  TIER4 is listed under out_of_scope, since"
  echo "# Google's scheme marks it never in scope and out_of_scope is checked first."
  echo
  echo "program: \"Google & Alphabet VRP — acquisitions (derived from tier protobuf)\""
  echo "platform: \"bughunters.google.com\""
  echo
  echo "in_scope:"
  for t in $IN_TIERS; do
    pairs | awk -F'\t' -v t="$t" '$2==t {print "  - \"" $1 "\"   # " t}' | sort -u
  done
  echo
  echo "out_of_scope:"
  pairs | awk -F'\t' '$2=="TIER4" {print "  - \"" $1 "\"   # TIER4 — never in scope"}' | sort -u
} > "$tmp"

# ---- controls: the generated file has to say what the source says ----
got_in=$(grep -c '^  - ' <<<"$(awk '/^in_scope:/,/^out_of_scope:/' "$tmp")" || true)
want_in=0
for t in $IN_TIERS; do
  want_in=$(( want_in + $(pairs | awk -F'\t' -v t="$t" '$2==t {print $1}' | sort -u | grep -c .) ))
done
got_out=$(awk '/^out_of_scope:/,0' "$tmp" | grep -c '^  - ' || true)
want_out=$(pairs | awk -F'\t' '$2=="TIER4" {print $1}' | sort -u | grep -c .)

# the in_scope block count includes the "out_of_scope:" line boundary, so compare
# on the exact tier lines instead
got_in=$(grep -cE '^  - .*# TIER[0-3]$' "$tmp" || true)

fail=0
[ "$got_in" -eq "$want_in" ]  || { echo "!! in_scope $got_in != $want_in from source"; fail=1; }
[ "$got_out" -eq "$want_out" ]|| { echo "!! out_of_scope $got_out != $want_out from source"; fail=1; }
grep -q '"api.appsheet.com"' "$tmp" || { echo "!! a known TIER0 host is missing"; fail=1; }
t4=$(pairs | awk -F'\t' '$2=="TIER4"{print $1; exit}')
if [ -n "${t4:-}" ] && grep -qE "^  - \"$t4\"   # TIER[0-3]$" "$tmp"; then
  echo "!! TIER4 host $t4 landed in in_scope"; fail=1
fi
[ "$fail" -eq 0 ] || { echo "!! not writing $OUT"; rm -f "$tmp"; exit 2; }

mv "$tmp" "$OUT"
echo "wrote $OUT"
echo "  in scope     : $got_in  ($IN_TIERS)"
echo "  out of scope : $got_out (TIER4)"
echo
echo "Use it:  SCOPE_FILE=$OUT ./scripts/acq-live.sh"
