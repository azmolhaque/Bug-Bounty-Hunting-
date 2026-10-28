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

# INHERIT decides whether an UNLISTED subdomain is in scope, and the two tier
# files answer that differently. From domain-tiers/README.md:
#
#   "Domain sensitivity is inherited from the parent domain by default. If you
#    don't see a particular subdomain (e.g. "foo.google.com"), check if its
#    parent (e.g. "google.com") is listed; the implicit sensitivity of the
#    subdomain will be the same as the parent's. Acquisition domains, however,
#    do not follow this approach. If the domain is not explicitly tiered,
#    TIER4 is assumed."
#
# So the Google file needs "*.domain" beside every entry and the acquisitions
# file must not have it. There is no safe default: guessing low hides a surface
# we are allowed to test, guessing high puts hosts in scope that Google never
# granted. It has to be stated.
case "${INHERIT:-}" in
  0|1) ;;
  *) echo "!! set INHERIT=1 for the Google tier file (subdomains inherit the parent's tier)"
     echo "!! set INHERIT=0 for the acquisitions file (unlisted subdomains are TIER4)"
     echo "!! see domain-tiers/README.md; there is no safe default to assume here"
     exit 1 ;;
esac

[ -f "$PB" ] || { echo "!! no tier file at $PB"; exit 1; }

pairs() {   # fqdn<TAB>tier, one per line
  awk '
    /fqdn:/ { f=$2; gsub(/"/,"",f) }
    /tier:/ { t=$2; if (f!="") { print f "\t" t; f="" } }
  ' "$PB"
}

# Domains whose tier Google says also covers their direct subdomains.
#
# This flag was in the protobuf from the start and the generator ignored it,
# so the scope file listed only the named hosts. 28 domains carry it, two of
# them TIER0 — cameyo.com and googleacquisitionmigration.com — and every
# unlisted direct subdomain of those was being treated as out of scope by our
# own encoding. A filter that silently excludes is the worst kind, and this is
# the second time that sentence has had to be written in this repo.
#
# Emitted as "+.domain", which scope-check matches at exactly one label.
# "*.domain" would also match a.b.domain, which is more than Google granted,
# and § 0 says the doubtful case is out of scope.
propagating() {   # fqdn<TAB>tier for records with the flag
  awk '
    /^domain: *\{/        { f=""; t=""; p=0 }
    /fqdn:/               { f=$2; gsub(/"/,"",f) }
    /tier:/               { t=$2 }
    /propagate_tier_to_direct_subdomains: *true/ { p=1 }
    /^\}/                 { if (f!="" && t!="" && p) print f "\t" t }
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
  if [ "$INHERIT" = "1" ]; then
    for t in $IN_TIERS; do
      pairs | awk -F'\t' -v t="$t" \
        '$2==t {print "  - \"*." $1 "\"   # " t " inherited by subdomains"}' | sort -u
    done
  fi
  for t in $IN_TIERS; do
    propagating | awk -F'\t' -v t="$t" \
      '$2==t {print "  - \"+." $1 "\"   # " t " propagate_tier_to_direct_subdomains"}' | sort -u
  done
  echo
  echo "out_of_scope:"
  pairs | awk -F'\t' '$2=="TIER4" {print "  - \"" $1 "\"   # TIER4 — never in scope"}' | sort -u
  if [ "$INHERIT" = "1" ]; then
    # TIER4 inherits downwards too. Without this, "*.nest.com" in in_scope
    # would put x.community.nest.com in scope even though community.nest.com
    # is TIER4 — scope-check decides on the most specific pattern, and the
    # exclusion has to exist before it can be the more specific one.
    pairs | awk -F'\t' \
      '$2=="TIER4" {print "  - \"*." $1 "\"   # TIER4 — never in scope, nor its subdomains"}' | sort -u
  fi
} > "$tmp"

# ---- controls: the generated file has to say what the source says ----
got_in=$(grep -c '^  - ' <<<"$(awk '/^in_scope:/,/^out_of_scope:/' "$tmp")" || true)
want_in=0
for t in $IN_TIERS; do
  want_in=$(( want_in + $(pairs | awk -F'\t' -v t="$t" '$2==t {print $1}' | sort -u | grep -c .) ))
done
got_out=$(grep -cE '^  - "[^*][^"]*"   # TIER4 — never in scope$' "$tmp" || true)
want_out=$(pairs | awk -F'\t' '$2=="TIER4" {print $1}' | sort -u | grep -c .)

# the in_scope block count includes the "out_of_scope:" line boundary, so compare
# on the exact tier lines instead
got_in=$(grep -cE '^  - .*# TIER[0-3]$' "$tmp" || true)

# And count the propagating entries separately, because the control above only
# matches lines ending in the bare tier. Without this the flag could be dropped
# again and every number in the output would still agree.
got_prop=$(grep -cE '^  - "\+\..*propagate_tier_to_direct_subdomains$' "$tmp" || true)
want_prop=0
for t in $IN_TIERS; do
  want_prop=$(( want_prop + $(propagating | awk -F'\t' -v t="$t" '$2==t {print $1}' | sort -u | grep -c .) ))
done

# Inheritance is the whole point of INHERIT=1, so it gets counted rather than
# trusted: one "*.domain" for every in-scope domain, and one for every TIER4
# domain. A generator that emits the exclusions and forgets the inclusions
# (or the reverse) would otherwise produce a file where every other number
# still agrees.
got_wild=$(grep -cE '^  - "\*\..*inherited by subdomains$' "$tmp" || true)
got_wild4=$(grep -cE '^  - "\*\..*nor its subdomains$' "$tmp" || true)

fail=0
if [ "$INHERIT" = "1" ]; then
  [ "$got_wild" -eq "$want_in" ] || { echo "!! inherited in_scope wildcards $got_wild != $want_in"; fail=1; }
  [ "$got_wild4" -eq "$want_out" ] || { echo "!! inherited TIER4 wildcards $got_wild4 != $want_out"; fail=1; }
  echo "   subdomains inherit: $got_wild in-scope wildcard(s), $got_wild4 TIER4 wildcard(s)"
else
  [ "$got_wild" -eq 0 ] && [ "$got_wild4" -eq 0 ] || { echo "!! INHERIT=0 but the file carries inherited wildcards"; fail=1; }
  echo "   subdomains do NOT inherit (acquisitions rule: unlisted means TIER4)"
fi
[ "$got_prop" -eq "$want_prop" ] || { echo "!! propagating entries $got_prop != $want_prop from source"; fail=1; }
echo "   $got_prop domain(s) propagate their tier to direct subdomains"
[ "$got_in" -eq "$want_in" ]  || { echo "!! in_scope $got_in != $want_in from source"; fail=1; }
[ "$got_out" -eq "$want_out" ]|| { echo "!! out_of_scope $got_out != $want_out from source"; fail=1; }
# The sentinel comes from the source being processed, not from a name typed
# here. It was `api.appsheet.com`, which exists only in the acquisitions file,
# so pointing this script at google_domains_tiers.asciipb failed a control that
# was really asking "is this the acquisitions protobuf". A control bound to one
# input is a control that stops working the first time the input changes.
SENTINEL="${SENTINEL:-$(pairs | awk -F'\t' '$2=="TIER0"{print $1; exit}')}"
[ -n "${SENTINEL:-}" ] || { echo "!! no TIER0 host in $PB to use as a sentinel"; fail=1; }
if [ -n "${SENTINEL:-}" ] && ! grep -q "\"$SENTINEL\"" "$tmp"; then
  echo "!! the first TIER0 host from the source ($SENTINEL) is missing from the output"; fail=1
fi
# With INHERIT=1 the two rules that matter are not countable, so they are
# asked directly: an unlisted child of an in-scope domain must be IN, and a
# child of a TIER4 domain must be OUT. These are the two sentences the README
# actually makes, checked against the file just written.
if [ "$INHERIT" = "1" ] && [ -x "$HERE/scope-check.sh" ]; then
  s_in="$(pairs | awk -F'\t' '$2=="TIER0"{print $1; exit}')"
  s_out="$(pairs | awk -F'\t' '$2=="TIER4"{print $1; exit}')"
  if [ -n "$s_in" ]; then
    if SCOPE_FILE="$tmp" "$HERE/scope-check.sh" "zz-unlisted-9f3a.$s_in" >/dev/null 2>&1; then
      echo "   POSITIVE  an unlisted subdomain of $s_in reads as in scope"
    else
      echo "!! an unlisted subdomain of the TIER0 host $s_in is NOT in scope — inheritance did not take"; fail=1
    fi
  fi
  if [ -n "$s_out" ]; then
    if SCOPE_FILE="$tmp" "$HERE/scope-check.sh" "zz-unlisted-9f3a.$s_out" >/dev/null 2>&1; then
      echo "!! a subdomain of the TIER4 host $s_out reads as IN SCOPE — the exclusion does not inherit"; fail=1
    else
      echo "   NEGATIVE  a subdomain of the TIER4 host $s_out stays out of scope"
    fi
  fi
fi

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
