#!/usr/bin/env bash
# scope-check.sh — the safety guardrail. A bug is only valid if it is IN SCOPE.
#
# Reads config/scope.yaml and decides whether a host/URL/IP may be touched.
# Exit 0 + prints "IN-SCOPE"     -> permitted
# Exit 1 + prints "OUT-OF-SCOPE" -> forbidden (default-deny)
# Exit 2 + prints "AMBIGUOUS"    -> scope missing/unparseable -> treat as forbidden
#
# Usage:  ./scripts/scope-check.sh <host|url|ip>
#         ./scripts/scope-check.sh https://api.example.com/v1/users
#
# Matching rules:
#   - out_of_scope is checked FIRST and always wins (default-deny on conflict).
#   - in_scope entries support exact hosts and leading-wildcard "*.example.com"
#     (which also matches the apex example.com).
#   - This is a deliberately strict, dependency-free parser (grep/sed/awk only)
#     so it runs anywhere, including a bare Raspberry Pi OS.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_FILE="${SCOPE_FILE:-$SCRIPT_DIR/../config/scope.yaml}"

die_ambiguous() { echo "AMBIGUOUS: $1"; exit 2; }

# --- --program flag: map program name to scope file ---------------------------
if [ "${1:-}" = "--program" ]; then
  [ -n "${2:-}" ] || die_ambiguous "--program requires a program name (e.g. --program marriott)"
  case "$2" in
    marriott) SCOPE_FILE="$SCRIPT_DIR/../config/marriott-scope.yaml" ;;
    google)   SCOPE_FILE="$SCRIPT_DIR/../config/scope.yaml" ;;
    *)        die_ambiguous "unknown program '$2' (known: marriott, google)" ;;
  esac
  shift 2
fi

[ -n "${1:-}" ] || die_ambiguous "no target supplied (usage: scope-check.sh [--program <name>] <host>)"
[ -f "$SCOPE_FILE" ] || die_ambiguous "scope file not found at $SCOPE_FILE — populate it before hunting"

# --- normalize the target down to a bare host ---------------------------------
target="$1"
target="${target#*://}"        # strip scheme
target="${target%%/*}"         # strip path
target="${target%%\?*}"        # strip query
target="${target%%:*}"         # strip port
target="${target%.}"           # strip trailing dot
target="$(printf '%s' "$target" | tr '[:upper:]' '[:lower:]')"

[ -n "$target" ] || die_ambiguous "target normalized to empty string"

# --- extract a YAML list section into newline-separated values ----------------
# Captures items under "  <key>:" as "    - value" until the next top-level key.
extract_list() {
  local key="$1"
  awk -v key="$key" '
    $0 ~ "^"key":[[:space:]]*$" { grab=1; next }
    /^[A-Za-z_].*:/             { grab=0 }
    grab && /^[[:space:]]*-[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      gsub(/[",]/, "", line)
      sub(/[[:space:]]*#.*$/, "", line)         # strip inline comments
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line != "") print tolower(line)
    }
  ' "$SCOPE_FILE"
}

# --- does $target match a scope pattern? --------------------------------------
matches() {
  local pat="$1" host="$2"
  pat="${pat%.}"
  case "$pat" in
    +.*)
      # Exactly one label: "+.cameyo.com" covers online.cameyo.com and does NOT
      # cover a.b.cameyo.com. This exists because Google's tier protobuf has a
      # per-domain flag, propagate_tier_to_direct_subdomains, and "direct"
      # means one label. Writing those as "*.cameyo.com" would put hosts in
      # scope that Google did not, and § 0 says the doubtful case is out.
      local base="${pat#+.}"
      case "$host" in
        *".$base")
          local head="${host%".$base"}"
          case "$head" in *.*) return 1 ;; esac          # more than one label
          [ -n "$head" ] && return 0
          ;;
      esac
      return 1
      ;;
    \*.*)
      local base="${pat#\*.}"
      [ "$host" = "$base" ] && return 0                 # wildcard also covers apex
      case "$host" in *".$base") return 0;; esac        # any subdomain depth
      return 1
      ;;
    \**)
      # Leading wildcard without dot: *gateway-apc.marriott.com
      # Matches the bare suffix (gateway-apc.marriott.com) and any host ending in
      # that suffix (api-gateway-apc.marriott.com, dev-gateway-apc.marriott.com).
      local base="${pat#\*}"
      [ "$host" = "$base" ] && return 0                 # apex match
      case "$host" in *"$base") return 0;; esac         # prefix wildcard match
      return 1
      ;;
    *\**)
      # Middle wildcard: gateway*.marriott.com, dcfgateway*.marriott.com
      # Use bash glob matching directly — case handles the glob expansion.
      case "$host" in $pat) return 0;; esac
      return 1
      ;;
    *)
      [ "$host" = "$pat" ] && return 0
      return 1
      ;;
  esac
}

in_scope_list="$(extract_list in_scope || true)"
out_scope_list="$(extract_list out_of_scope || true)"

[ -n "$in_scope_list" ] || die_ambiguous "in_scope is empty in $SCOPE_FILE — refuse to hunt without an authorized scope"

# --- the decision: the most specific pattern wins, and a tie is a refusal -----
#
# This replaced four ordered passes. The passes encoded "exact in beats
# anything out, then exact out, then wildcard in, then wildcard out", which is
# right for a programme that lists the few assets you may touch (Marriott:
# a catch-all *.marriott.com exclusion with specific hosts allowed) and wrong
# for Google's.
#
# Google's tier README says sensitivity is INHERITED from the parent domain:
# an unlisted foo.google.com is in scope at google.com's tier. Encoding that
# means putting "*.google.com" in in_scope — and then community.nest.com,
# which is TIER4, needs "*.community.nest.com" in out_of_scope to keep its own
# subdomains out. Under the old order the wildcard in_scope pass ran first and
# those hosts came back IN SCOPE. That is the one mistake § 0 calls
# unrecoverable, so the order was replaced by a rule that cannot depend on
# which list a pattern happens to sit in: whichever pattern is more specific
# decides, and if they are equally specific the host is out.
#
# Specificity is the length of the literal part, doubled, plus one for an
# exact host and plus one for "+." (one label) over "*." (any depth). So:
#   community.nest.com      exact   -> 2*18+2 = 38
#   *.community.nest.com    wildcard-> 2*18   = 36
#   *.nest.com              wildcard-> 2*9    = 18
# and x.community.nest.com is out of scope under either exclusion, while
# anything.nest.com is in.
specificity() {   # specificity <pattern>
  local pat="$1" lit
  case "$pat" in
    +.*)   lit="${pat#+.}"; echo $(( ${#lit} * 2 + 1 )) ;;
    \*.*)  lit="${pat#\*.}"; echo $(( ${#lit} * 2 )) ;;
    \**)   lit="${pat#\*}";  echo $(( ${#lit} * 2 )) ;;
    *\**)  lit="${pat//\*/}"; echo $(( ${#lit} * 2 )) ;;
    *)     echo $(( ${#pat} * 2 + 2 )) ;;
  esac
}

best_in=-1; best_in_pat=""
while IFS= read -r pat; do
  [ -n "$pat" ] || continue
  if matches "$pat" "$target"; then
    s="$(specificity "$pat")"
    if [ "$s" -gt "$best_in" ]; then best_in="$s"; best_in_pat="$pat"; fi
  fi
done <<< "$in_scope_list"

best_out=-1; best_out_pat=""
while IFS= read -r pat; do
  [ -n "$pat" ] || continue
  if matches "$pat" "$target"; then
    s="$(specificity "$pat")"
    if [ "$s" -gt "$best_out" ]; then best_out="$s"; best_out_pat="$pat"; fi
  fi
done <<< "$out_scope_list"

if [ "$best_in" -lt 0 ]; then
  echo "OUT-OF-SCOPE: $target matches no in_scope entry (default-deny)"
  exit 1
fi

if [ "$best_out" -ge "$best_in" ]; then
  echo "OUT-OF-SCOPE: $target matches exclusion '$best_out_pat' (more specific than, or as specific as, in_scope '$best_in_pat')"
  exit 1
fi

echo "IN-SCOPE: $target matches '$best_in_pat' (no more specific exclusion)"
exit 0
