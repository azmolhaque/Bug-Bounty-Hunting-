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
    *)
      [ "$host" = "$pat" ] && return 0
      return 1
      ;;
  esac
}

in_scope_list="$(extract_list in_scope || true)"
out_scope_list="$(extract_list out_of_scope || true)"

[ -n "$in_scope_list" ] || die_ambiguous "in_scope is empty in $SCOPE_FILE — refuse to hunt without an authorized scope"

# --- PASS 1: exact in-scope always wins ---------------------------------------
# An explicit non-wildcard in_scope entry beats any out_of_scope entry.
# Supports "test ONLY listed assets" programs (e.g. Marriott) where *.domain.com
# is in out_of_scope as a catch-all and specific subdomains are explicitly listed
# in in_scope. Google VRP Tier4 exact out_of_scope entries are unaffected because
# they are exact strings that win in PASS 2 before any wildcard matching.
while IFS= read -r pat; do
  [ -n "$pat" ] || continue
  case "$pat" in \**) continue ;; esac   # skip wildcards in this pass
  if [ "$target" = "$pat" ]; then
    echo "IN-SCOPE: $target matches explicit entry '$pat' (overrides wildcard exclusions)"
    exit 0
  fi
done <<< "$in_scope_list"

# --- PASS 2: exact out-of-scope (non-wildcard) wins over wildcard in-scope ----
# This ensures Google VRP Tier4 exact exclusions still block even if a wildcard
# in_scope pattern would otherwise match.
while IFS= read -r pat; do
  [ -n "$pat" ] || continue
  case "$pat" in \**) continue ;; esac   # only exact entries in this pass
  if matches "$pat" "$target"; then
    echo "OUT-OF-SCOPE: $target matches explicit exclusion '$pat'"
    exit 1
  fi
done <<< "$out_scope_list"

# --- PASS 3: wildcard in-scope beats wildcard out-of-scope --------------------
# A specific wildcard in_scope entry (e.g. *gateway-apc.marriott.com,
# *uat.marriott.com, *.apigwc.marriott.com) wins over a catch-all wildcard
# out_of_scope exclusion (e.g. *.marriott.com). This is "longest match wins"
# for wildcard patterns: the more-specific in_scope wildcard takes precedence.
while IFS= read -r pat; do
  [ -n "$pat" ] || continue
  case "$pat" in \**) ;; *) continue ;; esac   # only wildcards in this pass
  if matches "$pat" "$target"; then
    echo "IN-SCOPE: $target matches '$pat' (overrides wildcard exclusions)"
    exit 0
  fi
done <<< "$in_scope_list"

# --- PASS 4: wildcard out-of-scope (default-deny) -----------------------------
while IFS= read -r pat; do
  [ -n "$pat" ] || continue
  case "$pat" in \**) ;; *) continue ;; esac   # only wildcards in this pass
  if matches "$pat" "$target"; then
    echo "OUT-OF-SCOPE: $target matches exclusion '$pat'"
    exit 1
  fi
done <<< "$out_scope_list"

echo "OUT-OF-SCOPE: $target matches no in_scope entry (default-deny)"
exit 1
