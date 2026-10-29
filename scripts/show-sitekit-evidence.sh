#!/usr/bin/env bash
# show-sitekit-evidence.sh — print the site-kit-wp evidence for a screenshot.
#
# § 9 asks for a screenshot of the terminal showing the finding. The
# reproduction ran in a WordPress + Site Kit lab that is not on this machine,
# so this prints the recorded transcript rather than re-running anything, and
# it says so on screen. A screenshot of a transcript labelled as a transcript
# is honest; one presented as a live run is not, and a triager who reproduces
# the finding and sees a different hostname would be right to ask.
#
# Usage:
#   ./scripts/show-sitekit-evidence.sh authz     # the Site Goals write
#   ./scripts/show-sitekit-evidence.sh csrf      # the Golinks CSRF
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC="$HERE/../results/oss-vrp/poc"

case "${1:-}" in
  authz) FILE="$POC/evidence.txt";      WHAT="Site Goals: a view-only Dashboard Sharing user writes a site-wide option" ;;
  csrf)  FILE="$POC/evidence-csrf.txt"; WHAT="Golinks: one link, no nonce, re-enables the Analytics tag for every visitor" ;;
  *)     echo "usage: $0 authz|csrf"; exit 1 ;;
esac

[ -f "$FILE" ] || { echo "!! no evidence at $FILE"; exit 1; }

printf '\n'
printf '  google/site-kit-wp — Google OSS VRP\n'
printf '  %s\n' "$WHAT"
printf '  researcher: Md. Azmol Haque Rony (cindrasec)\n'
printf '  recorded  : %s\n' "$(grep -m1 -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z' "$FILE" || echo 2026-10-29)"
printf '  shown from: %s\n' "${FILE#"$HERE/../"}"
printf '  NOTE: transcript of the reproduction run, not a live run on this host.\n'
printf '  %s\n\n' "$(printf '%.0s-' {1..72})"
sed 's/^/  /' "$FILE"
printf '\n  %s\n' "$(printf '%.0s-' {1..72})"
printf '  full report: results/oss-vrp/SUBMISSION-%s.md\n\n' \
       "$([ "$1" = authz ] && echo site-goals-authz || echo golinks-csrf)"
