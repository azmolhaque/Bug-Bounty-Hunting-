#!/usr/bin/env bash
# marriott-quick-scope.sh — thin wrapper around scope-check.sh for Marriott hunts.
#
# Usage: ./scripts/marriott-quick-scope.sh <host|url|ip>
# Example: ./scripts/marriott-quick-scope.sh sso.marriott.com
#
# Sets SCOPE_FILE to the Marriott scope file and delegates to scope-check.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCOPE_FILE="$SCRIPT_DIR/../config/marriott-scope.yaml"
exec "$SCRIPT_DIR/scope-check.sh" "$@"
