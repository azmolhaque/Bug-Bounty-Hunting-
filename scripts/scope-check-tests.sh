#!/usr/bin/env bash
# scope-check-tests.sh — the scope rules this repo must not get wrong.
#
# Scope is the one thing CLAUDE.md § 0 calls non-negotiable, and it has now
# been wrong twice in the quiet direction: once with 84 of 195 TIER0/TIER1
# hosts missing from a hand-maintained list, and once with
# propagate_tier_to_direct_subdomains ignored by the generator, which removed
# every unlisted direct subdomain of cameyo.com and
# googleacquisitionmigration.com from scope. Both times every number in the
# output agreed with itself.
#
# So the rules get a test. Run it after touching scope-check.sh or
# scope-from-tiers.sh, and after regenerating a scope file.
#
# Usage: ./scripts/scope-check-tests.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
S="${SCOPE_FILE:-$ROOT/config/scope-acquisitions.yaml}"
[ -f "$S" ] || { echo "!! no scope file at $S"; exit 1; }

pass=0; fail=0
check() {   # check <host> <IN|OUT> <why>
  local out got=OUT
  out="$(SCOPE_FILE="$S" "$HERE/scope-check.sh" "$1" 2>&1)"
  case "$out" in IN-SCOPE*) got=IN ;; esac
  if [ "$got" = "$2" ]; then
    pass=$((pass+1)); printf '  ok   %-46s %-3s  %s\n' "$1" "$2" "$3"
  else
    fail=$((fail+1)); printf '  FAIL %-46s want %s got %s — %s\n       %s\n' "$1" "$2" "$got" "$3" "$out"
  fi
}

echo "== scope rules, against $(basename "$S") =="

# "+." is exactly one label, because Google's flag says "direct subdomains".
# Writing it as "*." would also match a.b.cameyo.com, which Google did not
# grant, and testing an out-of-scope host is the one unrecoverable mistake.
check online.cameyo.com              IN  "listed direct subdomain"
check anything-new-9f3a.cameyo.com   IN  "UNLISTED direct subdomain — the point of the flag"
check a.b.cameyo.com                 OUT "two labels is not direct"
check deep.nested.x.cameyo.com       OUT "three labels is not direct"
check cameyo.com                     IN  "the apex itself"

# The flag is per domain. It must not leak to domains that do not carry it.
check definitely-not-real-9f3a.nestlabs.com   OUT "nestlabs.com has no flag"
check definitely-not-real-9f3a.fitbit.com     OUT "fitbit.com has no flag"
check definitely-not-real-9f3a.photomath.net  OUT "photomath.net has no flag"
check nestlabs.com                            OUT "apex not listed and no flag"

# Added 2026-10-28, the day Google put the intrinsic estate in scope: three
# domains arrived at once, all carrying the flag. A generated scope file is
# only as good as the day it was generated, so the newest grant gets a test of
# its own — if a later regeneration drops the flag again, this fails instead of
# the surface quietly disappearing.
check intrinsic.ai                            IN  "TIER1 apex, added 2026-10-28"
check flowstate-9f3a.intrinsic.ai             IN  "UNLISTED direct subdomain, flag set"
check a.b.intrinsic.ai                        OUT "two labels is not direct"
check intrinsic.equipment                     IN  "TIER1 apex, added 2026-10-28"
check anything-9f3a.intrinsic.equipment       IN  "UNLISTED direct subdomain, flag set"
check anything-9f3a.flowmusic.app             OUT "flowmusic.app was added WITHOUT the flag"
check intrinsic.ai.attacker-9f3a.com          OUT "suffix match must not be a prefix match"
check evil-intrinsic.ai                       OUT "a label ending in the apex is not the apex"

# And the ordinary cases still hold.
check repos.nestlabs.com   IN  "explicitly listed"
check api.appsheet.com     IN  "explicitly listed TIER0"

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ] || exit 1
echo "POSITIVE  one label in, more than one out, and the flag does not leak"
