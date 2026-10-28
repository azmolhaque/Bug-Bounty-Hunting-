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

# ---- the Google file plays by the opposite rule ------------------------------
# domain-tiers/README.md: "Domain sensitivity is inherited from the parent
# domain by default ... Acquisition domains, however, do not follow this
# approach." So an unlisted foo.google.com is in scope and an unlisted
# foo.nestlabs.com is not, and the two files must disagree on purpose.
#
# This was wrong for as long as the generated Google file existed: it listed
# 487 explicit names and nothing else, so scope-check refused every unlisted
# Google subdomain. A guardrail that says "out of scope" too often is still a
# guardrail that is wrong, and it hid most of the programme from every sweep
# this repo has run.
G="${GOOGLE_SCOPE_FILE:-$ROOT/config/scope-google-tiers.yaml}"
if [ -f "$G" ]; then
  echo
  echo "== inheritance, against $(basename "$G") =="
  checkg() {   # checkg <host> <IN|OUT> <why>
    local out got=OUT
    out="$(SCOPE_FILE="$G" "$HERE/scope-check.sh" "$1" 2>&1)"
    case "$out" in IN-SCOPE*) got=IN ;; esac
    if [ "$got" = "$2" ]; then
      pass=$((pass+1)); printf '  ok   %-46s %-3s  %s\n' "$1" "$2" "$3"
    else
      fail=$((fail+1)); printf '  FAIL %-46s want %s got %s — %s\n       %s\n' "$1" "$2" "$got" "$3" "$out"
    fi
  }

  checkg google.com                       IN  "listed apex"
  checkg zz9f3a.google.com                IN  "UNLISTED subdomain inherits the parent's tier"
  checkg deep.nested.zz9f3a.google.com    IN  "inheritance is any depth, unlike the acquisitions flag"
  checkg zz9f3a.cloud.google.com          IN  "inherits from a listed subdomain too"

  # TIER4 inherits downwards as well, and these are the cases that made the
  # old first-match ordering unusable: the exclusion is deeper than the
  # inclusion, so it only wins if the more specific pattern decides.
  checkg app.google                       OUT "TIER4 under an in-scope parent"
  checkg zz9f3a.app.google                OUT "a TIER4 domain's children are TIER4 too"
  checkg cdn.ampproject.org               OUT "TIER4 under ampproject.org"
  checkg zz9f3a.cdn.ampproject.org        OUT "and its children"
  checkg zz9f3a.ampproject.org            IN  "a sibling of a TIER4 name is still in scope"
  checkg feeds.feedburner.com             OUT "TIER4 under feedburner.com"
  checkg zz9f3a.feedburner.com            IN  "sibling in scope"

  # The API hosts the Firebase keys would have been tested against. These are
  # TIER4, and the README says applications on TIER4 domains are not in scope.
  checkg googleapis.com                   OUT "TIER4"
  checkg identitytoolkit.googleapis.com   OUT "TIER4 by inheritance — the Firebase auth API"
  checkg firestore.googleapis.com         OUT "TIER4 by inheritance"
  checkg zz9f3a.appspot.com               OUT "TIER4 by inheritance"
  checkg ai.studio                        OUT "explicitly TIER4"
  checkg zz9f3a.cloud.run                 OUT "TIER4 by inheritance"
fi

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ] || exit 1
echo "POSITIVE  acquisitions: one label in, more than one out, and the flag does not leak"
echo "POSITIVE  google: subdomains inherit, TIER4 inherits too, and the deeper rule wins"
