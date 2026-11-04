#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV AUTHENTICATED GraphQL map + profile-IDOR scout (session48)
# Portable: Linux / Pi / Termux.
#
# M025 (reservation BOLA) is blocked — the test Bonvoy account (845440472) has
# ZERO reservations, so there's no own confirmation_id. Pivot: use the
# authenticated HnV session to reach the AUTHENTICATED GraphQL surface
# (getProfileDetails etc., hidden unauthenticated) and hunt profile/account IDOR,
# which needs NO reservation.
#
# PREREQUISITE: an authenticated HnV session. Log into homes-and-villas.marriott.com
# with the Bonvoy account in a browser with DevTools (Kiwi on Android / desktop),
# open any /gateway/graphql request -> Copy the full `Cookie:` header (it contains
# the HttpOnly hvmi_signInToken). Then run:
#   COOKIE='hvmi_signInToken=...; hvmi_loggedInUser=...; bm_sv=...; ...' \
#   OUTDIR=$HOME/s48 bash runbooks/PI-RUNBOOK-session48-hnv-authenticated.sh
#
# SAFETY: in-scope. Query YOUR OWN profile first. Any IDOR test uses your own id
# vs ONE synthetic/adjacent id; STOP the instant another real person's data
# appears and document own/synthetic only. Read-only — NO mutations.
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s48
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s48"
  else OUTDIR="$HOME/s48"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"

if [ -z "${COOKIE:-}" ]; then
  echo "ERROR: set COOKIE to your authenticated HnV Cookie header. See header of this file."
  echo "Example: COOKIE='hvmi_signInToken=...; hvmi_loggedInUser=...' OUTDIR=\$HOME/s48 bash $0"
  exit 1
fi

echo "============================================================"
echo "HNV AUTHENTICATED  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR   session: ${COOKIE:0:24}..."
echo "============================================================"; echo ""

# fresh csrf token from the (authenticated) homepage
curl -s -o "$OUTDIR/home.html" -H "User-Agent: $UA" -H "$IDH" -H "Cookie: $COOKIE" \
  --max-time 25 "$B/" >/dev/null || true
TOK=$(grep -oE 'id="sourceid"[^>]*data-source="[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*data-source="([^"]+)".*/\1/')
[ -z "$TOK" ] && TOK=$(grep -oE '"csrfToken":"[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
LOGGED=$(grep -oiE 'loggedInUser"?:"?(true|[A-Za-z0-9@._-]+)' "$OUTDIR/home.html" | head -1)
export TOK
echo "csrf token: ${TOK:0:28}...   homepage loggedIn hint: ${LOGGED:-?}"
echo ""

gq() { curl -s -o "$OUTDIR/$2.json" -H "User-Agent: $UA" -H "$IDH" -H "Cookie: $COOKIE" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -H "Origin: $B" -H "Referer: $B/" -H "x-hvmi-csrf-token: $TOK" \
  --max-time 20 --data "$1" -w '%{http_code}|%{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000|0"; }

echo "═══ PHASE A: AUTH CONFIRM + INTROSPECTION ═══"
m=$(gq '{"query":"{__typename}"}' a-typ); echo "  {__typename} -> ${m%|*}|${m#*|}B :: $(cat "$OUTDIR/a-typ.json"|head -c 80)"
m=$(gq '{"query":"query I{__schema{queryType{name} types{name kind fields{name}}}}"}' a-intro)
echo "  introspection -> ${m%|*}|${m#*|}B"
if grep -q '"__schema"' "$OUTDIR/a-intro.json" 2>/dev/null; then
  echo "  *** INTROSPECTION ENABLED (authenticated):"
  python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]
try:
  d=json.load(open(f"{O}/a-intro.json")); ts=d["data"]["__schema"]["types"]
  q=[t for t in ts if t["name"]=="Query"]
  if q and q[0].get("fields"):
    print("    Query fields:");
    for f in q[0]["fields"]: print("      ",f["name"])
  open(f"{O}/qfields.txt","w").write("\n".join(f["name"] for t in ts if t["name"]=="Query" for f in (t.get("fields") or [])))
except Exception as e: print("    parse:",e)
PYEOF
else
  echo "    introspection blocked: $(cat "$OUTDIR/a-intro.json"|head -c 120)"
fi
echo ""

echo "═══ PHASE B: AUTHENTICATED-ONLY OPS (error-oracle) ═══"
for OP in getProfileDetails profile viewer me currentUser account getMember member \
          customer getCustomer getTotalReservationData myTrips upcomingTrips trips \
          reservations getReservations wallet getProfile userProfile; do
  m=$(gq "{\"query\":\"query{${OP}{__typename}}\"}" "b-$OP")
  code="${m%|*}"; b=$(cat "$OUTDIR/b-$OP.json")
  echo "$b" | grep -q "Cannot query field" || printf '  %-26s [%s] %s\n' "$OP" "$code" "$(echo "$b"|head -c 150|tr '\n' ' ')"
  sleep 0.35
done
echo ""

echo "═══ PHASE C: OWN PROFILE DATA (whatever op resolved above) ═══"
echo "  If an op returned your own data, note its id argument — that's the IDOR"
echo "  parameter. Next session swaps your id for ONE adjacent/synthetic id only."
echo "  Candidate profile fields to request once the op is known:"
echo "   firstName lastName email phone loyaltyId memberId address ..."
echo ""

echo "════════════════════════════════════════════"
echo "NEXT"
echo "════════════════════════════════════════════"
echo "  - Any Phase B op returning data = authenticated surface to test for IDOR."
echo "  - Find its id arg (member/customer/loyalty id). With your own id it returns"
echo "    your data; the IDOR test (session49) swaps to ONE other id (synthetic or"
echo "    your own +/-1) — STOP on any real third-party PII."
echo "  - If introspection is enabled authenticated (Phase A) that is itself a"
echo "    reportable hardening gap on a production API + a full IDOR roadmap."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
