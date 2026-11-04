#!/usr/bin/env bash
# =============================================================================
# Google VRP — Photomath session3: enumerate the LIVE non-IAP API backends
# Portable: Linux / Pi / Termux.
#
# session2 verdicts (honest):
#   * internal.photomath.com 200s = Google IAP login catch-all = FALSE POSITIVE (dropped).
#   * metabase/argocd/cms/portal/idp/... = 000, not publicly reachable (dead unauth).
#   * REAL surface = 3 live custom API backends w/ NO Google login wall, each
#     answering /healthz 200 "alive":
#       - dpcapi-admin.photomath.com   (an ADMIN api — should not be internet-facing)
#       - lapi.photomath.net           (prod "L API")
#       - tlapi.photomath.net          (test "L API")
#
# GOAL: fingerprint framework + discover real endpoints. Classify each path:
#   200 = OPEN (read it — unauth data/admin = finding)
#   401/403 = endpoint EXISTS behind auth (map it; auth-bypass candidate)
#   405 = endpoint EXISTS, wrong method (probe allowed verbs)
#   404 = absent. Also: credentialed-CORS reflection test (real finding if creds+wildcard-ish).
#
# SAFETY: read-only GET (+ ONE read-only OPTIONS for Allow header, + ONE read-only
# GraphQL introspection QUERY if a /graphql endpoint is detected — query, never a
# mutation; no data modified). >=0.35s/req, curated ~50-path list (NO fuzzing).
#
# Run (Termux): mkdir -p $HOME/pm3; OUTDIR=$HOME/pm3 \
#   bash runbooks/PI-RUNBOOK-photomath-session3-apienum.sh 2>&1 | tee $HOME/pm3/pm3.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/pm3
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/pm3"
  else OUTDIR="$HOME/pm3"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-0.35}"
HOSTS="${HOSTS:-dpcapi-admin.photomath.com lapi.photomath.net tlapi.photomath.net dpcapi-admin.photomath.net}"
echo "============================================================"
echo "PHOTOMATH API ENUM  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Hosts: $HOSTS"
echo "Read-only GET (+1 OPTIONS, +1 GraphQL introspection query if detected). No fuzzing."
echo "============================================================"; echo ""

# curated API path list (NOT a fuzz list — known framework/app routes)
PATHS='
/ /healthz /health /readyz /livez /ping /status /info /version /metrics
/api /api/ /api/v1 /api/v1/ /api/v2 /v1 /v2 /v1/health
/graphql /graphiql /playground /api/graphql /query
/swagger /swagger-ui /swagger-ui.html /swagger/index.html /api-docs /v3/api-docs /openapi.json /openapi.yaml
/admin /admin/ /admin/api /administrator /manage /management /dashboard
/users /user /accounts /me /profile /auth /login /logout /token /oauth/token /session
/config /configuration /env /debug /actuator /actuator/env /actuator/health /actuator/info /actuator/mappings
/.well-known/security.txt /.well-known/openid-configuration /robots.txt /favicon.ico
/internal /private /v1/admin /api/admin /api/internal /api/users /api/user
'

fingerprint(){ # host
  local H="$1"
  echo "  ── fingerprint $H ──"
  curl -s -I -L --max-redirs 3 --max-time 15 -H "User-Agent: $UA" "https://$H/healthz" 2>/dev/null \
    > "$OUTDIR/fp-$H.hdr"
  # show the telling headers only
  grep -iE '^(server|x-powered-by|x-application-context|via|set-cookie|x-kubernetes|x-envoy|content-type|strict-transport|access-control)' \
    "$OUTDIR/fp-$H.hdr" | sed 's/^/    /' | tr -d '\r'
  # CORS credentialed reflection test
  cors=$(curl -s -I -L --max-time 15 -H "User-Agent: $UA" -H "Origin: https://evil.example.com" \
         "https://$H/healthz" 2>/dev/null | grep -iE '^access-control-allow-(origin|credentials)' | tr -d '\r')
  if [ -n "$cors" ]; then
    echo "    CORS reply to Origin https://evil.example.com:"
    printf '%s\n' "$cors" | sed 's/^/      /'
    printf '%s' "$cors" | grep -qi 'evil.example.com' && \
      echo "      *** ORIGIN REFLECTED — if allow-credentials:true => credentialed-CORS FINDING"
  fi
  sleep "$PACE"
}

enum(){ # host
  local H="$1"
  echo "  ── enumerate $H ──"
  : > "$OUTDIR/hits-$H.txt"
  for p in $PATHS; do
    m=$(curl -s -L --max-redirs 2 --max-time 12 -H "User-Agent: $UA" \
         -o "$OUTDIR/body.tmp" -w '%{http_code}|%{content_type}|%{size_download}' "https://$H$p" 2>/dev/null) || m="000|-|0"
    code="${m%%|*}"; rest="${m#*|}"; ct="${rest%%|*}"; size="${rest##*|}"
    case "$code" in
      404|000) : ;;  # absent/unreachable — skip
      *)
        snip=$(head -c 140 "$OUTDIR/body.tmp" 2>/dev/null | tr '\n\r' '  ')
        flag=""
        case "$code" in 401|403) flag="[exists-auth]";; 405) flag="[exists-method]";; 200) flag="[OPEN]";; esac
        echo "    [$code] $p  ct=${ct%%;*} size=$size $flag"
        echo "      :: ${snip:0:110}"
        echo "$code|$p|$ct|$size" >> "$OUTDIR/hits-$H.txt"
        # detect GraphQL
        case "$p" in */graphql|*/query)
          printf '%s' "$snip" | grep -qiE 'graphql|must provide|query' && echo "$H$p" >> "$OUTDIR/graphql.txt";;
        esac
        ;;
    esac
    sleep "$PACE"
  done
}

for H in $HOSTS; do
  # confirm live first
  hc=$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 12 -H "User-Agent: $UA" "https://$H/healthz" 2>/dev/null)
  if [ "${hc:-000}" = "000" ]; then echo "  (skip $H — /healthz 000, not reachable)"; echo ""; continue; fi
  fingerprint "$H"
  enum "$H"
  echo ""
done

# GraphQL introspection (read-only QUERY) on any detected endpoint
if [ -s "$OUTDIR/graphql.txt" ]; then
  echo "═══ GraphQL introspection (read-only query) ═══"
  Q='{"query":"query{__schema{queryType{name} types{name kind}}}"}'
  sort -u "$OUTDIR/graphql.txt" | while read -r GQ; do
    [ -z "$GQ" ] && continue
    echo "  POST https://$GQ  (introspection)"
    out=$(curl -s --max-time 15 -H "User-Agent: $UA" -H 'Content-Type: application/json' \
          -X POST --data "$Q" "https://$GQ" 2>/dev/null | head -c 300)
    echo "    ${out}"
    printf '%s' "$out" | grep -qi '__schema\|queryType' && \
      echo "    *** INTROSPECTION ENABLED — schema exposed. Map types, hunt unauth queries/IDOR."
    sleep "$PACE"
  done
  echo ""
fi

echo "════════════════════════════════════════════"
echo "READ-BACK"
echo "════════════════════════════════════════════"
for H in $HOSTS; do
  [ -s "$OUTDIR/hits-$H.txt" ] && { echo "  $H:"; sed 's/^/    /' "$OUTDIR/hits-$H.txt"; }
done
echo ""
echo "  Triage: [OPEN] 200 on /admin /users /api/* with real data = finding (unauth"
echo "  admin/API). [exists-auth] 401/403 on admin endpoints = auth-bypass candidate"
echo "  (next: test for default creds-free paths, JWT-none, path confusion). Origin"
echo "  reflected + allow-credentials = credentialed-CORS finding. Confirm, don't claim yet."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
