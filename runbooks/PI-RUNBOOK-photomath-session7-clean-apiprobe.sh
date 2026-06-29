#!/usr/bin/env bash
# =============================================================================
# Google VRP — Photomath session7: CURATED probe of the real API (no garbage)
# Portable: Termux / Linux / Pi.
#
# session6 recovered the REAL route map but the auto-probe tested regex noise
# (Android v21/v22 resource dirs), so the real endpoints were never hit. Firebase
# RTDB = disabled (dropped). This run probes a CURATED list of the actual
# Photomath endpoints across the real hosts, and on any non-404 captures the auth
# scheme (WWW-Authenticate) + content-type + snippet so we classify properly:
#   200 open data = finding;  401/403 = real endpoint behind auth = IDOR target;
#   400 = exists/needs params;  405 = exists/method.
#
# Real hosts (from APK): lapi.photomath.net /v{N}/ , rapi.photomath.net /v{N}/ ,
#   bhapi.photomath.net /api/v{N}/ , bookpoint.photomath.net , sfc.photomath.net
# Real object-id routes: books/{bookId}/pages , pages/{pageId}/tasks
#
# SAFETY: read-only GET, >=0.3s/req, curated ~ a few hundred reqs total (NOT
# fuzzing — every path is a real endpoint name from the app). No data beyond
# confirming reachability/auth. Never use any secret.
#
# Run (Termux): mkdir -p $HOME/pm7; OUTDIR=$HOME/pm7 \
#   bash runbooks/PI-RUNBOOK-photomath-session7-clean-apiprobe.sh 2>&1 | tee $HOME/pm7/pm7.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/pm7}"; export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36'
PACE="${PACE:-0.3}"
echo "============================================================"
echo "PHOTOMATH CLEAN API PROBE  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Curated real-endpoint probe. Read-only. Capture auth scheme on hits."
echo "============================================================"; echo ""

# base prefixes to try (real hosts x plausible version prefixes)
BASES="
https://lapi.photomath.net/
https://lapi.photomath.net/v1/
https://lapi.photomath.net/v2/
https://lapi.photomath.net/v3/
https://rapi.photomath.net/
https://rapi.photomath.net/v1/
https://rapi.photomath.net/v2/
https://rapi.photomath.net/v3/
https://bhapi.photomath.net/
https://bhapi.photomath.net/api/v1/
https://bhapi.photomath.net/api/v2/
https://bookpoint.photomath.net/
https://bookpoint.photomath.net/api/v1/
https://sfc.photomath.net/
"
# curated real endpoints (from APK nouns + object-id templates)
ENDPOINTS="
 me users users/me user user/me account accounts profile
 subscription subscriptions purchases purchase receipts orders
 sessions session devices device solutions solution history tasks problems
 books books/1 books/1/pages books/1/pages/1/tasks pages/1/tasks content bookpoint
 auth login register token oauth/token authenticate feedback
 health healthz status version ping config
"

echo "═══ PROBE (only non-404 shown; auth scheme captured) ═══"
: > "$OUTDIR/hits.txt"
total=0
for B in $BASES; do
  [ -z "$B" ] && continue
  for E in $ENDPOINTS; do
    [ -z "$E" ] && continue
    U="$B$E"
    total=$((total+1))
    m=$(curl -s -L --max-redirs 2 --max-time 12 -H "User-Agent: $UA" -H 'Accept: application/json' \
         -o "$OUTDIR/b.tmp" -D "$OUTDIR/h.tmp" \
         -w '%{http_code}|%{content_type}|%{size_download}' "$U" 2>/dev/null) || m="000|-|0"
    code="${m%%|*}"; rest="${m#*|}"; ct="${rest%%|*}"; size="${rest##*|}"
    case "$code" in
      404|000) : ;;
      *)
        wa=$(grep -i '^www-authenticate:' "$OUTDIR/h.tmp" 2>/dev/null | head -1 | tr -d '\r' | sed 's/^[Ww][^:]*: *//')
        snip=$(head -c 160 "$OUTDIR/b.tmp" 2>/dev/null | tr '\n\r' '  ')
        f=""; case "$code" in
          200) f="[OPEN!]";; 401) f="[401 auth->IDOR target]";; 403) f="[403 forbidden]";;
          400) f="[400 exists/needs-params]";; 405) f="[405 exists/method]";; 426) f="[426 upgrade]";; esac
        echo "  [$code] $U  $f"
        [ -n "$wa" ] && echo "      WWW-Authenticate: $wa"
        echo "      ct=${ct%%;*} size=$size :: ${snip:0:110}"
        echo "$code|$U|$wa" >> "$OUTDIR/hits.txt"
        ;;
    esac
    sleep "$PACE"
  done
done
echo ""
echo "  probed $total endpoints"
echo ""

echo "════════════════════════════════════════════"
echo "TRIAGE"
echo "════════════════════════════════════════════"
if [ -s "$OUTDIR/hits.txt" ]; then
  echo "  Non-404 endpoints (the real surface):"
  sort -t'|' -k1 "$OUTDIR/hits.txt" | sed 's/^/    /'
  echo ""
  echo "  * [OPEN!] 200 w/ real data unauth = finding -> verify+minimize+report."
  echo "  * [401 auth->IDOR target] = real authenticated endpoint. The WWW-Authenticate"
  echo "    header tells us the token type (Bearer/JWT). NEXT: register a free test"
  echo "    account, get a token, then swap the object id (books/{id}, users/{id},"
  echo "    subscription) to test cross-account read (BOLA). Our own accounts only."
  echo "  * [400 needs-params] = endpoint exists; map its required params next."
else
  echo "  All endpoints 404/000 from these bases. Means the real paths use a prefix"
  echo "  we haven't recovered statically -> the decisive next step is to observe ONE"
  echo "  real authenticated request (run the app through a proxy once) to capture the"
  echo "  exact base+path+auth, then resume IDOR testing from there."
fi
echo ""
echo "Evidence: $OUTDIR/hits.txt"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
