#!/usr/bin/env bash
# =============================================================================
# Marriott — bilt.marriott.com API surface hunt (session34)
# Portable: Linux / Pi / Termux.
#
# Why: s32 -> bilt.marriott.com = 200/412KB, raw-origin (no Akamai), login form.
# It's the Bilt fintech rewards integration. Large SPA => client JS likely
# exposes API base URLs + endpoints. Goal: extract those, then probe UNAUTH for
# endpoints that return data or are missing access control (rewards/points IDOR
# is the prize). hotel-development was a dead IIS redirector; bilt has real app.
#
# SAFETY: bilt.marriott.com explicitly in-scope. Read-only GET. No auth, no
# writes, no fuzzing. Scope-check any cross-host API base before probing it.
# Never follow into OOS. X-Bug-Bounty header. Record researcher IP below.
#
# Run (Termux): OUTDIR=$HOME/s34 bash runbooks/PI-RUNBOOK-session34-bilt-api.sh \
#                 2>&1 | tee $HOME/s34/s34.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s34
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s34"
  else OUTDIR="$HOME/s34"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="bilt.marriott.com"; B="https://$T"
SCOPE="SCOPE_FILE=config/marriott-scope.yaml ./scripts/scope-check.sh"

echo "============================================================"
echo "BILT API HUNT  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

echo "═══ PHASE A: FINGERPRINT + HOMEPAGE ═══"
m=$(curl -s -o "$OUTDIR/home.html" -D "$OUTDIR/home.hdr" -L --max-redirs 3 \
     -H "User-Agent: $UA" -H "$IDH" --max-time 25 \
     -w '%{http_code}|%{size_download}|%{url_effective}' "$B/" 2>/dev/null) || m="000|0|-"
echo "  GET / -> ${m%%|*} | $(echo "$m"|cut -d'|' -f2)B | final=$(echo "$m"|cut -d'|' -f3)"
grep -iE '^(server|x-powered-by|via|content-type|set-cookie|x-amz|x-vercel|x-nextjs):' \
  "$OUTDIR/home.hdr" 2>/dev/null | tr -d '\r' | sed 's/^/    /' | head -12 || true
grep -oiE '<title>[^<]*' "$OUTDIR/home.html" 2>/dev/null | head -1 | sed 's/^/    title:/' || true
echo ""

echo "═══ PHASE B: EXTRACT + DOWNLOAD JS BUNDLES ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]; T=os.environ.get("T","bilt.marriott.com")
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read() if os.path.exists(os.path.join(O,"home.html")) else ""
js=set(re.findall(r'(?:src)=["\']([^"\']+\.m?js)(?:\?[^"\']*)?["\']',h,re.I))
# also inline-referenced chunks (Next/webpack)
js|=set("/"+x for x in re.findall(r'["\'](_next/static/[^"\']+\.js)["\']',h))
open(os.path.join(O,"js.txt"),"w").write("\n".join(sorted(js)))
print(f"  {len(js)} JS refs")
for j in sorted(js)[:30]: print("   ",j)
PYEOF
echo ""
echo "  downloading JS (max 20)..."
i=0
while read -r J && [ $i -lt 20 ]; do
  [ -z "$J" ] && continue
  P=$(echo "$J" | sed -E "s#^https?://[^/]+##"); case "$P" in /*) ;; *) P="/$P";; esac
  curl -s --max-time 20 -H "User-Agent: $UA" -H "$IDH" "$B$P" >> "$OUTDIR/alljs.txt" 2>/dev/null || true
  printf '\0' >> "$OUTDIR/alljs.txt"
  i=$((i+1)); sleep 0.25
done < "$OUTDIR/js.txt"
echo "  collected $(wc -c < "$OUTDIR/alljs.txt" 2>/dev/null || echo 0) bytes of JS"
echo ""

echo "═══ PHASE C: MINE API BASES / ENDPOINTS / SECRETS ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]; p=os.path.join(O,"alljs.txt")
js=open(p,encoding="utf-8",errors="replace").read() if os.path.exists(p) else ""
js+=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read() if os.path.exists(os.path.join(O,"home.html")) else ""
def uniq(x):
    s=[];[s.append(i) for i in x if i not in s];return s
# absolute API hosts
hosts=uniq(re.findall(r'https?://([a-z0-9.-]+\.(?:marriott\.com|biltrewards\.com|bilt\.com|amazonaws\.com|execute-api[.a-z0-9-]*))',js,re.I))
# relative+absolute api paths
paths=uniq(re.findall(r'["\'`](https?://[^"\'`]+/(?:api|v\d|graphql|rewards|points|members?|users?|accounts?)[^"\'`]*|/(?:api|v\d|graphql|rewards|points|members?|users?|accounts?)/[A-Za-z0-9_./{}:-]{2,90})["\'`]',js))
ops=uniq(re.findall(r'(?:query|mutation)\s+([A-Za-z][A-Za-z0-9_]{3,40})',js))
keys=uniq(re.findall(r'((?:api[_-]?key|apikey|client[_-]?id|client[_-]?secret|x-api-key|authorization|bearer)["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{10,}["\'])',js,re.I))
graphql_uri=uniq(re.findall(r'(?:uri|graphqlEndpoint|endpoint|baseURL|apiUrl|API_URL)["\']?\s*[:=]\s*["\']([^"\']+)["\']',js,re.I))

def dump(label,items,lim=25):
    print(f"  {label}: {len(items)}")
    for i in items[:lim]: print("    ",i)
dump("API hosts",hosts)
dump("API/GraphQL base/config",graphql_uri)
dump("API paths",paths)
dump("graphql ops",ops,30)
dump("possible secrets",keys,15)
open(os.path.join(O,"hosts.txt"),"w").write("\n".join(hosts))
open(os.path.join(O,"paths.txt"),"w").write("\n".join(paths))
PYEOF
echo ""

echo "═══ PHASE D: UNAUTH PROBE OF DISCOVERED API PATHS (in-scope only) ═══"
echo "(flagging anything that returns data / non-401-403)"
if [ -s "$OUTDIR/paths.txt" ]; then
  while read -r U; do
    [ -z "$U" ] && continue
    # resolve to absolute + host for scope check
    if echo "$U" | grep -q '^http'; then ABS="$U"; H=$(echo "$U"|sed -E 's#https?://([^/]+).*#\1#'); else ABS="$B$U"; H="$T"; fi
    # scope guard for cross-host
    if [ "$H" != "$T" ]; then
      if ! eval "$SCOPE \"$H\"" 2>/dev/null | grep -q 'IN-SCOPE'; then
        printf '    [skip OOS] %s\n' "$H"; continue
      fi
    fi
    m=$(curl -s -o "$OUTDIR/probe.txt" -H "User-Agent: $UA" -H "$IDH" \
         -H 'Accept: application/json' --max-time 15 \
         -w '%{http_code}|%{size_download}' "$ABS" 2>/dev/null) || m="000|0"
    code="${m%|*}"; size="${m#*|}"
    case "$code" in
      404|000) ;;
      401|403) printf '    [%s %sB] %s\n' "$code" "$size" "$ABS";;
      *) printf '    *** [%s %sB] %s\n' "$code" "$size" "$ABS"
         head -c 200 "$OUTDIR/probe.txt" | tr '\n' ' '; echo;;
    esac
    sleep 0.4
  done < "$OUTDIR/paths.txt"
else
  echo "  no API paths mined — inspect alljs.txt manually."
fi
echo ""

echo "════════════════════════════════════════════"
echo "DECISION GATE"
echo "════════════════════════════════════════════"
echo "  Pursue: any Phase D *** (200 w/ data) = unauth API access -> test IDOR by"
echo "  swapping member/account/points IDs (own vs synthetic). Any leaked key in"
echo "  Phase C = validate scope/impact. GraphQL base found = try introspection."
echo "  If all 401/403, the API enforces auth -> capture an authenticated bilt"
echo "  request via DevTools to learn the model, then test IDOR with own account."
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
