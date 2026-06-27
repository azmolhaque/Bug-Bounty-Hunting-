#!/usr/bin/env bash
# =============================================================================
# Marriott — hotel-development.marriott.com DEEP DIVE + soft-target char (s33)
# Portable: Linux / Pi / Termux.
#
# s32 ranked hotel-development top (soft=5: 200/49KB, raw-origin, NONPROD). Dev
# environments are the richest class for: missing auth, debug/actuator endpoints,
# exposed source maps -> source code, GraphQL introspection, hardcoded secrets in
# JS, unauth API routes. This run maps that surface, then fast-characterizes the
# backup soft targets (mds, globaldesign, bilt, ifast, micmt.uat) so we pick the
# deepest exploitable surface next.
#
# SAFETY: all targets explicitly in-scope (or *uat wildcard). Read-only GET. No
# auth, no writes, no fuzzing (curated paths, paced). Never follow into OOS.
# X-Bug-Bounty header. Record researcher IP printed below.
#
# Run (Termux): OUTDIR=$HOME/s33 bash runbooks/PI-RUNBOOK-session33-hoteldev-deep.sh \
#                 2>&1 | tee $HOME/s33/s33.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s33
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s33"
  else OUTDIR="$HOME/s33"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="hotel-development.marriott.com"
B="https://$T"

echo "============================================================"
echo "HOTEL-DEV DEEP DIVE  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

get() { # path tag  -> code|size, saves body+hdr
  local path="$1" tag="$2"
  local m
  m=$(curl -s -o "$OUTDIR/$tag.txt" -D "$OUTDIR/$tag.hdr" \
       -H "User-Agent: $UA" -H "$IDH" --max-time 20 \
       -w '%{http_code}|%{size_download}' "$B$path" 2>/dev/null) || m="000|0"
  echo "$m"
}

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: FINGERPRINT ═══"
m=$(get "/" home); echo "  GET /  -> ${m%|*} | ${m#*|}B"
echo "  --- response headers ---"
grep -iE '^(server|x-powered-by|x-aspnet|via|set-cookie|content-type|x-frame|x-content|strict-transport|x-amz|x-vercel|x-nextjs|x-drupal|x-generator):' \
  "$OUTDIR/home.hdr" 2>/dev/null | tr -d '\r' | sed 's/^/    /' || true
echo "  --- title / generator ---"
grep -oiE '<title>[^<]*' "$OUTDIR/home.txt" 2>/dev/null | head -1 | sed 's/^/    /' || true
grep -oiE '<meta name="generator"[^>]*' "$OUTDIR/home.txt" 2>/dev/null | head -1 | sed 's/^/    /' || true
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: ASSET + SOURCE-MAP EXTRACTION ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
h=open(os.path.join(O,"home.txt"),encoding="utf-8",errors="replace").read() if os.path.exists(os.path.join(O,"home.txt")) else ""
assets=set(re.findall(r'(?:src|href)=["\']([^"\']+\.(?:js|mjs|css|json))[^"\']*["\']',h,re.I))
js=[a for a in assets if a.endswith(('.js','.mjs'))]
open(os.path.join(O,"assets.txt"),"w").write("\n".join(sorted(assets)))
open(os.path.join(O,"js.txt"),"w").write("\n".join(sorted(js)))
print(f"  {len(assets)} assets, {len(js)} JS files")
for a in sorted(js)[:25]: print("   ",a)
PYEOF
echo ""
echo "  [B2] probing each JS for a sibling .map (source code leak):"
MAPHIT=0
while read -r J; do
  [ -z "$J" ] && continue
  # normalize to path
  P=$(echo "$J" | sed -E "s#^https?://$T##; s#^//[^/]*##")
  case "$P" in /*) ;; *) P="/$P";; esac
  for MP in "${P}.map" "$(echo "$P" | sed 's/\.js$/.js.map/')"; do
    m=$(get "$MP" "map-$(echo "$MP"|tr -c 'A-Za-z0-9' '-')")
    code="${m%|*}"; size="${m#*|}"
    if [ "$code" = "200" ] && [ "$size" -gt 100 ]; then
      echo "    *** SOURCE MAP: $MP ($size B)"; MAPHIT=$((MAPHIT+1))
    fi
  done
  sleep 0.3
done < "$OUTDIR/js.txt"
[ "$MAPHIT" = 0 ] && echo "    no source maps exposed"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE C: DEV / DEBUG / API / SENSITIVE PATHS ═══"
echo "(flagging non-404, non-403 responses)"
for P in \
  /robots.txt /sitemap.xml /.well-known/security.txt \
  /api /api/ /api/health /api/v1 /api/v1/ /graphql /graphiql /api/graphql \
  /actuator /actuator/health /actuator/env /actuator/mappings /actuator/heapdump \
  /swagger-ui.html /swagger-ui/index.html /v2/api-docs /v3/api-docs /openapi.json \
  /.env /.git/HEAD /.git/config /config.json /app.config /web.config /appsettings.json \
  /debug /__debug /trace /server-status /status /health /healthz /info /version \
  /_next/static /_next/data /__nextjs_original-stack-frame \
  /admin /admin/ /login /user /users /test /dev /backup /.DS_Store \
  /wp-json /wp-login.php /sites/default/files /CHANGELOG.txt ; do
  m=$(get "$P" "c-$(echo "$P"|tr -c 'A-Za-z0-9' '-')")
  code="${m%|*}"; size="${m#*|}"
  case "$code" in
    404|000) ;;  # silent
    403) printf '    [403 %sB] %s\n' "$size" "$P";;
    *)   printf '    *** [%s %sB] %s\n' "$code" "$size" "$P"
         head -c 140 "$OUTDIR/c-$(echo "$P"|tr -c 'A-Za-z0-9' '-').txt" | tr '\n' ' '; echo;;
  esac
  sleep 0.3
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE D: JS SECRET / ENDPOINT MINING ═══"
# download up to 12 JS files and mine
i=0
while read -r J && [ $i -lt 12 ]; do
  [ -z "$J" ] && continue
  P=$(echo "$J" | sed -E "s#^https?://$T##; s#^//[^/]*##"); case "$P" in /*) ;; *) P="/$P";; esac
  curl -s --max-time 20 -H "User-Agent: $UA" -H "$IDH" "$B$P" >> "$OUTDIR/alljs.txt" 2>/dev/null || true
  i=$((i+1)); sleep 0.3
done
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]; p=os.path.join(O,"alljs.txt")
js=open(p,encoding="utf-8",errors="replace").read() if os.path.exists(p) else ""
print(f"  mined {len(js)} chars of JS")
def show(label,pat,lim=15):
    hits=sorted(set(re.findall(pat,js)))
    if hits:
        print(f"  {label}: {len(hits)}")
        for h in hits[:lim]: print("    ",h if isinstance(h,str) else h)
api=re.findall(r'["\'](/(?:api|graphql|v1|v2|services|rest)/[A-Za-z0-9_./{}-]{2,80})["\']',js)
show("API endpoints", r'["\'](/(?:api|graphql|v1|v2|services|rest)/[A-Za-z0-9_./{}-]{2,80})["\']')
show("Marriott hosts", r'([a-z0-9.-]+\.marriott\.com)')
show("other hosts", r'https?://([a-z0-9.-]+\.(?:amazonaws|cloudfront|googleapis|azure|cloud)[a-z.]*)')
show("possible keys", r'((?:api[_-]?key|apikey|token|secret|client[_-]?secret|aws_access)[\"\']?\s*[:=]\s*[\"\'][A-Za-z0-9_\-]{12,}[\"\'])',10)
show("graphql ops", r'(?:query|mutation)\s+([A-Za-z][A-Za-z0-9_]{3,40})\s*[({]',20)
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE E: FAST-CHARACTERIZE BACKUP SOFT TARGETS ═══"
for H in mds.marriott.com globaldesign.marriott.com bilt.marriott.com \
         ifast.marriott.com micmt.uat.marriott.com; do
  hb="$OUTDIR/e-$H"
  m=$(curl -s -o "$hb.txt" -D "$hb.hdr" -L --max-redirs 2 \
        -H "User-Agent: $UA" -H "$IDH" --max-time 15 \
        -w '%{http_code}|%{size_download}|%{url_effective}' "https://$H/" 2>/dev/null) || m="000|0|-"
  code="${m%%|*}"; rest="${m#*|}"; size="${rest%%|*}"; final="${rest##*|}"
  srv=$(grep -i '^server:' "$hb.hdr" 2>/dev/null|head -1|tr -d '\r'|cut -d' ' -f2-||true)
  pw=$(grep -i '^x-powered-by:' "$hb.hdr" 2>/dev/null|head -1|tr -d '\r'|cut -d' ' -f2-||true)
  title=$(grep -oiE '<title>[^<]*' "$hb.txt" 2>/dev/null|head -1|sed 's/<title>//I'|tr -d '\r\n'|cut -c1-45||true)
  printf '  %-38s %s/%sB  srv=%s %s\n' "$H" "$code" "$size" "${srv:-?}" "${pw:+xpb=$pw}"
  printf '       title="%s"\n' "$title"
  [ "$final" != "https://$H/" ] && printf '       final=%s\n' "$final"
  sleep 0.4
done
echo ""

echo "════════════════════════════════════════════"
echo "DECISION GATE"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,glob
O=os.environ["OUTDIR"]
# any interesting hotel-dev path?
hot=[]
for f in glob.glob(os.path.join(O,"c-*.hdr")):
    pass
print("Review above: source maps (Phase B), non-404 dev/API paths (Phase C),")
print("secrets/endpoints (Phase D), and backup-target tech (Phase E).")
print()
print("Pursue priority:")
print("  1. Exposed source map or .git -> pull source, find auth/IDOR logic")
print("  2. Unauth /api or /graphql (introspection) -> data access")
print("  3. /actuator/env or heapdump -> secrets")
print("  4. Hardcoded API key/secret in JS -> validate scope/impact")
print("  If hotel-dev is dry, deepest backup from Phase E becomes next target.")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
