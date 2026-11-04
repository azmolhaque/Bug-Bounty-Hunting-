#!/usr/bin/env bash
# =============================================================================
# Google VRP — Photomath session4: mine the web client for REAL API routes
# Portable: Linux / Pi / Termux.
#
# session3 verdict: lapi/tlapi/dpcapi-admin expose ONLY /healthz publicly; the
# real API is path-routed behind a Google LB and returns 404 to guessed paths.
# Guessing = fuzzing = banned. The INTELLIGENT move: the public web frontends
# (photomath.com / photomath.app / the web solver) call those same API hosts with
# the REAL routes baked into their JS. Read the client -> get the route map ->
# probe only the routes the app actually uses (no fuzzing, high signal).
#
# This run:
#   A. scope-check + fetch in-scope frontends, find their JS bundles + source maps.
#   B. mine JS for: api hostnames (*.photomath.net/com), real paths (/v1.. /api..),
#      graphql endpoints, firebase/config, and any embedded keys (report-only).
#   C. probe the DISCOVERED routes unauth (GET) and classify 200/401/403/405.
#
# SAFETY: read-only GET, >=0.3s/req, NEVER use any key found, no fuzzing (only
# routes literally present in the client). Sample bodies truncated.
#
# Run (Termux): mkdir -p $HOME/pm4; OUTDIR=$HOME/pm4 \
#   bash runbooks/PI-RUNBOOK-photomath-session4-jsroutes.sh 2>&1 | tee $HOME/pm4/pm4.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/pm4
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/pm4"
  else OUTDIR="$HOME/pm4"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
SD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_CHECK=""
for c in "./scripts/scope-check.sh" "$SD/../scripts/scope-check.sh" "$HOME/bbh/scripts/scope-check.sh"; do
  [ -f "$c" ] && { SCOPE_CHECK="$c"; break; }
done
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
PACE="${PACE:-0.3}"
echo "============================================================"
echo "PHOTOMATH JS ROUTE MINING  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Read the client to map real API routes. Read-only. Never use found keys."
echo "============================================================"; echo ""
GET(){ curl -s -L --max-redirs 4 --max-time 20 -H "User-Agent: $UA" "$@"; }

FRONTENDS="photomath.com www.photomath.com photomath.app www.photomath.app photomath.net"
echo "═══ A: FRONTENDS + JS DISCOVERY ═══"
: > "$OUTDIR/jsurls.txt"; : > "$OUTDIR/allcode.txt"
for H in $FRONTENDS; do
  if [ -n "$SCOPE_CHECK" ]; then
    r=$(bash "$SCOPE_CHECK" --program google "$H" 2>/dev/null)
    case "$r" in *IN-SCOPE*) : ;; *) echo "  skip(oos) $H"; continue;; esac
  fi
  page=$(GET "https://$H/" 2>/dev/null)
  code=$(curl -s -o /dev/null -w '%{http_code}' -L --max-time 15 -H "User-Agent: $UA" "https://$H/" 2>/dev/null)
  blen=$(printf '%s' "$page" | wc -c)
  echo "  [$code] https://$H/  (${blen} bytes)"
  [ -z "$page" ] && { sleep "$PACE"; continue; }
  echo "/*FRONTEND:$H*/" >> "$OUTDIR/allcode.txt"; printf '%s' "$page" >> "$OUTDIR/allcode.txt"
  # collect JS urls (src= and module preload and chunk refs)
  printf '%s' "$page" | grep -oE '(src|href)=["'"'"'][^"'"'"']+\.js[^"'"'"']*' | sed -E 's/^(src|href)=.//' \
    | while read -r J; do
        case "$J" in http*) U="$J";; //*) U="https:$J";; /*) U="https://$H$J";; *) U="https://$H/$J";; esac
        echo "$U" >> "$OUTDIR/jsurls.txt"
      done
  sleep "$PACE"
done
sort -u "$OUTDIR/jsurls.txt" -o "$OUTDIR/jsurls.txt"
echo "  $(wc -l < "$OUTDIR/jsurls.txt") JS bundles found"
echo ""

echo "═══ B: FETCH JS + MINE ROUTES/HOSTS/KEYS ═══"
n=0
while read -r U; do
  [ -z "$U" ] && continue
  n=$((n+1)); [ "$n" -gt "${MAXJS:-40}" ] && break
  echo "/*JS:$U*/" >> "$OUTDIR/allcode.txt"
  GET "$U" >> "$OUTDIR/allcode.txt" 2>/dev/null
  sleep 0.2
done < "$OUTDIR/jsurls.txt"
echo "  mined $(wc -c < "$OUTDIR/allcode.txt") bytes total"
echo ""

python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
code=open(os.path.join(O,"allcode.txt"),encoding="utf-8",errors="replace").read()
# API hostnames
hosts=sorted(set(re.findall(r'https?://([a-z0-9.-]*photomath\.(?:net|com|app))', code)))
# full URLs to the api hosts (capture path)
apiurls=sorted(set(re.findall(r'https?://(?:[a-z0-9.-]*)photomath\.(?:net|com|app)/[A-Za-z0-9_./%{}:-]{2,80}', code)))
# bare route paths near api/v1/v2/v3/graphql
paths=sorted(set(re.findall(r'["\'`](/(?:api|v[0-9]|graphql|rest|internal|admin|user[s]?|account[s]?|auth|solutions?|tasks?|problems?)[A-Za-z0-9_./{}:-]{0,60})["\'`]', code)))
gql=sorted(set(re.findall(r'https?://[a-z0-9.-]*photomath\.[a-z]+/[a-z0-9/_-]*graphql[a-z0-9/_-]*', code, re.I)))
# keys (report-only)
keys=[]
for name,pat in [("Google API key",r'AIza[0-9A-Za-z_\-]{35}'),
                 ("Firebase db",r'https://[a-z0-9-]+\.firebaseio\.com'),
                 ("firebase appId",r'1:[0-9]{6,}:web:[0-9a-f]{8,}'),
                 ("bearer/secret kv",r'(?i)(api[_-]?key|client[_-]?secret|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']')]:
    for m in re.finditer(pat,code):
        keys.append((name,m.group(0)[:70]))
print("  API HOSTNAMES referenced by the client:")
for h in hosts: print("    "+h)
print()
print(f"  FULL API URLS ({len(apiurls)} unique, showing up to 60):")
for u in apiurls[:60]: print("    "+u)
print()
print(f"  ROUTE PATHS ({len(paths)} unique, up to 60):")
for p in paths[:60]: print("    "+p)
print()
if gql:
    print("  GRAPHQL ENDPOINTS:")
    for g in sorted(set(gql)): print("    "+g)
    print()
seen=set()
ks=[(n,v) for (n,v) in keys if (n,v) not in seen and not seen.add((n,v))]
if ks:
    print("  EMBEDDED KEYS (report-only, NEVER use):")
    for n,v in ks[:25]: print(f"    [{n}] {v}")
    print()
# write probe list: api urls + host+path combos
probe=set()
for u in apiurls:
    probe.add("https://"+u if not u.startswith("http") else u)
open(os.path.join(O,"probe.txt"),"w").write("\n".join(sorted(probe)))
print(f"  -> {len(probe)} discovered URLs queued for unauth probe (Section C)")
PYEOF
echo ""

echo "═══ C: PROBE DISCOVERED ROUTES (unauth, GET) ═══"
if [ -s "$OUTDIR/probe.txt" ]; then
  n=0
  while read -r U; do
    [ -z "$U" ] && continue
    n=$((n+1)); [ "$n" -gt "${MAXPROBE:-60}" ] && break
    # strip template placeholders {id} -> 1 for a benign reachability check
    PU=$(printf '%s' "$U" | sed -E 's/\{[^}]+\}/1/g; s/:[A-Za-z_]+/1/g')
    m=$(curl -s -L --max-redirs 2 --max-time 12 -H "User-Agent: $UA" \
         -o "$OUTDIR/pb.tmp" -w '%{http_code}|%{content_type}|%{size_download}' "$PU" 2>/dev/null) || m="000|-|0"
    code="${m%%|*}"; rest="${m#*|}"; ct="${rest%%|*}"; size="${rest##*|}"
    case "$code" in
      404|000) : ;;
      *) snip=$(head -c 140 "$OUTDIR/pb.tmp" 2>/dev/null | tr '\n\r' '  ')
         f=""; case "$code" in 200) f="[OPEN]";; 401|403) f="[auth]";; 405) f="[method]";; esac
         echo "  [$code] $PU $f"
         echo "    ct=${ct%%;*} size=$size :: ${snip:0:100}";;
    esac
    sleep "$PACE"
  done < "$OUTDIR/probe.txt"
else
  echo "  (no API URLs extracted from client — see route paths above; may need the"
  echo "   mobile app bundle instead of web)"
fi
echo ""
echo "════════════════════════════════════════════"
echo "READ-BACK / NEXT"
echo "════════════════════════════════════════════"
echo "  * [OPEN] 200 on a real /api route returning data unauth = finding."
echo "  * [auth] 401/403 = real endpoint behind auth -> authenticated IDOR/BOLA target"
echo "    (next step: register a free test account, capture the token, test object refs)."
echo "  * If the web client is a thin marketing site with no API calls, the real"
echo "    surface is the MOBILE app -> we'd pivot to APK/token interception."
echo ""
echo "Evidence: $OUTDIR (allcode.txt = mined client; probe.txt = discovered routes)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
