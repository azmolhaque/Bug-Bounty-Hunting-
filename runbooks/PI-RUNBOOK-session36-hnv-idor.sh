#!/usr/bin/env bash
# =============================================================================
# Marriott — homes-and-villas.marriott.com IDOR surface map (session36)
# Portable: Linux / Pi / Termux.
#
# Why: HnV is Marriott's vacation-rental platform (guests + property owners =
# multi-tenant) with 17 prior IDOR reports — a PROVEN cross-tenant data-access
# asset. The fresh unauth softs (hotel-dev, bilt) were dead/hardened; HnV is the
# asset with a track record. In-scope: homes-and-villas.marriott.com AND
# channel-portal.homes-and-villas.marriott.com.
#
# Goal: map the API surface from client JS, find endpoints that take a
# property/listing/reservation/user ID, and probe them UNAUTH for data or
# enumerable IDs (the IDOR primitive). Authenticated cross-tenant confirmation
# is the follow-up once we know which endpoints carry IDs.
#
# SAFETY: both hosts explicitly in-scope. Read-only GET. No auth, no writes, no
# fuzzing (curated). Never exfil real PII — first sign of another tenant's data,
# STOP and document with own/synthetic. X-Bug-Bounty header. Record IP.
#
# Run (Termux): OUTDIR=$HOME/s36 bash runbooks/PI-RUNBOOK-session36-hnv-idor.sh \
#                 2>&1 | tee $HOME/s36/s36.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s36
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s36"
  else OUTDIR="$HOME/s36"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
SCOPE="SCOPE_FILE=config/marriott-scope.yaml ./scripts/scope-check.sh"

echo "============================================================"
echo "HNV IDOR SURFACE MAP  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

fetch() { # url tag  -> code|size, saves body+hdr (follows redirects within host)
  local url="$1" tag="$2"
  curl -s -o "$OUTDIR/$tag.txt" -D "$OUTDIR/$tag.hdr" -L --max-redirs 3 \
    -H "User-Agent: $UA" -H "$IDH" --max-time 25 \
    -w '%{http_code}|%{size_download}|%{url_effective}' "$url" 2>/dev/null || echo "000|0|-"
}

for HOST in homes-and-villas.marriott.com channel-portal.homes-and-villas.marriott.com; do
  echo "════════ HOST: $HOST ════════"
  B="https://$HOST"; SAFE=$(echo "$HOST"|tr -c 'A-Za-z0-9' '_')

  echo "  [scope] $(eval "$SCOPE \"$HOST\"" 2>/dev/null | tail -1)"
  m=$(fetch "$B/" "${SAFE}_home")
  echo "  GET / -> ${m%%|*} | $(echo "$m"|cut -d'|' -f2)B | final=$(echo "$m"|cut -d'|' -f3)"
  grep -iE '^(server|x-powered-by|x-amz|via|content-type|x-nextjs|set-cookie):' \
    "$OUTDIR/${SAFE}_home.hdr" 2>/dev/null | tr -d '\r' | head -6 | sed 's/^/      /' || true
  echo ""

  # mine homepage for JS, download, extract API endpoints + ID-bearing routes
  python3 - "$OUTDIR/${SAFE}_home.txt" "$HOST" "$SAFE" << 'PYEOF'
import sys,re,os
body=open(sys.argv[1],encoding="utf-8",errors="replace").read() if os.path.exists(sys.argv[1]) else ""
host,safe=sys.argv[2],sys.argv[3]; O=os.environ["OUTDIR"]
js=set(re.findall(r'(?:src)=["\']([^"\']+\.m?js)(?:\?[^"\']*)?["\']',body,re.I))
js|=set("/"+x for x in re.findall(r'["\'](_next/static/[^"\']+\.js)["\']',body))
js|=set(re.findall(r'["\'](https?://[^"\']+\.m?js)["\']',body))
open(os.path.join(O,safe+"_js.txt"),"w").write("\n".join(sorted(js)))
print(f"  {len(js)} JS refs on {host}")
PYEOF

  # download JS
  i=0
  while read -r J && [ $i -lt 25 ]; do
    [ -z "$J" ] && continue
    case "$J" in http*) U="$J";; /*) U="$B$J";; *) U="$B/$J";; esac
    curl -s --max-time 20 -H "User-Agent: $UA" -H "$IDH" "$U" >> "$OUTDIR/${SAFE}_alljs.txt" 2>/dev/null || true
    i=$((i+1)); sleep 0.2
  done < "$OUTDIR/${SAFE}_js.txt"
  echo "  collected $(wc -c < "$OUTDIR/${SAFE}_alljs.txt" 2>/dev/null || echo 0) bytes JS"

  # mine API surface
  python3 - "$OUTDIR/${SAFE}_alljs.txt" "$SAFE" << 'PYEOF'
import sys,re,os
O=os.environ["OUTDIR"]
js=open(sys.argv[1],encoding="utf-8",errors="replace").read() if os.path.exists(sys.argv[1]) else ""
safe=sys.argv[2]
def uniq(x):
    s=[];[s.append(i) for i in x if i not in s];return s
hosts=uniq(re.findall(r'https?://([a-z0-9.-]+\.(?:marriott\.com|amazonaws\.com|execute-api[.a-z0-9-]*|cloudfront\.net))',js,re.I))
bases=uniq(re.findall(r'(?:baseURL|apiUrl|API_URL|endpoint|graphqlEndpoint|uri)["\']?\s*[:=]\s*["\']([^"\']{6,120})["\']',js,re.I))
paths=uniq(re.findall(r'["\'`](/(?:api|v\d|graphql|listings?|properties|property|reservations?|bookings?|guests?|owners?|users?|messages?|units?|hosts?)/[A-Za-z0-9_./{}:$-]{1,80})["\'`]',js))
idroutes=uniq([p for p in paths if re.search(r'[{:$]|/\d|Id|ID|/%s',p)])
ops=uniq(re.findall(r'(?:query|mutation)\s+([A-Za-z][A-Za-z0-9_]{3,40})',js))
keys=uniq(re.findall(r'((?:api[_-]?key|x-api-key|client[_-]?id|authorization|bearer)["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-.]{10,}["\'])',js,re.I))
def d(l,x,n=20):
    print(f"    {l}: {len(x)}")
    for i in x[:n]: print("      ",i)
print("  --- API SURFACE ---")
d("API hosts",hosts); d("base/config URLs",bases); d("ID-bearing routes",idroutes,30)
d("all api paths",paths,30); d("graphql ops",ops,25); d("possible secrets",keys,10)
open(os.path.join(O,safe+"_paths.txt"),"w").write("\n".join(paths))
open(os.path.join(O,safe+"_hosts.txt"),"w").write("\n".join(hosts))
PYEOF
  echo ""
done

# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "NEXT STEPS"
echo "════════════════════════════════════════════"
echo "  Review ID-bearing routes + API hosts above. The IDOR primitive lives in"
echo "  any endpoint taking a property/listing/reservation/owner/user ID."
echo "  Session37 will: (1) probe the most promising endpoints UNAUTH for data,"
echo "  (2) for those needing auth, capture an authenticated HnV session and test"
echo "  cross-tenant access by swapping IDs (own listing/booking vs adjacent)."
echo "  Stop instantly on any real third-party PII; document own/synthetic only."
echo ""
echo "Evidence: $OUTDIR  (paths in *_paths.txt, hosts in *_hosts.txt)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
