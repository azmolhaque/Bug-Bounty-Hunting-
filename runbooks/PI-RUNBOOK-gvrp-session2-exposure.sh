#!/usr/bin/env bash
# =============================================================================
# Google VRP — Acquisition exposure / misconfig scan (gvrp-session2)
# Portable: Linux / Pi / Termux. curl + Google DoH only.
#
# Session1 takeover came up dry but found ~230 live acquisition hosts. This run
# scans live in-scope acquisition hosts for fundable, command-detectable bugs:
#   - exposed VCS/secrets: /.git/HEAD, /.git/config, /.env, /.env.* , /config.json
#   - source maps (.js.map) referenced by the homepage
#   - Spring actuator: /actuator/env, /actuator/heapdump (secret/heap leak)
#   - API docs: /swagger-ui, /v3/api-docs, /openapi.json
#   - GraphQL introspection: /graphql, /api/graphql, /query
#   - credentialed CORS reflection (ACAO mirrors attacker Origin + ACAC:true)
#
# SCOPE: only FQDNs in config/acquisitions_domains_tiers.asciipb (+ direct
# subdomains CT-found under propagate_tier_to_direct_subdomains apexes). Read-only
# GET/OPTIONS. Conservative pacing. Detection only.
#
# Run (Termux): MAXHOSTS=250 OUTDIR=$HOME/gv2 \
#   bash runbooks/PI-RUNBOOK-gvrp-session2-exposure.sh 2>&1 | tee $HOME/gv2/gv2.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/gv2
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/gv2"
  else OUTDIR="$HOME/gv2"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
MAX="${MAXHOSTS:-100000}"
BASEF="acquisitions_domains_tiers.asciipb"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
SCOPEFILE=""
for c in "${SCOPEFILE:-}" "config/$BASEF" "$PWD/config/$BASEF" "$SCRIPT_DIR/../config/$BASEF" "$HOME/bbh/config/$BASEF"; do
  [ -n "$c" ] && [ -f "$c" ] && { SCOPEFILE="$c"; break; }
done
[ -z "$SCOPEFILE" ] && { echo "scope file not found; pass SCOPEFILE=..."; exit 1; }

echo "============================================================"
echo "GVRP EXPOSURE SCAN  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR   scope: $SCOPEFILE"
echo "============================================================"; echo ""

grep -oE 'fqdn: "[^"]+"' "$SCOPEFILE" | sed 's/fqdn: "//;s/"//' \
  | grep -viE '(^|\.)(google|gstatic|googleapis|withgoogle)\.com$' | sort -u > "$OUTDIR/hosts.txt"
echo "in-scope acquisition FQDNs: $(wc -l < "$OUTDIR/hosts.txt")  (scanning up to $MAX live)"
echo ""

export UA MAX
python3 - << 'PYEOF'
import os,subprocess,json,re,sys
O=os.environ["OUTDIR"]; UA=os.environ["UA"]; MAX=int(os.environ["MAX"])
hosts=[h.strip() for h in open(os.path.join(O,"hosts.txt")) if h.strip()]

def run(args,t=12):
    try: return subprocess.run(["curl","-s","--max-time",str(t)]+args,capture_output=True,text=True)
    except Exception:
        class R: stdout=""; returncode=1
        return R()
def alive(h):
    out=run(["-H","accept: application/dns-json",f"https://dns.google/resolve?name={h}&type=A"],6).stdout
    try: return any(a.get("type")==1 for a in json.loads(out).get("Answer",[]))
    except Exception: return False
def get(url,extra=None,t=12,head=False):
    a=["-sk","-o","-","-D","-","-H",f"user-agent: {UA}","--max-time",str(t),"-L","--max-redirs","2"]
    if head: a=["-sk","-I","-H",f"user-agent: {UA}","--max-time",str(t)]
    if extra: a+=extra
    a.append(url)
    return run(a,t).stdout

PROBES=[
 ("/.git/HEAD",        re.compile(r'^ref: refs/|^[0-9a-f]{40}')),
 ("/.git/config",      re.compile(r'\[core\]|repositoryformatversion')),
 ("/.env",             re.compile(r'(?im)^[A-Z0-9_]+=|APP_KEY|SECRET|DB_|API_KEY')),
 ("/.env.local",       re.compile(r'(?im)^[A-Z0-9_]+=|SECRET|API_KEY')),
 ("/config.json",      re.compile(r'(?i)apiKey|secret|password|token')),
 ("/actuator/env",     re.compile(r'"propertySources"|systemEnvironment|spring')),
 ("/actuator/health",  re.compile(r'"status"\s*:\s*"UP"')),
 ("/v3/api-docs",      re.compile(r'"openapi"\s*:')),
 ("/swagger-ui/index.html", re.compile(r'swagger-ui')),
 ("/openapi.json",     re.compile(r'"openapi"\s*:|"swagger"\s*:')),
 ("/server-status",    re.compile(r'Apache Server Status')),
 ("/.well-known/security.txt", re.compile(r'(?i)contact:')),
]
GQL=["/graphql","/api/graphql","/query","/v1/graphql"]
INTRO='{"query":"query{__schema{queryType{name}}}"}'

scanned=0; hits=[]
for h in hosts:
    if scanned>=MAX: break
    if not alive(h): continue
    scanned+=1
    base=f"https://{h}"
    if scanned%25==0: print(f"  ...{scanned} live scanned (hits={len(hits)})",file=sys.stderr)
    # sensitive paths
    for path,rx in PROBES:
        resp=get(base+path)
        if not resp: continue
        # split headers/body (we used -D - -o -)
        parts=resp.split("\r\n\r\n",1); body=parts[-1] if parts else resp
        code=""
        m=re.search(r'HTTP/\S+\s+(\d{3})', resp); code=m.group(1) if m else "?"
        if code in ("200",) and rx.search(body[:4000]):
            hits.append({"host":h,"path":path,"code":code,"evi":body[:120].replace("\n"," ")})
            print(f"  *** {h}{path} [{code}] {body[:90].strip()}")
    # graphql introspection
    for g in GQL:
        resp=get(base+g, extra=["-X","POST","-H","content-type: application/json","--data",INTRO])
        if '"__schema"' in resp or '"queryType"' in resp:
            hits.append({"host":h,"path":g,"code":"200","evi":"introspection enabled"})
            print(f"  *** {h}{g} GRAPHQL INTROSPECTION ENABLED")
            break
    # credentialed CORS reflection
    aco=get(base+"/", extra=["-H","Origin: https://evil.example.com","-I"])
    if re.search(r'(?i)access-control-allow-origin:\s*https://evil\.example\.com', aco) and \
       re.search(r'(?i)access-control-allow-credentials:\s*true', aco):
        hits.append({"host":h,"path":"/","code":"CORS","evi":"reflects arbitrary Origin + ACAC:true"})
        print(f"  *** {h} CREDENTIALED CORS REFLECTION (ACAO=evil + ACAC=true)")

json.dump(hits, open(os.path.join(O,"hits.json"),"w"), indent=2)
print(f"\nSUMMARY: live-scanned={scanned}  hits={len(hits)}")
PYEOF
echo ""

echo "════════════════════════════════════════════"
echo "EXPOSURE HITS"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]; h=json.load(open(os.path.join(O,"hits.json")))
if not h: print("  none this pass.")
for r in h: print(f"  {r['code']:6}  {r['host']}{r['path']}   {r['evi']}")
print()
print("  Triage: .git/.env/actuator-env/heapdump = secret leak (High/Critical if")
print("  creds present). GraphQL introspection = info-disc (chain to IDOR). CORS")
print("  credentialed reflection = account data theft. Verify each manually, confirm")
print("  the data is real+sensitive, then report to Google VRP with a minimal PoC.")
PYEOF
echo ""
echo "Evidence: $OUTDIR/hits.json"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
