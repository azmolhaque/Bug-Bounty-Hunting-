#!/usr/bin/env bash
# =============================================================================
# Google VRP — Acquisition subdomain-takeover sweep (gvrp-session1)
# Portable: Linux / Pi / Termux. No tools beyond curl+python3 (uses Google DoH).
#
# Why: subdomain takeover is the bug class that already landed (Wiz), pays well on
# Google acquisitions, needs no account, and the scope file lists 2050 in-scope
# FQDNs — many on decommissioned acquisition infra (Fitbit/Nest/Photomath/Waze/
# Mandiant/Cloudsimple/Pring/Looker/Apigee...). Dangling CNAMEs to unclaimed
# S3/GitHub/Heroku/Firebase/GCS/Azure/etc = takeover.
#
# Pipeline: parse in-scope FQDNs -> DoH-resolve CNAME+A -> detect dangling/
# unclaimed -> HTTP fingerprint against takeover signature DB -> rank candidates.
#
# SCOPE: only FQDNs explicitly present in config/acquisitions_domains_tiers.asciipb
# are tested. Read-only (DNS + GET). No exploitation — detection only; a real
# takeover is then claimed/PoC'd per Google VRP rules (benign proof page).
#
# Run (Termux): OUTDIR=$HOME/gv1 bash runbooks/PI-RUNBOOK-gvrp-session1-takeover.sh \
#                 2>&1 | tee $HOME/gv1/gv1.log
#   Limit while testing:  MAXHOSTS=300 OUTDIR=$HOME/gv1 bash ...
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/gv1
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/gv1"
  else OUTDIR="$HOME/gv1"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
# Robustly locate the scope file: env override, cwd, repo-relative-to-this-script,
# and common clone paths. Works regardless of where the script is invoked from.
BASEF="acquisitions_domains_tiers.asciipb"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
SCOPEFILE=""
for cand in "${SCOPEFILE:-}" "config/$BASEF" "$PWD/config/$BASEF" \
            "$SCRIPT_DIR/../config/$BASEF" "$HOME/bbh/config/$BASEF" \
            "$HOME/bug-bounty-hunting-/config/$BASEF" "$HOME/Bug-Bounty-Hunting-/config/$BASEF"; do
  [ -n "$cand" ] && [ -f "$cand" ] && { SCOPEFILE="$cand"; break; }
done
if [ -z "$SCOPEFILE" ]; then
  echo "ERROR: scope file '$BASEF' not found. Diagnostics:"
  echo "  cwd=$PWD"; echo "  script_dir=$SCRIPT_DIR"
  echo "  ls config/ :"; ls -la config/ 2>/dev/null | head
  echo "  ls \$SCRIPT_DIR/../config/ :"; ls -la "$SCRIPT_DIR/../config/" 2>/dev/null | head
  echo "  -> If the file is missing, run: git -C \"\$SCRIPT_DIR/..\" checkout origin/$(git -C "$SCRIPT_DIR/.." rev-parse --abbrev-ref HEAD 2>/dev/null) -- config/$BASEF"
  echo "  -> Or pass it explicitly: SCOPEFILE=/path/to/$BASEF OUTDIR=\$HOME/gv1 bash \$0"
  exit 1
fi
echo "scope file: $SCOPEFILE"
MAX="${MAXHOSTS:-100000}"

echo "============================================================"
echo "GVRP TAKEOVER SWEEP  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR   scope: $SCOPEFILE"
echo "============================================================"; echo ""

# ── Phase A: in-scope FQDNs, prioritize acquisitions (exclude google core) ──
grep -oE 'fqdn: "[^"]+"' "$SCOPEFILE" | sed 's/fqdn: "//;s/"//' \
  | grep -viE '(^|\.)(google|gstatic|googleapis|withgoogle|google-analytics)\.com$' \
  | sort -u > "$OUTDIR/hosts.txt"
TOTAL=$(wc -l < "$OUTDIR/hosts.txt")
echo "Phase A: $TOTAL acquisition FQDNs in scope (testing up to $MAX)"
head -n "$MAX" "$OUTDIR/hosts.txt" > "$OUTDIR/hosts.work"
echo ""

echo "Phase B-D: DoH resolve + dangling/fingerprint detection..."
python3 - << 'PYEOF'
import os,json,subprocess,re,sys
O=os.environ["OUTDIR"]; UA=os.environ.get("UA","")
hosts=[h.strip() for h in open(os.path.join(O,"hosts.work")) if h.strip()]

def curl(args, t=12):
    try: return subprocess.run(["curl","-s","--max-time",str(t)]+args,
                               capture_output=True,text=True).stdout
    except Exception: return ""

def doh(name,typ):
    out=curl(["-H","accept: application/dns-json",
              f"https://dns.google/resolve?name={name}&type={typ}"],8)
    try: return json.loads(out) if out else {}
    except Exception: return {}

# takeover fingerprint DB: cname-substring -> (service, http-body-signature, claimable)
FP=[
 ("amazonaws.com","AWS/S3","The specified bucket does not exist",True),
 ("s3.amazonaws","AWS/S3","NoSuchBucket",True),
 ("cloudfront.net","CloudFront","Bad request",False),
 ("github.io","GitHub Pages","There isn't a GitHub Pages site here",True),
 ("herokuapp","Heroku","No such app",True),
 ("herokudns","Heroku","No such app",True),
 ("wordpress.com","WordPress","Do you want to register",True),
 ("pantheonsite","Pantheon","The gods are wise, but do not know of the site",True),
 ("zendesk.com","Zendesk","Help Center Closed",True),
 ("fastly.net","Fastly","Fastly error: unknown domain",True),
 ("netlify","Netlify","Not Found - Request ID",True),
 ("surge.sh","Surge","project not found",True),
 ("bitbucket.io","Bitbucket","Repository not found",True),
 ("ghost.io","Ghost","Domain error",True),
 ("shopify","Shopify","Sorry, this shop is currently unavailable",True),
 ("myshopify","Shopify","Sorry, this shop is currently unavailable",True),
 ("readme.io","Readme","Project doesnt exist",True),
 ("statuspage","Statuspage","Better Uptime",False),
 ("unbouncepages","Unbounce","The requested URL was not found",True),
 ("helpscoutdocs","HelpScout","No settings were found for this company",True),
 ("cargocollective","Cargo","404 Not Found",True),
 ("webflow.io","Webflow","The page you are looking for doesn't exist",True),
 ("firebaseapp.com","Firebase","Site Not Found",True),
 ("web.app","Firebase","Site Not Found",True),
 ("googleapis.com","GCS bucket","The specified bucket does not exist",True),
 ("storage.googleapis","GCS bucket","NoSuchBucket",True),
 ("azurewebsites.net","Azure","404 Web Site not found",True),
 ("cloudapp.azure","Azure","404 Web Site not found",True),
 ("trafficmanager.net","Azure TM","404 Web Site not found",True),
 ("azureedge.net","Azure CDN","404 Web Site not found",True),
 ("desk.com","Desk","Please try again or try Desk.com",True),
 ("tilda.ws","Tilda","Domain has been assigned",True),
 ("wpengine","WPEngine","The site you were looking for couldn't be found",True),
 ("fly.dev","Fly.io","404 Not Found",True),
 ("render.com","Render","not found",True),
]

cand=[]; dangling=[]; live=0; n=0
for h in hosts:
    n+=1
    if n%50==0: print(f"  ...{n}/{len(hosts)}  (cand={len(cand)})", file=sys.stderr)
    c=doh(h,"CNAME"); a=doh(h,"A")
    astatus=a.get("Status"); cname=""
    for ans in c.get("Answer",[]):
        if ans.get("type")==5: cname=ans.get("data","").rstrip(".")
    has_a=any(x.get("type")==1 for x in a.get("Answer",[]))
    # service match on the cname chain
    svc=None
    for sub,name,sig,claim in FP:
        if sub in cname:
            svc=(name,sig,claim); break
    if not cname and astatus==3:  # NXDOMAIN, no cname
        continue
    if svc:
        name,sig,claim=svc
        # fetch http to confirm fingerprint
        body=curl(["-H",f"user-agent: {UA}","-L","--max-redirs","2",
                   f"http://{h}/"],12)
        hit = sig.lower() in body.lower()
        rec={"host":h,"cname":cname,"service":name,"sig_hit":hit,"claimable":claim,
             "nxdomain": astatus==3}
        if hit or (astatus==3) or not has_a:
            cand.append(rec)
            print(f"  *** CANDIDATE {h} -> {cname} [{name}] sig={'HIT' if hit else 'no'} "
                  f"nx={astatus==3} a={has_a}")
    elif cname and astatus==3:
        dangling.append({"host":h,"cname":cname})
        print(f"  dangling-NXDOMAIN {h} -> {cname}")
    if has_a: live+=1

json.dump(cand, open(os.path.join(O,"candidates.json"),"w"), indent=2)
json.dump(dangling, open(os.path.join(O,"dangling.json"),"w"), indent=2)
print(f"\nSUMMARY: {len(hosts)} hosts | live={live} | takeover-candidates={len(cand)} | "
      f"dangling-cname-nxdomain={len(dangling)}")
PYEOF
echo ""

echo "════════════════════════════════════════════"
echo "TAKEOVER CANDIDATES (verify + claim per Google VRP rules)"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,json
O=os.environ["OUTDIR"]
c=json.load(open(os.path.join(O,"candidates.json")))
if not c: print("  none with positive signature/dangling this pass.")
for r in sorted(c, key=lambda x:(not x["sig_hit"], not x["nxdomain"])):
    flag="HIGH" if r["sig_hit"] else ("MED" if r["nxdomain"] else "LOW")
    print(f"  [{flag}] {r['host']}")
    print(f"        cname={r['cname']}  service={r['service']}  claimable={r['claimable']}")
print()
print("  HIGH = HTTP takeover signature matched -> likely claimable now.")
print("  Next: for a HIGH, register the unclaimed resource (e.g. the S3 bucket /")
print("  GitHub Pages repo / Firebase site named by the CNAME), host a benign")
print("  proof page (your VRP id + 'PoC, no malicious content'), screenshot, report.")
print("  Do NOT serve real content; benign canary only.")
PYEOF
echo ""
echo "Evidence: $OUTDIR (candidates.json, dangling.json)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
