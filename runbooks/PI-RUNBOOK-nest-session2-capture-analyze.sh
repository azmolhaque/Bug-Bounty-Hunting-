#!/usr/bin/env bash
# =============================================================================
# Google VRP — Nest: analyze captured web-session traffic (HAR) -> token + buckets
# Portable: Termux / Linux / Pi.
#
# Nest web app (home.nest.com) is LIVE with a real authed API (api.home.nest.com,
# /structures /devices /put /subscribe, 401 unauth). No APK patching needed — it's
# a WEBSITE, so HTTP Toolkit can intercept Chrome (browser trusts user CAs).
#
# Capture: HTTP Toolkit -> intercept your browser -> log into home.nest.com ->
#   click around (Home, devices, settings) -> Export HAR.
# This parses that HAR to extract: the session token (Authorization), YOUR user id,
# and the structure/device/shared/bucket IDs + the real API endpoints -> the exact
# knobs for the cross-account / sharing-revocation IDOR test.
#
# INPUT: HAR=/sdcard/Download/nest.har
#   HAR=/sdcard/Download/nest.har OUTDIR=$HOME/nest2 \
#     bash runbooks/PI-RUNBOOK-nest-session2-capture-analyze.sh 2>&1 | tee $HOME/nest2/nest2.log
#
# SAFETY: local analysis only. Token = OUR OWN session, masked here, gitignored,
# never committed.
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/nest2}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${HAR:?set HAR=/path/to/nest.har (export from HTTP Toolkit)}"
[ -f "$HAR" ] || { echo "HAR not found: $HAR"; exit 1; }
export HAR
echo "============================================================"
echo "NEST CAPTURE ANALYSIS  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "HAR: $HAR ($(wc -c < "$HAR") bytes)   local analysis only"
echo "============================================================"; echo ""

python3 - <<'PY'
import os,json,re
HAR=os.environ["HAR"]; O=os.environ["OUTDIR"]
try: har=json.load(open(HAR,encoding="utf-8",errors="replace"))
except Exception as e: print("  HAR parse error:",e); raise SystemExit
entries=har.get("log",{}).get("entries",[])
print(f"  {len(entries)} requests in capture")
def mask(t): return (t[:10]+"…"+t[-6:]) if t and len(t)>24 else (t or "")
tokens=set(); endpoints={}; userids=set(); buckets=set(); transport=set()
for e in entries:
    req=e.get("request",{}); url=req.get("url",""); method=req.get("method","")
    if not re.search(r'(home\.nest\.com|nest\.com|nestlabs)', url): continue
    host=re.sub(r'https?://','',url).split('/')[0]
    path="/"+url.split(host,1)[-1].split('?')[0].lstrip('/')
    for h in req.get("headers",[]):
        if h.get("name","").lower()=="authorization":
            tokens.add(h.get("value",""))
    body=(req.get("postData",{}) or {}).get("text","") or ""
    resp=e.get("response",{}); status=resp.get("status",0)
    rtext=(resp.get("content",{}) or {}).get("text","") or ""
    endpoints.setdefault((method,host,path),status)
    blob=path+" "+body+" "+rtext[:6000]
    # Nest user ids (numeric) + bucket ids: type.id  (structure. device. shared. user. quartz. topaz.)
    for m in re.findall(r'"userid"\s*:\s*"?(\w+)"?', blob): userids.add(m)
    for m in re.findall(r'/api/0\.1/user/(\w+)', blob): userids.add(m)
    for m in re.findall(r'\b(structure|device|shared|user|quartz|topaz|kryptonite|where|message|link|track)\.[A-Za-z0-9_\-]{6,}', blob): buckets.add(m)
    for m in re.findall(r'"(?:transport_url|weather_url|czfe_url|rubyapi_url)"\s*:\s*"([^"]+)"', blob): transport.add(m)
print()
print(f"  ==== SESSION TOKEN(S): {len(tokens)} ====")
for t in tokens: print("    "+mask(t)); open(O+"/token.txt","a").write(t+"\n")
print(f"  ==== USER IDs: {sorted(userids)}")
print(f"  ==== TRANSPORT/API URLs: {sorted(transport)}")
print(f"  ==== BUCKET IDs ({len(buckets)}) — IDOR knobs ====")
for b in sorted(buckets)[:50]: print("    "+b)
print()
print(f"  ==== ENDPOINTS ({len(endpoints)}) ====")
for (m,h,p),s in sorted(endpoints.items()): print(f"    {m:5} {h}{p} -> {s}")
open(O+"/endpoints.txt","w").write("\n".join(f"{m} https://{h}{p}" for (m,h,p) in endpoints))
open(O+"/buckets.txt","w").write("\n".join(sorted(buckets)))
print()
print("  -> token.txt / endpoints.txt / buckets.txt written (token local-only).")
PY
echo ""
echo "════════════════════════════════════════════"
echo "NEXT — paste the ENDPOINTS, USER IDs, BUCKET IDs (NOT the token)"
echo "════════════════════════════════════════════"
echo "  I'll build the IDOR/sharing test:"
echo "   * BOLA: with A's token, GET /api/0.1/user/{B_userid} and read B's"
echo "     structure/device buckets by id (A is not a member)."
echo "   * sharing-revocation: B shares a home with A, remove A, check if A's token"
echo "     still reads/controls the device bucket (/put, /subscribe)."
echo "   * The /put write path = can A change B's device state (e.g. unlock/temp)?"
echo ""
echo "Evidence: $OUTDIR (token.txt gitignored)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
