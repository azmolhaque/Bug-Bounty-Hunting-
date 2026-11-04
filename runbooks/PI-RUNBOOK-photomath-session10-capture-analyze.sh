#!/usr/bin/env bash
# =============================================================================
# Google VRP — Photomath: analyze captured app traffic (HAR) -> token + real API
# Portable: Termux / Linux / Pi.
#
# Escalated method: intercept the Photomath app (non-root: apk-mitm patch +
# HTTP Toolkit) and export the session as a HAR. This parses that HAR to recover
# what static analysis couldn't: the LIVE Bearer token, the real Connect/gRPC
# endpoint paths actually called, the request/response shapes, and the object-ids
# (userId/sessionId/scanId/etc) -> the exact material for the authenticated IDOR /
# business-logic test (PatchSubscriptionReceipt premium-grant, BOLA on objects).
#
# INPUT: a HAR file exported from HTTP Toolkit (or any proxy). Pass its path:
#   HAR=/sdcard/Download/photomath.har OUTDIR=$HOME/pm10 \
#     bash runbooks/PI-RUNBOOK-photomath-session10-capture-analyze.sh 2>&1 | tee $HOME/pm10/pm10.log
#
# SAFETY: local analysis only (no network). The token printed is OUR OWN anon/test
# token, used only to drive our own authenticated requests; it is masked here and
# never committed.
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/pm10}"; export OUTDIR; mkdir -p "$OUTDIR"
: "${HAR:?set HAR=/path/to/photomath.har (export from HTTP Toolkit)}"
[ -f "$HAR" ] || { echo "HAR not found: $HAR"; exit 1; }
export HAR
echo "============================================================"
echo "PHOTOMATH CAPTURE ANALYSIS  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "HAR: $HAR  ($(wc -c < "$HAR") bytes)   local analysis only"
echo "============================================================"; echo ""

python3 - <<'PY'
import os,json,re
HAR=os.environ["HAR"]; O=os.environ["OUTDIR"]
try: har=json.load(open(HAR,encoding="utf-8",errors="replace"))
except Exception as e:
    print("  HAR parse error:",e); raise SystemExit
entries=har.get("log",{}).get("entries",[])
print(f"  {len(entries)} requests in capture")
def mask(t):
    return (t[:8]+"…"+t[-6:]) if t and len(t)>20 else (t or "")
pm=[]; tokens=set(); endpoints={}; objids=set()
for e in entries:
    req=e.get("request",{}); url=req.get("url",""); method=req.get("method","")
    if "photomath.net" not in url and "photomath.com" not in url: continue
    host=re.sub(r'https?://','',url).split('/')[0]
    path="/"+url.split(host,1)[-1].split('?')[0].lstrip('/') if host in url else url
    # auth header
    for h in req.get("headers",[]):
        if h.get("name","").lower()=="authorization":
            v=h.get("value","")
            m=re.search(r'[Bb]earer\s+(\S+)',v)
            if m: tokens.add(m.group(1))
    # request body
    body=(req.get("postData",{}) or {}).get("text","")
    # response
    resp=e.get("response",{}); status=resp.get("status",0)
    rtext=(resp.get("content",{}) or {}).get("text","") or ""
    key=(method,host,path)
    endpoints.setdefault(key,{"status":status,"reqlen":len(body),"resplen":len(rtext)})
    # object ids in url/body/resp
    for blob in (path,body,rtext[:2000]):
        for m in re.findall(r'"?(\w*[Ii]d)"?\s*[:=]\s*"?([A-Za-z0-9_\-]{6,})"?', blob or ""):
            objids.add(f"{m[0]}={m[1][:24]}")
    pm.append((method,host,path,status,len(body),len(rtext)))

print()
print(f"  ==== BEARER TOKEN(S) captured: {len(tokens)} ====")
for t in tokens:
    print("    "+mask(t))
    open(os.path.join(O,"token.txt"),"a").write(t+"\n")
if tokens: print("    (full token saved to $OUTDIR/token.txt — never commit)")
print()
print(f"  ==== REAL API ENDPOINTS ({len(endpoints)}) ====")
for (mthd,host,path),meta in sorted(endpoints.items()):
    print(f"    {mthd:5} {host}{path}  -> {meta['status']}  (req {meta['reqlen']}b / resp {meta['resplen']}b)")
print()
print(f"  ==== OBJECT IDs seen ({len(objids)}) — IDOR knobs ====")
for o in sorted(objids)[:40]: print("    "+o)
# save a replay-ready list
open(os.path.join(O,"endpoints.txt"),"w").write("\n".join(f"{m} https://{h}{p}" for (m,h,p) in endpoints))
print()
print("  -> endpoints.txt + token.txt written. Next: replay an object-fetch with our")
print("     token, then swap the object id / try another user's id (BOLA), and probe")
print("     PatchSubscriptionReceipt for premium-grant abuse.")
PY
echo ""
echo "════════════════════════════════════════════"
echo "NEXT"
echo "════════════════════════════════════════════"
echo "  Paste the ENDPOINTS + OBJECT-ID list above (NOT the token). I'll build the"
echo "  authenticated IDOR/business-logic test against the real Connect methods:"
echo "   * BOLA: refetch a session/scan/document with a DIFFERENT id."
echo "   * Privilege/logic: PatchSubscriptionReceipt -> can we self-grant premium?"
echo "   * Anonymous-user IDOR: GetAnonymousUser(deviceId) with another deviceId."
echo ""
echo "Evidence: $OUTDIR (token.txt local-only, never committed)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
