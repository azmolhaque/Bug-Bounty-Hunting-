#!/usr/bin/env bash
# =============================================================================
# Google VRP — Photomath session9: extract EXACT api-key + auth + profiles paths
# Portable: Termux / Linux / Pi. Pure static (reuses session5 strings, no network).
#
# session8 found the IDOR setup:
#   * paths /profiles/cur/0 (own) and /profiles/ref/ (by reference id)
#   * id fields userId + myUserId
#   * GetAnonymousUserRequest  => app can mint an ANON bearer token (no real acct)
#   * auth = Authorization: Bearer  +  api-key header
# To run the IDOR test we need 3 exact literals from the binary:
#   (1) the api-key value,  (2) the anonymous-auth endpoint path/host,
#   (3) the full /profiles/{cur|ref}/... template.
# This prints context windows around the relevant markers to recover them.
#
# SAFETY: pure static text analysis. NO network. The api-key is printed for our
# own anonymous-token request only — never to access another user's data, never
# committed to git.
#
# Run (Termux): OUTDIR=$HOME/pm5 bash runbooks/PI-RUNBOOK-photomath-session9-extract-auth-profiles.sh \
#                 2>&1 | tee $HOME/pm5/pm9.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/pm5}"; export OUTDIR
S="$OUTDIR/strings.txt"
echo "============================================================"
echo "PHOTOMATH session9 — EXTRACT AUTH/PROFILES LITERALS  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Pure static. Source: $S"
echo "============================================================"; echo ""
[ -s "$S" ] || { echo "  strings.txt missing at $S — run session5 first."; exit 1; }

python3 - << 'PYEOF'
import os,re
S=os.environ["OUTDIR"]+"/strings.txt"
data=open(S,encoding="utf-8",errors="replace").read()

def windows(term, pat=None, n=90, lim=25):
    out=[]; seen=set()
    for m in re.finditer(re.escape(term) if pat is None else pat, data, re.I):
        a=max(0,m.start()-n); b=min(len(data),m.end()+n)
        w=data[a:b].replace("\n"," ")
        key=w.strip()[:120]
        if key in seen: continue
        seen.add(key); out.append(w.strip())
        if len(out)>=lim: break
    return out

print("════ A. /profiles/ path templates (full context) ════")
for w in windows("profiles/", pat=r'profiles/(?:cur|ref)[A-Za-z0-9/_{}.:%-]*', lim=30):
    print("   …"+w+"…")
print()

print("════ B. api-key VALUES (context around key headers) ════")
# look for header-name then a value-ish token nearby
for w in windows("", pat=r'(?i)(?:x-)?api[_-]?key["\':= ]{1,4}[A-Za-z0-9_\-]{16,60}', lim=20):
    print("   …"+w+"…")
# also standalone long key-like tokens near the word 'key'
print("   -- candidate key tokens near 'apikey'/'api_key' --")
for w in windows("", pat=r'(?i)api[_-]?key', n=60, lim=15):
    print("   …"+w+"…")
print()

print("════ C. anonymous-auth + login endpoints ════")
for term in ["anonymous","GetAnonymousUser","/login","authenticate","/auth","/token","refresh","oauth"]:
    ws=windows(term, n=70, lim=6)
    if ws:
        print(f"  [{term}]")
        for w in ws: print("     …"+w+"…")
print()

print("════ D. full URLs / paths on the api hosts (any depth) ════")
for w in sorted(set(re.findall(r'(?:https?://)?(?:lapi|rapi|bhapi)\.photomath\.net/[A-Za-z0-9/_{}.:%-]{1,80}', data))):
    print("   "+w)
print()

print("════ E. Authorization / Bearer header construction ════")
for w in windows("", pat=r'(?i)authorization["\':= ]{1,4}[A-Za-z0-9 _\-{}$]{0,40}', n=50, lim=12):
    print("   …"+w+"…")
for w in windows("Bearer", n=50, lim=8):
    print("   …"+w+"…")
PYEOF
echo ""
echo "════════════════════════════════════════════"
echo "WHAT WE NEED FROM THIS"
echo "════════════════════════════════════════════"
echo "  1. The api-key literal (Section B) — used ONLY to mint our own anon token."
echo "  2. The anonymous/login endpoint (Section C/D) — to POST for a Bearer token."
echo "  3. The /profiles/ref/{id} template (Section A/D) — the IDOR target."
echo "  With all 3, session10 will: mint OUR anon token -> read /profiles/cur (ours)"
echo "  -> request /profiles/ref/<other id> -> if it returns another user's data ="
echo "  CONFIRMED IDOR/BOLA. All reads; the only write is creating our own anon user."
echo ""
echo "  If the exact body schema isn't recoverable here, the fallback is ONE proxy"
echo "  capture of the app's anon-login + a profile fetch — then we replay+vary."
echo ""
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
