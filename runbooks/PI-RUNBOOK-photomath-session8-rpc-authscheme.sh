#!/usr/bin/env bash
# =============================================================================
# Google VRP — Photomath session8: extract gRPC/Connect RPC methods + auth scheme
# Portable: Termux / Linux / Pi. Reuses session5 strings (no re-download).
#
# session7: curated REST probe (602 paths) hit ONLY /health,/healthz,/version on
# lapi/rapi; every account/auth/subscription/books path 404'd, zero 401s. That is
# the signature of a gRPC / Connect-RPC API (POST-only method paths), not REST —
# which is why GET path-guessing can't see the real endpoints. But the RPC service
# + method names are string literals in the dex. Mine them statically:
#   1. gRPC/Connect method paths:  /pkg.Service/Method
#   2. proto package + message/field names (the DATA MODEL = IDOR object types)
#   3. AUTH SCHEME: Authorization/Bearer/x-api-key/id_token header usage
#   4. any endpoint path literals adjacent to the api hosts
#
# Output = the real RPC map + how the app authenticates. This tells us exactly
# what an authenticated IDOR test would target, and whether auth is a bearer JWT
# (swap object id) or an api-key (possibly unauth-abusable).
#
# SAFETY: pure static text analysis of strings already on disk. NO network calls
# to the target at all. Never use any secret printed.
#
# Run (Termux): OUTDIR=$HOME/pm5 bash runbooks/PI-RUNBOOK-photomath-session8-rpc-authscheme.sh \
#                 2>&1 | tee $HOME/pm5/pm8.log
# =============================================================================
set -o pipefail
OUTDIR="${OUTDIR:-$HOME/pm5}"; export OUTDIR; mkdir -p "$OUTDIR"
S="$OUTDIR/strings.txt"
echo "============================================================"
echo "PHOTOMATH session8 — RPC + AUTH STATIC MINE  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Pure static analysis (no network). Source: $S"
echo "============================================================"; echo ""
if [ ! -s "$S" ]; then
  echo "  strings.txt not found at $S — re-extracting from $OUTDIR/ex ..."
  : > "$S"
  find "$OUTDIR/ex" -type f 2>/dev/null | while read -r f; do
    grep -aoE '[[:print:]]{4,}' "$f" 2>/dev/null >> "$S" || true
  done
fi
echo "  corpus: $(wc -c < "$S" 2>/dev/null || echo 0) bytes"; echo ""

python3 - << 'PYEOF'
import os,re,collections
S=os.environ["OUTDIR"]+"/strings.txt"
data=open(S,encoding="utf-8",errors="replace").read()

def uniq(xs):
    seen=[];
    for x in xs:
        if x not in seen: seen.append(x)
    return seen

# 1. gRPC / Connect method paths:  /package.Service/Method  (>=1 dotted pkg seg)
rpc=re.findall(r'/(?:[a-z][a-zA-Z0-9_]*\.){1,6}[A-Z][A-Za-z0-9_]*/[A-Z][A-Za-z0-9_]*', data)
rpc=[r for r in rpc if not r.lower().endswith(('.xml','.png','.json'))]
# 2. proto packages referencing photomath / solving / book domains
pkgs=re.findall(r'\b(?:com\.)?photomath(?:\.[a-z][a-z0-9_]*){1,6}', data)
pkgs=[p for p in pkgs if not re.search(r'\.(R|BuildConfig|databinding)\b', p)]
# 3. proto-ish Service / Request / Response message type names
svc=re.findall(r'\b([A-Z][A-Za-z0-9]*(?:Service|Api|Controller))\b', data)
msgs=re.findall(r'\b([A-Z][A-Za-z0-9]*(?:Request|Response))\b', data)
# 4. auth scheme markers
auth_hdrs=re.findall(r'(?i)\b(authorization|x-api-key|x-photomath[a-z-]*|api[_-]?key|id[_-]?token|access[_-]?token|refresh[_-]?token|bearer)\b', data)
# 5. object-id / id-bearing field names (IDOR data model)
idfields=re.findall(r'\b([a-z][a-zA-Z0-9]*(?:Id|Uuid|Uid|Guid))\b', data)
# 6. endpoint path literals adjacent to api hosts or with solve/book/user nouns
paths=re.findall(r'/(?:v[0-9]/)?(?:solve|solution|results?|book[s]?|page[s]?|task[s]?|user[s]?|account[s]?|me|profile|subscription[s]?|purchase[s]?|receipt[s]?|session[s]?|device[s]?|auth|login|register|token|refresh)[A-Za-z0-9/_{}-]*', data, re.I)
paths=[p for p in paths if not re.search(r'\.(xml|png|json|webp|ttf|otf)$', p)]

def top(xs,n=60):
    c=collections.Counter(xs)
    return [f"{k}   (x{v})" for k,v in c.most_common(n)]

print("════ 1. gRPC/Connect METHOD PATHS (the real endpoints) ════")
r=uniq(rpc)
for x in r[:80]: print("   "+x)
if not r: print("   (none — not classic gRPC path form; may be Connect/Twirp w/ JSON)")
print()
print("════ 2. PROTO PACKAGES (photomath.*) ════")
for x in uniq(pkgs)[:60]: print("   "+x)
if not pkgs: print("   (none)")
print()
print("════ 3. SERVICE / MESSAGE TYPES ════")
print("  Services:")
for x in top(svc,40): print("    "+x)
print("  Request/Response msgs (data model):")
for x in top(msgs,40): print("    "+x)
print()
print("════ 4. AUTH SCHEME markers ════")
for x in top([a.lower() for a in auth_hdrs],20): print("   "+x)
if not auth_hdrs: print("   (none found — check OkHttp interceptor classes)")
print()
print("════ 5. ID FIELD NAMES (IDOR object types) ════")
for x in top(idfields,40): print("   "+x)
print()
print("════ 6. ENDPOINT PATH LITERALS ════")
for x in uniq(paths)[:60]: print("   "+x)
if not paths: print("   (none distinct)")
PYEOF
echo ""
echo "════════════════════════════════════════════"
echo "INTERPRETATION"
echo "════════════════════════════════════════════"
echo "  * RPC method paths present  -> the API is gRPC/Connect. Real endpoints are"
echo "    POST /pkg.Service/Method. We can test those (with your OK for POST), and"
echo "    the Request msgs + Id fields show which take an object id (IDOR targets)."
echo "  * AUTH = 'authorization/bearer' -> JWT bearer; IDOR test = swap id with our"
echo "    own token. AUTH = 'x-api-key' only -> the key may grant unauth-equivalent"
echo "    access (test if a static app key alone reaches user data = finding)."
echo "  * If RPC list is empty but Services/messages exist, it's Connect-JSON over"
echo "    POST; we map method names from the Service+Request pairs."
echo ""
echo "  NEXT DECISION: with the method+auth map, either (a) replay ONE real request"
echo "  via proxy to get a token and run the IDOR test, or (b) if a static api-key"
echo "  alone authorizes data reads, that's testable now. Paste this output."
echo ""
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
