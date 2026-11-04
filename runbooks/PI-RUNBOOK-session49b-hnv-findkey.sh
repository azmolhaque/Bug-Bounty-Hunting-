#!/usr/bin/env bash
# =============================================================================
# Marriott — HnV encData: locate the exact CryptoJS passphrase (session49b)
# Portable: Linux / Pi / Termux.
#
# s49 false-positived (loose check matched binary garbage). This run:
#   A. PRINT the real code around decrypt(/encrypt(/.gp/AES/Salted so we can SEE
#      where the passphrase comes from (literal vs __NEXT_DATA__ vs assembled)
#   B. Build a clean candidate set: JS string literals (8-64 chars, filtered) +
#      every string value in the page __NEXT_DATA__/config
#   C. Try each via openssl with a STRICT check: decrypted bytes must be valid
#      UTF-8 with a strong marker (operationName / "variables" / known op name)
#
# INPUT: ENCDATA='U2FsdGVkX1...'  (your own captured blob)
# SAFETY: offline crypto + public JS. Nothing committed. Read-only.
# =============================================================================
set -o pipefail
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s49b
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s49b"
  else OUTDIR="$HOME/s49b"; fi
fi
export OUTDIR; mkdir -p "$OUTDIR"
UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
IDH='X-Bug-Bounty: hackerone-researcher'
T="homes-and-villas.marriott.com"; B="https://$T"
[ -z "${ENCDATA:-}" ] && { echo "ERROR: set ENCDATA='U2FsdGVkX1...'"; exit 1; }
printf '%s' "$ENCDATA" > "$OUTDIR/enc.b64"

echo "============================================================"
echo "HNV FIND KEY  $(date -u '+%Y-%m-%dT%H:%M:%SZ')   IP: $(curl -s ifconfig.me)"
echo "Work: $OUTDIR"; echo "============================================================"; echo ""

curl -s -o "$OUTDIR/home.html" -H "User-Agent: $UA" -H "$IDH" --max-time 25 "$B/" >/dev/null || true
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read()
js=sorted(set(re.findall(r'src=["\']([^"\']+\.m?js)(?:\?[^"\']*)?["\']',h,re.I)))
open(os.path.join(O,"js.txt"),"w").write("\n".join(js))
PYEOF
: > "$OUTDIR/alljs.txt"; i=0
while read -r J && [ $i -lt 16 ]; do
  [ -z "$J" ] && continue
  case "$J" in http*) U="$J";; /*) U="$B$J";; *) U="$B/$J";; esac
  curl -s --max-time 20 -H "User-Agent: $UA" -H "$IDH" "$U" >> "$OUTDIR/alljs.txt" 2>/dev/null || true
  i=$((i+1)); sleep 0.15
done < "$OUTDIR/js.txt"
echo "mined $(wc -c < "$OUTDIR/alljs.txt") bytes JS"; echo ""

echo "═══ PHASE A: KEY-SOURCE CODE CONTEXT (read this) ═══"
python3 - << 'PYEOF'
import os,re
O=os.environ["OUTDIR"]
js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read()
seen=set()
for needle in [r'\.decrypt\(', r'\.encrypt\(', r'\bgp\b', r'CryptoJS', r'AES\.', r'Salted', r'encData']:
    for m in re.finditer(needle, js):
        ctx=js[max(0,m.start()-110):m.end()+150].replace("\n"," ")
        key=ctx[:60]
        if key in seen: continue
        seen.add(key)
        print(f"  «{needle}» {ctx[:240]}")
        if len(seen)>40: break
PYEOF
echo ""

echo "═══ PHASE B: CANDIDATE PASSPHRASES (JS literals + __NEXT_DATA__) ═══"
python3 - << 'PYEOF'
import os,re,json
O=os.environ["OUTDIR"]
js=open(os.path.join(O,"alljs.txt"),encoding="utf-8",errors="replace").read()
h=open(os.path.join(O,"home.html"),encoding="utf-8",errors="replace").read()
cands=set()
# explicit gp definitions
for m in re.finditer(r'\bgp\b\s*[:=]\s*["\']([ -~]{4,80})["\']', js): cands.add(m.group(1))
# string literal immediately passed to decrypt/encrypt as 2nd arg: decrypt(x,"KEY")
for m in re.finditer(r'(?:decrypt|encrypt)\([^,]{1,40},\s*["\']([ -~]{4,80})["\']', js): cands.add(m.group(1))
# __NEXT_DATA__ string values (key may be injected like csrfToken)
m=re.search(r'__NEXT_DATA__"[^>]*>(\{.*?\})</script>', h, re.DOTALL)
if m:
    try:
        d=json.loads(m.group(1))
        def walk(o):
            if isinstance(o,dict):
                for k,v in o.items():
                    if isinstance(v,str) and 4<=len(v)<=80: cands.add(v)
                    walk(v)
            elif isinstance(o,list):
                for v in o: walk(v)
        walk(d)
    except Exception as e: print("  __NEXT_DATA__ parse:",e)
# generic: short alnum/base64 string literals in JS that look like keys
for m in re.finditer(r'["\']([A-Za-z0-9+/=_@.\-]{8,48})["\']', js):
    s=m.group(1)
    if re.search(r'[0-9]', s) and re.search(r'[A-Za-z]', s) and not s.endswith(('.js','.css','.png','.svg')):
        cands.add(s)
cands=[c for c in cands if c.strip()]
open(os.path.join(O,"keycands.txt"),"w").write("\n".join(sorted(set(cands))))
print(f"  {len(set(cands))} candidates (saved)")
PYEOF
echo ""

echo "═══ PHASE C: STRICT DECRYPT TRY ═══"
FOUND=""
while IFS= read -r KEY; do
  [ -z "$KEY" ] && continue
  for CIPH in aes-256-cbc aes-128-cbc; do for MD in md5 sha256; do
    openssl enc -d -$CIPH -md $MD -a -A -pass pass:"$KEY" -in "$OUTDIR/enc.b64" -out "$OUTDIR/try.bin" 2>/dev/null || continue
    # strict: strong marker + valid utf-8 + no null bytes
    if LC_ALL=C grep -aqE 'operationName|"variables"|getProfileDetails|reservationDetails|getTotalReservationData|"query"' "$OUTDIR/try.bin" \
       && ! LC_ALL=C grep -aq $'\x00' "$OUTDIR/try.bin" \
       && python3 -c "import sys;open('$OUTDIR/try.bin','rb').read().decode('utf-8')" 2>/dev/null; then
      echo "  *** KEY FOUND: [$KEY]  ($CIPH/$MD)"
      echo "  --- DECRYPTED ---"; cat "$OUTDIR/try.bin" | head -c 1600; echo
      printf '%s' "$KEY" > "$OUTDIR/KEY.txt"; cp "$OUTDIR/try.bin" "$OUTDIR/decrypted.json"
      FOUND="$KEY"; break 3
    fi
  done; done
done < "$OUTDIR/keycands.txt"
echo ""
if [ -z "$FOUND" ]; then
  echo "  No clean decrypt. Read PHASE A context above — the passphrase source is"
  echo "  shown there (literal / __NEXT_DATA__ / assembled). Paste those lines and"
  echo "  I'll pin the exact key + derivation."
else
  echo "  PROTOCOL CRACKED with key [$FOUND]. decrypted.json saved (local only)."
fi
echo ""
echo "Evidence: $OUTDIR (NOT committed)"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
