#!/bin/bash
# Verify whether POST /apigee_create_account_request validates redirect_uri
# Run on Pi. Results go to results/apigee/03-candidates/APG-L001-post-responses.txt
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L001-post-responses.txt"

echo "=== APG-L001 Verification: POST /apigee_create_account_request ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo | tee -a "$OUT"

# ---- Test 1: External (attacker) redirect_uri ----
echo "=== TEST 1: redirect_uri=https://example.com (external/attacker) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 20 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
  -d "firstName=Test&lastName=Hunter&email=notrealaccount999999%40example.invalid&password=TestPass123%21&company=TestCo&companySize=1-9&country=United+States&tosAcceptance=true&client_id=unifiedui&redirect_uri=https%3A%2F%2Fexample.com&journey=0" \
  -w "\nHTTP_%{http_code}" \
  -o /tmp/apg_post_external.txt \
  "https://login.apigee.com/apigee_create_account_request"

echo "HTTP status: $(tail -1 /tmp/apg_post_external.txt)" | tee -a "$OUT"
echo "Body size: $(wc -c < /tmp/apg_post_external.txt) bytes" | tee -a "$OUT"
echo "--- Key indicators ---" | tee -a "$OUT"
/usr/bin/grep -oiE "(error|redirect|invalid|success|check.your.email|account.created|bad.request|not.allowed|invalid_redirect)[^<\"]{0,120}" \
  /tmp/apg_post_external.txt | /usr/bin/head -10 | tee -a "$OUT"
echo "--- First 500 chars ---" | tee -a "$OUT"
/usr/bin/head -c 500 /tmp/apg_post_external.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# ---- Test 2: Registered redirect_uri (baseline) ----
echo "=== TEST 2: redirect_uri=https://console.apigee.com/oauthCallback (registered/baseline) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 20 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
  -d "firstName=Test&lastName=Hunter&email=notrealaccount888888%40example.invalid&password=TestPass123%21&company=TestCo&companySize=1-9&country=United+States&tosAcceptance=true&client_id=unifiedui&redirect_uri=https%3A%2F%2Fconsole.apigee.com%2FoauthCallback&journey=0" \
  -w "\nHTTP_%{http_code}" \
  -o /tmp/apg_post_registered.txt \
  "https://login.apigee.com/apigee_create_account_request"

echo "HTTP status: $(tail -1 /tmp/apg_post_registered.txt)" | tee -a "$OUT"
echo "Body size: $(wc -c < /tmp/apg_post_registered.txt) bytes" | tee -a "$OUT"
echo "--- Key indicators ---" | tee -a "$OUT"
/usr/bin/grep -oiE "(error|redirect|invalid|success|check.your.email|account.created|bad.request|not.allowed|invalid_redirect)[^<\"]{0,120}" \
  /tmp/apg_post_registered.txt | /usr/bin/head -10 | tee -a "$OUT"
echo "--- First 500 chars ---" | tee -a "$OUT"
/usr/bin/head -c 500 /tmp/apg_post_registered.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# ---- Comparison ----
echo "=== COMPARISON ===" | tee -a "$OUT"
SIZE_EXT=$(wc -c < /tmp/apg_post_external.txt)
SIZE_REG=$(wc -c < /tmp/apg_post_registered.txt)
echo "External size:   $SIZE_EXT bytes" | tee -a "$OUT"
echo "Registered size: $SIZE_REG bytes" | tee -a "$OUT"
DIFF=$((SIZE_EXT - SIZE_REG))
[ $DIFF -lt 0 ] && DIFF=$((-DIFF))
echo "Size difference: $DIFF bytes" | tee -a "$OUT"

if [ "$DIFF" -lt 100 ]; then
  echo "VERDICT: Responses are similar in size (<100 byte diff)" | tee -a "$OUT"
  echo "  -> redirect_uri may NOT be validated at POST time" | tee -a "$OUT"
  echo "  -> PURSUE: check for actual redirect/Location header difference" | tee -a "$OUT"
else
  echo "VERDICT: Responses differ significantly ($DIFF bytes)" | tee -a "$OUT"
  echo "  -> redirect_uri IS likely validated; inspect error content" | tee -a "$OUT"
fi

# ---- Check actual redirect headers with -v ----
echo | tee -a "$OUT"
echo "=== TEST 3: redirect_uri=https://example.com with -v (capture Location header) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 20 \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
  -d "firstName=Test&lastName=Hunter&email=notrealaccount777777%40example.invalid&password=TestPass123%21&company=TestCo&companySize=1-9&country=United+States&tosAcceptance=true&client_id=unifiedui&redirect_uri=https%3A%2F%2Fexample.com&journey=0" \
  -D /tmp/apg_post_ext_headers.txt \
  -o /tmp/apg_post_ext_body.txt \
  "https://login.apigee.com/apigee_create_account_request"
echo "--- Response headers ---" | tee -a "$OUT"
/usr/bin/cat /tmp/apg_post_ext_headers.txt | tee -a "$OUT"

echo | tee -a "$OUT"
echo "Done. Results: $OUT"
echo
echo "Next: commit and push results/"
