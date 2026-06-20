#!/bin/bash
# Direct test of OAuth /oauth/authorize redirect_uri validation on login.apigee.com
# This is the DEFINITIVE test — bypasses the sign_up form complexity entirely
# Run on Pi.
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L001-authorize-redirect-uri.txt"

echo "=== APG-L001 Direct OAuth /oauth/authorize redirect_uri test ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo | tee -a "$OUT"

# KEY: login.apigee.com/oauth/authorize is the OIDC discovery authorization_endpoint
# Test whether it accepts arbitrary redirect_uri for client_id=unifiedui

# ---- Test A: external redirect_uri (no -L so we see the raw redirect/error) ----
echo "=== A: external redirect_uri (no follow) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 15 \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
  -D /tmp/auth_ext_headers.txt \
  -o /tmp/auth_ext_body.txt \
  "https://login.apigee.com/oauth/authorize?response_type=code&client_id=unifiedui&redirect_uri=https%3A%2F%2Fexample.com&state=teststate123"
echo "--- Headers ---" | tee -a "$OUT"
/usr/bin/cat /tmp/auth_ext_headers.txt | tee -a "$OUT"
echo "--- Body (first 600 chars) ---" | tee -a "$OUT"
/usr/bin/head -c 600 /tmp/auth_ext_body.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# ---- Test B: registered redirect_uri (baseline) ----
echo "=== B: registered redirect_uri (no follow) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 15 \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
  -D /tmp/auth_reg_headers.txt \
  -o /tmp/auth_reg_body.txt \
  "https://login.apigee.com/oauth/authorize?response_type=code&client_id=unifiedui&redirect_uri=https%3A%2F%2Fconsole.apigee.com%2FoauthCallback&state=teststate123"
echo "--- Headers ---" | tee -a "$OUT"
/usr/bin/cat /tmp/auth_reg_headers.txt | tee -a "$OUT"
echo "--- Body (first 600 chars) ---" | tee -a "$OUT"
/usr/bin/head -c 600 /tmp/auth_reg_body.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# ---- Test C: no client_id (baseline error) ----
echo "=== C: no client_id (baseline error response) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 15 \
  -D /tmp/auth_noid_headers.txt \
  -o /tmp/auth_noid_body.txt \
  "https://login.apigee.com/oauth/authorize?response_type=code&redirect_uri=https%3A%2F%2Fexample.com"
echo "--- Headers ---" | tee -a "$OUT"
/usr/bin/cat /tmp/auth_noid_headers.txt | tee -a "$OUT"
echo "--- Body (first 400 chars) ---" | tee -a "$OUT"
/usr/bin/head -c 400 /tmp/auth_noid_body.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# ---- Test D: invalid client_id (should error, not redirect) ----
echo "=== D: bogus client_id (should error without redirect) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 15 \
  -D /tmp/auth_bogus_headers.txt \
  -o /tmp/auth_bogus_body.txt \
  "https://login.apigee.com/oauth/authorize?response_type=code&client_id=bogusclientid99&redirect_uri=https%3A%2F%2Fexample.com"
echo "--- Headers ---" | tee -a "$OUT"
/usr/bin/cat /tmp/auth_bogus_headers.txt | tee -a "$OUT"
echo "--- Body (first 400 chars) ---" | tee -a "$OUT"
/usr/bin/head -c 400 /tmp/auth_bogus_body.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# ---- Summary ----
echo "=== SUMMARY ===" | tee -a "$OUT"
echo "Test A (external redirect_uri) Location:" | tee -a "$OUT"
/usr/bin/grep -i "^Location:" /tmp/auth_ext_headers.txt | tee -a "$OUT"
echo "Test B (registered redirect_uri) Location:" | tee -a "$OUT"
/usr/bin/grep -i "^Location:" /tmp/auth_reg_headers.txt | tee -a "$OUT"
echo | tee -a "$OUT"

# Interpretation
LOC_EXT=$(/usr/bin/grep -i "^Location:" /tmp/auth_ext_headers.txt | /usr/bin/head -1)
LOC_REG=$(/usr/bin/grep -i "^Location:" /tmp/auth_reg_headers.txt | /usr/bin/head -1)

echo "Interpretation:" | tee -a "$OUT"
if echo "$LOC_EXT" | /usr/bin/grep -qi "example.com"; then
  echo "  *** VULNERABLE: /oauth/authorize redirected to example.com — redirect_uri NOT validated!" | tee -a "$OUT"
  echo "  *** APG-L001 CONFIRMED. Write Google VRP report immediately." | tee -a "$OUT"
elif echo "$LOC_EXT" | /usr/bin/grep -qi "login"; then
  echo "  -> Test A redirected to login page (redirect_uri may be accepted, auth required)" | tee -a "$OUT"
  if [ "$(echo "$LOC_EXT" | /usr/bin/grep -oE 'https?://[^ ]+' | /usr/bin/head -1)" = "$(echo "$LOC_REG" | /usr/bin/grep -oE 'https?://[^ ]+' | /usr/bin/head -1)" ]; then
    echo "  -> Both redirect to same login URL — redirect_uri stored in session, NOT validated pre-auth" | tee -a "$OUT"
    echo "  -> PURSUE: after login, does callback go to example.com or console.apigee.com?" | tee -a "$OUT"
  fi
elif echo "$LOC_EXT" | /usr/bin/grep -qi "error\|invalid"; then
  echo "  -> Test A redirected to error page — redirect_uri appears validated" | tee -a "$OUT"
  echo "  -> DROP APG-L001" | tee -a "$OUT"
else
  echo "  -> No Location header / unexpected response — inspect body" | tee -a "$OUT"
fi

echo
echo "Done. Results: $OUT"
