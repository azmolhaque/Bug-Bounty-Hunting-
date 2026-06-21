# Pi Runbook — Mandiant Advantage Session 1
# Goal: Fingerprint cluster, map auth surface, identify unauthenticated endpoints
# Date: 2026-06-21

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /home/pi/hunt

# ============================================================
# PHASE A — DNS + HTTP fingerprint of all in-scope hosts
# ============================================================

for H in advantage.mandiant.com api.advantage.mandiant.com advantage-api.mandiant.com md.mandiant.com md-us.mandiant.com msvportal.mandiant.com plextrac.mandiant.com validation.mandiant.com; do
  echo "=== $H ==="
  curl -sk --max-time 10 -D - "https://$H/" -o /dev/null -w "HTTP %{http_code} | size=%{size_download} | redirect=%{redirect_url}\n"
done

# ============================================================
# PHASE B — Headers fingerprint on live hosts
# ============================================================
# Run this after Phase A — fill in the live hosts (those that returned non-000)

# advantage.mandiant.com
curl -sv --max-time 10 "https://advantage.mandiant.com/" 2>&1 | grep -E "^[<>*]" | head -30

# api.advantage.mandiant.com — key target
curl -sv --max-time 10 "https://api.advantage.mandiant.com/" 2>&1 | grep -E "^[<>*]" | head -30

# ============================================================
# PHASE C — Pre-auth surface probe (api.advantage.mandiant.com)
# ============================================================
# Test common API paths without auth token first

for URLPATH in / /v1 /v1/ /v2 /v3 /api /api/v1 /health /healthz /status /metrics /openapi.json /swagger.json /.well-known/openid-configuration /v1/users /v1/indicators /v1/reports /v1/organizations /v1/actors /v1/alerts /v1/search /v1/ping; do
  echo -n "$URLPATH: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://api.advantage.mandiant.com$URLPATH"
done

# ============================================================
# PHASE D — advantage.mandiant.com SPA check + OIDC discovery
# ============================================================

# Check if catch-all (SPA) or real route table
curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://advantage.mandiant.com/this-path-does-not-exist-abc123"
# If same size as / → SPA catch-all; if 404 → real routes

# OIDC discovery
curl -sk --max-time 10 "https://advantage.mandiant.com/.well-known/openid-configuration" | python3 -m json.tool 2>/dev/null || echo "(not JSON)"

# CSP headers
curl -sk --max-time 10 -I "https://advantage.mandiant.com/" 2>&1 | grep -i "content-security-policy"

# ============================================================
# PHASE E — validation.mandiant.com (SSRF surface)
# ============================================================

# Fingerprint
curl -sv --max-time 10 "https://validation.mandiant.com/" 2>&1 | grep -E "^[<>*]" | head -25

# Test common paths — validation platform may have exposed test config
for URLPATH in / /api /api/v1 /health /api/v1/simulations /api/v1/results /api/v1/targets /swagger /openapi.json; do
  echo -n "$URLPATH: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://validation.mandiant.com$URLPATH"
done

# ============================================================
# PHASE F — Dev/staging discovery (*.advantage.mandiant.com)
# ============================================================
# VERIFY SCOPE FIRST: only test if bughunters.google.com confirms *.advantage.mandiant.com in scope

for SUBDOMAIN in asm-api-dev asm-api-staging asm-dev asm-staging asm-gcp api-dev api-staging dev staging featflgs-ath featflgs-evt featflgs-sdk featflgs-str featflgs-tel; do
  echo -n "$SUBDOMAIN.advantage.mandiant.com: "
  IP=$(python3 -c "import socket; print(socket.gethostbyname('$SUBDOMAIN.advantage.mandiant.com'))" 2>/dev/null || echo "NXDOMAIN")
  if [ "$IP" != "NXDOMAIN" ]; then
    HTTP=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" "https://$SUBDOMAIN.advantage.mandiant.com/")
    echo "$IP → HTTP $HTTP"
  else
    echo "NXDOMAIN"
  fi
done

# ============================================================
# PHASE G — plextrac.mandiant.com (separate pentest platform)
# ============================================================

curl -sv --max-time 10 "https://plextrac.mandiant.com/" 2>&1 | grep -E "^[<>*]" | head -25

for URLPATH in / /health /api /api/v1 /api/v2 /.well-known/openid-configuration /login /auth/login /signup; do
  echo -n "$URLPATH: "
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | %{redirect_url}\n" "https://plextrac.mandiant.com$URLPATH"
done

# ============================================================
# DECISION GATE (after Phase A-G):
# If any host returns 200/401 with non-trivial body → pursue
# If all are SPA catch-alls or IAP-gated → CLOSE and PIVOT
# If api.advantage.mandiant.com has 401 paths → register free account, get token, test IDOR
# ============================================================
