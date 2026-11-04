# Pi Runbook — Area 120 Session 1
# Goal: Fingerprint all live Area 120 products, identify auth/API surface
# Date: 2026-06-21

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /home/pi/hunt

# ============================================================
# PHASE A — Full cluster fingerprint
# ============================================================

for H in orionwifi.area120.com signals.area120.com threadit.area120.com threadit.app; do
  echo "=== $H ==="
  curl -sv --max-time 12 "https://$H/" 2>&1 | grep -E "^[<>*]" | head -25
  echo ""
done

# ============================================================
# PHASE B — SPA catch-all vs real route table
# ============================================================

for H in orionwifi.area120.com signals.area120.com threadit.area120.com threadit.app; do
  echo "=== $H catch-all test ==="
  ROOT=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}|%{size_download}" "https://$H/")
  FAKE=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}|%{size_download}" "https://$H/this-path-does-not-exist-abc123xyz")
  echo "  / → $ROOT"
  echo "  /fake → $FAKE"
  if [ "$(echo $ROOT | cut -d'|' -f2)" = "$(echo $FAKE | cut -d'|' -f2)" ]; then
    echo "  VERDICT: SPA catch-all (same size)"
  else
    echo "  VERDICT: REAL ROUTE TABLE (different sizes) — PURSUE"
  fi
done

# ============================================================
# PHASE C — OIDC + auth surface discovery
# ============================================================

for H in orionwifi.area120.com signals.area120.com threadit.area120.com threadit.app; do
  echo "=== OIDC: $H ==="
  curl -sk --max-time 8 "https://$H/.well-known/openid-configuration" | python3 -m json.tool 2>/dev/null | head -20 || echo "(not JSON or 404)"
  
  echo "  /login: $(curl -sk --max-time 8 -o /dev/null -w "%{http_code}|%{redirect_url}" "https://$H/login")"
  echo "  /api/v1: $(curl -sk --max-time 8 -o /dev/null -w "%{http_code}|%{size_download}B" "https://$H/api/v1")"
  echo "  /api/v2: $(curl -sk --max-time 8 -o /dev/null -w "%{http_code}|%{size_download}B" "https://$H/api/v2")"
  echo ""
done

# ============================================================
# PHASE D — Orion WiFi deep probe (highest value — payment + venue multi-tenant)
# ============================================================

echo "=== ORION WIFI DEEP PROBE ==="

# Orion WiFi allows venues to sell WiFi access and users to buy it
# Check if API endpoints exist without auth
for URLPATH in / /api /api/v1 /api/v2 /health /healthz /venues /venues/1 /users /users/1 /sessions /sessions/1 /payments /stripe /webhook /api/v1/venues /api/v1/users /api/v1/sessions /api/v1/connections /robots.txt /.well-known/openid-configuration; do
  echo -n "  $URLPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | %{redirect_url}\n" "https://orionwifi.area120.com$URLPATH"
done

# CORS check
curl -sk --max-time 8 -H "Origin: https://attacker.com" -I "https://orionwifi.area120.com/api/v1/users" 2>&1 | grep -i "access-control"

# ============================================================
# PHASE E — Threadit deep probe (video messaging — user data)
# ============================================================

echo "=== THREADIT DEEP PROBE ==="

for URLPATH in / /health /api /api/v1 /api/v2 /graphql /threads /threads/1 /users /users/1 /videos /videos/1 /auth /login /signup /api/v1/threads /api/v1/users /robots.txt; do
  echo -n "  $URLPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | %{redirect_url}\n" "https://threadit.area120.com$URLPATH"
done

# ============================================================
# PHASE F — Signals deep probe (analytics data)
# ============================================================

echo "=== SIGNALS DEEP PROBE ==="

# signals.area120.com is on Akamai — different infra from other Area 120 hosts
curl -sv --max-time 12 "https://signals.area120.com/" 2>&1 | grep -E "^[<> ]" | head -25

for URLPATH in / /health /api /api/v1 /dashboard /organizations /projects /users /data /events /robots.txt; do
  echo -n "  $URLPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | %{redirect_url}\n" "https://signals.area120.com$URLPATH"
done

# ============================================================
# DECISION GATE:
# - If any endpoint returns 200 with non-trivial JSON (not SPA HTML) → pursue auth + IDOR
# - If all are SPA catch-alls or auth-gated → register accounts and test authenticated IDOR
# - If Orion WiFi has venue/user/session endpoints returning 401 (not 403) → register account
# - Orion WiFi account registration: test at orionwifi.area120.com (Google Sign-In)
# ============================================================
