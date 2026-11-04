# Pi Runbook — Looker Cluster Session 1
# Goal: Fingerprint TIER0 VPN cluster + TIER1 SaaS hosts
# Date: 2026-06-21

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /home/pi/hunt

# ============================================================
# PHASE A — DNS + HTTP fingerprint of all TIER0 hosts
# ============================================================

for H in de.looker.com keybox.looker.com rampart.looker.com pbvpn.looker.com gw2-pbvpn.looker.com; do
  echo "=== $H ==="
  curl -sv --max-time 12 "https://$H/" 2>&1 | grep -E "^[<>*< ]" | head -20
  echo ""
done

# ============================================================
# PHASE B — Path probe on keybox + rampart (key management candidates)
# ============================================================

for H in keybox.looker.com rampart.looker.com; do
  echo "=== PATH PROBE: $H ==="
  for URLPATH in / /health /healthz /status /api /api/v1 /api/v2 /keys /key /keybox /config /admin /login /.well-known/openid-configuration /metrics /v1 /v2; do
    echo -n "  $URLPATH: "
    curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | %{redirect_url}\n" "https://$H$URLPATH"
  done
done

# ============================================================
# PHASE C — de.looker.com deep probe (EU Looker instance)
# ============================================================

# Headers fingerprint first
curl -sv --max-time 12 "https://de.looker.com/" 2>&1 | grep -E "^[<> ]" | head -30

# SPA catch-all test
curl -sk --max-time 10 -o /dev/null -w "/ → HTTP %{http_code} | %{size_download}B\n" "https://de.looker.com/"
curl -sk --max-time 10 -o /dev/null -w "/this-does-not-exist → HTTP %{http_code} | %{size_download}B\n" "https://de.looker.com/this-path-does-not-exist-abc123xyz"

# If not catch-all, probe real paths
for URLPATH in /login /login/login /api/3.1/ping /api/4.0/ping /api/3.1/user /api/4.0/me /api/3.1/all_roles /healthz /.well-known/openid-configuration /oauth/token; do
  echo -n "  $URLPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B\n" "https://de.looker.com$URLPATH"
done

# CORS probe on Looker API
curl -sk --max-time 8 -H "Origin: https://attacker.com" -I "https://de.looker.com/api/4.0/me" 2>&1 | grep -i "access-control"

# ============================================================
# PHASE D — pbvpn.looker.com (browser VPN gateway)
# ============================================================

curl -sv --max-time 12 "https://pbvpn.looker.com/" 2>&1 | grep -E "^[<> ]" | head -20

for URLPATH in / /health /api /connect /tunnel /pac /proxy.pac /wpad.dat /status; do
  echo -n "  $URLPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | %{redirect_url}\n" "https://pbvpn.looker.com$URLPATH"
done

# ============================================================
# PHASE E — TIER1 Looker SaaS hosts
# ============================================================

for H in corp.looker.com instancemanagerui.looker.com lk.looker.com looker.com; do
  echo "=== $H ==="
  curl -sk --max-time 10 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | %{redirect_url}\n" "https://$H/"
done

# instancemanagerui — highest value: instance management console
curl -sv --max-time 12 "https://instancemanagerui.looker.com/" 2>&1 | grep -E "^[<> ]" | head -20
for URLPATH in / /health /api /api/v1 /admin /login /instances; do
  echo -n "  instancemanagerui $URLPATH: "
  curl -sk --max-time 8 -o /dev/null -w "HTTP %{http_code} | %{size_download}B | %{redirect_url}\n" "https://instancemanagerui.looker.com$URLPATH"
done

# ============================================================
# DECISION GATE:
# - de.looker.com: if Looker login page → try /api/3.1/ping + /api/4.0/me (API usually 401 not 302)
# - keybox/rampart: if any path returns 200 with non-trivial body → HIGH PRIORITY
# - pbvpn: if any path returns non-redirect → investigate; VPN config endpoints are goldmines
# - instancemanagerui: if 200 → instance manager = admin-class, IDOR target
# ============================================================
