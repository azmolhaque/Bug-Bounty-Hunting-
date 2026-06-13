#!/usr/bin/env bash
# Wiz no-credentials probe — targets that don't need a trial account
# Covers: tracking.wiz.io, team.wiz.io, RDE webhooks, a2a.test.wiz.io
# Run on Pi: bash scripts/wiz-no-cred-probe.sh 2>&1 | tee ~/wiz-no-cred-output.txt

set -euo pipefail
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
OUT="$HOME/bug-bounty-hunting-/results/wiz.io/evidence/no-cred-probe"
mkdir -p "$OUT"

c() { curl -sk --connect-timeout 10 -A "$UA" "$@"; }
ci() { curl -sI --connect-timeout 10 -A "$UA" "$@"; }

echo "══════════════════════════════════════"
echo "1. tracking.wiz.io"
echo "══════════════════════════════════════"
ci "https://tracking.wiz.io/" | tee "$OUT/tracking-headers.txt" | head -20
echo "--- body ---"
c "https://tracking.wiz.io/" | head -c 500

echo ""
echo "=== Path probe ==="
for p in /health /api /v1 /status /pixel /t /track /collect /events /ping /metrics; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 -A "$UA" "https://tracking.wiz.io${p}")
  echo "${code}  ${p}"
done

echo ""
echo "=== CORS check ==="
curl -sk --connect-timeout 8 -A "$UA" \
  -H "Origin: https://evil.com" -I "https://tracking.wiz.io/" | grep -i "access-control\|cors"

echo ""
echo "══════════════════════════════════════"
echo "2. team.wiz.io"
echo "══════════════════════════════════════"
ci "https://team.wiz.io/" | head -20
echo "--- body ---"
c "https://team.wiz.io/" | head -c 500

echo ""
echo "=== Path probe ==="
for p in /health /api /v1 /users /members /teams /admin /graphql /invite; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 -A "$UA" "https://team.wiz.io${p}")
  echo "${code}  ${p}"
done

echo ""
echo "══════════════════════════════════════"
echo "3. RDE webhook endpoints (developer environments)"
echo "══════════════════════════════════════"
for host in \
  "webhooks.guy.goldenberg.rde.wiz.io" \
  "webhooks.roey.dror-us.rde.wiz.io" \
  "webhooks.roy5.rde.wiz.io" \
  "webhooks.cfir.rde.wiz.io" \
  "webhooks.or.bin.rde.wiz.io" \
  "webhooks.on-demand-1.rde.wiz.io" \
  "webhooks.on-demand-5.rde.wiz.io" \
  "webhooks.bootstrap-rde-001.rde.wiz.io"; do
  echo "--- $host ---"
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" "https://${host}/")
  body=$(c "https://${host}/" | head -c 150)
  echo "${code}  ${body}"
done

echo ""
echo "══════════════════════════════════════"
echo "4. a2a.eu1.test.wiz.io (no WAF, direct ELB)"
echo "══════════════════════════════════════"
# Attempt specific a2a (agent-to-agent) paths that don't need auth tokens
for p in \
  "/" "/health" "/readyz" "/livez" "/ping" \
  "/api" "/v1" "/graphql" \
  "/a2a" "/agent" "/tasks" "/.well-known/agent.json" \
  "/openapi.json" "/swagger.json" "/docs"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 8 -A "$UA" "https://a2a.eu1.test.wiz.io${p}")
  body=$(c "https://a2a.eu1.test.wiz.io${p}" | head -c 100)
  echo "${code}  ${p}  ${body:0:60}"
done

echo ""
echo "=== a2a agent manifest (Google A2A protocol) ==="
c "https://a2a.eu1.test.wiz.io/.well-known/agent.json" | python3 -m json.tool 2>/dev/null | head -30

echo ""
echo "══════════════════════════════════════"
echo "5. Additional Wiz subdomains (untested)"
echo "══════════════════════════════════════"
for host in \
  "releases.wiz.io" \
  "changelog.wiz.io" \
  "status.wiz.io" \
  "trust.wiz.io" \
  "cdn.wiz.io" \
  "assets.wiz.io" \
  "images.wiz.io" \
  "media.wiz.io" \
  "connect.wiz.io" \
  "portal.wiz.io" \
  "marketplace.wiz.io" \
  "integrations.wiz.io" \
  "partner.wiz.io" \
  "partners.wiz.io"; do
  code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 -A "$UA" "https://${host}/")
  loc=$(curl -sI --connect-timeout 6 -A "$UA" "https://${host}/" | grep -i "^location:" | head -1)
  echo "${code}  ${host}  ${loc}"
done

echo ""
echo "══════════════════════════════════════"
echo "6. Looker unauthenticated endpoints"
echo "══════════════════════════════════════"
for host in "trial.looker.com" "test.looker.com"; do
  echo "--- ${host} ---"
  # Version info
  c "https://${host}/api/4.0/versions" | python3 -m json.tool 2>/dev/null | head -10
  # Error message info disclosure on various paths
  for ep in \
    "/api/4.0/session" \
    "/api/4.0/user" \
    "/api/4.0/config" \
    "/api/4.0/whitelabel_configuration" \
    "/api/4.0/internal_help_resources" \
    "/api/4.0/datagroups" \
    "/api/4.0/scheduled_plans" \
    "/api/4.0/alerts"; do
    resp=$(c "https://${host}${ep}" | head -c 200)
    code=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 6 "https://${host}${ep}")
    echo "  ${code}  ${ep}: ${resp:0:80}"
  done
  echo ""
done

echo ""
echo "=== Looker embed endpoint (sometimes accessible) ==="
c "https://trial.looker.com/api/4.0/embed/token_url/me" | head -c 200

echo ""
echo "Done. Evidence in $OUT/"
