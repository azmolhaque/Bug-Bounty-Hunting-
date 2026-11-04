#!/usr/bin/env bash
# unicef-hunt.sh — Phase 3+4 vulnerability discovery for UNICEF (unicef.org)
#
# Requires: unicef-recon.sh has been run first (results/unicef.org/02-surface/ populated)
#
# Bug classes targeted (in order of likely yield):
#   1. Subdomain takeover verification (confirm claimable CNAMEs)
#   2. Drupal JSON:API unauthenticated data exposure
#   3. Admin panel / sensitive path discovery (ffuf)
#   4. Nuclei — Drupal CVEs + exposures + generic web
#   5. OOB SSRF probing on URL-intake forms
#   6. API endpoint auth testing
#
# Run: bash scripts/unicef-hunt.sh [--target HOST] [--class CLASS]
#       CLASS: takeover | jsonapi | admin | nuclei | ssrf | api | all (default: all)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

export SCOPE_FILE="$ROOT_DIR/config/scope-unicef.yaml"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[unicef-hunt]${NC} $*"; }
warn() { echo -e "${YELLOW}[unicef-hunt]${NC} $*"; }
err()  { echo -e "${RED}[unicef-hunt]${NC} $*" >&2; }
info() { echo -e "${CYAN}[unicef-hunt]${NC} $*"; }

TARGET_HOST="${TARGET_HOST:-}"
RUN_CLASS="${1:-all}"

STAMP=$(date -u +%Y%m%d-%H%M)
OUT="$ROOT_DIR/results/unicef.org"
EVIDENCE="$OUT/evidence/${STAMP}"
mkdir -p "$EVIDENCE" "$OUT/03-candidates" "$OUT/findings"

LOG="$EVIDENCE/hunt.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== UNICEF HUNT — $STAMP ==="
echo "Class: $RUN_CLASS | Target: ${TARGET_HOST:-all-live}"
echo ""

have() { command -v "$1" >/dev/null 2>&1; }

LIVE="$OUT/02-surface/live.txt"
DRUPAL="$OUT/02-surface/drupal-instances.txt"
JSONAPI_LIVE="$OUT/02-surface/drupal-jsonapi-live.txt"
TAKEOVER="$OUT/02-surface/takeover-candidates.txt"
CNAMES="$OUT/01-assets/cnames.txt"

if [ ! -f "$LIVE" ]; then
  err "Live host list not found at $LIVE — run unicef-recon.sh first"
  exit 1
fi

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
RATE=20
OOB="${OOB_URL:-}"   # set OOB_URL=https://<interactsh-id>.oast.pro for SSRF testing

touch "$OUT/03-candidates/candidates.jsonl"

emit_candidate() {
  local class="$1" host="$2" endpoint="$3" evidence="$4" confidence="$5" impact="$6"
  local ts; ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf '{"ts":"%s","class":"%s","host":"%s","endpoint":"%s","confidence":"%s","impact":"%s","evidence":%s}\n' \
    "$ts" "$class" "$host" "$endpoint" "$confidence" "$impact" "\"${evidence}\"" \
    >> "$OUT/03-candidates/candidates.jsonl"
  echo ""
  echo "★ CANDIDATE [$class] [$confidence] $host$endpoint"
  echo "  Impact: $impact"
  echo "  Evidence: $evidence"
  echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 1: Subdomain takeover verification
# ─────────────────────────────────────────────────────────────────────────────
run_takeover() {
  log "=== CLASS 1: Subdomain Takeover Verification ==="

  if [ ! -s "$TAKEOVER" ]; then
    log "  No takeover candidates from recon — scanning CNAMEs now..."
    [ -s "$CNAMES" ] || { warn "cnames.txt empty — run recon first"; return; }
  fi

  # Takeover fingerprints: service → expected "not found" body pattern
  declare -A FINGERPRINTS
  FINGERPRINTS["netlify"]="Not Found|page not found|netlify"
  FINGERPRINTS["github.io"]="There isn't a GitHub Pages site here|404"
  FINGERPRINTS["azurewebsites.net"]="404 Web Site not found|The web app you have attempted"
  FINGERPRINTS["cloudapp.azure"]="404 Not Found"
  FINGERPRINTS["herokudns.com"]="No such app|herokucdn.com/error-pages/no-such-app"
  FINGERPRINTS["herokuapp.com"]="No such app"
  FINGERPRINTS["shopify.com"]="Sorry, this shop is currently unavailable"
  FINGERPRINTS["ghost.io"]="The thing you were looking for is no longer here|404"
  FINGERPRINTS["surge.sh"]="project not found"
  FINGERPRINTS["webflow.io"]="The page you are looking for doesn't exist"
  FINGERPRINTS["gitbook.io"]="404 - Not found|Gitbook - Page Not found"
  FINGERPRINTS["fastly.net"]="Fastly error: unknown domain"
  FINGERPRINTS["s3.amazonaws.com"]="NoSuchBucket|The specified bucket does not exist"
  FINGERPRINTS["vercel.app"]="The deployment could not be found"
  FINGERPRINTS["render.com"]="Service not found"
  FINGERPRINTS["fly.dev"]="404 fly.dev"

  CNAME_SRC="${TAKEOVER}"
  [ ! -s "$TAKEOVER" ] && CNAME_SRC="$CNAMES"

  while IFS= read -r LINE; do
    [ -z "$LINE" ] && continue
    # dnsx output format: "sub.unicef.org CNAME target.netlify.app"
    # or just "sub.unicef.org [CNAME target]"
    HOST=$(echo "$LINE" | awk '{print $1}')
    CNAME_TARGET=$(echo "$LINE" | grep -oE '[A-Za-z0-9._-]+\.(netlify|github\.io|azurewebsites|heroku|shopify|ghost\.io|surge\.sh|webflow|gitbook|fastly|amazonaws|vercel|render\.com|fly\.dev)[A-Za-z0-9._-]*' | head -1)

    [ -z "$HOST" ] && continue

    # Scope gate
    SCOPE_CHECK="$("$SCRIPT_DIR/scope-check.sh" "$HOST" 2>&1 || true)"
    case "$SCOPE_CHECK" in IN-SCOPE*) ;; *) continue ;; esac

    # Fetch the subdomain and look for takeover fingerprint
    RESP=$(curl -sk --max-time 15 \
      -H "User-Agent: ${UA}" \
      -w "\n__CODE__%{http_code}" \
      "https://${HOST}/" 2>/dev/null)
    CODE="${RESP##*__CODE__}"
    BODY="${RESP%__CODE__*}"

    # Try HTTP if HTTPS fails
    if [ "$CODE" = "000" ]; then
      RESP=$(curl -sk --max-time 10 \
        -H "User-Agent: ${UA}" \
        -w "\n__CODE__%{http_code}" \
        "http://${HOST}/" 2>/dev/null)
      CODE="${RESP##*__CODE__}"
      BODY="${RESP%__CODE__*}"
    fi

    # Check each fingerprint
    MATCHED=false
    for SERVICE in "${!FINGERPRINTS[@]}"; do
      PATTERN="${FINGERPRINTS[$SERVICE]}"
      if printf '%s' "$CNAME_TARGET $LINE" | grep -qi "$SERVICE"; then
        if printf '%s' "$BODY" | grep -qiE "$PATTERN"; then
          echo "  *** TAKEOVER CONFIRMED: $HOST → $CNAME_TARGET"
          echo "  Code: $CODE | Fingerprint: $PATTERN matched"
          emit_candidate "subdomain-takeover" "$HOST" "/" \
            "CNAME to $CNAME_TARGET; body matches takeover fingerprint: $PATTERN" \
            "HIGH" "Attacker can claim $CNAME_TARGET and serve content from $HOST"
          MATCHED=true
          break
        fi
      fi
    done

    if ! $MATCHED && [ "$CODE" != "000" ]; then
      echo "  [${CODE}] ${HOST} — ${CNAME_TARGET:-unknown CNAME} (no fingerprint match)"
    fi

  done < "$CNAME_SRC"

  log "Takeover scan complete. Candidates: $(grep -c 'subdomain-takeover' "$OUT/03-candidates/candidates.jsonl" 2>/dev/null || echo 0)"
}

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 2: Drupal JSON:API unauthenticated data exposure
# ─────────────────────────────────────────────────────────────────────────────
run_jsonapi() {
  log "=== CLASS 2: Drupal JSON:API Unauthenticated Data Exposure ==="

  TARGETS_FILE="${JSONAPI_LIVE}"
  if [ ! -s "$TARGETS_FILE" ]; then
    warn "No JSON:API live targets — using all Drupal instances"
    TARGETS_FILE="$DRUPAL"
  fi
  [ -s "$TARGETS_FILE" ] || { warn "No Drupal instances found — run recon first"; return; }

  # Endpoints to probe — ordered by impact
  JSONAPI_ENDPOINTS=(
    "/jsonapi/user/user"           # user list: emails, UIDs, roles → HIGH if staff PII exposed
    "/jsonapi/node/article"        # articles (may include drafts/embargoed)
    "/jsonapi/node/page"           # pages
    "/jsonapi/node/news"           # news items
    "/jsonapi/node/event"          # events
    "/jsonapi/file/file"           # uploaded files → path disclosure
    "/jsonapi/taxonomy_term/tags"  # taxonomy
    "/jsonapi/menu_link_content/menu_link_content"  # internal menu structure
    "/jsonapi"                     # schema index (reveals all entity types)
    "/api/jsonrpc"                 # Drupal JSON-RPC if enabled
    "/rest/session/token"          # session token (should require auth)
    "/user/login?_format=json"     # login endpoint info
    "/user/register?_format=json"  # registration endpoint info
  )

  while IFS= read -r BASE_URL; do
    [ -z "$BASE_URL" ] && continue
    BASE="${BASE_URL%/}"

    # Scope check
    HOST="${BASE#*://}"; HOST="${HOST%%/*}"
    SCOPE_CHECK="$("$SCRIPT_DIR/scope-check.sh" "$HOST" 2>&1 || true)"
    case "$SCOPE_CHECK" in IN-SCOPE*) ;; *) continue ;; esac

    echo ""
    echo "  Target: $BASE"

    for EP in "${JSONAPI_ENDPOINTS[@]}"; do
      RESP=$(curl -sk --max-time 15 \
        -H "User-Agent: ${UA}" \
        -H "Accept: application/vnd.api+json, application/json" \
        -w "\n__CODE__%{http_code}" \
        "${BASE}${EP}" 2>/dev/null)
      CODE="${RESP##*__CODE__}"
      BODY="${RESP%__CODE__*}"

      IS_JSON=$(printf '%s' "$BODY" | python3 -c "
import sys,json
try:
    d=json.loads(sys.stdin.read())
    has_data = 'data' in d or 'links' in d or 'meta' in d
    print('yes' if has_data else 'partial')
except: print('no')
" 2>/dev/null)

      printf '  [%s][json=%s] %s%s\n' "$CODE" "$IS_JSON" "$BASE" "$EP"

      if [ "$CODE" = "200" ] && [ "$IS_JSON" != "no" ]; then
        # Count records
        RECORD_COUNT=$(printf '%s' "$BODY" | python3 -c "
import sys,json
try:
    d=json.loads(sys.stdin.read())
    data = d.get('data',[])
    print(len(data) if isinstance(data,list) else 1)
except: print(0)
" 2>/dev/null)

        # Check for sensitive fields
        SENSITIVE=$(printf '%s' "$BODY" | python3 -c "
import sys,json,re
try:
    text = sys.stdin.read()
    d = json.loads(text)
    hits = []
    # Look for email addresses
    emails = re.findall(r'[\w.+-]+@[\w.-]+\.\w+', text)
    if emails: hits.append(f'emails: {emails[:3]}')
    # Look for uid field in user entities
    if '\"drupal_internal__uid\"' in text: hits.append('user UIDs exposed')
    if '\"field_private\"' in text: hits.append('private field exposed')
    if '\"status\":false' in text or '\"status\":0' in text: hits.append('unpublished content')
    if '\"roles\"' in text: hits.append('role data exposed')
    print(', '.join(hits) if hits else 'no sensitive fields')
except: print('parse error')
" 2>/dev/null)

        echo "    *** OPEN: $RECORD_COUNT records | $SENSITIVE"

        # Save evidence
        printf '%s' "$BODY" | python3 -m json.tool 2>/dev/null \
          | head -40 > "$EVIDENCE/${HOST}-jsonapi${EP//\//-}.json" 2>/dev/null || true

        if [ "$EP" = "/jsonapi/user/user" ]; then
          emit_candidate "drupal-jsonapi-user-enum" "$HOST" "$EP" \
            "HTTP 200 JSON:API /user/user returned $RECORD_COUNT users. Sensitive: $SENSITIVE" \
            "HIGH" "Unauthenticated user enumeration: staff emails, UIDs, roles exposed"
        elif [[ "$EP" == *"node"* ]]; then
          emit_candidate "drupal-jsonapi-content-exposure" "$HOST" "$EP" \
            "HTTP 200 JSON:API $EP returned $RECORD_COUNT items. Sensitive: $SENSITIVE" \
            "MEDIUM" "Unauthenticated content exposure — may include draft/embargoed items"
        else
          emit_candidate "drupal-jsonapi-unauth" "$HOST" "$EP" \
            "HTTP 200 JSON:API $EP accessible without auth: $RECORD_COUNT records. $SENSITIVE" \
            "MEDIUM" "Unauthenticated Drupal API data exposure"
        fi

      elif [ "$CODE" = "403" ]; then
        echo "    [403] — exists but blocked (good)"
      elif [ "$CODE" = "401" ]; then
        echo "    [401] — requires auth (good)"
      fi
      sleep 0.3
    done
    sleep 1
  done < "$TARGETS_FILE"

  log "JSON:API scan complete."
}

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 3: Admin panel + sensitive path discovery (ffuf)
# ─────────────────────────────────────────────────────────────────────────────
run_admin() {
  log "=== CLASS 3: Admin Panel + Sensitive Path Discovery ==="

  have ffuf || { warn "ffuf not found — skipping admin discovery"; return; }

  HIGH_PRIORITY_TARGETS="$EVIDENCE/admin-targets.txt"
  # Focus on non-prod and high-value hosts
  grep -iE '(admin|partner|extranet|supply|agora|jobs|data|dev|staging|test|internal|api)\.' \
    "$LIVE" 2>/dev/null > "$HIGH_PRIORITY_TARGETS" || true

  # Fall back to all live if no priority matches
  [ -s "$HIGH_PRIORITY_TARGETS" ] || cp "$LIVE" "$HIGH_PRIORITY_TARGETS"

  # Drupal-specific + generic admin paths
  WORDLIST="$EVIDENCE/admin-paths.txt"
  cat > "$WORDLIST" <<'EOF'
admin
admin/config
admin/content
admin/people
admin/reports
admin/reports/status
admin/structure
admin/modules
admin/appearance
user/login
user/register
user/password
node/add
core/authorize.php
misc/test/index.html
web.config
.htaccess
.env
.git/HEAD
.git/config
backup
backup.zip
backup.tar.gz
db.sql
database.sql
dump.sql
wp-admin
wp-login.php
swagger
swagger.json
swagger-ui
openapi.json
openapi.yaml
api/v1
api/v2
graphql
graphiql
__graphql
_graphql
rest
rest/session/token
jsonapi
jsonapi/user/user
jsonapi/node/article?filter[status]=0
robots.txt
sitemap.xml
server-status
server-info
phpinfo.php
info.php
test.php
debug
_debug_bar
_profiler
health
healthz
ping
status
metrics
actuator
actuator/env
actuator/health
adminer.php
phpmyadmin
pma
.well-known/security.txt
.well-known/change-password
EOF

  touch "$OUT/03-candidates/admin-hits.txt"
  COUNT=0
  TOTAL=$(wc -l < "$HIGH_PRIORITY_TARGETS")

  while IFS= read -r TARGET_URL; do
    [ -z "$TARGET_URL" ] && continue
    COUNT=$((COUNT+1))
    HOST="${TARGET_URL#*://}"; HOST="${HOST%%/*}"

    SCOPE_CHECK="$("$SCRIPT_DIR/scope-check.sh" "$HOST" 2>&1 || true)"
    case "$SCOPE_CHECK" in IN-SCOPE*) ;; *) continue ;; esac

    BASE="${TARGET_URL%/}"
    echo "  [$COUNT/$TOTAL] Scanning: $BASE"

    ffuf -u "${BASE}/FUZZ" \
      -w "$WORDLIST" \
      -H "User-Agent: ${UA}" \
      -mc 200,201,204,301,302,307,401,403 \
      -fc 404 \
      -t 10 \
      -rate "$RATE" \
      -timeout 10 \
      -s \
      -o "$EVIDENCE/ffuf-${HOST}.json" \
      -of json 2>/dev/null || true

    # Parse ffuf output for interesting hits
    if [ -f "$EVIDENCE/ffuf-${HOST}.json" ]; then
      python3 -c "
import json, sys
try:
    d = json.load(open('$EVIDENCE/ffuf-${HOST}.json'))
    for r in d.get('results', []):
        url   = r.get('url','')
        code  = r.get('status',0)
        length = r.get('length',0)
        # Flag 200s and unusual 401/403 (means path exists)
        if code == 200:
            print(f'  *** [{code}] {url} (len={length}) — OPEN!')
        elif code in (401, 403) and length > 100:
            print(f'  [{code}] {url} (len={length}) — protected path exists')
        elif code in (301,302,307):
            print(f'  [{code}] {url} — redirect')
except Exception as e:
    pass
" 2>/dev/null | tee -a "$OUT/03-candidates/admin-hits.txt"
    fi
    sleep 2
  done < "$HIGH_PRIORITY_TARGETS"

  OPEN_COUNT=$(grep -c '\*\*\*' "$OUT/03-candidates/admin-hits.txt" 2>/dev/null || echo 0)
  log "Admin scan: $OPEN_COUNT open paths found. Review: $OUT/03-candidates/admin-hits.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 4: Nuclei — Drupal CVEs + exposure templates
# ─────────────────────────────────────────────────────────────────────────────
run_nuclei() {
  log "=== CLASS 4: Nuclei CVE + Exposure Scan ==="
  have nuclei || { warn "nuclei not found — skipping"; return; }

  NUCLEI_OUT="$EVIDENCE/nuclei-results.txt"
  touch "$NUCLEI_OUT"

  # Tags to run — Drupal CVEs, generic exposures, misconfigs (no intrusive)
  TAGS="drupal,exposure,config,backup,debug,info,generic,tech"

  nuclei -l "$LIVE" \
    -tags "$TAGS" \
    -severity "critical,high,medium,low,info" \
    -exclude-severity "unknown" \
    -exclude-tags "dos,fuzz,brute,headless,network,ssl,dns" \
    -rate-limit "$RATE" \
    -bulk-size 10 \
    -concurrency 5 \
    -timeout 10 \
    -no-interactsh \
    -o "$NUCLEI_OUT" \
    -stats 2>/dev/null || warn "nuclei failed"

  # Parse and emit candidates for critical/high/medium
  python3 -c "
import re, sys
for line in open('$NUCLEI_OUT'):
    line = line.strip()
    if not line: continue
    # nuclei output: [template-id] [severity] [url]
    m = re.match(r'\[(.+?)\] \[(\w+)\] (.+)', line)
    if m:
        tid, sev, url = m.groups()
        if sev.lower() in ('critical','high','medium'):
            print(f'CANDIDATE [{sev.upper()}] {tid}: {url}')
" 2>/dev/null | tee -a "$OUT/03-candidates/admin-hits.txt"

  CRIT=$(grep -ciE '\[critical\]|\[high\]' "$NUCLEI_OUT" 2>/dev/null || echo 0)
  log "Nuclei: $CRIT critical/high findings. Full results: $NUCLEI_OUT"
}

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 5: SSRF probe on URL-intake forms
# ─────────────────────────────────────────────────────────────────────────────
run_ssrf() {
  log "=== CLASS 5: SSRF Probe on URL-intake Endpoints ==="

  if [ -z "$OOB" ]; then
    warn "OOB_URL not set — can only check for error-response reflection (blind SSRF unconfirmable)"
    warn "Set OOB_URL=https://<interactsh-id>.oast.pro before running for real SSRF confirmation"
  fi

  # Look for URL parameters in historical URLs and endpoints
  SSRF_TARGETS="$EVIDENCE/ssrf-candidates.txt"
  cat "$OUT/02-surface/all-endpoints.txt" "$OUT/01-assets/historical-urls.txt" 2>/dev/null \
    | grep -iE '[?&](url|redirect|callback|src|href|link|feed|proxy|endpoint|service|path|next|dest|destination|target|uri|site|host|ref|referer|image|img|icon|logo|file|download|fetch|load|import|source|data|rss|webhook|notify|return|forward|continue|to|from|base)=' \
    | sort -u > "$SSRF_TARGETS" || true

  SSRF_COUNT=$(wc -l < "$SSRF_TARGETS" 2>/dev/null || echo 0)
  log "  $SSRF_COUNT URL-parameter endpoints identified for SSRF testing"

  if [ "$SSRF_COUNT" -gt 0 ]; then
    echo "  Top SSRF candidates:"
    head -10 "$SSRF_TARGETS"

    if [ -n "$OOB" ]; then
      log "  Probing with OOB URL: $OOB"
      OOB_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$OOB" 2>/dev/null)
      head -20 "$SSRF_TARGETS" | while IFS= read -r URL; do
        [ -z "$URL" ] && continue
        # Inject OOB into each URL parameter
        INJECTED=$(python3 -c "
import sys, urllib.parse, re
url = sys.argv[1]
oob_enc = sys.argv[2]
# Replace first URL-like parameter value
result = re.sub(
    r'([?&][A-Za-z_-]+=)[^&]+',
    lambda m: m.group(1) + oob_enc,
    url, count=1
)
print(result)
" "$URL" "$OOB_ENC" 2>/dev/null)
        HOST="${URL#*://}"; HOST="${HOST%%/*}"
        SCOPE_CHECK="$("$SCRIPT_DIR/scope-check.sh" "$HOST" 2>&1 || true)"
        case "$SCOPE_CHECK" in IN-SCOPE*) ;; *) continue ;; esac

        RESP=$(curl -sk --max-time 15 \
          -H "User-Agent: $UA" \
          -w "\n__CODE__%{http_code}" \
          "$INJECTED" 2>/dev/null)
        CODE="${RESP##*__CODE__}"
        echo "  [${CODE}] $INJECTED"
        sleep 0.5
      done
      log "  Check your OOB listener for any incoming requests from unicef.org IPs"
    fi
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# CLASS 6: API authentication testing
# ─────────────────────────────────────────────────────────────────────────────
run_api() {
  log "=== CLASS 6: API Endpoint Authentication Testing ==="

  API_HOSTS="$EVIDENCE/api-hosts.txt"
  # Focus: /api, /rest, /v1, /v2, /graphql subdomains and paths
  {
    grep -iE '(^https?://api\.|/api/|/rest/|/v[0-9]|/graphql)' \
      "$OUT/02-surface/live.txt" 2>/dev/null || true
    cat "$OUT/02-surface/all-endpoints.txt" 2>/dev/null \
      | grep -iE '/api/|/rest/|/v[12]/' | awk -F'/' '{print $1"//"$3}' \
      | sort -u || true
  } | sort -u > "$API_HOSTS"

  API_COUNT=$(wc -l < "$API_HOSTS" 2>/dev/null || echo 0)
  log "  $API_COUNT API targets"

  # Probe common API patterns
  API_PATHS=(
    "/api/v1/users"
    "/api/v2/users"
    "/api/v1/me"
    "/api/users"
    "/rest/v1/user"
    "/api/v1/content"
    "/api/v1/nodes"
    "/api/v1/files"
    "/graphql"
    "/api/v1/health"
    "/api/health"
    "/api/status"
    "/api/v1/config"
    "/api/v1/settings"
  )

  touch "$OUT/03-candidates/api-hits.txt"
  while IFS= read -r BASE_URL; do
    [ -z "$BASE_URL" ] && continue
    HOST="${BASE_URL#*://}"; HOST="${HOST%%/*}"
    SCOPE_CHECK="$("$SCRIPT_DIR/scope-check.sh" "$HOST" 2>&1 || true)"
    case "$SCOPE_CHECK" in IN-SCOPE*) ;; *) continue ;; esac

    BASE="${BASE_URL%/}"
    for AP in "${API_PATHS[@]}"; do
      RESP=$(curl -sk --max-time 10 \
        -H "User-Agent: $UA" \
        -H "Accept: application/json" \
        -w "\n__CODE__%{http_code}" \
        "${BASE}${AP}" 2>/dev/null)
      CODE="${RESP##*__CODE__}"
      BODY="${RESP%__CODE__*}"
      IS_JSON=$(printf '%s' "$BODY" | python3 -c "
import sys,json
try: d=json.loads(sys.stdin.read()); print('yes')
except: print('no')
" 2>/dev/null)

      if [ "$IS_JSON" = "yes" ] && [ "$CODE" = "200" ]; then
        echo "  *** OPEN [${CODE}] ${BASE}${AP} — JSON returned without auth!"
        printf '%s' "$BODY" | python3 -m json.tool 2>/dev/null | head -15
        echo "${BASE}${AP}" >> "$OUT/03-candidates/api-hits.txt"
        emit_candidate "api-unauth-data" "$HOST" "$AP" \
          "HTTP 200 JSON response without auth at ${BASE}${AP}" \
          "MEDIUM" "Unauthenticated API data exposure"
      elif [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && [ "$CODE" != "400" ]; then
        printf '  [%s][json=%s] %s%s\n' "$CODE" "$IS_JSON" "$BASE" "$AP"
      fi
      sleep 0.2
    done
  done < "$API_HOSTS"
}

# ─────────────────────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────────────────────
case "$RUN_CLASS" in
  takeover) run_takeover ;;
  jsonapi)  run_jsonapi  ;;
  admin)    run_admin    ;;
  nuclei)   run_nuclei   ;;
  ssrf)     run_ssrf     ;;
  api)      run_api      ;;
  all)
    run_takeover
    echo ""
    run_jsonapi
    echo ""
    run_admin
    echo ""
    run_nuclei
    echo ""
    run_ssrf
    echo ""
    run_api
    ;;
  *)
    err "Unknown class: $RUN_CLASS. Valid: takeover | jsonapi | admin | nuclei | ssrf | api | all"
    exit 1
    ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=== HUNT COMPLETE — $STAMP ==="
echo ""
TOTAL_CANDIDATES=$(wc -l < "$OUT/03-candidates/candidates.jsonl" 2>/dev/null || echo 0)
echo "Candidates logged   : $TOTAL_CANDIDATES"
echo "Evidence directory  : $EVIDENCE"
echo "Candidates JSONL    : $OUT/03-candidates/candidates.jsonl"
echo "Log                 : $LOG"
echo ""
echo "NEXT STEPS:"
echo "  1. Review candidates:"
echo "     python3 -m json.tool --no-ensure-ascii < results/unicef.org/03-candidates/candidates.jsonl | less"
echo ""
echo "  2. Verify each HIGH-confidence candidate manually:"
echo "     - Subdomain takeover: claim the service, confirm unicef.org subdomain serves your content"
echo "     - JSON:API: confirm staff emails or private content is returned"
echo ""
echo "  3. Write report when a finding passes Section 2 of CLAUDE.md (all 5 criteria)"
echo "     bash scripts/unicef-report.sh (or use /report skill)"
echo ""
echo "  4. Submit to: infosecurity@unicef.org"
echo '     Subject: "Vulnerability Report: [Brief Description]"'
