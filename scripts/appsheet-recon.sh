#!/usr/bin/env bash
# appsheet-recon.sh — Deep unattended recon for appsheet.com (TIER0 SSRF hunt)
# Run from Pi: nohup bash scripts/appsheet-recon.sh > results/appsheet.com/recon.log 2>&1 &
# Review on return: cat results/appsheet.com/RECON-SUMMARY.md

set -euo pipefail

TARGET="appsheet.com"
OUT="results/$TARGET"
THREADS=10
RATE=50

mkdir -p "$OUT"/{01-assets,02-surface/js/raw,03-candidates/evidence}

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/recon.log"; }

# ── SCOPE GATE ─────────────────────────────────────────────────────────────────
log "Scope check..."
./scripts/scope-check.sh "$TARGET" | grep -q IN-SCOPE \
  || { echo "OUT-OF-SCOPE — abort"; exit 1; }

# ── PHASE 1: SUBDOMAIN ENUMERATION ─────────────────────────────────────────────
log "Phase 1 — Subdomain enumeration"

subfinder -d "$TARGET" -all -silent 2>/dev/null \
  | anew "$OUT/01-assets/subdomains.txt" || true

assetfinder --subs-only "$TARGET" 2>/dev/null \
  | anew "$OUT/01-assets/subdomains.txt" || true

curl -sfL "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
  | jq -r '.[].name_value // empty' \
  | tr ',' '\n' \
  | sed 's/^\*\.//' \
  | grep -E "^[a-zA-Z0-9._-]+\.$TARGET$" \
  | anew "$OUT/01-assets/subdomains.txt" || true

gau "$TARGET" --threads 5 2>/dev/null \
  | grep -oE "[a-zA-Z0-9._-]+\.$TARGET" \
  | anew "$OUT/01-assets/subdomains.txt" || true

waybackurls "$TARGET" 2>/dev/null \
  | grep -oE "[a-zA-Z0-9._-]+\.$TARGET" \
  | anew "$OUT/01-assets/subdomains.txt" || true

# GitHub subdomains (requires GITHUB_TOKEN env var)
if [ -n "${GITHUB_TOKEN:-}" ]; then
  github-subdomains -d "$TARGET" -t "$GITHUB_TOKEN" -o /tmp/gh-subs.txt 2>/dev/null \
    && cat /tmp/gh-subs.txt | anew "$OUT/01-assets/subdomains.txt" || true
fi

log "Subdomains collected: $(wc -l < "$OUT/01-assets/subdomains.txt")"

# ── PHASE 2: RESOLVE + LIVE DETECTION ──────────────────────────────────────────
log "Phase 2 — DNS resolution"

dnsx -l "$OUT/01-assets/subdomains.txt" -a -cname -resp -silent \
  -threads "$THREADS" 2>/dev/null \
  | tee "$OUT/01-assets/resolved.txt" || true

# Extract live hosts (have A record)
grep '\[A\]' "$OUT/01-assets/resolved.txt" 2>/dev/null \
  | awk '{print $1}' \
  | sed 's/\.$//' \
  | sort -u > "$OUT/01-assets/live-hosts.txt" || true

# Extract CNAMEs for takeover analysis
grep 'CNAME' "$OUT/01-assets/resolved.txt" 2>/dev/null \
  | tee "$OUT/01-assets/cname-records.txt" || true

log "Live hosts: $(wc -l < "$OUT/01-assets/live-hosts.txt")"
log "CNAMEs: $(wc -l < "$OUT/01-assets/cname-records.txt")"

# ── PHASE 3: SUBDOMAIN TAKEOVER SCAN ───────────────────────────────────────────
log "Phase 3 — Subdomain takeover scan (our proven technique)"

subzy run --targets "$OUT/01-assets/subdomains.txt" --hide-fails \
  --concurrency 20 2>/dev/null \
  | tee "$OUT/03-candidates/takeover-hits.txt" || true

TAKEOVER_COUNT=$(grep -c 'VULNERABLE\|vulnerable' "$OUT/03-candidates/takeover-hits.txt" 2>/dev/null || echo 0)
log "Takeover hits: $TAKEOVER_COUNT"

# ── PHASE 4: HTTP PROBING ───────────────────────────────────────────────────────
log "Phase 4 — HTTP probing"

httpx -l "$OUT/01-assets/live-hosts.txt" \
  -status-code -title -tech-detect -follow-redirects \
  -rate-limit "$RATE" -threads "$THREADS" -silent \
  -json -o "$OUT/02-surface/httpx-full.json" 2>/dev/null || true

httpx -l "$OUT/01-assets/live-hosts.txt" -silent \
  -rate-limit "$RATE" 2>/dev/null \
  | tee "$OUT/02-surface/live.txt" || true

log "Live HTTP hosts: $(wc -l < "$OUT/02-surface/live.txt")"

# Flag high-value subdomains immediately
grep -Ei '(dev|test|staging|admin|internal|legacy|api|rde|grafana|jenkins|kibana|dashboard|debug|beta|corp|git|auth|sso|login|iam|rbac|priv|mgmt|mgr|manage|backstage|argocd|vault|consul|prometheus)' \
  "$OUT/02-surface/live.txt" 2>/dev/null \
  | tee "$OUT/02-surface/priority-hosts.txt" || true

log "Priority hosts: $(wc -l < "$OUT/02-surface/priority-hosts.txt")"

# ── PHASE 5: CRAWL + ENDPOINT DISCOVERY ────────────────────────────────────────
log "Phase 5 — Crawl and endpoint discovery"

katana -list "$OUT/02-surface/live.txt" \
  -jc -d 3 -silent \
  -rate-limit "$RATE" -concurrency "$THREADS" \
  -o "$OUT/02-surface/katana-urls.txt" 2>/dev/null || true

# API endpoint patterns
grep -iE '(/api/|/v[0-9]+/|/rest/|/graphql|/gql|/query|/rpc|/grpc|/proto)' \
  "$OUT/02-surface/katana-urls.txt" 2>/dev/null \
  | sort -u \
  | tee "$OUT/02-surface/api-endpoints.txt" || true

# Swagger / OpenAPI discovery
for host in $(cat "$OUT/02-surface/live.txt" 2>/dev/null | head -50); do
  for path in /swagger.json /swagger/index.html /openapi.json /api/docs /api/v1/docs /api/v2/docs /api-docs /v3/api-docs; do
    code=$(curl -sfLk --max-time 8 -o /tmp/swagger-resp.json \
      -w "%{http_code}" "${host}${path}" 2>/dev/null || echo "000")
    if [[ "$code" == "200" ]] && grep -qiE '(swagger|openapi|paths|definitions)' /tmp/swagger-resp.json 2>/dev/null; then
      echo "API_DOCS_FOUND: ${host}${path}"
      cp /tmp/swagger-resp.json "$OUT/03-candidates/evidence/swagger-$(echo "$host" | tr '/:' '--')${path//\//-}.json"
    fi
  done
done 2>/dev/null | tee "$OUT/03-candidates/api-docs-hits.txt" || true

log "API endpoints: $(wc -l < "$OUT/02-surface/api-endpoints.txt")"

# ── PHASE 6: DIRECTORY FUZZING (priority hosts only) ───────────────────────────
log "Phase 6 — Directory/path fuzzing on priority hosts"

WORDLIST=""
for wl in ~/wordlists/assetnote/apiroutes_210228.txt \
           /usr/share/wordlists/dirb/common.txt \
           ~/wordlists/raft-medium-files.txt; do
  [ -f "$wl" ] && WORDLIST="$wl" && break
done

if [ -n "$WORDLIST" ]; then
  while IFS= read -r url; do
    host=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
    ./scripts/scope-check.sh "$host" 2>/dev/null | grep -q IN-SCOPE || continue
    ffuf -u "${url}/FUZZ" \
      -w "$WORDLIST" \
      -mc 200,201,204,403 \
      -fc 404 \
      -rate 30 -t 8 -silent \
      -o "$OUT/02-surface/ffuf-$(echo "$host" | tr '.' '-').json" \
      -of json 2>/dev/null &
  done < "$OUT/02-surface/priority-hosts.txt"
  wait
  log "Fuzzing complete"
else
  log "No wordlist found — skipping fuzzing"
fi

# ── PHASE 7: JS ANALYSIS ───────────────────────────────────────────────────────
log "Phase 7 — JS bundle analysis"

grep -E '\.js(\?[^"'"'"' ]*)?$' "$OUT/02-surface/katana-urls.txt" 2>/dev/null \
  | sort -u > "$OUT/02-surface/js/js-urls.txt" || true

log "JS files to analyze: $(wc -l < "$OUT/02-surface/js/js-urls.txt")"

# Download JS bundles
while IFS= read -r url; do
  fname=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
  curl -sfLk --max-time 20 "$url" \
    -o "$OUT/02-surface/js/raw/${fname}.js" 2>/dev/null || true
done < "$OUT/02-surface/js/js-urls.txt"

# jsluice analysis
find "$OUT/02-surface/js/raw" -name '*.js' 2>/dev/null \
  | xargs -I{} jsluice urls {} 2>/dev/null \
  | sort -u \
  | tee "$OUT/02-surface/js/jsluice-urls.txt" || true

find "$OUT/02-surface/js/raw" -name '*.js' 2>/dev/null \
  | xargs -I{} jsluice secrets {} 2>/dev/null \
  | tee "$OUT/02-surface/js/jsluice-secrets.txt" || true

# Internal hostnames
grep -rhEo '[a-zA-Z0-9.-]+\.(internal|corp|local|svc|gcp|googleapis\.com)[a-zA-Z0-9./-]*' \
  "$OUT/02-surface/js/raw/" 2>/dev/null \
  | sort -u \
  | tee "$OUT/02-surface/js/internal-hosts.txt" || true

# API paths
grep -rhEo '["\x60'"'"'](/[a-zA-Z0-9_/.-]{4,})["\x60'"'"']' \
  "$OUT/02-surface/js/raw/" 2>/dev/null \
  | grep -oE '/[a-zA-Z0-9_/.-]{4,}' \
  | sort -u \
  | tee "$OUT/02-surface/js/api-paths.txt" || true

# GCP/cloud config fragments
grep -rhEi '(storage\.googleapis\.com|cloud\.google\.com|appspot\.com|run\.app|cloudfunctions\.net|vertexai|aiplatform)' \
  "$OUT/02-surface/js/raw/" 2>/dev/null \
  | sort -u \
  | tee "$OUT/02-surface/js/gcp-refs.txt" || true

# AppSheet App IDs (UUID pattern — may reveal other tenants)
grep -rhEo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
  "$OUT/02-surface/js/raw/" 2>/dev/null \
  | sort -u \
  | tee "$OUT/02-surface/js/app-ids.txt" || true

log "JS secrets: $(wc -l < "$OUT/02-surface/js/jsluice-secrets.txt")"
log "Internal hosts in JS: $(wc -l < "$OUT/02-surface/js/internal-hosts.txt")"
log "API paths in JS: $(wc -l < "$OUT/02-surface/js/api-paths.txt")"

# ── PHASE 8: GRAPHQL DISCOVERY ─────────────────────────────────────────────────
log "Phase 8 — GraphQL endpoint discovery"

GQL_PATHS=("/graphql" "/api/graphql" "/v1/graphql" "/v2/graphql" "/query"
           "/gql" "/api/gql" "/api/v1/graphql" "/api/v2/graphql"
           "/appsheet/api/graphql" "/app/api/graphql")

while IFS= read -r url; do
  for path in "${GQL_PATHS[@]}"; do
    code=$(curl -sfXPOST --max-time 8 \
      -H 'Content-Type: application/json' \
      -d '{"query":"{__typename}"}' \
      -o /tmp/gql-resp.json \
      -w "%{http_code}" "${url}${path}" 2>/dev/null || echo "000")
    if [[ "$code" == "200" ]] && grep -q '__typename\|data\|errors' /tmp/gql-resp.json 2>/dev/null; then
      echo "GRAPHQL_HIT: ${url}${path} (HTTP $code)"
      # Try full introspection
      curl -sfXPOST --max-time 15 \
        -H 'Content-Type: application/json' \
        -d '{"query":"{__schema{queryType{fields{name}}}}"}' \
        -o "$OUT/03-candidates/evidence/graphql-$(echo "$url" | tr '/:' '--')${path//\//-}.json" \
        "${url}${path}" 2>/dev/null || true
    fi
  done
done < "$OUT/02-surface/live.txt" 2>/dev/null \
  | tee "$OUT/03-candidates/graphql-hits.txt" || true

log "GraphQL hits: $(wc -l < "$OUT/03-candidates/graphql-hits.txt")"

# ── PHASE 9: NUCLEI SCAN ───────────────────────────────────────────────────────
log "Phase 9 — Nuclei automated scan"

nuclei -l "$OUT/02-surface/live.txt" \
  -tags "takeover,exposure,misconfig,default-login,tech,graphql,cloud,ssrf,idor" \
  -severity "critical,high,medium" \
  -rate-limit "$RATE" -concurrency "$THREADS" \
  -exclude-tags "dos,fuzz,intrusive" \
  -silent \
  -o "$OUT/03-candidates/nuclei-hits.txt" 2>/dev/null || true

log "Nuclei hits: $(wc -l < "$OUT/03-candidates/nuclei-hits.txt")"

# ── PHASE 10: APPSHEET-SPECIFIC PROBES ─────────────────────────────────────────
log "Phase 10 — AppSheet-specific attack surface"

API_BASE="https://api.appsheet.com"

# Check AppSheet REST API versions and documentation
for path in /api/v2 /api/v2/docs /api/v2/swagger /api/v2/openapi \
            /api/v1 /swagger /openapi.json /docs \
            /api/v2/apps /api/v2/templates /api/v2/users; do
  code=$(curl -sfLk --max-time 10 \
    -H 'Accept: application/json' \
    -o /tmp/as-resp.json \
    -w "%{http_code}" "${API_BASE}${path}" 2>/dev/null || echo "000")
  [ "$code" != "000" ] && [ "$code" != "404" ] \
    && echo "API_PROBE: ${API_BASE}${path} → HTTP $code" \
    && cp /tmp/as-resp.json "$OUT/03-candidates/evidence/api-probe${path//\//-}.json" 2>/dev/null
done 2>/dev/null | tee "$OUT/03-candidates/api-probes.txt" || true

# EU instance — may lag on patches
EU_BASE="https://eu.appsheet.com"
for path in /api/v2 /api/v2/docs /swagger /openapi.json; do
  code=$(curl -sfLk --max-time 10 \
    -H 'Accept: application/json' \
    -o /tmp/eu-resp.json \
    -w "%{http_code}" "${EU_BASE}${path}" 2>/dev/null || echo "000")
  [ "$code" != "000" ] && [ "$code" != "404" ] \
    && echo "EU_API_PROBE: ${EU_BASE}${path} → HTTP $code"
done 2>/dev/null | tee -a "$OUT/03-candidates/api-probes.txt" || true

# AppSheet app sharing endpoint — IDOR candidate
# Tests whether app data is accessible without auth or with wrong tenant creds
APP_ID="c5dde27c-49a6-47e4-8529-737cf68a3c12"  # our test app
for path in \
  "/api/v2/apps/$APP_ID" \
  "/api/v2/apps/$APP_ID/tables" \
  "/api/v2/apps/$APP_ID/views" \
  "/api/v2/apps/$APP_ID/schemas" \
  "/start/$APP_ID"; do
  code=$(curl -sfLk --max-time 10 \
    -o /tmp/app-resp.json \
    -w "%{http_code}" "https://www.appsheet.com${path}" 2>/dev/null || echo "000")
  echo "APP_API: https://www.appsheet.com${path} → HTTP $code"
done 2>/dev/null | tee "$OUT/03-candidates/app-api-probes.txt" || true

# ── PHASE 11: CLOUD BUCKET ENUMERATION ─────────────────────────────────────────
log "Phase 11 — Cloud bucket enumeration"

for pattern in "appsheet" "appsheet-com" "appsheet-data" "appsheet-assets" \
               "appsheet-backup" "appsheet-prod" "appsheet-dev" \
               "google-appsheet" "appsheet-uploads" "appsheet-exports"; do
  # GCS
  code=$(curl -sfk --max-time 8 \
    -w "%{http_code}" \
    -o /tmp/bucket-resp.txt \
    "https://storage.googleapis.com/$pattern" 2>/dev/null || echo "000")
  [ "$code" = "200" ] && echo "PUBLIC_GCS: $pattern" \
    && cp /tmp/bucket-resp.txt "$OUT/03-candidates/evidence/gcs-$pattern.xml"

  # S3
  code=$(curl -sfk --max-time 8 \
    -w "%{http_code}" \
    -o /tmp/s3-resp.txt \
    "https://$pattern.s3.amazonaws.com" 2>/dev/null || echo "000")
  [ "$code" = "200" ] && echo "PUBLIC_S3: $pattern" \
    && cp /tmp/s3-resp.txt "$OUT/03-candidates/evidence/s3-$pattern.xml"
done 2>/dev/null | tee "$OUT/03-candidates/bucket-hits.txt" || true

log "Bucket hits: $(wc -l < "$OUT/03-candidates/bucket-hits.txt")"

# ── SUMMARY REPORT ─────────────────────────────────────────────────────────────
log "Writing summary..."

{
cat << EOF
# AppSheet Recon Summary
Generated: $(date)
Target: $TARGET

## Asset Counts
- Subdomains:       $(wc -l < "$OUT/01-assets/subdomains.txt" 2>/dev/null || echo 0)
- Resolved hosts:   $(wc -l < "$OUT/01-assets/resolved.txt" 2>/dev/null || echo 0)
- Live HTTP hosts:  $(wc -l < "$OUT/02-surface/live.txt" 2>/dev/null || echo 0)
- Priority hosts:   $(wc -l < "$OUT/02-surface/priority-hosts.txt" 2>/dev/null || echo 0)
- CNAMEs:           $(wc -l < "$OUT/01-assets/cname-records.txt" 2>/dev/null || echo 0)
- JS files:         $(wc -l < "$OUT/02-surface/js/js-urls.txt" 2>/dev/null || echo 0)
- API endpoints:    $(wc -l < "$OUT/02-surface/api-endpoints.txt" 2>/dev/null || echo 0)
- API paths in JS:  $(wc -l < "$OUT/02-surface/js/api-paths.txt" 2>/dev/null || echo 0)

## Candidate Findings
- Takeover hits:    $(wc -l < "$OUT/03-candidates/takeover-hits.txt" 2>/dev/null || echo 0)
- JS secrets:       $(wc -l < "$OUT/02-surface/js/jsluice-secrets.txt" 2>/dev/null || echo 0)
- GraphQL hits:     $(wc -l < "$OUT/03-candidates/graphql-hits.txt" 2>/dev/null || echo 0)
- Nuclei hits:      $(wc -l < "$OUT/03-candidates/nuclei-hits.txt" 2>/dev/null || echo 0)
- Bucket hits:      $(wc -l < "$OUT/03-candidates/bucket-hits.txt" 2>/dev/null || echo 0)
- API doc hits:     $(wc -l < "$OUT/03-candidates/api-docs-hits.txt" 2>/dev/null || echo 0)

## Priority Subdomains Found
$(cat "$OUT/02-surface/priority-hosts.txt" 2>/dev/null | head -30 || echo "(none)")

## Takeover Candidates
$(cat "$OUT/03-candidates/takeover-hits.txt" 2>/dev/null | head -20 || echo "(none)")

## JS Secrets (Top 20)
$(cat "$OUT/02-surface/js/jsluice-secrets.txt" 2>/dev/null | head -20 || echo "(none)")

## GraphQL Hits
$(cat "$OUT/03-candidates/graphql-hits.txt" 2>/dev/null || echo "(none)")

## Nuclei Findings
$(cat "$OUT/03-candidates/nuclei-hits.txt" 2>/dev/null | head -30 || echo "(none)")

## Internal Hosts in JS
$(cat "$OUT/02-surface/js/internal-hosts.txt" 2>/dev/null | head -20 || echo "(none)")

## GCP References in JS
$(cat "$OUT/02-surface/js/gcp-refs.txt" 2>/dev/null | head -20 || echo "(none)")

## API Probe Results
$(cat "$OUT/03-candidates/api-probes.txt" 2>/dev/null || echo "(none)")

## Review Order When You Return
1. cat $OUT/03-candidates/takeover-hits.txt        # CNAME takeovers (HIGH/CRITICAL)
2. cat $OUT/02-surface/js/jsluice-secrets.txt      # Live credentials in JS
3. cat $OUT/02-surface/priority-hosts.txt          # Dev/staging/admin targets
4. cat $OUT/03-candidates/nuclei-hits.txt          # Scanner hits to verify
5. cat $OUT/03-candidates/graphql-hits.txt         # GraphQL endpoints for IDOR
6. cat $OUT/02-surface/js/internal-hosts.txt       # Internal hostnames (SSRF chain)
7. cat $OUT/03-candidates/api-probes.txt           # API surface exposed
8. cat $OUT/02-surface/js/api-paths.txt            # All API paths for SSRF/IDOR
9. cat $OUT/01-assets/cname-records.txt            # CNAMEs for manual takeover check
EOF
} > "$OUT/RECON-SUMMARY.md"

log "Done. Results: $OUT/RECON-SUMMARY.md"
log "Run: cat $OUT/RECON-SUMMARY.md"
