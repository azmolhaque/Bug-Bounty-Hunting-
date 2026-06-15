#!/usr/bin/env bash
# appsheet-recon.sh — Deep unattended recon for appsheet.com
# Run: nohup bash scripts/appsheet-recon.sh > results/appsheet.com/recon.log 2>&1 &
# Check progress: tail -f results/appsheet.com/recon.log
# Final report:   cat results/appsheet.com/RECON-SUMMARY.md

TARGET="appsheet.com"
OUT="results/$TARGET"
THREADS=10
RATE=50

mkdir -p "$OUT"/{01-assets,02-surface/js/raw,03-candidates/evidence}

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/recon.log"; }
run() { "$@" 2>/dev/null || true; }

# ── SCOPE GATE ──────────────────────────────────────────────────────────────────
log "Scope check..."
if ! ./scripts/scope-check.sh "$TARGET" 2>/dev/null | grep -q IN-SCOPE; then
  log "ERROR: $TARGET is OUT-OF-SCOPE — aborting"
  exit 1
fi
log "Scope OK — starting recon on $TARGET"

# ── PHASE 1: SUBDOMAIN ENUMERATION ──────────────────────────────────────────────
log "Phase 1 — Subdomain enumeration"

run subfinder -d "$TARGET" -all -silent \
  | run anew "$OUT/01-assets/subdomains.txt"

run assetfinder --subs-only "$TARGET" \
  | run anew "$OUT/01-assets/subdomains.txt"

curl -sfL "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
  | jq -r '.[].name_value // empty' 2>/dev/null \
  | tr ',' '\n' \
  | sed 's/^\*\.//' \
  | grep -E "^[a-zA-Z0-9._-]+\.$TARGET$" 2>/dev/null \
  | run anew "$OUT/01-assets/subdomains.txt"

run gau "$TARGET" --threads 5 \
  | grep -oE "[a-zA-Z0-9._-]+\.$TARGET" 2>/dev/null \
  | run anew "$OUT/01-assets/subdomains.txt"

run waybackurls "$TARGET" \
  | grep -oE "[a-zA-Z0-9._-]+\.$TARGET" 2>/dev/null \
  | run anew "$OUT/01-assets/subdomains.txt"

if [ -n "${GITHUB_TOKEN:-}" ]; then
  run github-subdomains -d "$TARGET" -t "$GITHUB_TOKEN" \
    | run anew "$OUT/01-assets/subdomains.txt"
fi

SUBDOMAIN_COUNT=$(wc -l < "$OUT/01-assets/subdomains.txt" 2>/dev/null || echo 0)
log "Subdomains collected: $SUBDOMAIN_COUNT"

# ── PHASE 2: DNS RESOLUTION ──────────────────────────────────────────────────────
log "Phase 2 — DNS resolution"

run dnsx -l "$OUT/01-assets/subdomains.txt" \
  -a -cname -resp -silent -threads "$THREADS" \
  | tee "$OUT/01-assets/resolved.txt"

grep '\[A\]' "$OUT/01-assets/resolved.txt" 2>/dev/null \
  | awk '{print $1}' | sed 's/\.$//' | sort -u \
  > "$OUT/01-assets/live-hosts.txt" || true

grep 'CNAME' "$OUT/01-assets/resolved.txt" 2>/dev/null \
  > "$OUT/01-assets/cname-records.txt" || true

log "Live hosts: $(wc -l < "$OUT/01-assets/live-hosts.txt" 2>/dev/null || echo 0)"
log "CNAMEs:     $(wc -l < "$OUT/01-assets/cname-records.txt" 2>/dev/null || echo 0)"

# ── PHASE 3: SUBDOMAIN TAKEOVER ──────────────────────────────────────────────────
log "Phase 3 — Subdomain takeover scan"

run subzy run --targets "$OUT/01-assets/subdomains.txt" \
  --hide-fails --concurrency 20 \
  | tee "$OUT/03-candidates/takeover-hits.txt"

log "Takeover hits: $(grep -c 'VULNERABLE\|vulnerable' "$OUT/03-candidates/takeover-hits.txt" 2>/dev/null || echo 0)"

# ── PHASE 4: HTTP PROBING ─────────────────────────────────────────────────────────
log "Phase 4 — HTTP probing"

run httpx -l "$OUT/01-assets/live-hosts.txt" \
  -status-code -title -tech-detect -follow-redirects \
  -rate-limit "$RATE" -threads "$THREADS" -silent \
  -json -o "$OUT/02-surface/httpx-full.json"

run httpx -l "$OUT/01-assets/live-hosts.txt" \
  -silent -rate-limit "$RATE" \
  | tee "$OUT/02-surface/live.txt"

log "Live HTTP hosts: $(wc -l < "$OUT/02-surface/live.txt" 2>/dev/null || echo 0)"

grep -Ei '(dev|test|staging|admin|internal|legacy|rde|grafana|jenkins|kibana|dashboard|debug|beta|auth|sso|login|iam|vault|mgmt|manage|backstage|git|argocd|consul|prometheus)' \
  "$OUT/02-surface/live.txt" 2>/dev/null \
  > "$OUT/02-surface/priority-hosts.txt" || true

log "Priority hosts: $(wc -l < "$OUT/02-surface/priority-hosts.txt" 2>/dev/null || echo 0)"

# ── PHASE 5: CRAWL + ENDPOINT DISCOVERY ───────────────────────────────────────────
log "Phase 5 — Crawl and endpoint discovery"

run katana -list "$OUT/02-surface/live.txt" \
  -jc -d 3 -silent \
  -rate-limit "$RATE" -concurrency "$THREADS" \
  -o "$OUT/02-surface/katana-urls.txt"

grep -iE '(/api/|/v[0-9]+/|/rest/|/graphql|/gql|/query|/rpc)' \
  "$OUT/02-surface/katana-urls.txt" 2>/dev/null \
  | sort -u \
  > "$OUT/02-surface/api-endpoints.txt" || true

# Swagger / OpenAPI probes
while IFS= read -r host; do
  for path in /swagger.json /openapi.json /api/docs /api/v2/docs /api-docs /v3/api-docs /swagger/index.html; do
    code=$(curl -sfLk --max-time 8 \
      -o /tmp/sw-resp.json \
      -w "%{http_code}" "${host}${path}" 2>/dev/null || echo "000")
    if [[ "$code" == "200" ]] && grep -qiE '(swagger|openapi|paths|definitions)' /tmp/sw-resp.json 2>/dev/null; then
      echo "API_DOCS: ${host}${path}"
      cp /tmp/sw-resp.json "$OUT/03-candidates/evidence/apidocs-$(echo "${host}${path}" | tr '/:' '--').json" 2>/dev/null || true
    fi
  done
done < "$OUT/02-surface/live.txt" 2>/dev/null \
  | tee "$OUT/03-candidates/api-docs-hits.txt" || true

log "API endpoints: $(wc -l < "$OUT/02-surface/api-endpoints.txt" 2>/dev/null || echo 0)"

# ── PHASE 6: JS ANALYSIS ──────────────────────────────────────────────────────────
log "Phase 6 — JS bundle analysis"

grep -E '\.js(\?[^ ]*)?$' "$OUT/02-surface/katana-urls.txt" 2>/dev/null \
  | sort -u > "$OUT/02-surface/js/js-urls.txt" || true

log "JS files: $(wc -l < "$OUT/02-surface/js/js-urls.txt" 2>/dev/null || echo 0)"

while IFS= read -r url; do
  fname=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
  curl -sfLk --max-time 20 "$url" \
    -o "$OUT/02-surface/js/raw/${fname}.js" 2>/dev/null || true
done < "$OUT/02-surface/js/js-urls.txt"

find "$OUT/02-surface/js/raw" -name '*.js' 2>/dev/null \
  | xargs -I{} jsluice urls {} 2>/dev/null \
  | sort -u \
  | tee "$OUT/02-surface/js/jsluice-urls.txt" || true

find "$OUT/02-surface/js/raw" -name '*.js' 2>/dev/null \
  | xargs -I{} jsluice secrets {} 2>/dev/null \
  | tee "$OUT/02-surface/js/jsluice-secrets.txt" || true

grep -rhEo '[a-zA-Z0-9.-]+\.(internal|corp|local|svc|googleapis\.com|run\.app|cloudfunctions\.net)[a-zA-Z0-9./-]*' \
  "$OUT/02-surface/js/raw/" 2>/dev/null \
  | sort -u > "$OUT/02-surface/js/internal-hosts.txt" || true

grep -rhEo '"(/[a-zA-Z0-9_/.-]{4,})"' \
  "$OUT/02-surface/js/raw/" 2>/dev/null \
  | grep -oE '/[a-zA-Z0-9_/.-]{4,}' \
  | sort -u > "$OUT/02-surface/js/api-paths.txt" || true

grep -rhEi '(storage\.googleapis\.com|appspot\.com|run\.app|cloudfunctions\.net|vertexai|aiplatform)' \
  "$OUT/02-surface/js/raw/" 2>/dev/null \
  | sort -u > "$OUT/02-surface/js/gcp-refs.txt" || true

grep -rhEo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
  "$OUT/02-surface/js/raw/" 2>/dev/null \
  | sort -u > "$OUT/02-surface/js/app-ids.txt" || true

log "JS secrets:        $(wc -l < "$OUT/02-surface/js/jsluice-secrets.txt" 2>/dev/null || echo 0)"
log "Internal hosts:    $(wc -l < "$OUT/02-surface/js/internal-hosts.txt" 2>/dev/null || echo 0)"
log "API paths from JS: $(wc -l < "$OUT/02-surface/js/api-paths.txt" 2>/dev/null || echo 0)"

# ── PHASE 7: GRAPHQL DISCOVERY ────────────────────────────────────────────────────
log "Phase 7 — GraphQL endpoint discovery"

while IFS= read -r url; do
  for path in /graphql /api/graphql /v1/graphql /v2/graphql /query /gql /api/gql; do
    code=$(curl -sfXPOST --max-time 8 \
      -H 'Content-Type: application/json' \
      -d '{"query":"{__typename}"}' \
      -o /tmp/gql-resp.json \
      -w "%{http_code}" "${url}${path}" 2>/dev/null || echo "000")
    if [[ "$code" == "200" ]] && grep -q '__typename\|data\|errors' /tmp/gql-resp.json 2>/dev/null; then
      echo "GRAPHQL_HIT: ${url}${path}"
      curl -sfXPOST --max-time 15 \
        -H 'Content-Type: application/json' \
        -d '{"query":"{__schema{queryType{fields{name}}}}"}' \
        -o "$OUT/03-candidates/evidence/graphql-$(echo "${url}${path}" | tr '/:' '--').json" \
        "${url}${path}" 2>/dev/null || true
    fi
  done
done < "$OUT/02-surface/live.txt" 2>/dev/null \
  | tee "$OUT/03-candidates/graphql-hits.txt" || true

log "GraphQL hits: $(wc -l < "$OUT/03-candidates/graphql-hits.txt" 2>/dev/null || echo 0)"

# ── PHASE 8: NUCLEI SCAN ──────────────────────────────────────────────────────────
log "Phase 8 — Nuclei scan"

run nuclei -l "$OUT/02-surface/live.txt" \
  -tags "takeover,exposure,misconfig,default-login,tech,graphql,cloud,ssrf,idor" \
  -severity "critical,high,medium" \
  -rate-limit "$RATE" -concurrency "$THREADS" \
  -exclude-tags "dos,fuzz,intrusive" \
  -silent \
  -o "$OUT/03-candidates/nuclei-hits.txt"

log "Nuclei hits: $(wc -l < "$OUT/03-candidates/nuclei-hits.txt" 2>/dev/null || echo 0)"

# ── PHASE 9: APPSHEET API PROBES ──────────────────────────────────────────────────
log "Phase 9 — AppSheet-specific API probes"

APP_ID="c5dde27c-49a6-47e4-8529-737cf68a3c12"

for base in "https://api.appsheet.com" "https://eu.appsheet.com" "https://www.appsheet.com"; do
  for path in /api/v2 /api/v2/docs /api/v2/swagger /swagger /openapi.json \
              /api/v2/apps /api/v2/templates /api/v2/users \
              "/api/v2/apps/$APP_ID" "/api/v2/apps/$APP_ID/tables"; do
    code=$(curl -sfLk --max-time 10 \
      -H 'Accept: application/json' \
      -o /tmp/as-resp.json \
      -w "%{http_code}" "${base}${path}" 2>/dev/null || echo "000")
    if [[ "$code" != "000" && "$code" != "404" ]]; then
      echo "API_PROBE [$code]: ${base}${path}"
      cp /tmp/as-resp.json "$OUT/03-candidates/evidence/api-$(echo "${base}${path}" | tr '/:' '--').json" 2>/dev/null || true
    fi
  done
done 2>/dev/null | tee "$OUT/03-candidates/api-probes.txt" || true

log "API probe hits: $(wc -l < "$OUT/03-candidates/api-probes.txt" 2>/dev/null || echo 0)"

# ── PHASE 10: CLOUD BUCKETS ───────────────────────────────────────────────────────
log "Phase 10 — Cloud bucket enumeration"

for pattern in "appsheet" "appsheet-com" "appsheet-data" "appsheet-assets" \
               "appsheet-prod" "appsheet-dev" "appsheet-uploads" \
               "google-appsheet" "appsheet-exports" "appsheet-backup"; do
  code=$(curl -sfk --max-time 8 -w "%{http_code}" \
    -o /tmp/gcs.txt "https://storage.googleapis.com/$pattern" 2>/dev/null || echo "000")
  [[ "$code" == "200" ]] \
    && echo "PUBLIC_GCS: $pattern" \
    && cp /tmp/gcs.txt "$OUT/03-candidates/evidence/gcs-$pattern.xml" 2>/dev/null || true

  code=$(curl -sfk --max-time 8 -w "%{http_code}" \
    -o /tmp/s3.txt "https://$pattern.s3.amazonaws.com" 2>/dev/null || echo "000")
  [[ "$code" == "200" ]] \
    && echo "PUBLIC_S3: $pattern" \
    && cp /tmp/s3.txt "$OUT/03-candidates/evidence/s3-$pattern.xml" 2>/dev/null || true
done 2>/dev/null | tee "$OUT/03-candidates/bucket-hits.txt" || true

log "Bucket hits: $(wc -l < "$OUT/03-candidates/bucket-hits.txt" 2>/dev/null || echo 0)"

# ── SUMMARY ───────────────────────────────────────────────────────────────────────
log "Writing summary..."

cat > "$OUT/RECON-SUMMARY.md" << ENDSUMMARY
# AppSheet Recon Summary
Generated: $(date)

## Counts
- Subdomains:       $(wc -l < "$OUT/01-assets/subdomains.txt" 2>/dev/null || echo 0)
- Live HTTP hosts:  $(wc -l < "$OUT/02-surface/live.txt" 2>/dev/null || echo 0)
- Priority hosts:   $(wc -l < "$OUT/02-surface/priority-hosts.txt" 2>/dev/null || echo 0)
- CNAMEs:           $(wc -l < "$OUT/01-assets/cname-records.txt" 2>/dev/null || echo 0)
- JS files:         $(wc -l < "$OUT/02-surface/js/js-urls.txt" 2>/dev/null || echo 0)
- API endpoints:    $(wc -l < "$OUT/02-surface/api-endpoints.txt" 2>/dev/null || echo 0)

## Candidate Findings
- Takeover hits:    $(wc -l < "$OUT/03-candidates/takeover-hits.txt" 2>/dev/null || echo 0)
- JS secrets:       $(wc -l < "$OUT/02-surface/js/jsluice-secrets.txt" 2>/dev/null || echo 0)
- GraphQL hits:     $(wc -l < "$OUT/03-candidates/graphql-hits.txt" 2>/dev/null || echo 0)
- Nuclei hits:      $(wc -l < "$OUT/03-candidates/nuclei-hits.txt" 2>/dev/null || echo 0)
- Bucket hits:      $(wc -l < "$OUT/03-candidates/bucket-hits.txt" 2>/dev/null || echo 0)
- API doc hits:     $(wc -l < "$OUT/03-candidates/api-docs-hits.txt" 2>/dev/null || echo 0)

## Priority Subdomains
$(cat "$OUT/02-surface/priority-hosts.txt" 2>/dev/null || echo "(none found)")

## Takeover Candidates
$(cat "$OUT/03-candidates/takeover-hits.txt" 2>/dev/null || echo "(none found)")

## JS Secrets
$(cat "$OUT/02-surface/js/jsluice-secrets.txt" 2>/dev/null | head -30 || echo "(none found)")

## GraphQL Hits
$(cat "$OUT/03-candidates/graphql-hits.txt" 2>/dev/null || echo "(none found)")

## Nuclei Findings
$(cat "$OUT/03-candidates/nuclei-hits.txt" 2>/dev/null | head -30 || echo "(none found)")

## Internal Hosts in JS
$(cat "$OUT/02-surface/js/internal-hosts.txt" 2>/dev/null || echo "(none found)")

## API Probe Results
$(cat "$OUT/03-candidates/api-probes.txt" 2>/dev/null || echo "(none found)")

## Review Order
1. cat $OUT/03-candidates/takeover-hits.txt
2. cat $OUT/02-surface/js/jsluice-secrets.txt
3. cat $OUT/02-surface/priority-hosts.txt
4. cat $OUT/03-candidates/nuclei-hits.txt
5. cat $OUT/03-candidates/graphql-hits.txt
6. cat $OUT/02-surface/js/internal-hosts.txt
7. cat $OUT/03-candidates/api-probes.txt
ENDSUMMARY

log "DONE — cat $OUT/RECON-SUMMARY.md"
