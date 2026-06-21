# PI-RUNBOOK — Nest Session 3 — JS Mining + TIER0 Auth + CSP Hosts
**Date:** 2026-06-21  
**Target cluster:** nest.com / nestlabs.com (Google VRP TIER0/TIER1)  

**Objectives (priority order):**
1. Extract JS bundle URLs from `home.ft.nest.com`, fetch them, mine for API endpoints/secrets
2. Probe `accounts.nest.com` (TIER0) — CORS, OAuth redirect_uri, error differential
3. DNS + HTTP fingerprint `phoenix.nest.com` and `www5.dev.nestlabs.com` (found in CSP)
4. Probe `/health` + `/healthz` content on `admin.store.nest.com`

---

## PHASE A — JS bundle extraction from home.ft.nest.com SPA

```bash
echo "=== Step 1: Fetch index HTML, extract script src URLs ==="
curl -sk --max-time 15 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://home.ft.nest.com/" \
  | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//'
echo "---"

echo "=== Step 2: Also check for <script> tags without quotes and link tags ==="
curl -sk --max-time 15 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://home.ft.nest.com/" \
  | grep -oE "(src|href)=['\"][^'\"]+\.(js|css)[^'\"]*['\"]" | head -30
echo "---"

echo "=== Step 3: Check /static/ and /assets/ paths common in SPAs ==="
for PATH in /static/ /assets/ /js/ /dist/ /build/ /app/; do
  STATUS=$(curl -sko /dev/null --max-time 10 -w "%{http_code}" "https://home.ft.nest.com${PATH}")
  echo "home.ft.nest.com${PATH} → ${STATUS}"
  sleep 1
done
```

**After getting JS URLs from Step 1/2, fetch each bundle and mine it:**

```bash
# Replace BUNDLE_URL with each URL found above (relative → prepend https://home.ft.nest.com)
# Example: BUNDLE_URL="https://home.ft.nest.com/static/js/main.abc123.js"

# Mine for: API hosts, internal URLs, hardcoded tokens/keys, GraphQL schemas
BUNDLE_URL="REPLACE_WITH_ACTUAL_URL"
curl -sk --max-time 30 "$BUNDLE_URL" | strings | grep -E \
  "(api\.|internal\.|nest\.com|nestlabs\.com|googleapis\.com|phoenix|https?://[a-z0-9\-\.]+\.(nest|nestlabs|google)\.com)" \
  | sort -u | head -50
echo "---"

# Mine for hardcoded tokens, client IDs, API keys
curl -sk --max-time 30 "$BUNDLE_URL" | strings | grep -iE \
  "(apikey|api_key|client_id|client_secret|access_token|auth_token|bearer|x-api-key|secret)" \
  | grep -v "//.*apikey" | head -30
echo "---"

# Mine for all HTTPS endpoints in bundle
curl -sk --max-time 30 "$BUNDLE_URL" | grep -oE 'https://[a-zA-Z0-9\.\-]+/[a-zA-Z0-9/\-_\.]+' \
  | sort -u | head -60
```

**Decision gate:**
- If JS contains `phoenix.nest.com` endpoints: add to NST-L005 with specific paths found
- If JS contains hardcoded tokens/API keys: HIGH PRIORITY — verify scope, report if real credential
- If JS reveals internal API host different from `api.home.ft.nest.com`: new host to probe

---

## PHASE B — accounts.nest.com TIER0 probe

```bash
echo "=== accounts.nest.com — basic fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://accounts.nest.com/"

echo "=== accounts.ft.nest.com — ft variant fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://accounts.ft.nest.com/"

echo ""
echo "=== CORS probe: accounts.nest.com ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.nest.com/"

echo "=== CORS probe: accounts.ft.nest.com ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.ft.nest.com/"

echo "=== CORS probe on API paths (accounts.nest.com) ==="
for PATH in /api/v1/login /api/v1/user /api/v1/me /oauth2/token /.well-known/openid-configuration; do
  echo "--- accounts.nest.com${PATH} ---"
  curl -sk --max-time 10 -D - -o /dev/null \
    -H "Origin: https://evil-attacker.com" \
    "https://accounts.nest.com${PATH}" | grep -iE "(access-control|http/|location:)"
  sleep 1
done

echo ""
echo "=== accounts.nest.com — OIDC discovery ==="
curl -sk --max-time 15 "https://accounts.nest.com/.well-known/openid-configuration" | head -c 1000
echo ""

echo "=== accounts.ft.nest.com — OIDC discovery ==="
curl -sk --max-time 15 "https://accounts.ft.nest.com/.well-known/openid-configuration" | head -c 1000
echo ""
```

**What to look for on accounts.nest.com:**
- OIDC discovery endpoint: extract `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`
- CORS reflection: any reflected ACAO + ACAC=true combination (only valuable if endpoint returns
  session-gated data — remember FIT-C001 lesson)
- ft vs prod differential: does `accounts.ft.nest.com` serve the same auth flow?

---

## PHASE C — CSP host discovery: phoenix.nest.com + www5.dev.nestlabs.com

```bash
echo "=== phoenix.nest.com DNS ==="
dig +short A phoenix.nest.com
dig +short CNAME phoenix.nest.com

echo "=== www5.dev.nestlabs.com DNS ==="
dig +short A www5.dev.nestlabs.com
dig +short CNAME www5.dev.nestlabs.com

echo "=== api.phoenix.nest.com DNS ==="
dig +short A api.phoenix.nest.com

echo "=== *.phoenix.nest.com sampling ==="
for SUB in www api app web dev staging test; do
  IP=$(dig +short A "${SUB}.phoenix.nest.com" 2>/dev/null | head -1)
  echo "${SUB}.phoenix.nest.com → ${IP:-NXDOMAIN}"
done

echo ""
echo "=== HTTP probe: www5.dev.nestlabs.com ==="
curl -sk --max-time 15 -D - -o /dev/null \
  "https://www5.dev.nestlabs.com/"

echo "=== HTTP probe: phoenix.nest.com ==="
curl -sk --max-time 15 -D - -o /dev/null \
  "https://phoenix.nest.com/"
```

**Scope check before interacting with any new host:**
```bash
# Confirm nestlabs.com is in scope
grep -E "nestlabs|phoenix" ~/Bug-Bounty-Hunting-/config/scope.yaml
```

**Decision gate:**
- If `www5.dev.nestlabs.com` resolves and is HTTP-accessible: VERY HIGH PRIORITY — dev servers
  often have debug interfaces, relaxed auth, or admin UIs. Fingerprint immediately.
- If `phoenix.nest.com` resolves: map subdomains (`api.`, `app.`, etc.) and probe.
- If NXDOMAIN: leads closed.

---

## PHASE D — admin.store.nest.com health endpoint content

```bash
echo "=== admin.store.nest.com /health ==="
curl -sk --max-time 15 "https://admin.store.nest.com/health"
echo ""

echo "=== admin.store.nest.com /healthz ==="
curl -sk --max-time 15 "https://admin.store.nest.com/healthz"
echo ""

echo "=== admin.store.ft.nest.com /health ==="
curl -sk --max-time 15 "https://admin.store.ft.nest.com/health"
echo ""

echo "=== admin.store.ft.nest.com /healthz ==="
curl -sk --max-time 15 "https://admin.store.ft.nest.com/healthz"
echo ""

# Probe auth error format — what does the 403 body say?
echo "=== admin.store.nest.com / body (403) ==="
curl -sk --max-time 15 "https://admin.store.nest.com/"
echo ""

# Common admin paths
for PATH in /admin /login /signin /api /api/v1 /dashboard; do
  STATUS=$(curl -sko /dev/null --max-time 10 -w "%{http_code}" "https://admin.store.nest.com${PATH}")
  echo "admin.store.nest.com${PATH} → ${STATUS}"
  sleep 1
done
```

**What to look for:**
- Health endpoint returning JSON with version, environment, or dependency info
- 403 body — "Forbidden" vs IAP redirect vs custom auth page reveals the auth model
- Any 200 on paths below / (login page = potential auth bypass angle)

---

## Output

(Paste Pi output here after running)
