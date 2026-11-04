# PI-RUNBOOK — Nest Session 4 — JS Mining + TIER0 OIDC + Unprobed Hosts
**Date:** 2026-06-21  
**Target cluster:** nest.com (Google VRP TIER0/TIER1)

**SCOPE REMINDER:** Only probe hosts explicitly listed in config/scope.yaml.
- phoenix.nest.com: OUT OF SCOPE — do not probe
- www5.dev.nestlabs.com / www5.web-dev.s1.nestlabs.com: OUT OF SCOPE — do not probe
- integration.store.nest.com: OUT OF SCOPE — do not probe

---

## PHASE A — JS bundle mining (home.ft.nest.com main bundles)

### Step 1: Fetch the main app bundle
```bash
echo "=== Fetching main app bundle ==="
curl -sk --max-time 60 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://home.ft.nest.com/js/main-30c9a58864910c0d57f2.js" \
  -o /tmp/nest-main.js
wc -c /tmp/nest-main.js
echo ""

echo "=== API hosts embedded in main bundle ==="
strings /tmp/nest-main.js | grep -oE 'https?://[a-zA-Z0-9\.\-]+\.(nest|nestlabs|dropcam|google)\.com[a-zA-Z0-9/\-_\.%]*' \
  | grep -v '//google\|//www\.google\|analytics\|tagmanager\|gstatic\|fonts\.google\|doubleclick\|adsense' \
  | sort -u
echo ""

echo "=== Hardcoded tokens/keys in main bundle ==="
strings /tmp/nest-main.js | grep -iE '(apikey|api_key|client_id|client_secret|access_token|auth_token|bearer|secret|x-api-key)' \
  | grep -v '//\|/\*\|window\.\|document\.' \
  | head -30
echo ""

echo "=== All https:// endpoints extracted from main bundle ==="
strings /tmp/nest-main.js | grep -oE '"https://[^"]{10,100}"' | tr -d '"' | sort -u | head -80
echo ""
```

### Step 2: Fetch shared core bundle
```bash
echo "=== Fetching shared core bundle ==="
curl -sk --max-time 60 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://home.ft.nest.com/js/_shared_/main-b15efb8dfb535b5c78cb.js" \
  -o /tmp/nest-shared.js
wc -c /tmp/nest-shared.js

echo "=== API paths in shared bundle ==="
strings /tmp/nest-shared.js | grep -oE '"/[a-z][a-z0-9/_\-]{5,60}"' | sort -u | head -60
echo ""

echo "=== API hosts in shared bundle ==="
strings /tmp/nest-shared.js | grep -oE 'https?://[a-zA-Z0-9\.\-]+\.(nest|nestlabs|dropcam|google)\.com[/a-zA-Z0-9\-_\.]*' \
  | sort -u
echo ""
```

### Step 3: Fetch security module (highest sensitivity — auth/device access)
```bash
echo "=== Fetching security module ==="
curl -sk --max-time 60 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://home.ft.nest.com/css/security-c7179311710ad7c2fc43.js" \
  -o /tmp/nest-security.js

echo "=== Security module API references ==="
strings /tmp/nest-security.js | grep -oE 'https?://[a-zA-Z0-9\.\-]+\.(nest|nestlabs|dropcam)\.com[/a-zA-Z0-9\-_\.]*' \
  | sort -u
echo ""

echo "=== Endpoints in security module ==="
strings /tmp/nest-security.js | grep -oE '"/[a-z][a-z0-9/_\-\.]{5,80}"' | sort -u | head -50
echo ""
```

**Decision gate after JS mining:**
- Any in-scope host NOT yet in scope.yaml → add and probe
- Any hardcoded API key, token, or client_secret → HIGH PRIORITY (verify it's real before reporting)
- API paths revealing IDOR opportunity (e.g. `/api/v1/users/{id}/devices`) → follow up
- Auth logic: how does the app get its JWT/bearer? If from accounts.nest.com OAuth flow → TIER0 

---

## PHASE B — accounts.nest.com TIER0 (re-run, cut off in Session 3)

```bash
echo "=== accounts.nest.com root fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://accounts.nest.com/"
echo ""

echo "=== accounts.ft.nest.com root fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://accounts.ft.nest.com/"
echo ""

echo "=== accounts.nest.com OIDC discovery ==="
curl -sk --max-time 15 "https://accounts.nest.com/.well-known/openid-configuration" | python3 -m json.tool 2>/dev/null || curl -sk --max-time 15 "https://accounts.nest.com/.well-known/openid-configuration" | head -c 1000
echo ""

echo "=== accounts.ft.nest.com OIDC discovery ==="
curl -sk --max-time 15 "https://accounts.ft.nest.com/.well-known/openid-configuration" | python3 -m json.tool 2>/dev/null || curl -sk --max-time 15 "https://accounts.ft.nest.com/.well-known/openid-configuration" | head -c 1000
echo ""

echo "=== CORS probe accounts.nest.com ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.nest.com/"
echo ""

echo "=== CORS probe accounts.nest.com OIDC endpoint ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.nest.com/.well-known/openid-configuration"
echo ""

echo "=== accounts.nest.com /api/v1/login — status + headers ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.nest.com/api/v1/login"
echo ""
```

**What to look for:**
- OIDC discovery JSON: extract `authorization_endpoint`, `token_endpoint`, `jwks_uri`
- Any `redirect_uris` list in the OIDC response (reveals what redirect_uri values are registered)
- CORS: `Access-Control-Allow-Origin: https://evil-attacker.com` + `Access-Control-Allow-Credentials: true`
  → only actionable if a session-gated JSON endpoint returns data (remember FIT-C001 lesson)
- ft vs prod differential in OIDC config

---

## PHASE C — Unprobed TIER1 hosts

```bash
echo "=== fleet.home.nest.com — fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null "https://fleet.home.nest.com/"
curl -sk --max-time 15 -D - -o /dev/null "https://fleet.home.nest.com/health"
echo ""

echo "=== clips.home.nest.com — fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null "https://clips.home.nest.com/"
curl -sk --max-time 15 -D - -o /dev/null "https://clips.home.nest.com/health"
echo ""

echo "=== nssbridge.nest.com — fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null "https://nssbridge.nest.com/"
curl -sk --max-time 15 -D - -o /dev/null "https://nssbridge.nest.com/health"
echo ""

echo "=== beta.home.nest.com — fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null "https://beta.home.nest.com/"
echo ""

echo "=== alpha.home.nest.com — fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null "https://alpha.home.nest.com/"
echo ""

echo "=== myaccount.nest.com — fingerprint ==="
curl -sk --max-time 15 -D - -o /dev/null "https://myaccount.nest.com/"
curl -sk --max-time 15 "https://myaccount.nest.com/" | head -c 300
echo ""

# admin.store health content (still unread)
echo "=== admin.store.nest.com /health content ==="
curl -sk --max-time 15 "https://admin.store.nest.com/health"
echo ""
echo "=== admin.store.ft.nest.com /health content ==="
curl -sk --max-time 15 "https://admin.store.ft.nest.com/health"
echo ""
```

**Decision gate:**
- `fleet.home.nest.com`: If it returns real JSON on any path → IDOR angle (fleet = multi-device/multi-tenant)
- `nssbridge.nest.com`: "NSS" likely = Nest Security System; any pre-auth endpoint = high value
- `clips.home.nest.com`: Likely camera clip storage API; cross-account clip access = critical

---

## Output

(Paste Pi output here after running)
