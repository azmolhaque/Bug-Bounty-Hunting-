# PI-RUNBOOK — work.webpass.net — Session 1
**Date:** 2026-06-21
**Program:** Google/Alphabet VRP (bughunters.google.com) — TIER1
**Target:** work.webpass.net (Webpass ISP customer portal)

**Context:** Passive recon confirmed work.webpass.net resolves to 34.72.62.205 (GCP us-central1).
Rails app fingerprint from TLS/HTTP headers. ISP billing portal = high-impact IDOR target.
webpass.net apex also TIER1 — probe it too as a secondary.

**OOS — do NOT touch:**
- api.webpass.net (not in scope.yaml)
- www.webpass.net (not in scope.yaml)
- webpass.withgoogle.com (explicitly TIER4)

**PATH fix (run once before starting):**
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CURL=/usr/bin/curl
```

---

## PHASE A — DNS + HTTP fingerprint

```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CURL=/usr/bin/curl

echo "=== DNS ==="
dig +short A work.webpass.net
dig +short A webpass.net
echo ""

echo "=== work.webpass.net — full headers ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36" \
  "https://work.webpass.net/"
echo ""

echo "=== webpass.net — full headers ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36" \
  "https://webpass.net/"
echo ""

echo "=== work.webpass.net — body sample (first 600 bytes) ==="
$CURL -sk --max-time 15 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36" \
  "https://work.webpass.net/" | /usr/bin/head -c 600
echo ""
```

**What to look for:**
- `x-powered-by: Phusion Passenger` or `x-runtime:` or `x-request-id:` → confirmed Rails
- `set-cookie: _session_id=...` or `_webpass_session=...` → Rails session cookie name
- `<title>` tag — confirms app name, logged-in vs. redirect-to-login
- If `location:` header → check if it goes to `/login`, `/users/sign_in` (Devise), or external auth

---

## PHASE B — SPA catch-all detection + path probe

```bash
echo "=== SPA catch-all test ==="
STATUS_RANDOM=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
  "https://work.webpass.net/thisdoesnotexist_xhsj38")
echo "Random path → ${STATUS_RANDOM}"
echo "(if 200 = SPA catch-all; if 404 = real route table)"
echo ""

echo "=== Path probe — work.webpass.net ==="
for URLPATH in / /login /signin /users/sign_in /register /sign_up /users/sign_up /accounts /dashboard /api /api/v1 /api/v2 /health /healthz /robots.txt /.well-known/openid-configuration /.well-known/security.txt /rails/info/properties /admin /admin/users; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
    -A "Mozilla/5.0 Chrome/124" \
    "https://work.webpass.net${URLPATH}")
  echo "work${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""
```

**Decision gate:**
- 200 on `/register` or `/sign_up` → PRIORITY: create test account → authenticated testing
- 200 on `/rails/info/properties` → Rails debug mode exposed → reportable
- 200 on `/admin` or `/admin/users` → admin panel exposed → CRITICAL
- 404 on all paths (not catch-all) → real route table exists, probe further paths
- 000 on everything → GCP firewall blocking our IP; try from different IP

---

## PHASE C — Auth surface identification

```bash
echo "=== Devise auth paths ==="
for URLPATH in /users/sign_in /users/sign_up /users/password/new /users/confirmation/new /users/unlock/new /auth/google_oauth2 /auth/failure; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
    "https://work.webpass.net${URLPATH}")
  echo "work${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""

echo "=== /users/sign_in body (check for CSRF token + form fields) ==="
$CURL -sk --max-time 15 \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net/users/sign_in" | \
  /usr/bin/grep -iE '(input|form|action|csrf|authenticity|oauth|google|class="provider")' | \
  /usr/bin/head -20
echo ""

echo "=== /auth/google_oauth2 — does it redirect to Google? ==="
$CURL -sk --max-time 10 -D - -o /dev/null \
  "https://work.webpass.net/auth/google_oauth2"
echo ""
```

**What to look for:**
- `authenticity_token` in form → standard Rails CSRF (baseline, not vuln)
- `/auth/google_oauth2` → Google OAuth via OmniAuth (note `redirect_uri` in location)
- Any `state=` parameter → check if state is predictable/fixed (state fixation = CSRF on OAuth)
- Login form with email+password → try creating account if registration exists

---

## PHASE D — IDOR surface discovery (if any path returns 200)

```bash
echo "=== Account/billing API paths ==="
for URLPATH in /accounts /accounts/1 /accounts/2 /account /profile /invoices /invoices/1 /services /services/1 /customers /customers/1 /api/v1/accounts /api/v1/accounts/1 /api/v1/invoices /api/v1/profile /api/v1/me; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
    -A "Mozilla/5.0 Chrome/124" \
    "https://work.webpass.net${URLPATH}")
  echo "work${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""
```

**Decision gate:**
- 401/403 on `/accounts/1` → auth-gated (correct); need login first
- 200 on `/accounts/1` (no auth) → CRITICAL: unauth IDOR on account data
- 302 to login on `/accounts/1` → need account to test IDOR

---

## PHASE E — Rails-specific exposure check

```bash
echo "=== Rails info + debug exposures ==="
for URLPATH in /rails/info/properties /rails/info/routes /rails/mailers /assets/application.js /assets/application.min.js /.env /config/database.yml /Gemfile /Gemfile.lock; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
    "https://work.webpass.net${URLPATH}")
  echo "work${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""

echo "=== robots.txt + security.txt ==="
$CURL -sk --max-time 10 "https://work.webpass.net/robots.txt"
echo ""
$CURL -sk --max-time 10 "https://work.webpass.net/.well-known/security.txt"
echo ""
```

**Decision gate:**
- `/rails/info/properties` → 200 with Ruby/Rails version info → reportable if chains to version with known CVE
- `/assets/application.js` → 200 → mine for internal API routes
- Any config file (`.env`, `database.yml`) → 200 → CRITICAL

---

## PHASE F — CORS probe

```bash
echo "=== CORS probe: work.webpass.net ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net/"
echo ""

echo "=== CORS probe: work.webpass.net /api/v1 ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://work.webpass.net/api/v1"
echo ""
```

---

## Decision Matrix

| Observation | Next Action |
|-------------|-------------|
| 200 on `/register` or `/users/sign_up` | Create test account immediately → authenticated IDOR testing (Session 2) |
| 200 on `/rails/info/properties` | Document — Rails debug mode in production (check Rails version for CVE chain) |
| 200 on `/admin` with any content | CRITICAL — document headers + body sample |
| 000 on all paths | GCP firewall; pivot to prod.respond-software.com |
| SPA catch-all (200 on random path) | Identify `/api/` prefix → probe those paths directly |
| 401/403 on auth paths + no registration | BLOCKED — need Webpass ISP account; pivot to other target |
| OAuth redirect to Google | Note `redirect_uri` + `state` values; test redirect_uri bypass in Session 2 |

---

## Output

(Paste Pi output here after running)
