# PI-RUNBOOK — work.webpass.net — Session 2
**Date:** 2026-06-21
**Program:** Google/Alphabet VRP (bughunters.google.com) — TIER1

**Context from Session 1:**
- Rails + Phusion Passenger confirmed. Real route table (not SPA).
- `/invoices/1` → 302 (route exists, integer ID, auth-gated) = IDOR candidate
- `/admin` → 302 (admin panel exists, auth-gated)
- `/users/sign_up` → 302 (destination unknown — may be open registration)
- `/robots.txt` → 200 (needs mining)
- Auth: Authlogic at `/user_sessions/new`. CSP: Genesys Cloud iframe integration.

**Goals this session:**
1. Mine robots.txt for hidden paths
2. Determine if self-registration is possible (`/users/sign_up` redirect chain)
3. Fingerprint auth page (`/user_sessions/new`) — Google OAuth present?
4. Mine JS bundle for routes
5. Follow redirect chains for `/invoices/1` and `/admin` to confirm login wall

**PATH fix:**
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CURL=/usr/bin/curl
```

---

## PHASE A — robots.txt mining

```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CURL=/usr/bin/curl

echo "=== robots.txt ==="
$CURL -sk --max-time 10 "https://work.webpass.net/robots.txt"
echo ""

echo "=== security.txt ==="
$CURL -sk --max-time 10 "https://work.webpass.net/.well-known/security.txt"
echo ""
```

**What to look for:** `Disallow:` lines reveal internal paths (admin panels, API paths, user-specific paths that robots should not index but ARE real routes).

---

## PHASE B — Registration flow investigation

```bash
echo "=== /users/sign_up — follow redirects to final destination ==="
$CURL -sk --max-time 15 -L -D - -o /dev/null \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net/users/sign_up"
echo ""

echo "=== /users/sign_up — one hop only (no -L) ==="
$CURL -sk --max-time 10 -D - -o /dev/null \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net/users/sign_up"
echo ""
```

**What to look for:**
- Redirect lands at `/user_sessions/new` → no self-registration (must be existing customer)
- Redirect lands at `/users/new` or `/register` with a form → OPEN: create test account
- Location header tells us the full destination

---

## PHASE C — Auth page fingerprint

```bash
echo "=== /user_sessions/new — body ==="
$CURL -sk --max-time 15 \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net/user_sessions/new" | \
  /usr/bin/grep -iE '(form|input|action|oauth|google|omniauth|href.*auth|sign.in.with|provider|csrf|authenticity_token|data-provider)' | \
  /usr/bin/head -30
echo ""

echo "=== /user_sessions/new — full title + any OAuth links ==="
$CURL -sk --max-time 15 \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net/user_sessions/new" | \
  /usr/bin/grep -iE '(<title|href.*auth|data-url|omniauth|google|sso|saml|redirect_uri)' | \
  /usr/bin/head -20
echo ""
```

**What to look for:**
- `href="/auth/google_oauth2"` or `href="/auth/google"` → Google SSO button → TEST redirect_uri bypass
- `<form action="/user_sessions"` → email+password form → need ISP account credentials
- SAML link → SSO via corporate IDP

---

## PHASE D — Follow redirect chains

```bash
echo "=== /invoices/1 redirect chain ==="
$CURL -sk --max-time 10 -L -D - -o /dev/null \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net/invoices/1"
echo ""

echo "=== /admin redirect chain ==="
$CURL -sk --max-time 10 -L -D - -o /dev/null \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net/admin"
echo ""
```

**What to look for:**
- `/invoices/1` → login redirect → confirms route is auth-gated (expected; need account)
- `/invoices/1` → 200 without auth → CRITICAL: unauthenticated billing data access
- `/admin` → login redirect confirms admin is auth-gated
- `/admin` → redirect to different admin login (may reveal admin subdomain or path)

---

## PHASE E — JS bundle mining (route discovery)

```bash
echo "=== Find JS bundle URL from page source ==="
$CURL -sk --max-time 15 \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net/user_sessions/new" | \
  /usr/bin/grep -oE 'src="[^"]*\.js[^"]*"' | /usr/bin/head -10
echo ""

# If bundle URL found (e.g. /assets/application-abc123.js):
# Replace BUNDLE_URL below with the actual URL found above
BUNDLE_URL="/assets/application.js"   # placeholder — update from above output

echo "=== Fetch JS bundle ==="
$CURL -sk --max-time 30 \
  -A "Mozilla/5.0 Chrome/124" \
  "https://work.webpass.net${BUNDLE_URL}" -o /tmp/webpass-app.js
/usr/bin/wc -c /tmp/webpass-app.js
echo ""

echo "=== Rails routes from JS bundle ==="
/usr/bin/strings /tmp/webpass-app.js | \
  /usr/bin/grep -oE '"/(api|v[12]|account|invoice|payment|user|service|plan|support|ticket|admin|order|subscription)[a-zA-Z0-9/_\-\.]{0,60}"' | \
  /usr/bin/sort -u | /usr/bin/head -40
echo ""
```

---

## PHASE F — Extended path probe (guided by robots.txt + JS)

Run AFTER Phase A reveals robots.txt paths and Phase E reveals JS routes:

```bash
echo "=== Extended path probe ==="
for URLPATH in /invoices /payments /payments/1 /services /service_orders /service_orders/1 /users /users/1 /users/profile /tickets /tickets/1 /support /plans /subscriptions /subscriptions/1 /account /account/billing /locations /addresses; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
    -A "Mozilla/5.0 Chrome/124" "https://work.webpass.net${URLPATH}")
  echo "work${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""

echo "=== API paths probe ==="
for URLPATH in /api /api/v1 /api/v2 /api/users /api/accounts /api/invoices /api/invoices/1 /api/me /api/profile /api/services /v1/invoices /v1/accounts; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
    -A "Mozilla/5.0 Chrome/124" "https://work.webpass.net${URLPATH}")
  echo "work${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""
```

---

## Decision Matrix

| Observation | Decision |
|-------------|----------|
| `/users/sign_up` redirect → actual registration form | **CRITICAL PATH**: Create test Webpass account → go to Session 3 (authenticated IDOR test) |
| `/users/sign_up` redirect → `/user_sessions/new` | Registration closed → need real ISP account; assess if Google SSO login is testable |
| `/user_sessions/new` has Google OAuth button | Test: `GET /auth/google_oauth2?redirect_uri=https://attacker.com` |
| `/invoices/1` → 200 (no auth) | CRITICAL: document body immediately |
| JS bundle reveals `/api/v1/invoices/:id` | Probe that API path — may have different auth behavior |
| robots.txt reveals `/admin_panel` or similar | Add to path probe immediately |
| All paths → 000 | GCP blocking Pi; pivot to prod.respond-software.com |

---

## Output

(Paste Pi output here after running)
