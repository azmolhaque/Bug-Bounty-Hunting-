# PI-RUNBOOK — Nest Session 2 — Content Probe + Auth Model
**Date:** 2026-06-21  
**Target cluster:** nest.com / nestlabs.com (Google VRP TIER0/TIER1)  
**Objective:** Determine what `home.ft.nest.com/` actually serves (SPA vs real content),
map the API error format on `api.home.ft.nest.com`, fingerprint CORS on ft hosts,
and collect the redirect URL from `supportadmin.nestlabs.com`.

---

## SAFETY CHECKS (run first, before every session)

```bash
# Confirm scope
grep -E "nest|nestlabs" ~/Bug-Bounty-Hunting-/config/scope.yaml

# No internal/cloud probing — scope limited to these public hosts only
# No brute-force, no destructive writes, no DoS
# Rate limit: 1 req/s minimum between probes
```

---

## PHASE A — What does home.ft.nest.com root actually serve?

```bash
echo "=== home.ft.nest.com / — content sample ==="
curl -sk --max-time 15 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  "https://home.ft.nest.com/" | head -c 800
echo ""
echo "=== home.ft.nest.com / — full response headers ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://home.ft.nest.com/"

echo "=== home.ft.nest.com /robots.txt ==="
curl -sk --max-time 15 "https://home.ft.nest.com/robots.txt"
echo ""

echo "=== home.ft.nest.com /api/v1 — headers + body ==="
curl -sk --max-time 15 -D - \
  "https://home.ft.nest.com/api/v1" | head -c 400
echo ""

echo "=== home.ft.nest.com /api/v1/ with trailing slash ==="
curl -sk --max-time 15 -D - \
  "https://home.ft.nest.com/api/v1/" | head -c 400
echo ""

# Check if a non-existent path 404s or 200s (SPA catch-all test)
echo "=== home.ft.nest.com /this-path-does-not-exist-zz9xyz — SPA catch-all check ==="
curl -sk --max-time 15 -D - -o /dev/null \
  "https://home.ft.nest.com/this-path-does-not-exist-zz9xyz"
echo ""
```

**Decision gate:**
- If `/this-path-does-not-exist-zz9xyz` → **200**: SPA catch-all (same false-positive as biz.waze.com and AppSheet prod). Record but low value.
- If `/this-path-does-not-exist-zz9xyz` → **404**: Real route table. Root 200 is a real endpoint. PURSUE.
- If root `/` body contains `<title>Nest</title>` or similar app HTML: SPA shell.
- If root `/` body is JSON: real unauthenticated API endpoint — HIGH PRIORITY.

---

## PHASE B — CORS check on ft hosts (with credential header)

```bash
echo "=== CORS probe: home.ft.nest.com ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://home.ft.nest.com/"

echo "=== CORS probe: api.home.ft.nest.com ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://api.home.ft.nest.com/"

echo "=== CORS probe: accounts.ft.nest.com ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.ft.nest.com/api/v1"

echo "=== CORS probe: accounts.nest.com (TIER0 prod) ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.nest.com/"
```

**What to look for:** `Access-Control-Allow-Origin: https://evil-attacker.com` AND
`Access-Control-Allow-Credentials: true` → CORS origin reflection (potential data exfil
if a session-gated JSON endpoint exists). Remember FIT-C001 lesson: headers alone aren't
enough — must confirm a session-gated JSON endpoint returns real data cross-origin.

---

## PHASE C — api.home.ft.nest.com error format + auth model

```bash
echo "=== api.home.ft.nest.com / — auth error body ==="
curl -sk --max-time 15 "https://api.home.ft.nest.com/" | head -c 500
echo ""

echo "=== api.home.ft.nest.com /robots.txt ==="
curl -sk --max-time 15 "https://api.home.ft.nest.com/robots.txt"
echo ""

echo "=== api.home.ft.nest.com /health — full response ==="
curl -sk --max-time 15 -D - "https://api.home.ft.nest.com/health"
echo ""

# Check common API paths for version info or auth error details
for PATH in /v1 /v2 /v3 /api /api/v1 /api/v2 /swagger /openapi.json /v1/health /v2/health; do
  STATUS=$(curl -sko /dev/null --max-time 10 -w "%{http_code}" "https://api.home.ft.nest.com${PATH}")
  echo "api.home.ft.nest.com${PATH} → ${STATUS}"
  sleep 1
done
echo ""
```

---

## PHASE D — supportadmin.nestlabs.com redirect target

```bash
echo "=== supportadmin.nestlabs.com — follow redirect chain ==="
curl -sk --max-time 15 -D - -o /dev/null -L \
  --max-redirs 5 \
  "https://supportadmin.nestlabs.com/" 2>&1 | head -40
echo ""

echo "=== supportadmin.nestlabs.com — no-follow, just first redirect ==="
curl -sk --max-time 15 -D - -o /dev/null \
  "https://supportadmin.nestlabs.com/" | head -10
echo ""
```

**What to look for:** Does it redirect to a Google login (`accounts.google.com`), to a
Nest-specific auth page, or to a third-party IdP? If the redirect target is predictable and
contains an open `redirect_uri` parameter, that's an OAuth redirect_uri chain opportunity.

---

## PHASE E — Prod vs ft differential on home.nest.com

```bash
echo "=== home.nest.com / — prod baseline ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://home.nest.com/"

echo "=== home.nest.com /api/v1 — prod baseline ==="
curl -sk --max-time 15 -D - -o /dev/null \
  "https://home.nest.com/api/v1"
echo ""
```

This establishes the baseline: if `home.nest.com/` → 302/301 (auth redirect) but
`home.ft.nest.com/` → 200 (real content), that's the auth bypass differential.

---

## PHASE F — Phase A re-run (DNS fingerprint, fixed loop)

```bash
# Fixed: hardcode hosts, don't use $HOSTS variable
HOSTS="home.nest.com api.home.nest.com beta.home.nest.com alpha.home.nest.com fleet.home.nest.com clips.home.nest.com home.ft.nest.com api.home.ft.nest.com myaccount.nest.com myaccount.ft.nest.com developer-api.nest.com nssbridge.nest.com admin.store.nest.com admin.store.ft.nest.com supportadmin.nestlabs.com accounts.nest.com accounts.ft.nest.com"

echo "=== DNS + HTTP fingerprint (all 18 hosts) ==="
for H in $HOSTS; do
  IP=$(dig +short A "$H" 2>/dev/null | head -1)
  STATUS=$(curl -sko /dev/null --max-time 10 -w "%{http_code}" -A "Chrome/124" "https://${H}/")
  SERVER=$(curl -sk --max-time 10 -D - -o /dev/null -A "Chrome/124" "https://${H}/" 2>/dev/null | grep -i "^server:" | head -1 | tr -d '\r')
  echo "${H} | IP=${IP} | HTTP=${STATUS} | ${SERVER}"
  sleep 1
done
```

---

## Expected output / decision tree

After running all phases, paste the full output below this line.

**If home.ft.nest.com root is a real non-SPA endpoint (404 on random path):**
→ Investigate what the 200 returns. If unauthenticated data: REPORT CANDIDATE.
→ If login page: check for auth bypass paths (/api/v1 without token, debug endpoints).

**If home.ft.nest.com is SPA catch-all:**
→ Mine the JS bundles for real API host + endpoints (spawn js-hunter agent).
→ Focus shifts to accounts.ft.nest.com (TIER0 auth bypass potential).

**If CORS reflection found on ft hosts:**
→ Check whether any ft endpoint returns session-gated JSON. If yes: chain to CORS data read.

---

## Output

(Paste Pi output here after running)
