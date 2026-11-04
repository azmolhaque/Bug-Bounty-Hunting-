# PI-RUNBOOK — Tenor Session 2 — robots.txt + Search + CORS + JS Bundle
**Date:** 2026-06-21
**Target:** tenor.com (Google VRP TIER1)

**Context:** tenor.com is a live App Engine Flex app (build r260617-1-master-a09c, 2026-06-17).
Real route table confirmed. `/search` returns 200. `/api/v1` returns real 404 (not catch-all).
Scope: ONLY `tenor.com` paths — all subdomains (media.tenor.com, c.tenor.com, tenor.co, etc.) are OOS.

**PATH fix (run once before starting):**
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
CURL=/usr/bin/curl
```

---

## PHASE A — robots.txt + route discovery

```bash
echo "=== tenor.com/robots.txt ==="
$CURL -sk --max-time 15 "https://tenor.com/robots.txt"
echo ""

echo "=== tenor.com/search — content sample ==="
$CURL -sk --max-time 15 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  -H "Accept: application/json, text/plain, */*" \
  "https://tenor.com/search?q=cats" | head -c 600
echo ""

echo "=== tenor.com/search — headers (Accept: JSON) ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Accept: application/json" \
  "https://tenor.com/search?q=cats"
echo ""

# Content negotiation: does /search return JSON if we ask?
echo "=== tenor.com/search.json — extension trick ==="
$CURL -sk --max-time 10 -D - -o /dev/null "https://tenor.com/search.json?q=cats"
echo ""
```

---

## PHASE B — GAE standard paths

```bash
echo "=== GAE internal paths ==="
for PATH in /_ah/health /_ah/start /_ah/stop /_ah/warmup /_ah/background /_ah/admin /admin/; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" "https://tenor.com${PATH}")
  echo "tenor.com${PATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""
```

**Decision gate:** `/_ah/admin` returning 200 or 403 (not 404) would be significant — GAE admin console sometimes exposed.

---

## PHASE C — CORS probe

```bash
echo "=== CORS probe: tenor.com root ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://tenor.com/"
echo ""

echo "=== CORS probe: tenor.com/search ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://tenor.com/search?q=cats"
echo ""
```

**What to look for:** `Access-Control-Allow-Origin: https://evil-attacker.com` + `Access-Control-Allow-Credentials: true`
→ only worth pursuing if `/search` or another endpoint returns session-gated user data.

---

## PHASE D — JS bundle mining

From root response headers: `link: </assets/dist/main.min.js?release=r260617-1-master-a09c>; rel=preload`

```bash
echo "=== Fetch tenor.com JS bundle ==="
$CURL -sk --max-time 60 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://tenor.com/assets/dist/main.min.js?release=r260617-1-master-a09c" \
  -o /tmp/tenor-main.js
/usr/bin/wc -c /tmp/tenor-main.js
echo ""

echo "=== API endpoints in bundle ==="
/usr/bin/strings /tmp/tenor-main.js | grep -oE '"https://[^"]{10,100}"' | /usr/bin/tr -d '"' \
  | grep -v 'google-analytics\|doubleclick\|facebook\|googletagmanager\|gstatic' \
  | sort -u | head -60
echo ""

echo "=== API paths in bundle ==="
/usr/bin/strings /tmp/tenor-main.js | grep -oE '"/api/[a-zA-Z0-9/_\-\.]{3,60}"' | sort -u | head -40
echo ""

echo "=== Internal routes in bundle ==="
/usr/bin/strings /tmp/tenor-main.js | grep -oE '"/(v[12]|api|gifapi|internal|admin|account|user|upload)[a-zA-Z0-9/_\-\.]{0,50}"' \
  | sort -u | head -40
echo ""
```

---

## PHASE E — Auth surface discovery

```bash
echo "=== Probe auth-related paths ==="
for PATH in /account /accounts /login /signin /logout /signout /register /signup /api/account /api/user /api/auth /gifapi /gifapi/register /gifapi/search; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" "https://tenor.com${PATH}")
  echo "tenor.com${PATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""
```

---

## Output

(Paste Pi output here after running)
