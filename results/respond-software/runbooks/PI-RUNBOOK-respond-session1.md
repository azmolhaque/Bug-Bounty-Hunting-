# PI-RUNBOOK — prod.respond-software.com — Session 1
**Date:** 2026-06-21
**Program:** Google/Alphabet VRP (bughunters.google.com) — TIER1
**Target:** prod.respond-software.com (Respond Software AI security platform)

**Context:** Respond Software was an AI-driven SOAR/detection platform acquired by Google
in August 2021. It was folded into Chronicle/Google SecOps. The `prod` prefix suggests this
may still serve live traffic or may be a redirector to a new Chronicle URL.

**OOS — do NOT touch:**
- respond-software.com apex (not in scope.yaml)
- Any other respond-software.com subdomains (not listed)

**PATH fix:**
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
dig +short A prod.respond-software.com
dig +short CNAME prod.respond-software.com
echo ""

echo "=== prod.respond-software.com — full headers ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36" \
  "https://prod.respond-software.com/"
echo ""

echo "=== body sample (first 800 bytes) ==="
$CURL -sk --max-time 15 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36" \
  "https://prod.respond-software.com/" | /usr/bin/head -c 800
echo ""
```

**What to look for:**
- 000 (TCP timeout) → dead/internal-only
- 301/302 → where does it redirect? Chronicle? Google? Indicates migration state.
- 200 → live! Check `x-powered-by`, `server`, `via` headers for stack fingerprint
- `x-goog-iap-generated-response` → Google IAP (auth-gated, dead end without Google corp credentials)
- `x-cloud-trace-context` → GCP backend

---

## PHASE B — SPA catch-all detection + path probe

```bash
echo "=== SPA catch-all test ==="
STATUS_RANDOM=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
  "https://prod.respond-software.com/thisdoesnotexist_xhsj38")
echo "Random path → ${STATUS_RANDOM}"
echo "(200 = SPA catch-all; 404 = real route table)"
echo ""

echo "=== Path probe ==="
for URLPATH in / /login /signin /register /signup /api /api/v1 /api/v2 /health /healthz /robots.txt /.well-known/openid-configuration /swagger /swagger/index.html /docs /api/docs /graphql /v1 /v2; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
    -A "Mozilla/5.0 Chrome/124" \
    "https://prod.respond-software.com${URLPATH}")
  echo "prod${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""
```

**Decision gate:**
- 000 on all → DEAD; close immediately
- All → same code (200/302) including random path → SPA catch-all; probe `/api/` prefix
- 200 on `/health` or `/healthz` → JSON health response (real endpoint) — mine the response
- 200 on `/swagger` or `/api/docs` → schema exposure (unauthenticated API docs)
- 301/302 on `/` → follow Location header

---

## PHASE C — If live: API + auth surface

```bash
echo "=== API prefix probe ==="
for URLPATH in /api/v1/health /api/v2/health /api/incidents /api/incidents/1 /api/alerts /api/cases /api/users /api/me /api/profile /api/status /v1/incidents /v1/alerts; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
    -H "Accept: application/json" \
    -A "Mozilla/5.0 Chrome/124" \
    "https://prod.respond-software.com${URLPATH}")
  echo "prod${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""

echo "=== OIDC discovery ==="
$CURL -sk --max-time 10 \
  "https://prod.respond-software.com/.well-known/openid-configuration" | \
  /usr/bin/python3 -m json.tool 2>/dev/null || echo "(not JSON or empty)"
echo ""

echo "=== Registration check ==="
for URLPATH in /register /signup /trial /free /sign_up /create-account /auth/register /api/register /api/signup; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" \
    "https://prod.respond-software.com${URLPATH}")
  echo "prod${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""
```

---

## PHASE D — CORS probe

```bash
echo "=== CORS probe ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  -A "Mozilla/5.0 Chrome/124" \
  "https://prod.respond-software.com/"
echo ""

$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  -H "Accept: application/json" \
  "https://prod.respond-software.com/api/v1/incidents"
echo ""
```

---

## Decision Matrix

| Observation | Action |
|-------------|--------|
| 000 (TCP refused/timeout) | CLOSED — dead host; pivot to adhawkdev.com or Pring |
| 301/302 → chronicle.security or secops.google.com | CLOSED — migrated; already covered |
| 301/302 → respond-software.com apex (OOS) | CLOSED — redirector only |
| 200 + IAP header | CLOSED — corp-gated |
| 200 + real content | PURSUE — run Phases C+D; check Swagger/API schema |
| 200 on `/health` or `/swagger` | HIGH PRIORITY — document immediately |
| 401 on `/api/v1/incidents` (not 404/000) | Route EXISTS — need auth; check trial signup |
| 200 on `/register` or `/trial` | CRITICAL — create account → authenticated IDOR testing |
| CORS: `ACAO: https://evil-attacker.com` + `ACAC: true` | Only if session-gated JSON data confirmed |

---

## Output

(Paste Pi output here after running)
