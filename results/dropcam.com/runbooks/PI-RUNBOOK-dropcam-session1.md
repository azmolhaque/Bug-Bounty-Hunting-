# PI-RUNBOOK — Dropcam Session 1 — DNS + HTTP Fingerprint + WebSocket Probe
**Date:** 2026-06-21
**Target:** dropcam.com (Google VRP TIER1)

**Context:** dropcam.com is actively referenced in the Nest SPA CSP as a WebSocket
camera-streaming backend (`wss://*.dropcam.com:80 wss://*.dropcam.com`). Older
Nest/Google infrastructure — potentially less hardened than current nest.com cluster.

---

## PHASE A — DNS + subdomain fingerprint

```bash
CURL=/usr/bin/curl

echo "=== dropcam.com DNS ==="
dig +short A dropcam.com
dig +short CNAME dropcam.com
dig +short MX dropcam.com

echo "=== Common subdomains ==="
for SUB in www api app web dev staging beta alpha test m mobile camera cameras stream ws wss cdn static media; do
  IP=$(dig +short A "${SUB}.dropcam.com" 2>/dev/null | head -1)
  echo "${SUB}.dropcam.com → ${IP:-NXDOMAIN}"
done
echo ""

echo "=== Nest-related subdomains (from camera streaming context) ==="
for SUB in camera nest live stream api2 app2 accounts auth video clips oauth; do
  IP=$(dig +short A "${SUB}.dropcam.com" 2>/dev/null | head -1)
  echo "${SUB}.dropcam.com → ${IP:-NXDOMAIN}"
done
echo ""
```

---

## PHASE B — HTTP fingerprint on resolvable hosts

```bash
echo "=== dropcam.com root ==="
$CURL -sk --max-time 15 -D - -o /dev/null "https://dropcam.com/"
echo ""

echo "=== www.dropcam.com ==="
$CURL -sk --max-time 15 -D - -o /dev/null "https://www.dropcam.com/"
echo ""

# For any subdomain that resolved in Phase A, add probes here:
# $CURL -sk --max-time 15 -D - -o /dev/null "https://api.dropcam.com/"
```

---

## PHASE C — API surface discovery

```bash
echo "=== dropcam.com API paths ==="
for PATH in /api /api/v1 /api/v2 /api/v3 /health /healthz /v1 /v2 /robots.txt /.well-known/openid-configuration /oauth2/token /cameras /clips /accounts; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" "https://dropcam.com${PATH}")
  echo "dropcam.com${PATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""

echo "=== www.dropcam.com API paths ==="
for PATH in /api /api/v1 /health /v1 /robots.txt /.well-known/openid-configuration; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" "https://www.dropcam.com${PATH}")
  echo "www.dropcam.com${PATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""
```

---

## PHASE D — CORS probe

```bash
echo "=== CORS probe dropcam.com ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://dropcam.com/"

echo "=== CORS probe dropcam.com/api/v1 ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://dropcam.com/api/v1"
echo ""
```

---

## Decision gate

- If dropcam.com is a live API (not just redirect → nest.com): map all paths, look for auth model
- If 401/403 on API paths: what's the auth error body? Same "provide authorization" as Nest? Or different (older Dropcam token system)?
- If any path returns 200 unauthenticated: HIGH PRIORITY
- If all 301/302 → nest.com or home.nest.com: dropcam is just a redirect alias; CLOSE

---

## Output

(Paste Pi output here after running)
