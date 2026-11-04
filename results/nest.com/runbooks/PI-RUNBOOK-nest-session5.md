# PI-RUNBOOK — Nest Session 5 — Final Sweep + Pivot Decision
**Date:** 2026-06-21  
**Status:** FINAL SWEEP — if nothing actionable after this, CLOSE Nest and pivot

---

## PHASE A — alpha.home.nest.com path probe

Root returns 403 (nginx, not IAP). Try specific paths:

```bash
echo "=== alpha.home.nest.com path probe ==="
for PATH in / /health /healthz /api /api/v1 /login /signin /status /robots.txt /.well-known/openid-configuration /v1 /v2 /admin; do
  STATUS=$(curl -sko /dev/null --max-time 10 -w "%{http_code}" "https://alpha.home.nest.com${PATH}")
  echo "alpha.home.nest.com${PATH} → ${STATUS}"
  sleep 1
done
echo ""

echo "=== alpha.home.nest.com / — full headers ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://alpha.home.nest.com/"
echo ""
```

---

## PHASE B — accounts.nest.com CORS probe

```bash
echo "=== accounts.nest.com root — full headers ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36" \
  "https://accounts.nest.com/"
echo ""

echo "=== CORS probe: accounts.nest.com root ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.nest.com/"
echo ""

echo "=== CORS probe: accounts.nest.com /oauth2/token ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.nest.com/oauth2/token"
echo ""

echo "=== CORS probe: accounts.ft.nest.com ==="
curl -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://accounts.ft.nest.com/"
echo ""

echo "=== accounts.nest.com /login — what's there? ==="
curl -sk --max-time 15 -D - "https://accounts.nest.com/login" | head -c 400
echo ""
```

---

## PHASE C — admin.store.nest.com health content

```bash
echo "=== admin.store.nest.com /health — body ==="
curl -sk --max-time 15 "https://admin.store.nest.com/health"
echo ""

echo "=== admin.store.ft.nest.com /health — body ==="
curl -sk --max-time 15 "https://admin.store.ft.nest.com/health"
echo ""

echo "=== admin.store.nest.com / — auth error body ==="
curl -sk --max-time 15 "https://admin.store.nest.com/"
echo ""
```

---

## PIVOT DECISION GATE

After running all three phases:

**CLOSE Nest and pivot if ALL of the following are true:**
- alpha.home.nest.com: all paths 403 (no partial-auth surface found)
- accounts.nest.com: no CORS reflection, no session-gated data endpoint
- admin.store /health: returns only version string or empty (no sensitive data)

**Stay on Nest if ANY of the following:**
- alpha.home.nest.com: any path returns 200 or different 4xx (partial surface)
- accounts.nest.com: CORS reflection + credentials=true (need to verify data endpoint too)
- admin.store /health: returns JSON with internal hostnames, debug keys, or service versions

**Pivot candidates (ranked):**
1. `fleet.home.nest.com` — would need Nest account; IDOR potential on multi-device fleet
2. Photomath IDOR (`portal.photomath.net /api/quiz/grade-quizzes/user/{N}`) — TIER0, active lead (blocked from Pi IP; try via web proxy or mobile)
3. Tenor.com (TIER1) — fresh, no prior recon
4. Dataform (TIER1) — BigQuery integration, SSRF angles

---

## Output

(Paste Pi output here after running)
