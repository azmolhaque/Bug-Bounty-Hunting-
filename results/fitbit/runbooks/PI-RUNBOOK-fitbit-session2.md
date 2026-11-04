# PI-RUNBOOK — Fitbit Unprobed TIER1 Subdomains — Session 1
**Date:** 2026-06-21
**Program:** Google/Alphabet VRP (bughunters.google.com) — TIER1 (Fitbit health data)

**Context:** We previously hit accounts.fitbit.com (CORS WAI closure, Issue 518912931).
Five Fitbit TIER1 subdomains have never been probed. Admin-class names are top priority.

**In-scope hosts (from scope.yaml):**
- health-admin.fitbit.com  ← TIER1, admin-class name — PROBE FIRST
- mgmt.fitbit.com          ← TIER1, management — PROBE FIRST  
- ngw.fitbit.com           ← TIER1, unknown role
- coaching-dashboard.fitbit.com ← TIER1, dashboard
- strava.fitbit.com        ← TIER1, Strava integration
- (accounts.fitbit.com — closed, WAI)
- (autodiscover, help, myhelp, strava — lower priority)

**PATH fix (always run first):**
```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CURL=/usr/bin/curl
```

---

## PHASE A — DNS + HTTP fingerprint (all five hosts)

```bash
echo "=== DNS fingerprint ==="
for H in health-admin.fitbit.com mgmt.fitbit.com ngw.fitbit.com coaching-dashboard.fitbit.com strava.fitbit.com; do
  IP=$(dig +short A "$H" 2>/dev/null | head -1)
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" -A "Mozilla/5.0 Chrome/124" "https://${H}/")
  echo "${H} | IP=${IP:-NXDOMAIN} | root=${STATUS}"
  /usr/bin/sleep 1
done
echo ""

echo "=== health-admin.fitbit.com — full headers ==="
$CURL -sk --max-time 15 -D - -o /dev/null "https://health-admin.fitbit.com/"
echo ""

echo "=== mgmt.fitbit.com — full headers ==="
$CURL -sk --max-time 15 -D - -o /dev/null "https://mgmt.fitbit.com/"
echo ""
```

---

## PHASE B — Path probe on live hosts

Run for each host that returned non-000 status in Phase A:

```bash
echo "=== health-admin.fitbit.com path probe ==="
for URLPATH in / /health /healthz /api /api/v1 /login /signin /admin /dashboard /robots.txt /.well-known/openid-configuration; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" "https://health-admin.fitbit.com${URLPATH}")
  echo "health-admin${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""

echo "=== mgmt.fitbit.com path probe ==="
for URLPATH in / /health /healthz /api /api/v1 /login /signin /admin /dashboard /robots.txt; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" "https://mgmt.fitbit.com${URLPATH}")
  echo "mgmt${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""

echo "=== ngw.fitbit.com path probe ==="
for URLPATH in / /health /api /api/v1 /robots.txt; do
  STATUS=$($CURL -sko /dev/null --max-time 10 -w "%{http_code}" "https://ngw.fitbit.com${URLPATH}")
  echo "ngw${URLPATH} → ${STATUS}"
  /usr/bin/sleep 1
done
echo ""
```

---

## PHASE C — CORS probe on admin hosts

```bash
echo "=== CORS probe: health-admin.fitbit.com ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://health-admin.fitbit.com/"
echo ""

echo "=== CORS probe: mgmt.fitbit.com ==="
$CURL -sk --max-time 15 -D - -o /dev/null \
  -H "Origin: https://evil-attacker.com" \
  "https://mgmt.fitbit.com/"
echo ""
```

---

## Decision gate

- `health-admin.fitbit.com` / `mgmt.fitbit.com` → **200 or 403 (not 000)**: pursue path probe
- Any path returning 200 pre-auth: HIGH PRIORITY — check if content is admin data or SPA shell
- CORS reflection + credentials=true: ONLY worth pursuing if a session-gated JSON endpoint is found (FIT-C001 lesson)
- All 000 (VPN-only): close immediately

---

## Output

(Paste Pi output here after running)
