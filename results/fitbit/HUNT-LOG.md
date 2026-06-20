# Hunt Log — accounts.fitbit.com
Target: accounts.fitbit.com + Fitbit cluster
Program: Google / Alphabet VRP — bughunters.google.com
Tier: TIER1 (Fitbit, acquired 2021, $2.1B)
Started: 2026-06-20

---

## Status Summary

| ID | Class | Surface | Status | Severity |
|----|-------|---------|--------|----------|
| FIT-C001 | CORS Misconfiguration | accounts.fitbit.com — all endpoints | **REPORT NOW** | High (8.1) |

---

## Session 1 — 2026-06-20

### Background

Automated scan (deep-recon-orchestrator v4) surfaced a CORS finding on
`accounts.fitbit.com`. The scanner sent `Origin: https://evil-attacker.com` and
received `Access-Control-Allow-Origin: https://evil-attacker.com` +
`Access-Control-Allow-Credentials: true`.

### Manual Verification

Three curl probes run from Pi 5 (Bangladesh IP, direct connection):

**Probe 1 — OIDC config endpoint:**
```
< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-credentials: true
< access-control-allow-methods: GET, POST, PUT, PATCH, OPTIONS, DELETE
```

**Probe 2 — OAuth token endpoint (`/oauth2/token`):**
```
< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-credentials: true
```

**Probe 3 — User profile API (`/api/1/user/-/profile.json`):**
```
< HTTP/2 200
< access-control-allow-origin: https://evil-attacker.com
< access-control-allow-credentials: true
```

### Decision

**CONFIRMED HIGH — SUBMIT**

All three probes confirm origin reflection + credentials. The `/oauth2/token` and
`/api/1/user/-/profile.json` endpoints are highest impact — OAuth token handling and
user health data are both affected.

Browser PoC still needed before submission (Step 4 in FIT-C001-cors-accounts.md).

### Other Findings Dropped

- API schema paths all returning 10243B → login redirect false positive
- GraphQL bare 200 → no introspection confirmed, informational
- OIDC "exposed" → HTML response, catch-all redirect
- strava.fitbit.com CORS → no credentials=true, not exploitable for session theft
- Siemplify swagger.json → JSON decode error = HTML, not actual schema
- All Apigee findings → 1737B uniform = redirect false positive

### Next Steps

1. Run browser PoC (HTML fetch with victim's session cookies)
2. Screenshot profile data returned to evil origin
3. Submit FIT-C001 to bughunters.google.com
4. While waiting for triage: start Pring or Dataform cluster (both TIER0/1, untested)
