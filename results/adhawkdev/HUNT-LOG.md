# Hunt Log — adhawkdev.com (Google VRP TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER1 (Adhawk Microsystems — acquired by Google ~2022)
**Started:** 2026-06-21
**Status:** ACTIVE — Session 1 queued

---

## Scope (from config/scope.yaml)

```
- adhawkdev.com    # TIER1
```

**Scope notes:**
- Only `adhawkdev.com` is listed.
- `adhawkmicrosystems.com` is explicitly TIER4 in out_of_scope. Do not test.

---

## Pre-Recon Thesis

Adhawk Microsystems built micro-scale eye-tracking technology (used in AR/VR headsets,
accessibility devices). Acquired by Google ~2022. `adhawkdev.com` is likely a developer
portal or SDK distribution site for the eye-tracking SDK.

**Expected surface:**
- Developer portal (docs, SDK downloads)
- Possibly an authenticated API for eye-tracking data processing
- OAuth/API key management

**Bug classes to investigate:**
- If multi-tenant API: IDOR on eye-tracking sessions/calibration data
- If SDK download portal: path traversal to arbitrary files
- If unauthenticated API endpoints exist: data exposure
- Auth bypass on developer account management

---

## ⛔ ADHAWKDEV CLOSED — 2026-06-21

`adhawkdev.com`: NXDOMAIN (no DNS A/CNAME) + 000 (TCP refused) on all paths.
Fully decommissioned. Eye-tracking SDK/portal has been removed post-acquisition.
Same pattern as Respond Software, Dataform, Dropcam.

**PIVOT → Cameyo cluster (TIER0)**: cameyo.com, online.cameyo.com, session.svc.cameyo.com,
gwebhook.svc.cameyo.com — cloud VDI/application streaming, acquired ~2023, completely untested.

## Session 1 — 2026-06-21

DNS: NXDOMAIN. All paths: 000 (TCP refused).

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| ADH-L001 | TBD | `adhawkdev.com` | PENDING — session 1 |
