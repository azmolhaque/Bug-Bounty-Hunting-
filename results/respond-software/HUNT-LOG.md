# Hunt Log — prod.respond-software.com (Google VRP TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER1 (Respond Software — acquired by Google/Chronicle, Aug 2021)
**Started:** 2026-06-21
**Status:** ACTIVE — Session 1 queued

---

## Scope (from config/scope.yaml)

```
- prod.respond-software.com    # TIER1
```

**Scope notes:**
- Only `prod.respond-software.com` is explicitly listed — TIER1.
- `respond-software.com` apex and other subdomains are NOT listed → TIER4 (OOS). Do not test.
- Acquired August 2021 by Google for Chronicle (security operations suite).

---

## Pre-Recon Thesis

Respond Software built an AI-driven autonomous threat detection and response platform
(SOAR-adjacent). Acquired into Chronicle/Google SecOps. Key characteristics:
- Security orchestration platform → SSRF via integration connectors (same pattern as Siemplify)
- Multi-tenant SaaS → IDOR on incident/alert/case IDs across tenants
- AI/ML-driven detection → potential for prompt injection on alert fields
- Likely integrated with Siemplify/Chronicle backend after acquisition

**Hypothesized attack surface:**
| Rank | Surface | Why | Bug class |
|------|---------|-----|-----------|
| 1 | SOAR integration connectors | URL-based API connectors → SSRF | SSRF |
| 2 | Incident/alert object IDs | Multi-tenant case management → IDOR | IDOR |
| 3 | Self-registration | If trial exists → create account → test authenticated surface | Auth |
| 4 | Unauthenticated API surface | Security platforms often expose health/swagger endpoints | Info |

---

## ⛔ RESPOND SOFTWARE CLOSED — 2026-06-21

`prod.respond-software.com`: NXDOMAIN (no DNS A/CNAME record) + 000 (TCP refused) on all paths.
Host is fully decommissioned. Same pattern as Dataform (DNS SERVFAIL) and Dropcam (blanket 301).
Service was folded into Chronicle/Google SecOps infrastructure post-acquisition with no retained
public hostname.

**PIVOT → Pring cluster (TIER0)**: admin.pring.app, api.pring.jp, dev-api.pring.jp,
staging.callback.pring.app, callback.pring.app — Japanese payment app, highest payout tier.

## Session 1 — 2026-06-21 (DNS + HTTP fingerprint)

### Output

```
DNS: (empty — NXDOMAIN)
All paths: 000 (TCP refused — no listener)
```

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| RSW-L001 | SSRF via connectors | `prod.respond-software.com` integration API | PENDING — needs session 1 |
| RSW-L002 | IDOR on incidents/alerts | `prod.respond-software.com` case management | PENDING — needs session 1 |
| RSW-L003 | Auth surface / registration | Login + trial signup | PENDING — needs session 1 |
