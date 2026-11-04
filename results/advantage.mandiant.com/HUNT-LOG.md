# Hunt Log — Mandiant Advantage (TIER1)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER1 (Mandiant, acquired Sept 2022 — $5.4B)
**Started:** 2026-06-21
**Status:** RECON — Session 1 runbook ready, awaiting Pi execution

---

## Scope (from config/scope.yaml — TIER1)

```
- advantage.mandiant.com
- *.advantage.mandiant.com   # VERIFY: asm-api-dev, asm-api-staging, asm-dev, asm-staging
- api.advantage.mandiant.com
- advantage-api.mandiant.com
- intel.mandiant.com         # NXDOMAIN as of 2026-06-21
- md.mandiant.com
- md-us.mandiant.com
- msvportal.mandiant.com
- plextrac.mandiant.com
- validation.mandiant.com
- mandiant.com               # apex TIER4; specific subdomains listed above are TIER1
```

**NOTE:** `mandiant.com` apex is TIER4. Only the explicitly listed subdomains are in scope.
`*.advantage.mandiant.com` — VERIFY at bughunters.google.com before active testing on dev/staging variants.

---

## Pre-Recon Thesis

Mandiant Advantage is Google's B2B threat intelligence and SOAR platform. It offers:
- **Attack Surface Management (ASM)** — external exposure discovery
- **Threat Intelligence** — IOC/actor/campaign data
- **Automated Defense** — detection orchestration
- **Validation** — breach-and-attack simulation

Cloud env fingerprint (2026-06-21): all in-scope hosts resolve and return 403 from cloud env
(egress gateway block); actual HTTP responses need Pi probing.

### DNS fingerprint (cloud env)

| Host | IP | Notes |
|------|----|-------|
| advantage.mandiant.com | 34.117.43.50 | GCP GCLB |
| api.advantage.mandiant.com | 162.159.240.125 | Cloudflare |
| md.mandiant.com | 99.83.191.89 | AWS Global Accelerator |
| validation.mandiant.com | 162.159.241.125 | Cloudflare |
| msvportal.mandiant.com | 162.159.x.x | Cloudflare |
| plextrac.mandiant.com | Cloudflare | Plextrac pentest platform |
| intel.mandiant.com | NXDOMAIN | Dead |

**Key insight:** `api.advantage.mandiant.com` and `validation.mandiant.com` are on Cloudflare,
not GCP. This suggests they may be older infrastructure or separately managed.

### Attack Surface Hypotheses (ranked)

| Rank | Surface | Why | Bug class |
|------|---------|-----|-----------|
| 1 | `api.advantage.mandiant.com` | REST API — multi-tenant; Cloudflare (separate WAF) | IDOR (org/asset IDs), auth bypass |
| 2 | `*.advantage.mandiant.com` dev/staging | Scope comments say asm-api-dev, asm-api-staging present | Auth bypass / env differential |
| 3 | `validation.mandiant.com` | BAS simulation engine — may accept user-supplied IP/URL targets | SSRF |
| 4 | `md.mandiant.com` / `md-us.mandiant.com` | "MD" = Mandiant Defend? Multi-tenant data platform | IDOR |
| 5 | `plextrac.mandiant.com` | Plextrac is a separate pentest platform product | Auth bypass / IDOR |
| 6 | `msvportal.mandiant.com` | MSV = Managed Security; likely customer portal | Auth, IDOR |

**Free tier:** advantage.mandiant.com offers a free community account (Mandiant Threat Intelligence free tier).
Register at advantage.mandiant.com → enables authenticated API testing.

---

## Session 1 — 2026-06-21

[Pending Pi probe output — see runbooks/PI-RUNBOOK-mandiant-session1.md]

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| MND-L001 | IDOR / Auth | `api.advantage.mandiant.com` | PENDING — session 1 |
| MND-L002 | SSRF | `validation.mandiant.com` | PENDING — session 1 |
| MND-L003 | Auth bypass | `*.advantage.mandiant.com` dev/staging | PENDING — session 1 |
