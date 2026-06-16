# Hunt Log — chronicle.security

**Program:** Google VRP  
**Target:** chronicle.security (Google Security Operations — former Siemplify SOAR + Chronicle SIEM)  
**Scope confirmed:** IN-SCOPE — matches `chronicle.security` in `config/scope.yaml`  
**Hypothesis:** SOAR connector framework follows same SSRF pattern as AppSheet — connectors make server-side HTTP requests to user-supplied URLs with no centralized egress filter.

---

## Session 1 — 2026-06-16 (Remote — setup only)

**Actions:**
- Confirmed chronicle.security IN-SCOPE via scope-check.sh
- Siemplify.co recon confirmed dead — 161 subdomains, 0 live high-value, all migrated to chronicle.security / Google Cloud
- Created results directory tree
- Created PI-RUNBOOK-chronicle-recon.md with exact Phase 0-4 commands
- Web research running (agent) to map known attack surface, connectors, tech stack

**Pending (next Pi session):**
- Run Phase 1 asset discovery (subfinder + dnsx + httpx)
- Create free/trial chronicle.security account
- Navigate to Integrations/Marketplace — enumerate connector types
- Run SSRF probe on first 5 connector URL fields with interactsh OOB
- Run nuclei exposures/tech-detect scan

**Status:** SETUP — ready for Pi execution

---

## Findings

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| — | — | — | No findings yet — recon not started |
