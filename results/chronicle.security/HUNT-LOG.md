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

**OSINT findings (web research, no live access):**
- Backend: Python (SOAR actions/connectors), GCP-native (SIEM); Swagger at `{tenant}.siemplify-soar.com/swagger/index.html` — still live post-migration
- Primary SSRF surface: **Feed Management HTTP(S) source** — Google backend fetches user-supplied URL per official docs, no documented IP blocklist
- Secondary SSRF: 300+ integration connectors each with API URL fields
- New attack surface: TIN Agent + Agentic Automation (Public Preview, Nov 2025–2026) — AI reads alert content → prompt injection
- IDOR: SOAR legacy REST API case/integration IDs in URL paths
- Zero prior public CVEs for Siemplify/Chronicle — low-competition target
- Tenant URL: `{customer}.backstory.chronicle.security`, legacy `{tenant}.siemplify-soar.com`

**Pending (next Pi session):**
- Pull: `git pull` to get runbook
- Create free/trial chronicle.security account at cloud.google.com/security/products/security-operations
- Phase 1: subfinder + dnsx + httpx against chronicle.security
- Phase 3A: Feed Management SSRF test (OOB listener → HTTP(S) feed source)
- Phase 3B: Integration connector URL field tests (Jira, ServiceNow, PagerDuty, Slack)
- Phase 3C: Open Swagger at `{tenant}.siemplify-soar.com/swagger/index.html` — enumerate endpoints, test IDOR
- Phase 3D: TIN Agent prompt injection (if available on free tier)

**Status:** SETUP — ready for Pi execution

---

## Findings

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| — | — | — | No findings yet — recon not started |
