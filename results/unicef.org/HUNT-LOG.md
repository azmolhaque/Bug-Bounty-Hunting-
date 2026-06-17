# UNICEF Hunt Log — unicef.org

## Session 1 — 2026-06-17

### Phase 0: Scope & Authorization
- [x] `config/scope-unicef.yaml` created — in-scope: `unicef.org`, `*.unicef.org`
- [x] `scripts/unicef-recon.sh` and `scripts/unicef-hunt.sh` created and chmod +x
- [x] `results/unicef.org/00-plan.md` written — primary thesis: Drupal JSON:API + subdomain takeover

### Phase 1: Asset Discovery
- [x] subfinder + crt.sh + gau/waybackurls + amass — 263 subdomains enumerated
- [x] dnsx resolution — 190+ live hosts
- [x] CNAME extraction for takeover candidates

### Phase 2: Attack Surface Mapping
- [x] httpx probing — 190+ hosts probed, tech detection enabled
- [x] Drupal instance detection — 11 Drupal instances identified
- [x] JSON:API probe — `ram.unicef.org/jsonapi` returned HTTP 200 (all others 403/301)
- [x] subzy takeover scan — 263 targets, 0 vulnerable (Azure CNAME protection — not claimable)
- [x] JS file inventory — not completed (SSH disconnect during Phase 2e katana)

### Phase 3: Vulnerability Discovery
- [x] Probed `ram.unicef.org/en/jsonapi/user/user` — HTTP 200, staff emails exposed
- [x] Captured JSON:API schema — 60+ entity types including oauth2 endpoints
- [ ] OAuth2 endpoint enumeration — schema confirmed, content probe PENDING (needs Pi run)
- [ ] Admin panel discovery (ffuf) — not yet run
- [ ] nuclei scan — not yet run

### Phase 4: Verification
- [x] Confirmed unauthenticated HTTP 200 on `/en/jsonapi/user/user`
- [x] Confirmed 4 real `@unicef.org` staff emails in response
- [x] Schema JSON:API file uploaded to session as proof
- [ ] Full user count — PENDING (Pi command in F001 Section 6)
- [ ] OAuth2 probe result — PENDING

### Phase 5: Triage
- [x] F001 passes CLAUDE.md Section 2 (attacker gain: PII + attack enablement)
- [x] F001 passes Section 3 (not in hard-rejection list — real data exposed)
- [x] CVSS assigned: 5.3 Medium (standalone) / 7.5 High (if OAuth2 confirms)
- [x] Dedup: no public prior disclosure found for ram.unicef.org JSON:API

### Phase 6: Report
- [x] F001 internal report: `findings/F001-jsonapi-user-enum.md`
- [x] F001 email draft: `findings/submission/F001-unicef-email-report.md`
- [ ] Submission: PENDING — complete Pi verification first (Section 6 of F001)

---

## Findings Registry

| ID | Host | Class | Severity | Status |
|---|---|---|---|---|
| F001 | ram.unicef.org | Drupal JSON:API unauth user enum | Medium (5.3) / High (7.5) | Verified — pending full PoC |

---

## Dropped Leads

| Host | Class | Reason Dropped |
|---|---|---|
| 263 subdomains via subzy | Subdomain takeover | All NOT VULNERABLE — Azure blocks cross-org CNAME claim |
| www-origin.unicef.org | - | Pi-hole local 127.0.0.1 artifact — not real |
| www-self.unicef.org | - | Pi-hole local 127.0.0.1 artifact — not real |

---

## Secondary Leads (Uninvestigated)

| Host | Lead | Priority |
|---|---|---|
| rdmapi.unicef.org | API endpoint enumeration | P1 |
| etools-demo.unicef.org | WordPress 4.7.3 (multiple CVEs) | P1 |
| prometheus.inform.unicef.org | Prometheus metrics endpoint, possible default creds | P1 |
