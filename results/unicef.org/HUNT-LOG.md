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
- [x] Captured JSON:API schema — 70 entity types including oauth2 endpoints
- [x] OAuth2 endpoint enumeration — 10 internal UUIDs leaked via meta.omitted across 5 endpoints
- [x] OAuth2 bearer token endpoint returns HTTP 500 (unhandled exception, reachable unauthenticated)

### Phase 4: Verification
- [x] Confirmed unauthenticated HTTP 200 on `/en/jsonapi/user/user`
- [x] Confirmed 10 real `@unicef.org` staff emails in first-page sample
- [x] Full user count confirmed: 13,112 accounts across 263 pages (Pi run, --sample-only + manual pagination count)
- [x] OAuth2 UUID leak confirmed: 1 client UUID, 4 scope UUIDs, 3 consumer UUIDs, 2 config UUIDs
- [x] PoC script verified clean on Pi: all 4 tests pass, 7/7 sensitive entities detected, 0 false positives

### Phase 5: Triage
- [x] F001 passes CLAUDE.md Section 2 (attacker gain: PII + attack enablement)
- [x] F001 passes Section 3 (not in hard-rejection list — real data exposed)
- [x] CVSS assigned: 7.5 High (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
- [x] WAI preemption: framed as email PII disclosure, not username enumeration
- [x] Dedup: no public prior disclosure found for ram.unicef.org JSON:API

### Phase 6: Report
- [x] F001 internal report: `findings/F001-jsonapi-user-enum.md`
- [x] F001 email: `findings/submission/F001-unicef-email-report.md`
- [x] PoC script: `findings/poc-F001-unicef-jsonapi-disclosure.py`
- [x] **SUBMITTED: 2026-06-17 ~03:16 UTC — sent to infosecurity@unicef.org from azmolhaque95@gmail.com**
- [x] Attachment: poc-F001-unicef-jsonapi-disclosure.py.txt (renamed for Gmail filter bypass)

---

## Findings Registry

| ID | Host | Class | Severity | Status |
|---|---|---|---|---|
| F001 | ram.unicef.org | Drupal JSON:API unauth user enum | High (7.5) | **SUBMITTED 2026-06-17** — awaiting Hall of Fame listing |

---

## Dropped Leads

| Host | Class | Reason Dropped |
|---|---|---|
| 263 subdomains via subzy | Subdomain takeover | All NOT VULNERABLE — Azure blocks cross-org CNAME claim |
| www-origin.unicef.org | - | Pi-hole local 127.0.0.1 artifact — not real |
| www-self.unicef.org | - | Pi-hole local 127.0.0.1 artifact — not real |
| etools-demo.unicef.org | WordPress CVEs | Blocked by Cloudflare WAF on all paths including wp-json — no access |
| rdmapi.unicef.org | API endpoint enumeration | Intentionally public reference data — WAI |
| prometheus.inform.unicef.org | Prometheus metrics / default creds | No response (silent) — host unreachable |

**All UNICEF secondary leads closed 2026-06-19.**
