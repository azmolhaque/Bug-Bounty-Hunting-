# Hunt Log — virustotal.com (Google VRP TIER1)
Started: 2026-06-13

| Time | Phase | Action | Finding |
|------|-------|---------|---------|
| 2026-06-13 | 0 | Scope confirmed | `virustotal.com`, `www.virustotal.com`, `virustotal-plugins.com`, `gtidocs.virustotal.com` IN-SCOPE TIER1 |
| 2026-06-13 | 0 | Plan written | See `00-plan.md` — 5 hypotheses, H1 (SSRF→IMDS) is CRITICAL priority |
| 2026-06-13 | 1-2 | Recon ran on Pi | 8 live subdomains; API v3 surface mapped; no unauth GraphQL |
| 2026-06-13 | 3 | H1 SSRF — URL submission | `metadata.google.internal` rejected 400; `169.254.169.254` accepted and queued |
| 2026-06-13 | 3 | H1 SSRF — OOB confirmed | webhook.site received 19 requests from GCP IPs 35.187.132.96-102 + 8.228.6.118; User-Agent: Chrome/124 Linux |
| 2026-06-13 | 3 | H1 SSRF — IMDS **CONFIRMED** | `GET /api/v3/urls/{id}` returned `"Server": "Metadata Server for VM"` in `last_http_response_headers`; `last_http_response_code: 404`; `times_submitted: 423` |
| 2026-06-13 | 3 | H4 User IDOR | admin/test/support users exist (200 OK); no email or private data exposed; IDOR not confirmed |
| 2026-06-13 | 3 | H5 Premium endpoints | 403/404 on all — no differential leak |
| 2026-06-13 | 4 | Report written | **F001** — `findings/F001-ssrf-gcp-imds-via-url-scanner.md` — CVSS 8.5 HIGH |
| 2026-06-13 | 4 | GCP path escalation | `scripts/vt-gcp-ssrf.sh` ready — tests `/computeMetadata/v1beta1/` token endpoint; **MUST RUN ON PI** |
| 2026-06-14 | 5 | Triage complete | CVSS `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` = 5.0 Medium; VRP internal tier expected High; submission text finalized in `findings/submission/` |
| 2026-06-14 | 6 | **SUBMITTED to Google VRP** | Issue **#523823039** — Status: New; awaiting human triage; vulnerability type: Sensitive data exposure; attachments: 6 files (E01-E06) |

## Key Hypotheses

### [CRITICAL — H1] SSRF via URL Submission
VirusTotal scans submitted URLs by fetching them server-side from GCP infrastructure.
Submitting `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
could yield a GCP service account token if VT's scanner doesn't block metadata requests.
Script: `vt-attack.sh` Phase H1.

**Chain:** URL submission → VT scanner fetches URL → GCP IMDS response in analysis result → service account token

**SSRF bypass techniques to test:**
1. Direct metadata URL
2. AWS IMDS (169.254.169.254) — in case VT runs on hybrid
3. IPv6 link-local (fe80::1)
4. Octal IP encoding (0251.0376.0251.0376)
5. Hex IP encoding (0xa9fea9fe)
6. Redirect chain: external URL → 302 → IMDS
7. Alt schemes: gopher://, file://, ftp://

### [HIGH — H2] Analysis Object IDOR
VT analysis IDs encode `base64(hash:timestamp)`. Private analyses may be
enumerable if timestamp is guessable. Test: decode own analysis ID structure → test
adjacent IDs.

### [MEDIUM — H3] Premium Endpoint Error Differential
Enterprise-only endpoints (/intelligence/search, /retrohunt_jobs, /hunting_rulesets)
might return different 403 error codes for "no permission" vs "not found",
leaking existence of enterprise objects to free users.

### [MEDIUM — H4] User/Group IDOR
`/api/v3/users/{id}/relationships/{rel}` — if user IDs are enumerable and access
control only checks the top-level object (not relationships), another user's
comments/votes/files might be readable.

## Current Status — SUBMITTED ✓

**F001 submitted 2026-06-14 to Google VRP as Issue #523823039.** Status: New — awaiting human triage. Final CVSS 5.0 Medium (`AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N`); VRP internal tier expected High. Three independent proof vectors (IP literal bypass, wildcard DNS alias bypass, OOB GCP scanner IPs), 6 attachments filed.

**No further action needed on this target** unless VRP responds requesting more information or escalation evidence.

## Decision Log
- Chose VirusTotal: TIER1, explicitly in scope (no VERIFY caveat), rich documented API v3
- SSRF via URL scanner is primary vector — VT's product fetches arbitrary attacker-controlled URLs
- `Server: Metadata Server for VM` in publicly-readable URL object = concrete attacker gain (GCP infra leak)
- `times_submitted: 423` = finding has been in DB publicly accessible for an extended period
- H4 User IDOR dropped: no email/private data exposed, public relationship data is intended
- H5 Premium endpoints dropped: consistent 403, no error-code differential
- F001 passes all 5 submission quality criteria (CLAUDE.md §2) — report-ready
