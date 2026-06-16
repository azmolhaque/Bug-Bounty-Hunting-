# AppSheet — Google VRP Submission Package

**Program:** Google Bug Hunters / Google VRP — https://bughunters.google.com/report
**Target:** `appsheet.com` (AppSheet, in scope via `*.appsheet.com`)
**Prepared:** 2026-06-16

## Contents

| File | Purpose |
|------|---------|
| `F001-google-vrp-report.md` | Final report — staging REST API auth bypass (`api.gcp-staging.appsheet.com`) |
| `F002-google-vrp-report.md` | Final report — OData connector SSRF + credential/header leak |
| `F002-dedup-CVE-2023-4212.md` | Dedup analysis showing F002 ≠ CVE-2023-4212 |

Source findings: `../F001-staging-api-auth-bypass.md`, `../F002-odata-ssrf.md`.

## Submission summary

| ID | Title | CVSS | Severity |
|----|-------|------|----------|
| F001 | Missing `ApplicationAccessKey` auth on public staging REST API | 6.5 (→9.1 w/ valid UUID) | Medium → Critical ceiling |
| F002 | SSRF in OData connector; creds + `Traceparent` leaked from GCP backend | 7.7 (floor 5.0; IMDS not priced in) | High |

## How to submit

1. Go to https://bughunters.google.com/report and sign in.
2. Select **Google VRP**, product **AppSheet** (`appsheet.com`).
3. Submit F001 and F002 as **two separate reports** (distinct components/classes).
4. Paste the body of the relevant `*-google-vrp-report.md`. For F002, attach/paste
   `F002-dedup-CVE-2023-4212.md` so triage does not conflate it with the Trane CVE.

## Honesty guardrails applied (read before submitting)

- **F002 IMDS** is framed as **TCP-reachability only** — a documented risk. No metadata
  token was retrieved; the HTTPS→HTTP redirect needed to reach IMDS was tested and is
  **blocked** by the .NET HTTP client. Do not claim credential retrieval.
- **CVE-2023-4212 is unrelated** (Trane thermostat command injection, physical USB). The
  earlier "prior AppSheet SSRF" label was wrong and has been removed from all files.
- **F001 escalation to Critical** is contingent on obtaining a valid staging App UUID,
  which was **not** done; today's confirmed severity is Medium (auth control fully bypassed).
- No customer data was read or modified; only attacker-owned servers/credentials were used.
