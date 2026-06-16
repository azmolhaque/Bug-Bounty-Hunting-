# AppSheet — Google VRP Submission Package

**Program:** Google Bug Hunters / Google VRP — https://bughunters.google.com/report
**Target:** `appsheet.com` (AppSheet, in scope via `*.appsheet.com`)
**Prepared:** 2026-06-16

## Contents

| File | Purpose |
|------|---------|
| `F002-google-vrp-report.md` | Final report — OData connector SSRF + credential/header leak |
| `F002-dedup-CVE-2023-4212.md` | Prior-art & dedup: F002 vs 2021 webhook SSRF, 2022 RCE, and CVE-2023-4212 |
| `OSINT-prior-art-and-leads.md` | Passive OSINT review + highest-impact next-session leads (egress-gap audit) |
| `F001-google-vrp-report.md` | ⛔ **WITHDRAWN** — false positive, do not submit (see `../F001-RETRACTION.md`) |

Source findings: `../F002-odata-ssrf.md`. (`../F001-*` retracted.)

## Submission summary

| ID | Title | CVSS | Severity | Status |
|----|-------|------|----------|--------|
| F002 | SSRF in OData connector; creds + `Traceparent` leaked from GCP backend | 7.7 (floor 5.0; IMDS not priced in) | High | Verifying live |
| ~~F001~~ | ~~Staging REST API auth bypass~~ | — | — | ⛔ Retracted 2026-06-16 (false positive) |

## How to submit

1. Go to https://bughunters.google.com/report and sign in.
2. Select **Google VRP**, product **AppSheet** (`appsheet.com`).
3. Submit **F002 only**. (F001 is withdrawn — prod and staging behave identically; no bypass.)
4. Paste the body of `F002-google-vrp-report.md`. Attach/paste
   `F002-dedup-CVE-2023-4212.md` so triage does not conflate it with the Trane CVE.

## Honesty guardrails applied (read before submitting)

- **F002 IMDS** is framed as **TCP-reachability only** — a documented risk. No metadata
  token was retrieved; the HTTPS→HTTP redirect needed to reach IMDS was tested and is
  **blocked** by the .NET HTTP client. Do not claim credential retrieval.
- **F002 prior art** is the **2021 AppSheet *webhook* SSRF** (different subsystem, fixed there).
  F002 is the **OData connector** and is net-new — the 2021 fix was never generalized to an
  IP-level egress control. **CVE-2023-4212 is unrelated** (Trane thermostat, physical USB);
  the earlier "prior AppSheet SSRF" label was wrong and has been removed from all files.
- **F001 is RETRACTED** (2026-06-16). Live re-test showed prod and staging respond
  identically (`"App … not found"` across GET/POST); production never returns
  `"ApplicationAccessKey is missing"`. No bypass exists. Do not submit it. See
  `../F001-RETRACTION.md`.
- No customer data was read or modified; only attacker-owned servers/credentials were used.
