# AppSheet — Google VRP Submission Package

**Program:** Google Bug Hunters / Google VRP — https://bughunters.google.com/report
**Target:** `appsheet.com` (AppSheet, in scope via `*.appsheet.com`)
**Prepared:** 2026-06-16

## Contents

| File | Purpose |
|------|---------|
| `F003-systemic-ssrf-report.md` | **PRIMARY SUBMISSION** — systemic egress-control gap; OData + Apigee both confirmed |
| `F002-google-vrp-report.md` | Standalone OData-only report — fallback if F003's Apigee surface (S2) is duped |
| `F002-dedup-CVE-2023-4212.md` | Prior-art & dedup: F002 vs 2021 webhook SSRF, 2022 RCE, and CVE-2023-4212 |
| `OSINT-prior-art-and-leads.md` | Passive OSINT review + highest-impact next-session leads (egress-gap audit) |
| `F001-google-vrp-report.md` | ⛔ **WITHDRAWN** — false positive, retracted 2026-06-16 (see `../F001-RETRACTION.md`) |

Evidence: `../evidence/session3-20260616/oob_L1_20260616.log`
Test matrix: `../runbooks/egress-test-log.md`

## Submission summary

| ID | Title | CVSS | Severity | Status |
|----|-------|------|----------|--------|
| **F003** | **Systemic SSRF egress-control gap — OData + Apigee connectors both confirmed** | **7.2** | **High** | **PRIMARY — submit this** |
| F002 | SSRF in OData connector only (standalone) | 7.2 | High | Fallback only — use if F003/S2 duped |
| ~~F001~~ | ~~Staging REST API auth bypass~~ | — | — | ⛔ Retracted 2026-06-16 (false positive) |

## How to submit

1. Go to https://bughunters.google.com/report and sign in.
2. Select **Google VRP**, product **AppSheet** (`appsheet.com`).
3. Submit **F003 as the primary report**. Attach `F002-dedup-CVE-2023-4212.md` for context.
4. In the report, note explicitly: Surface 2 (Apigee) may overlap the prior fixed Apigee
   report — you flag it transparently and ask triage to assess; Surface 1 (OData) is novel
   regardless.
5. If F003 Surface 2 is closed as duplicate of the prior Apigee fix, follow up with
   **F002** (OData standalone) as a separate submission — OData is definitively novel.

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
- **CVSS corrected to 7.2** (was briefly miscalculated as 7.7 in an earlier draft —
  re-derived by hand against the official CVSS 3.1 Roundup formula using the correct
  Scope-Changed `PR:L` weight of 0.68). The conservative-floor vector is **4.6**, not 5.0.
