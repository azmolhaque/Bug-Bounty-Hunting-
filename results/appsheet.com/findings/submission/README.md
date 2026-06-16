# AppSheet — Google VRP Submission Package

Target: `appsheet.com` (Google VRP, AppSheet, TIER0). Two confirmed findings, packaged for
filing at https://bughunters.google.com. Each finding has a full `REPORT.md` plus two
paste-ready files matching the bughunters.google.com form fields
(`problem-description.md` → description, `impact-analysis.md` → impact/severity).

## Findings

### F001 — Missing auth on staging REST API
`F001-staging-api-auth-bypass/`
- **Asset:** `api.gcp-staging.appsheet.com`
- **Class:** Authentication bypass (`ApplicationAccessKey` not enforced)
- **Confirmed:** unauthenticated reach to all REST v2 endpoints, public internet, any IP
- **CVSS:** 6.5 Medium confirmed → 9.1 Critical with a valid staging app UUID
- **Status:** verified; no app UUID used, no data accessed

### F002 — SSRF via OData connector
`F002-odata-ssrf/`
- **Asset:** `appsheet.com` OData connector **Test** action (backend `35.203.182.241`)
- **Class:** SSRF + credential forwarding + internal tracing-header leak
- **Confirmed:** server-side fetch from GCP backend; `Authorization: Basic` (form creds)
  and `Traceparent` leaked; GCP IMDS `169.254.169.254:443` **TCP-reachable**
- **CVSS:** 7.7 High (conservative floor 5.0 Medium)
- **IMDS framing:** documented TCP-reachability **risk only** — no metadata/token/credential
  retrieved, no redirect chaining, no internal port probing (out of scope by design)
- **Dedup:** see `F002-odata-ssrf/dedup-CVE-2023-4212.md`

## Duplicate check
CVE-2023-4212 is an **OS command injection in Trane thermostats** (CISA ICSA-23-234-02) —
unrelated to AppSheet/SSRF. F002 is **not** a duplicate. Earlier drafts that cited it as a
"prior AppSheet SSRF" were factually wrong; the citation has been removed from this package
and corrected in the source finding files.

## Scope discipline
Both findings are within `*.appsheet.com`. For F002, IMDS token retrieval, redirect
chaining, and internal port probing were intentionally not performed; IMDS reachability is
reported as a risk for AppSheet to remediate.
