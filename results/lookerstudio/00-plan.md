# Looker Studio — Hunt Plan (00-plan)

Target: lookerstudio.google.com (Google VRP, IN-SCOPE, TIER per google core).
EV tier (FO-1): #3 self-service multi-tenant SaaS + #2 documented fresh pattern.
Constraint: phone + browser + curl; 2 free Google accounts (A=gorib, B=gorib2).

## Thesis
Tenable "LeakyLooker" proved a class of cross-tenant + injection bugs in Looker
Studio. Google patched the specific instances; the ROOT-CAUSE PATTERNS are the
prior (Recurring-Pattern Lens). Test the same patterns on other flows/connectors:

### H1 (priority) — Owner-credential retention on Copy/Share ("Sticky Credential")
Looker Studio data sources can use "Owner's credentials" (viewers query as owner).
The LeakyLooker Sticky-Credential bug: copying a report retained the owner's stored
DB creds. HYPOTHESIS: if account B copies A's shared report whose data source uses
A's owner-credentials, and B can then REPOINT/EDIT the data source query/table/sheet
within their copy while it still executes with A's retained creds, B reads A's
OTHER private data (other BigQuery datasets / other private Google Sheets / other DB
tables) = cross-tenant data access. Highest impact, pure-browser testable.

### H2 — User-controlled-field SQL injection
Calculated fields, custom column aliases, filters, parameters, blended-data exprs
concatenated into generated SQL/BigQuery jobs (LeakyLooker TRA-2025-28 was column-
alias SQLi). HYPOTHESIS: a crafted field name/alias/calculated-field/parameter
breaks out of the generated query. Needs interception to see generated SQL.

### H3 — Cross-tenant IDOR on report/datasource/embed object id
Access another account's PRIVATE report/datasource/embed by id via the internal API.
Validity gate FO-3: baseline = B reads B's own report (200) before claiming A's
private report is/ isn't reachable by B.

## Method
- Pure-browser first (H1) — no curl needed for the core test.
- For H2/H3: capture the SPA's internal API (batchexecute/RPC) with the mitmproxy
  rig (FO-4), map report/datasource/embed object-id model, replay with curl.
- FO-2 catch-all control + FO-3 baseline-200 on every negative.
- Read-only, own 2 accounts, no third-party data.

## Status
- [ ] H1 credential-retention on copy — STEP 1 procedure issued to operator
- [ ] H2 field SQLi
- [ ] H3 cross-tenant IDOR
