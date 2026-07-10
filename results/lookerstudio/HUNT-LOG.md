# Looker Studio — Hunt Log
Started 2026-06-30. Target lookerstudio.google.com (IN-SCOPE). Phone+browser+curl.
Source: deep-research 2026-06 (Tenable LeakyLooker recurring patterns).
Hypotheses: H1 owner-credential retention on copy (priority), H2 field SQLi,
H3 cross-tenant report/datasource IDOR. See 00-plan.md.

## Candidates / progress
- H1: procedure issued — operator to execute browser steps (two accounts).
- 2026-07-10: PIVOTED here from Wiz F001 (claimability unproven, precondition-only).
  Wrote `H1-PROCEDURE.md` — full FO-3/FO-9-gated browser test:
    Phase 0 validity gate (B blocked on Sheet-A2) → Phase 1 A builds owner-creds
    report on Sheet-A1 → Phase 2 B copies, test retention → Phase 3 decisive: B
    repoints copy's data source to A's Sheet-A2 (B can't open it); if B sees
    `A2SECRET-90909` = CONFIRMED cross-tenant read. Canary strings, screenshot list,
    drop conditions all specified. Google Sheets = free/pure-browser primary;
    BigQuery variant noted for higher impact. Operator to execute.
