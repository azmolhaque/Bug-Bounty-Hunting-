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

## 2026-07-25 — H1 EXECUTED → **DEFENDED. Class patched. H1 CLOSED.**

Accounts: A=`kaseym484@gmail.com` (owner), B=`azmolhaque95@gmail.com`.
Canaries: `A1CANARY-8kq3wm` (Sheet-A1 `ls-source-8kq3wm`),
`A2SECRET-4td9nz` (Sheet-A2 `ls-victim-4td9nz`, the victim resource).

### Phase 0 — validity gate: PASSED
B, logged in as `azmolhaque95@gmail.com`, opened Sheet-A2's URL directly →
**"You need access"**, with B's email visible in the same frame (screenshot held).
The boundary is proven before any attack step. B also separately denied on A's report
pre-share ("Can't access report").

### Phase 1 — owner-credentials report built
Sheets restructured to header `canary` + data rows so the value renders as a dimension
(first attempt put the canary in row 1, so Looker read it as a column header and exposed
only `Record Count` — 1/1 fields. Not a defence; a setup artefact. Worth remembering.)
Data source `ls-source-8kq3wm - Sheet1`, **Data credentials = Owner's Credentials**,
credential owner **Kasey Murray** (screenshot held — dialog text: *"Allows this data source
to connect to the underlying data set using the credentials owned by the person below"*).
Table renders `A1CANARY-8kq3wm`. Shared to B as Viewer, copy permitted.

### Phase 2 — B copies the report → **credentials NOT retained**
B opened the shared report (rendered A's data — expected, documented owner-credentials
behaviour, not a bug) and used **⋮ → Make a copy**.

The copy dialog *does* carry the data-source **reference** across — both "Original Data
Source" and "New Data Source" read `ls-source-8kq3wm - Sheet1`, each flagged with a ⚠️.

But B's resulting copy fails closed:
> **"Data Set Configuration Error — Data Studio cannot connect to your data set."**

B ends up holding a report that *points at* A's sheet and **cannot read it**. The owner
credential did not travel with the copy.

### Verdict
This is the procedure's explicit drop condition — *"Empty / credentials needed → secure."*
**Phase 3 (repoint to Sheet-A2) is moot**: there is no retained credential to redirect, so
repointing can only reproduce the same configuration error.

**The Sticky Credential class (Tenable TRA-2025-29) is patched.** Consistent with Google
having remediated all nine LeakyLooker findings in March 2026. Nothing crossed the boundary;
B never saw `A2SECRET-4td9nz`.

**H1 CLOSED — no submission.** Logged as an honest negative (FO-7). Retention alone was never
submittable (FO-9/FO-11), and here there is not even retention.

### Reusable
- Copy carries the data-source **reference** but not the **credential** — fails closed with a
  Data Set Configuration Error. That is the current, post-patch behaviour.
- Setup trap for anyone re-running this: canary must be in row 2+, with a header in row 1, or
  Looker treats it as a column name and no data renders. Do not mistake that for a defence.
- H2 (field/alias SQLi) and H3 (cross-tenant report/datasource IDOR) remain untested — but
  both need request interception, now feasible on the laptop rig.
