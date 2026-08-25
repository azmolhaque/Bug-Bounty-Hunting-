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
> **"Data Set Configuration Error — Data Studio cannot connect to your data set.
> The sheet to which you are trying to connect no longer exists."** (Error ID `401370b3`)

Note the wording: **not** "access denied" or "credentials required" — Looker tells B the sheet
**does not exist**. From B's position A's private sheet is indistinguishable from a deleted
one, so the error itself does not leak existence. Same design as Drive's
*"the file you have requested does not exist"* seen at the Phase 0 gate. Fail closed **and**
no existence oracle.

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

## 2026-08 — H1 closed, pivoting to H3

H1 (owner-credential retention on copy) is CLOSED/defended — see the 2026-07-25 entry.
H3 (cross-tenant IDOR on report/datasource objects) is now the active hypothesis:
`H3-PROCEDURE.md`.

Rationale for choosing H3 over H2 (field/alias SQLi): the one report in this portfolio that
earned P2 and real triage traction is the Looker XFF allowlist bypass — a *control bypass
proven by a differential*. H3 has that same shape (B's session returns A's private object, or
it does not) with no informative middle state. H2 needs generated-SQL visibility we do not
reliably have.

**Setup note carried forward:** do NOT reuse the H1 objects. A's report `68285b28-…` was
shared with B during H1, so B has legitimate access and it cannot demonstrate anything. H3
requires a freshly created, never-shared report in A.

## 2026-08-26 — H3 executed: report-ID swap → **DEFENDED (PERMISSION_DENIED)**

Accounts: A=`kaseym484@gmail.com`, B=`azmolhaque95@gmail.com`.
Objects (both freshly created; A's report **never shared**):

| | Report ID | Datasource | Canary |
|---|---|---|---|
| A (private) | `07b120ce-1c62-4a5c-824b-c561b106ccee` | `ls-h3-src-9wt4kp` | `H3SECRET-9wt4kp` |
| B (own) | `76c73896-f100-4188-900b-257c62ba14b1` | `af13982f-924b-4cb3-8526-2b2703164b5a` | `BOWN-9wt4kp` |

### Gates
- **0A — human boundary:** B loading A's report URL → *"Can't access report… your current account
  azmolhaque95@gmail.com can't access this report"*, B's email in frame. Screenshot held.
- **0B — query shape valid:** B's captured `batchedDataV2` cURL replayed → returns `BOWN-9wt4kp`
  (`grep -c` = 1). **Re-verified after the cross test — still 1**, so the session was live
  throughout and the cross result is not session death.

### Endpoint
`POST https://datastudio.google.com/u/0/batchedDataV2?appVersion=…`, cookie-authenticated,
`x-rap-xsrf-token` header. Body carries **two** independent identifiers:
`reportContext.reportId` and `datasetSpec.dataset[].datasourceId`, plus field IDs
(`sourceFieldName: _n906277200_` — appears to be derived from the column name `secret`).

### Cross test 1 — swap `reportId` only (B's cookies + A's report ID)
```
sed 's/<B_REPORT_ID>/<A_REPORT_ID>/g' b.sh > x.sh
```
Response (278 bytes):
```json
{"dataResponse":[{"dataSubset":[{"requestId":"","jobRequestUrl":[]}],
"errorStatus":{"code":7,"reason":4,"reasonStr":"PERMISSION_DENIED",
"uniqueErrorCode":"0cc43aa0","category":1,"errorCategoryStr":"ACCESS",
"errorDetails":{"permissionDeniedErrorDetails":{"aclModes":2}}}}]}
```
**gRPC code 7 / PERMISSION_DENIED / category ACCESS, with ACL evaluation details
(`aclModes:2`).** This is an *authorization* denial — the backend resolved A's report and
evaluated B's access against its ACL — not a malformed-request rejection.

**Verdict: report-level object authorization is enforced. Clean negative.**

### Still untested — the genuinely different question
The swap above kept **B's `datasourceId`**, so it only proves the *report* ACL is checked.
The data source is a **separate object with its own ACL**. The classic bug shape is:
> keep B's own `reportId` (report ACL passes) but point it at **A's `datasourceId`** — if the
> backend authorizes on the container and then fetches the referenced object without
> re-checking, B reads A's data through B's own report.

That is one `sed` away once A's datasource ID is captured. Also pending: FO-2 catch-all control
(garbage report ID) to confirm `PERMISSION_DENIED` is not the generic response for everything —
and to check whether a *nonexistent* ID returns a different code (which would be a minor
existence oracle, informational only, not a finding).

### Cross tests 2–4 — full matrix → **H3 DEFENDED, CLOSED**

A's datasource (embedded in A's report, **Owner's credentials / Kasey Murray**):
`29545b0f-aafc-4006-bdbf-78de76293092`.
Note: A's and B's `sourceFieldName` are **identical** (`_n906277200_`) because both sheets use
the column `secret` — so the field ID is derived from the column name. This mattered: it means
a datasource-only swap was **structurally valid**, and any rejection is a real control firing,
not a schema mismatch.

| # | B's cookies + … | Response | Control that fired |
|---|---|---|---|
| control | B's own report + B's own datasource | **200 + `BOWN-9wt4kp`** | — (gate 0B, verified twice) |
| 1 | **A's** reportId + B's datasource | `code 7 PERMISSION_DENIED` / ACCESS / `aclModes:2` | **Report ACL** |
| 2 | B's reportId + **A's** datasourceId | `code 3 BROKEN_CLAIM` / USER_CONFIGURATION | **Report↔datasource binding** |
| 3 | **A's** reportId + **A's** datasourceId (fully consistent) | `code 7 PERMISSION_DENIED` / ACCESS / `aclModes:2` | **Report ACL** |
| FO-2 | garbage reportId `00000000-…` | `PERMISSION_DENIED` / ACCESS / **empty** `permissionDeniedErrorDetails` | — |

**Two independent controls close the class:**
1. **Report-level ACL** — B cannot query A's report object, even with a perfectly formed,
   internally consistent request using all of A's own identifiers.
2. **Report↔datasource binding** — B cannot graft A's data source onto B's own report; the
   backend rejects the pairing as `BROKEN_CLAIM` *before* reaching authorization.

Test 2 is the important one for the classic bug shape (authorize on container, fetch referenced
object without re-checking). Looker Studio blocks it structurally: you cannot even express the
request, so the ACL question never arises.

**Owner's-credentials made no difference** — A's datasource was switched from Viewer's to
Owner's credentials precisely so that a successful cross would have executed as A and returned
A's rows. It still denied.

### Minor observation — existence oracle (informational, NOT reportable)
`permissionDeniedErrorDetails` is `{"aclModes":2}` for a **real** report B cannot access, but
`{}` for a **nonexistent** ID. That distinguishes "exists but denied" from "does not exist".
Per the Hard Rejection List (enumeration without record access — cf. Salesforce "873 fields"
→ N/A) this is **informational only. Do not submit.**

### VERDICT — H3 CLOSED, no submission
Coverage: 3 cross-tenant permutations + 1 catch-all control + a verified-before-and-after
positive control. **No data crossed. B never saw `H3SECRET-9wt4kp`.**
Logged as an honest negative (FO-7). Object-level authorization on `batchedDataV2` is sound.

H2 (calculated-field / alias SQLi) remains the only untested Looker Studio hypothesis.
