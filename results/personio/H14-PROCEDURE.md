# H14 — Personio: cross-tenant access to employee records

## Environment

| | Tenant | Canary identity |
|---|---|---|
| A | `sectestgorib01.app.personio.com` | `CANARY-TENANT-A` |
| B | `sectestgorib02.app.personio.com` *(pending)* | `CANARY-TENANT-B` |

Both registered to `gorib@intigriti.me` per the program's own instructions. Created
2026-09-30; **14-day trial expiry — note the date, instances must be rebuilt after.**

Tenant A confirmed **preloaded with 1152 employees** of realistic demo data. This is the
single biggest advantage over the last two engagements: Coveo's orgs were empty, so every
comparison was empty-vs-empty and proved nothing until a canary was planted by hand.

## The identifier structure — this is the attack surface

An employee profile is addressed as:

```
https://sectestgorib01.app.personio.com/staff/details/39463216
```

Two distinct identifiers exist on the same record:

| Identifier | Example | Scope |
|---|---|---|
| **URL / system id** | `39463216` | 8 digits, **appears global across Personio** |
| "Employee ID" field | `65` | tenant-local, sequential |

A globally-shaped identifier sitting in the URL path, on a per-tenant subdomain, is the
classic IDOR shape. The question is whether the handler validates that the record belongs to
the tenant in the hostname, or only that the caller is authenticated somewhere.

## Data on the record — why impact will not be arguable

Visible on one profile: full name, date of birth, citizenship, work email, supervisor,
notice period, probation end, hire date, FTE. Tabs and sections present: **Salary**,
**Documents**, **Payroll information**, **Bank details** (IBAN/BIC), **Emergency contact**,
**Visa**, Attendance, Time off, History, Roles.

Personio's published severity table:

- **Critical** — *"Multi-tenant PII access"*, *"access to all users or accounts"*
- **High** — *"access to one user or account"*, *"gaining access to salary info"*

1152 records × that field set. There is no version of this where the impact has to be
argued, which is the failure mode that closed the Google VRP and AppSheet reports.

## Hard rule — the identifiers

**Only ever use identifiers belonging to tenant A and tenant B, which we own.**

Do **not** increment, decrement, fuzz or guess the 8-digit ID. Those numbers belong to real
Personio customers' employees — real people's salaries, bank details and dates of birth.
Guessing one is not a test, it is unauthorised access to a third party's personal data, it
breaches the program terms, and it would end the account (FO-14).

The whole purpose of holding two tenants is that we never need to guess: we read B's real
identifiers from B, then present them to A.

## Test plan

### Phase 1 — controls first (FO-19)

1. **Positive control.** Logged into A, `GET /staff/details/<A-employee-id>` → must return
   that employee. Without this passing, nothing below means anything.
2. **Negative baseline.** Logged into A, request an id that cannot exist (e.g. `1`) → record
   the exact status, error body and whether it distinguishes "not found" from "forbidden".
3. **Existence oracle check.** Does A answer differently for a well-formed id that is not in
   A versus one that is nowhere? On Coveo this mattered more than the status code.

### Phase 2 — the cross-tenant test

4. In **B**, collect a handful of B's own employee ids and one distinctive value
   (`CANARY-TENANT-B` is already one).
5. From **A's session**, request `sectestgorib01.app.personio.com/staff/details/<B-id>`.
6. Read the body. Success is **B's data appearing in A's tenant**, proven by the canary
   string — not a 200, not a redirect, not an empty page (Adobe H10: a 200 on a JS shell
   proves nothing).

### Phase 3 — the API

`api.personio.com` is Tier 2 and in scope. The same question applies to every endpoint that
takes an employee identifier, and API handlers are written per-endpoint where the web app may
share one guard. This is where the Coveo phase-2 lesson applies: the query-parameter surface
is checked by hand per handler and is structurally weaker than the path surface.

### Phase 4 — the sensitive tabs

If any cross-tenant read works, the severity is decided by which tab it reaches. Salary,
Payroll information, Bank details and Documents are the ones that move it from High to
Critical. Test the *least* sensitive route that proves the boundary is broken, then stop —
one record is proof, 1152 is exfiltration.

## Standing constraints

- No DoS, no brute force, no rate-limit testing — all explicitly out of scope.
- No automated scanning against the tenants; build and test at human pace (FO-20).
- Do not touch real users. Only the two tenants we own.
- Trial expires in 14 days; record tenant names and creation dates in this file.
