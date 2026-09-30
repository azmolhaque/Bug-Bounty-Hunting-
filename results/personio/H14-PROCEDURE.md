# H14 — Personio: cross-tenant access to employee records

## Environment

| | Tenant | Canary identity |
|---|---|---|
| A | `sectestgorib01.app.personio.com` | `CANARY-TENANT-A` |
| B | `sectestgorib02.app.personio.com` *(pending)* | `CANARY-TENANT-B` |

Both registered to `gorib@intigriti.me` per the program's own instructions. Created
2026-09-30; **14-day trial expiry — note the date, instances must be rebuilt after.**

Tenant A confirmed **preloaded with 34 employees** of realistic demo data. This is the
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

34 records × that field set. There is no version of this where the impact has to be
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
one record is proof, 34 is exfiltration.

## Standing constraints

- No DoS, no brute force, no rate-limit testing — all explicitly out of scope.
- No automated scanning against the tenants; build and test at human pace (FO-20).
- Do not touch real users. Only the two tenants we own.
- Trial expires in 14 days; record tenant names and creation dates in this file.

---

## Negative baseline — established from Personio's own configuration. 2026-09-30

Tenant A roles:

| Role | Permissions | Members |
|---|---|---|
| **All employees** | **24** | **34** — auto-assigned to every active employee, cannot be removed or deleted |
| Recruiting Manager | 6 | 4 |
| Project Manager | 28 | 2 |
| Line Manager | 30 | 10 |
| Management | 32 | 2 |
| HR Manager | 59 | 2 |
| Super Admin | 116 (all) | 2 |

Every permission carries a scope: **All** / **Self** / **Off**.

### `All employees` — the exact boundary under test

```
Employee profile
  Public profile .................. All + Self     <- the ONLY "All"
  HR information .................. Self
  Personal Information ............ Self
  Payroll information ............. Self
  Bank details .................... Self
  Emergency contact ............... Self
  Qualifications / Equipment / Visa  Self

Salary and Compensation
  Salary band ..................... Off
  Salary information .............. Self
  Compensation & prelim payroll ... Off
  Import one-time comp / salary ... Off
  Manage compensation cycles ...... Off

Documents
  Work contracts .................. Self
  Time off certificates ........... Self
  Application documents ........... Self
  Payroll ......................... Self
  Performance ..................... Self
  Other / Certificate / Study ..... Off

Employment details
  Assigning roles to employees .... Off      <- escalation target
  Create employee profile / rehire  Off
  Delete employee profile ......... Off
  Employee history (both) ......... Off
  Import - employee data .......... Off
  People list & org chart (export)  Off

Organisation
  Org chart view .................. On
  everything else ................. Off
```

**Personio's written contract:** a member of `All employees` may read **only their own**
salary, bank details, payroll information and payroll documents. They may read **everyone's**
public profile, and view the org chart. They may not assign roles.

That is the negative baseline, defined by the vendor rather than assumed by us — which is
exactly what phase 1 on Coveo lacked.

### What now gets tested

**T1 — horizontal read.** As an `All employees` member, reach *another* employee's Salary,
Payroll information, Bank details or payroll Documents. The UI will hide them; the question
is whether the **backend** enforces it. Routes to try, in order:

1. Direct URL: `/staff/details/<other-employee-id>` and each tab beneath it.
2. The XHR endpoints those tabs call (read them from DevTools on the admin session first,
   then replay as the low-privilege user).
3. `api.personio.com` with credentials minted under the restricted role.
4. Exports, reports and Analytics — a common place where a per-field check is skipped
   because the aggregate query was written separately.

**T2 — vertical escalation.** `Assigning roles to employees` is **Off**. Can the user assign
themselves a role anyway, via the endpoint the admin UI uses? That is "making yourself admin"
in Personio's own severity wording.

### Controls (FO-19 — the positive control must pass first)

- **Positive control:** the low-privilege user CAN read their **own** salary and bank details.
  If that fails, the account is misconfigured and every negative below is meaningless.
- **Negative baseline:** the same user, same request shape, pointed at another employee.
- **Catch-all sentinel:** an employee id that does not exist in this tenant, to distinguish
  "denied" from "not found" — the distinction that mattered most on Coveo.

### Severity if T1 lands

Personio's table, verbatim: **High** — *"Privilege escalation within the same account with
account take-over or similar (making yourself admin, gaining access to salary info)"*.
Tier 2 High = **€1,125**. T2 would be the same band or better.

Note their exclusion does **not** cover this: it applies only where the data is not
sensitive, and it names firstname/lastname/email as the non-sensitive examples. Salary,
payroll, bank details and documents are not on that list.

## Recruiting API credentials — recorded, not yet used

`Settings → Marketplace → Connected integrations → Recruiting API key`

```
Company ID     339177
Access token   (held by operator, not recorded here)
```

The company id is small and sequential-looking. **Adjacent ids belong to real Personio
customers.** They are never to be probed — that is not testing, it is unauthorised access to
another company's HR data. The second tenant exists precisely so that no id ever has to be
guessed; until it is provisioned, the cross-tenant axis stays parked.

### Correction — employee count

The Organization dialog showed "1152 people" on first open and that figure was recorded.
The People list itself ends with *"You've reached the end of the list (34 people)"*, and the
header count reads 34. **34 is the real number**; the 1152 was a stale or unfiltered counter
in that dialog. Corrected throughout.

Thirty-four demo employees with complete HR records is ample for the test — the count was
never the point, the field coverage is.

### Add-employee affordance located

`Organization → People` → **Add people ▾** → *"Add a new person"* (or *"Import new people
data"*). `/staff/new` returns 404 — that guess was wrong, and the UI path is the correct one.

---

## T3 — API credential scoping. CLEAN NEGATIVE, fully controlled. 2026-09-30

`Settings → Marketplace → Connected integrations → Create custom integration` provides a
three-step wizard with genuinely granular scoping:

- **Endpoint scopes** (Read/Write per area): Employees, Attendances, Time Off, Documents,
  Custom Reports, Compensations, Recruiting, Webhooks, Org Units, Legal Entities, Cost
  Centers, Workplaces, Reports, Job Catalog, Salary Bands.
- **Readable employee attributes** — field-level, ~60 attributes including `Fixed salary`,
  `Hourly salary`, `Salary type`, `IBAN`, `BIC`, `Holder of bank account`,
  `National Insurance Number`, `Date of birth`, `Address`, `Personal Email`,
  `Marital Status`, health insurance, emergency contact, visa.
- **Legal entities**, with the written claim: *"Legal entity selection will override any
  query parameters passed in the API call."*

### The credential under test

`h14-restricted` — **Employees: Read only**, every other scope unchecked, and readable
attributes limited to **First name + Last name only**.

That is the negative baseline, written by the vendor in their own UI: this credential may
read two fields and nothing else.

### Results

Auth against `POST https://api.personio.de/v1/auth` succeeded (91-char token) —
**positive control passed**, so everything below is a valid test.

| # | Request | Result |
|---|---|---|
| 1 | `GET /v1/company/employees?limit=1` | `id`, `first_name`, `last_name` — **exactly the grant** |
| 2 | `GET /v2/persons?limit=1` | same three, plus an employment id reference |
| 3 | `GET /v2/persons/<id>/employments` | employment **id** and a back-link only — no salary, contract or dates |
| 4 | `GET /v1/…?attributes[]=salary_data&iban&date_of_birth` | **only `id` returned** — forbidden attributes silently dropped |
| 5 | `GET /v2/persons?attributes=salary,iban,date_of_birth` | default fields only, no leak |
| 6 | `/v1/company/attendances` | **403** forbidden |
| 7 | `/v1/company/time-offs` | **403** forbidden |
| 8 | `/v1/company/document-categories` | **403** forbidden |

### Verdict

**Attribute-level filtering holds on four distinct paths** — the v1 default response, the v2
response, a linked sub-resource, and an explicit request naming the forbidden attributes.
**Endpoint-level scoping holds** — ungranted areas return 403.

The v1/v2 split was the hypothesis worth testing, since the two generations return different
error shapes and are therefore different code. Both enforce identically. Test 4 is the
strongest evidence: asking by name for `salary_data`, `iban` and `date_of_birth` returns a
record containing only `id` — the filter is applied after the request is honoured, not merely
omitted from a default projection.

`api.personio.de` matches the in-scope wildcard `https://*.personio.de` (Tier 2).
`api.personio.com` is CloudFront and 302s to `www.personio.com/login/` — not the API host.

## Still untested

1. **The legal-entity override claim.** *"Legal entity selection will override any query
   parameters passed in the API call"* is an explicit written security promise and therefore
   the cleanest possible finding if it fails. Needs a second legal entity in the tenant to
   test properly — `Settings → Organization → Legal entities`.
2. **The UI role boundary** — the actual €1,125 axis, and not started. An `All employees`
   member reaching another employee's salary through the web app is entirely separate code
   from the API credential path just cleared.

---

## Session state — 2026-09-30 04:13. Environment complete, UI test not yet run.

### Ready

| Item | State |
|---|---|
| Tenant A | `sectestgorib01.app.personio.com`, 35 active people, 13 days of trial left |
| Admin identity | `CANARY-TENANT-A` / `gorib@intigriti.me` — Super Admin |
| **Low-privilege identity** | **`LOWPRIV TESTER` / `gorib+lowpriv@intigriti.me` — created, invited, password set, login confirmed** |
| Negative baseline | `All employees` role, 24 permissions, salary/bank/payroll all **Self** |
| API axis | tested and closed — 8 requests, clean negative |

Login as LOWPRIV was confirmed working: the onboarding screen renders
*"Welcome to Personio, LOWPRIV!"*. **The positive control for the UI axis is therefore
established in principle**, though its first assertion has not been run.

### Blocked on a rendering bug, not on the target

The LOWPRIV session renders as a black screen on the operator's phone in Chrome incognito —
the page loads (the saved MHTML contains the onboarding content) but paints black, most
likely a dark-theme conflict. Nothing to do with Personio's security.

### Next session — ten minutes of work

1. Log in as LOWPRIV (Chrome or Kiwi incognito), finish the onboarding wizard.
2. **[1] Positive control** — own profile → Salary tab → must be visible.
3. **[2] The test** — `/staff/details/39463216` (Alan Foster) → Salary tab → must not be.
4. **[3] Sentinel** — `/staff/details/1`.

Baseline already measured as admin: `/staff/details/1` returns **"Restricted access"**, not
"not found". So Personio does not distinguish forbidden from nonexistent — meaning any
*different* response on [2] is itself signal, exactly as on Coveo.

Every screenshot must include the top banner so the acting identity is provable. Six times
this session a test was run in the wrong session; the banner is the cheapest guard against it.

### If [2] succeeds

Stop immediately. One record is proof; reading more is exfiltration. Personio's own wording:
**High — "gaining access to salary info"**, Tier 2 = **€1,125**.

---

## T1 — horizontal read via the UI. CLEAN NEGATIVE, controls valid. 2026-09-30

Session identity confirmed on every screenshot by the banner reading
**"LOWPRIV, welcome to your Personio"** — the guard that six earlier attempts lacked.

### The profile view is filtered, not just hidden

As **admin**, `/staff/details/39463216` (Alan Foster) shows:
`About · Personal information · Salary · Documents · Attendance · Time off · Onboarding ·
History · Roles · More`

As **LOWPRIV**, the same URL shows **only**:
`About · Personal information`

Consistent with `Public profile: All` and everything else `Self`. The tab set itself is
server-driven, not merely CSS-hidden.

### The direct salary route

The UI hiding a tab proves nothing — that was the Adobe H10 lesson, where a 200 on a JS
shell nearly produced the opposite conclusion. Salary lives on its **own route**, found from
LOWPRIV's own profile:

```
/salary/employee-salary/<id>
```

| Request as LOWPRIV | Result |
|---|---|
| `/salary/employee-salary/39494707` (own) | **200**, compensation components render — **positive control PASSED** |
| `/salary/employee-salary/39463216` (Alan Foster) | **"Your session has ended"** — session terminated |
| `/staff/details/1` (sentinel) | "Restricted access", identical to the admin baseline |

**No salary data was disclosed.** The route is protected — aggressively so: requesting
another employee's salary page does not return 403, it tears down the session.

That response is blunt and slightly odd (most applications return 403), but it is a defence,
not a leak. The forced logout harms only the caller, so it is not reportable either.

### Verdict

**T1 is a clean negative.** Personio enforces the `Self` scope on salary at the route level,
not merely in the rendered tab set.

This is the first test in the whole engagement where the positive control passed on the
first attempt and the negative was therefore trustworthy immediately.

## Personio status

| Axis | Result |
|---|---|
| T3 — API credential scoping (8 requests) | clean negative |
| T1 — horizontal read, UI + direct route | clean negative |
| **T2 — vertical escalation (self-assign role)** | **not started** |
| Documents / Attendance direct routes | not started |
| Cross-tenant (Critical, €3,000) | blocked — second tenant cannot be provisioned |
| Legal-entity override claim | not started, needs a second legal entity |

`Assigning roles to employees` is **Off** for `All employees`. T2 asks whether LOWPRIV can
assign itself a role through the endpoint the admin UI uses — "making yourself admin" in
Personio's own severity wording, and the same €1,125 band.

---

## T4 — unauthenticated recon of the wider in-scope estate. CLEAN NEGATIVE. 2026-09-30

Passive discovery via crt.sh (**no traffic to Personio**) across the in-scope wildcards,
then a rate-limited GET probe. 56 unique names, all under `*.personio.tools` — an in-scope
**Tier 2** wildcard.

### What the certificate transparency logs revealed

An internal AI/BI estate that is not otherwise advertised:

```
MCP servers      mcp-metricflow · rag-mcp · salesforce-mcp · zendesk-mcp   (bi-dev / bi-prod)
                 safebase-mcp.sec
AI / LLM         data-agent · llm-evaluations · copilot · claude-sf-connector
                 channel-name-generator · incident-splitter · slide-builder
Other            activ8 · payops · dummy-shared-db · toolsuite-test · skf.sec · skf-dev.sec
Per-developer    anastasiamakhonina-* · douglaszickuhr-* · jamesarch-*
                 jamesdoldissen-* · niklaskeil-* · yemiogoundele-*
```

### Probe results — the estate is not exposed

**Almost every host returned `000` — DNS does not resolve publicly.** The certificates exist
in CT logs but the hosts live behind a private network. That is correct posture: issuing a
public certificate for an internal name leaks the name, not the service.

Reachable from the internet:

| Host | Result |
|---|---|
| `safebase-mcp.sec.personio.tools` | `Cannot GET /` — Express, alive |
| `personio.tools` | 200, AmazonS3 |
| `app.personio-dev.com` | 403 → `{"errors":[{"title":"Unauthenticated Request"}]}` |
| `docs.personio.tools`, 4 × `*-static.bi-dev.*` | 302 CloudFront |

### The one live MCP server — properly protected

`safebase-mcp.sec.personio.tools`, on the security team's subdomain:

```
/health /sse /message /messages   404
/mcp                              405   {"error":"method_not_allowed","detail":"Stateless mode; use POST."}
/.well-known/oauth-authorization-server   200   Okta metadata (personio.okta.com)
```

A single MCP `initialize` POST, with `clientInfo.name` set to `intigriti-gorib-research` so
the identity is honest in their logs:

```
POST /mcp  {"jsonrpc":"2.0","method":"initialize",…}
  -> 401 {"error":"missing_bearer_token"}
```

**OAuth is enforced.** Stopped there — no retry, no bypass attempt, no `tools/list`.

The `.well-known` document is **not a finding**: OAuth discovery metadata is public by
design on every Okta tenant, and it discloses nothing that is not already published.

Its `registration_endpoint` points at `personio.okta.com/oauth2/v1/clients`. Open dynamic
client registration is a known issue class, but **`personio.okta.com` is not in the program
scope** — the scope lists `*.personio.de`, `*.app.personio.com`, `*.personio.tools` and the
rest, and Okta is a third party. Not touched.

### Verdict

Clean negative. Internal services are not publicly resolvable, the one exposed MCP server
enforces bearer auth, and the dev application rejects unauthenticated requests.

### Rule earned

**FO-21 — Stating a rate limit in a comment does not enforce it.**
The recon script carried "max 2 requests/sec" in its own header and then issued three curls
per host with no delay between them — roughly 5 req/s against Personio's published cap.
Caught before the 56-host run, but only by reading the implementation rather than trusting
the comment. Constraints belong in the code path, not the documentation.

## T5 — v1 / v2 scope parity. CLEAN NEGATIVE. 2026-09-30

Positive control asserted first and passed (`first_name, id, last_name` — exactly the grant).

18 v2 collections probed with a credential holding **Employees:Read only**:

```
enforced (401/403)   compensations · absence-periods · attendance-periods
                     projects · cost-centers · legal-entities
absent (404)         employments · documents · custom-reports · departments · teams
                     offices · positions · employees · company · goals · trainings
other                org-units 400 (missing parameter)
```

v1 baseline unchanged: `attendances`, `time-offs`, `document-categories` → 403.

`/v2/persons` field check: `employments, first_name, id, last_name` — **nothing beyond the
grant**.

**Zero reached.** The hypothesis — that two API generations with different error envelopes
means authorization written twice, and twice means differently — was reasonable and did not
pay out. Personio enforces scope identically across both.

### Two anomalies, neither a finding

- **`/v2/compensations` returns 401** where every other enforced v2 endpoint returns 403.
  A different code path for the most sensitive collection, but no data either way, and 401
  is if anything the more conservative answer.
- **`/v2/org-units` returns 400**, wanting a parameter, rather than deciding authorization
  first. Parameter validation ahead of the auth check — the same ordering seen on Meta's
  `generatepreviews` — and equally inert, since it discriminates nothing.

## Personio: five axes closed

| Axis | Requests | Result |
|---|---|---|
| T3 API credential scoping | 8 | clean negative |
| T1 salary, UI + direct route | 3 | clean negative |
| T4 unauthenticated estate recon | 62 | clean negative |
| T5 v1/v2 scope parity | 25 | clean negative |
| **T2 vertical escalation** | — | **not started** |

Roughly 100 authorized requests, every one with a passing positive control behind it. No
finding. That is a well-built authorization layer, and saying so is the honest read.

## T2 is a different question and is the one left

Everything above asks *"can this credential read data it was not granted?"* — and the answer
is consistently no.

T2 asks something else: *"can this identity perform an **action** it was not granted?"*
`Assigning roles to employees` is **Off** for `All employees`. If LOWPRIV can drive the
endpoint the admin UI uses to assign itself a role, that is Personio's own
**High — "making yourself admin"**, Tier 2 **€1,125**.

Different class, different code, and untouched.

### Getting the request shape

Role assignment is **not** in the public v1/v2 API — it is an internal XHR on
`sectestgorib01.app.personio.com`. So:

1. In the **admin** session (Kiwi, normal window), open DevTools → **Network**.
2. Assign any role to LOWPRIV through the UI.
3. Find the request that carries it, **Copy as cURL**.
4. Replay it from the terminal with **LOWPRIV's** session instead of the admin's.

Step 4 is the test. Step 2 is setup performed as the legitimate admin, which is allowed —
we own the tenant.

Rule for it: if the replay succeeds, **revert the role immediately** and record the two
requests. A privilege escalation demonstrated once is proof; leaving it in place is changing
the tenant's security state for no evidential gain.

## T6 — SPA bundle mining. NOT POSSIBLE, and session stopped on a 429. 2026-09-30

The Adobe play — read the app's JavaScript for its internal API routes — does not work here.

```
https://sectestgorib01.app.personio.com/                     401, 0 bytes
https://sectestgorib01.app.personio.com/staff/details/...    401, 0 bytes
https://sectestgorib01.app.personio.com/login                302
```

**Personio serves no HTML and therefore no script references to an unauthenticated caller.**
On Adobe the entire agentic tool registry came out of a public login page's bundle; here
there is no public bundle to read. That is a clean negative and good posture.

The bundle URLs would still be obtainable from an authenticated page, so T6 is deferred
rather than closed — but it needs the browser, which is where T2 already sits.

### Two reasons this session stopped here

**Rate limited.** `login.personio.com` returned **429**. After a full session of authorised
requests Personio pushed back, and the rules of engagement cap tooling at 2 req/sec
precisely so this does not happen. Backing off is the correct response, not tuning around it.

**A redirect crossed the scope boundary.** `login.personio.com` 302s to **`personio.com`**,
and `www.personio.com` is explicitly out of scope. The `-L` flag followed it. One GET against
a marketing page, no harm — but I wrote that flag without checking where the redirect led.

### Rule earned

**FO-22 — Know where a redirect goes before following it.**
`-L` delegates the choice of target to the server. On an engagement with an explicit
out-of-scope list, that is the server deciding what you test. Resolve the `Location` first,
check it against scope, then fetch it deliberately. The same class of slip put us on
`adobeioruntime.net` earlier in this engagement.

## Personio — session close, 2026-09-30

| Axis | Requests | Result |
|---|---|---|
| T3 API credential scoping | 8 | clean negative |
| T1 salary, UI + direct route | 3 | clean negative |
| T4 unauthenticated estate recon | 62 | clean negative |
| T5 v1/v2 scope parity | 25 | clean negative |
| T6 SPA bundle exposure | 3 | not possible unauthenticated |
| **T2 vertical escalation** | — | **not started, needs browser** |
| Cross-tenant (Critical, €3,000) | — | blocked, second tenant unprovisionable |
| Legal-entity override claim | — | not started, needs a second legal entity |

**~100 authorised requests. Zero findings. Zero false positives.**

Every negative recorded here has a passing positive control behind it. That is the
difference from the Coveo runlog, where 102 of 196 endpoints were written up as clean and
had in fact never been tested.

Environment persists: tenant A, 35 employees, LOWPRIV identity with a known password, an
API credential, and 13 days of trial remaining.

## T7 — single-resource and sub-resource paths. CLEAN NEGATIVE. API axis exhausted.

Not rate limited after all: the 429 came from `personio.com`, a marketing host behind a WAF
that answers non-browser user agents that way. `api.personio.de` authenticated normally
(91-char token) and answered every request. Generalising from that 429 to "we are limited"
would have been wrong.

The collection endpoint had been tested; the **single-resource** handler never had. Those are
usually different code, and a filter applied to a list but not to `GET /thing/{id}` is a
common gap.

| Request | Fields returned |
|---|---|
| `/v1/company/employees?limit=1` (control) | `first_name, id, last_name` |
| `/v1/company/employees/39463216` | **same three** |
| `/v2/persons/39463216` | same three + an employment id reference |
| `/v2/persons/39463216/employments` | employment id, person ref, links only |
| `/v2/employments/{employment-id}` | 404 — no top-level route |
| `/v2/persons/{id}/employments/{employment-id}` | **id, person, links — no contract, no salary, no dates** |
| `/v1/company/employees/attributes` | **`first_name`, `last_name` — nothing else** |

That last row is the strongest evidence in the whole engagement. The **attribute catalogue
itself is filtered to the grant** — Personio will not even enumerate which other attributes
exist. Most systems leak their schema freely; this one treats the schema as part of the
protected surface.

### The API axis is exhausted, and that is a conclusion rather than fatigue

The same control has now been tested along **seven distinct paths**: the collection, the
single resource on v1 and on v2, a sub-resource, a nested sub-resource, an explicit request
naming forbidden attributes, and the attribute catalogue. It holds on all seven, plus
endpoint scoping across 18 v2 collections and 5 v1 equivalents.

There is no remaining shape of "read data you were not granted" left to try against this API
from a terminal. Saying so is a finding about the target, not about my imagination — and the
distinction matters, because twice in this engagement I called something exhausted when it
was not (FO-16).

## What genuinely remains — none of it terminal-only

| Test | Blocker | Value |
|---|---|---|
| **T2 — self-assign a role** | needs the admin UI's XHR captured in DevTools | **€1,125**, different bug class entirely |
| T6 — authenticated bundle mining | bundle URLs only obtainable from a logged-in page | would unblock T2 without DevTools |
| Legal-entity override claim | needs a second legal entity created in the UI | vendor's own written promise |
| Cross-tenant | second tenant unprovisionable; program asked | **€3,000** |

T2 remains the best bet, and it is a different question from everything closed so far:
**not "can this credential read what it was not granted" but "can this identity perform an
action it was not granted."** Every test to date has answered the first question. None has
touched the second.

## T8 — dev API environment. NOT EXPOSED. Terminal work on Personio is complete.

`api.personio-dev.com` is in scope at Tier 2 and had only ever been touched at its root.
Two questions were open: does it serve the same endpoints, and does a **production**
credential authenticate against it — environment isolation being a real failure mode.

```
GET  /v1/company/employees   (prod bearer)   302
POST /v1/auth                (prod client)   403  CloudFront error page
GET  /v1/auth · /v1/company/employees · /v2/persons · /v1/company/attendances   302
```

Everything redirects; the POST is refused by CloudFront itself rather than by an
application. Same shape as `api.personio.com`, which 302s to `www.personio.com/login/`.
**The dev API is not publicly exposed**, so neither question can be answered from outside —
and neither is a weakness.

Redirect targets were not followed this time (FO-22).

## Terminal testing on Personio: complete

Stated as a conclusion, with the count behind it:

| Surface | Coverage | Result |
|---|---|---|
| API attribute filter | 7 distinct paths | enforced on all |
| API endpoint scoping | 18 v2 + 5 v1 collections | enforced |
| Salary route, direct | own vs foreign vs nonexistent | enforced |
| Unauthenticated estate | 62 hosts, 5 MCP servers | not exposed / OAuth enforced |
| SPA bundles | 3 entry points | no public bundle to read |
| Dev API | 6 requests | not publicly exposed |

**~115 authorised requests. Zero findings. Zero false positives.**

### Why there is nothing left here for a terminal

Everything remaining needs a browser, and not incidentally — structurally:

- **T2 (self-assign a role)** — the endpoint is an internal XHR, absent from the public API,
  and the only terminal route to its path was the JS bundle, which is not served
  unauthenticated.
- **Stored XSS** — the terminal can confirm an API stores a payload raw, but that is
  *correct* behaviour for an API; encoding belongs at render time. The finding is whether the
  **browser** renders it unencoded, which a terminal cannot observe. Proposing it as terminal
  work would be busywork.
- **Legal-entity override** — needs a second legal entity created in the UI first.
- **Cross-tenant** — blocked on tenant provisioning, awaiting the program's answer.

Saying "terminal is done" is itself a claim that can be wrong, and it was wrong twice in this
engagement (FO-16). It is made here with the surface list above as evidence, not as a feeling.

---

## T2 — vertical privilege escalation via self-assigned role. CLOSED, enforced. 2026-09-30

The one question every earlier test left untouched: not *"can this credential **read** what it
was not granted"* but *"can this identity **perform an action** it was not granted."*

`Assigning roles to employees` is **Off** for the `All employees` role that LOWPRIV holds.
The admin UI performs the assignment through an internal persisted-query GraphQL call,
captured from DevTools in the admin session:

```
POST /graphql?op=ARM_BulkAssignRoles_v2025091501
{"query":"ARM_BulkAssignRoles_v2025091501",
 "operationName":"ARM_BulkAssignRoles_v2025091501",
 "variables":{"roleIds":[{"id":"11120349"}],"userIds":["39494707"]}}
```

`11120349` = Recruiting Manager · `39494707` = LOWPRIV · `39490672` = admin · `339177` = company.

Replayed verbatim with LOWPRIV's own session cookie. Three assertions, in order, because a
result without them is worthless (FO-19, and the wrong-session incident earlier in this hunt):

```
A. IDENTITY   grep of the authenticated app shell -> "39494707" x2, no "azmol", no 39490672
B. LIVENESS   POST SM_CanCompanyAccessPersonio_v2025102201
              {"data":{"canAccessPersonio":{"canAccessPersonio":true}}}   [200] 57b
C. THE TEST   POST ARM_BulkAssignRoles_v2025091501                         [200]
   {"errors":[{"message":"Permission denied","path":["bulkAssignRoles"],
     "extensions":{"title":"Access denied for action ACTION_EDIT on assign/unassign
      roles to/from employees","classification":"DataFetchingException"}}],
    "data":{"bulkAssignRoles":null}}
```

**Enforced server-side.** The UI hides the control *and* the resolver refuses the mutation.
Nothing to report.

### What the refusal handed us

The error is not a generic 403 — it names the check: `ACTION_EDIT` on a named resource. So
every internal operation sits behind an `<ACTION> on <resource>` authorization decision. That
is the shape of an engine, and an engine applied across hundreds of operations is exactly the
kind of thing that is applied unevenly.

Everything closed so far (~115 requests) was on the **public v1/v2 API**. The **internal
GraphQL API has never been tested**, because persisted queries mean an operation cannot be
called without knowing its exact name, and the names live in the SPA bundles — which T6 found
are not served to an unauthenticated client.

With LOWPRIV's cookie in hand that blocker is gone. Next: harvest operation names from the
authenticated bundles (`~/h14/opmine.sh`), then sweep them as LOWPRIV with a positive control,
same discipline as the v1/v2 parity sweep.

**T2 is a negative, and the surface it opened is the largest untested one in this engagement.**

---

## The internal API — mapped, swept, enforced. 2026-09-30

Everything before this tested the **public** v1/v2 API. This section tested the application's
own internal surface, which had never been touched because persisted queries hide the
operation names and the SPA serves no bundle to an anonymous client.

### How the surface was obtained

1. An authenticated fetch of `/` yields the orchestrator shell. Its `__NEXT_DATA__` carries the
   **module-federation registry**: 170 micro-frontends as `[name, uuid, "__remote/entry.<hash>.js",
   "<group>/<module>"]`. Personio's whole front-end topology, in one page.
2. `https://assets.cdn.personio.de/artifact-service/<group>/<module>/__remote/entry.js` — the
   unhashed alias — returns 200, so any module's bundle is retrievable without knowing a hash.
   59 high-value bundles pulled (payroll ×32, documents ×7, access-management, data-governance,
   whistleblowing, identity, integrations).
3. That was a dead end: the entries are federation containers, and the feature code sits in
   chunks behind them. **The cheap route won instead** — `performance.getEntriesByType('resource')`
   in the admin's console, run on each privileged page, prints every request URL in full.

### What that produced, and what it answered

| Test | Result |
|---|---|
| `scope=` on `/platform/dashboard/api/v2/people` — `everyone`, `all`, `company`, `team`, `__canary__` | only `reports`/`everyone`/`self` valid; unknown values return 0 records — **whitelisted, not trusted** |
| `scope=everyone` field set | `id, name, full_name, profile_picture_url, profile_url, logged_in_user, email` — exactly the Public profile the role grants. Intended; dropped |
| `PAY_ListPeople`, `PAY_ListPayrollLegalEntities` | `Permission denied — PAYROLL_VIEW` |
| `ARM_GetCapabilities` / `ListPermissionSets` / `GetPermissionConfigCatalog` / `ListPermissionSetGroupStatus` | Permission denied, all four |
| `EO_ListPositionIds` | Permission denied |
| `/api/v1/payrolls`, `/api/v2/payrolls/*/personal`, `/*/files` | `403 — User does not have payroll access to this subcompany` |
| `DM_ListAppDocuments` with `ownerEmployeeId` / `employeeId` / `personId` = another employee | `documentsList: []` — the parameter is ignored, scope comes from the session |
| `/api/v2/document-management/documents?employeeId=<other>` | `{"success":true,"data":[]}` |
| **`/documents/download/{id}/{storageKey}`** for another employee's signed contract + NDA | **403** |
| same, with id and storageKey deliberately mismatched | **403** — the pair is not the check; the session is |
| `DM_GetInitializationData` | `404 — Only known, curated queries allowed to execute in Production` |

The document test is the one that matters, and it was set up properly: three documents exist in
the tenant, owned by employee `39463247`, and their ids and storage keys were read from the
admin's own session. LOWPRIV asked for them by exact id **and** exact key. 403.

Two operations did return data — `DM_ListAppDocumentCategories` (category names, companyId) and
`ARM_GetFeatureAccess` (subscription feature slugs). Both are configuration, neither is anyone's
personal data, and §3 drops them. Recorded so the absence of a report is not mistaken for an
oversight.

### Verdict on this axis

**~200 authorised requests across seven distinct enforcement surfaces — public API, internal
GraphQL gateway, internal per-module REST, document storage, payroll, permission engine, role
assignment — and not one gap.**

Personio enforces authorization in the resolver, not the UI. Every client-supplied identifier
(`scope`, `employeeId`, `ownerEmployeeId`, document id, storage key) is ignored in favour of the
session. That is the correct design, and testing it further has no expected value.

### The strategy error, stated plainly

Four programs running — Exoscale, Adobe, Coveo, Meta, now Personio — the bug class chosen was
**authorization**, every time. It is the class every mature SaaS hardens first and tests most.
Personio has 351 accepted reports and its own severity table names XSS three times; we never
tested XSS, stored input rendering, or file-upload handling once.

The next move on this target is not another authorization probe. It is the classes the program
actually pays out on, starting with what the document service does with an uploaded file.

---

## XSS axis opened: whistleblowing, anonymous reporter -> case manager. ESCAPED. 2026-10-01

The authorization axis was exhausted, so the class changed. The target chosen was the one
shape that pays: **an unauthenticated outsider writes text that a company employee then opens
in their own session.**

Personio has exactly two such surfaces, both in scope:

| surface | writer | reader |
|---|---|---|
| `*.personiowhistleblowing.com` (Tier 2) | anyone, no login | case manager |
| `<tenant>.jobs.personio.com` | any applicant | recruiter |

Whistleblowing was taken first: Tier 2 by name, and anonymity is its whole design.

### Why the document-upload route was dropped before any payload was built

`/documents/download/{id}/{storageKey}` serves uploaded files from the app origin, so an SVG
or HTML upload would have been stored XSS on the session origin. One header read closed it:

```
content-disposition: attachment; filename=file; filename*=utf-8''Signed%20working%20contract.pdf
x-content-type-options: nosniff
```

Forced download, no sniffing. Checking the defence before building the payload cost one
request and saved an hour.

Worth recording from the same response, though it is not a finding on its own (§3):

```
content-security-policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' data: <~60 hosts>
```

`unsafe-inline` **and** `unsafe-eval`. If an injection is ever found in this app, CSP will not
stop it.

### The test

Environment built to make the boundary unambiguous: a `General` reporting channel with
**LOWPRIV TESTER** as its only case manager — so the reader is an ordinary employee, not an admin.

Submitted from a clean incognito session with no Personio cookie, through the public wizard
(channel -> category -> describe -> upload -> review -> password; hCaptcha on step 1, so this
cannot be scripted):

```
Title        <b>GORIBT6</b>
Description  GORIBT0 probe <b>GORIBT1</b> <i>GORIBT2</i> <u>GORIBT3</u>
             <a href="https://example.com">GORIBT4</a> <img src=x alt=GORIBT5>
```

No script tag, no event handler. The question at this stage is only *does HTML render at all*.

Read back at `/whistleblowing/report/78c58ded-5d2c-4f3d-9787-d5c9beb94ae0`, saved as MHTML and
grepped rather than eyeballed:

```html
<h1 class="ds-type-heading-five">&lt;b&gt;GORIBT6&lt;/b&gt;</h1>
<span class="ds-type-body-medium">GORIBT0 probe &lt;b&gt;GORIBT1&lt;/b&gt; &lt;i&gt;GORIBT2&lt;/i&gt;
 &lt;u&gt;GORIBT3&lt;/u&gt; &lt;a href="https://example.com"&gt;GORIBT4&lt;/a&gt;
 &lt;img src=x alt=GORIBT5&gt;</span>
```

Escaped in the case list, in the detail heading, and in the chat message body. Three separate
components, three correct escapes.

### Read on the remaining XSS surface

The application is React end to end, and React escapes by default. An injection would require
an explicit `dangerouslySetInnerHTML`, which in practice means a rich-text sink: job
descriptions, email templates, announcements, document templates. **Every one of those is
authored by an admin**, so even if unescaped it is admin -> employee, not outsider -> employee,
and would not clear §2.

One genuine outsider-to-employee sink is left: **a candidate application on the public job
site**, rendered to a recruiter. That is the last XSS experiment worth running here.

## The second outsider-to-employee sink: job application -> recruiter. STRIPPED AT INPUT.

The last XSS surface worth testing on this target. An applicant is fully unauthenticated, and
what they type is read by a recruiter inside the product.

### Terminal work did the mapping

The career page was not where it was assumed to be. `sectestgorib01.jobs.personio.com` returned
`<html id="__next_error__">` — a Next.js error page, not an empty career page. The cause was a
setting, not a wrong host: **Enable Personio career page** was unchecked. Once enabled:

```
GET /                     200  79,950b   4 positions listed
GET /job/2822178          200            QA Engineer
GET /job/2822178/apply    200  71,772b
     fields: first_name last_name email phone available_from salary_expectations + uploads
     turnstile            <- Cloudflare Turnstile
```

Turnstile means the application cannot be submitted from curl, so the submission itself was done
from a clean incognito browser with no Personio cookie. Everything up to that point — finding the
career page, the position, the form endpoint and the exact field names — was terminal.

### Result

Submitted as an anonymous applicant:

```
first_name  <b>GORJ1</b>
last_name   <i>GORJ2</i>
```

Read back in the recruiter view (`/recruiting/position/2822178?applicationId=145052466`), saved
as MHTML and grepped. 14 occurrences of the canary, every one identical:

```html
data-cell-value="GORJ1 GORJ2"
<span class="TableCell-module__truncate___qZYUF" data-align="left">GORJ1 GORJ2</span>
<p data-test-id="applicant-title" ...>GORJ1 GORJ2</p>
```

Not `<b>GORJ1</b>` and not `&lt;b&gt;GORJ1&lt;/b&gt;` — **the tags are gone**. The markup was
stripped server-side on input, before any rendering question arises. Two independent defences:
sanitise on write, escape on read.

## Personio: closed. 2026-10-01

| axis | coverage | result |
|---|---|---|
| Authorization | ~200 requests, 7 enforcement surfaces | no gap |
| Document storage -> XSS | response headers | attachment + nosniff |
| Whistleblowing, anonymous -> case manager | title, description, chat body | escaped |
| Recruiting, applicant -> recruiter | name fields | stripped at input |

Roughly 230 authorised requests, four bug classes, zero findings and zero false positives. The
negatives are clean and documented, which is worth something — but it is not income, and saying
otherwise would be dishonest.

### What actually went wrong, and it is not the bug class

Changing class from authorization to XSS was the right correction and it still produced nothing,
which means the class was not the binding constraint. The binding constraint is **target
selection**.

Five programs: Exoscale, Adobe, Coveo, Meta, Personio. Every one a mature vendor with a funded
security team, a bug bounty programme running for years, and the exact surfaces a solo researcher
can reach already swept by hundreds of researchers before us. `accepted-per-researcher` measured
how *rewarding* a programme is to the people already in it; it did not measure whether anything
is left for a newcomer with a phone.

The gates in `rank-programs.py` need a sixth column, and the next session starts by writing it:
prefer **recently launched programmes and recently launched assets**, where the sweep has not
happened yet, over well-paying programmes where it has.

### Housekeeping owed on this tenant

- Operator's **real CV** was uploaded as the test application's document. Delete the application.
- Delete the `QA Engineer` job and unpublish the career page.
- Delete the whistleblowing test case and the `General` channel.
- Log out both the admin and LOWPRIV sessions — both cookies were pasted into the transcript.
- Delete the `h14-restricted` API integration.

## Two loose ends pulled before closing. Both held. 2026-10-01

Neither was busywork: both were surfaces the earlier sweeps had genuinely not reached.

### The `filter` argument on `DM_ListAppDocuments`

An earlier error revealed `filter` is a `String!` — a filter expression language, not a scalar.
If the resolver substituted our filter for the session scope rather than intersecting with it,
a low-privileged user could enumerate every document in the tenant.

```
filter=''                          documentsList: []
filter='ownerEmployeeId==39463247' documentsList: []
filter='ownerEmployeeId!=39494707' Invalid filter provided: Unsupported operator
filter='companyId==339177'         documentsList: []
filter='true'                      Invalid filter provided: No expression found in filter
filter='1=1'                       Invalid filter provided: Malformed filter
```

The parser demonstrably read our input — it distinguishes an unsupported operator from a
malformed expression from a valid one — and a *valid* filter naming another employee still
returned nothing. Scope is applied independently of the filter. Enforced.

### Recruiting's own API, and a candidate's CV

The recruiting module has a separate API that no earlier sweep touched. Its routes came from
`performance.getEntriesByType('resource')` on the recruiter's application drawer:

```
/recruiting/api/v1/applications/{id}/profile/info
/recruiting/api/v1/applications/{id}/profile/bootstrap
/recruiting/api/v2/applications/{id}/profile/document-categories
/recruiting/api/documents/v2/{jobId}
/recruiting/application/{id}/preview-popup/{documentId}
```

This is the most sensitive data reachable in the tenant: a job applicant is **not an employee**,
so their name, email, phone, salary expectation and CV are a third party's personal data. LOWPRIV
is not a recruiter.

```
profile/bootstrap            403  {"error":{"message":"unauthorised","code":403}}
profile/document-categories  403  {"error":{"message":"Unauthorised","code":403}}
documents/v2/2822178         403  {"error":{"message":"Unauthorised","code":403}}
preview-popup/223476255      403  (the CV)
profile/info                 405  GET and POST -- method, not authorisation
profile/info  (PUT)          403  {"error":{"message":"unauthorised","code":403}}
```

The 405 was not accepted as an answer: a method error says nothing about authorisation, so the
route was retried until it answered the actual question. PUT returns 403, so the route is guarded;
GET and POST return 405 with no body of any kind. No leak, no finding.

**Personio is closed.** ~240 authorised requests, four bug classes, seven enforcement surfaces,
zero findings, zero false positives, zero rules-of-engagement violations beyond the one redirect
to an out-of-scope host, which is recorded above.
