# Wiz Chain 4 — GraphQL cross-tenant IDOR (Org A token → Org B data)

**Target:** `app.wiz.io` — **IN-SCOPE**, TIER1, explicitly exempt from the 6-month
acquisition blackout (verified `scripts/scope-check.sh wiz.io`, 2026-07-25).
**Program:** Google VRP (Wiz acquired Mar 2026).
**Class:** Broken cross-tenant isolation (multi-tenant CNAPP).
**Why this one:** it is the only live candidate whose *entire success condition* is a crossed
boundary. Every stalled report in this portfolio (VT, AppSheet, Wiz F001, Photomath) died at
"precondition, no cross". This test has no informative middle state — either Org A's token
returns Org B's data, or it doesn't.
**Rig:** laptop + browser DevTools (Burp optional). Two trial orgs.

---

## The boundary that must actually be crossed (FO-9)

A finding exists **only** if:

> **Org A's JWT, sent to the Wiz GraphQL API with an object ID belonging to Org B,
> returns Org B's data.**

Not a finding: schema introspection, field-name enumeration, a `node(id:)` query existing,
UUIDs being guessable, a 403 that "looks inconsistent". Those are all preconditions.
**Data from the other tenant, in hand, or it is nothing.** (FO-8/9/11)

---

## PHASE 0 — the three gates. Do these BEFORE any cross-tenant attempt.

Run in order. Screenshot each. Without them the final result is unprovable.

| # | Gate | Why it matters |
|---|---|---|
| **0A** | **Org A's token reads Org A's own object → `200` + data** | Proves the query shape, auth header, and endpoint are all correct. Without this, a `403` on B's object might just mean "my query was malformed" |
| **0B** | **Org B's token reads Org B's own object → `200` + data** | Proves B's object ID is real and readable *by its owner*. Without this, a `404` on the cross might just mean "that ID doesn't exist" |
| **0C** | **Org A (browser, logged in as A) cannot see Org B's object in the UI** | The human-level boundary |

**FO-2 catch-all control:** also send a **garbage** object ID (`00000000-0000-0000-0000-000000000000`)
with A's token. Record the response. If garbage IDs also return `200` with content, the API
is a catch-all and every "hit" is a false positive — stop and re-baseline.

---

## PHASE 1 — two independent tenants

1. Sign up at **`https://app.wiz.io/signup`** → **Org A** (email 1).
2. Sign up again, **different email, different org name** → **Org B**.
   - Use two separate browser profiles, or one profile + one incognito. Never share a session.
   - If signup demands a business domain, note it and try: personal domain, alias addressing,
     or the "Request a demo"/free-tier path. **If both orgs cannot be created, STOP** — a
     single-tenant test cannot prove cross-tenant isolation, and faking it is worthless.
3. In **each** org, create at least one distinctly-named object so ownership is unambiguous:
   - Project named `zt-orgA-<canary>` in A, `zt-orgB-<canary>` in B
   - Canary strings: random, ≥8 chars, no English words (e.g. `q4m7xk2p`). Keep out of git.

---

## PHASE 2 — capture tokens and the request shape

In **Org A's** browser: **DevTools → Network → filter `graphql`** → click around the portal.

Capture from a real request:
- the **endpoint URL** (e.g. `https://api.<region>.app.wiz.io/graphql` — record it exactly)
- the **`Authorization: Bearer …`** JWT
- a working **query body** (copy one verbatim — do not hand-write GraphQL if you can copy)

Repeat in **Org B's** browser for B's JWT.

> Tokens are short-lived. Re-capture if you start getting `401`. A `401` is **not** a
> negative result — it means the token expired, not that the API is secure. Do not record a
> `401` as "defended".

Optional: `scripts/graphql-attack-wiz.sh` for introspection (schema only — **not a finding**),
`scripts/graphql-idor-wiz.sh` for the probe loop.

---

## PHASE 3 — collect the object IDs

From **Org B's** session, note the IDs of B's objects. Priority order (highest impact first):

| Target | Why it matters if it crosses |
|---|---|
| `connector(id:)` | Cloud connector = **cloud credentials / deep account access** — Critical |
| `cloudResource(id:)` | Direct cloud asset data from another tenant |
| `issue(id:)` | Another tenant's security findings (their unpatched vulns) |
| `project(id:)` | Tenant structure/inventory |
| `node(id:)` | Relay global-ID lookup — **most dangerous if present**, often misses per-type authz |

Record B's IDs. These are the needles.

---

## PHASE 4 — the decisive test

**Org A's JWT + Org B's object ID.** Nothing else changes.

```bash
curl -s -i -X POST 'https://<GRAPHQL-ENDPOINT>' \
  -H 'Authorization: Bearer <ORG_A_JWT>' \
  -H 'Content-Type: application/json' \
  --data '{"query":"query($id:ID!){ project(id:$id){ id name } }","variables":{"id":"<ORG_B_PROJECT_ID>"}}'
```

Repeat per target type (`connector`, `issue`, `cloudResource`, `node`).

### Reading the result

| Response | Meaning | Action |
|---|---|---|
| **`200` + Org B's real data** (B's canary name appears) | **CONFIRMED cross-tenant IDOR** | Stop. Screenshot everything. Go to evidence. |
| `200` + `data: null` + authz error | Correctly isolated | Log negative, next target type |
| `403` / `404` / "not found" | Correctly isolated (B's object is invisible to A) | Log negative |
| `401` | **Token expired — not a result.** Re-capture and re-run | — |
| `200` on the **garbage** ID too | Catch-all → all hits invalid | Re-baseline (FO-2) |

**The proof is the canary**, not the status code. A `200` whose body contains `zt-orgB-q4m7xk2p`
— a string that exists only inside Org B — is unambiguous. A `200` with an empty object is not
a finding.

---

## Drop conditions (say so plainly; do not force it)

- Every object type returns `403`/`404`/null across tenants → **isolated. Drop Chain 4.**
  Move to Chain 3 (webhook SSRF) or Chain 13 (forensics IDOR).
- Only introspection/schema worked → **not a finding** (schema enumeration without record
  access is on the Hard Rejection List — cf. the Salesforce "873 fields" N/A).
- The two "orgs" turned out to share a tenant → the test is void, not negative.
- Behaviour matches documented Wiz multi-org/shared-view features → intended (Quality Bar #2).
  **Check the docs before writing anything.**

---

## Evidence checklist (CLAUDE.md §9.8 — complete BEFORE any submit)

- [ ] Phase 0A screenshot: A's token → A's own object → `200` + data
- [ ] Phase 0B screenshot: B's token → B's own object → `200` + data
- [ ] Phase 0C screenshot: A's UI cannot see B's object
- [ ] FO-2 catch-all: garbage ID response recorded
- [ ] Date/time + external IP (`curl ifconfig.me`)
- [ ] **The decisive request/response pasted verbatim** — full headers + body bytes, with
      **Org B's canary string visible** in A's response
- [ ] HTTP status + response size
- [ ] Before/after differential: expected (403/null) vs observed (200 + B's data)
- [ ] Both orgs are ours; **no third-party tenant was ever queried**
- [ ] JWTs **redacted** in the report (truncate to first/last 8 chars)
- [ ] First-person plain voice, real terminal output (FO-10)

---

## Safety

- Read-only queries. **No mutations against another tenant** — do not create, modify, or
  delete anything in Org B via A's token, even if it appears possible. Reading proves the
  isolation break; writing is destructive testing on a live multi-tenant platform.
- Only ever use object IDs from **our own two orgs**. Never enumerate or guess IDs that might
  belong to a real customer tenant.
- If a response ever contains data belonging to a **third party**, stop immediately, do not
  save it, and report that fact — that is a live production leak, not a lab result.

---

## STATUS 2026-07-25 — **BLOCKED at Phase 1 (no self-serve tenant)**

`app.wiz.io/signup` resolves to `app.wiz.io/login/email-challenge` — a **login** flow, not a
signup. Wiz is enterprise / sales-led; there is no self-serve trial that yields a tenant.
Submitting an address returns *"If your individual email is associated with one or more Wiz
tenants, we've sent a sign in link… If your organization's email domain is [associated], we've
notified your Wiz admins."*

**Two consequences:**

1. **Chain 4 cannot be run.** Cross-tenant isolation cannot be tested with fewer than two
   tenants, and there is no honest substitute. Per the drop condition above: STOP, do not
   force it. Chains 3 and 13 are blocked by the same wall (all need a tenant).

2. **Do not iterate on that form.** By Wiz's own message, submitting addresses can notify the
   Wiz admins of whatever organisation owns the domain. Repeated submissions across addresses
   are effectively **tenant enumeration directed at third parties** — outside authorised
   scope, and it generates noise for real customers. One attempt on our own domain was fine;
   a sweep is not. **No further probing of this endpoint.**

**Unblock condition:** a legitimately provisioned Wiz tenant (e.g. an employer/client
engagement with written authorisation). Until then Chains 3/4/13 stay parked.
