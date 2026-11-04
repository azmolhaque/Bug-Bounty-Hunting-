# Exoscale H4 — role-assumption privilege escalation

**Target:** `api-ch-gva-2.exoscale.com/v2/iam-role/{id}/assume` — Tier 2 (**€50–€5,000**),
IAM explicitly in scope.
**Class:** Privilege escalation / broken access control.
**Cost:** 0.00 CHF. No billable resource is created. **Requests:** ~6.
**Customer risk:** none. Only our own organisation's own roles are touched.

---

## Why this exists at all

`egoscale/v3/schemas.go` shows two fields on `IAMRole` that the portal's role-creation form
**never displayed** when we built `zt-dns-only` field by field:

```go
AssumeRolePolicy *IAMAssumeRolePolicy   // who is permitted to assume this role
MaxSessionTtl    int64                  // how long assumed credentials live
```

And the operation returns real credentials:

```
POST /v2/iam-role/{id}/assume     {"ttl": <int64>}
  -> {"key": ..., "secret": ..., "expires-at": ..., "role-id": ..., "org-id": ...}
```

A security control that the product's own UI does not let you configure is a control most
customers have never set. That is the whole hypothesis.

---

## The boundary that must be crossed (FO-9)

A finding exists **only** if:

> **Our `zt-dns-only` key receives working credentials for a role it should not be able to
> assume** — and we can show the restricted policy, the assume request, and the returned
> credentials functioning.

**Not a finding:** the endpoint existing · `AssumeRolePolicy` being absent from the UI ·
a confusing error · a 200 with no `secret` · assuming a role *less* privileged than our own.

---

## Prerequisites

- `exo-req.py` in `~/exoscale`, `EXO_KEY` / `EXO_SECRET` exported for **`zt-dns-only-key`**
- Role IDs from **our own** portal IAM page — never constructed, never guessed:
  - `Owner`  → `fd475130…` (get the full UUID from the portal, copy button)
  - `Billing` → `55c3473d…`
  - `zt-dns-only` → note its UUID too
- `curl ifconfig.me` recorded for the evidence pack

---

## The tests, in order

### 0 — controls first (do not skip)

| # | Request | Purpose | Expected |
|---|---|---|---|
| 0A | `GET /v2/dns-domain` | key still live and signing works | 200 |
| 0B | `GET /v2/iam-role` | `iam` service is denied to us | 403 `Forbidden by role policy for iam` |

0B matters: it establishes on the record that our key has **no** `iam` access. Everything
after it is measured against that.

### (a) Which gate applies?

```bash
./exo-req.py POST /v2/iam-role/<ZT_DNS_ONLY_UUID>/assume '{"ttl": 3600}'
```

Assuming **our own role** — the one our key is already bound to. No escalation either way,
so this is purely diagnostic.

| Result | Meaning |
|---|---|
| **403 `...for iam`** | Assume is gated by the ordinary service policy. Escalation via this route is closed; record it and go to (c) only |
| **200 + `secret`** | **Assume is NOT gated by the service policy.** The only control is the target role's `AssumeRolePolicy` — which the portal never let us set. Continue to (b) immediately |
| 400 / 422 | Body shape wrong — fix `ttl` and retry. Not a result |

### (b) The escalation — assume `Owner`

Only if (a) returned 200.

```bash
./exo-req.py POST /v2/iam-role/<OWNER_UUID>/assume '{"ttl": 3600}'
```

| Result | Meaning |
|---|---|
| **200 + `key` + `secret`** | 🎯 **Critical.** A dns-only credential just minted Owner credentials for the organisation |
| 403 | Correctly gated by `AssumeRolePolicy`. Try `Billing` for completeness, then close |

**If it returns credentials — STOP.**

1. Screenshot and save the full request and response.
2. **Prove they work with exactly one read**, so the report shows credentials, not a JSON blob:
   `EXO_KEY=<assumed> EXO_SECRET=<assumed> ./exo-req.py GET /v2/iam-role`
   That call is 403 for our real key (control 0B) — a 200 here is the differential that makes
   the report undeniable.
3. **Do nothing else with them.** No writes, no key creation, no org-policy changes. The
   escalation is the finding; anything further is unnecessary and looks like an intrusion.
4. Let them expire, note the expiry in the report, and write it up the same session.

### (c) TTL validation

```bash
./exo-req.py POST /v2/iam-role/<ZT_DNS_ONLY_UUID>/assume '{"ttl": 31536000}'
```

One year. Compare `expires-at` in the response against the role's `MaxSessionTtl`.

- Clamped to the maximum → correct.
- **Honoured** → credentials outlive their configured lifetime. On its own that is a Low/Medium,
  and it only earns a report if the assumed role is meaningfully privileged. Judge honestly.

Also try `{"ttl": -1}`, `{"ttl": 0}`, and a value beyond int64 — sign-handling bugs in TTL
arithmetic occasionally produce sessions that never expire.

### (d) Do assumed credentials carry `Permissions`?

Only relevant if (a) or (b) yielded credentials. Check whether the assumed session holds
`reset-iam-organization-policy` — the permission we deliberately left unchecked on our role.

**Read-only check.** `GET /v2/iam-organization-policy` with the assumed credentials. **Do not
attempt the reset.** Demonstrating that a restricted key can obtain a session holding a
governance-bypass permission is sufficient; actually resetting the org policy is destructive
testing on a live account and proves nothing extra.

---

## Reading results

| Response | Meaning |
|---|---|
| 200 with `key` + `secret` for a role we should not hold | 🎯 Finding. Capture verbatim |
| 403 naming `iam` | Service policy gates assume. Correct. H4 closes at (a) |
| 403 not naming `iam` | Gated by `AssumeRolePolicy`. Correct, **and interesting** — note the wording |
| 404 | Role ID wrong. Re-copy from the portal. Not a result |
| 401 | Signature problem — `ttl` body must be byte-identical to what was signed. **Rig failure** |

---

## Drop conditions

- (a) returns 403 and (c) clamps correctly → **enforcement is sound. H4 closes.** Log it
  honestly (FO-7) and move to H5.
- Credentials are issued but only for roles **at or below** our own privilege → that is
  documented delegation behaviour, not escalation. **Not a finding.**
- Behaviour matches the published IAM documentation → intended (Quality Bar #2). Read the
  policy guide before writing anything.

---

## Evidence checklist (CLAUDE.md §9.8)

- [ ] `zt-dns-only` policy JSON — `deny` default, `dns` only
- [ ] Control 0B: `GET /v2/iam-role` → 403 with our real key
- [ ] The assume request and response **verbatim**, headers and body
- [ ] `X-Intigriti-Username: gorib` visible in the captured request
- [ ] The one confirming read performed **with the assumed credentials**, next to 0B — the differential
- [ ] Date/time, external IP (`curl ifconfig.me`), tool versions
- [ ] Screenshot of the terminal showing the escalation
- [ ] **All keys and secrets redacted to first/last 4 characters**
- [ ] Statement that the credentials were used for nothing further and allowed to expire
- [ ] Only our own organisation involved; no ID guessed — both role IDs copied from our portal
- [ ] First-person plain voice, real terminal output (FO-10)

## Safety

- Read-only with the single exception of the assume call itself, which mints a session rather
  than modifying anything.
- **Never** call `reset-iam-organization-policy`, create keys, or modify roles with assumed
  credentials.
- If any response ever contains data belonging to another organisation: stop, do not save it,
  report that fact.
