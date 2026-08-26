# Exoscale H1 — run log

**Program:** Exoscale (Intigriti) · **Researcher:** `gorib` · **Header:** `X-Intigriti-Username: gorib`
**Rule:** ≤10 req/s · never `portal.exoscale.com/api/tickets` · own org only.

---

## Setup — 2026-08-26

| Item | Value |
|---|---|
| Org | `exo-org-a` (`gorib+exoA@intigriti.me`) |
| Portal slug | `goribexoaintigritime` |
| Balance at start | **20.00 CHF** (free credit, card authorised — no charge) |
| Instances | **0** — none created, none needed |
| Built-in roles | `Billing` (`55c3473d…`), `Owner` (`fd475130…`) — both non-editable |

### Test role `zt-dns-only`

Role permissions: **both left unchecked** — `bypass-governance-retention`,
`reset-iam-organization-policy`. Granting either would make any observed escalation a granted
feature rather than a bug.

```json
{
  "default-service-strategy": "deny",
  "services": {
    "dns": {
      "type": "allow"
    }
  }
}
```

API key `zt-dns-only-key` bound to that role. Secret held locally, never committed.

---

## Gates

**Both gates PASSED — 2026-08-26 03:34 UTC+6, zone `ch-gva-2`, `exo` 1.99.0 (egoscale v3.1.42).**

| Gate | Request | Result |
|---|---|---|
| **0A** positive control | `GET /v2/dns-domain` | **200 OK, 18b** (empty list) ✅ key, signing and header all work |
| **0B** negative baseline | `GET /v2/instance` | **403 Forbidden, 50b** — `Forbidden by role policy for compute` ✅ |

The 403 body names the layer that denied it (`role policy`) and the service (`compute`), so
every later denial is attributable rather than ambiguous.

### Free result: zone-crossing axis closed for `ListInstances`

`exo compute instance list` fans out to **all 8 zones** automatically. Every one returned 403:

`ch-gva-2` · `ch-dk-2` · `at-vie-1` · `at-vie-2` · `de-fra-1` · `de-muc-1` · `bg-sof-1` · `hr-zag-1`

Per-zone policy enforcement is **consistent**, including in `hr-zag-1` (new zone, not present in
the older docs — the most likely candidate for a stale policy cache). That axis is answered for
this endpoint without a single extra request.

### Observation that reframed the hypothesis

`GET /v2/zone` returned **200 OK, 1.3k** to a key whose policy is `deny` + `dns` only.

**Not a finding** — the zone list is public information (published on the website and in the
docs), so nothing was disclosed that an attacker lacks. Quality Bar #1 fails: attacker gain is nil.

**But it is a signal.** Authorization is evaluated **per-endpoint against a service mapping**, and
at least one endpoint is unmapped or deliberately exempt. The question worth answering is whether
any *other* unmapped endpoint returns something that is **not** public. That is a sharper
hypothesis than the one we started with, and it came out of a control rather than a guess.

Rig: `exo` CLI → mitmdump `:8080` addon injecting the required header. mitmproxy CA must be in
the Windows **Trusted Root** store or `exo` (Go, uses the OS trust store) fails TLS.
**A TLS or signature error is a rig failure, not a test result.**

---

## Surface noted during setup (test only after the gates pass)

| Item | Why it's interesting |
|---|---|
| **ORGANIZATION POLICY** | A *second* enforcement layer above role policies. Two evaluators in one authorization path — do they agree on precedence, and is the org policy enforced on the API or only in the portal? |
| **`reset-iam-organization-policy`** | A named, deliberately-gated permission. Can a role *without* it still reset the org policy via the API? |
| **Service-class `RULES`** | A *third* layer: per-operation control inside a service. New API operations that were never mapped into the rules table fall through — a classic miss. |
| **KMS** (`kms`) | Added to the denied-service attack list. A `dns`-only key reaching key management is a far better story than one reaching compute. |

---

## H1 RESULT — **CLEAN NEGATIVE. Closed 2026-08-26.**

Three independent axes, ~120 requests, no bypass. Enforcement is sound.

### Axis 1 — service coverage (`h1-sweep.py`, 42 endpoints)

**41 of 42 denied.** Only `/v2/dns-domain` — the single allowed service — returned 200.
Every sensitive class refused: `iam`, `kms`, `organization`, `sos`, `compute`,
`block-storage`, `dbaas`, `ai`. Endpoint list taken from egoscale v3 `operations.go`
(371 operations, 134 GET, 51 with no path parameter), so **no resource ID was ever
constructed or guessed** — customer resources were unreachable by construction, not by care.

### Axis 2 — zone consistency (free, via the CLI's own fan-out)

`GET /v2/instance` → 403 in **all 8 zones** including the new `hr-zag-1`. No per-zone
policy-cache drift.

### Axis 3 — path normalisation vs policy mapping (`h1-pathvariants.py`, 32 requests)

16 variants each against `/v2/api-key` and `/v2/instance` — traversal, double slash,
percent-encoding, semicolon params, case, trailing dot/space/null, overlong UTF-8.
**Nothing reached a handler.** Every variant resolved to 403, 404 or 400.

**Notable — the system fails closed.** Normalised variants returned a **39-byte** 403 where
the baseline returned 46/50 bytes. The shorter body drops the service name, i.e. those
requests were denied by *default-deny before the service was resolved*, rather than by a
matching rule. Unrecognised paths cannot fall through. That is deliberate design, not luck.

---

## Side observation — unauthenticated endpoint allowlist (`h1-noauth.py`)

Three endpoints answer with **no `Authorization` header at all**, while returning **403 to
our authenticated restricted key**:

| Path | No auth | Restricted key |
|---|---|---|
| `/v2/zone` | 200, 1312 b | 403 |
| `/v2/instance-type` | 200, 9643 b | 403 |
| `/v2/template` | 200, 17002 b | 403 |

This explains the `/v2/zone` contradiction we saw between the CLI and our signed request:
egoscale performs zone discovery unauthenticated, and that path never reaches the policy engine.

**NOT REPORTED — deliberately.** Every byte returned is already public: zone names and
endpoints, instance-type specs (the pricing page), and the OS/marketplace template catalogue.
Attacker gain is **nil**, so Quality Bar #1 fails and the Hard Rejection List (information
disclosure with no exploitable data) applies. Submitting it would earn an informational close
and cost signal on a program where we have none banked.

The *inversion* is architecturally odd — a valid-but-restricted credential gets **less** than
no credential — but no privilege is gained, so it stays a note, not a report.

---

## Findings

**None.** No denied operation ever succeeded. Per FO-7 this is logged as a negative result,
not padded into a report. Per FO-9, a precondition is not a finding and neither is a
public-data endpoint.

**Cost:** 0.00 CHF consumed. Balance unchanged at 20.00 CHF; no billable resource created.

---

## COST DISCIPLINE — binding for every Exoscale session

The account is **post-paid with no hard spending cap**. The operator is funding this
personally and cannot absorb an unexpected bill. These rules are not advisory.

1. **No compute instances, ever.** Instances bill per hour, continuously, used or not.
   They are the only thing here that burns money at a meaningful rate. **No hypothesis in
   H1, H2 or H3 requires one.**
2. **State the cost before creating anything.** If the cost is unknown, find it out first.
   Never "create it and see."
3. **Delete in the same session as you create.** Not "later", not "next time".
4. **Check the balance at the start AND end of every session.** If it moved at all — stop,
   find out why, before any further testing.
5. **SOS objects for H3 must be a few KB each.** Priced per GB-month; a handful of small
   objects is a fraction of a centime against 20.00 CHF of credit.
6. **If the operator stops testing, close the organisation.** A dormant post-paid account is
   an open liability, not a neutral state.

**Activation charge, 2026-08-26 02:46:** CHF 20.00 to DBBL card, Exoscale Lausanne.
Not yet established whether this is an authorisation hold (reverses in ~7–30 days) or a
capture converted to the 20.00 CHF account credit. Check portal Billing for an invoice;
`support@exoscale.com` for a refund on closure. **Do not use the portal ticket form** —
it calls `portal.exoscale.com/api/tickets`, which the program rules prohibit.

**Consumed to date: 0.00 CHF.**

### Billing state verified in portal — 2026-08-26 04:23

| Page | Reading |
|---|---|
| **Invoices** | **"No resource available"** — nothing invoiced |
| **Usage Details** | **0.00 CHF** total. Sole line item: `Key Management Service - default key`, 0.00 CHF/hour × 1.41 h = **free** |
| **Current balance** | 20.00 CHF, unchanged |
| **Billing mode** | POST-PAID (monthly invoice, default card charged for the due amount) |
| **Credit threshold** | was 15 CHF → **set to 19 CHF** so any real consumption trips an alert immediately |

No invoice exists behind the card authorisation, so it should reverse (typically 7–30 days).
If it has not reversed by late September, email `support@exoscale.com` with the date and amount.

**Tripwire in place:** balance alert at 19 CHF. Combined with "no instances, ever", a
surprise bill would require both the alert to fail and a billable resource to exist.

---

## H4 session 1 — role assumption. 2026-08-26 07:50–08:02 UTC

Key `zt-dns-only-key`, zone `ch-gva-2`, external IP `180.148.212.32`, balance 20.00 CHF (unchanged).

### Controls

| Request | Result |
|---|---|
| `GET /v2/dns-domain` | **200**, `{"dns-domains": []}` — key live, signing correct |
| `GET /v2/iam-role` | **403**, `Forbidden by role policy for iam` — no `iam` access, on the record |

### `POST /v2/iam-role/{id}/assume`

| Target | Body | Result |
|---|---|---|
| `zt-dns-only` `538cf5fe-…` | `{"ttl":3600}` | **500** `server error` |
| `Billing` `55c3473d-…` | `{"ttl":3600}` | **500** `server error` |
| `Owner` `fd475130-…` | `{"ttl":3600}` | **500** `server error` |
| sentinel `00000000-…0000` | `{"ttl":3600}` | **404** `not found` |
| `zt-dns-only` | `{}` | **400** `missing keys 'ttl'` |

All role IDs copied from our own portal. The sentinel is an all-zero UUID that cannot be a
real role — no identifier was guessed (FO-14).

### What this establishes

- The 500 is **not** generic (sentinel → clean 404) and **not** a body-parsing crash
  (`{}` → clean 400). It occurs only when a real role and a valid body reach the handler.
- It faults for **every** role in the organisation, including the built-ins — so it is not
  caused by our role specifically.
- Most likely reading: `AssumeRolePolicy` is `null` on every role here, because nothing that
  created them ever set one (the portal form has no such field), and the handler faults
  instead of evaluating.

### Ordering observation

Sentinel UUID returns **404**, not 403, while `GET /v2/iam-role` with the same key returns
**403**. On the assume endpoint, **role lookup precedes the policy decision** — an existence
oracle. Weak in practice (role IDs are UUIDs; we will not enumerate), recorded for completeness.

### Verdict

**Not reportable.** A 500 with a bare `"server error"` body is an unhandled service defect, not
a boundary crossing. No credential was issued, nothing escalated. Quality Bar #1 fails and the
Hard Rejection List (verbose/error responses with no exploitable data) applies.

## H4 session 2 — trust policies and the CEL evaluator. 2026-08-26 08:22–08:50 UTC

Owner-scoped key `zt-owner-key` created for the session and **deleted afterwards**.

### Correction to session 1

The `iam` service policy **does** gate `POST /assume`. On roles created via the API the
restricted key gets a clean `403 Forbidden by role policy for iam`. The earlier 500s were old
roles faulting *before* that check, not the check being absent.

### `assume-role-policy` is persisted and enforced

Roles created via API with a trust policy (the portal cannot set one; `resources: []` is
rejected — the validator wants a non-empty set, so omit the field):

| Role | Trust rule | `owner` assume result |
|---|---|---|
| `zt-assume-deny` | `action: deny, expression: "true"` | **403** `Forbidden by resource policy for iam - A deny rule matched. Rule index: 0` |
| `zt-assume-allow` | `action: allow, expression: "true"` | **404**, 9 bytes, **plain text**, no Content-Type |

`GET /v2/iam-role/{id}` does **not** display `assume-role-policy` or `max-session-ttl` — but
they clearly persist. A read-back gap, not a data-loss bug. (Worth noting: an administrator
cannot verify a trust policy they configured. Not reportable — no attacker gain.)

### The 404 oracle

The plain-text 404 differs from the API's JSON 404 (`{"message":"not found"}`, 23 b, with
Content-Type). Two different layers. Authorization **passed** and the request forwarded to a
role-assumption backend that is not deployed — which also explains the session-1 500s.

**Useful by-product:** `403` = denied, `404` plain = authorization passed. A clean decision oracle.

### CEL evaluator — write-time validation vs runtime behaviour

| Expression | Create | Assume |
|---|---|---|
| `this is not valid cel` | **400** — parse error with caret | — |
| `nosuchvar.x == 1` | **200 accepted** | **403** `Forbidden by resource policy for iam` |
| `1/0 == 1` | **200 accepted** | **403** (same) |
| `"a" + 1 == "a1"` | **200 accepted** | **403** (same) |

The validator **parses but does not type-check**: CEL is statically typed, so an unbound
variable and `"a" + 1` should both fail compilation, and all three were accepted as security
rules.

**But evaluation fails CLOSED**, and deliberately so — the message for an erroring rule
(50 b, no rule index) is *distinct* from a genuine match (87 b, `Rule index: 0`). Someone
handled the error path on purpose and chose deny.

### Verdict

**Clean negative. No finding.** The fail-open hypothesis — the highest-ceiling item in
`02-STRATEGY-2026-08.md` — is dead for the IAM evaluator.

Residual observations, all **not reportable** (no attacker gain, Hard Rejection List):
500 on roles lacking a trust policy · undeployed assume backend returning a bare 404 ·
`GET` not returning `assume-role-policy` · write-time validation not type-checking (fails
closed, so no impact).

### Cleanup

5 test roles deleted; `zt-owner-key` deleted. Balance 20.00 CHF, unchanged. 0 instances.

---

## Running tally — Exoscale authorization, 4 independent attacks

| Attack | Requests | Result |
|---|---|---|
| Service coverage, 42 endpoints | 42 | 41/42 denied |
| Zone consistency, 8 regions | 8 | Uniform |
| Path normalisation, 16 variants × 2 targets | 32 | Fails closed on unrecognised paths |
| CEL expression errors, 3 classes | 7 | Fails closed, distinct messaging |

This is a well-engineered authorization stack, and that is now an evidenced conclusion rather
than an assumption. It is consistent with the programme's 0.16 accepted-reports-per-researcher
figure recorded in `00-PROGRAM.md`.

## Next

H3 (SOS bucket ACLs). S3-compatible implementations have a far richer history of ACL and
policy-parsing bugs than a policy engine that has now survived three separate attacks.
H2 (cross-org) remains blocked on a second organisation.
