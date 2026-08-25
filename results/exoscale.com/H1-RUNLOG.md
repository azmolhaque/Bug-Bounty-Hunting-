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

## Next

H3 (SOS bucket ACLs). S3-compatible implementations have a far richer history of ACL and
policy-parsing bugs than a policy engine that has now survived three separate attacks.
H2 (cross-org) remains blocked on a second organisation.
