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

| Gate | Command | Expected | Result |
|---|---|---|---|
| **0A** positive control | `exo dns list` | **200** (empty table is fine — read the status from mitmdump, not the CLI text) | _pending_ |
| **0B** negative baseline | `exo compute instance list` | denied — record exact error + status | _pending_ |

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

## Findings

_None yet. A denied operation that returns 200 and takes effect, or nothing (FO-9)._
