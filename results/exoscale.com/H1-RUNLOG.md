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

## Findings

_None yet. A denied operation that returns 200 and takes effect, or nothing (FO-9)._
