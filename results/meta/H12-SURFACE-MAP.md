# H12 — Business sharing surface, mapped from the Business SDK

Built 2026-09-25 from `github.com/facebook/facebook-python-business-sdk`
(`facebook_business/adobjects/`, 1112 generated objects). The SDK is generated from Meta's
internal API spec, so this is the real edge list, not the documentation's curated subset.

**Zero requests sent to Meta.** Source reading only. No accounts required to produce this.

---

## The sharing model, as the API actually implements it

`/business` carries **four parallel asset families**. Understanding that they are parallel
is the whole point — each one is a separate authorization decision, and they were clearly
added at different times.

| Family | Meaning | Edges |
|---|---|---|
| `owned_*` | assets this business owns | `owned_ad_accounts`, `owned_apps`, `owned_businesses`, `owned_instagram_accounts`, `owned_instagram_assets`, `owned_offsite_signal_container_business_objects`, `owned_pages`, `owned_pixels`, `owned_product_catalogs`, `owned_whats_app_business_accounts` |
| `client_*` | assets shared **to** this business (it acts as agency) | `client_ad_accounts`, `client_apps`, `client_instagram_assets`, `client_offsite_signal_container_business_objects`, `client_pages`, `client_pixels`, `client_product_catalogs`, `client_whats_app_business_accounts` |
| `pending_*` | grants in flight, **both directions** | `pending_client_ad_accounts`, `pending_client_apps`, `pending_client_pages`, `pending_owned_ad_accounts`, `pending_owned_pages`, `pending_shared_offsite_signal_container_business_objects`, `pending_users` |
| relationship | business-to-business links | `agencies`, `clients`, `managed_businesses`, `managed_partner_businesses`, `owned_businesses` |

Note the asymmetry: **`client_*` has eight asset types, `pending_*` has five.** Three asset
types can be shared but have no pending-state edge exposed. Asymmetries in a generated API
are where the hand-written authorization checks diverge.

## The state machine — the single most promising construct

`BusinessAssetSharingAgreement` (`businessassetsharingagreement.py`):

```
Fields:  initiator · recipient · relationship_type · request_type · request_status

RequestStatus: PENDING · IN_PROGRESS · APPROVE · DECLINE · CANCELED · EXPIRED
               PENDING_EMAIL_VERIFICATION · PENDING_INTEGRITY_REVIEW
               MMA_DIRECT_ASSETS_{PENDING,APPROVED,DECLINED,EXPIRED}
```

Twelve states, two parties, and an explicit `initiator` / `recipient` split. A two-party
state machine with twelve states is the highest-yield authorization target on this surface.

Paired request edges on `/business`:
- `initiated_audience_sharing_requests`
- `received_audience_sharing_requests`

## Ranked targets

Each tied to a **published** payout sub-tier. Numbers from `00-PROGRAM.md`.

### T1 — Self-approval of a sharing agreement · *business & page take-over, $50k*

`request_status` is a writable-looking field on an object that names its own `initiator`
and `recipient`. Test whether the **recipient** can drive the status to `APPROVE` directly,
rather than the initiator granting it. If the check is "are you a party to this agreement"
rather than "are you the party entitled to *this* transition", it falls.

### T2 — Revocation that does not revoke · *Ads Audience $7.5k / page admin disclosure $5k*

Six of the twelve states are terminal-negative: `DECLINE`, `CANCELED`, `EXPIRED`,
`MMA_DIRECT_ASSETS_{DECLINED,EXPIRED}`. For each, establish access, drive to that state,
then re-issue the **same token** against the asset. Stale authorization after revocation is
clean, cheap to demonstrate, and hard to argue is intended.

*Carry the Adobe lesson: prove revocation against the Graph API JSON, never against a page
that returns 200 because it is a JS shell.*

### T3 — Access before verification · *business & page take-over, $50k*

`PENDING_EMAIL_VERIFICATION` and `PENDING_INTEGRITY_REVIEW` are states that exist
specifically to gate access behind a check. Does the grant function while in them? If yes,
both gates are decorative.

### T4 — Audience reachable outside the sharing relationship · *Ads Audience, $7.5k*

Meta's own wording is *"being able to use audiences outside of shared relationships between
businesses."* `CustomAudience` exposes `get_shared_account_info`, plus
`get_ad_accounts` / `create_ad_account` / `delete_ad_accounts` — an audience is bound **to
ad accounts**, and ad accounts are shared **to businesses**. Two hops, two different grant
systems, one of which predates the other. Test whether binding an unshared audience to a
shared ad account leaks it across the boundary.

`CustomAudienceSharingStatus` carries only `sharing_relationship_id` + `status` — a thin
object. Check whether `sharing_relationship_id` is validated against the caller at all.

### T5 — System user tokens across the boundary · *developer platform privacy assertions, $25k*

`create_system_user_access_token` mints a token bound to a system user, which is itself
scoped by `AssignedUser` (`business`, `user_type`). A system user in the agency business
holding a token — does its reach honour per-asset assignment, or per-business relationship?
This is the closest analogue to the Exoscale `parameters.bucket` binding work.

### T6 — Nested tenancy · *business & page take-over, $50k*

`create_owned_business`, `create_managed_business`, `create_managed_partner_business`,
`get_owned_businesses`. Businesses can own businesses. Every nesting level is a chance for
an authorization check to test the wrong ancestor. Does a grant to a parent implicitly reach
a child, or vice versa?

### T7 — Shared phone numbers · *contact point deanonymization, $10k*

`create_share_pre_verified_number`, `delete_share_pre_verified_numbers`,
`get_pre_verified_numbers`. Phone numbers shared **between businesses**. A contact point
crossing a tenant boundary is simultaneously an access-control bug and a deanonymization
bug, and Meta pays for the latter separately.

---

## What this does and does not give us

It gives us the complete attack list before spending a single authenticated request, so the
first token-holding session is execution rather than exploration. It is the Exoscale play —
build the surface from vendor SDK source rather than docs — applied to a target that is not
a security vendor.

It gives us **no finding**. Every T above is a hypothesis. None can be tested without two
accounts, two businesses and a live sharing relationship.

## Next action

Account creation is now the only blocker. Phase 1 of `H12-PROCEDURE.md`, unchanged:
two test accounts → two businesses → share **one Page at the narrowest role** → everything
else stays unshared as negative controls.

Then T1–T7 in order, one variable at a time, with the positive control, negative baseline,
token-debugger provenance and catch-all sentinel from Phase 2 in place before the first
attack request.

---

## Addendum — 2026-09-25, second SDK pass

### T1 is a one-request test

`BusinessAssetSharingAgreement.api_update` exists, and its entire parameter spec is:

```python
param_types = { 'request_response': 'string' }
request = FacebookRequest(node_id=self['id'], method='POST', endpoint='/')
```

So approving or declining a business asset sharing agreement is:

```
POST /v23.0/<agreement_id>
     request_response=<...>
```

**One string parameter, on a node addressed by ID alone.** Nothing in the request states
who the caller is relative to the agreement — the `initiator` / `recipient` split is
entirely implicit in the token. That is exactly the shape where a server checks *"are you a
party to this agreement"* rather than *"are you the party entitled to make this
transition."*

This upgrades T1 from a hypothesis to a minimal, single-request PoC. If the recipient can
POST `request_response` and drive the agreement to approval, that is an unauthorized
cross-business grant — *business & page take-over, up to $50k*.

Test order once tokens exist: B attempts the transition that only A should be able to make,
and A attempts the one that only B should. Both directions, because the check may exist on
one side only.

### Permission vocabulary — hypothesis checked, comes back weak

`Page` exposes two enum classes, `PermittedTasks` and `Tasks`. Both hold **29 entries**,
both include the same **14** `PROFILE_PLUS_*` values. They are mirrors used in different
parameter positions (granting versus filtering), not two competing vocabularies.

So the "grant in one vocabulary, check in the other" idea does **not** hold. Recorded as a
closed negative rather than left implied — it looked promising on first read and it is not.

The 29-value task list is still useful as the granularity axis for T1/T2: it is a wide
surface, and `PROFILE_PLUS_FULL_CONTROL` sitting in the same enum as `ANALYZE` means the
distance between the narrowest and widest grant is large.

`business.py` carries `PermittedTasks` but no `Tasks` class — a small asymmetry, noted, not
yet meaningful.

### Environment limit

The agent container's egress proxy denies `graph.facebook.com`, so **no request to Meta can
originate from the agent side.** All live probing runs from the operator's terminal. Source
mining, which is where the value has been, is unaffected.

---

## Unauthenticated probe — API version liveness. 2026-09-25, operator terminal

Nine requests, no auth, no account, no user data touched.
`GET https://graph.facebook.com/v<X>/me` with no token.

| Version | Response |
|---|---|
| v3.0 · v5.0 · v8.0 · v10.0 · v12.0 · v15.0 · v18.0 · v20.0 · v23.0 | **all identical** |

```json
{"error":{"message":"An active access token must be used to query information about the current user.",
          "type":"OAuthException","code":2500,"fbtrace_id":"..."}}
HTTP 400
```

**Every version back to v3.0 (April 2018) is accepted.** None is rejected as unsupported —
the API asks for a token rather than refusing the version.

Also recorded, from the bare root with no version and no path:

```json
{"error":{"message":"Unsupported get request. ...","type":"GraphMethodException",
          "code":100,"error_subcode":33}}
```

### What this proves, and what it does not

**Proves:** the version path is accepted, at least eight years back.

**Does not prove:** that old *semantics* are served. Meta may route every one of these to the
current backend and merely tolerate the version string in the path. That distinction cannot
be resolved without a token, so this is a **mapped precondition, not a finding** (FO-8/11 —
a reachable endpoint is not a boundary crossing).

### Why it is worth having

It adds a **version axis** to every target T1–T7. `BusinessAssetSharingAgreement` and the
partner-sharing model postdate v3.0 by years. Each hypothesis therefore gets run twice —
against v23.0 and against the oldest accepted version — on the theory that an authorization
check added to the current handler may not exist on the legacy path.

This doubles the test matrix for no extra account cost and is the kind of
operation-others-skip that the selection rubric identifies as the operator's edge.

### Two baselines banked for later

Both are needed to recognise a bypass when one appears:

- `OAuthException / code 2500` — no token supplied.
- `GraphMethodException / code 100 / error_subcode 33` — Meta's **unified** "object does not
  exist **or** you cannot see it". They deliberately collapse those two cases so the API
  cannot be used as an existence oracle. Any response that *differs* from subcode 33 on an
  object we should not be able to see is itself the signal.

### Open

Find the floor — probe v1.0, v2.0, v2.5, v2.8, v2.12. Anything below v3.0 predates Meta's
post-2018 permissions lockdown entirely.

### Control test — is the version string actually validated? 2026-09-25

The v1.0-is-live result looked too good, so it was controlled before being carried forward.
A version from 2010 answering is more plausibly *no validation* than *fifteen-year-old
semantics still served*. Four requests with versions that have never existed:

| Probe | Response | Reading |
|---|---|---|
| `v99.0`, `v7.3`, `v42.9` | `Unknown path components: \/me` (OAuthException 2500) | **not** parsed as a version — the string is taken as a node, and `/me` beneath it is unknown |
| `v0.1` | `An active access token must be used…` | parsed as a **valid version** |
| no version at all | `An active access token must be used…` | defaults to current |

**Validation is real.** The earlier liveness result therefore stands on its own terms:
v1.0 through v23.0 are genuinely accepted versions, not path normalisation. The version axis
on T1–T7 is worth the doubled test matrix.

The prediction going in was the opposite — that `v99.0` would answer like the rest and the
legacy hypothesis would die. It did not. Four requests turned a guess into a fact, which is
FO-17 working as intended rather than being learned the expensive way.

#### A free enumeration oracle

The two error strings discriminate cleanly, with no token:

- `Unknown path components: \/me` → version string not recognised
- `An active access token must be used…` → version recognised

That enumerates Meta's entire accepted-version set unauthenticated. It is **not** a finding —
supported API versions are public documentation, so nothing is disclosed that is not already
published. It is a mapping tool for choosing which legacy paths to re-run T1–T7 against.

#### Open — the `v0.1` anomaly

`v0.1` parses as a version. Either it is a real ancient entry, or low/unrecognised versions
clamp to the oldest supported. Discriminator: `v2.12` was the last v2 release and `v3.3` the
last v3. If `v2.13` and `v3.4` are rejected while `v2.12` and `v3.3` are accepted, the set is
a precise allowlist of real versions and `v0.1` is a genuine target. If they are accepted, it
is a range clamp and `v0.1` means nothing.

#### Resolved — precise allowlist, with one anomaly at major version 0

| Accepted | Rejected | Known release history |
|---|---|---|
| `v2.12` | `v2.13` | v2.12 was the last v2 release |
| `v3.3` | `v3.4` | v3.3 was the last v3 release |
| `v7.0` | `v7.1` | v7.0 was the only v7 |
| `v0.0`, `v0.9` | — | **no v0.x has ever existed** |

Three clean boundary pairs. The set is a **precise allowlist of genuinely released
versions** — Meta rejects plausible-but-nonexistent minors exactly. So the liveness result is
confirmed a second time: v1.0 through v23.0 are really served, and the version axis on T1–T7
is worth running.

The anomaly: the allowlist is exact for v1 and above, and **loose for major version 0** —
any minor is accepted.

**This is not a finding.** Attacker gain is nil: `v0.x` almost certainly resolves to the
default, i.e. the *current* version, which is the most restrictive path available. Nothing is
bypassed and there is nothing to report. Recorded only because it implies one concrete
authenticated test.

**The test it implies:** does `v0.0` route to *current* or to *oldest*? If it silently
resolves to the oldest supported version, it is an undocumented route into legacy semantics
and belongs in front of every T1–T7 legacy run. Settle it in three requests once a token
exists — compare field availability across `v0.0`, `v1.0` and `v23.0` and see which `v0.0`
matches.

---

## Unauthenticated phase: closed

Everything testable without an account has now been tested. Result: **no findings, and no
leads left open that a token would not be required to pursue.** That is the correct outcome —
the phase existed to build the map and the baselines, not to produce a bug.

Carried into the authenticated session:

1. Seven ranked targets (T1–T7), each against a published payout tier.
2. T1 reduced to a single request: `POST /<agreement_id>` with `request_response`, run in
   **both** directions.
3. A confirmed version axis — every target re-run against a legacy version.
4. Two error baselines: `OAuthException 2500` (no token) and `GraphMethodException 100 /
   subcode 33` (Meta's unified does-not-exist-or-not-permitted). A deviation from subcode 33
   on an object we should not see is itself the signal.
5. One open routing question on `v0.0`.
6. Two closed negatives recorded rather than left implied: the `PermittedTasks`/`Tasks`
   vocabulary idea, and the initial assumption that version strings were unvalidated.

Blocker is account creation. Nothing further can be learned without it.
