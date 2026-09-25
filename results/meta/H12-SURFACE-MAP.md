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
