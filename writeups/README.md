# Writeups

Publishable, portfolio-grade accounts of finished findings. These mirror the public
`security-writeups` repo — corrected against the source-of-truth report threads and
written in plain human voice per METHODOLOGY FO-10 (no AI-report tells) and FO-13
(honest severity-vs-reward calibration).

| File | Target | Program | Outcome | Ref |
|------|--------|---------|---------|-----|
| `2026-05-exposed-iam-frontend-google-vrp.md` | `rip.photomath.net` | Google VRP | Fixed (P2/S2), credit / Honorable Mention | Issue 509594209 |

## Corrections applied vs. the originally-published version (2026-07-10)
Reconciled against the real IssueTracker thread (509594209):
1. **Removed a fabricated self-quote** in the appeal section — the published version
   put *"an attacker could host a convincing portal here"* in quotation marks; the
   actual appeal (comment #10) argued credential-harvesting from staff who recognize
   the interface. A writeup about honesty cannot contain an invented quote — fixed to
   a truthful paraphrase.
2. **Embedded the dashboard screenshot** as real image markdown (was floating alt text).
3. **Real shields.io badges** (were bare placeholder words).
4. Tightened "shipped a fix in ~9 days" → "decommissioned it in nine days" (the fix was
   pulling the DNS record, not an app patch — which is the writeup's own point), added
   real dates + the appeal-submission row to the timeline, and pinned Issue 509594209.

## Enhancements (depth that signals judgment, not padding)
- **§1** now shows the *repeatable detection method* for un-migrated acquisition infra
  (acquisition-tier scope file → CT/passive expansion → resolve-and-fingerprint tells).
- **§5 "edge-fronted ≠ Google-operated"** explains, at a mechanism level, why routing
  through Google's edge is not the same as being a Google-operated system — the core
  reason the fix was fast but the reward was zero.
- **§6** adds a concrete *"what would have crossed the reward bar"* counterfactual table.
- **§7 "If I were defending this"** adds the blue-team detection/prevention lens.

## Embedded evidence (added 2026-07-10)
Real PoC artifacts are committed under `images/` and embedded inline (verbatim
terminal + browser captures per CLAUDE.md §9.8):
- `rip-api-roles-unauth.png` — unauth `GET /api/roles` → `200 []` in a browser (§3)
- `rip-api-options-allow.png` — `OPTIONS` → `Allow: POST,GET,HEAD,OPTIONS`, `Via: 1.1 google` (§3)
- `rip-spring-boot-whitelabel.png` — Spring Boot Whitelabel Error Page fingerprint (§3)
- `rip-nxdomain-fixed.png` — post-fix `DNS_PROBE_FINISHED_NXDOMAIN` (§4)
- `rip-auth-bypass.mp4` — screen recording: random-password login → admin dashboard (§2)

Corrections made against the actual captures: the `Allow` header is
`POST,GET,HEAD,OPTIONS` (not "GET, POST, HEAD"); the Spring Boot fingerprint came
from a `404` on an unmapped path; removed the placeholder `rip-photomath-dashboard.png`
reference (the auth-bypass video covers the dashboard visual).
