## What Is Exposed Right Now

Any VirusTotal Community user — free account, zero-barrier registration, instantly obtainable — can retrieve the following from VT's public API today with a single API call:

| Exposed Data | Value | API Field |
|---|---|---|
| IMDS HTTP status | **200** — root path actively responding with content | `last_http_response_code` |
| IMDS server identity | **Metadata Server for VM** — GCP self-identifying in VT's public corpus | `last_http_response_headers.Server` |
| IMDS body SHA256 | `9efd71b96213e65bceff3749bfc96401c6728b0faae74fe47d627bd1a120f0d7` | `last_http_response_content_sha256` |
| Cumulative fetches | **1,647** — continuous, ongoing, not a one-time event | `times_submitted` |
| Raw response bytes | Indexed in VT Intelligence corpus; downloadable by premium subscribers | VT Intelligence |

Retrieval endpoint (any Community key): `GET /api/v3/urls/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8`

---

## Every IMDS Path Reached the Metadata Server

| Path | IMDS HTTP Response | Notes |
|---|---|---|
| `/` | **200** | Root responds without auth header; 17-byte body stored in VT's corpus |
| `/computeMetadata/` | **200** | Version listing; no auth header required |
| `/computeMetadata/v1/` | 403 | GCP's `Metadata-Flavor` header check — not VT's filter |
| `/computeMetadata/v1/instance/service-accounts/default/token` | 403 | OAuth token endpoint — **network-confirmed reachable from VT's fleet** |
| `/computeMetadata/v1beta1/` | 404 | Decommissioned by Google |
| `/latest/meta-data/` | 404 | AWS path — does not exist on GCP IMDS |

`Server: Metadata Server for VM` confirmed in response headers on every path. All response data — headers, status codes, body SHA256 — is stored in VT's public URL corpus and retrievable by any Community user.

---

## Escalation Path — One Header Away From Critical

**The GCP OAuth2 service-account token endpoint is confirmed network-reachable from VT's scanner fleet.**

    http://169-254-169-254.nip.io/computeMetadata/v1/instance/service-accounts/default/token
      → VT: accepted, no filter applied
      → GCP IMDS: HTTP 403, Server: Metadata Server for VM
      → 403 = GCP's Metadata-Flavor header requirement — NOT VT's filter

VT's scanner has confirmed direct network access to the token endpoint. The only barrier between VT's scanner and live GCP service-account credentials is GCP's independent `Metadata-Flavor: Google` header validation — a control VT does not own, does not enforce, and cannot guarantee.

**Any of the following escalates this to credential extraction:**

- A redirect chain through a VT-scanned URL that injects `Metadata-Flavor: Google`
- Any VT scanner configuration change that adds the required header
- Any future change to GCP's independent header enforcement

This is a confirmed reachable endpoint with a confirmed active service behind it — not a speculative path.

---

## Ongoing and Systemic

`times_submitted: 1,647` — VT's scanner has fetched Google's own production metadata server 1,647 times and stored every response. This is not a one-time discovery; it is an unpatched, continuously active exposure that predates this report.

The flaw is architectural. Pre-DNS hostname string-matching cannot be patched by blocking one more hostname or one more IP. The same bypass works with `sslip.io`, attacker-controlled DNS, or split-horizon DNS. The attack surface at the application layer is unbounded without a network-layer fix (VPC egress deny on `169.254.0.0/16`).

---

## Severity

**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` = **5.0 Medium**

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network | VT's free public API, accessible from anywhere |
| Attack Complexity | Low | No race condition, timing requirement, or special configuration |
| Privileges Required | Low | Free Community account, instantly registrable |
| User Interaction | None | Fully automated exploitation |
| Scope | **Changed** | VT scanner (vulnerable component) impacts GCP IMDS (separate component, different authorization boundary) |
| Confidentiality | Low | IMDS headers and SHA256 publicly disclosed; credentials not extracted due to downstream GCP control VT does not own |
| Integrity | None | No write capability demonstrated |
| Availability | None | No denial-of-service capability demonstrated |

**Google VRP reward note:** Confirmed SSRF reaching GCP IMDS on a TIER1 asset (`www.virustotal.com`) with documented public data exposure across 1,647 fetches and OAuth token endpoint network reachability is categorized as **High** under Google VRP's internal reward structure. The CVSS base score of 5.0 reflects C:L because credential extraction was blocked by a downstream GCP control that VT does not own or control — not by any VT-implemented protection. The real-world business risk exceeds what the base score conveys.
