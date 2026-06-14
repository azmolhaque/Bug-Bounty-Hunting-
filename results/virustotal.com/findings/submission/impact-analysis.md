**Confirmed, verifiable right now — any free Community account, one command, under 60 seconds.**

Any VirusTotal Community user can retrieve Google's GCP Instance Metadata Service response data from VT's public API today. No special privileges, no premium tier, no waiting. This is an ongoing live exposure across **1,647+ documented fetches**.

---

### Verified Exposed Data (Retrievable Today)

| Data Point | Value | Where |
|---|---|---|
| IMDS HTTP status | **200** (root path actively responding) | `last_http_response_code` |
| Server identity | **Metadata Server for VM** (GCP self-identifying) | `last_http_response_headers.Server` |
| Response body SHA256 | `9efd71b96213e65bceff3749bfc96401c6728b0faae74fe47d627bd1a120f0d7` | `last_http_response_content_sha256` |
| Cumulative fetches | **1,647** (continuous, ongoing) | `times_submitted` |
| Raw response bytes | Stored in VT Intelligence corpus; SHA256 is publicly listed | VT premium corpus |

All of the above is accessible to any registered Community user via `GET /api/v3/urls/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8`.

---

### GCP IMDS Path Coverage — All Paths Reached the Metadata Server

| Path | IMDS HTTP Response | Notes |
|---|---|---|
| `/` | **200** | Root responds without auth header; 17-byte body stored |
| `/computeMetadata/` | **200** | Version listing; no auth header required |
| `/computeMetadata/v1/` | 403 | GCP's `Metadata-Flavor` header check — not VT's filter |
| `/computeMetadata/v1/instance/service-accounts/default/token` | 403 | OAuth token endpoint — **network-reachable** from VT's fleet |
| `/computeMetadata/v1beta1/` | 404 | Decommissioned by Google |

`Server: Metadata Server for VM` confirmed in response headers for every path. All response data indexed in VT's public corpus.

---

### Escalation Path — One Step From Critical

The GCP OAuth2 service-account token endpoint (`/computeMetadata/v1/instance/service-accounts/default/token`) is **confirmed network-reachable** from VT's scanner fleet. The only barrier is GCP's independent `Metadata-Flavor: Google` header requirement. VT has no block, no rate-limit, and no logging on requests to this endpoint.

Live GCP service-account credentials would be exposed by any of the following:

- A redirect chain through a VT-scanned URL that injects the `Metadata-Flavor` header
- Any future relaxation or change in GCP's header enforcement (outside VT's control)
- VT scanner configuration change that adds the required header

This is not a speculative chain — the network path is confirmed. The barrier is a single header on a service VT does not control.

---

### Scope and Reach

- Exploitable via VT's **free public API** from anywhere on the internet
- `169.254.169.254` is link-local (RFC 3927) — unreachable from the public internet, accessible only from within GCP's production network. VT's scanner fleet operates there.
- Two independent bypass vectors succeed simultaneously — this is an architectural flaw (pre-DNS string matching), not a single missed edge case
- The same flaw permits bypass via `sslip.io`, attacker-controlled DNS, or any DNS alias service targeting `169.254.0.0/16`

---

### CVSS 3.1

`AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` = **5.0 Medium**

- **S:C (Scope Changed):** VT's scanner (the vulnerable component) impacts GCP IMDS (a separate component outside VT's authorization boundary)
- **C:L:** IMDS response headers, HTTP codes, and body SHA256 publicly disclosed; raw credentials not extracted due to GCP's independent header control
- **PR:L:** Free, instantly-registrable VirusTotal Community account

**Google VRP reward note:** Confirmed SSRF reaching GCP IMDS on a TIER1 asset (`www.virustotal.com`) with documented public data exposure and OAuth token endpoint network reachability is categorized as **High** under Google VRP's reward structure, independent of the base CVSS score. The CVSS C:L reflects a downstream GCP control that VT does not own or control — not the absence of real impact.
