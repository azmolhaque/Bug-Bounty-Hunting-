VirusTotal's URL scanner applies an SSRF blocklist for the GCP Instance Metadata Service — but the filter checks **hostname strings only**, before DNS resolution, and never validates the post-resolution IP. Two independent techniques bypass it trivially.

---

### Bypass 1 — IP Literal

| Submitted URL | VT Response |
|---|---|
| `http://metadata.google.internal/computeMetadata/v1/` | `400 InvalidArgumentError` — **BLOCKED** |
| `http://169.254.169.254/` | `200 OK` + analysis ID — **ACCEPTED** |

Same physical destination. The filter has no string to match on the IP literal and passes it through. VT's GCP-hosted scanner fleet (`35.187.132.0/24`) then connects to Google's own production IMDS and stores the response.

---

### Bypass 2 — Wildcard DNS Alias

`169-254-169-254.nip.io` is a public wildcard DNS service that resolves to `169.254.169.254`. VT's filter evaluates the hostname string **before** DNS resolution — it sees a third-party domain, not a blocked address, and allows the request.

| Submitted URL | VT Accepts? | IMDS Response | Server Header Stored in VT |
|---|---|---|---|
| `http://169-254-169-254.nip.io/computeMetadata/v1/` | **Yes** | 403 | `Metadata Server for VM` |
| `http://169-254-169-254.nip.io/computeMetadata/v1/instance/service-accounts/default/token` | **Yes** | 403 | `Metadata Server for VM` |

The 403s come from GCP's independent `Metadata-Flavor` header requirement — **not** VT's filter. The IMDS received and responded to both requests. VT applied no block.

---

### What VT Stores and Exposes

VT's scanner stores the full HTTP response from IMDS — headers, status code, body SHA256 — in its **public URL corpus**, retrievable by any free Community account.

Key fields in `GET /api/v3/urls/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8`:

- `last_http_response_code`: **200**
- `last_http_response_headers.Server`: **Metadata Server for VM**
- `last_http_response_content_sha256`: `9efd71b96213e65bceff3749bfc96401c6728b0faae74fe47d627bd1a120f0d7`
- `times_submitted`: **1647**

---

### Instant Verification — Live Right Now

No submission needed. The data is already stored. Run with any free Community API key:

    curl -s "https://www.virustotal.com/api/v3/urls/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8" \
      -H "x-apikey: YOUR_COMMUNITY_KEY" | python3 -c "
    import sys, json
    a = json.load(sys.stdin)['data']['attributes']
    print('HTTP Status  :', a['last_http_response_code'])
    print('Server       :', a['last_http_response_headers'].get('Server'))
    print('Body SHA256  :', a['last_http_response_content_sha256'])
    print('Times fetched:', a['times_submitted'])"

Expected output:

    HTTP Status  : 200
    Server       : Metadata Server for VM
    Body SHA256  : 9efd71b96213e65bceff3749bfc96401c6728b0faae74fe47d627bd1a120f0d7
    Times fetched: 1647

`aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8` is the base64url encoding of `http://169.254.169.254/` per VT's URL identifier scheme. The triager can verify this finding in under 60 seconds without submitting anything.

---

### Root Cause

The SSRF filter performs hostname string-matching **before** DNS resolution. It never resolves the submitted URL to an IP address and never validates the resolved IP against blocked CIDR ranges. The correct fix is post-resolution IP validation against `169.254.0.0/16` and other private ranges.

The same architectural flaw permits bypass via `sslip.io`, attacker-controlled DNS, or any service that aliases an arbitrary hostname to `169.254.0.0/16`.

---

### This Is a Control Bypass, Not Absent Protection

The hostname blocklist (`metadata.google.internal` → `400 InvalidArgumentError`) proves VT **intentionally implemented** SSRF protection for the GCP metadata endpoint. A filter bypassable by two trivially equivalent representations of the blocked address is a broken control — not a working one. "Intended behavior" is not a valid response when the intended behavior is a functioning filter.

Full reproduction steps, evidence bundle (JSON API responses), and automated PoC script are attached.
