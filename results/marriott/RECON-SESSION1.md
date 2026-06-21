# Marriott Bug Bounty - Recon Session 1
# Date: 2026-06-21
# Phase: 1 (Asset Discovery) + 2 (Surface Mapping - DNS only)
# Method: Python socket resolution (getaddrinfo), PTR lookups, IP ASN classification
# Constraint: crt.sh, certspotter, ipinfo.io blocked by egress gateway

---

## SCOPE VERIFICATION

Scope file loaded: /home/user/Bug-Bounty-Hunting-/config/marriott-scope.yaml
- 80 in-scope assets enumerated
- Out-of-scope catch-all: *.marriott.com (only EXPLICITLY listed subdomains allowed)
- Key OOS confirmed: www.travelagents.marriott.com (apex travelagents.marriott.com IS in-scope)
- Rate limit: max 20 req/sec; Burp Intruder 10k+ req = ban

---

## DNS RESOLUTION RESULTS

### RESOLVED (60 assets with confirmed A records)

| HOST | IP(s) | INFRASTRUCTURE | TIER | REPORTS |
|------|--------|----------------|------|---------|
| psp.marriott.com | 23.195.81.179, 23.195.81.136 | Akamai | Critical | 0 |
| passwordchallenge.marriott.com | 141.193.213.11, .10 | Akamai | Critical | 2 |
| lawmanager.marriott.com | 162.130.196.111 | Zscaler/Marriott-CDN | Critical | 0 |
| mgs.marriott.com | 34.198.35.55, 52.204.141.187, 52.7.3.35 | AWS EC2 us-east-1 | Critical | 3 |
| marrtool.com | 34.203.116.40 | AWS EC2 direct (no WAF) | Critical | 1 |
| esupplier.marriott.com | 3.219.138.243 | AWS EC2 direct (no WAF) | Critical | 0 |
| gatewaydsapdev2.marriott.com | 23.195.81.162, .186 | Akamai | Critical | 0 |
| gatewaydsapdev1.marriott.com | 23.195.81.162, .186 | Akamai | Critical | 0 |
| gatewaydsaptst1.marriott.com | 23.195.81.162, .186 | Akamai | Critical | 2 |
| gatewaydsaptst2.marriott.com | 23.195.81.161, .163 | Akamai | High | 0 |
| dcfgatewaytst1.marriott.com | 159.166.124.24 | Marriott Private DC | Critical | 1 |
| cpp.marriott.com | 3.146.43.228, .227, .229 | AWS EC2 (ELB cluster) | Critical | 3 |
| homes-and-villas.marriott.com | 23.217.76.125 | Akamai | Critical | 17 |
| all-inclusive.marriott.com | 23.195.81.162, .186 | Akamai | Critical | 11 |
| moments.marriottbonvoy.com | 23.195.81.162, .186 | Akamai | Critical | 0 |
| marriottfranchisetransactions.marriott.com | 54.204.97.74 | AWS EC2 direct (no WAF) | Critical | 1 |
| reservations.all-inclusive.marriott.com | 45.223.18.235 | AWS CloudFront | Critical | 3 |
| www.ritzcarlton.com | 23.14.140.117 | Akamai | Critical | 5 |
| editionhotels.com | 141.193.213.11, .10 | Akamai | Critical | 2 |
| jobs.marriott.com | 23.195.81.162, .186 | Akamai | Critical | 2 |
| careers.marriott.com | 23.195.81.162, .186 | Akamai | Critical | 1 |
| help.marriott.com | 3.146.43.228, .227, .229 | AWS EC2 (ELB cluster) | Critical | 17 |
| auth-apc.marriott.com | 23.61.96.201 | Akamai | High | 0 |
| apcgateway.marriott.com | 23.61.96.201 | Akamai | High | 0 |
| gateway-apc.marriott.com | 23.61.96.201 | Akamai | High | 0 |
| traveler.marriott.com | 23.195.81.162, .186 | Akamai | High | 2 |
| mipartnerprivileges.marriott.com | 18.238.176.32, .83, .41, .97 | AWS CloudFront | High | 0 |
| ifast.marriott.com | 99.84.118.89, .68, .22, .78 | AWS CloudFront | High | 0 |
| efast.marriott.com | 99.84.118.78, .89, .22, .68 | AWS CloudFront | High | 0 |
| eidhelp.marriott.com | 18.238.136.113, .69, .19, .66 | AWS CloudFront | High | 0 |
| device.marriott.com | 54.243.246.159 | AWS EC2 direct (no WAF) | High | 0 |
| bpa2.marriott.com | 162.130.197.86 | Zscaler/Marriott-CDN | High | 0 |
| ssm-marriottms.saviyntcloud.com | 104.18.1.128, 104.18.0.128 | Cloudflare | High | 0 |
| travelagents.marriott.com | 12.27.102.176 | AT&T/CDN | High | 0 |
| activities.marriott.com | 13.226.251.95, .21, .47, .108 | AWS CloudFront | High | 1 |
| sba.marriott.com | 159.166.44.21 | Marriott Private DC | High | 0 |
| owa.marriott.com | 162.130.196.138 | Zscaler/Marriott-CDN | Medium | 0 |
| oasisprod.marriott.com | 162.130.125.91 | Zscaler/Marriott-CDN | Medium | 0 |
| ocijlbex1prd.marriott.com | 193.122.173.64 | Oracle Cloud (OCI) | Medium | 0 |
| mds.marriott.com | 3.146.43.228, .229, .227 | AWS EC2 (ELB) | Medium | 0 |
| globaldesign.marriott.com | 34.200.133.99, 18.210.231.182 | AWS EC2 | Medium | 0 |
| join.marriott.com | 35.231.127.158 | GCP | Medium | 0 |
| moments.marriott.com | 35.231.127.158 | GCP | Medium | 0 |
| university.marriott.com | 3.214.21.245 | AWS EC2 direct | Medium | 0 |
| ci-propertyconversionportal.marriott.com | 23.217.76.125 | Akamai | Medium | 1 |
| channel-portal.homes-and-villas.marriott.com | 23.217.76.125 | Akamai | Medium | 0 |
| splunk-phantom-nlb.marriott.com | 34.205.160.170 | AWS EC2 direct | Low | 0 |
| www.shopmarriott.com | 99.84.118.50, .114, .99, .15 | AWS CloudFront | Medium | 0 |
| hotel-development.marriott.com | 104.18.36.146, 172.64.151.110 | Cloudflare | Medium | 0 |
| hotel-deals.marriott.com | 141.193.213.10, .11 | Akamai | Medium | 0 |
| gifts.marriott.com | 23.200.156.70, .76 | Akamai | Medium | 0 |
| joinmarriottbonvoy.com | 13.226.251.25, .59, .20, .38 | AWS CloudFront | Medium | 0 |
| joinrewards.marriott.com | 216.177.151.43 | Salesforce/Marketing | Medium | 0 |
| meetmarriottbonvoy.marriott.com | 141.193.213.10, .11 | Akamai | Medium | 0 |
| app-insiders.marriott.com | 141.193.213.11, .10 | Akamai | Medium | 0 |
| cache.marriott.com | 23.217.76.125 | Akamai | Medium | 0 |
| bilt.marriott.com | 44.227.154.152, 184.32.206.99 | Akamai | Medium | 0 |
| uber.marriott.com | 44.227.154.152, 184.32.206.99 | Akamai | Medium | 0 |
| www.travel-brilliantly.marriott.com | 162.130.197.62 | Zscaler/Marriott-CDN | Medium | 0 |
| prod-mipaasiaasservices.marriott.com | 23.217.76.125 | Akamai | Medium | 0 |
| www.members.marriott.com | 141.193.213.11, .10 | Akamai | Low | 0 |
| vacation.marriott.com | 141.193.213.11, .10 | Akamai | Low | 0 |
| www.giving.marriott.com | 23.96.187.5 | Unknown/Azure? | Low | 0 |

### NXDOMAIN (6 assets - no DNS record, not actively deployed)

| HOST | TIER | REPORTS | SIGNIFICANCE |
|------|------|---------|-------------|
| sso.marriott.com | Critical | 33 | PRIMARY SSO IS DARK - moved elsewhere or deprecated |
| wechat.api.marriott.com | High | 0 | WeChat integration not yet deployed |
| contentportal.marriott.com | Medium | 0 | Content portal offline |
| contentportalauth.marriott.com | Medium | 0 | Content auth offline |
| giftcards.marriott.com | Low | 0 | Gift cards offline |
| bsp.marriott.com | Medium | 0 | BSP offline |

### BONUS FINDS (in-scope via wildcard, not explicitly listed)

| HOST | IP | WILDCARD MATCH | NOTES |
|------|-----|----------------|-------|
| gatewaydsapdev1.marriott.com | 23.195.81.162, .186 | gateway*.marriott.com | DEV gateway - extra instance |
| gateway-apc.marriott.com | 23.61.96.201 | *gateway-apc.marriott.com | APC gateway - same IP cluster as auth-apc |
| sba.marriott.com | 159.166.44.21 | *.sba.marriott.com (apex) | Private DC IP - worth probing |

---

## INFRASTRUCTURE CLUSTERS (VIRTUAL HOSTING NOTE)

The following hosts share identical IPs, meaning they run on the same Akamai
virtual hosting infrastructure. Host header manipulation between co-tenant hosts
is worth testing (routing confusion, cross-host info leakage):

- CLUSTER A (23.195.81.162/.186): gatewaydsapdev1, gatewaydsapdev2, gatewaydsaptst1,
  all-inclusive.marriott.com, traveler.marriott.com, jobs.marriott.com, careers.marriott.com,
  moments.marriottbonvoy.com

- CLUSTER B (23.217.76.125): homes-and-villas, prod-mipaasiaasservices,
  ci-propertyconversionportal, channel-portal.homes-and-villas, cache.marriott.com

- CLUSTER C (3.146.43.228/227/229): cpp.marriott.com, help.marriott.com, mds.marriott.com

- APC CLUSTER (23.61.96.201): auth-apc.marriott.com, apcgateway.marriott.com,
  gateway-apc.marriott.com (all three point to same IP)

---

## RAW EC2 HOSTS (no CDN/WAF - highest attack exposure)

These hosts resolve directly to AWS EC2 IPs with no Akamai/CloudFront/Cloudflare
intermediary. Port scanning is viable. Applications have no WAF signature filtering.

1. esupplier.marriott.com - 3.219.138.243 (Critical, 0 reports)
2. device.marriott.com - 54.243.246.159 (High, 0 reports)
3. marrtool.com - 34.203.116.40 (Critical, 1 report)
4. marriottfranchisetransactions.marriott.com - 54.204.97.74 (Critical, 1 report)
5. splunk-phantom-nlb.marriott.com - 34.205.160.170 (Low scope but HIGH impact if accessible)
6. mgs.marriott.com - 34.198.35.55, 52.7.3.35 (Critical, 3 reports)
7. university.marriott.com - 3.214.21.245 (Medium)
8. globaldesign.marriott.com - 34.200.133.99 (Medium)

---

## CT LOG STATUS

External CT log queries (crt.sh, certspotter) are blocked by the egress gateway.
The following wildcard patterns remain unresolved - these MUST be queried from
external infrastructure for complete coverage:

Priority CT queries to run externally:
  curl "https://crt.sh/?q=%25.apigwc.marriott.com&output=json"
  curl "https://crt.sh/?q=%25.apigatewayc.marriott.com&output=json"
  curl "https://crt.sh/?q=%25.dcfgateway.marriott.com&output=json"
  curl "https://crt.sh/?q=%25.gateway.marriott.com&output=json"
  curl "https://crt.sh/?q=%25.artifactory.marriott.com&output=json"
  curl "https://crt.sh/?q=%25.mgs.marriott.com&output=json"
  curl "https://crt.sh/?q=%25.sba.marriott.com&output=json"
  curl "https://crt.sh/?q=%25uat.marriott.com&output=json"
  curl "https://crt.sh/?q=%25gateway-apc.marriott.com&output=json"

---

## TOP 5 PRIORITY TARGETS

1. ssm-marriottms.saviyntcloud.com (Saviynt IAM) - Cloudflare-proxied, 0 reports,
   NEW Oct 2025. Identity governance misconfiguration = privilege escalation/cross-tenant.

2. esupplier.marriott.com - Raw AWS EC2 (no WAF), 0 reports, Critical tier, supplier
   portal = multi-tenant IDOR goldmine, direct port scanning viable.

3. psp.marriott.com - Payment Service Provider, 0 reports, Critical tier, Akamai-protected
   but payment logic bugs bypass WAF. Amount/state manipulation, webhook abuse.

4. gatewaydsapdev2.marriott.com + gatewaydsapdev1.marriott.com - DEV gateways, 0 reports,
   Critical tier. Dev environments: debug endpoints, relaxed auth, Swagger exposure.

5. lawmanager.marriott.com - Legal document management, 0 reports, Critical tier,
   private Zscaler CDN. Document IDOR, sensitive data exposure, SSRF potential.

---

## NEXT STEPS (Phase 2 continuation)

1. Run naabu port scan on raw EC2 hosts (esupplier, device, marrtool, splunk-nlb)
   - Cap: --rate 100, -c 5 per config/tools.yaml
2. Run katana/httpx on all 60 resolved hosts (from external HTTP-capable environment)
3. Run CT log queries above from external infra
4. Run subzy for takeover check once CNAME records obtained (dig not available here)
5. Probe Saviynt (ssm-marriottms.saviyntcloud.com) for:
   - /api/ endpoint enumeration
   - Default admin paths (/ECM/, /SAVIYNT/)
   - Unauthenticated user list endpoints
6. Probe OWA (owa.marriott.com) for NTLM hash disclosure via /autodiscover/autodiscover.xml
7. Probe APC cluster (auth-apc / apcgateway / gateway-apc - all on 23.61.96.201) for
   auth bypass and token handling issues
