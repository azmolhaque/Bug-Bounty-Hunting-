# Hunt Log — Looker TIER0 Cluster (VPN/Infra)

**Program:** Google/Alphabet VRP (bughunters.google.com)
**Tier:** TIER0 (de.looker.com) + TIER1 (looker.com, corp.looker.com, etc.)
**Started:** 2026-06-21
**Status:** RECON — Session 1 runbook ready, awaiting Pi execution

---

## Scope (from config/scope.yaml)

**TIER0 — VPN/Auth cluster:**
```
- de.looker.com
- keybox.looker.com
- rampart.looker.com
- pbvpn.looker.com
- gw2-pbvpn.looker.com
```

**TIER1 — Looker SaaS:**
```
- looker.com
- corp.looker.com
- instancemanagerui.looker.com
- lk.looker.com
- lookercdn.com
- lookerdata.com
- lookermail.com
- censuslooker.com
- devops-survey.com
- lookerstudio.google.com   # separate hunt log (LS-L001 on HOLD)
```

---

## DNS Fingerprint (cloud env — 2026-06-21)

| Host | IP | Infra | Status |
|------|----|-------|--------|
| de.looker.com | 18.238.176.67 (×4) | AWS CloudFront | 403 from cloud env |
| keybox.looker.com | 52.73.216.99 | AWS | 403 from cloud env |
| rampart.looker.com | 52.73.216.99 | AWS (same as keybox) | 403 from cloud env |
| pbvpn.looker.com | 52.32.84.94 | AWS | 403 from cloud env |
| gw2-pbvpn.looker.com | 184.73.107.230 | AWS | 403 from cloud env |

**All 403s from cloud env = Anthropic egress gateway blocking. Actual responses unknown — need Pi.**

**Infra insight:** All TIER0 Looker hosts are on **AWS**, not GCP. This matches the pre-acquisition
infrastructure (Looker was AWS-hosted before Google migration). These appear to be legacy VPN endpoints:
- **keybox / rampart** — same IP; likely key management + VPN gateway (Rampart is a security boundary metaphor)
- **pbvpn / gw2-pbvpn** — "Personal Browser VPN" gateways (Looker had a browser-based VPN product for their cloud SaaS)
- **de.looker.com** — CloudFront distribution; "de" may be Germany/EU data residency instance

### Attack Surface Hypothesis

| Host | Hypothesis | Bug class |
|------|-----------|-----------|
| `de.looker.com` | EU Looker SaaS instance — separate tenant with potentially different security posture | IDOR, tenant isolation |
| `keybox.looker.com` | Key management service — if any endpoint unauthenticated → private key exposure | Info disclosure, auth bypass |
| `rampart.looker.com` | Security gateway — if config endpoint exposed → auth bypass | Config exposure |
| `pbvpn.looker.com` | Browser VPN gateway — if handshake endpoint accessible → connection abuse | Auth bypass |
| `corp.looker.com` | Corporate internal portal — may have weaker auth if still on legacy Looker infra | Auth, IDOR |

---

## Session 1 — 2026-06-21

[Pending Pi probe output — see runbooks/PI-RUNBOOK-looker-session1.md]

---

## Lead Status

| ID | Class | Surface | Status |
|----|-------|---------|--------|
| LOK-L001 | Auth/config | `keybox.looker.com` + `rampart.looker.com` | PENDING — session 1 |
| LOK-L002 | IDOR / tenant | `de.looker.com` | PENDING — session 1 |
| LOK-L003 | VPN abuse | `pbvpn.looker.com` + `gw2-pbvpn.looker.com` | PENDING — session 1 |
