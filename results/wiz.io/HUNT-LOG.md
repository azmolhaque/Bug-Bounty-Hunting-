# Hunt Log — wiz.io (Google VRP TIER1)
Started: 2026-06-11

| Time | Phase | Action | Finding |
|------|-------|---------|---------|
| 2026-06-11 | 0 | Scope confirmed | `*.wiz.io` IN-SCOPE, TIER1, blackout-exempt |
| 2026-06-11 | 1 | DNS resolution (dnsx) COMPLETE | See key findings below |
| 2026-06-11 | 1 | gau/waybackurls — IN PROGRESS | — |

## Key Findings So Far

### DNS Phase Highlights

**[P0] 4x Grafana instances exposed**
- `us1.grafana.wiz.io`, `us2.grafana.wiz.io` (production)
- `us1.grafana.test.wiz.io`, `us1.grafana.fedtest.wiz.io` (non-prod)
- Status: NOT YET PROBED — httpx next

**[P0] Named developer RDE environments**
- `webhooks.guy.goldenberg.rde.wiz.io`, `webhooks.roey.dror-us.rde.wiz.io`, others
- 100+ on-demand RDE environments
- Status: NOT YET PROBED

**[P1] Webhook infrastructure mapped**
- 100+ regional webhook endpoints (us1–us117, eu1–eu32, ap, ca, sa, me, il, gov)
- Primary SSRF target once test account acquired
- Status: REQUIRES WIZ TRIAL ACCOUNT

**[P1] `www.peach.wiz.io` → GCP (34.149.87.45)**
- Internal project on Google Cloud — post-acquisition infrastructure
- Status: NOT YET PROBED

**[P1] WizCLI non-prod endpoints**
- test/stage/demo/e2e/integration variants
- Status: NOT YET PROBED

## Decision Log

- Chose Wiz as first target: TIER1, blackout-exempt, zero prior VRP research, CNAPP = rich attack surface
- Starting with passive then active probe; webhook SSRF requires trial account
- Grafana instances are immediate priority — no auth required to test

## Next Steps
1. Wait for gau/wayback to finish
2. httpx all discovered hosts
3. Probe Grafana instances for anon access / default creds
4. Register Wiz trial account for active webhook/integration SSRF testing
