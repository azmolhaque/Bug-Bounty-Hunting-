# Hunt Plan — www.pring.jp
# Generated: 2026-06-11T20:29:23Z

## Target Classification
- Root domain: www.pring.jp
- Archetype: [update after Phase 1 — wildcard/saas/cnapp/api-first/mobile]

## Hunt Thesis
[Orchestrator will update after Phase 2 surface map]

## Attack Chain Hypotheses (probability × impact rank)
1. [update after Phase 1+2]
2. [update after Phase 1+2]
3. [update after Phase 1+2]

## Fastest Path to High/Critical
[update after Phase 2]

## Resource Plan (Pi 5, 16 GB ARM64)
- Recon:    background, streaming to disk, concurrency ≤ 3
- Phase 3:  nuclei fan-out max 3 parallel, dead-end after 3 failures
- Temp cap: 78°C / RAM cap: 82%

## Phase History
| Phase | Status | Timestamp |
|-------|--------|-----------|
| 0 | DONE | 2026-06-11T20:29:23Z |

## Updated Hunt Thesis (after Phase 2 — 2026-06-11T20:33:48Z)

### Top priority targets:
# Priority Targets — www.pring.jp
# Generated: 2026-06-11T20:33:48Z

| Target | Signals | Priority | Rationale |
|--------|---------|----------|-----------|

### Recommended Phase 3 focus (based on surface map):
1. Any non-production / dev / staging / RDE hosts → relaxed auth
2. GraphQL endpoints → IDOR / cross-tenant
3. Webhook / integration endpoints → SSRF
4. Subdomains with dangling CNAMEs → takeover
5. Admin / internal-exposed hosts → default creds, unauth access

## Re-plan after Phase 4 (2026-06-11T20:34:04Z)
Zero auto-verified findings. Next steps:
1. Obtain trial account → run scripts/phase4-trial-account-wiz.sh
2. Test webhook SSRF manually (Chain 3)
3. Test cross-tenant GraphQL IDOR with 2 accounts (Chain 4)
4. Re-run Phase 3 with --force after Phase 1+2 if recon is now complete
