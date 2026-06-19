[2026-06-12 02:00:36][INFO ] ══ Bug Bounty Orchestrator v2.0 ══  target=metabase.photomath.net  phases=0-6  bg=false  dry=false
[2026-06-12 02:00:36][INFO ] Initializing new orchestrator state

══════════════════════════════════════════════════════════════════════
[2026-06-12 02:00:36][PHASE] 0 — Scope Gate & Hunt Plan
══════════════════════════════════════════════════════════════════════[2026-06-12 02:00:36][INFO ] Scope OK: metabase.photomath.net
[2026-06-12 02:00:36][INFO ] Created 00-plan.md
[2026-06-12 02:00:36][INFO ] Phase 0 DONE
[2026-06-12 02:00:36][INFO ] Intelligence re-plan after phase 0

══════════════════════════════════════════════════════════════════════
[2026-06-12 02:00:36][PHASE] 1+2 — Asset Discovery & Surface Mapping
══════════════════════════════════════════════════════════════════════[2026-06-12 02:00:36][INFO ] Pi5 resources — CPU:7% RAM:9% TEMP:52°C
[2026-06-12 02:05:14][INFO ] Phase 1+2 DONE
[2026-06-12 02:05:14][INFO ] Intelligence re-plan after phase 1
[2026-06-12 02:05:14][INFO ] Phase 2 already DONE — skipping (--force to re-run)

══════════════════════════════════════════════════════════════════════
[2026-06-12 02:05:14][PHASE] 3 — Vulnerability Discovery + Lead Qualification
══════════════════════════════════════════════════════════════════════[2026-06-12 02:05:14][INFO ] Pi5 resources — CPU:3% RAM:9% TEMP:51°C
[2026-06-12 02:05:14][INFO ] Phase 3 scanning 1 targets
[2026-06-12 02:05:15][INFO ] Pi5 resources — CPU:3% RAM:9% TEMP:52°C
[2026-06-12 02:05:15][INFO ] nuclei → metabase.photomath.net
[2026-06-12 02:05:30][INFO ] Running lead qualification gate on all nuclei output
[2026-06-12 02:05:30][INFO ] Lead gate: 0 pursuing / 0 auto-closed
[2026-06-12 02:05:30][INFO ] Phase 3 DONE
[2026-06-12 02:05:30][INFO ] Intelligence re-plan after phase 3
[2026-06-12 02:05:30][DECIDE] Phase 3 result: 0
0 pursuing (0
0 HIGH confidence)

══════════════════════════════════════════════════════════════════════
[2026-06-12 02:05:30][PHASE] 4 — Verification, PoC & Chain Elevation
══════════════════════════════════════════════════════════════════════[2026-06-12 02:05:30][INFO ] 0
0 candidates in PURSUE status
[2026-06-12 02:05:30][INFO ] Phase 4 DONE
[2026-06-12 02:05:30][INFO ] Intelligence re-plan after phase 4
[2026-06-12 02:05:30][DECIDE] Phase 4: 0 auto-verified, 0 need manual verification
[2026-06-12 02:05:30][DECIDE] Zero findings — consider: (1) Trial account for SSRF/IDOR, (2) Deeper JS analysis, (3) Manual auth testing

══════════════════════════════════════════════════════════════════════
[2026-06-12 02:05:30][PHASE] 5 — Triage, CVSS & Pre-Submission Gate
══════════════════════════════════════════════════════════════════════[2026-06-12 02:05:30][INFO ] Triage → /home/gorib/bug-bounty-hunting-/results/metabase.photomath.net/05-triage/triage.md
[2026-06-12 02:05:30][INFO ] Phase 5 DONE
[2026-06-12 02:05:30][INFO ] Intelligence re-plan after phase 5

══════════════════════════════════════════════════════════════════════
[2026-06-12 02:05:30][PHASE] 6 — Report Generation
══════════════════════════════════════════════════════════════════════[2026-06-12 02:05:30][INFO ] Phase 6: 0 draft reports generated in /home/gorib/bug-bounty-hunting-/results/metabase.photomath.net/findings/
[2026-06-12 02:05:30][INFO ] Phase 6 DONE
[2026-06-12 02:05:30][INFO ] Intelligence re-plan after phase 6
