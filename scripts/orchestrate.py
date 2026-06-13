#!/usr/bin/env -S bash -c 'exec "$(dirname "$0")/../.venv/bin/python3" "$0" "$@" 2>/dev/null || exec python3 "$0" "$@"'
# ↑ auto-selects .venv/bin/python3 if present, falls back to system python3
"""
orchestrate.py — Python-native bug bounty orchestrator (v2.2)

Replaces agent-orchestrate.sh with:
  - Zero bash parsing bugs (no grep -c exit-1, no top output, no unbound vars)
  - Claude API intelligence at Phase 3 (lead qualification) and Phase 6 (reports)
  - Chain elevation analysis between Phase 3 and 4
  - Discord webhook notifications on confirmed findings
  - asyncio concurrency with Semaphore cap (no bash & race conditions)
  - Atomic state writes (tempfile + os.replace — no partial-write corruption)
  - Single source of truth for candidate status (no JSONL vs state.json divergence)

v2.2 additions:
  - Hypothesis Engine (lib/hypothesis.py): tech-stack aware ranked bug test hypotheses.
    Auth0 → OAuth confusion. Cognito → Identity Pool unauth. PingFederate → dynamic reg.
    GraphQL → introspection + IDOR + batch alias. Rails → mass assignment + debug endpoints.
    JWT → alg=none + RS256/HS256 confusion. Open APIs → IDOR + CORS data exfil.
    Results written to 02-surface/hypotheses.md and seeded as Phase 3 candidates.
  - CORS fix: CORS on authenticated data endpoints no longer auto-closed (upgraded to High).

v2.1 additions:
  - Phase 2.5: Structured surface mapper — reachability + WAF detection + self-registration
    + admin panel exposure + auth platform fingerprinting (runs in ~30s before nuclei)
  - Phase 3 WAF gate: skip nuclei on WAF-blocked targets (no wasted scans)
  - Persistent ManualQueue: browser/credential actions survive context resets
  - qualify_manual() / qualify_self_registration() for hand-discovered findings
  - --complete-action <id>: mark a manual action done from CLI
  - --ingest <jsonl>: ingest manually discovered candidates into candidates.jsonl

Usage:
  python3 scripts/orchestrate.py <target> [--phase N] [--dry-run] [--status]
  python3 scripts/orchestrate.py <target> --complete-action Mxxxxxx
  python3 scripts/orchestrate.py <target> --ingest path/to/manual.jsonl
  ANTHROPIC_API_KEY=... DISCORD_WEBHOOK_URL=... python3 scripts/orchestrate.py wiz.io
"""
import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Path bootstrap ──────────────────────────────────────────────────────────
SCRIPTS_DIR = Path(__file__).parent
ROOT        = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

from lib import claude_ai, discord_notify, hunter, recon, reporter, resources, scope, state, tools
from lib.surface_map import run_surface_map, load_surface_map, reachable_targets, high_priority_surfaces, all_manual_actions
from lib.manual_queue import ManualQueue, add_oauth_browser_action, add_self_registration_action
from lib.qualifier import qualify_manual, qualify_self_registration
from lib.hypothesis import generate as generate_hypotheses


# ── Logging setup ───────────────────────────────────────────────────────────

def setup_logging(log_path: Path, level: str = "INFO") -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("[%(asctime)s][%(levelname)-5s] %(message)s", "%Y-%m-%dT%H:%M:%S")
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # File handler — same path as bash version
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    root.addHandler(ch)
    return logging.getLogger("orchestrate")


# ── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Bug bounty orchestrator — Python v2.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="Target domain (e.g. wiz.io)")

    # Phase control
    pg = p.add_argument_group("Phase control")
    pg.add_argument("--phase", metavar="N or N-M", default="0-6",
                    help="Run phase N only, or range N-M (default: 0-6)")
    pg.add_argument("--force", action="store_true", help="Re-run already-completed phases")
    pg.add_argument("--background", action="store_true", help="Run Phase 1+2 recon in background")
    pg.add_argument("--passive-only", action="store_true", help="Passive recon only")
    pg.add_argument("--max-targets", type=int, default=300,
                    help="Cap Phase 3 target list after service-deduplication (default: 300)")

    # Mode
    p.add_argument("--dry-run", action="store_true", help="Plan without executing anything")
    p.add_argument("--status", action="store_true", help="Print status and exit")
    p.add_argument("--no-claude", action="store_true", help="Disable Claude API (offline mode)")
    p.add_argument("--no-discord", action="store_true", help="Disable Discord notifications")

    # Manual action management
    mq = p.add_argument_group("Manual action management")
    mq.add_argument("--complete-action", metavar="ACTION_ID",
                    help="Mark a manual queue action as DONE (e.g. --complete-action Mxxxxxx)")
    mq.add_argument("--action-result", metavar="RESULT", default="",
                    help="Result/notes to record when completing an action")
    mq.add_argument("--queue", action="store_true",
                    help="Print pending manual actions and exit")
    mq.add_argument("--ingest", metavar="JSONL_PATH",
                    help="Ingest manually discovered candidates from a JSONL file")

    # Output
    p.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARN","ERROR"])

    args = p.parse_args()

    if not args.target and not args.status:
        p.print_help()
        sys.exit(1)

    # Parse --phase range
    phase_str = args.phase
    if "-" in phase_str and not phase_str.startswith("-"):
        parts = phase_str.split("-")
        args.phase_start = int(parts[0])
        args.phase_end   = int(parts[1])
    else:
        n = int(phase_str.lstrip("-"))
        args.phase_start = n
        args.phase_end   = n

    return args


# ── Orchestrator class ───────────────────────────────────────────────────────

class Orchestrator:
    VERSION = "2.2.0"

    def __init__(self, args: argparse.Namespace):
        self.target      = args.target
        self.phase_start = args.phase_start
        self.phase_end   = args.phase_end
        self.dry_run     = args.dry_run
        self.force       = args.force
        self.background    = args.background
        self.passive       = args.passive_only
        self.max_targets   = getattr(args, "max_targets", 300)

        self.results_dir = ROOT / "results" / self.target
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self.log = setup_logging(
            self.results_dir / "orchestrator.log",
            args.log_level,
        )

        # Load / init state
        self._state_path = self.results_dir / ".orchestrator-state.json"
        self.hunt_state  = state.load_or_init(self._state_path, self.target)

        # Tool availability
        self.tools_ok = tools.check_tools()

        # Claude AI client (lazy — only if key set and not disabled)
        self.claude = None if args.no_claude else claude_ai.ClaudeAI()

        # Discord notifier
        self.discord = None if args.no_discord else discord_notify.DiscordNotifier.from_env()

        # Scope checker
        self._scope = scope

        # Resource limits from tools.yaml
        self._max_parallel = self._load_int("limits.max_parallel_subagents", 3)
        self._rate         = self._load_int("limits.http_rate_per_sec", 100)
        self._threads      = self._load_int("limits.threads", 25)

        # Manual action queue (persisted across runs)
        self.manual_q = ManualQueue(self.results_dir, self.target)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _save_state(self) -> None:
        state.save(self.hunt_state, self._state_path)

    def _should_run(self, phase: int) -> bool:
        if phase < self.phase_start or phase > self.phase_end:
            return False
        if not self.force and self.hunt_state.phase_done(phase):
            self.log.info("Phase %d already DONE — skipping (use --force to re-run)", phase)
            return False
        return True

    def _scope_ok(self, host: str) -> bool:
        ok, reason = self._scope.check(host)
        if not ok:
            self.log.error("SCOPE VIOLATION: %s — %s", host, reason)
        return ok

    def _load_int(self, dotpath: str, default: int) -> int:
        try:
            import yaml
            cfg = yaml.safe_load((ROOT / "config" / "tools.yaml").read_text()) or {}
            parts = dotpath.split(".")
            val = cfg
            for p in parts:
                val = val[p]
            return int(val)
        except Exception:
            return default

    def _notify_finding(self, finding: dict) -> None:
        if self.discord and self.discord.enabled:
            self.discord.send_confirmed_finding(finding)

    def _notify_phase(self, phase: int, summary: str, stats: dict) -> None:
        if self.discord and self.discord.enabled:
            self.discord.send_phase_complete(phase, self.target, summary, stats)

    # ── Phase 0 — Scope gate + hunt plan ────────────────────────────────────

    async def phase0(self) -> None:
        self.log.info("══ Phase 0 — Scope Gate & Hunt Plan")
        self.hunt_state.mark_phase_start(0)
        self._save_state()

        # Hard scope gate
        self._scope.assert_in_scope(self.target)
        prog = self._scope.get_program_name(self.target)
        self.log.info("Scope OK: %s (program: %s)", self.target, prog or "unknown")

        # Create / check 00-plan.md
        plan_path = self.results_dir / "00-plan.md"
        if not plan_path.exists():
            plan_path.write_text(self._generate_plan())
            self.log.info("Created 00-plan.md")
        else:
            self.log.info("00-plan.md exists — resuming hunt")

        self.hunt_state.mark_phase_done(0, summary=f"Scope OK ({self.target})")
        self._save_state()
        self.log.info("Phase 0 DONE")

    def _generate_plan(self) -> str:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return f"""# Hunt Plan — {self.target}
Generated: {now}

## Target Classification
- Target: `{self.target}`
- Program: {self._scope.get_program_name(self.target) or 'unknown'}

## Hunt Thesis
(Update this after Phase 2 surface mapping)

## Top Attack Hypotheses
1. [To be populated after Phase 2]
2.
3.

## Phase Notes
"""

    # ── Phase 1+2 — Recon & Surface Mapping ─────────────────────────────────

    async def phase12(self) -> None:
        self.log.info("══ Phase 1+2 — Recon & Surface Mapping")
        self.hunt_state.mark_phase_start(2)
        self._save_state()

        if self.dry_run:
            self.log.info("[DRY-RUN] Would run recon.sh for %s", self.target)
            self.hunt_state.mark_phase_done(2, summary="dry-run")
            self._save_state()
            return

        # Check if background recon already running
        running_pid = recon.is_recon_running(self.results_dir)
        if running_pid:
            self.log.info("Background recon already running (PID %d)", running_pid)
            return

        ok, summary = await recon.run_recon(
            self.target,
            self.results_dir,
            passive_only=self.passive,
            background=self.background,
            rate=self._rate,
            threads=self._threads,
        )

        if not ok:
            self.log.warning("Recon reported failure — continuing with available data")

        stats = self._collect_recon_stats()
        self.hunt_state.mark_phase_done(2, summary=summary[:500], stats=stats)
        self._save_state()

        self._notify_phase(2, summary[:200], stats)

        # Claude intelligence replan after recon
        if self.claude and self.claude.enabled:
            brief = self.claude.intelligence_replan(2, summary, self.target, {
                "pursuing": self.hunt_state.pursuing,
                "confirmed": self.hunt_state.confirmed,
                "intelligence_notes": self.hunt_state.intelligence_notes,
            })
            if brief:
                self.hunt_state.add_intelligence_note(f"[Phase 2 replan]\n{brief}")
                self._save_state()
                self.log.info("Intelligence replan:\n%s", brief[:400])

        self.log.info("Phase 1+2 DONE — %s", stats)

    def _collect_recon_stats(self) -> dict:
        def count(path: Path) -> int:
            return tools.count_lines(path)
        return {
            "subdomains": count(self.results_dir / "01-assets" / "subdomains.txt"),
            "resolved":   count(self.results_dir / "01-assets" / "resolved.txt"),
            "live_hosts": count(self.results_dir / "02-surface" / "live.txt"),
            "endpoints":  count(self.results_dir / "02-surface" / "all-endpoints.txt"),
            "js_files":   count(self.results_dir / "02-surface" / "js-files.txt"),
        }

    # ── Phase 2.5 — Structured Surface Map ──────────────────────────────────

    async def phase25(self) -> None:
        """
        30-second structured surface probe that runs AFTER recon and BEFORE nuclei.

        For each live target, detects:
          - Reachability + WAF blocking (CloudFront, Cloudflare, etc.)
          - Self-registration endpoints (/sign_up, /register, etc.)
          - Exposed admin panels (Sidekiq, Grafana, Swagger, etc.)
          - Auth platform (Auth0, Cognito, PingFederate, Okta)
          - Open unauthenticated API endpoints

        Outputs:
          - results/<target>/02-surface/surface_map.jsonl
          - Adds CRITICAL actions to ManualQueue for self-registration + admin panels
          - Filters WAF-blocked targets from Phase 3 nuclei scan
        """
        self.log.info("══ Phase 2.5 — Structured Surface Mapping")

        if self.dry_run:
            self.log.info("[DRY-RUN] Skipping surface map")
            return

        targets = recon.load_targets(self.results_dir, self.target, max_targets=self.max_targets)
        if not targets:
            targets = [self.target]

        records = await run_surface_map(
            targets, self.results_dir,
            max_parallel=min(self._max_parallel * 3, 15),  # faster than nuclei, safe to parallelize more
            timeout=10,
        )

        # Process findings from surface map
        candidates_path = self.results_dir / "03-candidates" / "candidates.jsonl"
        candidates_path.parent.mkdir(parents=True, exist_ok=True)

        for rec in records:
            # Self-registration = immediate PURSUE_HIGH candidate
            if rec.self_registration:
                self.log.info("[SURFACE] Self-registration OPEN: %s%s", rec.host, rec.self_registration_path)
                qr = qualify_self_registration(rec.host, rec.self_registration_path)
                candidate = {
                    "id": f"S{_sha6(rec.host + rec.self_registration_path)}",
                    "target": rec.host,
                    "url": f"https://{rec.host}{rec.self_registration_path}",
                    "vuln_class": "self-registration",
                    "template": "surface-map-self-registration",
                    "severity": "high",
                    "evidence": f"GET {rec.self_registration_path} → HTTP 200 (open self-registration)",
                    "confidence": "HIGH",
                    "status": "PURSUE",
                    "score": qr.score,
                    "chain_potential": qr.chain_potential,
                    "next_steps": qr.next_steps,
                    "estimated_cvss": qr.estimated_cvss,
                    "source": "phase25-surface-map",
                }
                with candidates_path.open("a") as f:
                    f.write(json.dumps(candidate) + "\n")
                add_self_registration_action(
                    self.manual_q, rec.host,
                    f"https://{rec.host}{rec.self_registration_path}",
                )
                self.hunt_state.update_candidate(candidate["id"], status="PURSUE", score=qr.score)
                if self.discord and self.discord.enabled:
                    self.discord.send_pursue_lead(candidate)

            # Unauthenticated admin panels = immediate PURSUE_HIGH
            for panel in rec.admin_panels:
                if panel["code"] == 200:
                    self.log.info(
                        "[SURFACE] Admin panel EXPOSED: %s%s (%s)",
                        rec.host, panel["path"], panel["name"],
                    )
                    qr = qualify_manual(
                        vuln_class="admin-panel-exposed",
                        severity="high",
                        evidence=f"{panel['name']} at {panel['path']} returns HTTP 200",
                        impact=f"Unauthenticated access to {panel['name']} admin panel on {rec.host}",
                        confidence="HIGH",
                        estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    )
                    candidate = {
                        "id": f"S{_sha6(rec.host + panel['path'])}",
                        "target": rec.host,
                        "url": f"https://{rec.host}{panel['path']}",
                        "vuln_class": "admin-panel-exposed",
                        "template": f"surface-map-admin-{panel['name']}",
                        "severity": "high",
                        "evidence": f"{panel['name']} at {rec.host}{panel['path']} → HTTP 200 (no auth)",
                        "confidence": "HIGH",
                        "status": "PURSUE",
                        "score": 5,
                        "source": "phase25-surface-map",
                    }
                    with candidates_path.open("a") as f:
                        f.write(json.dumps(candidate) + "\n")
                    self.manual_q.add(
                        host=rec.host,
                        action_type="ADMIN_PANEL_CHECK",
                        priority="CRITICAL",
                        title=f"Investigate exposed {panel['name']} on {rec.host}",
                        instruction=(
                            f"Access https://{rec.host}{panel['path']} in browser — "
                            f"document what is visible without auth. Screenshot immediately."
                        ),
                        unlocks=f"Unauthenticated admin panel access — immediate High/Critical",
                    )

            # Auth platform — queue OAuth capture action if Auth0/Cognito with OIDC
            if rec.auth_platform in ("auth0", "cognito", "oidc-unknown") and "OIDC_DISCOVERY" in " ".join(rec.flags):
                add_oauth_browser_action(
                    self.manual_q,
                    host=rec.host,
                    login_url=f"https://{rec.host}/login",
                    auth_url=f"https://auth.{rec.host.split('.')[-2]}.{rec.host.split('.')[-1]}",
                )

        # ── Hypothesis Engine: generate targeted bug hypotheses per host ────
        hyp_dir = self.results_dir / "02-surface"
        hyp_path = hyp_dir / "hypotheses.md"
        hyp_lines = ["# Bug Hypotheses — Phase 2.5 Output\n"]
        total_pursue = 0
        for rec in records:
            if not rec.reachable or rec.waf_blocked:
                continue
            try:
                hrep = generate_hypotheses(rec)
                pursue = hrep.pursue()
                if pursue:
                    total_pursue += len(pursue)
                    hyp_lines.append(hrep.render_markdown())
                    hyp_lines.append("")
                    # Add pursue-worthy hypotheses as candidates
                    for hyp in pursue:
                        if hyp.manual_required:
                            # Queue as manual action instead of automated candidate
                            self.manual_q.add(
                                host=rec.host,
                                action_type="VERIFY_CHAIN_LINK",
                                priority=hyp.impact,
                                title=hyp.title,
                                instruction=hyp.rationale + " — " + (hyp.chain_link or ""),
                                commands=hyp.test_commands[:3],
                                expected_output=hyp.estimated_cvss,
                                unlocks=hyp.chain_link,
                            )
                        else:
                            # Automated — add as candidate for Phase 3 follow-up
                            candidate = {
                                "id": f"H{_sha6(hyp.id)}",
                                "target": rec.host,
                                "url": f"https://{rec.host}",
                                "vuln_class": hyp.vuln_class,
                                "template": f"hypothesis-{hyp.vuln_class}",
                                "severity": hyp.impact.lower(),
                                "evidence": hyp.rationale,
                                "confidence": hyp.confidence,
                                "status": "PURSUE",
                                "score": 4 if hyp.impact == "CRITICAL" else 3,
                                "chain_potential": hyp.chain_link,
                                "next_steps": hyp.test_commands,
                                "estimated_cvss": hyp.estimated_cvss,
                                "source": "phase25-hypothesis-engine",
                            }
                            with candidates_path.open("a") as f:
                                f.write(json.dumps(candidate) + "\n")
            except Exception as e:
                self.log.debug("Hypothesis generation error for %s: %s", rec.host, e)

        hyp_path.write_text("\n".join(hyp_lines))
        self.log.info("Hypothesis engine: %d pursue-worthy hypotheses written to %s", total_pursue, hyp_path)

        # Summary
        waf_blocked  = sum(1 for r in records if r.waf_blocked)
        self_reg     = sum(1 for r in records if r.self_registration)
        admin_open   = sum(1 for r in records if any(p["code"] == 200 for p in r.admin_panels))
        open_api     = sum(1 for r in records if r.open_api_endpoints)
        self.log.info(
            "Phase 2.5 DONE — waf_blocked=%d self_reg=%d admin_exposed=%d open_api=%d hypotheses=%d",
            waf_blocked, self_reg, admin_open, open_api, total_pursue,
        )

    # ── Phase 3 — Vulnerability Discovery ───────────────────────────────────

    async def phase3(self) -> None:
        self.log.info("══ Phase 3 — Vulnerability Discovery")
        self.hunt_state.mark_phase_start(3)
        self._save_state()

        # Load all targets, then filter out WAF-blocked ones (Phase 2.5 output)
        raw_targets = recon.load_targets(self.results_dir, self.target, max_targets=self.max_targets)
        surface_records = load_surface_map(self.results_dir)
        if surface_records:
            reachable = set(reachable_targets(surface_records))
            targets = [t for t in raw_targets if (
                t in reachable or
                t.replace("https://", "").replace("http://", "").split("/")[0] in reachable
            )]
            blocked_count = len(raw_targets) - len(targets)
            if blocked_count > 0:
                self.log.info(
                    "Phase 3: %d/%d targets (skipped %d WAF-blocked from surface map)",
                    len(targets), len(raw_targets), blocked_count,
                )
        else:
            targets = raw_targets
        self.log.info("Phase 3: %d targets", len(targets))

        # Resource check
        cpu, ram, temp = resources.get_pi_resources()
        self.log.info("Pi5 resources — %s", resources.resource_summary())

        stats = await hunter.phase3_hunt(
            targets=targets,
            results_dir=self.results_dir,
            state=self.hunt_state,
            scope_check=self._scope.check,
            claude_client=self.claude,
            dry_run=self.dry_run,
            max_parallel=self._max_parallel,
            rate=self._rate,
            threads=self._threads,
        )

        self.hunt_state.mark_phase_done(3, summary=str(stats), stats=stats)
        self._save_state()

        self._notify_phase(3, f"Pursuing: {stats['pursuing']}/{stats['total']} leads", stats)

        # Alert on any PURSUE_HIGH leads
        if self.discord and self.discord.enabled and stats["pursuing"] > 0:
            candidates_path = self.results_dir / "03-candidates" / "candidates.jsonl"
            pursuing = hunter.load_candidates(candidates_path, status="PURSUE")
            for c in pursuing[:5]:  # cap Discord spam at 5
                self.discord.send_pursue_lead(c)

        # Claude intelligence replan
        if self.claude and self.claude.enabled:
            summary = (
                f"Total candidates: {stats['total']}\n"
                f"PURSUE: {stats['pursuing']} | AUTO_CLOSE: {stats['auto_closed']}"
            )
            brief = self.claude.intelligence_replan(3, summary, self.target, {
                "pursuing": self.hunt_state.pursuing,
                "confirmed": self.hunt_state.confirmed,
                "intelligence_notes": self.hunt_state.intelligence_notes,
            })
            if brief:
                self.hunt_state.add_intelligence_note(f"[Phase 3 replan]\n{brief}")
                self._save_state()
                self.log.info("Phase 3 replan:\n%s", brief[:400])

        # Chain analysis on pursuing leads
        if self.claude and self.claude.enabled and stats["pursuing"] > 0:
            candidates_path = self.results_dir / "03-candidates" / "candidates.jsonl"
            pursuing = hunter.load_candidates(candidates_path, status="PURSUE")
            chains = self.claude.analyze_chains(pursuing, self.target)
            if chains:
                self.log.info("Chain analysis: %d chain opportunities identified", len(chains))
                for ch in chains:
                    self.hunt_state.add_intelligence_note(
                        f"[Chain] {ch.get('title')} confidence={ch.get('confidence')}"
                    )
                self._save_state()

        self.log.info("Phase 3 DONE — %s", stats)

    # ── Phase 4 — Verification ───────────────────────────────────────────────

    async def phase4(self) -> None:
        self.log.info("══ Phase 4 — Verification & PoC")
        self.hunt_state.mark_phase_start(4)
        self._save_state()

        candidates_path = self.results_dir / "03-candidates" / "candidates.jsonl"
        pursuing = hunter.load_candidates(candidates_path, status="PURSUE")
        self.log.info("Phase 4: %d candidates to verify", len(pursuing))

        verified_dir = self.results_dir / "04-verified"
        verified_dir.mkdir(parents=True, exist_ok=True)
        manual_queue = self.results_dir / "04-verified" / "manual-queue.txt"

        confirmed: list[dict] = []
        needs_manual: list[str] = []

        for c in pursuing:
            result = await self._verify_candidate(c, verified_dir)
            if result == "CONFIRMED":
                confirmed.append(c)
                self._notify_finding(c)
            elif result == "MANUAL":
                needs_manual.append(f"{c['id']} — {c['vuln_class']} on {c['url']}")

        if needs_manual:
            for item in needs_manual:
                parts = item.split(" — ", 1)
                cid = parts[0]
                desc = parts[1] if len(parts) > 1 else item
                self.manual_q.add(
                    host=desc.split(" on ")[-1] if " on " in desc else self.target,
                    action_type="VERIFY_CHAIN_LINK",
                    priority="HIGH",
                    title=f"Manual verification: {desc}",
                    instruction=(
                        f"Candidate {cid} needs manual verification. "
                        f"Reproduce from a clean session, confirm impact, minimize PoC."
                    ),
                    finding_id=cid,
                )
            self.log.info("%d candidates queued for manual review (see --queue)", len(needs_manual))

        stats = {
            "confirmed": len(confirmed),
            "needs_manual": len(needs_manual),
            "pursuing_in": len(pursuing),
        }
        self.hunt_state.mark_phase_done(4, summary=str(stats), stats=stats)
        self._save_state()

        self._notify_phase(4, f"Confirmed: {len(confirmed)} findings", stats)
        self.log.info("Phase 4 DONE — %s", stats)

    async def _verify_candidate(self, candidate: dict, verified_dir: Path) -> str:
        """
        Try to auto-verify a candidate. Returns CONFIRMED, MANUAL, or DEAD_END.

        Currently implements:
          - Subdomain takeover: re-probe for DEPLOYMENT_NOT_FOUND fingerprint
          - Default creds: retry with empty credentials
          - All others: mark as NEEDS_MANUAL

        With a valid WIZ_JWT set, Phase 4 can attempt API-level verification.
        """
        vuln_class = candidate.get("vuln_class", "")
        url        = candidate.get("url", candidate.get("target", ""))
        cid        = candidate.get("id", "")

        if vuln_class == "subdomain-takeover":
            return await self._verify_takeover(candidate, verified_dir)

        if vuln_class == "default-creds":
            return await self._verify_default_creds(candidate, verified_dir)

        # For all other classes: queue for manual verification
        self.log.info("  %s (%s) → NEEDS_MANUAL", cid, vuln_class)
        return "MANUAL"

    async def _verify_takeover(self, candidate: dict, verified_dir: Path) -> str:
        """Re-confirm subdomain takeover fingerprints."""
        host = candidate.get("target", "").replace("https://", "").replace("http://", "").split("/")[0]
        self.log.info("  Verifying takeover: %s", host)

        FINGERPRINTS = [
            "deployment_not_found", "noSuchBucket", "nosuchbucket",
            "there is no app", "no such app", "project not found",
            "does not exist", "herokucdn.com", "github.com pages",
            "404 not found", "fastly error: unknown domain",
        ]

        rc, stdout, _ = await tools.arun(
            ["curl", "-sk", "--connect-timeout", "10", "-L",
             f"https://{host}/", "--max-redirs", "3"],
            timeout=20,
        )
        body = stdout.lower()
        for fp in FINGERPRINTS:
            if fp.lower() in body:
                self.log.info("  CONFIRMED takeover: %s (fingerprint: %s)", host, fp)
                evidence_dir = verified_dir / candidate["id"]
                evidence_dir.mkdir(parents=True, exist_ok=True)
                (evidence_dir / "evidence.txt").write_text(
                    f"Host: {host}\nFingerprint matched: {fp}\nResponse body excerpt:\n{stdout[:500]}"
                )
                # Add to findings
                finding = {**candidate, "verdict": "CONFIRMED", "evidence": f"Fingerprint: {fp}",
                           "impact": f"Attacker can claim {host} via Vercel/AWS/GitHub Pages",
                           "remediation": "Remove dangling CNAME or reclaim the resource."}
                self.hunt_state.add_finding(state.Finding(
                    id=candidate["id"], candidate_id=candidate["id"],
                    target=candidate.get("target", ""), vuln_class="subdomain-takeover",
                    severity=candidate.get("severity", "high"),
                    title=f"Subdomain Takeover — {host}",
                    summary=f"Host {host} has a dangling CNAME pointing to an unclaimed resource.",
                    cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                    cvss_score=8.2,
                    impact=finding["impact"],
                    remediation=finding["remediation"],
                ))
                self._save_state()
                return "CONFIRMED"

        self.log.info("  Takeover fingerprint not found for %s → MANUAL", host)
        return "MANUAL"

    async def _verify_default_creds(self, candidate: dict, verified_dir: Path) -> str:
        """Try common default credentials against admin panels."""
        # Placeholder — extend with actual credential testing per service
        self.log.info("  Default-creds verification for %s → MANUAL (not yet automated)", candidate.get("url"))
        return "MANUAL"

    # ── Phase 5 — Triage ────────────────────────────────────────────────────

    async def phase5(self) -> None:
        self.log.info("══ Phase 5 — Triage & Pre-Submission Gate")
        self.hunt_state.mark_phase_start(5)
        self._save_state()

        triage_dir = self.results_dir / "05-triage"
        triage_dir.mkdir(parents=True, exist_ok=True)

        findings = self.hunt_state.findings
        self.log.info("Phase 5: triaging %d confirmed findings", len(findings))

        triage_rows = []
        for f in findings:
            row = self._triage_finding(f)
            triage_rows.append(row)

        self._write_triage_md(triage_dir / "triage.md", triage_rows)

        stats = {
            "findings": len(findings),
            "report_ready": sum(1 for r in triage_rows if r["gate_pass"]),
        }
        self.hunt_state.mark_phase_done(5, summary=str(stats), stats=stats)
        self._save_state()
        self.log.info("Phase 5 DONE — %s", stats)

    def _triage_finding(self, f: dict) -> dict:
        score = f.get("cvss_score", 0.0)
        sev   = f.get("severity", "").lower()
        gate  = (
            score >= 4.0
            and bool(f.get("impact"))
            and bool(f.get("evidence"))
        )
        return {
            "id": f.get("id"),
            "title": f.get("title", ""),
            "severity": sev,
            "cvss_score": score,
            "gate_pass": gate,
            "target": f.get("target", ""),
        }

    def _write_triage_md(self, path: Path, rows: list[dict]) -> None:
        lines = [
            "# Triage Report", "",
            "| ID | Severity | CVSS | Target | Gate | Title |",
            "|----|----------|------|--------|------|-------|",
        ]
        for r in sorted(rows, key=lambda x: x.get("cvss_score", 0), reverse=True):
            gate = "✅ SUBMIT" if r["gate_pass"] else "❌ HOLD"
            lines.append(
                f"| {r['id']} | {r['severity']} | {r['cvss_score']} "
                f"| {r['target']} | {gate} | {r['title'][:60]} |"
            )
        path.write_text("\n".join(lines))
        self.log.info("Triage report: %s", path)

    # ── Phase 6 — Report generation ──────────────────────────────────────────

    async def phase6(self) -> None:
        self.log.info("══ Phase 6 — Report Generation")
        self.hunt_state.mark_phase_start(6)
        self._save_state()

        findings_dir = self.results_dir / "findings"
        report_count = 0

        for f in self.hunt_state.findings:
            if not self._passes_submission_gate(f):
                self.log.info("  %s — DOES NOT pass submission gate, skipping report", f.get("id"))
                continue
            rpath = reporter.generate_report(
                f, findings_dir, self.claude,
                target_context=f"Program: {self._scope.get_program_name(self.target) or self.target}",
            )
            if rpath:
                report_count += 1
                self.log.info("  Report: %s", rpath)
                # Update finding with report path
                self.hunt_state.update_candidate(f.get("id", ""), report_path=str(rpath))

        self._save_state()
        stats = {"reports_written": report_count}
        self.hunt_state.mark_phase_done(6, summary=f"{report_count} reports written", stats=stats)
        self._save_state()
        self.log.info("Phase 6 DONE — %d reports written", report_count)

    def _passes_submission_gate(self, f: dict) -> bool:
        required = ["impact", "evidence", "target", "vuln_class"]
        if not all(f.get(k) for k in required):
            return False
        cvss = f.get("cvss_score", 0.0)
        return cvss >= 4.0 or f.get("severity", "").lower() in ("high", "critical")

    # ── Status display ────────────────────────────────────────────────────────

    def print_status(self) -> None:
        s = self.hunt_state
        candidates_path = self.results_dir / "03-candidates" / "candidates.jsonl"
        c_stats = hunter.candidate_stats(candidates_path)
        pursuing    = c_stats.get("PURSUE", 0)
        auto_closed = c_stats.get("AUTO_CLOSE", 0)
        total_cands = sum(c_stats.values())

        cpu, ram, temp = resources.get_pi_resources()
        mq_stats = self.manual_q.stats()
        pending_actions = mq_stats.get("PENDING", 0)

        sep = "═" * 60
        print(f"\n{sep}")
        print(f"  Bug Bounty Agent v{self.VERSION} — {self.target}")
        print(sep)
        print(f"  Phase:     {s.current_phase}")
        print(f"  Candidates:{total_cands:4d}  (Pursuing:{pursuing}  Closed:{auto_closed})")
        print(f"  Findings:  {s.confirmed:4d}  (confirmed)")
        print(f"  Actions:   {pending_actions:4d}  pending manual  (run --queue to see all)")
        print(f"  Pi5:       CPU:{cpu}%  RAM:{ram}%  Temp:{temp}°C")
        print(sep)
        print("  Phase completion:")
        for ph in range(7):
            done = "✓" if s.phase_done(ph) else "·"
            pnames = {0:"Scope",1:"Assets",2:"Surface+Map",3:"Hunt",4:"Verify",5:"Triage",6:"Report"}
            print(f"    {done} Phase {ph} — {pnames.get(ph,'')}")
        print(sep)
        if s.intelligence_notes:
            print("\n  Latest intelligence note:")
            print(f"  {s.intelligence_notes[-1][:120]}")
        print()

    # ── Main entry point ─────────────────────────────────────────────────────

    async def run(self) -> int:
        self.log.info(
            "══ Bug Bounty Orchestrator v%s ══  target=%s  phases=%d-%d  dry=%s",
            self.VERSION, self.target, self.phase_start, self.phase_end, self.dry_run,
        )

        if not self.tools_ok.get("nuclei"):
            self.log.warning("nuclei not found — Phase 3 will be limited")

        try:
            if self._should_run(0):
                await self.phase0()
            if self._should_run(2):
                await self.phase12()
            # Phase 2.5 always runs between 2 and 3 when both are in range
            if self.phase_start <= 2 and self.phase_end >= 3:
                await self.phase25()
            elif self._should_run(3):
                # Also run 2.5 if phase 3 is being run standalone
                await self.phase25()
            if self._should_run(3):
                await self.phase3()
            if self._should_run(4):
                await self.phase4()
            if self._should_run(5):
                await self.phase5()
            if self._should_run(6):
                await self.phase6()
        except SystemExit:
            raise
        except Exception as e:
            self.log.exception("Orchestrator fatal error: %s", e)
            if self.discord:
                self.discord.send_error(self.target, self.hunt_state.current_phase, str(e))
            return 3
        finally:
            self._save_state()

        self.print_status()

        # Always print manual action queue at end of run
        pending = self.manual_q.pending()
        if pending:
            sep = "═" * 60
            print(f"\n{sep}")
            print("  MANUAL ACTIONS REQUIRED (do these on your machine)")
            print(sep)
            print(self.manual_q.render())

        return 0


# ── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    target = args.target or "unknown"
    results_dir = ROOT / "results" / target

    if args.status:
        # Fast status-only path (no phase execution)
        s = state.load_or_init(results_dir / ".orchestrator-state.json", target)
        cpu, ram, temp = resources.get_pi_resources()
        mq = ManualQueue(results_dir, target)
        print(f"Target: {target}  v2.1")
        print(f"Phase: {s.current_phase}  Findings: {s.confirmed}  Pi: CPU:{cpu}% RAM:{ram}% T:{temp}°C")
        print(f"Manual actions pending: {len(mq.pending())}")
        for ph in range(7):
            done = "DONE" if s.phase_done(ph) else "----"
            print(f"  Phase {ph}: {done}")
        return 0

    if getattr(args, "queue", False):
        # Print manual action queue only
        mq = ManualQueue(results_dir, target)
        sep = "═" * 60
        print(f"\n{sep}")
        print(f"  Manual Action Queue — {target}")
        print(sep)
        print(mq.render())
        return 0

    if getattr(args, "complete_action", None):
        # Mark an action as done
        mq = ManualQueue(results_dir, target)
        action_id = args.complete_action
        result = getattr(args, "action_result", "")
        if mq.complete(action_id, result):
            print(f"Action {action_id} marked DONE.")
        else:
            print(f"Action {action_id} not found in queue.")
        return 0

    if getattr(args, "ingest", None):
        # Ingest manually discovered candidates
        ingest_path = Path(args.ingest)
        if not ingest_path.exists():
            print(f"File not found: {ingest_path}")
            return 1
        candidates_path = results_dir / "03-candidates" / "candidates.jsonl"
        candidates_path.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with ingest_path.open() as inf, candidates_path.open("a") as outf:
            for line in inf:
                line = line.strip()
                if line:
                    try:
                        json.loads(line)   # validate JSON
                        outf.write(line + "\n")
                        count += 1
                    except json.JSONDecodeError as e:
                        print(f"  Skipped malformed line: {e}")
        print(f"Ingested {count} candidates from {ingest_path} → {candidates_path}")
        return 0

    orch = Orchestrator(args)
    return asyncio.run(orch.run())


def _sha6(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()[:6]


if __name__ == "__main__":
    sys.exit(main())
