"""
Claude AI intelligence client.

Integrates the Anthropic API at five points in the hunt pipeline:

  1. qualify_lead()      — Phase 3: 5-gate lead qualification with tool use
  2. analyze_chains()    — Phase 3→4: chain elevation analysis for confirmed leads
  3. intelligence_replan() — Between phases: reprioritize targets & hypotheses
  4. generate_report()   — Phase 6: write a triager-grade vulnerability report
  5. discord_summary()   — On confirmation: brief summary for Discord embed

Set ANTHROPIC_API_KEY in the environment before running.
"""
import json
import logging
import os
from typing import Any, Optional

log = logging.getLogger(__name__)

try:
    import anthropic as _anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False
    log.warning("anthropic package not installed — Claude features disabled. Run: pip3 install anthropic")

MODEL = "claude-sonnet-4-6"

# ── Qualification gate tool schema ───────────────────────────────────────────

_QUALIFY_TOOL = {
    "name": "submit_qualification",
    "description": "Submit your structured qualification decision for this security finding.",
    "input_schema": {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "enum": ["PURSUE_HIGH", "PURSUE_MARGINAL", "AUTO_CLOSE"],
                "description": (
                    "PURSUE_HIGH: score 4-5, actionable immediately. "
                    "PURSUE_MARGINAL: score 2-3, needs more information or has major gaps. "
                    "AUTO_CLOSE: score 0-1, falls in Hard Rejection List or no attacker gain."
                ),
            },
            "score": {
                "type": "integer", "minimum": 0, "maximum": 5,
                "description": "Sum of gate questions passed (1 point each, max 5).",
            },
            "q1_concrete_attacker_gain": {
                "type": "boolean",
                "description": "Attacker concretely gains: account access, another user's data, code execution, SSRF to sensitive targets, auth bypass, cross-tenant isolation break, or meaningful privilege escalation.",
            },
            "q2_not_intended_behavior": {
                "type": "boolean",
                "description": "The behavior is NOT documented as intentional or expected product design.",
            },
            "q3_vendor_would_fix": {
                "type": "boolean",
                "description": "The vendor would actually change code/config to fix this (not just 'add a header' with no exploit path).",
            },
            "q4_cvss_above_4": {
                "type": "boolean",
                "description": "Estimated CVSS 3.1 base score is ≥ 4.0 (Medium or higher).",
            },
            "q5_not_hard_rejected": {
                "type": "boolean",
                "description": "Finding does NOT appear in the Hard Rejection List (missing headers, self-XSS, CSRF on logout, version disclosure, rate limit on non-sensitive endpoints, etc.).",
            },
            "rejection_reasons": {
                "type": "array", "items": {"type": "string"},
                "description": "Specific Hard Rejection List categories this falls under, if any.",
            },
            "chain_potential": {
                "type": "string",
                "description": "If Low/Info: describe a TESTABLE chain that would elevate this to Medium+. Empty if not applicable.",
            },
            "next_steps": {
                "type": "array", "items": {"type": "string"},
                "description": "Specific, executable verification steps if PURSUE_HIGH or PURSUE_MARGINAL.",
            },
            "estimated_cvss": {
                "type": "string",
                "description": "Estimated CVSS 3.1 vector string, e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            },
        },
        "required": [
            "status", "score",
            "q1_concrete_attacker_gain", "q2_not_intended_behavior",
            "q3_vendor_would_fix", "q4_cvss_above_4", "q5_not_hard_rejected",
        ],
    },
}

# ── System prompts ─────────────────────────────────────────────────────────

_QUALIFY_SYSTEM = """You are an elite, authorized bug bounty hunter with 10+ years of experience. \
You apply a rigorous 5-gate qualification framework before investing time in any security finding. \
Your goal is to eliminate noise ruthlessly and pursue only findings with real, demonstrable impact.

## The 5-Gate Qualification Framework

For each gate, you must be able to answer YES with SPECIFIC evidence — not "could potentially".

**Q1 — Concrete Attacker Gain** (1 point)
The attacker must concretely gain ONE of:
- Access to another user's account
- Data belonging to another user (PII, secrets, cloud assets)
- Persistent remote code execution
- SSRF to sensitive internal resources (cloud metadata, internal services with creds/data)
- Authentication bypass (skip auth entirely)
- Cross-tenant isolation break (read/write another organization's data)
- Meaningful privilege escalation (user→admin, read→write on sensitive resource)

"Information disclosure" ONLY qualifies if the disclosed information directly enables one of the above.

**Q2 — Not Intended Behavior** (1 point)
The behavior must not be documented as intentional in:
- The vendor's public documentation
- The program's known-issues list
- Reasonable product design (e.g., a public API endpoint being... public)

**Q3 — Fix Test** (1 point)
The vendor would need to make a real code or configuration change to fix this.
If the "fix" is just "add a header" and no actual exploit path exists → FAIL this gate.
If fixing it requires changing application logic, access control, or data validation → PASS.

**Q4 — CVSS ≥ 4.0** (1 point)
Estimated CVSS 3.1 base score must be ≥ 4.0 (Medium or higher).
Be realistic. A missing header is 0. An SSRF to metadata is 8.5+. An IDOR reading someone's profile is 5-6.

**Q5 — Not in Hard Rejection List** (1 point)
AUTOMATICALLY FAIL and AUTO_CLOSE if the finding falls into ANY of these:
- Missing security headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) without demonstrated exploit
- TLS 1.0/1.1 support without proof of active downgrade
- CORS permissive on endpoints returning no sensitive data
- CSP weaknesses / development artifacts (ws://localhost) where no content injection or exfiltration path exists
- Clickjacking without a sensitive state-changing authenticated action
- Software/server version disclosure without CVE chained
- Stack traces / verbose errors without exploitable data exposed
- Public API documentation (Swagger/OpenAPI) revealing no credentials and no exploitable logic
- SPF, DKIM, DMARC email misconfigs
- Subdomain takeover on host with NO user traffic AND NO shared cookie domain AND NO OAuth redirect use
- Rate limiting absent on non-sensitive endpoints (no credential brute-force or PII enumeration demonstrated)
- Open redirect to a domain OWNED by the target
- Login page lacks CAPTCHA/lockout (without demonstrated rate-limit bypass)
- Password policy issues
- Self-XSS (victim must attack themselves)
- CSRF on logout or non-sensitive read-only actions
- Feature gaps ("no 2FA") without bypass demonstrated
- Theoretical chains where ANY link is unverified

## Decision Rules
- Score 4-5: PURSUE_HIGH — actionable, investigate immediately
- Score 2-3: PURSUE_MARGINAL — has potential but significant gaps; log and revisit with more context
- Score 0-1: AUTO_CLOSE — drop it, one-line note in log, move on

Always use the submit_qualification tool to return your structured decision. Do not return plain text."""

_CHAIN_SYSTEM = """You are an elite bug bounty hunter specializing in vulnerability chaining \
and escalation analysis. You receive a list of confirmed or pursuing leads and identify \
TESTABLE chains that elevate Low/Info findings to Medium+ severity.

## Chain Elevation Rules

A Low or Info finding is worth pursuing ONLY if you can identify a TESTABLE chain that elevates it to Medium+.
The chain must be: specific, testable NOW (not "if condition X is true"), and documented step-by-step.

## Valid Chain Examples
- Subdomain takeover (F001) + shared cookie domain → session theft (High, 8.0)
- Subdomain takeover (F001) + OAuth redirect_uri allowlist → account takeover (Critical, 9.3)
- Blind SSRF + reachable internal Grafana → datasource credentials (Critical, 9.1)
- Reflected XSS in low-sensitivity page + page embedded in admin panel → admin session theft (High, 7.5)
- S3 bucket listing disabled + guessable key pattern + valid auth token → cross-tenant data read (High, 7.8)

## Invalid Chains (do not propose)
- Chains where ANY step is "if the vendor has X misconfigured" without confirming it
- Chains requiring attacker to be on the same LAN
- Chains requiring user to have a specific browser extension
- Chains where the elevation is speculative ("could theoretically...")

## Output Format
Return a JSON array of chain objects:
[
  {
    "chain_id": "C1",
    "title": "One-line chain description",
    "components": ["finding_id_1", "finding_id_2"],
    "steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
    "elevated_severity": "High",
    "elevated_cvss": 8.0,
    "confidence": "HIGH|MEDIUM|LOW",
    "blocker": "What is needed to confirm/execute this chain?",
    "testable_now": true
  }
]"""

_REPLAN_SYSTEM = """You are the orchestrator intelligence for an autonomous bug bounty hunting agent. \
After each phase, you analyze the results and decide how to best direct the next phase. \
You are strategic, ruthless about killing noise, and focused on finding real High/Critical bugs. \
Your output must be specific and actionable — not generic advice."""

_REPORT_SYSTEM = """You are an expert bug bounty reporter. Your reports get triagers to pay out \
within minutes because they are specific, minimal, reproducible, and have concrete impact stories. \
You follow the structure: Title → Summary → Severity → Steps to Reproduce → Proof → Impact → Remediation → References.

Rules:
- Title format: [Class] [Impact] via [Location]
- Summary: 2-3 sentences only. What, where, why it matters.
- Severity: CVSS 3.1 vector string + business impact sentence
- Steps: numbered, copy-pasteable, from a clean state, executable by someone who hasn't seen the app
- Proof: minimal request/response or screenshot description. Sanitize PII.
- Impact: CONCRETE. "An attacker can read any customer's cloud asset inventory" not "sensitive information could be accessed"
- Remediation: specific fix tied to root cause
- Never overstate severity. Never claim unverified chains as confirmed."""


class ClaudeAI:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.enabled = bool(self.api_key) and _ANTHROPIC_AVAILABLE
        self._client = None
        if self.enabled:
            self._client = _anthropic.Anthropic(api_key=self.api_key)
        elif not _ANTHROPIC_AVAILABLE:
            log.warning("Install anthropic: pip3 install anthropic")
        elif not self.api_key:
            log.warning("Set ANTHROPIC_API_KEY to enable Claude intelligence features")

    def qualify_lead(self, candidate: dict, target_context: str = "") -> dict:
        """
        Score a candidate finding 0-5 on the 5-gate framework.

        Returns the tool_use result dict, or a fallback AUTO_CLOSE if Claude is unavailable.
        """
        if not self.enabled:
            return _fallback_qualification(candidate)

        prompt = _build_qualify_prompt(candidate, target_context)
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=1024,
                system=_QUALIFY_SYSTEM,
                tools=[_QUALIFY_TOOL],
                tool_choice={"type": "any"},
                messages=[{"role": "user", "content": prompt}],
            )
            for block in response.content:
                if block.type == "tool_use" and block.name == "submit_qualification":
                    result = dict(block.input)
                    log.info(
                        "Lead qualified: %s score=%s url=%s",
                        result.get("status"), result.get("score"),
                        candidate.get("url", candidate.get("target", "?"))
                    )
                    return result
            # Claude didn't call the tool — shouldn't happen with tool_choice=any
            log.warning("Claude did not call qualification tool — AUTO_CLOSE fallback")
            return _fallback_qualification(candidate)
        except Exception as e:
            log.warning("Claude qualify_lead failed: %s", e)
            return _fallback_qualification(candidate)

    def analyze_chains(self, candidates: list[dict], target: str) -> list[dict]:
        """
        Propose chain escalation paths from pursuing/confirmed candidates.
        Returns list of chain dicts.
        """
        if not self.enabled or not candidates:
            return []

        pursue = [c for c in candidates if c.get("status") in ("PURSUE", "CONFIRMED")]
        if not pursue:
            return []

        prompt = (
            f"Target: {target}\n\n"
            f"Current pursuing/confirmed leads:\n"
            f"{json.dumps(pursue, indent=2)[:6000]}\n\n"
            f"Identify all TESTABLE chain escalation opportunities. "
            f"Return a JSON array of chain objects as described in your instructions."
        )
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=2048,
                system=_CHAIN_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            text = _extract_text(response)
            # Parse JSON array from response
            chains = _parse_json_array(text)
            log.info("Chain analysis: %d chains identified for %s", len(chains), target)
            return chains
        except Exception as e:
            log.warning("Chain analysis failed: %s", e)
            return []

    def intelligence_replan(self, phase: int, results_summary: str, target: str, hunt_state: dict) -> str:
        """
        After a phase completes, ask Claude to reprioritize and suggest next actions.
        Returns a plain-text intelligence brief.
        """
        if not self.enabled:
            return ""

        pursuing = hunt_state.get("pursuing", 0)
        confirmed = hunt_state.get("confirmed", 0)
        prompt = (
            f"Target: {target}\n"
            f"Phase {phase} just completed.\n\n"
            f"Phase results summary:\n{results_summary}\n\n"
            f"Current hunt state:\n"
            f"- Pursuing leads: {pursuing}\n"
            f"- Confirmed findings: {confirmed}\n"
            f"- Intelligence notes: {json.dumps(hunt_state.get('intelligence_notes', [])[-5:])}\n\n"
            f"Given these results, what should the hunt prioritize next? "
            f"Be specific: name exact hosts, endpoints, or attack classes to test. "
            f"Kill noise aggressively. Focus on paths to High/Critical bugs."
        )
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=1024,
                system=_REPLAN_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            brief = _extract_text(response)
            log.info("Intelligence replan complete for phase %d", phase)
            return brief
        except Exception as e:
            log.warning("Intelligence replan failed: %s", e)
            return ""

    def generate_report(self, finding: dict, target_context: str = "") -> str:
        """
        Generate a triager-grade vulnerability report in Markdown.
        Returns the full report text.
        """
        if not self.enabled:
            return _fallback_report(finding)

        prompt = (
            f"Target context: {target_context}\n\n"
            f"Finding details:\n{json.dumps(finding, indent=2)[:4000]}\n\n"
            f"Write a complete, triager-grade vulnerability report in Markdown. "
            f"Follow the structure exactly: Title, Summary, Severity, Steps to Reproduce, "
            f"Proof, Impact, Remediation, References. "
            f"Be concrete, specific, and minimal. No filler. No speculation."
        )
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=2048,
                system=_REPORT_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            report = _extract_text(response)
            log.info("Report generated for finding: %s", finding.get("id"))
            return report
        except Exception as e:
            log.warning("Report generation failed: %s", e)
            return _fallback_report(finding)

    def discord_summary(self, finding: dict) -> str:
        """
        Generate a 2-3 sentence executive summary for a Discord notification.
        """
        if not self.enabled:
            return finding.get("summary", "No summary available.")

        prompt = (
            f"Write a 2-3 sentence executive summary for this security finding, "
            f"suitable for a Discord notification. Lead with the impact, not the class. "
            f"Be specific about what an attacker gains.\n\n"
            f"Finding: {json.dumps(finding, indent=2)[:2000]}"
        )
        try:
            response = self._client.messages.create(
                model=MODEL,
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            return _extract_text(response).strip()
        except Exception as e:
            log.warning("Discord summary failed: %s", e)
            return finding.get("summary", "Confirmed vulnerability — see findings directory.")


# ── Helper functions ───────────────────────────────────────────────────────

def _build_qualify_prompt(candidate: dict, target_context: str) -> str:
    return (
        f"Target context: {target_context or 'Not provided'}\n\n"
        f"Candidate finding to qualify:\n"
        f"```json\n{json.dumps(candidate, indent=2)[:3000]}\n```\n\n"
        f"Apply the 5-gate framework and submit your qualification decision using the tool."
    )


def _fallback_qualification(candidate: dict) -> dict:
    """Heuristic fallback when Claude is unavailable."""
    sev = candidate.get("severity", "info").lower()
    template = candidate.get("template", "").lower()

    # Auto-close informational headers/config issues
    hard_reject_patterns = [
        "missing-header", "hsts", "x-frame", "csp", "cors", "clickjack",
        "ssl-dns-names", "self-signed", "version", "stack-trace", "robots",
        "sitemap", "rate-limit", "captcha", "password-policy",
    ]
    for p in hard_reject_patterns:
        if p in template:
            return {
                "status": "AUTO_CLOSE",
                "score": 0,
                "q1_concrete_attacker_gain": False,
                "q2_not_intended_behavior": True,
                "q3_vendor_would_fix": False,
                "q4_cvss_above_4": False,
                "q5_not_hard_rejected": False,
                "rejection_reasons": [f"Hard rejection: matches pattern '{p}'"],
                "chain_potential": "",
                "next_steps": [],
                "estimated_cvss": "",
            }

    if sev in ("critical", "high"):
        return {
            "status": "PURSUE_HIGH", "score": 4,
            "q1_concrete_attacker_gain": True, "q2_not_intended_behavior": True,
            "q3_vendor_would_fix": True, "q4_cvss_above_4": True, "q5_not_hard_rejected": True,
            "rejection_reasons": [], "chain_potential": "",
            "next_steps": ["Manual verification required — Claude unavailable"],
            "estimated_cvss": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if sev == "critical" else "",
        }
    return {
        "status": "AUTO_CLOSE", "score": 1,
        "q1_concrete_attacker_gain": False, "q2_not_intended_behavior": True,
        "q3_vendor_would_fix": False, "q4_cvss_above_4": False, "q5_not_hard_rejected": True,
        "rejection_reasons": [f"Low/medium severity with no confirmed impact chain"],
        "chain_potential": "", "next_steps": [], "estimated_cvss": "",
    }


def _fallback_report(finding: dict) -> str:
    return (
        f"# {finding.get('title', 'Untitled Finding')}\n\n"
        f"**Severity:** {finding.get('severity', 'Unknown')}\n"
        f"**Target:** {finding.get('target', 'Unknown')}\n"
        f"**Class:** {finding.get('vuln_class', 'Unknown')}\n\n"
        f"## Summary\n{finding.get('summary', 'No summary.')}\n\n"
        f"## Impact\n{finding.get('impact', 'Not specified.')}\n\n"
        f"## Evidence\n```\n{finding.get('evidence', 'No evidence.')}\n```\n\n"
        f"## Remediation\n{finding.get('remediation', 'Not specified.')}\n"
    )


def _extract_text(response: Any) -> str:
    for block in response.content:
        if hasattr(block, "text"):
            return block.text
    return ""


def _parse_json_array(text: str) -> list:
    import re
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return []
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return []
