"""
Manual Action Queue — tracks steps that require human intervention.

The agentic workflow can automate network probes but cannot:
  - Open a browser and observe redirects
  - Log in with enterprise credentials
  - Receive emails for registration confirmation
  - Capture OAuth tokens from a live SSO flow

This module persists those actions so they survive context resets and
renders a clear TODO checklist when the orchestrator finishes a run.

Storage: results/<target>/manual_queue.jsonl
Format : one JSON object per line, append-only
"""
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class ActionStatus(str, Enum):
    PENDING   = "PENDING"
    DONE      = "DONE"
    BLOCKED   = "BLOCKED"   # cannot be done (no credentials, no access, etc.)
    SKIPPED   = "SKIPPED"   # decided not to pursue


class ActionPriority(str, Enum):
    CRITICAL  = "CRITICAL"  # unlocks a confirmed Critical/High finding
    HIGH      = "HIGH"      # unlocks a High finding
    MEDIUM    = "MEDIUM"    # unlocks a Medium finding or chain step
    LOW       = "LOW"       # nice to have


# Maps to human-readable descriptions in the queue printout
_ACTION_LABELS = {
    "BROWSER_OAUTH_FLOW":       "Capture OAuth client_id from browser Network tab",
    "BROWSER_OIDC_FLOW":        "Capture OIDC redirect from browser",
    "SELF_REGISTRATION":        "Complete self-registration on target",
    "AUTHENTICATED_RECON":      "Run authenticated API enumeration after login",
    "VERIFY_CHAIN_LINK":        "Manually verify a chain link that requires auth",
    "OIDC_DYNAMIC_REGISTRATION":"Test OIDC dynamic client registration",
    "ADMIN_PANEL_CHECK":        "Investigate admin panel content",
    "EMAIL_CONFIRMATION":       "Complete email confirmation for registration",
    "ENTERPRISE_CREDENTIALS":   "Obtain enterprise trial/credentials to access target",
    "SCREENSHOT_EVIDENCE":      "Take screenshot for PoC documentation",
    "CLAIM_SUBDOMAIN":          "Claim vulnerable subdomain on Vercel/GitHub Pages/etc.",
    "OTHER":                    "Manual action required",
}


@dataclass
class ManualAction:
    id: str
    target: str
    host: str
    action_type: str
    priority: str
    status: str = ActionStatus.PENDING
    title: str = ""
    instruction: str = ""
    commands: list[str] = field(default_factory=list)
    expected_output: str = ""
    finding_id: str = ""          # links to a candidate/finding if applicable
    unlocks: str = ""             # what this action unlocks (e.g. "OAuth chain Critical")
    created_ts: str = ""
    completed_ts: str = ""
    result: str = ""


class ManualQueue:
    """Persistent queue of actions that require human intervention."""

    def __init__(self, results_dir: Path, target: str):
        self.target = target
        self.path = results_dir / "manual_queue.jsonl"
        self._items: dict[str, ManualAction] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text().splitlines():
            try:
                d = json.loads(line)
                action = ManualAction(**d)
                self._items[action.id] = action
            except Exception as e:
                log.debug("Could not parse manual queue entry: %s", e)

    def _save_all(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w") as f:
            for item in self._items.values():
                f.write(json.dumps(asdict(item)) + "\n")

    def _append(self, action: ManualAction) -> None:
        """Append a single new action (does not overwrite existing)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(json.dumps(asdict(action)) + "\n")

    def add(
        self,
        host: str,
        action_type: str,
        priority: str,
        instruction: str,
        title: str = "",
        commands: Optional[list[str]] = None,
        expected_output: str = "",
        finding_id: str = "",
        unlocks: str = "",
    ) -> ManualAction:
        """Add a new action. Returns the action. Skips if identical action already exists."""
        action_id = _make_id(host, action_type)

        # Don't duplicate an existing PENDING action of the same type/host
        if action_id in self._items:
            existing = self._items[action_id]
            if existing.status == ActionStatus.PENDING:
                log.debug("Duplicate manual action %s — skipping", action_id)
                return existing

        action = ManualAction(
            id=action_id,
            target=self.target,
            host=host,
            action_type=action_type,
            priority=priority,
            title=title or _ACTION_LABELS.get(action_type, action_type),
            instruction=instruction,
            commands=commands or [],
            expected_output=expected_output,
            finding_id=finding_id,
            unlocks=unlocks,
            created_ts=_now(),
        )
        self._items[action_id] = action
        self._append(action)
        log.info("Manual action queued [%s] %s on %s", priority, action_type, host)
        return action

    def complete(self, action_id: str, result: str = "") -> bool:
        """Mark an action as DONE."""
        if action_id not in self._items:
            return False
        self._items[action_id].status = ActionStatus.DONE
        self._items[action_id].completed_ts = _now()
        self._items[action_id].result = result
        self._save_all()
        return True

    def block(self, action_id: str, reason: str = "") -> bool:
        """Mark an action as BLOCKED (cannot be done right now)."""
        if action_id not in self._items:
            return False
        self._items[action_id].status = ActionStatus.BLOCKED
        self._items[action_id].result = reason
        self._save_all()
        return True

    def pending(self) -> list[ManualAction]:
        """Return all PENDING actions sorted by priority."""
        _order = {ActionStatus.PENDING: 0}
        _priority = {
            ActionPriority.CRITICAL: 0,
            ActionPriority.HIGH: 1,
            ActionPriority.MEDIUM: 2,
            ActionPriority.LOW: 3,
        }
        return sorted(
            [a for a in self._items.values() if a.status == ActionStatus.PENDING],
            key=lambda a: _priority.get(a.priority, 99),
        )

    def render(self) -> str:
        """Render the pending queue as a human-readable checklist."""
        pending = self.pending()
        if not pending:
            return "  ✓  No pending manual actions."

        lines = []
        lines.append(f"  {len(pending)} pending manual action(s) — do these on your machine:\n")

        for i, action in enumerate(pending, 1):
            priority_emoji = {
                "CRITICAL": "🔴",
                "HIGH":     "🟠",
                "MEDIUM":   "🟡",
                "LOW":      "⚪",
            }.get(action.priority, "•")

            lines.append(f"  [{i}] {priority_emoji} [{action.priority}] {action.title}")
            lines.append(f"      Host:    {action.host}")
            if action.unlocks:
                lines.append(f"      Unlocks: {action.unlocks}")
            lines.append(f"      Action:  {action.instruction}")
            if action.commands:
                lines.append("      Commands:")
                for cmd in action.commands:
                    lines.append(f"        $ {cmd}")
            if action.expected_output:
                lines.append(f"      Expected: {action.expected_output}")
            lines.append(f"      ID: {action.id}  (run: python3 scripts/orchestrate.py {self.target} --complete-action {action.id})")
            lines.append("")

        return "\n".join(lines)

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self._items.values():
            counts[item.status] = counts.get(item.status, 0) + 1
        return counts


# ── Pre-built action factories for common scenarios ──────────────────────────

def add_oauth_browser_action(
    queue: ManualQueue,
    host: str,
    login_url: str,
    auth_url: str,
    finding_id: str = "",
) -> ManualAction:
    """Add a browser OAuth client_id capture action."""
    return queue.add(
        host=host,
        action_type="BROWSER_OAUTH_FLOW",
        priority=ActionPriority.HIGH,
        title=f"Capture OAuth client_id from {host} login",
        instruction=(
            f"Open {login_url} in Chrome. "
            f"Open DevTools → Network → filter by 'authorize'. "
            f"Click 'Sign in with SSO' button (NOT the email form). "
            f"Watch for redirect to {auth_url}/authorize?client_id=XXXXXXXX. "
            f"Copy the client_id value."
        ),
        commands=[
            f"# After capturing client_id from browser:",
            f"CLIENT_ID=<value> bash scripts/wiz-oauth-chain-verify.sh",
        ],
        expected_output="client_id=<32-char alphanumeric value>",
        finding_id=finding_id,
        unlocks="OAuth redirect_uri chain → Critical account takeover if win-test.wiz.io accepted",
    )


def add_self_registration_action(
    queue: ManualQueue,
    host: str,
    registration_url: str,
    finding_id: str = "",
) -> ManualAction:
    """Add a self-registration investigation action."""
    return queue.add(
        host=host,
        action_type="SELF_REGISTRATION",
        priority=ActionPriority.CRITICAL,
        title=f"Complete self-registration on {host}",
        instruction=(
            f"Register at {registration_url} with a test email (use a burner). "
            f"After login: enumerate /api/*, look for IDOR (can you access other orgs/users?), "
            f"check what data is visible, test privilege escalation endpoints."
        ),
        commands=[
            f"# After registering and logging in, run authenticated scan:",
            f"SESSION_COOKIE='your_session_here' bash scripts/mandiant-followup-probe.sh",
        ],
        expected_output="Access to authenticated surface; check for IDOR/data leakage",
        finding_id=finding_id,
        unlocks="Authenticated API surface → potential IDOR/broken-access-control High",
    )


def add_subdomain_claim_action(
    queue: ManualQueue,
    host: str,
    cname_target: str,
    provider: str,
    finding_id: str = "",
) -> ManualAction:
    """Add a subdomain claim action for verified takeovers."""
    return queue.add(
        host=host,
        action_type="CLAIM_SUBDOMAIN",
        priority=ActionPriority.HIGH,
        title=f"Claim {host} on {provider} (subdomain takeover PoC)",
        instruction=(
            f"ONLY for PoC documentation — do NOT serve malicious content. "
            f"On {provider}: add {host} as a custom domain "
            f"(DNS proves ownership via the CNAME {cname_target}). "
            f"Serve a benign 'PoC by <researcher>' page. Screenshot. Remove immediately after."
        ),
        commands=[
            f"# 1. Create {provider} project",
            f"# 2. Add custom domain: {host}",
            f"# 3. curl https://{host}/ to confirm PoC page loads",
            f"# 4. Take screenshot",
            f"# 5. Remove domain from project immediately",
        ],
        expected_output=f"Your PoC page loads at https://{host}/",
        finding_id=finding_id,
        unlocks="Completes PoC for subdomain takeover report; may elevate from High to Critical with OAuth chain",
    )


def _make_id(host: str, action_type: str) -> str:
    import hashlib
    return "M" + hashlib.sha256(f"{host}:{action_type}".encode()).hexdigest()[:6]


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
