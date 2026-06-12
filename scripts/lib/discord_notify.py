"""
Discord webhook notifications for confirmed findings and high-priority leads.

Sends rich embeds with severity color-coding, CVSS scores, and reproduction hints.
Set DISCORD_WEBHOOK_URL environment variable or pass webhook_url explicitly.
"""
import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": 0xE74C3C,   # red
    "high":     0xE67E22,   # orange
    "medium":   0xF1C40F,   # yellow
    "low":      0x3498DB,   # blue
    "info":     0x95A5A6,   # grey
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}


class DiscordNotifier:
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL", "")
        self.enabled = bool(self.webhook_url)
        if not self.enabled:
            log.debug("DISCORD_WEBHOOK_URL not set — Discord notifications disabled")

    @classmethod
    def from_env(cls) -> "DiscordNotifier":
        return cls()

    def _post(self, payload: dict) -> bool:
        if not self.enabled:
            return False
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                ok = 200 <= resp.status < 300
                if not ok:
                    log.warning("Discord returned %s", resp.status)
                return ok
        except urllib.error.HTTPError as e:
            log.warning("Discord HTTP error: %s %s", e.code, e.reason)
            return False
        except Exception as e:
            log.warning("Discord send failed: %s", e)
            return False

    def send_confirmed_finding(self, finding: dict) -> bool:
        """Rich embed for a confirmed, verified vulnerability."""
        sev = finding.get("severity", "info").lower()
        color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        cvss = finding.get("cvss_score", 0)

        fields = [
            {"name": "🎯 Target", "value": f"`{finding.get('target', 'unknown')}`", "inline": True},
            {"name": "🏷️ Class",  "value": finding.get("vuln_class", "Unknown"), "inline": True},
            {"name": "📊 CVSS",   "value": f"{cvss} ({finding.get('cvss_vector', 'N/A')})", "inline": False},
            {"name": "💥 Impact", "value": finding.get("impact", "Not specified")[:500], "inline": False},
        ]
        if finding.get("report_path"):
            fields.append({"name": "📄 Report", "value": finding["report_path"], "inline": False})

        embed = {
            "title": f"{emoji} CONFIRMED FINDING: {finding.get('title', 'Untitled')}",
            "description": finding.get("summary", "")[:2000],
            "color": color,
            "fields": fields,
            "footer": {"text": f"Bug Bounty Agent • {_now()}"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        payload = {
            "username": "BugBounty Agent",
            "avatar_url": "https://cdn.discordapp.com/embed/avatars/0.png",
            "embeds": [embed],
        }
        log.info("Sending confirmed finding to Discord: %s", finding.get("title"))
        return self._post(payload)

    def send_pursue_lead(self, candidate: dict) -> bool:
        """Lightweight embed for a PURSUE_HIGH lead (not yet verified)."""
        sev = candidate.get("severity", "info").lower()
        color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
        score = candidate.get("score", 0)

        embed = {
            "title": f"🔎 PURSUE LEAD [{score}/5]: {candidate.get('vuln_class', 'Unknown')}",
            "description": (
                f"**Target:** `{candidate.get('url', candidate.get('target', 'unknown'))}`\n"
                f"**Evidence:** {candidate.get('evidence', 'N/A')[:400]}\n"
                f"**Chain potential:** {candidate.get('chain_potential', 'None identified')}"
            )[:2000],
            "color": color,
            "fields": [
                {"name": "Next Steps", "value": "\n".join(f"• {s}" for s in candidate.get("next_steps", ["Manual verification needed"]))[:500], "inline": False},
            ],
            "footer": {"text": f"Lead (unverified) • {_now()}"},
        }
        payload = {
            "username": "BugBounty Agent",
            "embeds": [embed],
        }
        return self._post(payload)

    def send_phase_complete(self, phase: int, target: str, summary: str, stats: dict) -> bool:
        """Phase completion notification with stats."""
        phase_names = {
            0: "Scope & Plan",
            1: "Asset Discovery",
            2: "Surface Mapping",
            3: "Vulnerability Discovery",
            4: "Verification & PoC",
            5: "Triage",
            6: "Reporting",
        }
        name = phase_names.get(phase, f"Phase {phase}")
        stats_text = "\n".join(f"**{k}:** {v}" for k, v in stats.items()) or "No stats"

        embed = {
            "title": f"✅ Phase {phase} Complete — {name}",
            "description": f"**Target:** `{target}`\n{summary[:500]}",
            "color": 0x2ECC71,
            "fields": [{"name": "Stats", "value": stats_text[:500], "inline": False}],
            "footer": {"text": _now()},
        }
        payload = {"username": "BugBounty Agent", "embeds": [embed]}
        return self._post(payload)

    def send_error(self, target: str, phase: int, error: str) -> bool:
        embed = {
            "title": f"❌ Error in Phase {phase} — {target}",
            "description": f"```{error[:1500]}```",
            "color": 0xE74C3C,
            "footer": {"text": _now()},
        }
        payload = {"username": "BugBounty Agent", "embeds": [embed]}
        return self._post(payload)

    def send_hunt_complete(self, target: str, findings: int, candidates: int, pursuing: int) -> bool:
        embed = {
            "title": f"🏁 Hunt Complete — {target}",
            "description": (
                f"**Confirmed findings:** {findings}\n"
                f"**Leads pursuing:** {pursuing}\n"
                f"**Total candidates:** {candidates}"
            ),
            "color": 0x9B59B6,
            "footer": {"text": _now()},
        }
        payload = {"username": "BugBounty Agent", "embeds": [embed]}
        return self._post(payload)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
