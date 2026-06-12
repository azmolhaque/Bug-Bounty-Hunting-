"""
Phase 1+2 recon pipeline runner.

Delegates to recon.sh as an async subprocess. The bash script handles the
full tool chain (subfinder, dnsx, httpx, katana, naabu). Python manages the
process lifecycle, PID tracking, and output monitoring.
"""
import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

SCRIPT = Path(__file__).parent.parent / "recon.sh"


async def run_recon(
    target: str,
    results_dir: Path,
    passive_only: bool = False,
    background: bool = False,
    rate: int = 100,
    threads: int = 25,
    timeout: int = 3600,
) -> tuple[bool, str]:
    """
    Run recon.sh for the given target.

    Returns (success: bool, summary: str).
    If background=True, launches without waiting and returns immediately.
    """
    if not SCRIPT.exists():
        log.error("recon.sh not found at %s", SCRIPT)
        return False, "recon.sh missing"

    cmd = ["bash", str(SCRIPT), target]
    if passive_only:
        cmd.append("--passive-only")

    env = {**os.environ, "RATE": str(rate), "THREADS": str(threads)}
    log.info("Starting recon: %s (background=%s)", " ".join(cmd), background)

    if background:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        pid_file = results_dir / ".recon.pid"
        pid_file.write_text(str(proc.pid))
        log.info("Recon running in background (PID %d)", proc.pid)
        return True, f"recon started in background (PID {proc.pid})"

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        log.info("Recon PID: %d", proc.pid)
        pid_file = results_dir / ".recon.pid"
        pid_file.write_text(str(proc.pid))

        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode(errors="replace")
        rc = proc.returncode or 0

        # Clean up PID file
        try:
            pid_file.unlink()
        except Exception:
            pass

        if rc != 0:
            log.warning("recon.sh exited with code %d", rc)
            return False, f"recon exited {rc}"

        # Extract summary from SUMMARY.txt
        summary_path = results_dir / "02-surface" / "SUMMARY.txt"
        if summary_path.exists():
            return True, summary_path.read_text()

        return True, _extract_summary(output)

    except asyncio.TimeoutError:
        log.warning("Recon timed out after %ds", timeout)
        return False, f"recon timeout after {timeout}s"
    except Exception as e:
        log.error("Recon failed: %s", e)
        return False, str(e)


def is_recon_running(results_dir: Path) -> Optional[int]:
    """Check if a background recon is still running. Returns PID or None."""
    pid_file = results_dir / ".recon.pid"
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
        cmdline = Path(f"/proc/{pid}/cmdline").read_text()
        if "recon.sh" in cmdline or "recon" in cmdline:
            return pid
        pid_file.unlink()
        return None
    except (ValueError, FileNotFoundError, PermissionError):
        try:
            pid_file.unlink()
        except Exception:
            pass
        return None


def load_targets(results_dir: Path, target: str, max_targets: int = 300) -> list[str]:
    """
    Load priority targets from priority.md for Phase 3.

    Applies two passes:
      1. Priority ordering: P0 (dev/staging/admin/api) → P1 (integration/webhook) → P2 (rest)
      2. Service deduplication: agent-ai.ap.ap1, ap2, ap3... → keep only 2 per service prefix
         (same microservice deployed in N regions = scan 2 representative instances)

    Caps at max_targets (default 300) to keep nuclei runtime under ~2 hours on Pi.
    """
    priority_md = results_dir / "02-surface" / "priority.md"
    live_txt    = results_dir / "02-surface" / "live.txt"

    p0: list[str] = []  # dev/staging/internal/admin/api
    p1: list[str] = []  # integration/webhook/forensics
    p2: list[str] = []  # everything else

    if priority_md.exists():
        for line in priority_md.read_text().splitlines():
            line = line.strip()
            if not line.startswith("|") or "---" in line:
                continue
            cols = [c.strip() for c in line.split("|") if c.strip()]
            if not cols:
                continue
            # First column is always the host/Target header
            host = cols[0].strip("`").strip()
            if not host or host.lower() in ("target", "#") or "." not in host:
                continue

            # Determine priority: try column 2 first, then fall back to hostname keywords
            priority = "P2"
            if len(cols) > 2:
                col2 = cols[2].upper()
                if "P0" in col2:
                    priority = "P0"
                elif "P1" in col2:
                    priority = "P1"
            # Fallback: infer from hostname regardless of table column format
            if priority == "P2":
                priority = _infer_priority(host)

            if priority == "P0":
                p0.append(host)
            elif priority == "P1":
                p1.append(host)
            else:
                p2.append(host)

    if not p0 and not p1 and not p2 and live_txt.exists():
        for line in live_txt.read_text().splitlines():
            url = line.strip()
            if url:
                host = url.replace("https://", "").replace("http://", "").split("/")[0]
                prio = _infer_priority(host)
                if prio == "P0":
                    p0.append(host)
                elif prio == "P1":
                    p1.append(host)
                else:
                    p2.append(host)

    if not p0 and not p1 and not p2:
        return [target]

    # Service deduplication: group by "service prefix" — the part before
    # numeric/region suffixes. e.g. "agent-ai.ap.ap1" and "agent-ai.ap.ap2"
    # both map to prefix "agent-ai.ap" — keep at most MAX_PER_SERVICE.
    MAX_PER_SERVICE = 2

    def dedup_by_service(hosts: list[str]) -> list[str]:
        import re
        seen_prefixes: dict[str, int] = {}
        result: list[str] = []
        for host in hosts:
            # Strip trailing numeric/region component to get service key
            # e.g. "agent-ai.ap.eu10.app.wiz.io" → key "agent-ai.ap.*.app.wiz.io"
            #      "prod-us52.forensics-package.app.wiz.io" → key "*.forensics-package.app.wiz.io"
            parts = host.split(".")
            # Remove purely numeric or short region labels (us1, eu2, ap3, ca1, etc.)
            normalized = [
                "*" if re.fullmatch(r'[a-z]{0,3}\d+[a-z]?', p) or re.fullmatch(r'prod-[a-z]{2}\d+', p)
                else p
                for p in parts
            ]
            key = ".".join(normalized)
            count = seen_prefixes.get(key, 0)
            if count < MAX_PER_SERVICE:
                seen_prefixes[key] = count + 1
                result.append(host)
        return result

    # Dedup each priority bucket then combine P0 (full) + P1 (deduped) + P2 (deduped, capped)
    p0_deduped = dedup_by_service(p0)
    p1_deduped = dedup_by_service(p1)
    p2_deduped = dedup_by_service(p2)

    # Always include all P0; fill remaining budget with P1 then P2
    combined = p0_deduped[:]
    remaining = max(0, max_targets - len(combined))
    combined += p1_deduped[:remaining]
    remaining = max(0, max_targets - len(combined))
    combined += p2_deduped[:remaining]

    # Final global dedup (preserve order)
    seen: set[str] = set()
    deduped: list[str] = []
    for t in combined:
        if t not in seen:
            seen.add(t)
            deduped.append(t)

    log.info(
        "Loaded %d targets (P0:%d P1:%d P2:%d → deduped+capped from %d raw, max=%d)",
        len(deduped), len(p0_deduped), len(p1_deduped), len(p2_deduped),
        len(p0) + len(p1) + len(p2), max_targets,
    )
    return deduped


def _infer_priority(host: str) -> str:
    """Infer target priority from hostname keywords."""
    import re
    h = host.lower()
    # Split on dots, hyphens, and underscores to isolate tokens
    parts = re.split(r'[.\-_]', h)
    joined = " ".join(parts)
    P0_KEYWORDS = r"\b(dev|test|staging|internal|admin|api|rde|grafana|jenkins|kibana|dashboard|debug|beta|qa|uat|preview|canary|mgmt|management|auth|sso|login|identity|console|portal|secrets|vault)\b"
    P1_KEYWORDS = r"\b(integration|cli|event|forensic|webhook|connect|hook|scan|result|report|ingest|outpost|sensor|relay|proxy|gateway|collect|metric|telemetry|alert|notify)\b"
    if re.search(P0_KEYWORDS, joined):
        return "P0"
    if re.search(P1_KEYWORDS, joined):
        return "P1"
    return "P2"


def _extract_summary(output: str) -> str:
    """Extract key stats from recon.sh stdout."""
    lines = [l for l in output.splitlines() if any(
        kw in l for kw in ["subdomains", "resolved", "live", "endpoints", "js files"]
    )]
    return "\n".join(lines[-10:]) if lines else "recon complete"
