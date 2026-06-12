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


def load_targets(results_dir: Path, target: str) -> list[str]:
    """
    Load priority targets from priority.md for Phase 3.

    Parses the markdown table robustly — no brittle regex.
    Returns list of hostnames (without scheme) in priority order.
    """
    priority_md = results_dir / "02-surface" / "priority.md"
    live_txt    = results_dir / "02-surface" / "live.txt"

    targets: list[str] = []

    if priority_md.exists():
        for line in priority_md.read_text().splitlines():
            line = line.strip()
            if not line.startswith("|") or "Target" in line or "---" in line:
                continue
            cols = [c.strip() for c in line.split("|") if c.strip()]
            if cols:
                host = cols[0].strip("`").strip()
                if "." in host and not host.startswith("#"):
                    targets.append(host)

    if not targets and live_txt.exists():
        for line in live_txt.read_text().splitlines():
            url = line.strip()
            if url:
                host = url.replace("https://", "").replace("http://", "").split("/")[0]
                targets.append(host)

    if not targets:
        targets = [target]

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)

    log.info("Loaded %d targets for Phase 3", len(deduped))
    return deduped


def _extract_summary(output: str) -> str:
    """Extract key stats from recon.sh stdout."""
    lines = [l for l in output.splitlines() if any(
        kw in l for kw in ["subdomains", "resolved", "live", "endpoints", "js files"]
    )]
    return "\n".join(lines[-10:]) if lines else "recon complete"
