"""
External tool runner: subprocess wrappers for Go security tools.

All tools are invoked via subprocess.run / asyncio.create_subprocess_exec.
Never use shell=True — prevents injection if target names contain special chars.
"""
import asyncio
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# Tools expected on the Pi — all arm64 Go binaries in ~/go/bin or ~/.local/bin
REQUIRED_TOOLS = ["nuclei", "httpx", "dnsx", "subfinder"]
OPTIONAL_TOOLS = [
    "assetfinder", "amass", "gau", "waybackurls", "katana",
    "naabu", "anew", "ffuf", "dalfox", "puredns",
]


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def check_tools() -> dict[str, bool]:
    result = {}
    for t in REQUIRED_TOOLS + OPTIONAL_TOOLS:
        result[t] = have(t)
    return result


def run(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout: int = 300,
    capture: bool = True,
) -> subprocess.CompletedProcess:
    """Run a command, log it, return CompletedProcess. Never raises on non-zero exit."""
    log.debug("run: %s", " ".join(cmd))
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.warning("Timeout (%ds) running: %s", timeout, cmd[0])
        return subprocess.CompletedProcess(cmd, returncode=124, stdout="", stderr="timeout")
    except FileNotFoundError:
        log.warning("Tool not found: %s", cmd[0])
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr="not found")
    except Exception as exc:
        log.warning("Tool error %s: %s", cmd[0], exc)
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr=str(exc))


async def arun(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout: int = 300,
) -> tuple[int, str, str]:
    """Async version of run(). Returns (returncode, stdout, stderr)."""
    log.debug("arun: %s", " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, stdout.decode(), stderr.decode()
    except asyncio.TimeoutError:
        log.warning("Async timeout (%ds): %s", timeout, cmd[0])
        return 124, "", "timeout"
    except FileNotFoundError:
        log.warning("Async tool not found: %s", cmd[0])
        return 127, "", "not found"
    except Exception as exc:
        log.warning("Async tool error %s: %s", cmd[0], exc)
        return 1, "", str(exc)


def count_lines(path: Path) -> int:
    """Count non-empty lines in a file. Returns 0 if file missing."""
    try:
        return sum(1 for line in path.read_text().splitlines() if line.strip())
    except Exception:
        return 0


def append_unique(path: Path, lines: list[str]) -> int:
    """Append lines not already in file. Returns count added."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: set[str] = set()
    if path.exists():
        existing = {l.strip() for l in path.read_text().splitlines() if l.strip()}
    new_lines = [l for l in lines if l.strip() and l.strip() not in existing]
    if new_lines:
        with path.open("a") as f:
            f.write("\n".join(new_lines) + "\n")
    return len(new_lines)
