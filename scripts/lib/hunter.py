"""
Phase 3 vulnerability discovery — nuclei fan-out with async concurrency.

Fixes over bash version:
- asyncio.Semaphore caps parallel nuclei (no bash background & race conditions)
- JSON output mode for reliable parsing (no text format fragility)
- Single-source candidate JSONL with atomic appends
- nuclei_to_class() with word-boundary regex (no "resource" → RCE mismatch)
- Explicit exception handling per scan — one failure doesn't stop the fan-out
"""
import asyncio
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Optional

from .qualifier import nuclei_to_class, qualify_fast, qualify_with_claude, QualifyResult
from .resources import is_overloaded
from .tools import arun, have
from .state import Candidate, _now

log = logging.getLogger(__name__)

# Nuclei config aligned with config/tools.yaml
_NUCLEI_SEVERITY  = "critical,high,medium"
_NUCLEI_TAGS      = "cve,misconfig,exposure,takeover,default-login,tech,intrusive"
_NUCLEI_EXCL_TAGS = "dos,fuzz"
_NUCLEI_RATE      = 100
_NUCLEI_THREADS   = 25
_NUCLEI_BULK      = 25
_DEAD_END_LIMIT   = 3


def _candidate_id(template: str, url: str) -> str:
    """Deterministic 7-char hex ID from template+url."""
    h = hashlib.sha256(f"{template}:{url}".encode()).hexdigest()
    return "N" + h[:6]


async def run_nuclei(
    target_url: str,
    output_path: Path,
    dry_run: bool = False,
    rate: int = _NUCLEI_RATE,
    threads: int = _NUCLEI_THREADS,
) -> tuple[int, str]:
    """
    Run nuclei against a single URL. Output written to output_path as JSONL.
    Returns (returncode, error_message).
    """
    if not have("nuclei"):
        return 127, "nuclei not found"
    if dry_run:
        log.info("[DRY-RUN] nuclei -u %s → %s", target_url, output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("")
        return 0, ""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "nuclei", "-u", target_url,
        "-s", _NUCLEI_SEVERITY,
        "-tags", _NUCLEI_TAGS,
        "-etags", _NUCLEI_EXCL_TAGS,
        "-rl", str(rate),
        "-c", str(threads),
        "-bs", str(_NUCLEI_BULK),
        "-j",                           # JSON output — reliable parsing
        "-o", str(output_path),
        "-silent",
        "-no-color",
    ]
    rc, _, err = await arun(cmd, timeout=600)
    if rc not in (0, None) and "no templates" not in err.lower():
        log.warning("nuclei returned %d for %s: %s", rc, target_url, err[:200])
    return rc or 0, err


def parse_nuclei_jsonl(path: Path) -> list[dict]:
    """Parse nuclei JSON output. Silently skips malformed lines."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    results = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append(obj)
        except json.JSONDecodeError:
            pass
    return results


def nuclei_hit_to_candidate(hit: dict) -> Optional[Candidate]:
    """Convert a single nuclei JSON hit to a Candidate dataclass."""
    try:
        template  = hit.get("template-id") or hit.get("templateID") or ""
        severity  = hit.get("info", {}).get("severity", "info").lower()
        url       = hit.get("matched-at") or hit.get("host") or ""
        target    = hit.get("host") or url

        if not template or not url:
            return None

        vuln_class = nuclei_to_class(template, severity)
        evidence   = (
            f"template:{template} severity:{severity} "
            f"url:{url} matcher:{hit.get('matcher-name', '')}"
        ).strip()

        return Candidate(
            id=_candidate_id(template, url),
            target=target,
            vuln_class=vuln_class,
            severity=severity,
            template=template,
            evidence=evidence,
            url=url,
            confidence="HIGH" if severity in ("critical", "high") else "MEDIUM",
        )
    except Exception as e:
        log.debug("Could not convert nuclei hit: %s — %s", hit, e)
        return None


def _append_candidate(candidates_path: Path, candidate: Candidate, result: QualifyResult) -> None:
    """Append a qualified candidate to candidates.jsonl (append-only evidence log)."""
    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "id": candidate.id,
        "target": candidate.target,
        "url": candidate.url,
        "vuln_class": candidate.vuln_class,
        "template": candidate.template,
        "severity": candidate.severity,
        "evidence": candidate.evidence,
        "confidence": candidate.confidence,
        "status": result.status.replace("PURSUE_HIGH", "PURSUE").replace("PURSUE_MARGINAL", "PURSUE"),
        "score": result.score,
        "rejection_reasons": result.rejection_reasons,
        "chain_potential": result.chain_potential,
        "next_steps": result.next_steps,
        "estimated_cvss": result.estimated_cvss,
        "claude_used": result.claude_used,
        "ts": _now(),
    }
    with candidates_path.open("a") as f:
        f.write(json.dumps(record) + "\n")


async def phase3_hunt(
    targets: list[str],
    results_dir: Path,
    state,
    scope_check,
    claude_client=None,
    dry_run: bool = False,
    max_parallel: int = 3,
    rate: int = _NUCLEI_RATE,
    threads: int = _NUCLEI_THREADS,
) -> dict:
    """
    Fan-out nuclei across all targets, qualify every hit, write candidates.jsonl.

    Returns stats dict: {total, pursuing, auto_closed, dead_ends}.
    """
    if not targets:
        return {"total": 0, "pursuing": 0, "auto_closed": 0, "dead_ends": 0}

    candidates_dir  = results_dir / "03-candidates"
    evidence_dir    = candidates_dir / "evidence"
    candidates_path = candidates_dir / "candidates.jsonl"
    candidates_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    sem = asyncio.Semaphore(max_parallel)
    stats = {"total": 0, "pursuing": 0, "auto_closed": 0, "dead_ends": 0}
    seen_ids: set[str] = _load_seen_ids(candidates_path)

    async def scan_target(host: str) -> None:
        # Scope gate on every host
        in_scope, reason = scope_check(host)
        if not in_scope:
            log.info("Skipping %s — %s", host, reason)
            return

        # Resource throttle
        while is_overloaded():
            log.info("Pi overloaded — waiting 30s before starting %s", host)
            await asyncio.sleep(30)

        async with sem:
            url = host if host.startswith(("http://", "https://")) else f"https://{host}"
            safe_name = re.sub(r"[^a-z0-9._-]", "_", host.lower())
            output_path = evidence_dir / f"nuclei-{safe_name}.jsonl"

            log.info("Phase 3: scanning %s", url)
            rc, err = await run_nuclei(url, output_path, dry_run=dry_run, rate=rate, threads=threads)

            hits = parse_nuclei_jsonl(output_path)
            log.info("  %s: %d nuclei hits (rc=%d)", host, len(hits), rc)

            for hit in hits:
                candidate = nuclei_hit_to_candidate(hit)
                if candidate is None:
                    continue

                # Skip duplicates (same template + URL seen before)
                if candidate.id in seen_ids:
                    log.debug("  Duplicate candidate %s — skipping", candidate.id)
                    continue
                seen_ids.add(candidate.id)
                stats["total"] += 1

                # Fast qualification
                qr = qualify_fast(
                    candidate.vuln_class,
                    candidate.severity,
                    candidate.template,
                    candidate.evidence,
                    candidate.confidence,
                )

                # Claude escalation for borderline (score == 3)
                if qr.score == 3 and claude_client:
                    log.info("  Borderline lead %s — escalating to Claude", candidate.id)
                    qr = qualify_with_claude(
                        {
                            "id": candidate.id,
                            "url": candidate.url,
                            "target": candidate.target,
                            "vuln_class": candidate.vuln_class,
                            "template": candidate.template,
                            "severity": candidate.severity,
                            "evidence": candidate.evidence,
                            "confidence": candidate.confidence,
                        },
                        claude_client,
                    )

                _append_candidate(candidates_path, candidate, qr)

                final_status = qr.status.replace("PURSUE_HIGH", "PURSUE").replace("PURSUE_MARGINAL", "PURSUE")
                if final_status == "PURSUE":
                    stats["pursuing"] += 1
                    log.info(
                        "  [PURSUE %d/5] %s — %s on %s",
                        qr.score, candidate.vuln_class, candidate.template, candidate.url,
                    )
                    state.update_candidate(candidate.id, status="PURSUE", score=qr.score)
                else:
                    stats["auto_closed"] += 1
                    log.debug("  [CLOSE] %s — %s", candidate.vuln_class, qr.rejection_reasons)

    tasks = [scan_target(host) for host in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            log.warning("Scan task raised exception: %s", r)

    log.info(
        "Phase 3 complete — total=%d pursuing=%d auto_closed=%d",
        stats["total"], stats["pursuing"], stats["auto_closed"],
    )
    return stats


def _load_seen_ids(candidates_path: Path) -> set[str]:
    """Load IDs of already-processed candidates to avoid duplicates on resume."""
    if not candidates_path.exists():
        return set()
    ids: set[str] = set()
    for line in candidates_path.read_text().splitlines():
        try:
            ids.add(json.loads(line)["id"])
        except (json.JSONDecodeError, KeyError):
            pass
    return ids


def load_candidates(candidates_path: Path, status: Optional[str] = None) -> list[dict]:
    """Load candidates from JSONL. Optionally filter by status."""
    if not candidates_path.exists():
        return []
    results = []
    for line in candidates_path.read_text().splitlines():
        try:
            c = json.loads(line)
            if status is None or c.get("status") == status:
                results.append(c)
        except json.JSONDecodeError:
            pass
    return results


def candidate_stats(candidates_path: Path) -> dict[str, int]:
    """Return counts by status without loading all data into memory."""
    counts: dict[str, int] = {}
    if not candidates_path.exists():
        return counts
    for line in candidates_path.read_text().splitlines():
        try:
            status = json.loads(line).get("status", "UNKNOWN")
            counts[status] = counts.get(status, 0) + 1
        except json.JSONDecodeError:
            pass
    return counts
