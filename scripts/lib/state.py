"""
Persistent hunt state — JSON-backed, atomic writes.

State survives reboots, context resets, and partial runs.
Always write via State.save() which does an atomic rename.
"""
import json
import os
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class PhaseRecord:
    phase: int
    status: str          # DONE | RUNNING | FAILED | SKIPPED
    started: str = ""
    finished: str = ""
    summary: str = ""
    stats: dict = field(default_factory=dict)


@dataclass
class Candidate:
    id: str
    target: str
    vuln_class: str
    severity: str
    template: str
    evidence: str
    url: str
    confidence: str = "LOW"
    status: str = "UNQUALIFIED"   # PURSUE | AUTO_CLOSE | DEAD_END
    score: int = 0
    chain_potential: str = ""
    next_steps: list[str] = field(default_factory=list)
    rejection_reasons: list[str] = field(default_factory=list)
    ts: str = field(default_factory=_now)


@dataclass
class Finding:
    id: str
    candidate_id: str
    target: str
    vuln_class: str
    severity: str
    title: str
    summary: str
    cvss_vector: str
    cvss_score: float
    repro_steps: list[str] = field(default_factory=list)
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    report_path: str = ""
    discord_sent: bool = False
    ts: str = field(default_factory=_now)


@dataclass
class HuntState:
    target: str
    started: str = field(default_factory=_now)
    updated: str = field(default_factory=_now)
    current_phase: int = 0
    phases: dict[int, dict] = field(default_factory=dict)
    candidates: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    intelligence_notes: list[str] = field(default_factory=list)

    # Convenience counters (derived, not authoritative)
    @property
    def pursuing(self) -> int:
        return sum(1 for c in self.candidates if c.get("status") == "PURSUE")

    @property
    def auto_closed(self) -> int:
        return sum(1 for c in self.candidates if c.get("status") == "AUTO_CLOSE")

    @property
    def confirmed(self) -> int:
        return len(self.findings)

    def phase_done(self, phase: int) -> bool:
        return self.phases.get(phase, {}).get("status") == "DONE"

    def mark_phase_start(self, phase: int) -> None:
        self.phases[phase] = {"phase": phase, "status": "RUNNING", "started": _now()}
        self.current_phase = phase
        self.updated = _now()

    def mark_phase_done(self, phase: int, summary: str = "", stats: dict | None = None) -> None:
        rec = self.phases.get(phase, {"phase": phase, "started": _now()})
        rec.update({"status": "DONE", "finished": _now(), "summary": summary, "stats": stats or {}})
        self.phases[phase] = rec
        self.updated = _now()

    def add_candidate(self, c: Candidate) -> None:
        self.candidates.append(asdict(c))
        self.updated = _now()

    def update_candidate(self, cid: str, **kwargs: Any) -> None:
        for c in self.candidates:
            if c["id"] == cid:
                c.update(kwargs)
                c["ts"] = _now()
                break
        self.updated = _now()

    def add_finding(self, f: Finding) -> None:
        self.findings.append(asdict(f))
        self.updated = _now()

    def add_intelligence_note(self, note: str) -> None:
        self.intelligence_notes.append(f"[{_now()}] {note}")
        self.updated = _now()


def load_or_init(path: Path, target: str) -> HuntState:
    if path.exists():
        try:
            data = json.loads(path.read_text())
            state = HuntState(**{k: v for k, v in data.items() if k in HuntState.__dataclass_fields__})
            return state
        except Exception:
            pass
    return HuntState(target=target)


def save(state: HuntState, path: Path) -> None:
    """Atomic write: temp file → rename (no partial-write corruption)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    state.updated = _now()
    data = {
        "target": state.target,
        "started": state.started,
        "updated": state.updated,
        "current_phase": state.current_phase,
        "phases": state.phases,
        "candidates": state.candidates,
        "findings": state.findings,
        "stats": state.stats,
        "intelligence_notes": state.intelligence_notes,
    }
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".state-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise
