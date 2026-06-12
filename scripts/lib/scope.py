"""
Scope gate — reads config/scope.yaml and validates targets.

Wraps the existing scope-check.sh for string-match logic but also
provides a Python-native check for use inside the orchestrator.
"""
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


ROOT = Path(__file__).parent.parent.parent


def _load_scope_yaml() -> dict:
    scope_file = ROOT / "config" / "scope.yaml"
    if not scope_file.exists():
        return {}
    if not _HAS_YAML:
        return {}
    try:
        return yaml.safe_load(scope_file.read_text()) or {}
    except Exception:
        return {}


def check(target: str) -> tuple[bool, str]:
    """
    Returns (in_scope: bool, reason: str).

    Delegates to scope-check.sh for the authoritative check, falls back
    to Python YAML parse if the shell script is unavailable.
    """
    script = ROOT / "scripts" / "scope-check.sh"
    if script.exists():
        try:
            result = subprocess.run(
                ["bash", str(script), target],
                capture_output=True,
                text=True,
                timeout=10,
            )
            out = (result.stdout + result.stderr).strip()
            if out.startswith("IN-SCOPE"):
                return True, out
            return False, out or "OUT-OF-SCOPE"
        except Exception as e:
            pass

    # Python fallback: parse scope.yaml directly
    return _python_scope_check(target)


def _python_scope_check(target: str) -> tuple[bool, str]:
    scope = _load_scope_yaml()
    if not scope:
        return False, "scope.yaml missing or unreadable — cannot determine scope"

    programs = scope.get("programs", [])
    if not programs:
        return False, "No programs defined in scope.yaml"

    for prog in programs:
        in_scope = prog.get("in_scope", [])
        out_scope = prog.get("out_of_scope", [])

        # Check out-of-scope first
        for pattern in out_scope:
            if _matches(target, str(pattern)):
                return False, f"OUT-OF-SCOPE: matches out_of_scope pattern '{pattern}'"

        # Check in-scope
        for pattern in in_scope:
            if _matches(target, str(pattern)):
                return True, f"IN-SCOPE: matches '{pattern}' in program '{prog.get('name', 'unknown')}'"

    return False, f"OUT-OF-SCOPE: '{target}' not matched in any program"


def _matches(host: str, pattern: str) -> bool:
    """Glob-style pattern matching: *.example.com matches sub.example.com."""
    if pattern.startswith("*."):
        domain = pattern[2:]
        return host == domain or host.endswith("." + domain)
    return host == pattern or host.endswith("." + pattern.lstrip("*"))


def assert_in_scope(target: str) -> None:
    """Abort the process if target is not in scope."""
    ok, reason = check(target)
    if not ok:
        print(f"\n[SCOPE VIOLATION] {reason}", file=sys.stderr)
        print("Refusing to proceed. Populate config/scope.yaml correctly.", file=sys.stderr)
        sys.exit(2)


def get_program_name(target: str) -> Optional[str]:
    """Return the program name that covers this target, or None."""
    scope = _load_scope_yaml()
    for prog in scope.get("programs", []):
        for pattern in prog.get("in_scope", []):
            if _matches(target, str(pattern)):
                return prog.get("name")
    return None
