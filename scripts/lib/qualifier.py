"""
Lead qualification gate — Phase 3 core intelligence.

Fast Python-native 5-gate scoring for every nuclei hit.
Claude API is called ONLY for borderline (score == 3) candidates.

Key fix over bash version: nuclei_to_class() uses compiled regex with
word boundaries — never misclassifies "cross-origin-resource-policy" as RCE.
"""
import re
import logging
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

# ── Nuclei template → vulnerability class ─────────────────────────────────
# Order matters: specificity high → low, hard classes before substrings.
_CLASS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\bsubdomain[_-]?takeover\b|\btakeover\b'), "subdomain-takeover"),
    (re.compile(r'\bssrf\b'), "SSRF-blind"),
    (re.compile(r'\bidor\b|\bbola\b|\bbroken[_-]?access\b'), "IDOR"),
    (re.compile(r'\bsqli?\b|\bsql[_-]?injection\b'), "SQLi"),
    (re.compile(r'\bssti\b'), "SSTI"),
    (re.compile(r'\bstored[_-]?xss\b'), "XSS-stored"),
    (re.compile(r'\bxss\b'), "XSS-reflected"),
    # Missing-header patterns BEFORE any *rce* to prevent "resource" → RCE substring match
    (re.compile(r'\bmissing[_-]?(?:security[_-]?)?header\b|\bhttp[_-]?missing\b'), "missing-header"),
    (re.compile(r'\b(?:hsts|x[_-]frame|x[_-]content[_-]type|csp[_-]|cross[_-]origin|permissions[_-]policy|referrer[_-]policy)\b'), "missing-header"),
    (re.compile(r'\bclickjack\b|\bframe[_-]inject\b'), "clickjacking"),
    # RCE: strict word boundary — never matches "resource", "procedure", "process"
    (re.compile(r'\brce\b|\bcommand[_-]?injection\b|\bcode[_-]?execution\b|\bcode[_-]?inject\b|\bremote[_-]?exec\b'), "RCE"),
    (re.compile(r'\bdefault[_-]?(?:login|creds?|passwords?)\b'), "default-creds"),
    (re.compile(r'\bexposure\b|\bexposed[_-]?cred\b|\bapi[_-]?key\b|\bcredential[_-]?exposure\b'), "credential-exposure"),
    (re.compile(r'\bcors\b'), "CORS-sensitive-data"),
    (re.compile(r'\bopen[_-]?redirect\b'), "open-redirect"),
    (re.compile(r'\bpath[_-]?traversal\b|\blfi\b|\bdirectory[_-]?traversal\b'), "path-traversal"),
    (re.compile(r'\bjwt\b'), "JWT-attack"),
    (re.compile(r'\boauth\b'), "oauth-hijack"),
    (re.compile(r'\bgraphql\b'), "IDOR"),
    (re.compile(r'\bxxe\b'), "XXE"),
    (re.compile(r'\bsql\b'), "SQLi"),
    (re.compile(r'\bfileupload\b|\bfile[_-]?upload\b'), "file-upload"),
    (re.compile(r'\bdeseri\b|\bdeserializ\b'), "deserialization"),
    (re.compile(r'\bversion\b|\btech[_-]?detect\b|\bfingerprint\b'), "version-disclosure"),
]

# Hard rejection patterns — AUTO_CLOSE immediately, no Claude needed
_HARD_REJECT_CLASSES = frozenset({
    "missing-header", "clickjacking", "version-disclosure",
    "CORS-sensitive-data",  # unless impact confirmed — re-scored after context
})
_HARD_REJECT_TEMPLATES = [
    re.compile(p) for p in [
        r'\bmissing[_-]?(?:security[_-]?)?headers?\b',
        r'\bhsts\b', r'\bx[_-]frame\b', r'\breferrer[_-]policy\b',
        r'\bx[_-]content[_-]type\b', r'\bpermissions[_-]policy\b',
        r'\bssl[_-]dns[_-]names?\b', r'\bself[_-]signed\b',
        r'\btech[_-]detect\b', r'\bfingerprint\b', r'\bserver[_-]version\b',
        r'\brobots\b', r'\bsitemap\b', r'\bwordpress[_-]user[_-]enum\b',
        r'\brate[_-]limit\b', r'\bcaptcha\b', r'\bpassword[_-]policy\b',
        r'\bspf\b', r'\bdmarc\b', r'\bdkim\b',
        r'\bssl[_-]certificate\b', r'\btls[_-]version\b',
        r'\bopen[_-]redirect\b',  # standalone open-redirect is usually low value
    ]
]

# Classes that almost always PURSUE (score 4+ heuristically)
_HIGH_VALUE_CLASSES = frozenset({
    "SSRF-blind", "IDOR", "SQLi", "RCE", "SSTI",
    "XSS-stored", "JWT-attack", "oauth-hijack", "default-creds",
    "credential-exposure", "subdomain-takeover", "deserialization",
    "XXE", "path-traversal",
})


@dataclass
class QualifyResult:
    status: str              # PURSUE_HIGH | PURSUE_MARGINAL | AUTO_CLOSE
    score: int               # 0-5
    q1: bool = False         # concrete attacker gain
    q2: bool = False         # not intended behavior
    q3: bool = False         # vendor would fix
    q4: bool = False         # CVSS >= 4.0
    q5: bool = False         # not hard-rejected
    rejection_reasons: list[str] = field(default_factory=list)
    chain_potential: str = ""
    next_steps: list[str] = field(default_factory=list)
    estimated_cvss: str = ""
    claude_used: bool = False


def nuclei_to_class(template: str, severity: str) -> str:
    """
    Map a nuclei template ID to a vulnerability class using regex.

    Word-boundary safe — will never match "resource" as "rce",
    "process" as "rce", or "cross-origin-resource-policy" as "RCE".
    """
    t = template.lower().replace("/", "-")
    for pattern, cls in _CLASS_PATTERNS:
        if pattern.search(t):
            return cls
    if severity in ("critical", "high", "medium"):
        return template   # preserve template ID for medium+ unknowns — aids triage
    return f"unknown-{severity}"


def _is_hard_rejected(template: str, vuln_class: str) -> tuple[bool, str]:
    """Check if a template/class falls in the Hard Rejection List."""
    t = template.lower()
    for pat in _HARD_REJECT_TEMPLATES:
        if pat.search(t):
            return True, f"Hard rejection: template matches '{pat.pattern}'"
    if vuln_class in _HARD_REJECT_CLASSES:
        return True, f"Hard rejection: class '{vuln_class}' is universally low-value"
    return False, ""


def qualify_fast(
    vuln_class: str,
    severity: str,
    template: str,
    evidence: str = "",
    confidence: str = "MEDIUM",
) -> QualifyResult:
    """
    Pure Python 5-gate qualification. No I/O, no API calls. < 1ms.

    Returns a QualifyResult. Borderline score=3 cases should be sent to Claude.
    """
    q1 = q2 = q3 = q4 = q5 = False
    reasons: list[str] = []
    chain_potential = ""
    next_steps: list[str] = []
    estimated_cvss = ""

    # Q5 first — hard rejection short-circuits everything
    rejected, reject_reason = _is_hard_rejected(template, vuln_class)
    if rejected:
        reasons.append(reject_reason)
        return QualifyResult(
            status="AUTO_CLOSE", score=0,
            q1=False, q2=True, q3=False, q4=False, q5=False,
            rejection_reasons=reasons,
        )
    q5 = True

    # Q4 — severity proxy for CVSS >= 4.0
    sev = severity.lower()
    if sev in ("critical", "high"):
        q4 = True
        estimated_cvss = (
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if sev == "critical"
            else "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
        )
    elif sev == "medium":
        q4 = True
        estimated_cvss = "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
    else:
        reasons.append(f"Severity '{sev}' unlikely to reach CVSS 4.0 without chain")

    # Q1 — concrete attacker gain from class
    if vuln_class in _HIGH_VALUE_CLASSES:
        q1 = True
    else:
        reasons.append(f"Class '{vuln_class}' has no obvious concrete attacker gain")
        chain_potential = f"Investigate if '{vuln_class}' can be chained to data access or auth bypass"

    # Q2 — not intended behavior (heuristic: high-value classes are never intended)
    q2 = vuln_class in _HIGH_VALUE_CLASSES or sev in ("critical", "high")
    if not q2:
        reasons.append("Behavior may be intended for this class at this severity")

    # Q3 — vendor would fix (heuristic: same as Q1 for structured classes)
    q3 = q1
    if not q3:
        reasons.append("Vendor may not fix without demonstrated exploit path")

    score = sum([q1, q2, q3, q4, q5])

    if score >= 4:
        status = "PURSUE_HIGH"
        next_steps = [
            f"Reproduce {vuln_class} manually from clean session",
            "Minimize PoC to smallest request demonstrating impact",
            "Attempt chain elevation if severity < High",
        ]
    elif score == 3:
        status = "PURSUE_MARGINAL"  # Send to Claude for deeper analysis
        next_steps = ["Claude analysis recommended for borderline decision"]
    else:
        status = "AUTO_CLOSE"

    return QualifyResult(
        status=status, score=score,
        q1=q1, q2=q2, q3=q3, q4=q4, q5=q5,
        rejection_reasons=reasons,
        chain_potential=chain_potential,
        next_steps=next_steps,
        estimated_cvss=estimated_cvss,
    )


def qualify_manual(
    vuln_class: str,
    severity: str,
    evidence: str,
    impact: str,
    confidence: str = "HIGH",
    chain_potential: str = "",
    next_steps: Optional[list[str]] = None,
    estimated_cvss: str = "",
) -> QualifyResult:
    """
    Qualify a manually discovered finding (not from nuclei).

    Use this when Phase 4 manual investigation produces a candidate —
    e.g. subdomain takeover, self-registration access, IDOR found by hand.

    Manual findings start at higher confidence than nuclei hits because a
    human researcher already exercised judgment before calling this.
    """
    qr = qualify_fast(
        vuln_class=vuln_class,
        severity=severity,
        template=vuln_class,   # use class as template ID for manual findings
        evidence=f"MANUAL: {evidence} | impact: {impact}",
        confidence=confidence,
    )

    # Manual findings with HIGH confidence and concrete impact override borderline scores
    if confidence.upper() in ("HIGH", "CONFIRMED", "CRITICAL"):
        if impact and any(kw in impact.lower() for kw in [
            "account", "session", "token", "data", "bypass", "rce", "takeover",
            "exfil", "credential", "injection", "internal", "cross-tenant",
        ]):
            if qr.score == 3:
                qr.score = 4
                qr.status = "PURSUE_HIGH"
                if "Manual evidence upgraded" not in qr.rejection_reasons:
                    qr.rejection_reasons.append("Manual evidence upgraded borderline to PURSUE_HIGH")

    # Special override: CORS on an endpoint that returns user-specific/auth data
    # is NOT a generic CORS report — it's a data exfil path (High).
    # The hard-rejection for CORS-sensitive-data applies only to empty/non-sensitive responses.
    if qr.status == "AUTO_CLOSE" and vuln_class == "CORS-sensitive-data":
        sensitive_impact_kws = ["user", "account", "token", "auth", "session", "api key", "credential", "profile", "email"]
        if impact and any(kw in impact.lower() for kw in sensitive_impact_kws):
            qr.status = "PURSUE_HIGH"
            qr.score = 4
            qr.q1 = True  # attacker can exfiltrate user data cross-origin
            qr.q2 = True
            qr.q3 = True
            qr.q4 = True
            qr.q5 = True
            qr.rejection_reasons = ["CORS override: endpoint returns sensitive user data — not a generic CORS finding"]
            qr.next_steps = [
                "Confirm CORS header: Access-Control-Allow-Origin: <attacker origin>",
                "Confirm credentials mode: Access-Control-Allow-Credentials: true",
                "Write PoC JS that reads /api/me cross-origin and exfiltrates email/token",
                "Report as: CORS misconfiguration enables cross-origin theft of authenticated user data",
            ]
            qr.estimated_cvss = "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N"

    if chain_potential:
        qr.chain_potential = chain_potential
    if next_steps:
        qr.next_steps = next_steps or qr.next_steps
    if estimated_cvss:
        qr.estimated_cvss = estimated_cvss

    return qr


def qualify_self_registration(host: str, path: str) -> QualifyResult:
    """
    Qualify a confirmed self-registration endpoint.

    Self-registration on an enterprise security product = immediate PURSUE_HIGH:
    - Unauthorized access to enterprise platform (Q1: account access)
    - Not intended for public (Q2: should require invite/approval)
    - Vendor would fix (Q3: add invitation gate or domain restriction)
    - CVSS 7.5+ (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N) (Q4)
    - Not hard-rejected (Q5)
    """
    return QualifyResult(
        status="PURSUE_HIGH",
        score=5,
        q1=True, q2=True, q3=True, q4=True, q5=True,
        rejection_reasons=[],
        chain_potential=(
            f"After self-registration at {host}{path}: "
            f"enumerate /api/* for IDOR (access other tenants/users), "
            f"test privilege escalation, look for data leakage across org boundaries."
        ),
        next_steps=[
            f"Register at https://{host}{path} with a test email",
            "After login: capture session cookie",
            "Run: SESSION_COOKIE=<value> bash scripts/mandiant-followup-probe.sh",
            "Enumerate /api/users, /api/orgs, /api/admin — test for IDOR",
            "Document what data is visible immediately after registration",
        ],
        estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",  # 7.5 — unauthorized access
    )


def qualify_with_claude(candidate: dict, claude_client) -> QualifyResult:
    """
    Enhance qualification with Claude API for borderline (score==3) cases.
    Falls back to fast qualification if Claude is unavailable.
    """
    if not claude_client or not claude_client.enabled:
        return qualify_fast(
            candidate.get("vuln_class", ""),
            candidate.get("severity", "info"),
            candidate.get("template", ""),
        )

    result = claude_client.qualify_lead(
        candidate,
        target_context=f"Target: {candidate.get('target', '')}",
    )

    status_map = {
        "PURSUE_HIGH": "PURSUE_HIGH",
        "PURSUE_MARGINAL": "PURSUE_MARGINAL",
        "AUTO_CLOSE": "AUTO_CLOSE",
    }
    status = status_map.get(result.get("status", "AUTO_CLOSE"), "AUTO_CLOSE")
    score = min(5, max(0, int(result.get("score", 0))))

    return QualifyResult(
        status=status,
        score=score,
        q1=result.get("q1_concrete_attacker_gain", False),
        q2=result.get("q2_not_intended_behavior", False),
        q3=result.get("q3_vendor_would_fix", False),
        q4=result.get("q4_cvss_above_4", False),
        q5=result.get("q5_not_hard_rejected", False),
        rejection_reasons=result.get("rejection_reasons", []),
        chain_potential=result.get("chain_potential", ""),
        next_steps=result.get("next_steps", []),
        estimated_cvss=result.get("estimated_cvss", ""),
        claude_used=True,
    )
