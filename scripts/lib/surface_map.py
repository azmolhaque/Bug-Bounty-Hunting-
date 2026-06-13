"""
Phase 2.5 — Structured Surface Mapper

Runs after recon (Phase 1+2) and before nuclei (Phase 3).
Goal: 30-second structured fingerprint of each live target that answers:

  1. Is the target reachable, or WAF-blocked from this IP?
  2. Does the target have self-registration? (sign_up / register)
  3. Does the target have exposed admin panels? (Sidekiq, Grafana, etc.)
  4. What auth platform is in use? (Auth0 / Cognito / PingFederate / Okta / SAML)
  5. Are there unauthenticated API endpoints returning data?

Outputs:
  results/<target>/02-surface/surface_map.jsonl  — one record per host
  results/<target>/02-surface/priority.md        — updated with surface flags

These records feed Phase 3 (nuclei target selection) and the manual queue.
"""
import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from .tools import arun

log = logging.getLogger(__name__)

# ── Auth platform signatures ─────────────────────────────────────────────────
_AUTH_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("auth0",         re.compile(r'auth0\.com|\.auth0\.', re.I)),
    ("cognito",       re.compile(r'cognito|amazoncognito|auth\.app\.wiz\.io', re.I)),
    ("pingfederate",  re.compile(r'pingfederate|pingidentity|/pf/', re.I)),
    ("okta",          re.compile(r'okta\.com|\.okta\.', re.I)),
    ("azure_ad",      re.compile(r'microsoftonline\.com|login\.microsoft\.com', re.I)),
    ("google_oauth",  re.compile(r'accounts\.google\.com/o/oauth', re.I)),
    ("saml",          re.compile(r'saml|ShibbolethDS|Shibboleth', re.I)),
    ("nextauth",      re.compile(r'/api/auth/providers|NextAuth', re.I)),
]

# ── Admin panel URL patterns ─────────────────────────────────────────────────
_ADMIN_PANELS: list[tuple[str, list[str]]] = [
    ("sidekiq",    ["/sidekiq", "/sidekiq/web", "/sidekiq/queues"]),
    ("grafana",    ["/grafana", "/grafana/login"]),
    ("kibana",     ["/kibana", "/kibana/app/discover"]),
    ("jenkins",    ["/jenkins", "/jenkins/login"]),
    ("spring",     ["/actuator", "/actuator/env", "/actuator/health"]),
    ("rails",      ["/rails/info/properties", "/admin/sidekiq"]),
    ("django",     ["/admin/", "/django-admin/"]),
    ("phpmyadmin", ["/phpmyadmin/", "/pma/"]),
    ("swagger",    ["/swagger-ui.html", "/swagger", "/api-docs", "/openapi.json"]),
    ("graphql",    ["/graphql", "/api/graphql"]),
    ("redis",      ["/redis", "/redis-commander/"]),
    ("metabase",   ["/metabase/", "/api/session"]),
]

# ── Self-registration URL patterns ───────────────────────────────────────────
_REGISTRATION_PATHS = [
    "/users/sign_up",
    "/register",
    "/signup",
    "/sign-up",
    "/create-account",
    "/api/register",
    "/api/v1/register",
    "/api/users/register",
    "/api/signup",
    "/accounts/register",
    "/auth/register",
    "/auth/signup",
]

# ── WAF fingerprints ─────────────────────────────────────────────────────────
_WAF_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("cloudfront",  re.compile(r'X-Cache.*?Error|cloudfront|AmazonS3', re.I)),
    ("cloudflare",  re.compile(r'cloudflare|CF-RAY|__cfduid', re.I)),
    ("akamai",      re.compile(r'AkamaiGHost|akamai', re.I)),
    ("fastly",      re.compile(r'fastly|X-Served-By.*fastly', re.I)),
    ("sucuri",      re.compile(r'sucuri|X-Sucuri', re.I)),
]


@dataclass
class SurfaceRecord:
    host: str
    url: str
    ts: str = ""
    reachable: bool = False
    http_code: int = 0
    waf: str = ""                         # "cloudfront" | "cloudflare" | "" (none detected)
    waf_blocked: bool = False             # 403/429 with WAF header
    server: str = ""
    tech: list[str] = field(default_factory=list)
    auth_platform: str = ""              # "auth0" | "cognito" | "pingfederate" | ...
    self_registration: bool = False      # /sign_up or /register returns 200
    self_registration_path: str = ""
    admin_panels: list[dict] = field(default_factory=list)   # [{name, path, code}]
    open_api_endpoints: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)           # P0 priority flags
    manual_actions: list[dict] = field(default_factory=list) # browser-required steps


# ── Core probe ───────────────────────────────────────────────────────────────

async def _fetch(
    url: str,
    method: str = "GET",
    timeout: int = 8,
    headers: Optional[list[str]] = None,
    max_redirs: int = 5,
) -> tuple[int, dict[str, str], str]:
    """
    Async HTTP fetch via curl. Returns (status_code, headers_dict, body_snippet).
    Returns (0, {}, "") on connection failure.
    """
    cmd = [
        "curl", "-sk",
        "-w", "\n__STATUS_CODE__:%{http_code}",
        "--max-time", str(timeout),
        "--max-redirs", str(max_redirs),
        "-X", method,
        "-H", "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "-H", "Accept: application/json, text/html, */*",
        "-D", "-",   # dump headers to stdout
    ]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    cmd.append(url)

    rc, stdout, _ = await arun(cmd, timeout=timeout + 2)
    if rc == 127 or not stdout:
        return 0, {}, ""

    # Split headers from body
    parts = stdout.split("\r\n\r\n", 1)
    header_text = parts[0] if parts else ""
    body = (parts[1] if len(parts) > 1 else "")[:2000]

    # Extract status from curl marker
    status = 0
    if "__STATUS_CODE__:" in body:
        body, marker = body.rsplit("__STATUS_CODE__:", 1)
        try:
            status = int(marker.strip()[:3])
        except ValueError:
            pass

    # Parse headers
    headers_dict: dict[str, str] = {}
    for line in header_text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            headers_dict[k.strip().lower()] = v.strip()

    return status, headers_dict, body


async def probe_host(url: str, timeout: int = 8) -> SurfaceRecord:
    """
    Full surface probe of a single host URL.
    Runs all checks concurrently where possible.
    """
    host = re.sub(r'^https?://', '', url).split('/')[0]
    rec = SurfaceRecord(host=host, url=url, ts=_now())

    # ── Step 1: Basic reachability ────────────────────────────────────────
    code, hdrs, body = await _fetch(url, timeout=timeout)
    rec.http_code = code
    rec.reachable = code > 0

    if code == 0:
        rec.flags.append("UNREACHABLE")
        return rec

    # WAF detection from headers
    all_header_text = " ".join(f"{k}: {v}" for k, v in hdrs.items())
    for waf_name, pat in _WAF_PATTERNS:
        if pat.search(all_header_text):
            rec.waf = waf_name
            break

    # WAF block detection: 403/429 with a WAF header → don't waste nuclei
    if code in (403, 429) and rec.waf:
        rec.waf_blocked = True
        rec.flags.append(f"WAF_BLOCKED:{rec.waf}")

    rec.server = hdrs.get("server", "")

    # ── Step 2: Auth platform fingerprint ────────────────────────────────
    combined_text = all_header_text + " " + body
    for platform, pat in _AUTH_SIGNATURES:
        if pat.search(combined_text):
            rec.auth_platform = platform
            break

    # Check OIDC discovery for Auth0/Cognito/PingFederate
    if not rec.auth_platform:
        oidc_url = f"https://{host}/.well-known/openid-configuration"
        oidc_code, oidc_hdrs, oidc_body = await _fetch(oidc_url, timeout=5)
        if oidc_code == 200 and '"authorization_endpoint"' in oidc_body:
            for platform, pat in _AUTH_SIGNATURES:
                if pat.search(oidc_body):
                    rec.auth_platform = platform
                    break
            if not rec.auth_platform:
                rec.auth_platform = "oidc-unknown"
            rec.flags.append(f"OIDC_DISCOVERY:{rec.auth_platform}")
            # Check for dynamic client registration — finding if enabled
            if '"registration_endpoint"' in oidc_body and '"dynamic_client_registration_disabled"' not in oidc_body:
                rec.manual_actions.append({
                    "type": "OIDC_DYNAMIC_REGISTRATION",
                    "priority": "HIGH",
                    "url": oidc_url,
                    "instruction": (
                        f"OIDC discovery has registration_endpoint. "
                        f"Test: curl -sk -X POST {url}/.well-known/openid-configuration "
                        f"to see if dynamic client registration is enabled."
                    ),
                })

    # ── Step 3: Self-registration detection ──────────────────────────────
    reg_tasks = [
        _fetch(f"https://{host}{path}", max_redirs=3, timeout=6)
        for path in _REGISTRATION_PATHS
    ]
    reg_results = await asyncio.gather(*reg_tasks, return_exceptions=True)

    for path, result in zip(_REGISTRATION_PATHS, reg_results):
        if isinstance(result, Exception):
            continue
        r_code, _, r_body = result
        if r_code == 200:
            rec.self_registration = True
            rec.self_registration_path = path
            rec.flags.append(f"SELF_REGISTRATION:{path}")
            rec.manual_actions.append({
                "type": "SELF_REGISTRATION",
                "priority": "CRITICAL",
                "url": f"https://{host}{path}",
                "instruction": (
                    f"Self-registration is OPEN at {host}{path} (HTTP 200). "
                    f"Register with a test email, login, then enumerate authenticated surface "
                    f"for IDOR/broken-access-control/data-leakage."
                ),
            })
            break  # One confirmed path is enough

    # ── Step 4: Admin panel detection ────────────────────────────────────
    # Fan out all admin panel checks
    panel_urls: list[tuple[str, str]] = []
    for panel_name, paths in _ADMIN_PANELS:
        for path in paths[:1]:  # only check first path per panel type
            panel_urls.append((panel_name, path))

    panel_tasks = [
        _fetch(f"https://{host}{path}", max_redirs=1, timeout=5)
        for _, path in panel_urls
    ]
    panel_results = await asyncio.gather(*panel_tasks, return_exceptions=True)

    for (panel_name, path), result in zip(panel_urls, panel_results):
        if isinstance(result, Exception):
            continue
        p_code, _, p_body = result
        if p_code in (200, 302, 401):  # 302 = auth-redirect (confirmed exists), 401 = auth required
            entry = {"name": panel_name, "path": path, "code": p_code}
            rec.admin_panels.append(entry)

            if p_code == 200:
                rec.flags.append(f"ADMIN_PANEL_EXPOSED:{panel_name}:{path}")
                rec.manual_actions.append({
                    "type": "ADMIN_PANEL_UNAUTHENTICATED",
                    "priority": "CRITICAL",
                    "url": f"https://{host}{path}",
                    "instruction": (
                        f"UNAUTHENTICATED admin panel at {host}{path} ({panel_name}). "
                        f"Access immediately and document what is visible."
                    ),
                })
            elif p_code in (302, 401):
                rec.flags.append(f"ADMIN_PANEL_AUTH_REQUIRED:{panel_name}:{path}")

    # ── Step 5: Unauthenticated API endpoints ────────────────────────────
    api_paths = ["/api", "/api/v1", "/api/v2", "/graphql", "/api/health",
                 "/api/status", "/api/ping", "/api/version", "/.well-known/security.txt"]
    api_tasks = [_fetch(f"https://{host}{p}", timeout=5) for p in api_paths]
    api_results = await asyncio.gather(*api_tasks, return_exceptions=True)

    for path, result in zip(api_paths, api_results):
        if isinstance(result, Exception):
            continue
        a_code, a_hdrs, a_body = result
        ct = a_hdrs.get("content-type", "")
        if a_code == 200 and ("application/json" in ct or a_body.lstrip().startswith("{")):
            rec.open_api_endpoints.append(path)
            rec.flags.append(f"OPEN_API:{path}")

    # ── Step 6: Tech stack hints ─────────────────────────────────────────
    tech: list[str] = []
    if "_session_id" in " ".join(hdrs.get("set-cookie", "")).lower():
        tech.append("Rails")
    if "x-runtime" in hdrs and float(hdrs.get("x-runtime", "0") or 0) > 0:
        tech.append("Rails")
    if "x-powered-by" in hdrs:
        tech.append(hdrs["x-powered-by"])
    if "django" in body.lower() or "csrftoken" in " ".join(hdrs.get("set-cookie", "")).lower():
        tech.append("Django")
    if "laravel" in " ".join(hdrs.get("set-cookie", "")).lower():
        tech.append("Laravel")
    if "wordpress" in body.lower():
        tech.append("WordPress")
    if "next.js" in body.lower() or "__next_data__" in body.lower():
        tech.append("Next.js")
    if "angular" in body.lower():
        tech.append("Angular")
    rec.tech = list(dict.fromkeys(tech))  # deduplicate preserving order

    return rec


async def run_surface_map(
    targets: list[str],
    results_dir: Path,
    max_parallel: int = 10,
    timeout: int = 10,
) -> list[SurfaceRecord]:
    """
    Fan-out surface probe across all targets.

    Writes results to results_dir/02-surface/surface_map.jsonl.
    Returns list of SurfaceRecords.
    """
    surface_dir = results_dir / "02-surface"
    surface_dir.mkdir(parents=True, exist_ok=True)
    out_path = surface_dir / "surface_map.jsonl"

    sem = asyncio.Semaphore(max_parallel)

    async def probe_with_limit(url: str) -> SurfaceRecord:
        async with sem:
            return await probe_host(url, timeout=timeout)

    log.info("Phase 2.5: surface mapping %d targets", len(targets))
    tasks = []
    for t in targets:
        url = t if t.startswith(("http://", "https://")) else f"https://{t}"
        tasks.append(probe_with_limit(url))

    records = await asyncio.gather(*tasks, return_exceptions=True)

    # Write results and collect valid records
    valid: list[SurfaceRecord] = []
    with out_path.open("w") as f:
        for r in records:
            if isinstance(r, Exception):
                log.warning("Surface probe exception: %s", r)
                continue
            f.write(json.dumps(asdict(r)) + "\n")
            valid.append(r)

    # Log summary
    reachable    = sum(1 for r in valid if r.reachable)
    waf_blocked  = sum(1 for r in valid if r.waf_blocked)
    self_reg     = sum(1 for r in valid if r.self_registration)
    admin_open   = sum(1 for r in valid if any(p["code"] == 200 for p in r.admin_panels))
    log.info(
        "Surface map done — reachable=%d waf_blocked=%d self_reg=%d admin_exposed=%d",
        reachable, waf_blocked, self_reg, admin_open,
    )

    return valid


def load_surface_map(results_dir: Path) -> list[SurfaceRecord]:
    """Load previously written surface map from disk."""
    path = results_dir / "02-surface" / "surface_map.jsonl"
    if not path.exists():
        return []
    records: list[SurfaceRecord] = []
    for line in path.read_text().splitlines():
        try:
            d = json.loads(line)
            records.append(SurfaceRecord(**d))
        except Exception:
            pass
    return records


def reachable_targets(records: list[SurfaceRecord]) -> list[str]:
    """Return URLs that are reachable AND not WAF-blocked — safe for nuclei."""
    return [r.url for r in records if r.reachable and not r.waf_blocked]


def high_priority_surfaces(records: list[SurfaceRecord]) -> list[SurfaceRecord]:
    """Return records with P0-worthy surface flags, sorted by flag count."""
    p0_flags = {
        "SELF_REGISTRATION", "ADMIN_PANEL_EXPOSED", "OPEN_API",
        "OIDC_DYNAMIC_REGISTRATION",
    }
    priority = [r for r in records if any(
        any(f.startswith(p) for p in p0_flags) for f in r.flags
    )]
    return sorted(priority, key=lambda r: len(r.flags), reverse=True)


def all_manual_actions(records: list[SurfaceRecord]) -> list[dict]:
    """Collect all manual actions across all records, sorted by priority."""
    actions: list[dict] = []
    for rec in records:
        for action in rec.manual_actions:
            actions.append({**action, "host": rec.host})
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(actions, key=lambda a: priority_order.get(a.get("priority", "LOW"), 99))


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
