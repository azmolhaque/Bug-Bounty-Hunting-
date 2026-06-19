#!/usr/bin/env python3
"""
deep-recon-orchestrator.py — Intelligent Multi-target Recon with Claude Lead Analysis
Google/Alphabet VRP | Pi 5 deployment | Runs 2-4 hours unattended

Usage:
    cd ~/bug-bounty-hunting- && export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
    ANTHROPIC_API_KEY=sk-ant-... nohup python3 scripts/deep-recon-orchestrator.py \
      2>&1 | tee /tmp/recon-$(date +%Y%m%d-%H%M).log &

Without API key: runs full recon + local heuristic scoring (no Claude analysis).
With API key: adds Claude-powered lead triage after each cluster completes.

Target clusters (priority order):
  TIER0: Photomath (ArgoCD + admin/internal — highest reward)
  TIER1: Siemplify, Dataform, Waze, Fitbit, Apigee, Chronicle/Backstory

Constraints:
  - 0.5s rate limit between requests to same host, max 3 concurrent
  - No RFC1918 / IMDS / localhost requests
  - Passive DNS only; no brute-force credential attacks
  - Benign GET/HEAD probes only; no payload injection
"""

# ── stdlib ───────────────────────────────────────────────────────────────────
import socket, ssl, json, re, os, sys, time, threading, datetime, subprocess, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse, urljoin

# Force full PATH so curl/sleep work on Pi's broken zsh environment
os.environ["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:" + os.environ.get("PATH", "")

# ── Config ───────────────────────────────────────────────────────────────────

def find_repo_root():
    """Auto-detect repo root — works on Pi (lowercase) and remote env (camelcase)."""
    try:
        out = subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                                      stderr=subprocess.DEVNULL, text=True).strip()
        return Path(out)
    except Exception:
        # Fallback: check common paths
        for p in [Path.home() / "bug-bounty-hunting-",
                  Path.home() / "Bug-Bounty-Hunting-",
                  Path("/home/user/Bug-Bounty-Hunting-")]:
            if p.exists():
                return p
        return Path.cwd()

REPO = find_repo_root()
RESULTS_BASE = REPO / "results"
LOG_PATH = Path("/tmp/recon-orchestrator.log")
CURL = "/usr/bin/curl"
DELAY = 0.5          # seconds between requests to the same host
TIMEOUT = 20         # per-request timeout
MAX_WORKERS = 3      # total concurrent HTTP requests
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = "claude-sonnet-4-6"
UA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Mobile Safari/537.36"

_log_lock = threading.Lock()
_host_locks: dict = {}
_host_locks_lock = threading.Lock()
start_ts = datetime.datetime.now()


# ── Logging ───────────────────────────────────────────────────────────────────

def log(msg: str, level: str = "INFO"):
    elapsed = str(datetime.datetime.now() - start_ts).split(".")[0]
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}|{elapsed}] [{level:6s}] {msg}"
    with _log_lock:
        print(line, flush=True)
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")

def logfind(host: str, title: str, detail: str = ""):
    log(f"*** LEAD [{host}] {title} {detail}", "FIND  ")


# ── Target clusters ──────────────────────────────────────────────────────────

CLUSTERS = [
    {
        "name": "photomath", "tier": 0, "priority": 1,
        "description": "Photomath TIER0 — ArgoCD dev cluster without IAP + admin APIs",
        "hosts": [
            "argocd-dwh-eu-dev.photomath.net",       # 403 NOT via IAP — ArgoCD unauthenticated
            "portal.photomath.net",
            "idp.photomath.net",
            "dpcapi.photomath.net",
            "dpcapi-admin.photomath.net",
            "lapi.photomath.net",
            "tlapi.photomath.net",
            "baja.photomath.net",
            "cuvar.photomath.net",
            "daportal.photomath.net",
            "mankey.photomath.net",
            "taportal.photomath.net",
            "zuja.photomath.net",
            "glooker.photomath.net",
            "cms.photomath.net",
            "internal.photomath.net",
            "internal.photomath.com",
            "dpcapi-admin.photomath.com",
            "argocd-gke-app-eu-prod.photomath.net",
            "argocd-gke-app-us-prod.photomath.net",
        ],
        "extra_wordlist": ["staging", "dev", "api", "app", "admin", "k8s",
                           "grafana", "prometheus", "kibana", "vault", "harbor"],
        "root_domains": ["photomath.net", "photomath.com"],
    },
    {
        "name": "siemplify", "tier": 1, "priority": 1,
        "description": "Siemplify SOAR — SSRF via connectors, tenant isolation",
        "hosts": [
            "app.siemplify-soar.com",
            "api.siemplify-soar.com",
            "dev.siemplify-soar.com",
            "staging.siemplify-soar.com",
            "admin.siemplify-soar.com",
            "portal.siemplify-soar.com",
            "siemplify.co",
            "siemplifycloud.com",
            "passbolt.siemplify.co",
            "api.siemplify.co",
            "app.siemplify.co",
        ],
        "extra_wordlist": ["api", "app", "admin", "portal", "marketplace", "docs", "integrations"],
        "root_domains": ["siemplify.co", "siemplifycloud.com"],
    },
    {
        "name": "dataform", "tier": 1, "priority": 2,
        "description": "Google Dataform (BigQuery) — workspace IDOR, project isolation",
        "hosts": ["app.dataform.co", "api.dataform.co", "dataform.co"],
        "extra_wordlist": ["api", "app", "staging", "dev", "docs", "console"],
        "root_domains": ["dataform.co"],
    },
    {
        "name": "waze", "tier": 1, "priority": 2,
        "description": "Waze Biz — prior XSS + location IDOR; ad API staging",
        "hosts": [
            "biz.waze.com", "adsapi.waze.com",
            "adsapi-staging.waze.com", "proxy.waze.com", "proxy-staging.waze.com",
        ],
        "extra_wordlist": ["biz", "ads", "api", "partner", "dashboard", "reports"],
        "root_domains": ["waze.com"],
    },
    {
        "name": "fitbit", "tier": 1, "priority": 3,
        "description": "Fitbit health admin — sensitive health data, management portal",
        "hosts": [
            "accounts.fitbit.com", "health-admin.fitbit.com",
            "ngw.fitbit.com", "mgmt.fitbit.com",
            "coaching-dashboard.fitbit.com", "strava.fitbit.com",
        ],
        "extra_wordlist": ["health", "admin", "api", "mgmt", "dashboard", "partner", "coach"],
        "root_domains": ["fitbit.com"],
    },
    {
        "name": "apigee", "tier": 1, "priority": 3,
        "description": "Apigee enterprise portal — API management, policy injection",
        "hosts": ["enterprise.apigee.com", "sense-ui.apigee.com", "apigee.com", "apigee.google.com"],
        "extra_wordlist": ["api", "enterprise", "ui", "console", "portal", "docs", "sense"],
        "root_domains": ["apigee.com"],
    },
]

# ── Path sets ─────────────────────────────────────────────────────────────────

CORE_PATHS = [
    "/robots.txt", "/sitemap.xml",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/.well-known/security.txt",
    "/health", "/healthz", "/ready", "/readyz", "/live", "/livez", "/ping",
    "/metrics", "/status", "/version", "/info", "/debug", "/env",
    "/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/swagger-ui.html",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/gql",
    "/v1", "/v2", "/v3",
    "/auth", "/oauth", "/login", "/signin", "/sso", "/logout",
    "/oauth/token", "/oauth/authorize",
    "/admin", "/admin/api", "/internal", "/management", "/dashboard",
    "/.env", "/config", "/server-status", "/server-info",
    "/__/firebase/init.json", "/__/firebase/init.js",
    "/api/user", "/api/users", "/api/me", "/api/account",
]

ARGOCD_PATHS = [
    "/api/v1/settings", "/api/v1/clusters", "/api/v1/applications",
    "/api/v1/repositories", "/api/v1/projects", "/api/version",
    "/api/v1/session",    # auth endpoint — 200/401 tells us auth status
    "/api/v1/account",
    "/api/v1/users",
]

SIEMPLIFY_PATHS = [
    "/api/external/v1/cases", "/api/external/v1/alerts",
    "/api/external/v1/playbooks", "/api/external/v1/connectors",
    "/api/1.0/settings", "/api/settings", "/api/auth/login",
    "/api/connectors", "/integrations", "/marketplace",
    "/api/v1/health",
]

DATAFORM_PATHS = [
    "/api/v1/projects", "/api/v1/workspaces",
    "/api/v1/repositories", "/api/v1/compilationResults",
    "/api/v1/workflowInvocations", "/v1/projects",
]

WAZE_PATHS = [
    "/api/v1", "/api/v2",
    "/campaigns", "/api/campaigns", "/api/reports",
    "/api/locations", "/api/users", "/api/accounts",
]

EXTRA_PATHS_BY_CLUSTER = {
    "photomath": ARGOCD_PATHS,
    "siemplify": SIEMPLIFY_PATHS,
    "dataform": DATAFORM_PATHS,
    "waze": WAZE_PATHS,
}

# ── HTTP layer ────────────────────────────────────────────────────────────────

def get_host_lock(host: str) -> threading.Lock:
    with _host_locks_lock:
        if host not in _host_locks:
            _host_locks[host] = threading.Lock()
        return _host_locks[host]


def dns_resolve(host: str) -> list[str]:
    try:
        info = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list({r[4][0] for r in info})
    except socket.gaierror:
        return []


def is_safe_ip(ip: str) -> bool:
    """Return False for any IP we must not probe (RFC1918, IMDS, loopback)."""
    try:
        p = [int(x) for x in ip.split(".")]
        if p[0] in (10, 127): return False
        if p[0] == 172 and 16 <= p[1] <= 31: return False
        if p[0] == 192 and p[1] == 168: return False
        if p[0] == 169 and p[1] == 254: return False
    except Exception:
        pass
    return True


def curl(url: str, method: str = "GET", extra_headers: list | None = None,
         body_limit: int = 131072, follow: bool = True, timeout: int = TIMEOUT) -> tuple[int, dict, str]:
    """Execute curl; return (status_code, headers_dict, body_str)."""
    cmd = [CURL, "-s", f"--max-time={timeout}", f"--max-filesize={body_limit}",
           "-A", UA, "-D", "-", "-o", "-", "--compressed"]
    if follow:
        cmd += ["-L", "--max-redirs", "5"]
    if method != "GET":
        cmd += ["-X", method]
    for h in (extra_headers or []):
        cmd += ["-H", h]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        raw = r.stdout
    except subprocess.TimeoutExpired:
        return 0, {}, "timeout"
    except Exception as e:
        return 0, {}, str(e)

    hdrs: dict = {}
    body_parts: list[str] = []
    last_code = 0
    in_body = False
    for line in raw.split("\n"):
        s = line.strip()
        if s.startswith("HTTP/"):
            parts = s.split()
            last_code = int(parts[1]) if len(parts) > 1 else 0
            hdrs = {}; in_body = False
        elif not in_body:
            if s == "":
                in_body = True
            elif ":" in s:
                k, _, v = s.partition(":")
                hdrs[k.lower().strip()] = v.strip()
        else:
            body_parts.append(line)
    return last_code, hdrs, "\n".join(body_parts)


# ── Subdomain discovery ───────────────────────────────────────────────────────

def brute_dns(root_domain: str, wordlist: list[str]) -> list[str]:
    """Resolve a short wordlist against root_domain; return live subdomains."""
    live = []
    for word in wordlist:
        host = f"{word}.{root_domain}"
        ips = dns_resolve(host)
        if ips and all(is_safe_ip(ip) for ip in ips):
            log(f"  DNS BRUTE: {host} → {ips[0]}", "DNS   ")
            live.append(host)
        time.sleep(0.05)
    return live


def crt_sh_subdomains(root_domain: str) -> list[str]:
    """Pull subdomains from crt.sh (best-effort; may be blocked)."""
    code, _, body = curl(
        f"https://crt.sh/?q=%25.{root_domain}&output=json",
        body_limit=2_000_000, timeout=30
    )
    if code != 200 or not body.strip().startswith("["):
        return []
    try:
        data = json.loads(body)
        names: set[str] = set()
        for e in data:
            for n in e.get("name_value", "").split("\n"):
                n = n.strip().lstrip("*.")
                if n and root_domain in n:
                    names.add(n.lower())
        log(f"  crt.sh: {len(names)} names for {root_domain}", "DNS   ")
        return sorted(names)
    except Exception:
        return []


# ── Technology detection ──────────────────────────────────────────────────────

TECH_SIGNALS = {
    "argocd":     [("x-argocd-version", "*"), ("server", "argo"), ("body", "argocd"), ("body", "Argo CD")],
    "firebase":   [("body", "firebaseapp"), ("body", "firebase"), ("body", "AIzaSy")],
    "nextjs":     [("body", "__NEXT_DATA__"), ("body", "_next/static"), ("x-powered-by", "Next.js")],
    "framer":     [("server", "Framer")],
    "kubernetes": [("body", "kubernetes"), ("body", "k8s"), ("body", "kubectl")],
    "grafana":    [("body", "Grafana"), ("x-grafana-version", "*")],
    "metabase":   [("body", "Metabase"), ("body", "metabase")],
    "hasura":     [("body", "hasura"), ("body", "graphql")],
    "django":     [("body", "csrfmiddlewaretoken"), ("x-frame-options", "SAMEORIGIN")],
    "rails":      [("x-powered-by", "Phusion Passenger"), ("set-cookie", "_session_id")],
    "fastapi":    [("body", '"detail":'), ("body", "FastAPI")],
    "gcp":        [("server", "sffe"), ("server", "Google Frontend"), ("x-cloud-trace-context", "*")],
    "cloudflare": [("server", "cloudflare"), ("cf-ray", "*")],
    "looker":     [("body", "looker"), ("x-looker-version", "*")],
}

def detect_tech(hdrs: dict, body: str) -> list[str]:
    detected = []
    for tech, signals in TECH_SIGNALS.items():
        for header, value in signals:
            if header == "body":
                if value.lower() in body[:8000].lower():
                    detected.append(tech); break
            else:
                hval = hdrs.get(header, "")
                if value == "*" and hval:
                    detected.append(tech); break
                elif value.lower() in hval.lower():
                    detected.append(tech); break
    return list(dict.fromkeys(detected))


# ── JS mining ─────────────────────────────────────────────────────────────────

JS_PATTERNS = [
    ("ENDPOINT",      r'["\'](/(?:api|v\d|graphql|auth|oauth|internal|admin)[/\w\-\.?={}&:@]*)["\']'),
    ("FIREBASE_KEY",  r'(AIzaSy[A-Za-z0-9_-]{33})'),
    ("API_KEY",       r'(?:api[_-]?key|apiKey)[\s"\']*[:=][\s"\']*([A-Za-z0-9_\-]{20,80})'),
    ("CLIENT_ID",     r'(?:client[_-]?id|clientId)[\s"\']*[:=][\s"\']*([A-Za-z0-9_\-.]{12,120})'),
    ("GCP_PROJECT",   r'(?:project[_-]?id|projectId)[\s"\']*[:=][\s"\'`]*([a-z][a-z0-9-]{4,29})["\']'),
    ("SECRET",        r'(?:secret|password)[\s"\']*[:=][\s"\'`]([A-Za-z0-9_+/=]{16,80})["\']'),
    ("INTERNAL_HOST", r'["\'`]([a-z][a-z0-9\-]+\.(?:internal|local|corp|svc\.cluster\.local)(?:/[^"\']{0,60})?)["\']'),
    ("GRAPHQL_OP",    r'(?:query|mutation)\s+(\w+)\s*[({]'),
    ("AUTH_HEADER",   r'(?:Authorization|Bearer|X-API-Key)["\s]*[:=]\s*["\']([^"\']{8,})["\']'),
    ("S3_BUCKET",     r'([a-z][a-z0-9\-]{2,62})\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com'),
    ("GCS_BUCKET",    r'storage\.googleapis\.com/([a-z][a-z0-9\-_]{2,62})'),
    ("GITHUB_TOKEN",  r'(gh[pousr]_[A-Za-z0-9]{36,255})'),
]

NOISE_VALUES = {"example", "placeholder", "your_", "changeme", "test", "demo",
                "undefined", "null", "none", "todo", "fixme", "xxx"}

def mine_js(host: str, body: str, host_lock: threading.Lock) -> list[dict]:
    js_urls = re.findall(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body)
    findings: list[dict] = []

    for raw_url in js_urls[:10]:   # cap at 10 bundles per host
        url = raw_url if raw_url.startswith("http") else f"https://{host}{raw_url}"
        with host_lock:
            time.sleep(DELAY)
            code, _, js_body = curl(url, body_limit=524288, follow=False)
        if code != 200 or not js_body:
            continue

        for label, pattern in JS_PATTERNS:
            for m in re.findall(pattern, js_body):
                val = m if isinstance(m, str) else (m[0] if m else "")
                if not val or len(val) < 3:
                    continue
                if any(n in val.lower() for n in NOISE_VALUES):
                    continue
                findings.append({"source": url.split("/")[-1][:50], "type": label, "value": val[:120]})

    # Deduplicate by (type, value)
    seen = set()
    deduped = []
    for f in findings:
        key = (f["type"], f["value"])
        if key not in seen:
            seen.add(key); deduped.append(f)
    return deduped[:40]


# ── CORS analysis ─────────────────────────────────────────────────────────────

def check_cors(host: str, paths: list[str], host_lock: threading.Lock) -> list[dict]:
    issues = []
    test_origins = [
        "https://evil-attacker.com",
        f"https://evil{host}",
        "null",
        f"https://{host}.evil.com",
    ]
    test_path = next((p for p in paths if "api" in p), "/api/v1/")

    for origin in test_origins[:2]:   # keep it brief
        with host_lock:
            time.sleep(DELAY)
            _, hdrs, _ = curl(
                f"https://{host}{test_path}",
                extra_headers=[f"Origin: {origin}",
                               "Access-Control-Request-Method: GET"],
                follow=False, body_limit=512,
            )
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "")
        if not acao:
            continue
        if acao == origin or acao == "*":
            sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
            issues.append({"origin": origin, "acao": acao, "acac": acac, "severity": sev})
            logfind(host, f"CORS {sev}", f"acao={acao} acac={acac} path={test_path}")
    return issues


# ── GraphQL introspection ─────────────────────────────────────────────────────

GRAPHQL_INTROSPECT = '{"query":"{__schema{queryType{name}types{name kind description fields{name type{name kind}}}}}"}'

def check_graphql(host: str, host_lock: threading.Lock) -> dict | None:
    for path in ["/graphql", "/gql", "/api/graphql", "/v1/graphql"]:
        with host_lock:
            time.sleep(DELAY)
            code, hdrs, body = curl(
                f"https://{host}{path}",
                extra_headers=["Content-Type: application/json",
                               f"Content-Length: {len(GRAPHQL_INTROSPECT)}"],
                body_limit=32768, follow=False,
            )
        ct = hdrs.get("content-type", "")
        if code in (200, 400) and ("graphql" in ct or "json" in ct):
            if "__schema" in body or "queryType" in body:
                logfind(host, "GRAPHQL INTROSPECTION ENABLED", f"path={path}")
                return {"path": path, "schema_snippet": body[:500]}
            if code == 200:
                logfind(host, f"GRAPHQL ENDPOINT [{code}]", f"path={path}")
                return {"path": path, "code": code}
    return None


# ── Claude lead analysis ──────────────────────────────────────────────────────

CLAUDE_PROMPT_TEMPLATE = """\
You are an elite authorized bug bounty hunter analyzing recon data for Google/Alphabet VRP.
The program pays up to $151,515. Only report if findings pass ALL of:
  1. Attacker gain is concrete (account access, data of another user, RCE, SSRF to internal, auth bypass)
  2. Not intended behavior
  3. Passes Fix Test (vendor would actually change code)
  4. Reproducible with minimal PoC
  5. In scope, not a known dup

HARD REJECT (never submit standalone): self-XSS, missing security headers, software version disclosure,
login page lacks lockout, SPF/DKIM misconfig, subdomain takeover without cookie/OAuth proof,
open redirect without token exfil chain, rate limit absent on non-sensitive endpoints.

RECON DATA FOR: {cluster_name} (TIER{tier})
Description: {description}

{host_summaries}

TASK:
1. Score each LIVE host 0-5 on vulnerability potential (5 = near-certain High/Critical finding)
2. For the top 2-3 hosts, name the SINGLE most plausible bug class and give the exact curl
   command to verify it in the next hunting session
3. Flag any finding that clears the submission bar already (report immediately)
4. Explicitly DROP any finding that is on the Hard Reject list above
5. If ArgoCD endpoint is unauthenticated → escalate to CRITICAL immediately

Respond in strict JSON (no markdown fences, no commentary outside JSON):
{{
  "cluster_score": 1-5,
  "top_hosts": [
    {{
      "host": "...",
      "score": 0-5,
      "bug_class": "...",
      "rationale": "...",
      "verify_command": "curl ...",
      "severity_estimate": "Critical|High|Medium|Low|Info",
      "submit_now": false
    }}
  ],
  "immediate_flags": ["..."],
  "drop_list": ["..."],
  "next_session_priority": "one sentence"
}}"""


def call_claude(prompt: str) -> dict | None:
    if not ANTHROPIC_KEY:
        return None
    payload = json.dumps({
        "model": CLAUDE_MODEL,
        "max_tokens": 2000,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    cmd = [
        CURL, "-s", "--max-time", "45",
        "-X", "POST", "https://api.anthropic.com/v1/messages",
        "-H", "Content-Type: application/json",
        "-H", f"x-api-key: {ANTHROPIC_KEY}",
        "-H", "anthropic-version: 2023-06-01",
        "-d", "@-",
    ]
    try:
        r = subprocess.run(cmd, input=payload, capture_output=True, timeout=50)
        data = json.loads(r.stdout)
        text = data.get("content", [{}])[0].get("text", "")
        # Strip any markdown fences
        text = re.sub(r"^```json\s*|\s*```$", "", text.strip())
        return json.loads(text)
    except Exception as e:
        log(f"Claude API error: {e}", "WARN  ")
        return None


def score_host_heuristic(r: dict) -> int:
    """Local scoring when Claude is unavailable. Returns 0-5."""
    score = 0
    codes_200 = [p for p, v in r["paths"].items() if v["code"] == 200]
    if any("/api" in p or "/v1" in p for p in codes_200): score += 2
    if "/graphql" in codes_200 or r.get("graphql"): score += 2
    if r.get("cors"): score += 2
    if r.get("js_findings"):
        types = {f["type"] for f in r["js_findings"]}
        if "FIREBASE_KEY" in types: score += 3
        if "API_KEY" in types: score += 2
        if "SECRET" in types: score += 2
        if "INTERNAL_HOST" in types: score += 1
    if "argocd" in r.get("tech", []):
        if any("/api/v1/clusters" in p or "/api/v1/applications" in p for p in codes_200):
            score += 5   # ArgoCD unauthenticated = CRITICAL
    return min(score, 5)


# ── Main probe ────────────────────────────────────────────────────────────────

def probe_host(host: str, cluster_name: str) -> dict:
    result: dict = {
        "host": host, "cluster": cluster_name,
        "resolved": [], "live": False, "status": 0,
        "server": "", "tech": [], "paths": {}, "js_findings": [],
        "cors": [], "graphql": None, "interesting": [], "heuristic_score": 0,
    }

    ips = dns_resolve(host)
    if not ips:
        log(f"  NXDOMAIN {host}", "DNS   ")
        return result
    if not all(is_safe_ip(ip) for ip in ips):
        log(f"  SKIP internal IP {host} → {ips}", "WARN  ")
        return result

    result["resolved"] = ips
    log(f"  RESOLVED {host} → {', '.join(ips)}", "DNS   ")

    lock = get_host_lock(host)

    # ── Base request ──────────────────────────────────────────────────────────
    with lock:
        time.sleep(DELAY)
        code, hdrs, body = curl(f"https://{host}/")

    if code == 0:
        # Try HTTP fallback
        with lock:
            time.sleep(DELAY)
            code, hdrs, body = curl(f"http://{host}/")

    result["status"] = code
    result["live"] = code > 0
    if not result["live"]:
        log(f"  DEAD {host}", "HTTP  ")
        return result

    result["server"] = hdrs.get("server", "")
    result["tech"] = detect_tech(hdrs, body)
    log(f"  [{code}] {host}  server={result['server'][:30]}  tech={result['tech']}", "HTTP  ")

    # Determine probe path set
    paths_to_probe = list(CORE_PATHS) + EXTRA_PATHS_BY_CLUSTER.get(cluster_name, [])
    # Add technology-specific paths
    if "argocd" in result["tech"] or "argocd-" in host:
        paths_to_probe = list(set(paths_to_probe + ARGOCD_PATHS))
    if "grafana" in result["tech"] or "grafana" in host:
        paths_to_probe += ["/api/dashboards", "/api/datasources", "/api/orgs",
                           "/api/admin/settings", "/api/plugins"]
    if "metabase" in result["tech"] or "metabase" in host:
        paths_to_probe += ["/api/database", "/api/card", "/api/dashboard",
                           "/api/user", "/api/session/forgot_password"]

    # ── Path enumeration ──────────────────────────────────────────────────────
    interesting_codes = {200, 201, 204, 206, 301, 302, 307, 308, 400, 401, 403, 405, 500}
    skip_in_body = {"<html", "<!doctype", "framer", "not found", "404"}

    for path in paths_to_probe:
        with lock:
            time.sleep(DELAY)
            pcode, phdrs, pbody = curl(f"https://{host}{path}", follow=False, body_limit=32768)

        if pcode not in interesting_codes:
            continue
        if pcode == 301 or pcode == 308:
            loc = phdrs.get("location", "")
            if any(skip in loc.lower() for skip in ["wing.com", "framer"]):
                continue   # redirect to marketing/Framer — not interesting

        entry = {
            "code": pcode,
            "content_type": phdrs.get("content-type", "")[:60],
            "length": phdrs.get("content-length", ""),
            "server": phdrs.get("server", ""),
            "body_snippet": pbody[:400].strip(),
            "location": phdrs.get("location", ""),
        }

        # Filter boring 200s (HTML marketing pages)
        if pcode == 200:
            if any(s in pbody[:500].lower() for s in skip_in_body):
                if "application/json" not in entry["content_type"]:
                    continue

        result["paths"][path] = entry

        icon = "🔴" if pcode == 200 else ("🟡" if pcode in {401, 403} else "  ")
        log(f"  {icon} {pcode} {host}{path}  [{entry['content_type'][:35]}]", "PATH  ")

        # Immediate flags
        if pcode == 200:
            if "json" in entry["content_type"]:
                result["interesting"].append(f"JSON-200: {path} body={pbody[:200]}")
            if "swagger" in path or "openapi" in path:
                result["interesting"].append(f"API-SCHEMA: {path} ({len(pbody)} bytes)")
                logfind(host, "API SCHEMA EXPOSED", f"{path}")
            if path in ARGOCD_PATHS and "cluster" in path:
                result["interesting"].append(f"ARGOCD-UNAUTH: {path} → 200 !!!")
                logfind(host, "ARGOCD UNAUTHENTICATED CLUSTER API", f"{path}")

        if pcode == 200 and "openid-configuration" in path:
            result["interesting"].append(f"OIDC-CONFIG: {pbody[:300]}")
            logfind(host, "OIDC CONFIG EXPOSED", "")

        if path == "/graphql" and pcode in {200, 400}:
            result["interesting"].append(f"GRAPHQL: {path} [{pcode}]")

    # ── CORS check ────────────────────────────────────────────────────────────
    result["cors"] = check_cors(host, list(result["paths"].keys()) or ["/api/v1/"], lock)

    # ── GraphQL introspection ─────────────────────────────────────────────────
    if result["paths"].get("/graphql") or "graphql" in body.lower()[:3000]:
        result["graphql"] = check_graphql(host, lock)

    # ── JS mining ─────────────────────────────────────────────────────────────
    if code == 200 and body:
        result["js_findings"] = mine_js(host, body, lock)
        for f in result["js_findings"]:
            if f["type"] in {"FIREBASE_KEY", "API_KEY", "SECRET", "GITHUB_TOKEN"}:
                logfind(host, f"JS CREDENTIAL FOUND: {f['type']}", f["value"][:40])

    result["heuristic_score"] = score_host_heuristic(result)
    return result


# ── Cluster runner ────────────────────────────────────────────────────────────

def run_cluster(cluster: dict) -> list[dict]:
    name = cluster["name"]
    log(f"{'='*60}", "CLUST ")
    log(f"CLUSTER START: {name} (TIER{cluster['tier']}) — {cluster['description']}", "CLUST ")
    log(f"{'='*60}", "CLUST ")

    # Collect hosts: listed + brute DNS + optional crt.sh
    all_hosts = list(cluster["hosts"])

    for root in cluster.get("root_domains", []):
        wl = cluster.get("extra_wordlist", [])
        brute = brute_dns(root, wl)
        for h in brute:
            if h not in all_hosts:
                all_hosts.append(h)

        ct_hosts = crt_sh_subdomains(root)
        for h in ct_hosts:
            if h not in all_hosts and root in h:
                all_hosts.append(h)

    log(f"Total hosts to probe: {len(all_hosts)}", "CLUST ")

    probe_results: list[dict] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(probe_host, h, name): h for h in all_hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                res = fut.result()
                probe_results.append(res)
            except Exception as e:
                log(f"  ERROR probing {host}: {e}", "ERR   ")

    live = [r for r in probe_results if r["live"]]
    log(f"Cluster {name}: {len(live)}/{len(all_hosts)} live hosts", "CLUST ")

    # Write raw report
    out_dir = RESULTS_BASE / name / "02-surface"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    md_lines = [
        f"# Deep Recon — {name}", f"Generated: {ts}",
        f"Live: {len(live)}/{len(all_hosts)}  Tier: {cluster['tier']}", "",
        "## Live Hosts",
    ]
    all_leads: list[dict] = []

    for r in sorted(live, key=lambda x: -x["heuristic_score"]):
        md_lines += [
            f"\n### {r['host']}  [score={r['heuristic_score']}]",
            f"- Status: {r['status']}  IPs: {', '.join(r['resolved'])}",
            f"- Server: {r['server']}  Tech: {', '.join(r['tech']) or '?'}",
        ]
        if r["cors"]:
            md_lines.append(f"- **CORS: {r['cors']}**")
        if r["graphql"]:
            md_lines.append(f"- **GRAPHQL: {r['graphql']}**")
        hit200 = {p: v for p, v in r["paths"].items() if v["code"] == 200}
        if hit200:
            md_lines.append("- 200 paths: " + ", ".join(f"`{p}`" for p in hit200))
        if r["js_findings"]:
            md_lines.append("- **JS findings:**")
            for f in r["js_findings"][:15]:
                md_lines.append(f"  - `{f['type']}` `{f['value'][:80]}`")
        for i in r["interesting"]:
            md_lines.append(f"- ⚠️ `{i}`")
            all_leads.append({"host": r["host"], "cluster": name, "finding": i,
                               "score": r["heuristic_score"]})

    (out_dir / "deep-recon.md").write_text("\n".join(md_lines))

    # Save raw JSON (gitignored dir)
    raw_dir = RESULTS_BASE / name / "03-candidates"
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / "recon-raw.json").write_text(json.dumps(probe_results, indent=2))

    # ── Claude analysis ───────────────────────────────────────────────────────
    claude_result: dict | None = None
    if ANTHROPIC_KEY and live:
        log("Calling Claude for lead analysis…", "CLAUDE")
        host_summaries = []
        for r in sorted(live, key=lambda x: -x["heuristic_score"])[:8]:
            paths_200 = [p for p, v in r["paths"].items() if v["code"] == 200]
            paths_401 = [p for p, v in r["paths"].items() if v["code"] == 401]
            paths_403 = [p for p, v in r["paths"].items() if v["code"] == 403]
            host_summaries.append(
                f"HOST: {r['host']}\n"
                f"  status={r['status']} server={r['server']} tech={r['tech']}\n"
                f"  paths_200={paths_200}\n"
                f"  paths_401={paths_401}\n"
                f"  paths_403={paths_403}\n"
                f"  cors={r['cors']}\n"
                f"  graphql={r['graphql']}\n"
                f"  js_findings={[f['type']+':'+f['value'][:40] for f in r['js_findings'][:10]]}\n"
                f"  interesting={r['interesting'][:5]}\n"
                f"  heuristic_score={r['heuristic_score']}"
            )
        prompt = CLAUDE_PROMPT_TEMPLATE.format(
            cluster_name=name, tier=cluster["tier"],
            description=cluster["description"],
            host_summaries="\n\n".join(host_summaries),
        )
        claude_result = call_claude(prompt)
        if claude_result:
            log(f"Claude cluster_score={claude_result.get('cluster_score')}", "CLAUDE")
            log(f"Claude priority: {claude_result.get('next_session_priority')}", "CLAUDE")
            for th in claude_result.get("top_hosts", []):
                score = th.get("score", 0)
                if score >= 3:
                    logfind(th["host"], f"Claude [{th['severity_estimate']}] {th['bug_class']}",
                            th.get("rationale", "")[:80])
            (out_dir / "claude-analysis.json").write_text(json.dumps(claude_result, indent=2))
            (out_dir / "claude-analysis.md").write_text(
                f"# Claude Analysis — {name}\nGenerated: {ts}\n\n```json\n"
                + json.dumps(claude_result, indent=2) + "\n```\n"
            )
        else:
            log("Claude unavailable or returned no result; using heuristic scores only", "WARN  ")

    log(f"CLUSTER DONE: {name}  leads={len(all_leads)}", "CLUST ")
    return all_leads, claude_result


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    LOG_PATH.parent.mkdir(exist_ok=True)
    log("="*60, "INIT  ")
    log(f"deep-recon-orchestrator v2 — {datetime.datetime.now().isoformat()}", "INIT  ")
    log(f"Repo: {REPO}", "INIT  ")
    log(f"Clusters: {[c['name'] for c in CLUSTERS]}", "INIT  ")
    log(f"Claude: {'enabled (' + CLAUDE_MODEL + ')' if ANTHROPIC_KEY else 'DISABLED (no ANTHROPIC_API_KEY)'}", "INIT  ")
    log(f"Workers: {MAX_WORKERS}  Delay: {DELAY}s  Timeout: {TIMEOUT}s", "INIT  ")
    log("="*60, "INIT  ")

    master_leads: list[dict] = []
    master_claude: list[dict] = []

    for cluster in sorted(CLUSTERS, key=lambda c: c["priority"]):
        try:
            leads, claude_out = run_cluster(cluster)
            for l in leads:
                l["cluster"] = cluster["name"]
            master_leads.extend(leads)
            if claude_out:
                claude_out["cluster"] = cluster["name"]
                master_claude.append(claude_out)
        except Exception as e:
            log(f"Cluster {cluster['name']} crashed: {e}", "ERR   ")

    # ── Final master report ───────────────────────────────────────────────────
    elapsed = str(datetime.datetime.now() - start_ts).split(".")[0]
    print("\n" + "="*70)
    print(f"RECON COMPLETE — {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} — {elapsed}")
    print("="*70)

    scored = sorted(master_leads, key=lambda x: -x.get("score", 0))
    if scored:
        print(f"\n{'RANK':<5} {'SCORE':<6} {'HOST':<40} FINDING")
        print("-"*100)
        for i, l in enumerate(scored[:20], 1):
            print(f"{i:<5} {l.get('score',0):<6} {l.get('host',''):<40} {l.get('finding','')[:60]}")
    else:
        print("No leads surfaced in this run.")

    if master_claude:
        print("\nCLAUDE TOP PRIORITIES:")
        for c in master_claude:
            print(f"\n  [{c.get('cluster','?')}] cluster_score={c.get('cluster_score')}")
            print(f"  → {c.get('next_session_priority','')}")
            for th in c.get("top_hosts", [])[:2]:
                if th.get("score", 0) >= 3:
                    print(f"    [{th.get('severity_estimate')}] {th.get('host')} — {th.get('bug_class')}")
                    print(f"    CMD: {th.get('verify_command','')[:100]}")

    print(f"\nFull log: {LOG_PATH}")
    print("="*70)

    # Save master leads
    ml_path = RESULTS_BASE / "MASTER-LEADS.json"
    existing = []
    if ml_path.exists():
        try: existing = json.loads(ml_path.read_text())
        except Exception: pass
    existing.extend(scored)
    ml_path.write_text(json.dumps(existing, indent=2))
    log(f"Master leads saved: {ml_path}  ({len(scored)} new)", "DONE  ")


if __name__ == "__main__":
    main()
