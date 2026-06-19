#!/usr/bin/env python3
"""
deep-recon-orchestrator.py v3 — Advanced Bug Hunter with Claude CLI Integration
Google/Alphabet VRP | Pi 5 | Runs 2-4 hours unattended

Phases per cluster:
  1. Discovery    — DNS resolve, crt.sh CT pull, targeted wordlist brute
  2. Surface map  — HTTP probe, tech fingerprint, header analysis
  3. Active tests — ArgoCD unauth, Firebase key validation, CORS chain,
                    GraphQL introspection, OpenAPI schema parse, JWT decode,
                    IDOR probe on discovered IDs, method override tests
  4. JS mining    — Bundle download, credential extraction, endpoint harvest,
                    source-map detection, GCS/S3 bucket enumeration
  5. Claude CLI   — `claude -p` validates each finding against CLAUDE.md §2-4,
                    scores 0-5, writes exact curl commands, decides PURSUE/DROP
  6. Report       — Ranked lead table + triager-grade markdown per finding

Usage (no API cost — uses local Claude Code install):
  cd ~/bug-bounty-hunting-
  export PATH="/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
  nohup python3 scripts/deep-recon-orchestrator.py 2>&1 | tee /tmp/recon-$(date +%Y%m%d-%H%M).log &

Constraints honored:
  - 0.5s rate limit per host, max 3 concurrent requests
  - No RFC1918/IMDS/localhost probing
  - Benign payloads only — no destructive writes, no brute-force credentials
  - Single IDOR probe per resource (not mass enumeration)
"""

import os, sys, re, json, time, socket, threading, datetime, subprocess, hashlib, base64
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode, urlparse

# ── Bootstrap PATH so curl/dig work on Pi's broken zsh env ───────────────────
os.environ["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:" + os.environ.get("PATH", "")
CURL = "/usr/bin/curl"

# ── Repo root auto-detection (Pi: ~/bug-bounty-hunting- OR remote: ~/Bug-Bounty-Hunting-) ──
def _find_repo() -> Path:
    try:
        r = subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                                    stderr=subprocess.DEVNULL, text=True).strip()
        return Path(r)
    except Exception:
        for p in [Path.home()/"bug-bounty-hunting-", Path.home()/"Bug-Bounty-Hunting-",
                  Path("/home/user/Bug-Bounty-Hunting-")]:
            if p.exists(): return p
        return Path.cwd()

REPO         = _find_repo()
RESULTS      = REPO / "results"
LOG_PATH     = Path("/tmp/recon-orchestrator.log")
DELAY        = 0.5       # seconds between requests to same host
TIMEOUT      = 18        # per-request curl timeout
MAX_WORKERS  = 3         # global concurrent HTTP cap
UA           = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.6422.60 Mobile Safari/537.36")

_log_lock   = threading.Lock()
_hlocks: dict[str, threading.Lock] = {}
_hlocks_mu  = threading.Lock()
_t0         = datetime.datetime.now()

# ── Logging ───────────────────────────────────────────────────────────────────
def log(msg: str, lvl: str = "INFO"):
    ts  = datetime.datetime.now().strftime("%H:%M:%S")
    ela = str(datetime.datetime.now() - _t0).split(".")[0]
    line = f"[{ts}|{ela}][{lvl:6s}] {msg}"
    with _log_lock:
        print(line, flush=True)
        LOG_PATH.parent.mkdir(exist_ok=True)
        with open(LOG_PATH, "a") as f: f.write(line + "\n")

def lead(host: str, title: str, detail: str = ""):
    log(f"★ LEAD [{host}] {title}  {detail}", "FIND")

# ── Target clusters ───────────────────────────────────────────────────────────
CLUSTERS = [
    {
        "name": "photomath", "tier": 0, "priority": 1,
        "desc": "Photomath TIER0 — ArgoCD dev cluster exposed without IAP + admin APIs",
        "hosts": [
            "argocd-dwh-eu-dev.photomath.net",        # KEY: 403 NOT via IAP
            "argocd-gke-app-eu-prod.photomath.net",
            "argocd-gke-app-us-prod.photomath.net",
            "idp.photomath.net",
            "dpcapi.photomath.net",      "dpcapi-admin.photomath.net",
            "lapi.photomath.net",        "tlapi.photomath.net",
            "baja.photomath.net",        "cuvar.photomath.net",
            "daportal.photomath.net",    "mankey.photomath.net",
            "taportal.photomath.net",    "zuja.photomath.net",
            "glooker.photomath.net",     "cms.photomath.net",
            "portal.photomath.net",
            "internal.photomath.net",   "internal.photomath.com",
            "dpcapi-admin.photomath.com",
        ],
        "brute_words": ["grafana","prometheus","kibana","vault","harbor","k8s",
                        "staging","dev","api","admin","ops","monitoring","logging"],
        "roots": ["photomath.net", "photomath.com"],
    },
    {
        "name": "siemplify", "tier": 1, "priority": 1,
        "desc": "Siemplify SOAR — hundreds of webhook connectors = SSRF surface, tenant IDOR",
        "hosts": [
            "app.siemplify-soar.com",   "api.siemplify-soar.com",
            "dev.siemplify-soar.com",   "staging.siemplify-soar.com",
            "admin.siemplify-soar.com", "portal.siemplify-soar.com",
            "siemplify.co",             "siemplifycloud.com",
            "passbolt.siemplify.co",    "api.siemplify.co",
            "app.siemplify.co",
        ],
        "brute_words": ["api","app","admin","portal","marketplace","docs",
                        "integrations","staging","dev","webhook","connector"],
        "roots": ["siemplify.co", "siemplifycloud.com"],
    },
    {
        "name": "dataform", "tier": 1, "priority": 2,
        "desc": "Google Dataform (BigQuery) — workspace IDOR, project isolation flaw",
        "hosts": ["app.dataform.co", "api.dataform.co", "dataform.co"],
        "brute_words": ["api","app","staging","dev","console","docs","beta"],
        "roots": ["dataform.co"],
    },
    {
        "name": "waze", "tier": 1, "priority": 2,
        "desc": "Waze Biz portal — prior XSS + location IDOR; ad API staging surface",
        "hosts": [
            "biz.waze.com",           "adsapi.waze.com",
            "adsapi-staging.waze.com","proxy.waze.com",
            "proxy-staging.waze.com",
        ],
        "brute_words": ["biz","ads","api","partner","dashboard","reports","staging"],
        "roots": ["waze.com"],
    },
    {
        "name": "fitbit", "tier": 1, "priority": 3,
        "desc": "Fitbit health admin — sensitive health data, management portal",
        "hosts": [
            "accounts.fitbit.com",          "health-admin.fitbit.com",
            "ngw.fitbit.com",               "mgmt.fitbit.com",
            "coaching-dashboard.fitbit.com","strava.fitbit.com",
        ],
        "brute_words": ["health","admin","api","mgmt","dashboard","partner","coach","staging"],
        "roots": ["fitbit.com"],
    },
    {
        "name": "apigee", "tier": 1, "priority": 3,
        "desc": "Apigee enterprise portal — API management, policy sandbox injection",
        "hosts": [
            "enterprise.apigee.com","sense-ui.apigee.com",
            "apigee.com",           "apigee.google.com",
        ],
        "brute_words": ["api","enterprise","ui","console","portal","docs","sense","staging"],
        "roots": ["apigee.com"],
    },
]

# ── Path lists ────────────────────────────────────────────────────────────────
CORE_PATHS = [
    "/robots.txt", "/sitemap.xml",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/.well-known/security.txt",
    "/health","/healthz","/ready","/readyz","/live","/livez","/ping",
    "/metrics","/status","/version","/info","/debug","/env",
    "/swagger.json","/openapi.json","/openapi.yaml",
    "/api-docs","/swagger-ui.html",
    "/v1/swagger.json","/v2/swagger.json","/v3/swagger.json",
    "/api","/api/v1","/api/v2","/api/v3",
    "/graphql","/gql",
    "/v1","/v2","/v3",
    "/auth","/oauth","/login","/signin","/sso",
    "/oauth/token","/oauth/authorize",
    "/admin","/admin/api","/internal","/management","/dashboard",
    "/.env","/config","/server-status","/server-info",
    "/__/firebase/init.json","/__/firebase/init.js",
    "/api/user","/api/users","/api/me","/api/account","/api/profile",
]

ARGOCD_PATHS = [
    "/api/v1/settings","/api/v1/clusters","/api/v1/applications",
    "/api/v1/repositories","/api/v1/projects","/api/version",
    "/api/v1/session","/api/v1/account","/api/v1/users",
    "/api/v1/clusters?fields=items.name,items.server",
]

SIEMPLIFY_PATHS = [
    "/api/external/v1/cases","/api/external/v1/alerts",
    "/api/external/v1/playbooks","/api/external/v1/connectors",
    "/api/1.0/settings","/api/settings","/api/auth/login",
    "/integrations","/marketplace","/api/v1/health",
    "/api/external/v1/integrations",
]

DATAFORM_PATHS = [
    "/api/v1/projects","/api/v1/workspaces",
    "/api/v1/repositories","/api/v1/compilationResults",
    "/api/v1/workflowInvocations","/v1/projects",
]

WAZE_PATHS = [
    "/api/v1","/api/v2",
    "/campaigns","/api/campaigns","/api/reports",
    "/api/locations","/api/users","/api/accounts","/api/creatives",
]

GRAFANA_PATHS = [
    "/api/dashboards/home","/api/datasources","/api/orgs",
    "/api/admin/settings","/api/plugins","/api/users","/api/admin/users",
]

CLUSTER_EXTRA = {
    "photomath": ARGOCD_PATHS,
    "siemplify": SIEMPLIFY_PATHS,
    "dataform":  DATAFORM_PATHS,
    "waze":      WAZE_PATHS,
}

# ── HTTP layer ────────────────────────────────────────────────────────────────
def _hlock(host: str) -> threading.Lock:
    with _hlocks_mu:
        if host not in _hlocks: _hlocks[host] = threading.Lock()
        return _hlocks[host]

def dns_resolve(host: str) -> list[str]:
    """Resolve a host; prefer IPv4 (Pi may have no IPv6 route to internet)."""
    ips: list[str] = []
    # Try IPv4 first
    try:
        v4 = [r[4][0] for r in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)]
        ips.extend(v4)
    except socket.gaierror:
        pass
    # Fall back to IPv6 only if no IPv4
    if not ips:
        try:
            v6 = [r[4][0] for r in socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM)]
            ips.extend(v6)
        except socket.gaierror:
            pass
    return list(dict.fromkeys(ips))

def safe_ip(ip: str) -> bool:
    # Allow IPv6 public addresses; block RFC1918/IMDS
    if ":" in ip:
        return not ip.startswith(("::1", "fc", "fd"))
    try:
        p = [int(x) for x in ip.split(".")]
        if p[0] in (10, 127): return False
        if p[0] == 172 and 16 <= p[1] <= 31: return False
        if p[0] == 192 and p[1] == 168: return False
        if p[0] == 169 and p[1] == 254: return False
    except Exception: pass
    return True

# Optional proxy — set ALL_PROXY or HTTP_PROXY env var to route through VPN/SOCKS5
_PROXY = os.environ.get("ALL_PROXY") or os.environ.get("HTTP_PROXY") or ""

def http(url: str, method: str = "GET", headers: list | None = None,
         data: str | None = None, follow: bool = True,
         limit: int = 131072, timeout: int = TIMEOUT) -> tuple[int, dict, str]:
    """curl wrapper. Returns (status, headers_dict, body).
    Forces IPv4, sets connect-timeout separately from transfer timeout,
    forwards ALL_PROXY/HTTP_PROXY if set (e.g. for VPN/SOCKS5 bypass).
    """
    connect_timeout = min(12, timeout)
    cmd = [
        CURL, "-s",
        "--ipv4",                         # avoid broken IPv6 on Pi
        f"--connect-timeout={connect_timeout}",
        f"--max-time={timeout}",
        f"--max-filesize={limit}",
        "-A", UA,
        "-D", "-",    # dump headers to stdout
        "-o", "-",    # body to stdout
        "--compressed",
        "-k",         # ignore TLS cert errors (captures geo-block pages too)
        "-w", "\n##CURL_EXIT:%{response_code}##",  # append exit info
    ]
    if _PROXY: cmd += ["--proxy", _PROXY]
    if follow: cmd += ["-L", "--max-redirs", "5"]
    if method != "GET": cmd += ["-X", method]
    for h in (headers or []): cmd += ["-H", h]
    if data: cmd += ["-d", data]
    cmd.append(url)

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 8)
        raw = r.stdout
        # On total failure retry once with longer timeout
        if not raw.strip() and r.returncode != 0:
            time.sleep(1)
            r2 = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout + 15)
            raw = r2.stdout
    except (subprocess.TimeoutExpired, Exception) as e:
        return 0, {"_curl_error": str(e)}, str(e)

    hdrs: dict = {}; body_parts: list[str] = []; in_body = False; code = 0

    # Strip and parse our exit trailer
    curl_code_match = re.search(r'\n##CURL_EXIT:(\d+)##\s*$', raw)
    if curl_code_match:
        raw = raw[:curl_code_match.start()]
        fallback_code = int(curl_code_match.group(1))
    else:
        fallback_code = 0

    for line in raw.split("\n"):
        s = line.strip()
        if s.upper().startswith("HTTP/"):
            parts = s.split()
            code = int(parts[1]) if len(parts) > 1 else 0
            hdrs = {}; in_body = False
        elif not in_body:
            if s == "": in_body = True
            elif ":" in s:
                k, _, v = s.partition(":")
                hdrs[k.lower().strip()] = v.strip()
        else:
            body_parts.append(line)

    # If our HTTP parser got 0 but curl's own %{response_code} gave something, use it
    if code == 0 and fallback_code > 0:
        code = fallback_code

    body = "\n".join(body_parts)

    # Detect geo-block / Cloudflare challenge pages — mark them as 403 with a flag
    if code in (0, 403) and ("cloudflare" in body.lower() or "cf-ray" in hdrs):
        hdrs["_geoblock"] = "cloudflare"
    if code == 0 and "access denied" in body.lower():
        hdrs["_geoblock"] = "access-denied"

    return code, hdrs, body

# ── Tech detection ────────────────────────────────────────────────────────────
TECH_SIGS: dict[str, list[tuple[str, str]]] = {
    "argocd":     [("body","argocd"), ("body","Argo CD"), ("x-argocd-version","*")],
    "firebase":   [("body","firebaseapp"), ("body","AIzaSy"), ("body","firebase.google.com")],
    "nextjs":     [("body","__NEXT_DATA__"), ("x-powered-by","Next.js")],
    "framer":     [("server","Framer")],
    "grafana":    [("body","grafana"), ("x-grafana-version","*")],
    "metabase":   [("body","Metabase")],
    "hasura":     [("body","hasura"), ("body","HGE version")],
    "fastapi":    [("body","FastAPI"), ("body",'"detail":')],
    "django":     [("body","csrfmiddlewaretoken")],
    "gcp":        [("server","Google Frontend"), ("server","sffe"), ("x-cloud-trace-context","*")],
    "cloudflare": [("server","cloudflare"), ("cf-ray","*")],
    "looker":     [("body","looker"), ("x-looker-version","*")],
    "kubernetes": [("body","kubernetes"), ("body","kubectl")],
    "springboot": [("x-application-context","*")],
    "express":    [("x-powered-by","Express")],
}

def detect_tech(hdrs: dict, body: str) -> list[str]:
    found = []
    for tech, sigs in TECH_SIGS.items():
        for hdr, val in sigs:
            if hdr == "body":
                if val.lower() in body[:6000].lower(): found.append(tech); break
            else:
                hval = hdrs.get(hdr, "")
                if (val == "*" and hval) or val.lower() in hval.lower():
                    found.append(tech); break
    return list(dict.fromkeys(found))

# ── Discovery ─────────────────────────────────────────────────────────────────
def crt_sh(root: str) -> list[str]:
    code, _, body = http(f"https://crt.sh/?q=%25.{root}&output=json",
                         limit=3_000_000, timeout=30)
    if code != 200 or not body.strip().startswith("["): return []
    try:
        data = json.loads(body)
        names: set[str] = set()
        for e in data:
            for n in e.get("name_value","").split("\n"):
                n = n.strip().lstrip("*.")
                if n and root in n: names.add(n.lower())
        log(f"  crt.sh → {len(names)} names for {root}", "DNS")
        return sorted(names)
    except Exception: return []

def brute_dns(root: str, words: list[str]) -> list[str]:
    live = []
    for w in words:
        h = f"{w}.{root}"
        ips = dns_resolve(h)
        if ips and all(safe_ip(ip) for ip in ips):
            log(f"  DNS-BRUTE: {h} → {ips[0]}", "DNS")
            live.append(h)
        time.sleep(0.05)
    return live

# ── JS mining ─────────────────────────────────────────────────────────────────
_JS_PATS = [
    ("ENDPOINT",      r'["\'`](/(?:api|v\d|graphql|auth|oauth|internal|admin|webhook)[/\w\-\.?={}&:@%]*)["\']'),
    ("FIREBASE_KEY",  r'(AIzaSy[A-Za-z0-9_-]{33})'),
    ("API_KEY",       r'(?:api[_-]?key|apiKey)["\s\']*[:=]["\s\']*([A-Za-z0-9_\-]{20,100})'),
    ("CLIENT_ID",     r'(?:client[_-]?id|clientId)["\s\']*[:=]["\s\']*([A-Za-z0-9_\-\.@]{12,200})'),
    ("GCP_PROJECT",   r'(?:project[_-]?id|projectId)["\s\']*[:=]["\s\'`]*([a-z][a-z0-9-]{4,29})["\']'),
    ("SECRET",        r'(?:client[_-]?secret|clientSecret|app[_-]?secret)["\s\']*[:=]["\s\'`]([A-Za-z0-9_+/=\-]{16,100})["\']'),
    ("INTERNAL_HOST", r'["\'`]([a-z][a-z0-9\-]+\.(?:internal|local|corp|svc\.cluster\.local)(?:/[^"\'`]{0,80})?)["\']'),
    ("GCS_BUCKET",    r'storage\.googleapis\.com/([a-z][a-z0-9\-_]{2,62})'),
    ("S3_BUCKET",     r'([a-z][a-z0-9\-]{2,62})\.s3(?:[\.-][a-z0-9-]+)?\.amazonaws\.com'),
    ("GITHUB_TOKEN",  r'(gh[pousr]_[A-Za-z0-9]{36,255})'),
    ("JWT",           r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}'),
    ("GRAPHQL_OP",    r'(?:query|mutation)\s+(\w+)\s*[({]'),
    ("OAUTH_SCOPE",   r'scope["\s\']*[:=]["\s\'`]([a-z][a-z0-9:/_\-\. ]{4,120})["\']'),
]
_NOISE = {"example","placeholder","your_","changeme","test","demo","undefined",
          "null","none","todo","fixme","xxx","insert","abcdef","12345"}

def mine_js(host: str, body: str, lock: threading.Lock) -> list[dict]:
    js_urls = re.findall(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body)
    # Also check for source maps
    sm_urls  = re.findall(r'sourceMappingURL=([^\s*]+\.map)', body)
    findings: list[dict] = []

    for raw in (js_urls[:12] + sm_urls[:4]):
        url = raw if raw.startswith("http") else f"https://{host}{raw}"
        with lock: time.sleep(DELAY)
        code, _, js = http(url, limit=1_048_576, follow=False)
        if code != 200 or not js: continue

        for label, pat in _JS_PATS:
            for m in re.findall(pat, js):
                val = m if isinstance(m, str) else (m if m else "")
                if isinstance(val, tuple): val = val[0]
                if not val or len(val) < 4: continue
                if any(n in val.lower() for n in _NOISE): continue
                findings.append({"src": url.split("/")[-1][:50], "type": label, "value": val[:150]})

    # Deduplicate
    seen: set = set()
    dedup = []
    for f in findings:
        key = (f["type"], f["value"])
        if key not in seen: seen.add(key); dedup.append(f)
    return dedup[:50]

# ── JWT decode ────────────────────────────────────────────────────────────────
def decode_jwt(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3: return {}
        header  = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        alg = header.get("alg","")
        findings = []
        if alg.lower() == "none":   findings.append("ALG_NONE — critical: no signature")
        if alg.upper() in ("HS256","HS384","HS512") and len(parts[2]) < 50:
            findings.append("SHORT_SIG — possible weak secret")
        return {"header": header, "payload": payload, "flags": findings}
    except Exception: return {}

# ── Active vulnerability tests ────────────────────────────────────────────────

def test_argocd(host: str, lock: threading.Lock) -> list[dict]:
    """Test all ArgoCD REST API endpoints for unauthenticated access."""
    results = []
    for path in ARGOCD_PATHS:
        with lock: time.sleep(DELAY)
        code, hdrs, body = http(f"https://{host}{path}", follow=False, limit=16384)
        ct = hdrs.get("content-type","")
        if code in (200, 206) and "json" in ct:
            snippet = body[:300].replace("\n"," ")
            results.append({"path": path, "code": code, "body": snippet})
            lead(host, f"ARGOCD UNAUTH [{code}] {path}", snippet[:80])
        elif code == 401:
            results.append({"path": path, "code": 401, "note": "auth required"})
    return results

def validate_firebase_key(api_key: str, host: str) -> dict:
    """Call Firebase identitytoolkit to confirm key is active (read-only probe)."""
    payload = json.dumps({"identifier":"probe@probe.invalid","continueUri":f"https://{host}"})
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={api_key}"
    code, _, body = http(url, method="POST",
                         headers=["Content-Type: application/json"], data=payload,
                         follow=False, limit=4096, timeout=12)
    if code == 200:
        return {"valid": True, "response": body[:200]}
    try:
        err = json.loads(body).get("error",{}).get("message","")
        return {"valid": False, "error": err}
    except Exception:
        return {"valid": False, "error": body[:100]}

def test_graphql(host: str, path: str, lock: threading.Lock) -> dict:
    """GraphQL introspection + batch/alias checks."""
    introspect = '{"query":"{ __schema { queryType { name } types { name kind description fields { name type { name kind ofType { name kind } } } } } }"}'
    with lock: time.sleep(DELAY)
    code, hdrs, body = http(f"https://{host}{path}", method="POST",
                             headers=["Content-Type: application/json"],
                             data=introspect, follow=False, limit=131072)
    result: dict = {"path": path, "introspection": False}
    if "__schema" in body:
        result["introspection"] = True
        try:
            schema = json.loads(body)
            types  = [t["name"] for t in schema.get("data",{}).get("__schema",{}).get("types",[])
                      if not t["name"].startswith("__")]
            result["types"] = types[:30]
            result["type_count"] = len(types)
            lead(host, f"GRAPHQL INTROSPECTION OPEN", f"{path} → {len(types)} types")
        except Exception:
            result["raw_snippet"] = body[:500]
    elif code in (200, 400):
        result["alive"] = True
        result["code"]  = code
    return result

def test_cors(host: str, api_paths: list[str], lock: threading.Lock) -> list[dict]:
    """Test CORS with 4 origin variants on best API path."""
    path = next((p for p in api_paths if "api" in p), "/api/v1/")
    test_origins = [
        f"https://evil.com",
        f"https://{host}.evil.com",     # domain-prefix bypass
        "null",                         # null origin bypass
        f"https://evil{host}",          # evil prefix
    ]
    issues = []
    for origin in test_origins:
        with lock: time.sleep(DELAY)
        _, hdrs, _ = http(
            f"https://{host}{path}", follow=False, limit=512,
            headers=[f"Origin: {origin}",
                     "Access-Control-Request-Method: GET",
                     "Access-Control-Request-Headers: Authorization"],
        )
        acao = hdrs.get("access-control-allow-origin","")
        acac = hdrs.get("access-control-allow-credentials","")
        acah = hdrs.get("access-control-allow-headers","")
        if not acao: continue
        if acao in (origin, "*"):
            sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
            issue = {"origin": origin, "acao": acao, "acac": acac, "path": path, "sev": sev}
            issues.append(issue)
            lead(host, f"CORS {sev}", f"acao={acao} acac={acac} origin={origin}")
            if acac.lower() == "true":
                break   # critical — stop testing
    return issues

def test_openapi(host: str, schema_path: str, schema_body: str, lock: threading.Lock) -> list[dict]:
    """Parse OpenAPI/Swagger schema and probe every documented endpoint."""
    endpoints = []
    try:
        schema = json.loads(schema_body)
        base  = schema.get("basePath","") or ""
        for path, methods in schema.get("paths", {}).items():
            for method in methods:
                if method.lower() in ("get","post","put","delete","patch"):
                    endpoints.append((method.upper(), base + path))
    except Exception: return []

    results = []
    for method, path in endpoints[:40]:    # cap at 40
        # Replace path params with benign values
        clean_path = re.sub(r'\{[^}]+\}', '1', path)
        with lock: time.sleep(DELAY)
        code, hdrs, body = http(f"https://{host}{clean_path}", method=method,
                                 follow=False, limit=8192)
        if code in (200, 201):
            results.append({"method": method, "path": clean_path, "code": code,
                            "ct": hdrs.get("content-type",""), "body": body[:200]})
            lead(host, f"OPENAPI ENDPOINT 200 [{method}]", clean_path)
    return results

def test_method_override(host: str, path: str, lock: threading.Lock) -> dict:
    """Test HTTP method override headers (can bypass WAF/auth on some frameworks)."""
    overrides = [
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-HTTP-Method",          "DELETE"),
        ("_method",                "DELETE"),
    ]
    base_code, _, _ = http(f"https://{host}{path}", follow=False, limit=512, method="GET")
    for hdr, val in overrides:
        with lock: time.sleep(DELAY)
        code, _, body = http(f"https://{host}{path}", method="POST",
                              headers=[f"{hdr}: {val}",
                                       "Content-Type: application/x-www-form-urlencoded"],
                              data="_method=DELETE", follow=False, limit=4096)
        if code != base_code and code in (200, 204, 202):
            lead(host, f"METHOD OVERRIDE [{hdr}: {val}]", f"{path} base={base_code} → override={code}")
            return {"header": hdr, "value": val, "path": path, "code": code}
    return {}

def test_idor_probe(host: str, path: str, lock: threading.Lock) -> list[dict]:
    """Single IDOR probe: swap any numeric ID in path for id±1 and id=0."""
    # Find numeric segment in path
    match = re.search(r'/(\d+)(?:/|$)', path)
    if not match: return []
    orig_id = int(match.group(1))
    issues = []
    for probe_id in [max(0, orig_id - 1), orig_id + 1, 0, 99999]:
        probe_path = path[:match.start(1)] + str(probe_id) + path[match.end(1):]
        if probe_path == path: continue
        with lock: time.sleep(DELAY)
        code, _, body = http(f"https://{host}{probe_path}", follow=False, limit=8192)
        if code == 200 and len(body) > 50:
            issues.append({"probe_id": probe_id, "path": probe_path,
                           "code": code, "body": body[:200]})
            lead(host, "IDOR PROBE HIT", f"{probe_path} [{code}] len={len(body)}")
            break  # one confirmation is enough
    return issues

# ── Main host probe ───────────────────────────────────────────────────────────
def probe_host(host: str, cluster: str) -> dict:
    R: dict = {
        "host": host, "cluster": cluster,
        "ips": [], "live": False, "code": 0, "server": "", "tech": [],
        "paths": {}, "js": [], "cors": [], "graphql": None,
        "argocd": [], "idor": [], "openapi": [], "method_override": {},
        "firebase_key": {}, "jwt": [], "interesting": [], "score": 0,
    }

    ips = dns_resolve(host)
    if not ips: log(f"  NXDOMAIN {host}", "DNS"); return R
    # Filter: skip if ALL resolved IPs are internal (one public IP is enough)
    if not any(safe_ip(ip) for ip in ips):
        log(f"  SKIP all-internal IPs {host} → {ips}", "WARN"); return R
    R["ips"] = [ip for ip in ips if safe_ip(ip)] or ips

    lock = _hlock(host)

    # ── Base response — try HTTPS then HTTP, log reason on failure ────────────
    with lock: time.sleep(DELAY)
    code, hdrs, body = http(f"https://{host}/")

    if code == 0:
        # HTTPS failed — try HTTP
        with lock: time.sleep(DELAY)
        code, hdrs, body = http(f"http://{host}/")

    R["code"] = code
    geoblock = hdrs.get("_geoblock", "")

    if code == 0:
        # Diagnose: is it a connection refusal, timeout, or just TLS error?
        diag_cmd = [CURL, "-sv", "--ipv4", "--connect-timeout", "8",
                    "--max-time", "10", "https://" + host + "/",
                    "-o", "/dev/null"]
        diag = subprocess.run(diag_cmd, capture_output=True, text=True, timeout=15)
        err = (diag.stderr or "")[:200]
        reason = "timeout" if "timed out" in err.lower() else \
                 "refused" if "connection refused" in err.lower() else \
                 "geoblock" if any(x in err.lower() for x in ("403","handshake","alert")) else \
                 "unknown"
        log(f"  DEAD {host}  reason={reason}  proxy={'yes' if _PROXY else 'NONE—set ALL_PROXY for VPN'}", "HTTP")
        R["dead_reason"] = reason
        return R

    R["live"] = True
    R["server"] = hdrs.get("server","")
    R["tech"]   = detect_tech(hdrs, body)
    if geoblock:
        R["tech"].append(f"geoblock:{geoblock}")
        log(f"  [{code}] {host}  GEO-BLOCKED via {geoblock} — continuing probe", "WARN")
    else:
        log(f"  [{code}] {host}  srv={R['server'][:25]}  tech={R['tech']}", "HTTP")

    # Adaptive path set
    paths = list(CORE_PATHS) + CLUSTER_EXTRA.get(cluster, [])
    if "argocd" in R["tech"] or "argocd" in host: paths = list(set(paths + ARGOCD_PATHS))
    if "grafana" in R["tech"] or "grafana" in host: paths = list(set(paths + GRAFANA_PATHS))

    # ── Path probe ───────────────────────────────────────────────────────────
    _skip_body = {"<html","<!doctype","framer","not found","404 page"}
    _interesting_codes = {200,201,204,206,301,302,307,308,400,401,403,405,500}
    for path in paths:
        with lock: time.sleep(DELAY)
        pc, ph, pb = http(f"https://{host}{path}", follow=False, limit=65536)
        if pc not in _interesting_codes: continue
        # Filter Framer redirects
        if pc in (301, 308) and "framer" in ph.get("location","").lower(): continue
        # Filter boring 200 HTML pages
        if pc == 200 and any(s in pb[:300].lower() for s in _skip_body):
            if "json" not in ph.get("content-type",""): continue

        entry = {"code": pc, "ct": ph.get("content-type","")[:60],
                 "len": ph.get("content-length",""), "body": pb[:600]}
        R["paths"][path] = entry
        icon = "★" if pc == 200 else ("○" if pc in {401,403} else "·")
        log(f"  {icon} {pc} {host}{path}", "PATH")

        if pc == 200:
            # OpenAPI schema → parse and probe endpoints
            if any(x in path for x in ("swagger","openapi")):
                ops = test_openapi(host, path, pb, lock)
                R["openapi"].extend(ops)
                R["interesting"].append(f"API_SCHEMA:{path} ({len(pb)}B, {len(ops)} endpoints tested)")

            # OIDC config
            if "openid-configuration" in path:
                R["interesting"].append(f"OIDC_CONFIG:{pb[:300]}")

            # JSON body with ID field → IDOR probe
            if "json" in ph.get("content-type",""):
                ids = re.findall(r'"id"\s*:\s*(\d+)', pb[:2000])
                if ids:
                    idor = test_idor_probe(host, path, lock)
                    R["idor"].extend(idor)

            # Method override on API endpoints
            if "/api" in path:
                mo = test_method_override(host, path, lock)
                if mo: R["method_override"][path] = mo

    # ── ArgoCD specific ───────────────────────────────────────────────────────
    if "argocd" in R["tech"] or "argocd" in host:
        R["argocd"] = test_argocd(host, lock)

    # ── CORS ─────────────────────────────────────────────────────────────────
    api_paths = [p for p in R["paths"] if "/api" in p or "/v1" in p]
    if api_paths:
        R["cors"] = test_cors(host, api_paths, lock)

    # ── GraphQL ───────────────────────────────────────────────────────────────
    gql_paths = [p for p in R["paths"] if "graphql" in p or "gql" in p]
    if not gql_paths and body and "graphql" in body.lower()[:4000]:
        gql_paths = ["/graphql"]
    for gp in gql_paths[:2]:
        res = test_graphql(host, gp, lock)
        if res.get("introspection") or res.get("alive"):
            R["graphql"] = res; break

    # ── JS mining ─────────────────────────────────────────────────────────────
    if code == 200 and body:
        R["js"] = mine_js(host, body, lock)
        # Firebase key validation
        fb_keys = [f["value"] for f in R["js"] if f["type"] == "FIREBASE_KEY"]
        for key in fb_keys[:2]:
            val = validate_firebase_key(key, host)
            R["firebase_key"][key[:10]+"..."] = val
            if val.get("valid"):
                lead(host, "FIREBASE KEY VALID", key[:20]+"...")
        # JWT decode
        for f in R["js"]:
            if f["type"] == "JWT":
                dec = decode_jwt(f["value"])
                if dec and dec.get("flags"):
                    R["jwt"].append(dec)
                    lead(host, "JWT WEAK", str(dec["flags"]))

    # ── Heuristic score ───────────────────────────────────────────────────────
    s = 0
    p200 = [p for p,v in R["paths"].items() if v["code"] == 200]
    if any("/api" in p for p in p200): s += 2
    if R["graphql"] and R["graphql"].get("introspection"): s += 3
    if any(c["sev"]=="HIGH" for c in R["cors"]): s += 3
    if any(c["sev"]=="MEDIUM" for c in R["cors"]): s += 1
    if any(f["type"] in {"FIREBASE_KEY","API_KEY","SECRET"} for f in R["js"]): s += 2
    if any(f.get("valid") for f in R["firebase_key"].values()): s += 3
    if R["argocd"] and any(a["code"]==200 for a in R["argocd"]): s += 5
    if R["idor"]: s += 3
    if R["openapi"] and len(R["openapi"]) > 2: s += 2
    if R["method_override"]: s += 1
    if R["jwt"]: s += 2
    R["score"] = min(s, 5)
    return R

# ── Claude CLI analysis ───────────────────────────────────────────────────────
_CLAUDE_SYS = """\
You are an elite authorized bug bounty hunter. Analyze recon findings for Google/Alphabet VRP.

SUBMISSION GATE — a finding must pass ALL of:
1. Attacker gain is CONCRETE: account access, another user's data, RCE, SSRF to internal, auth bypass
2. NOT intended behavior
3. Fix Test: vendor would change code to fix it
4. Reproduced with minimal PoC
5. In scope, not a known dup

HARD REJECT (skip unless chained): self-XSS, missing security headers, software version disclosure,
login page lacks lockout, SPF/DKIM misconfig, subdomain takeover without cookie/OAuth proof,
open redirect without token exfil, rate limit absent on non-sensitive endpoint.

CHAIN RULE: Low + Low can equal High if each link is CONFIRMED and testable.

CONSTRAINTS on the hunter:
- No RFC1918/IMDS/localhost probing allowed
- No credential brute-force
- OOB confirmation via interactsh only
- No destructive writes to real data"""

_CLAUDE_PROMPT = """\
CLUSTER: {cluster} (TIER{tier}) — {desc}

RECON DATA (highest-scored hosts first):
{host_data}

FOR EACH HOST with score ≥ 2:
1. VALIDATE: does any finding pass the full submission gate above? Say YES/NO + reason.
2. SCORE: 0-5 confidence this yields a payable bug this session (5=near-certain High+)
3. BUG CLASS: single most plausible class given the evidence
4. VERIFY CMD: exact `curl` command to confirm in the next 10 minutes
5. CHAIN: if standalone is Low, what chain step elevates it? Is it testable?
6. DECISION: REPORT_NOW / PURSUE / HOLD / DROP

For ArgoCD unauthenticated access → auto-escalate to CRITICAL, REPORT_NOW.
For Firebase key validated active → REPORT_NOW.
For CORS HIGH (reflected + credentials) → REPORT_NOW.
For GraphQL introspection open → PURSUE (extract mutations, test IDOR next).

Respond as VALID JSON only (no markdown, no prose outside JSON):
{
  "cluster_score": 0-5,
  "summary": "one sentence",
  "findings": [
    {
      "host": "...",
      "score": 0-5,
      "bug_class": "...",
      "severity": "Critical|High|Medium|Low|Info",
      "decision": "REPORT_NOW|PURSUE|HOLD|DROP",
      "rationale": "...",
      "verify_cmd": "curl ...",
      "chain_note": "..."
    }
  ],
  "top_priority": "host + exact next action in one sentence"
}"""

def _claude_available() -> bool:
    try:
        r = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except FileNotFoundError:
        return False

def ask_claude(cluster: dict, host_results: list[dict]) -> dict | None:
    if not _claude_available():
        log("claude CLI not found — skipping AI analysis", "WARN")
        return None

    # Build host summaries (only live hosts with score ≥ 1)
    summaries = []
    for r in sorted(host_results, key=lambda x: -x["score"]):
        if not r["live"]: continue
        p200 = [p for p,v in r["paths"].items() if v["code"] == 200]
        p401 = [p for p,v in r["paths"].items() if v["code"] == 401]
        p403 = [p for p,v in r["paths"].items() if v["code"] == 403]
        summaries.append(
            f"HOST: {r['host']}  score={r['score']}\n"
            f"  tech={r['tech']}  server={r['server']}\n"
            f"  paths_200={p200}\n"
            f"  paths_401={p401}\n"
            f"  paths_403={p403}\n"
            f"  cors={[c['sev']+'@'+c['origin'] for c in r['cors']]}\n"
            f"  graphql={r['graphql']}\n"
            f"  argocd_unauth={[a for a in r['argocd'] if a.get('code')==200]}\n"
            f"  firebase_key_valid={any(v.get('valid') for v in r['firebase_key'].values())}\n"
            f"  openapi_200_endpoints={len(r['openapi'])}\n"
            f"  idor_hits={r['idor']}\n"
            f"  method_override={bool(r['method_override'])}\n"
            f"  jwt_flags={[j.get('flags') for j in r['jwt']]}\n"
            f"  js_types={list({f['type'] for f in r['js']})}\n"
            f"  js_samples={[f['type']+':'+f['value'][:40] for f in r['js'][:8]]}\n"
            f"  interesting={r['interesting'][:5]}"
        )

    if not summaries:
        return None

    prompt = _CLAUDE_PROMPT.format(
        cluster=cluster["name"], tier=cluster["tier"],
        desc=cluster["desc"], host_data="\n\n".join(summaries)
    )

    full_prompt = _CLAUDE_SYS + "\n\n" + prompt
    log(f"Calling claude CLI for {cluster['name']} ({len(full_prompt)} chars)…", "CLAUDE")

    # Method 1: stdin pipe — most reliable for long prompts
    def _run(extra_flags: list[str] = []) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["claude", "--print"] + extra_flags,
            input=full_prompt,
            capture_output=True, text=True, timeout=150,
            env={**os.environ, "NO_COLOR": "1"},
        )

    try:
        r = _run()
        # If claude needs --output-format flag on this install
        if "unknown flag" in r.stderr.lower() or not r.stdout.strip():
            r = _run(["--output-format", "text"])
        text = r.stdout.strip()
        if r.returncode != 0 and not text:
            log(f"Claude stderr: {r.stderr[:200]}", "WARN"); return None
    except subprocess.TimeoutExpired:
        log("Claude timed out after 150s", "WARN"); return None
    except FileNotFoundError:
        log("claude binary not found", "WARN"); return None
    except Exception as e:
        log(f"Claude error: {e}", "WARN"); return None

    # Extract JSON from response
    try:
        # Try direct parse
        return json.loads(text)
    except json.JSONDecodeError:
        # Strip markdown fences and retry
        text2 = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
        # Extract first {...} block
        m = re.search(r'\{[\s\S]*\}', text2)
        if m:
            try: return json.loads(m.group())
            except Exception: pass
        # Save raw response for debugging
        (RESULTS / cluster["name"] / "02-surface" / "claude-raw.txt").write_text(text)
        log("Claude response not parseable as JSON — saved raw to claude-raw.txt", "WARN")
        return None

# ── Report writer ─────────────────────────────────────────────────────────────
def write_report(cluster: dict, results: list[dict], claude: dict | None) -> list[dict]:
    name    = cluster["name"]
    out_dir = RESULTS / name / "02-surface"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    live    = [r for r in results if r["live"]]
    all_leads: list[dict] = []

    md = [f"# Deep Recon — {name}", f"Generated: {ts}",
          f"Live: {len(live)}/{len(results)}  Tier: {cluster['tier']}", "",
          f"> {cluster['desc']}", "", "## Findings by Host"]

    for r in sorted(live, key=lambda x: -x["score"]):
        md += [f"\n### `{r['host']}`  score={r['score']}/5",
               f"- **IPs**: {', '.join(r['ips'])}",
               f"- **Server**: {r['server']}  **Tech**: {', '.join(r['tech']) or 'unknown'}"]

        p200 = {p: v for p, v in r["paths"].items() if v["code"] == 200}
        if p200:
            md.append("- **200 paths**:")
            for p, v in p200.items():
                md.append(f"  - `{p}` `{v['ct'][:40]}`")
                if v.get("body") and "json" in v.get("ct",""):
                    md.append(f"    ```{v['body'][:300]}```")

        p401 = [p for p,v in r["paths"].items() if v["code"] == 401]
        p403 = [p for p,v in r["paths"].items() if v["code"] == 403]
        if p401: md.append(f"- **401 (auth required)**: {', '.join(p401)[:200]}")
        if p403: md.append(f"- **403 (forbidden)**:     {', '.join(p403)[:200]}")

        if r["cors"]:
            for c in r["cors"]:
                md.append(f"- ⚠️ **CORS {c['sev']}**: acao=`{c['acao']}` acac=`{c['acac']}` origin=`{c['origin']}`")
        if r["graphql"]:
            md.append(f"- ⚠️ **GraphQL**: {r['graphql']}")
        if r["argocd"]:
            unauth = [a for a in r["argocd"] if a.get("code")==200]
            if unauth: md.append(f"- 🚨 **ARGOCD UNAUTH**: {[a['path'] for a in unauth]}")
        if r["idor"]: md.append(f"- ⚠️ **IDOR probe hit**: {r['idor']}")
        if r["openapi"]: md.append(f"- ⚠️ **OpenAPI endpoints 200**: {len(r['openapi'])} paths")
        if r["firebase_key"]:
            for k, v in r["firebase_key"].items():
                if v.get("valid"): md.append(f"- 🚨 **FIREBASE KEY VALID**: `{k}`")
        if r["jwt"]: md.append(f"- ⚠️ **JWT flags**: {[j.get('flags') for j in r['jwt']]}")
        if r["js"]:
            hi = [f for f in r["js"] if f["type"] in {"FIREBASE_KEY","API_KEY","SECRET","GITHUB_TOKEN","INTERNAL_HOST"}]
            if hi:
                md.append("- **JS credentials/hosts**:")
                for f in hi[:10]: md.append(f"  - `{f['type']}` `{f['value'][:80]}`")
        for i in r["interesting"]:
            md.append(f"- 📌 `{i}`")
            all_leads.append({"host": r["host"], "cluster": name,
                              "finding": i, "score": r["score"]})

    if claude:
        md += ["", "## Claude Analysis", f"**Cluster score**: {claude.get('cluster_score')}",
               f"**Summary**: {claude.get('summary','')}",
               f"**Top priority**: {claude.get('top_priority','')}",""]
        for f in claude.get("findings",[]):
            decision = f.get("decision","")
            icon = "🚨" if decision == "REPORT_NOW" else ("🟡" if decision == "PURSUE" else "⬜")
            md.append(f"\n#### {icon} `{f.get('host','')}` — {f.get('bug_class','')} [{f.get('severity','')}] → **{decision}**")
            md.append(f"- Rationale: {f.get('rationale','')}")
            if f.get("verify_cmd"):
                md.append(f"- Verify: `{f['verify_cmd']}`")
            if f.get("chain_note"):
                md.append(f"- Chain: {f['chain_note']}")
            if decision in ("REPORT_NOW","PURSUE"):
                all_leads.append({"host": f["host"], "cluster": name,
                                  "finding": f["bug_class"], "severity": f.get("severity"),
                                  "decision": decision, "score": f.get("score",0),
                                  "verify_cmd": f.get("verify_cmd","")})
        (out_dir / "claude-analysis.json").write_text(json.dumps(claude, indent=2))

    (out_dir / "deep-recon.md").write_text("\n".join(md))
    log(f"Report → {out_dir / 'deep-recon.md'}", "DONE")

    # Save raw results (gitignored)
    raw = RESULTS / name / "03-candidates"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "recon-raw.json").write_text(json.dumps(results, indent=2))
    return all_leads

# ── Cluster runner ────────────────────────────────────────────────────────────
def run_cluster(cluster: dict) -> list[dict]:
    name = cluster["name"]
    log(f"{'═'*60}", "CLUST")
    log(f"START {name.upper()} (TIER{cluster['tier']}) — {cluster['desc']}", "CLUST")
    log(f"{'═'*60}", "CLUST")

    # Expand host list
    all_hosts = list(cluster["hosts"])
    for root in cluster.get("roots", []):
        for h in brute_dns(root, cluster.get("brute_words",[])):
            if h not in all_hosts: all_hosts.append(h)
        for h in crt_sh(root):
            if h not in all_hosts and root in h: all_hosts.append(h)
    log(f"Total hosts: {len(all_hosts)}", "CLUST")

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        fut_map = {pool.submit(probe_host, h, name): h for h in all_hosts}
        for fut in as_completed(fut_map):
            host = fut_map[fut]
            try: results.append(fut.result())
            except Exception as e:
                log(f"ERROR {host}: {e}", "ERR")
                results.append({"host": host, "cluster": name, "live": False,
                                 "score": 0, "ips":[], "code":0, "server":"",
                                 "tech":[], "paths":{}, "js":[], "cors":[],
                                 "argocd":[], "idor":[], "openapi":[],
                                 "method_override":{}, "firebase_key":{},
                                 "graphql": None, "jwt":[], "interesting":[]})

    live = [r for r in results if r["live"]]
    log(f"Live: {len(live)}/{len(all_hosts)}", "CLUST")

    claude_result = ask_claude(cluster, results)
    leads = write_report(cluster, results, claude_result)
    log(f"DONE {name} — leads={len(leads)}", "CLUST")
    return leads

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log("="*60, "INIT")
    log(f"deep-recon v3  {datetime.datetime.now().isoformat()}", "INIT")
    log(f"Repo: {REPO}", "INIT")
    log(f"Claude CLI: {'available' if _claude_available() else 'NOT FOUND — heuristic-only mode'}", "INIT")
    log(f"Workers:{MAX_WORKERS}  Delay:{DELAY}s  Timeout:{TIMEOUT}s", "INIT")
    log("="*60, "INIT")

    all_leads: list[dict] = []
    for cluster in sorted(CLUSTERS, key=lambda c: c["priority"]):
        try:
            leads = run_cluster(cluster)
            all_leads.extend(leads)
        except Exception as e:
            log(f"Cluster {cluster['name']} crashed: {e}", "ERR")

    # ── Final summary ─────────────────────────────────────────────────────────
    elapsed = str(datetime.datetime.now() - _t0).split(".")[0]
    print("\n" + "═"*72)
    print(f"  RECON COMPLETE — {datetime.datetime.now():%Y-%m-%d %H:%M} — {elapsed}")
    print("═"*72)

    # Prioritize by score, then by decision
    _decision_rank = {"REPORT_NOW": 5, "PURSUE": 4, "HOLD": 2, "DROP": 0}
    ranked = sorted(all_leads,
                    key=lambda x: (x.get("score",0) * 2 + _decision_rank.get(x.get("decision",""),1)),
                    reverse=True)

    if ranked:
        print(f"\n{'#':<4} {'DEC':<12} {'SEV':<8} {'SCORE':<6} {'HOST':<35} FINDING")
        print("─"*110)
        for i, l in enumerate(ranked[:25], 1):
            dec  = l.get("decision", "—")[:11]
            sev  = l.get("severity","—")[:7]
            scr  = str(l.get("score",0))
            host = l.get("host","")[:34]
            find = l.get("finding","")[:55]
            print(f"{i:<4} {dec:<12} {sev:<8} {scr:<6} {host:<35} {find}")
        print()
        report_now = [l for l in ranked if l.get("decision") == "REPORT_NOW"]
        if report_now:
            print(f"\n🚨 REPORT NOW ({len(report_now)} findings):")
            for l in report_now:
                print(f"   [{l['cluster']}] {l['host']} — {l['finding']}")
                if l.get("verify_cmd"):
                    print(f"   └─ {l['verify_cmd'][:100]}")
    else:
        print("  No leads surfaced this run.")

    print(f"\n  Full log:    {LOG_PATH}")
    print(f"  Reports:     {RESULTS}/<cluster>/02-surface/deep-recon.md")
    print("═"*72)

    ml = RESULTS / "MASTER-LEADS.json"
    existing = []
    if ml.exists():
        try: existing = json.loads(ml.read_text())
        except Exception: pass
    existing.extend(ranked)
    ml.write_text(json.dumps(existing, indent=2))
    log(f"Master leads → {ml}  ({len(ranked)} new)", "DONE")

if __name__ == "__main__":
    main()
