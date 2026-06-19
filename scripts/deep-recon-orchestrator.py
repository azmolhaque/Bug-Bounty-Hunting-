#!/usr/bin/env python3
"""
deep-recon-orchestrator.py — Multi-target deep recon for Google/Alphabet VRP
Pi 5 deployment. Designed to run 2-4 hours unattended.

Usage:
    nohup python3 scripts/deep-recon-orchestrator.py 2>&1 | tee /tmp/recon-$(date +%Y%m%d-%H%M).log &

Covers 6 target clusters in priority order:
  1. Photomath  (TIER0 — ArgoCD + admin/internal subdomains)
  2. Siemplify  (TIER1 — SOAR platform + tenant subdomains)
  3. Dataform   (TIER1 — BigQuery DataForm)
  4. Waze       (TIER1 — biz portal + ad API)
  5. Fitbit     (TIER1 — health admin + management)
  6. Apigee     (TIER1 — enterprise portal)

Constraints honored:
  - Rate limit: 0.5s delay between requests to same host
  - Max 4 concurrent global requests
  - No requests to RFC1918, IMDS, or localhost
  - Passive DNS via socket only (no external DNS APIs that are network-blocked)
  - Benign probes only — no auth bypass attempts, no data modification
"""

import socket, ssl, json, re, os, sys, time, threading, datetime, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse, urljoin
import subprocess

# ── Constants ────────────────────────────────────────────────────────────────

RESULTS_BASE = Path(os.path.dirname(os.path.abspath(__file__))).parent / "results"
LOG_PATH = Path("/tmp/recon-orchestrator.log")
DELAY = 0.5           # seconds between requests to the same host
TIMEOUT = 18          # per-request HTTP timeout
MAX_WORKERS = 4       # total concurrent requests across all targets
UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
CURL = "/usr/bin/curl"

_log_lock = threading.Lock()
_host_locks = {}
_host_locks_lock = threading.Lock()
start_time = datetime.datetime.now()

# ── Target clusters ──────────────────────────────────────────────────────────

CLUSTERS = [
    {
        "name": "photomath",
        "tier": 0,
        "priority": 1,
        "hosts": [
            # Explicit in-scope list from scope.yaml
            "portal.photomath.net",
            "argocd-dwh-eu-dev.photomath.net",       # 403 NOT via IAP — highest priority
            "argocd-gke-app-eu-prod.photomath.net",  # ArgoCD prod EU — IAP protected
            "argocd-gke-app-us-prod.photomath.net",  # ArgoCD prod US — IAP protected
            "idp.photomath.net",                     # Identity provider
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
            "photomath.com",
        ],
    },
    {
        "name": "siemplify",
        "tier": 1,
        "priority": 2,
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
    },
    {
        "name": "dataform",
        "tier": 1,
        "priority": 2,
        "hosts": [
            "app.dataform.co",
            "api.dataform.co",
            "dataform.co",
        ],
    },
    {
        "name": "waze",
        "tier": 1,
        "priority": 3,
        "hosts": [
            "biz.waze.com",
            "adsapi.waze.com",
            "adsapi-staging.waze.com",
            "proxy.waze.com",
            "proxy-staging.waze.com",
        ],
    },
    {
        "name": "fitbit",
        "tier": 1,
        "priority": 3,
        "hosts": [
            "accounts.fitbit.com",
            "health-admin.fitbit.com",
            "ngw.fitbit.com",
            "mgmt.fitbit.com",
            "coaching-dashboard.fitbit.com",
            "strava.fitbit.com",
        ],
    },
    {
        "name": "apigee",
        "tier": 1,
        "priority": 3,
        "hosts": [
            "enterprise.apigee.com",
            "sense-ui.apigee.com",
            "apigee.com",
            "apigee.google.com",
        ],
    },
]

# ── Probe path sets ──────────────────────────────────────────────────────────

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/.well-known/security.txt", "/.well-known/oauth-authorization-server",
    "/health", "/healthz", "/ready", "/readyz", "/live", "/livez",
    "/metrics", "/status", "/version", "/info", "/debug",
    "/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/swagger-ui.html", "/swagger-ui/",
    "/v1/swagger.json", "/v2/swagger.json",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/gql",
    "/v1", "/v2", "/v3",
    "/auth", "/oauth", "/login", "/signin", "/sso",
    "/oauth/token", "/oauth/authorize", "/connect/authorize",
    "/admin", "/admin/api", "/internal", "/management",
    "/.env", "/config", "/server-status", "/server-info",
    "/__/firebase/init.json", "/__/firebase/init.js",
]

ARGOCD_PATHS = [
    "/api/v1/settings",
    "/api/v1/clusters",
    "/api/v1/applications",
    "/api/v1/repositories",
    "/api/v1/projects",
    "/api/v1/session",           # ArgoCD login endpoint (check auth required)
    "/api/version",
]

SIEMPLIFY_PATHS = [
    "/api/external/v1/cases",
    "/api/external/v1/alerts",
    "/api/external/v1/playbooks",
    "/api/1.0/settings",
    "/api/settings",
    "/api/auth/login",
    "/api/v1/health",
    "/api/connectors",
    "/integrations",
    "/marketplace",
    "/api/external/v1/connectors",
]

DATAFORM_PATHS = [
    "/api/v1/workspaces",
    "/api/v1/repositories",
    "/api/v1/projects",
    "/api/workspaces",
    "/v1/projects",
    "/api/v1/compilationResults",
    "/api/v1/workflowInvocations",
    "/health",
    "/api",
]

WAZE_BIZ_PATHS = [
    "/api/v1",
    "/api/v2",
    "/campaigns",
    "/api/campaigns",
    "/api/reports",
    "/api/locations",
    "/api/users",
    "/api/accounts",
    "/api/auth",
    "/health",
    "/status",
]

CLUSTER_EXTRA_PATHS = {
    "photomath": ARGOCD_PATHS,
    "siemplify": SIEMPLIFY_PATHS,
    "dataform": DATAFORM_PATHS,
    "waze": WAZE_BIZ_PATHS,
}

# ── Utilities ─────────────────────────────────────────────────────────────────

def log(msg, level="INFO"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    elapsed = str(datetime.datetime.now() - start_time).split(".")[0]
    line = f"[{ts}] [{elapsed}] [{level}] {msg}"
    with _log_lock:
        print(line, flush=True)
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")

def get_host_lock(host):
    with _host_locks_lock:
        if host not in _host_locks:
            _host_locks[host] = threading.Lock()
        return _host_locks[host]

def dns_resolve(host):
    try:
        info = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list({r[4][0] for r in info})
        return ips
    except socket.gaierror:
        return []

def is_internal_ip(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
        if parts[0] == 10: return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
        if parts[0] == 192 and parts[1] == 168: return True
        if parts[0] == 127: return True
        if parts[0] == 169 and parts[1] == 254: return True
        return False
    except Exception:
        return False

def curl_get(url, extra_headers=None, max_size=65536, follow=True, method="GET"):
    """Run curl via subprocess — handles HTTPS + TLS better than urllib on Pi."""
    cmd = [
        CURL, "-s", "--max-time", str(TIMEOUT),
        "--max-filesize", str(max_size),
        "-A", UA,
        "-D", "-",   # dump headers to stdout
        "-o", "-",   # body to stdout
    ]
    if follow:
        cmd += ["-L", "--max-redirs", "5"]
    if method != "GET":
        cmd += ["-X", method]
    if extra_headers:
        for h in extra_headers:
            cmd += ["-H", h]
    cmd.append(url)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT+5)
        raw = result.stdout
        # Split headers from body at first blank line after status
        lines = raw.split("\n")
        headers = {}
        body_lines = []
        in_body = False
        last_status = None
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("HTTP/"):
                last_status = stripped
                headers = {}
                in_body = False
            elif not in_body:
                if stripped == "":
                    in_body = True
                elif ":" in stripped:
                    k, _, v = stripped.partition(":")
                    headers[k.lower().strip()] = v.strip()
            else:
                body_lines.append(line)
        body = "\n".join(body_lines)
        code = int(last_status.split()[1]) if last_status and len(last_status.split()) > 1 else 0
        return code, headers, body
    except Exception as e:
        return 0, {}, str(e)

def ensure_results_dir(cluster_name, subdir):
    d = RESULTS_BASE / cluster_name / subdir
    d.mkdir(parents=True, exist_ok=True)
    return d

# ── Core probe logic ──────────────────────────────────────────────────────────

def probe_host(host, cluster_name):
    """Full probe for one host: DNS → HTTP fingerprint → path enumeration → JS mining."""
    results = {
        "host": host, "cluster": cluster_name,
        "resolved": [], "live": False, "status": 0,
        "server": "", "tech": [], "paths": {}, "js_findings": [],
        "cors": None, "graphql": False, "interesting": [],
    }

    # DNS resolution
    ips = dns_resolve(host)
    if not ips:
        log(f"  NXDOMAIN: {host}", "DNS")
        return results
    if any(is_internal_ip(ip) for ip in ips):
        log(f"  SKIP internal IP: {host} → {ips}", "WARN")
        return results

    results["resolved"] = ips
    log(f"  LIVE {host} → {', '.join(ips)}", "DNS")

    lock = get_host_lock(host)

    # ── Base request ──────────────────────────────────────────────────────────
    with lock:
        time.sleep(DELAY)
        code, hdrs, body = curl_get(f"https://{host}/")
    results["status"] = code
    results["live"] = code > 0

    if not results["live"]:
        log(f"  DEAD {host} (no response)", "HTTP")
        return results

    results["server"] = hdrs.get("server", "")
    log(f"  [{code}] {host}  server={results['server'][:40]}", "HTTP")

    # Tech fingerprinting from headers
    tech = []
    header_blob = json.dumps(hdrs).lower()
    if "cloudflare" in header_blob: tech.append("cloudflare")
    if "framer" in header_blob: tech.append("framer")
    if "firebase" in body.lower()[:2000]: tech.append("firebase")
    if "google-cloud-trace" in header_blob or "x-cloud-trace" in header_blob: tech.append("gcp")
    if "x-powered-by" in hdrs: tech.append(f"powered-by:{hdrs['x-powered-by']}")
    if "x-argocd" in header_blob or "argocd" in body.lower()[:500]: tech.append("argocd")
    if "react" in body.lower()[:3000] or "__next" in body.lower()[:3000]: tech.append("react/nextjs")
    results["tech"] = tech

    # ── CORS check ────────────────────────────────────────────────────────────
    with lock:
        time.sleep(DELAY)
        _, cors_hdrs, _ = curl_get(
            f"https://{host}/api/v1/",
            extra_headers=["Origin: https://evil-attacker.com", "Access-Control-Request-Method: GET"],
            follow=False
        )
    acao = cors_hdrs.get("access-control-allow-origin", "")
    acac = cors_hdrs.get("access-control-allow-credentials", "")
    if acao == "*" or acao == "https://evil-attacker.com":
        results["cors"] = f"MISCONFIGURED: acao={acao} acac={acac}"
        results["interesting"].append(f"CORS-MISS: acao={acao} acac={acac}")
        log(f"  *** CORS MISCONFIGURATION: {host} acao={acao} acac={acac}", "FIND")
    elif acao:
        results["cors"] = f"acao={acao}"

    # ── Path enumeration ──────────────────────────────────────────────────────
    paths_to_probe = list(COMMON_PATHS)
    extra = CLUSTER_EXTRA_PATHS.get(cluster_name, [])
    paths_to_probe.extend(extra)

    interesting_codes = [200, 201, 204, 206, 301, 302, 307, 308, 401, 403, 405, 500]

    for path in paths_to_probe:
        with lock:
            time.sleep(DELAY)
            pcode, phdrs, pbody = curl_get(
                f"https://{host}{path}",
                follow=False,
                max_size=16384
            )

        if pcode in interesting_codes and pcode != 404:
            results["paths"][path] = {
                "code": pcode,
                "content_type": phdrs.get("content-type", ""),
                "length": phdrs.get("content-length", ""),
                "server": phdrs.get("server", ""),
                "body_snippet": pbody[:300].replace("\n", " ").strip(),
            }
            flag = "***" if pcode in [200, 201] else "  >"
            log(f"  {flag} {pcode} https://{host}{path}  [{phdrs.get('content-type','')[:30]}]", "PATH")

            # Special: GraphQL detection
            if path == "/graphql" and pcode in [200, 400, 405]:
                results["graphql"] = True
                results["interesting"].append(f"GRAPHQL at {path} [{pcode}]")

            # Special: ArgoCD unauth
            if "argocd" in cluster_name and path == "/api/v1/clusters" and pcode == 200:
                results["interesting"].append("ARGOCD-UNAUTH: /api/v1/clusters returned 200!")
                log(f"  *** ARGOCD UNAUTHENTICATED ACCESS: {host}/api/v1/clusters", "CRITICAL")

            # Special: OIDC config
            if path == "/.well-known/openid-configuration" and pcode == 200:
                results["interesting"].append(f"OIDC config exposed: {pbody[:200]}")

            # Special: Swagger/OpenAPI
            if pcode == 200 and ("swagger" in path or "openapi" in path):
                results["interesting"].append(f"API_SCHEMA: {path} [{len(pbody)} bytes]")

    # ── JS bundle mining ──────────────────────────────────────────────────────
    if code == 200 and body:
        js_urls = re.findall(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body)
        js_urls = [u if u.startswith("http") else f"https://{host}{u}" for u in js_urls]
        js_urls = [u for u in js_urls if host in u or u.startswith("/")][:8]  # cap at 8

        for js_url in js_urls:
            if not js_url.startswith("http"):
                js_url = f"https://{host}{js_url}"
            with lock:
                time.sleep(DELAY)
                jcode, _, jbody = curl_get(js_url, max_size=524288, follow=False)

            if jcode != 200 or not jbody:
                continue

            findings = []

            # API endpoints
            for m in re.findall(r'["\'](/(?:api|v\d|graphql|auth|oauth|internal)[/\w\-\.?\={}:]*)["\']', jbody):
                if len(m) > 3 and not m.startswith("//"):
                    findings.append(f"ENDPOINT: {m}")

            # Credentials / API keys
            for label, pattern in [
                ("FIREBASE_KEY", r'AIzaSy[A-Za-z0-9_-]{33}'),
                ("API_KEY",     r'(?:api[_-]?key|apiKey)["\s]*[:=]["\s]*([A-Za-z0-9_\-]{20,60})'),
                ("CLIENT_ID",   r'(?:client[_-]?id|clientId)["\s]*[:=]["\s]*([A-Za-z0-9_\-\.]{15,80})'),
                ("SECRET",      r'(?:secret|password|token)["\s]*[:=]["\s]*["\'`]([A-Za-z0-9_\-/+=]{16,80})["\']'),
                ("GCP_PROJECT", r'(?:project[_-]?id|projectId)["\s]*[:=]["\s]*["\'`]([a-z][a-z0-9-]{4,29})["\']'),
            ]:
                for m in re.findall(pattern, jbody):
                    val = m if isinstance(m, str) else m[0] if m else ""
                    if val and not any(skip in val.lower() for skip in ["example", "placeholder", "xxxx", "your_", "changeme"]):
                        findings.append(f"{label}: {val[:60]}")

            # Internal hostnames
            for m in re.findall(r'["\']([a-z][a-z0-9\-]+\.(?:internal|local|corp|svc\.cluster\.local)(?:/[^"\']{0,50})?)["\']', jbody):
                findings.append(f"INTERNAL_HOST: {m}")

            if findings:
                unique = list(dict.fromkeys(findings))[:30]
                results["js_findings"].extend([f"{js_url.split('/')[-1]}: {f}" for f in unique])
                for f in unique:
                    log(f"  JS [{js_url.split('/')[-1][:40]}] {f}", "JS")

    return results

# ── Output writer ─────────────────────────────────────────────────────────────

def write_cluster_report(cluster_name, probe_results):
    out_dir = ensure_results_dir(cluster_name, "02-surface")
    ts = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    live_hosts = [r for r in probe_results if r["live"]]
    findings = []

    report_lines = [
        f"# Deep Recon Report — {cluster_name}",
        f"Generated: {ts}",
        f"Hosts probed: {len(probe_results)} | Live: {len(live_hosts)}",
        "",
        "## Live Hosts",
    ]

    for r in live_hosts:
        report_lines.append(f"\n### {r['host']}")
        report_lines.append(f"- Status: {r['status']}")
        report_lines.append(f"- IPs: {', '.join(r['resolved'])}")
        report_lines.append(f"- Server: {r['server']}")
        report_lines.append(f"- Tech: {', '.join(r['tech']) or 'unknown'}")
        if r["cors"]:
            report_lines.append(f"- CORS: {r['cors']}")
        if r["graphql"]:
            report_lines.append("- GraphQL: YES")

        interesting_paths = {p: v for p, v in r["paths"].items() if v["code"] in [200, 201, 204]}
        if interesting_paths:
            report_lines.append("- **200 Paths:**")
            for p, v in interesting_paths.items():
                report_lines.append(f"  - `{p}` [{v['code']}] {v['content_type'][:40]}")
                if v["body_snippet"]:
                    report_lines.append(f"    ```{v['body_snippet'][:200]}```")

        auth_paths = {p: v for p, v in r["paths"].items() if v["code"] in [401, 403]}
        if auth_paths:
            report_lines.append(f"- Auth-gated paths (401/403): {', '.join(auth_paths.keys())[:200]}")

        if r["js_findings"]:
            report_lines.append("- **JS Findings:**")
            for f in r["js_findings"][:20]:
                report_lines.append(f"  - {f}")

        if r["interesting"]:
            report_lines.append("- **⚠ Interesting:**")
            for i in r["interesting"]:
                report_lines.append(f"  - **{i}**")
                findings.append({"host": r["host"], "finding": i})

    report_lines += ["", "## Raw JSON", "```json"]
    report_lines.append(json.dumps(probe_results, indent=2)[:8000])
    report_lines.append("```")

    report_path = out_dir / "deep-recon.md"
    report_path.write_text("\n".join(report_lines))
    log(f"Report written: {report_path}", "DONE")

    if findings:
        leads_path = out_dir / "leads.json"
        leads_path.write_text(json.dumps(findings, indent=2))
        log(f"LEADS: {len(findings)} interesting findings → {leads_path}", "LEAD")

    return findings

# ── Main ──────────────────────────────────────────────────────────────────────

def run_cluster(cluster):
    name = cluster["name"]
    hosts = cluster["hosts"]
    tier = cluster["tier"]
    log(f"=== START cluster={name} tier={tier} hosts={len(hosts)} ===", "CLUST")

    all_results = []
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = {ex.submit(probe_host, h, name): h for h in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                result = fut.result()
                all_results.append(result)
            except Exception as e:
                log(f"  ERROR {host}: {e}", "ERR")
                all_results.append({"host": host, "cluster": name, "error": str(e), "live": False,
                                    "resolved": [], "status": 0, "server": "", "tech": [],
                                    "paths": {}, "js_findings": [], "cors": None,
                                    "graphql": False, "interesting": []})

    findings = write_cluster_report(name, all_results)
    live_count = sum(1 for r in all_results if r["live"])
    log(f"=== DONE cluster={name} live={live_count}/{len(hosts)} leads={len(findings)} ===", "CLUST")
    return findings


def print_summary(all_findings):
    print("\n" + "="*70)
    print("RECON COMPLETE — LEAD SUMMARY")
    print("="*70)
    if not all_findings:
        print("No high-signal leads found in this run.")
    for f in all_findings:
        print(f"  [{f.get('cluster','?')}] {f.get('host','?')}: {f.get('finding','?')}")
    elapsed = str(datetime.datetime.now() - start_time).split(".")[0]
    print(f"\nTotal runtime: {elapsed}")
    print(f"Full log: {LOG_PATH}")
    print("="*70)


def main():
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    log("deep-recon-orchestrator starting", "INIT")
    log(f"Targets: {[c['name'] for c in CLUSTERS]}", "INIT")
    log(f"Results base: {RESULTS_BASE}", "INIT")
    log(f"Max workers: {MAX_WORKERS}, delay: {DELAY}s, timeout: {TIMEOUT}s", "INIT")

    all_findings = []

    # Run clusters sequentially by priority (Pi RAM/CPU management)
    # Priority 1 first (Photomath, Siemplify, Dataform), then 2, then 3
    sorted_clusters = sorted(CLUSTERS, key=lambda c: c["priority"])

    for cluster in sorted_clusters:
        try:
            findings = run_cluster(cluster)
            for f in findings:
                f["cluster"] = cluster["name"]
            all_findings.extend(findings)
        except Exception as e:
            log(f"Cluster {cluster['name']} crashed: {e}", "ERR")

    print_summary(all_findings)

    # Write master leads file
    master_leads = RESULTS_BASE / "MASTER-LEADS.json"
    try:
        existing = json.loads(master_leads.read_text()) if master_leads.exists() else []
    except Exception:
        existing = []
    existing.extend(all_findings)
    master_leads.write_text(json.dumps(existing, indent=2))
    log(f"Master leads updated: {master_leads}", "DONE")


if __name__ == "__main__":
    main()
