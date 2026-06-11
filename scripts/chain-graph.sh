#!/usr/bin/env bash
# chain-graph.sh — Chain state manager for the bug bounty pipeline
#
# Tracks: confirmed finding → chain test → outcome → elevation status
#
# Usage:
#   ./scripts/chain-graph.sh init   <target>
#   ./scripts/chain-graph.sh add    <target> <id> <class> <base-severity>
#   ./scripts/chain-graph.sh link   <target> <id> <test-name> <status>
#     (status: PENDING | PASS | FAIL | SKIPPED)
#   ./scripts/chain-graph.sh next   <target> <id>       → prints next PENDING test
#   ./scripts/chain-graph.sh status <target> <id>       → prints chain summary
#   ./scripts/chain-graph.sh report <target>            → full chain report
#   ./scripts/chain-graph.sh elevate <target> <id> <elevated-severity>
#
# State file: results/<target>/chain-graph.json
#
# Elevation table (class → chain tests that can elevate it):
#   subdomain-takeover   → csp-script-src, oauth-redirect-uri, cookie-domain
#   SSRF-blind           → imds-v1, imds-v2, gcp-metadata, internal-grafana, internal-auth
#   IDOR-read            → idor-write, cross-tenant-enum, connector-id
#   XSS-reflected        → admin-context, session-accessible, DOM-escalation
#   open-redirect        → oauth-state-leak, oauth-code-redirect
#   credential-exposure  → validity-check, privilege-level, blast-radius

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CMD="${1:-help}"
TARGET="${2:-}"

[ -n "$TARGET" ] || { echo "Usage: $0 <cmd> <target> [args...]"; exit 1; }

GRAPH_FILE="$REPO_ROOT/results/$TARGET/chain-graph.json"

# ─────────────────────────────────────────────────────────────────────────────
# Elevation table — what to test for each confirmed class
# ─────────────────────────────────────────────────────────────────────────────
elevation_tests() {
  local class="$1"
  case "$class" in
    subdomain-takeover)
      echo "csp-script-src-check oauth-redirect-uri-check cookie-domain-share-check user-traffic-check" ;;
    SSRF-blind|SSRF-partial|SSRF)
      echo "imds-v1-probe imds-v2-probe gcp-metadata-probe internal-grafana-probe internal-auth-service-probe" ;;
    SSRF-full)
      echo "cloud-cred-extraction internal-pivot imds-full-read" ;;
    IDOR-read|IDOR|BOLA)
      echo "idor-write-test cross-tenant-id-enum connector-id-idor-test" ;;
    XSS-reflected)
      echo "admin-context-check session-token-accessible DOM-XSS-escalation" ;;
    XSS-stored)
      echo "admin-reads-content-check session-theft-poc csp-bypass-check" ;;
    open-redirect)
      echo "token-in-redirect-url oauth-state-leakage oauth-code-redirect-chain" ;;
    credential-exposure)
      echo "credential-validity-check privilege-of-cred blast-radius-estimate" ;;
    default-creds)
      echo "datasource-list-check sensitive-dashboard-check pivot-to-internal" ;;
    oauth-hijack|auth-bypass)
      echo "code-exchange-poc token-scope-enum full-account-takeover-poc" ;;
    JWT-attack)
      echo "alg-none-test key-confusion-test weak-secret-brute" ;;
    path-traversal)
      echo "sensitive-file-read etc-passwd-check cloud-config-read" ;;
    *)
      echo "" ;;
  esac
}

# Severity after chain test passes (elevation outcome)
elevated_severity() {
  local base_class="$1" test_name="$2"
  case "$test_name" in
    *imds*|*gcp-metadata*|*cloud-cred*)    echo "Critical" ;;
    *oauth-redirect*)                       echo "Critical" ;;
    *account-takeover*|*full-account*)     echo "Critical" ;;
    *internal-*|*pivot*)                   echo "Critical" ;;
    *cookie-domain*)                        echo "High" ;;
    *idor-write*|*cross-tenant*)           echo "Critical" ;;
    *admin-context*|*session-theft*)       echo "High" ;;
    *datasource*|*sensitive-dashboard*)    echo "High" ;;
    *csp-script-src*|*oauth-state*)        echo "High" ;;
    *credential-validity*)                 echo "High" ;;
    *)                                     echo "Medium" ;;
  esac
}

# ─────────────────────────────────────────────────────────────────────────────
_py() {
  python3 - "$@" <<'PYEOF'
import json, sys, datetime, os

graph_file = os.environ.get("GRAPH_FILE", "")

def load():
    if os.path.exists(graph_file):
        with open(graph_file) as f:
            return json.load(f)
    return {"target": "", "findings": {}, "updated": ""}

def save(d):
    d["updated"] = datetime.datetime.utcnow().isoformat() + "Z"
    with open(graph_file, "w") as f:
        json.dump(d, f, indent=2)

cmd = sys.argv[1] if len(sys.argv) > 1 else ""

if cmd == "init":
    target = sys.argv[2]
    d = load()
    d["target"] = target
    save(d)
    print(f"Initialized chain graph for {target}")

elif cmd == "add":
    finding_id, cls, severity = sys.argv[2], sys.argv[3], sys.argv[4]
    d = load()
    d.setdefault("findings", {})[finding_id] = {
        "class": cls,
        "base_severity": severity,
        "elevated_to": None,
        "tests": {},
        "added": datetime.datetime.utcnow().isoformat() + "Z"
    }
    save(d)
    print(f"Added finding {finding_id} ({cls} / {severity})")

elif cmd == "link":
    finding_id, test_name, status = sys.argv[2], sys.argv[3], sys.argv[4]
    elevated = sys.argv[5] if len(sys.argv) > 5 else None
    d = load()
    f = d.setdefault("findings", {}).setdefault(finding_id, {"tests": {}})
    f.setdefault("tests", {})[test_name] = {
        "status": status,
        "elevated_to": elevated,
        "updated": datetime.datetime.utcnow().isoformat() + "Z"
    }
    if status == "PASS" and elevated:
        f["elevated_to"] = elevated
    save(d)
    print(f"Linked {finding_id}/{test_name} → {status}" + (f" elevated={elevated}" if elevated else ""))

elif cmd == "next":
    finding_id = sys.argv[2]
    d = load()
    tests = d.get("findings", {}).get(finding_id, {}).get("tests", {})
    for t, v in tests.items():
        if v.get("status") == "PENDING":
            print(t)
            sys.exit(0)
    print("")

elif cmd == "status":
    finding_id = sys.argv[2]
    d = load()
    f = d.get("findings", {}).get(finding_id)
    if not f:
        print(f"Finding {finding_id} not in chain graph")
        sys.exit(1)
    print(f"Finding:      {finding_id}")
    print(f"Class:        {f.get('class','?')}")
    print(f"Base Severity: {f.get('base_severity','?')}")
    print(f"Elevated To:   {f.get('elevated_to') or '(not yet elevated)'}")
    print(f"Chain Tests:")
    for t, v in f.get("tests", {}).items():
        elev = f" → {v['elevated_to']}" if v.get("elevated_to") else ""
        print(f"  [{v.get('status','?'):8}] {t}{elev}")

elif cmd == "elevate":
    finding_id, new_sev = sys.argv[2], sys.argv[3]
    d = load()
    d.setdefault("findings", {}).setdefault(finding_id, {})["elevated_to"] = new_sev
    save(d)
    print(f"Elevated {finding_id} → {new_sev}")

elif cmd == "report":
    d = load()
    print(f"# Chain Graph Report — {d.get('target','?')}")
    print(f"# Updated: {d.get('updated','?')}")
    print("")
    findings = d.get("findings", {})
    if not findings:
        print("(no findings in chain graph)")
    for fid, f in findings.items():
        elev = f.get("elevated_to")
        sev = elev if elev else f.get("base_severity","?")
        marker = "↑ELEVATED" if elev else ""
        print(f"## {fid} [{f.get('class','?')}] — {sev} {marker}")
        tests = f.get("tests", {})
        if not tests:
            print("  (no chain tests queued)")
        for t, v in tests.items():
            elev_note = f" → {v['elevated_to']}" if v.get("elevated_to") else ""
            print(f"  [{v.get('status','?'):8}] {t}{elev_note}")
        print("")

PYEOF
}

# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────
export GRAPH_FILE="$GRAPH_FILE"

case "$CMD" in
  init)
    mkdir -p "$(dirname "$GRAPH_FILE")"
    _py init "$TARGET"
    ;;

  add)
    ID="${3:-}"; CLASS="${4:-}"; SEVERITY="${5:-Medium}"
    [ -n "$ID" ] && [ -n "$CLASS" ] || { echo "Usage: $0 add <target> <id> <class> [severity]"; exit 1; }
    _py add "$ID" "$CLASS" "$SEVERITY"

    # Automatically queue all known chain tests as PENDING
    tests=$(elevation_tests "$CLASS")
    for t in $tests; do
      _py link "$ID" "$t" "PENDING"
    done
    echo "Queued chain tests: ${tests:-none}"
    ;;

  link)
    ID="${3:-}"; TEST="${4:-}"; STATUS="${5:-PENDING}"
    [ -n "$ID" ] && [ -n "$TEST" ] || { echo "Usage: $0 link <target> <id> <test> <status> [elevated-severity]"; exit 1; }
    ELEV="${6:-}"
    if [ -n "$ELEV" ]; then
      _py link "$ID" "$TEST" "$STATUS" "$ELEV"
    else
      # Auto-compute elevation if PASS
      if [ "$STATUS" = "PASS" ]; then
        ELEV=$(elevated_severity "" "$TEST")
        _py link "$ID" "$TEST" "$STATUS" "$ELEV"
      else
        _py link "$ID" "$TEST" "$STATUS"
      fi
    fi
    ;;

  next)
    ID="${3:-}"
    [ -n "$ID" ] || { echo "Usage: $0 next <target> <id>"; exit 1; }
    _py next "$ID"
    ;;

  status)
    ID="${3:-}"
    [ -n "$ID" ] || { echo "Usage: $0 status <target> <id>"; exit 1; }
    _py status "$ID"
    ;;

  elevate)
    ID="${3:-}"; SEV="${4:-High}"
    _py elevate "$ID" "$SEV"
    ;;

  report)
    _py report
    ;;

  tests)
    # Print chain tests for a given class (useful for planning)
    CLASS="${3:-}"
    [ -n "$CLASS" ] || { echo "Usage: $0 tests <target> <class>"; exit 1; }
    tests=$(elevation_tests "$CLASS")
    if [ -n "$tests" ]; then
      for t in $tests; do
        elev=$(elevated_severity "$CLASS" "$t")
        printf "  %-45s → elevates to %s if PASS\n" "$t" "$elev"
      done
    else
      echo "  (no known chain tests for class '$CLASS')"
    fi
    ;;

  help|*)
    cat <<EOF
chain-graph.sh — Chain state manager

Commands:
  init   <target>                          Initialize chain graph
  add    <target> <id> <class> [severity]  Add finding + auto-queue chain tests
  link   <target> <id> <test> <status>     Update chain test status (PENDING|PASS|FAIL|SKIPPED)
  next   <target> <id>                     Print next PENDING chain test
  status <target> <id>                     Print finding chain status
  elevate <target> <id> <severity>         Mark finding as elevated
  report <target>                          Full chain graph report
  tests  <target> <class>                  Show chain tests for a class

Status values: PENDING | PASS | FAIL | SKIPPED
EOF
    ;;
esac
