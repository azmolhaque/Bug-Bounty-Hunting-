#!/usr/bin/env bash
# agent-orchestrate.sh — Master intelligence orchestrator for the bug bounty pipeline
#
# Architecture:
#   State machine:      phase 0-6, persist/resume across reboots
#   Lead qualification: auto-kill bad leads <60s (5-point gate)
#   Dead-end detector:  3 failed probes → auto-close lead
#   Chain elevation:    confirmed Low → auto-test chain links
#   Pi resource guard:  CPU/RAM/temp aware, adaptive concurrency cap
#   Intelligence loop:  re-plan after every phase
#
# Usage:
#   ./scripts/agent-orchestrate.sh <target> [OPTIONS]
#
# Options:
#   --phase N     run only phase N (0-6)
#   --phase N-M   run phases N through M
#   --background  run long scans (Phase 1+2) in background
#   --dry-run     print plan, execute nothing
#   --force       re-run even if phase already marked DONE
#   --status      print status summary and exit
#
# State: results/<target>/.orchestrator-state.json
# Log:   results/<target>/HUNT-LOG.md

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin:$PATH

# ══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ══════════════════════════════════════════════════════════════════════════════
TARGET=""
START_PHASE=0
END_PHASE=6
BACKGROUND=false
DRY_RUN=false
FORCE=false
STATUS_ONLY=false

usage() {
  cat <<EOF
Usage: $0 <target> [--phase N|N-M] [--background] [--dry-run] [--force] [--status]

  target:        target domain (e.g. wiz.io)
  --phase N:     run only phase N (0-6)
  --phase N-M:   run phases N through M
  --background:  run Phase 1+2 recon in background (Pi-safe)
  --dry-run:     print plan without executing probes
  --force:       re-run phases even if already DONE
  --status:      print status summary and exit
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase)
      shift
      if [[ "$1" =~ ^([0-9])-([0-9])$ ]]; then
        START_PHASE="${BASH_REMATCH[1]}"; END_PHASE="${BASH_REMATCH[2]}"
      elif [[ "$1" =~ ^[0-9]$ ]]; then
        START_PHASE="$1"; END_PHASE="$1"
      else
        echo "ERROR: invalid --phase: $1" >&2; usage
      fi
      shift ;;
    --background) BACKGROUND=true; shift ;;
    --dry-run)    DRY_RUN=true; shift ;;
    --force)      FORCE=true; shift ;;
    --status)     STATUS_ONLY=true; shift ;;
    -*)           echo "ERROR: unknown flag $1" >&2; usage ;;
    *)            [ -z "$TARGET" ] && TARGET="$1" || { echo "ERROR: unexpected arg $1" >&2; usage; }; shift ;;
  esac
done

[ -n "$TARGET" ] || usage

# ══════════════════════════════════════════════════════════════════════════════
# PATHS
# ══════════════════════════════════════════════════════════════════════════════
RESULTS="$REPO_ROOT/results/$TARGET"
STATE="$RESULTS/.orchestrator-state.json"
LOG="$RESULTS/HUNT-LOG.md"
CANDIDATES="$RESULTS/03-candidates/candidates.jsonl"

mkdir -p "$RESULTS"/{01-assets,02-surface,"03-candidates/evidence",04-verified,05-triage,findings}

# ══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════════
_log() {
  local level="$1"; shift
  local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[$ts][$level] $*" | tee -a "$LOG"
}
log_info()     { _log "INFO " "$@"; }
log_warn()     { _log "WARN " "$@"; }
log_error()    { _log "ERROR" "$@"; }
log_phase()    { echo -e "\n$(printf '═%.0s' {1..70})" | tee -a "$LOG"; _log "PHASE" "$@"; printf '═%.0s' {1..70} | tee -a "$LOG"; echo ""; }
log_decision() { _log "DECIDE" "$@"; }
log_lead()     { _log "LEAD " "$@"; }

# ══════════════════════════════════════════════════════════════════════════════
# STATE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
state_init() {
  if [ -f "$STATE" ]; then
    log_info "Resuming from existing state"
    return 0
  fi
  log_info "Initializing new orchestrator state"
  python3 - <<PYEOF
import json, datetime
state = {
    "target": "$TARGET",
    "started": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
    "current_phase": 0,
    "phase_status": {},
    "leads": {},
    "chain_graph": {},
    "dead_ends": [],
    "verified": []
}
with open("$STATE", "w") as f:
    json.dump(state, f, indent=2)
PYEOF
}

state_py() {
  local _sf="$STATE"
  STATE_FILE="$_sf" python3 - "$@" <<'PYEOF'
import json, sys, datetime, os

state_file = os.environ.get("STATE_FILE", "")
if not state_file:
    raise RuntimeError("STATE_FILE env var not set")

def load():
    with open(state_file) as f:
        return json.load(f)

def save(d):
    with open(state_file, "w") as f:
        json.dump(d, f, indent=2)

cmd = sys.argv[1] if len(sys.argv) > 1 else ""

if cmd == "get_phase":
    d = load()
    print(d.get("phase_status", {}).get(sys.argv[2], ""))

elif cmd == "set_phase":
    d = load()
    d.setdefault("phase_status", {})[sys.argv[2]] = sys.argv[3]
    d["current_phase"] = int(sys.argv[2])
    save(d)

elif cmd == "update_lead":
    d = load()
    lead_id, status, reason = sys.argv[2], sys.argv[3], sys.argv[4]
    d.setdefault("leads", {}).setdefault(lead_id, {})
    d["leads"][lead_id].update({
        "status": status,
        "reason": reason,
        "updated": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    })
    save(d)

elif cmd == "inc_probes":
    d = load()
    lead = d.setdefault("leads", {}).setdefault(sys.argv[2], {})
    lead["probes"] = lead.get("probes", 0) + 1
    save(d)
    print(lead["probes"])

elif cmd == "get_probes":
    d = load()
    print(d.get("leads", {}).get(sys.argv[2], {}).get("probes", 0))

elif cmd == "add_verified":
    d = load()
    d.setdefault("verified", [])
    if sys.argv[2] not in d["verified"]:
        d["verified"].append(sys.argv[2])
    save(d)

elif cmd == "chain_update":
    # chain_update <target> <finding_id> <test_name> <status>
    d = load()
    cg = d.setdefault("chain_graph", {}).setdefault(sys.argv[2], {})
    cg.setdefault("tests", {})[sys.argv[3]] = {
        "status": sys.argv[4],
        "updated": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    }
    save(d)

elif cmd == "report":
    d = load()
    print(json.dumps(d, indent=2))

PYEOF
}

state_phase_done() {
  local phase="$1"
  local status; status=$(state_py get_phase "$phase" 2>/dev/null || echo "")
  [ "$status" = "DONE" ]
}

state_should_run() {
  local phase="$1"
  if $FORCE; then return 0; fi
  if state_phase_done "$phase"; then return 1; fi
  return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# PI 5 RESOURCE GUARD
# ══════════════════════════════════════════════════════════════════════════════
MAX_TEMP_C=78
MAX_RAM_PCT=82
MAX_CPU_PCT=88
MAX_PARALLEL=3
DEAD_END_PROBES=3

pi_resource_check() {
  # Temperature
  local temp_raw=0 temp_c=0
  if [ -f /sys/class/thermal/thermal_zone0/temp ]; then
    temp_raw=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo "0")
    temp_c=$((temp_raw / 1000))
  fi

  # RAM
  local ram_used_kb ram_total_kb ram_pct=0
  ram_total_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "16000000")
  ram_used_kb=$(grep -E '^(MemTotal|MemAvailable)' /proc/meminfo 2>/dev/null | awk '{sum += ($2 * (NR==1 ? 1 : -1))} END {print sum}' || echo "0")
  [ "$ram_total_kb" -gt 0 ] && ram_pct=$((ram_used_kb * 100 / ram_total_kb)) || ram_pct=0

  # CPU (two-sample /proc/stat delta — avoids top's stray output on Pi OS)
  local _l1 _l2 _cpu_used=0
  read -r _l1 < /proc/stat 2>/dev/null || true
  sleep 0.3
  read -r _l2 < /proc/stat 2>/dev/null || true
  _cpu_used=$(awk -v l1="$_l1" -v l2="$_l2" 'BEGIN {
    n = split(l1, a); split(l2, b)
    idle1 = a[5]; idle2 = b[5]
    total1=0; total2=0
    for (i=2;i<=n;i++) { total1+=a[i]; total2+=b[i] }
    td = total2 - total1; id = idle2 - idle1
    if (td > 0) print int((td - id) * 100 / td); else print 0
  }') 2>/dev/null || _cpu_used=0
  local cpu_used=$((_cpu_used + 0))

  log_info "Pi5 resources — CPU:${cpu_used}% RAM:${ram_pct}% TEMP:${temp_c}°C"

  local delay=0
  if [ "$temp_c" -ge "$MAX_TEMP_C" ]; then
    log_warn "THROTTLE: temp ${temp_c}°C ≥ ${MAX_TEMP_C}°C — cooling 120s"
    delay=120
  elif [ "$ram_pct" -ge "$MAX_RAM_PCT" ]; then
    log_warn "THROTTLE: RAM ${ram_pct}% ≥ ${MAX_RAM_PCT}% — waiting 60s"
    delay=60
  elif [ "$cpu_used" -ge "$MAX_CPU_PCT" ]; then
    log_warn "THROTTLE: CPU ${cpu_used}% ≥ ${MAX_CPU_PCT}% — waiting 30s"
    delay=30
  fi

  if [ "$delay" -gt 0 ]; then
    sleep "$delay"
    pi_resource_check  # recurse once after delay
  fi
  return 0
}

count_active_nuclei() {
  pgrep -f "nuclei" 2>/dev/null | wc -l
}

wait_for_slot() {
  local active; active=$(count_active_nuclei)
  while [ "$active" -ge "$MAX_PARALLEL" ]; do
    log_info "Parallel cap ($MAX_PARALLEL active) — waiting 20s"
    sleep 20
    active=$(count_active_nuclei)
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# SCOPE GATE
# ══════════════════════════════════════════════════════════════════════════════
require_in_scope() {
  local host="$1"
  local result; result=$(./scripts/scope-check.sh "$host" 2>&1) || true
  case "$result" in
    IN-SCOPE*)       log_info "Scope OK: $host"; return 0 ;;
    OUT-OF-SCOPE*)   log_error "SCOPE VIOLATION — $host is OUT-OF-SCOPE. Aborting."; exit 1 ;;
    AMBIGUOUS*)      log_error "AMBIGUOUS scope for $host — treating as out-of-scope. Aborting."; exit 1 ;;
    *)               log_error "scope-check.sh unexpected output: $result"; exit 1 ;;
  esac
}

is_in_scope() {
  local host="$1"
  local result; result=$(./scripts/scope-check.sh "$host" 2>&1) || true
  case "$result" in IN-SCOPE*) return 0 ;; *) return 1 ;; esac
}

# ══════════════════════════════════════════════════════════════════════════════
# LEAD QUALIFICATION GATE  (5-point, <60s)
# ══════════════════════════════════════════════════════════════════════════════
# Scoring (1 point each):
#   Q1 — Concrete attacker gain (not vague "info disclosure")
#   Q2 — NOT intended/documented behavior
#   Q3 — Vendor would actually fix this (requires code/config change)
#   Q4 — CVSS ≥ 4.0 standalone or clear chain to Medium+
#   Q5 — In scope, not on hard rejection list
#
# Score 4-5 → PURSUE:HIGH
# Score 3   → PURSUE:MARGINAL
# Score <3  → AUTO_CLOSE

# Hard rejection: classes we immediately close (§3 of CLAUDE.md)
_in_rejection_list() {
  local class="$1"
  case "$class" in
    missing-header|HSTS-missing|X-Frame-Options|X-Content-Type|Referrer-Policy|\
    CSP-informational|SPF-missing|DMARC-missing|DKIM-missing|\
    TLS-version-old|CORS-no-sensitive|self-XSS|CSRF-logout|\
    open-redirect-owned|rate-limit-nonsensitive|version-disclosure|\
    no-2fa|password-policy|swagger-public-no-secrets|stack-trace-no-data|\
    clickjacking-nonsensitive|HTTP-methods|punycode-phishing)
      return 0 ;;
    *) return 1 ;;
  esac
}

# Classes with inherently high-value concrete gain
_high_value_class() {
  local class="$1"
  case "$class" in
    SSRF|SSRF-blind|SSRF-partial|SSRF-full|\
    IDOR|BOLA|IDOR-read|IDOR-write|cross-tenant|\
    RCE|command-injection|SQLi|SSTI|\
    auth-bypass|account-takeover|oauth-hijack|JWT-attack|\
    subdomain-takeover|XSS-stored|credential-exposure|\
    default-creds|path-traversal|business-logic-financial|\
    CORS-sensitive-data)
      return 0 ;;
    *) return 1 ;;
  esac
}

qualify_lead() {
  local class="$1" confidence="$2" impact="$3" evidence="$4"
  local score=0
  local reasons=()

  # Q1: Concrete attacker gain
  if _high_value_class "$class"; then
    score=$((score + 1))
  elif echo "$impact $evidence" | grep -qiE \
    "account.takeover|steal.*token|session.*theft|cloud.key|credential|read.*data|RCE|code.exec|cross.tenant|bypass.*auth|exfil|privilege.escal"; then
    score=$((score + 1))
  else
    reasons+=("Q1: vague gain — no concrete account/data/RCE impact stated")
  fi

  # Q2: NOT intended behavior
  if _in_rejection_list "$class"; then
    reasons+=("Q2: class '$class' is documented-intended or universally rejected")
  else
    case "$confidence" in
      HIGH|CONFIRMED|CRITICAL) score=$((score + 1)) ;;
      MEDIUM) score=$((score + 1)) ;; # benefit of doubt
      LOW)    reasons+=("Q2: low-confidence hit may be intended behavior") ;;
      *)      score=$((score + 1)) ;;
    esac
  fi

  # Q3: Vendor would fix this
  if _high_value_class "$class"; then
    score=$((score + 1))
  elif _in_rejection_list "$class"; then
    reasons+=("Q3: vendor won't fix '$class' without concrete exploit chain")
  else
    score=$((score + 1))
  fi

  # Q4: CVSS >= 4.0 standalone OR chain to Medium+
  case "$class" in
    RCE|account-takeover|IDOR|BOLA|SSRF*|SQLi|auth-bypass|credential-exposure|oauth-hijack|JWT-attack|cross-tenant|command-injection|SSTI)
      score=$((score + 1)) ;;
    subdomain-takeover|XSS-stored|path-traversal|default-creds|CORS-sensitive-data|business-logic-financial)
      if echo "$impact $evidence" | grep -qiE "chain|cookie.domain|oauth|redirect_uri|session|admin|credential|auth|token"; then
        score=$((score + 1))
      else
        reasons+=("Q4: '$class' needs chain link to reach CVSS >= 4.0")
      fi ;;
    XSS-reflected|open-redirect)
      if echo "$impact $evidence" | grep -qiE "session|admin|auth.*token|OAuth|JWT"; then
        score=$((score + 1))
      else
        reasons+=("Q4: '$class' without auth/session context stays below CVSS 4.0")
      fi ;;
    *)
      score=$((score + 1)) ;;
  esac

  # Q5: Not on hard rejection list
  if _in_rejection_list "$class"; then
    reasons+=("Q5: '$class' on CLAUDE.md §3 hard rejection list")
  else
    score=$((score + 1))
  fi

  local reason_str
  reason_str=$(printf '%s; ' "${reasons[@]:-}")
  reason_str="${reason_str%%; }"

  if [ "$score" -ge 4 ]; then
    echo "PURSUE:HIGH:${score}/5:${reason_str:-clean}"
  elif [ "$score" -eq 3 ]; then
    echo "PURSUE:MARGINAL:${score}/5:${reason_str}"
  else
    echo "AUTO_CLOSE:${score}/5:${reason_str}"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# DEAD-END DETECTOR
# ══════════════════════════════════════════════════════════════════════════════
is_dead_end() {
  local id="$1"
  local probes; probes=$(state_py get_probes "$id" 2>/dev/null || echo "0")
  if [ "$probes" -ge "$DEAD_END_PROBES" ]; then
    log_decision "DEAD_END: $id has $probes failed probes ≥ threshold $DEAD_END_PROBES"
    state_py update_lead "$id" "DEAD_END" "auto-closed after $probes failed probes" 2>/dev/null || true
    return 0
  fi
  return 1
}

# ══════════════════════════════════════════════════════════════════════════════
# CHAIN ELEVATION ENGINE
# Next tests to queue when a finding of this class is confirmed
# ══════════════════════════════════════════════════════════════════════════════
chain_next_tests() {
  case "$1" in
    subdomain-takeover)
      echo "csp-script-src-check oauth-redirect-uri-check cookie-domain-share-check user-traffic-check" ;;
    SSRF-blind|SSRF-partial|SSRF)
      echo "imds-v1-probe imds-v2-probe gcp-metadata-probe internal-grafana-probe internal-auth-probe internal-enum" ;;
    SSRF-full)
      echo "cloud-credential-extraction imds-full-read internal-service-pivot" ;;
    XSS-reflected)
      echo "admin-panel-context-check auth-session-accessible-check DOM-XSS-escalation" ;;
    XSS-stored)
      echo "admin-reads-check session-theft-poc cookie-flags-check" ;;
    IDOR-read|IDOR|BOLA)
      echo "idor-write-escalation cross-tenant-id-enum connector-idor-check" ;;
    open-redirect)
      echo "token-in-redirect-url oauth-state-leakage oauth-code-redirect-chain" ;;
    credential-exposure)
      echo "credential-validity-check privilege-of-cred blast-radius-estimate" ;;
    default-creds)
      echo "datasource-list-check dashboard-sensitive-data-check pivot-to-internal" ;;
    oauth-hijack)
      echo "code-exchange-test token-scope-check account-takeover-poc" ;;
    auth-bypass)
      echo "privilege-escalation admin-api-access data-exfil-test" ;;
    *)
      echo "" ;;
  esac
}

# ══════════════════════════════════════════════════════════════════════════════
# NUCLEI TEMPLATE → CLASS MAPPER
# ══════════════════════════════════════════════════════════════════════════════
nuclei_to_class() {
  local template="$1" severity="$2"
  case "$template" in
    *takeover*|*subdomain-takeover*) echo "subdomain-takeover" ;;
    *ssrf*) echo "SSRF-blind" ;;
    *idor*|*bola*|*broken-access*) echo "IDOR" ;;
    *sqli*|*sql-injection*) echo "SQLi" ;;
    *ssti*) echo "SSTI" ;;
    *xss*) echo "XSS-reflected" ;;
    *stored-xss*) echo "XSS-stored" ;;
    *rce*|*command-injection*) echo "RCE" ;;
    *default-login*|*default-creds*|*default-password*) echo "default-creds" ;;
    *exposure*|*exposed-cred*|*api-key*) echo "credential-exposure" ;;
    *cors*) echo "CORS-sensitive-data" ;;
    *header*|*hsts*|*x-frame*|*csp-*|*missing-header*) echo "missing-header" ;;
    *open-redirect*) echo "open-redirect" ;;
    *path-traversal*|*lfi*|*directory-traversal*) echo "path-traversal" ;;
    *jwt*) echo "JWT-attack" ;;
    *oauth*) echo "oauth-hijack" ;;
    *graphql*) echo "IDOR" ;;
    *)
      case "$severity" in
        critical|high) echo "$template" ;;
        *) echo "unknown-$severity" ;;
      esac ;;
  esac
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 0 — Scope, Authorization & Plan
# ══════════════════════════════════════════════════════════════════════════════
run_phase_0() {
  log_phase "0 — Scope Gate & Hunt Plan"

  require_in_scope "$TARGET"

  local plan="$RESULTS/00-plan.md"
  if [ ! -f "$plan" ] || $FORCE; then
    cat > "$plan" <<EOF
# Hunt Plan — $TARGET
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Target Classification
- Root domain: $TARGET
- Archetype: [update after Phase 1 — wildcard/saas/cnapp/api-first/mobile]

## Hunt Thesis
[Orchestrator will update after Phase 2 surface map]

## Attack Chain Hypotheses (probability × impact rank)
1. [update after Phase 1+2]
2. [update after Phase 1+2]
3. [update after Phase 1+2]

## Fastest Path to High/Critical
[update after Phase 2]

## Resource Plan (Pi 5, 16 GB ARM64)
- Recon:    background, streaming to disk, concurrency ≤ $MAX_PARALLEL
- Phase 3:  nuclei fan-out max $MAX_PARALLEL parallel, dead-end after $DEAD_END_PROBES failures
- Temp cap: ${MAX_TEMP_C}°C / RAM cap: ${MAX_RAM_PCT}%

## Phase History
| Phase | Status | Timestamp |
|-------|--------|-----------|
| 0 | DONE | $(date -u +%Y-%m-%dT%H:%M:%SZ) |
EOF
    log_info "Created 00-plan.md"
  else
    log_info "00-plan.md exists — resuming"
  fi

  state_py set_phase 0 DONE 2>/dev/null || true
  log_info "Phase 0 DONE"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1+2 — Asset Discovery & Surface Mapping  [delegate to recon.sh]
# ══════════════════════════════════════════════════════════════════════════════
run_phase_12() {
  log_phase "1+2 — Asset Discovery & Surface Mapping"

  pi_resource_check

  if [ -f "$RESULTS/02-surface/priority.md" ] && ! $FORCE; then
    log_info "priority.md exists — Phase 1+2 already complete"
    state_py set_phase 1 DONE 2>/dev/null || true
    state_py set_phase 2 DONE 2>/dev/null || true
    return 0
  fi

  if $DRY_RUN; then
    log_info "[DRY-RUN] Would run: ./scripts/recon.sh $TARGET"
    state_py set_phase 1 DONE 2>/dev/null || true
    state_py set_phase 2 DONE 2>/dev/null || true
    return 0
  fi

  if $BACKGROUND; then
    nohup ./scripts/recon.sh "$TARGET" >> "$RESULTS/recon.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$RESULTS/.recon.pid"
    log_info "Recon running background PID $pid — tail $RESULTS/recon.log"
    state_py set_phase 1 RUNNING 2>/dev/null || true
    state_py set_phase 2 RUNNING 2>/dev/null || true
  else
    ./scripts/recon.sh "$TARGET" 2>&1 | tee -a "$RESULTS/recon.log" || true
    state_py set_phase 1 DONE 2>/dev/null || true
    state_py set_phase 2 DONE 2>/dev/null || true
    log_info "Phase 1+2 DONE"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Vulnerability Discovery  [nuclei + lead qualification gate]
# ══════════════════════════════════════════════════════════════════════════════
run_phase_3() {
  log_phase "3 — Vulnerability Discovery + Lead Qualification"

  pi_resource_check

  # Build target list from priority.md or fall back to live.txt or root target
  local -a targets=()
  if [ -f "$RESULTS/02-surface/priority.md" ]; then
    while IFS= read -r line; do
      local t; t=$(echo "$line" | grep -oP '(?<=\| )[a-z0-9._-]+\.[a-z]{2,}(?= )' | head -1 || true)
      [ -n "$t" ] && targets+=("$t")
    done < <(grep -E '^\| [a-z]' "$RESULTS/02-surface/priority.md" 2>/dev/null | head -30)
  fi
  if [ -f "$RESULTS/02-surface/live.txt" ] && [ "${#targets[@]}" -eq 0 ]; then
    mapfile -t targets < <(head -30 "$RESULTS/02-surface/live.txt" 2>/dev/null || true)
  fi
  [ "${#targets[@]}" -gt 0 ] || targets=("$TARGET")

  log_info "Phase 3 scanning ${#targets[@]} targets"
  touch "$CANDIDATES"

  local -a pids=()

  for t in "${targets[@]}"; do
    [ -n "$t" ] || continue
    is_in_scope "$t" || { log_warn "Skip (out-of-scope): $t"; continue; }

    wait_for_slot
    pi_resource_check

    local nuclei_out="$RESULTS/03-candidates/nuclei-$(echo "$t" | tr '/.' '_').txt"

    if $DRY_RUN; then
      log_info "[DRY-RUN] nuclei -u https://$t (would write → $nuclei_out)"
      continue
    fi

    log_info "nuclei → $t"
    nuclei \
      -u "https://$t" \
      -severity critical,high,medium \
      -exclude-tags dos,fuzz,intrusive \
      -include-tags cve,misconfig,exposure,takeover,default-login,tech \
      -c 25 -rl 100 -bs 25 \
      -o "$nuclei_out" \
      -silent 2>/dev/null &
    pids+=("$!")
  done

  # Wait all
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

  # Lead qualification pass
  log_info "Running lead qualification gate on all nuclei output"
  _qualify_nuclei_results

  state_py set_phase 3 DONE 2>/dev/null || true
  log_info "Phase 3 DONE"
}

_qualify_nuclei_results() {
  local pursued=0 closed=0

  while IFS= read -r f; do
    [ -f "$f" ] || continue
    while IFS= read -r line; do
      [ -n "$line" ] || continue

      # Nuclei output formats vary; handle: [template-id] [severity] url
      local template severity url
      template=$(echo "$line" | grep -oP '\[\K[^\]]+(?=\])' | head -1 || echo "unknown")
      severity=$(echo "$line"  | grep -oP '\[\K(critical|high|medium|low|info)(?=\])' | head -1 || echo "info")
      url=$(echo "$line" | awk '{print $NF}')
      [ -n "$url" ] || continue

      local class; class=$(nuclei_to_class "$template" "$severity")
      local confidence="MEDIUM"
      { [ "$severity" = "critical" ] || [ "$severity" = "high" ]; } && confidence="HIGH"

      # Short deterministic ID
      local id; id="N$(echo "${template}${url}" | md5sum | cut -c1-6)"
      local evidence="template:$template severity:$severity url:$url"
      local impact="Auto-detected via nuclei/$template"

      local verdict; verdict=$(qualify_lead "$class" "$confidence" "$impact" "$evidence")
      local decision; decision=$(echo "$verdict" | cut -d: -f1)
      local qual_detail; qual_detail=$(echo "$verdict" | cut -d: -f2-)

      printf '{"id":"%s","target":"%s","class":"%s","evidence":"%s","confidence":"%s","qualify":"%s","status":"%s","ts":"%s"}\n' \
        "$id" "$url" "$class" "$evidence" "$confidence" "$qual_detail" \
        "$decision" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$CANDIDATES"

      if [ "$decision" = "PURSUE" ]; then
        log_lead "PURSUE ($qual_detail): $class @ $url"
        state_py update_lead "$id" "PURSUING" "$qual_detail" 2>/dev/null || true
        pursued=$((pursued + 1))
      else
        log_lead "AUTO_CLOSE ($qual_detail): $class @ $url"
        state_py update_lead "$id" "AUTO_CLOSED" "$qual_detail" 2>/dev/null || true
        closed=$((closed + 1))
      fi

    done < "$f"
  done < <(ls "$RESULTS/03-candidates/nuclei-"*.txt 2>/dev/null)

  log_info "Lead gate: $pursued pursuing / $closed auto-closed"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — Verification, PoC & Chain Elevation
# ══════════════════════════════════════════════════════════════════════════════
run_phase_4() {
  log_phase "4 — Verification, PoC & Chain Elevation"

  if [ ! -f "$CANDIDATES" ]; then
    log_warn "No candidates.jsonl — nothing to verify (run Phase 3 first)"
    state_py set_phase 4 DONE 2>/dev/null || true
    return 0
  fi

  local pursuing; pursuing=$(grep -c '"status":"PURSUE"' "$CANDIDATES" 2>/dev/null || echo "0")
  log_info "$pursuing candidates in PURSUE status"

  while IFS= read -r cand; do
    [ -n "$cand" ] || continue

    local id class target_url
    id=$(echo "$cand"        | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || true)
    class=$(echo "$cand"    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('class',''))" 2>/dev/null || true)
    target_url=$(echo "$cand" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('target',''))" 2>/dev/null || true)

    [ -n "$id" ] || continue

    # Dead-end check
    if is_dead_end "$id"; then
      log_decision "Skip $id — DEAD_END"
      continue
    fi

    # Scope re-check
    is_in_scope "$target_url" || { log_warn "Out-of-scope skip: $id ($target_url)"; continue; }

    log_info "Verifying $id [$class] @ $target_url"
    state_py inc_probes "$id" 2>/dev/null || true

    local verified_dir="$RESULTS/04-verified/$id"
    mkdir -p "$verified_dir"

    local ok=false
    case "$class" in
      subdomain-takeover)        _verify_subdomain_takeover "$id" "$target_url" "$verified_dir" && ok=true ;;
      credential-exposure)       _verify_credential_exposure "$id" "$target_url" "$verified_dir" && ok=true ;;
      default-creds)             _verify_default_creds "$id" "$target_url" "$verified_dir" && ok=true ;;
      SSRF*|IDOR*|BOLA*|SQLi*|RCE*|account-takeover|auth-bypass|oauth-hijack|JWT-attack|cross-tenant)
        log_info "Manual verification required for $class — queueing"
        echo "MANUAL: $id [$class] @ $target_url — requires authenticated session or OOB infrastructure" \
          > "$verified_dir/verification.txt"
        echo "VERDICT: NEEDS_MANUAL" >> "$verified_dir/verification.txt"
        echo "$id" >> "$RESULTS/04-verified/manual-queue.txt" ;;
      *)
        log_info "No auto-verifier for $class — queuing for manual"
        echo "MANUAL: $id [$class]" > "$verified_dir/verification.txt"
        echo "VERDICT: NEEDS_MANUAL" >> "$verified_dir/verification.txt"
        echo "$id" >> "$RESULTS/04-verified/manual-queue.txt" ;;
    esac

    if $ok; then
      log_info "VERIFIED: $id [$class]"
      state_py update_lead "$id" "VERIFIED" "auto-confirmed" 2>/dev/null || true
      state_py add_verified "$id" 2>/dev/null || true

      # Chain elevation
      local chain_tests; chain_tests=$(chain_next_tests "$class")
      if [ -n "$chain_tests" ]; then
        log_decision "Chain elevation for $id ($class) — queuing: $chain_tests"
        {
          echo "# Chain tests for $id [$class]"
          echo "# Each must be tested to confirm/deny elevation"
          for ct in $chain_tests; do
            echo "[ ] $ct"
            state_py chain_update "$id" "$ct" "PENDING" 2>/dev/null || true
          done
        } > "$verified_dir/chain-queue.txt"
      fi
    fi

  done < <(grep '"status":"PURSUE"' "$CANDIDATES" 2>/dev/null || true)

  state_py set_phase 4 DONE 2>/dev/null || true
  log_info "Phase 4 DONE"
}

_verify_subdomain_takeover() {
  local id="$1" target="$2" outdir="$3"
  local host="${target#*://}"; host="${host%%/*}"; host="${host%%:*}"

  local cname; cname=$(dig +short CNAME "$host" 2>/dev/null | head -1 | sed 's/\.$//' || echo "")
  local body; body=$(curl -sk --connect-timeout 12 --max-time 20 "https://$host/" 2>/dev/null \
    || curl -sk --connect-timeout 12 --max-time 20 "http://$host/" 2>/dev/null || echo "")

  {
    echo "=== Subdomain Takeover Verification: $host ==="
    echo "CNAME: ${cname:-NONE}"
    echo "BODY_SNIPPET:"
    echo "${body:0:800}"
    echo ""

    local confirmed=false
    for fp in \
      "DEPLOYMENT_NOT_FOUND" "NoSuchBucket" "NoSuchKey" \
      "There isn't a GitHub Pages site here" "Repository not found" \
      "Project not found" "doesn't exist" "Fastly error" \
      "No such app" "herokucdn" "isn't a GitHub Pages site" \
      "azurewebsites.net" "404 Not Found" "page not found"; do
      if echo "$body" | grep -qi "$fp"; then
        echo "FINGERPRINT_MATCH: $fp"
        confirmed=true
        break
      fi
    done

    if $confirmed && [ -n "$cname" ]; then
      echo ""
      echo "VERDICT: CONFIRMED_TAKEOVER — $host CNAME $cname shows takeover fingerprint"
    else
      echo ""
      echo "VERDICT: NOT_CONFIRMED — CNAME=${cname:-none}, no takeover fingerprint"
    fi
  } > "$outdir/verification.txt" 2>&1

  grep -q "VERDICT: CONFIRMED_TAKEOVER" "$outdir/verification.txt"
}

_verify_credential_exposure() {
  local id="$1" target="$2" outdir="$3"
  local body; body=$(curl -sk --connect-timeout 12 --max-time 20 "$target" 2>/dev/null || echo "")
  {
    echo "=== Credential Exposure Verification: $target ==="
    echo "RESPONSE_SNIPPET: ${body:0:2000}"
    if echo "$body" | grep -qiE '(api[_-]?key|secret[_-]?key|access[_-]?key|password|token|private[_-]?key)[[:space:]]*[=:][[:space:]]*[A-Za-z0-9/+_-]{20,}'; then
      echo "VERDICT: CONFIRMED — credential pattern found"
    else
      echo "VERDICT: NOT_CONFIRMED — no active credential pattern"
    fi
  } > "$outdir/verification.txt" 2>&1
  grep -q "VERDICT: CONFIRMED" "$outdir/verification.txt"
}

_verify_default_creds() {
  local id="$1" target="$2" outdir="$3"
  {
    echo "=== Default Credentials Verification: $target ==="
    local confirmed=false
    for creds in "admin:admin" "admin:password" "admin:grafana" "admin:123456" "admin:" "grafana:admin"; do
      local user="${creds%%:*}" pass="${creds#*:}"
      local resp; resp=$(curl -sk --connect-timeout 10 --max-time 15 \
        -u "$user:$pass" "$target/api/org" 2>/dev/null | head -c 200 || true)
      echo "CREDS $creds → ${resp:0:80}"
      if echo "$resp" | grep -qi '"id"'; then
        echo "VERDICT: CONFIRMED — default credentials $creds work"
        confirmed=true
        break
      fi
    done
    $confirmed || echo "VERDICT: NOT_CONFIRMED — no default credentials accepted"
  } > "$outdir/verification.txt" 2>&1
  grep -q "VERDICT: CONFIRMED" "$outdir/verification.txt"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — Triage & Pre-Submission Gate
# ══════════════════════════════════════════════════════════════════════════════
run_phase_5() {
  log_phase "5 — Triage, CVSS & Pre-Submission Gate"

  mkdir -p "$RESULTS/05-triage"
  local triage="$RESULTS/05-triage/triage.md"

  {
    echo "# Triage Report — $TARGET"
    echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "## Verified Findings"
    echo ""
    echo "| ID | Class | CVSS | Dedup | Report-Ready? | Notes |"
    echo "|----|-------|------|-------|---------------|-------|"

    local vcount=0
    while IFS= read -r vdir; do
      local vid; vid=$(basename "$vdir")
      local vfile="$vdir/verification.txt"
      [ -f "$vfile" ] || continue
      local verdict; verdict=$(grep "VERDICT:" "$vfile" | tail -1 | sed 's/VERDICT: //')
      local chain_pending=0
      [ -f "$vdir/chain-queue.txt" ] && chain_pending=$(grep -c '^\[ \]' "$vdir/chain-queue.txt" 2>/dev/null || echo "0")
      echo "| $vid | auto | TBD | novel | TBD | $verdict (chain-pending: $chain_pending) |"
      vcount=$((vcount + 1))
    done < <(ls -d "$RESULTS/04-verified"/*/ 2>/dev/null || true)

    [ "$vcount" -eq 0 ] && echo "| — | — | — | — | — | No auto-verified findings — see manual-queue |"

    echo ""
    echo "## Manual Verification Queue"
    echo ""
    if [ -f "$RESULTS/04-verified/manual-queue.txt" ]; then
      cat "$RESULTS/04-verified/manual-queue.txt"
    else
      echo "(empty)"
    fi

    echo ""
    echo "## Auto-Closed Leads"
    echo ""
    grep '"status":"AUTO_CLOSE"' "$CANDIDATES" 2>/dev/null | python3 -c "
import json,sys
for line in sys.stdin:
    try:
        d = json.loads(line)
        print(f\"- {d.get('id','?')}: {d.get('class','?')} — {d.get('qualify','')[:100]}\")
    except: pass
" 2>/dev/null || echo "(none)"

    echo ""
    echo "## Dead-End Leads"
    echo ""
    grep '"status":"DEAD_END"' "$CANDIDATES" 2>/dev/null | python3 -c "
import json,sys
for line in sys.stdin:
    try:
        d = json.loads(line)
        print(f\"- {d.get('id','?')}: {d.get('class','?')} — {d.get('qualify','')[:100]}\")
    except: pass
" 2>/dev/null || echo "(none)"

    echo ""
    echo "## Pre-Submission Checklist"
    echo ""
    echo "For each finding before submitting:"
    echo "- [ ] Attacker gain is concrete and specific"
    echo "- [ ] Behavior NOT documented as intended"
    echo "- [ ] Vendor would actually fix this (code/config change)"
    echo "- [ ] Not in CLAUDE.md §3 hard rejection list (or chained past it)"
    echo "- [ ] CVSS ≥ 4.0 OR confirmed chain to CVSS ≥ 4.0"
    echo "- [ ] Not a known duplicate (checked program known-issues + results/)"
    echo "- [ ] Reproducible from clean state — PoC exists"
    echo "- [ ] Google VRP tier confirmed for target host"
    echo "- [ ] Chain tests completed (see chain-queue.txt per finding)"

  } > "$triage"

  log_info "Triage → $triage"
  state_py set_phase 5 DONE 2>/dev/null || true
  log_info "Phase 5 DONE"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 — Report Generation
# ══════════════════════════════════════════════════════════════════════════════
run_phase_6() {
  log_phase "6 — Report Generation"

  mkdir -p "$RESULTS/findings"

  local rcount=0
  while IFS= read -r vdir; do
    local vid; vid=$(basename "$vdir")
    local vfile="$vdir/verification.txt"
    [ -f "$vfile" ] || continue

    if grep -q "VERDICT: CONFIRMED" "$vfile" 2>/dev/null; then
      local report="$RESULTS/findings/${vid}-report.md"
      if [ ! -f "$report" ] || $FORCE; then
        _generate_draft_report "$vid" "$vfile" "$vdir" "$report"
        rcount=$((rcount + 1))
      fi
    fi
  done < <(ls -d "$RESULTS/04-verified"/*/ 2>/dev/null || true)

  log_info "Phase 6: $rcount draft reports generated in $RESULTS/findings/"
  state_py set_phase 6 DONE 2>/dev/null || true
  log_info "Phase 6 DONE"
}

_generate_draft_report() {
  local id="$1" vfile="$2" vdir="$3" output="$4"
  local verdict; verdict=$(grep "VERDICT:" "$vfile" | tail -1)

  cat > "$output" <<EOF
# DRAFT — $id  [needs manual completion]
# Use templates/report.md as the final format

## Title
[Bug class] [Impact] via [Location] — $id

## Summary
[2–3 sentences: what, where, why it matters]

## Severity
CVSS 3.1: [vector]   Score: [X.X]
Business impact: [one sentence]

## Steps to Reproduce
1. [From a clean state]
2. [Copy-pasteable steps]
3. [Observable evidence]

## Proof
[Sanitized request/response — no real secrets or PII]

Verification evidence:
$(cat "$vfile")

## Chain Tests Outstanding
$(cat "$vdir/chain-queue.txt" 2>/dev/null || echo "(none)")

## Impact
[Concrete attacker capability — what they gain, whose data/account]

## Remediation
[Specific fix tied to root cause]

## References
- CWE: [CWE-XXX]
- OWASP: [A0X:2021]
EOF
  log_info "Draft report: $output"
}

# ══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE RE-PLAN  (runs after each phase)
# ══════════════════════════════════════════════════════════════════════════════
intelligence_replan() {
  local after_phase="$1"
  log_info "Intelligence re-plan after phase $after_phase"

  case "$after_phase" in
    2)
      if [ -f "$RESULTS/02-surface/priority.md" ]; then
        log_decision "Surface map ready — updating hunt thesis in 00-plan.md"
        {
          echo ""
          echo "## Updated Hunt Thesis (after Phase 2 — $(date -u +%Y-%m-%dT%H:%M:%SZ))"
          echo ""
          echo "### Top priority targets:"
          head -25 "$RESULTS/02-surface/priority.md" 2>/dev/null || true
          echo ""
          echo "### Recommended Phase 3 focus (based on surface map):"
          echo "1. Any non-production / dev / staging / RDE hosts → relaxed auth"
          echo "2. GraphQL endpoints → IDOR / cross-tenant"
          echo "3. Webhook / integration endpoints → SSRF"
          echo "4. Subdomains with dangling CNAMEs → takeover"
          echo "5. Admin / internal-exposed hosts → default creds, unauth access"
        } >> "$RESULTS/00-plan.md"
      fi
      ;;
    3)
      local high_count; high_count=$(grep -c '"confidence":"HIGH"' "$CANDIDATES" 2>/dev/null || echo "0")
      local pursue_count; pursue_count=$(grep -c '"status":"PURSUE"' "$CANDIDATES" 2>/dev/null || echo "0")
      log_decision "Phase 3 result: $pursue_count pursuing ($high_count HIGH confidence)"
      if grep -q '"class":"SSRF' "$CANDIDATES" 2>/dev/null; then
        log_decision "SSRF candidate found → chain tests for metadata + internal services queued in Phase 4"
      fi
      if grep -q '"class":"subdomain-takeover"' "$CANDIDATES" 2>/dev/null; then
        log_decision "Subdomain takeover candidate → chain tests for CSP + OAuth redirect queued in Phase 4"
      fi
      ;;
    4)
      local v; v=$(find "$RESULTS/04-verified" -name "verification.txt" 2>/dev/null \
        | xargs -I{} grep -l "CONFIRMED" {} 2>/dev/null | wc -l || echo "0")
      local m; m=$(cat "$RESULTS/04-verified/manual-queue.txt" 2>/dev/null | wc -l)
      log_decision "Phase 4: $v auto-verified, $m need manual verification"
      if [ "$v" -eq 0 ] && [ "$m" -eq 0 ]; then
        log_decision "Zero findings — consider: (1) Trial account for SSRF/IDOR, (2) Deeper JS analysis, (3) Manual auth testing"
        {
          echo ""
          echo "## Re-plan after Phase 4 ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
          echo "Zero auto-verified findings. Next steps:"
          echo "1. Obtain trial account → run scripts/phase4-trial-account-wiz.sh"
          echo "2. Test webhook SSRF manually (Chain 3)"
          echo "3. Test cross-tenant GraphQL IDOR with 2 accounts (Chain 4)"
          echo "4. Re-run Phase 3 with --force after Phase 1+2 if recon is now complete"
        } >> "$RESULTS/00-plan.md"
      fi
      ;;
  esac
}

# ══════════════════════════════════════════════════════════════════════════════
# STATUS SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
print_status() {
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════════╗"
  printf "║  ORCHESTRATOR STATUS — %-46s ║\n" "$TARGET"
  echo "╚══════════════════════════════════════════════════════════════════════╝"

  echo ""
  echo "PHASE STATUS:"
  for p in 0 1 2 3 4 5 6; do
    local s; s=$(state_py get_phase "$p" 2>/dev/null || echo "NOT_RUN")
    printf "  Phase %s: %s\n" "$p" "$s"
  done

  echo ""
  echo "LEADS:"
  if [ -f "$CANDIDATES" ]; then
    local tot pur cls dead
    tot=$(wc -l  < "$CANDIDATES"  2>/dev/null || echo "0")
    pur=$(grep -c '"status":"PURSUE"'    "$CANDIDATES" 2>/dev/null || echo "0")
    cls=$(grep -c '"status":"AUTO_CLOSE"' "$CANDIDATES" 2>/dev/null || echo "0")
    dead=$(grep -c '"status":"DEAD_END"' "$CANDIDATES" 2>/dev/null || echo "0")
    echo "  Total=$tot  Pursuing=$pur  Auto-closed=$cls  Dead-ends=$dead"
  else
    echo "  (no candidates yet)"
  fi

  echo ""
  echo "VERIFIED FINDINGS:"
  local vcount=0
  while IFS= read -r vdir; do
    local vf="$vdir/verification.txt"
    if [ -f "$vf" ] && grep -q "VERDICT: CONFIRMED" "$vf" 2>/dev/null; then
      local vid; vid=$(basename "$vdir")
      echo "  ✓ $vid"
      vcount=$((vcount + 1))
    fi
  done < <(ls -d "$RESULTS/04-verified"/*/ 2>/dev/null || true)
  [ "$vcount" -eq 0 ] && echo "  (none auto-confirmed)"

  echo ""
  echo "MANUAL QUEUE:"
  if [ -s "$RESULTS/04-verified/manual-queue.txt" ]; then
    sed 's/^/  → /' "$RESULTS/04-verified/manual-queue.txt"
  else
    echo "  (empty)"
  fi

  echo ""
  echo "NEXT ACTION:"
  if state_phase_done 6; then
    echo "  Pipeline complete — submit reports at bughunters.google.com"
  elif state_phase_done 5; then
    echo "  Phase 6: run report generation, then submit"
  elif state_phase_done 4; then
    echo "  Phase 5: triage + pre-submission gate"
  elif state_phase_done 3; then
    echo "  Phase 4: verification + chain elevation"
  elif state_phase_done 2; then
    echo "  Phase 3: vulnerability discovery"
  elif state_phase_done 1; then
    echo "  Phase 2: surface mapping"
  elif state_phase_done 0; then
    echo "  Phase 1+2: asset discovery + surface mapping"
  else
    echo "  Phase 0: scope gate + plan"
  fi

  echo ""
  echo "  State: $STATE"
  echo "  Log:   $LOG"
  echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
main() {
  log_info "══ Bug Bounty Orchestrator v2.0 ══  target=$TARGET  phases=${START_PHASE}-${END_PHASE}  bg=$BACKGROUND  dry=$DRY_RUN"

  state_init

  if $STATUS_ONLY; then print_status; exit 0; fi

  local phase
  for phase in $(seq "$START_PHASE" "$END_PHASE"); do
    # Resume: skip completed phases unless --force
    if ! state_should_run "$phase"; then
      log_info "Phase $phase already DONE — skipping (--force to re-run)"
      continue
    fi

    case "$phase" in
      0) run_phase_0 ;;
      1) run_phase_12 ;;  # phases 1+2 run together
      2) ;;               # handled by phase 1
      3) run_phase_3 ;;
      4) run_phase_4 ;;
      5) run_phase_5 ;;
      6) run_phase_6 ;;
    esac

    intelligence_replan "$phase"
  done

  print_status
}

main "$@"
