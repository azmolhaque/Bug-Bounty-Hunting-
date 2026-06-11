#!/usr/bin/env bash
# pi-resource-guard.sh — Pi 5 adaptive resource monitor
#
# Reports current CPU/RAM/Temperature and blocks (with sleep) until
# resources are below configured thresholds. Designed for Raspberry Pi 5
# (ARM64, 16 GB, active cooling recommended).
#
# Usage:
#   ./scripts/pi-resource-guard.sh [--max-temp N] [--max-ram N] [--max-cpu N] [--report]
#
#   --max-temp N   throttle temperature ceiling in °C  (default: 78)
#   --max-ram  N   throttle RAM usage ceiling in %     (default: 82)
#   --max-cpu  N   throttle CPU usage ceiling in %     (default: 88)
#   --report       print stats and exit without blocking
#   --wait         keep sleeping until all metrics are below threshold
#
# Exit codes:
#   0 = resources OK (all below threshold)
#   1 = resources stressed (if --report is used without --wait)
#
# Example in a script:
#   ./scripts/pi-resource-guard.sh --wait || true
#   # Now safe to launch next parallel task

set -uo pipefail

MAX_TEMP=${MAX_TEMP:-78}
MAX_RAM=${MAX_RAM:-82}
MAX_CPU=${MAX_CPU:-88}
REPORT_ONLY=false
WAIT_MODE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-temp) shift; MAX_TEMP="$1" ;;
    --max-ram)  shift; MAX_RAM="$1"  ;;
    --max-cpu)  shift; MAX_CPU="$1"  ;;
    --report)   REPORT_ONLY=true ;;
    --wait)     WAIT_MODE=true ;;
    *) echo "Unknown arg: $1" >&2 ;;
  esac
  shift
done

get_temp_c() {
  local raw=0
  for zone in /sys/class/thermal/thermal_zone*/temp; do
    [ -f "$zone" ] || continue
    local t; t=$(cat "$zone" 2>/dev/null || echo "0")
    [ "$t" -gt "$raw" ] && raw="$t"
  done
  echo $((raw / 1000))
}

get_ram_pct() {
  local total avail
  total=$(grep MemTotal   /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "16384000")
  avail=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "16384000")
  local used=$((total - avail))
  echo $((used * 100 / total))
}

get_cpu_pct() {
  # /proc/stat delta — avoids top's stray terminal output on Pi OS
  local line1 line2
  read -r line1 < /proc/stat 2>/dev/null || { echo "0"; return; }
  sleep 0.3
  read -r line2 < /proc/stat 2>/dev/null || { echo "0"; return; }
  local used
  used=$(awk -v l1="$line1" -v l2="$line2" 'BEGIN {
    n = split(l1, a); split(l2, b)
    idle1 = a[5]; idle2 = b[5]
    total1=0; total2=0
    for (i=2;i<=n;i++) { total1+=a[i]; total2+=b[i] }
    td = total2 - total1; id = idle2 - idle1
    if (td > 0) print int((td - id) * 100 / td); else print 0
  }')
  local used=$((used + 0))
  echo "$used"
}

get_active_nuclei() {
  pgrep -c nuclei 2>/dev/null || echo "0"
}

print_stats() {
  local temp; temp=$(get_temp_c)
  local ram;  ram=$(get_ram_pct)
  local cpu;  cpu=$(get_cpu_pct)
  local nuc;  nuc=$(get_active_nuclei)

  local temp_status="OK"; [ "$temp" -ge "$MAX_TEMP" ] && temp_status="THROTTLE"
  local ram_status="OK";  [ "$ram"  -ge "$MAX_RAM"  ] && ram_status="THROTTLE"
  local cpu_status="OK";  [ "$cpu"  -ge "$MAX_CPU"  ] && cpu_status="THROTTLE"

  printf "Pi5 Resources  |  TEMP: %3d°C [%s]  |  RAM: %3d%% [%s]  |  CPU: %3d%% [%s]  |  nuclei: %s\n" \
    "$temp" "$temp_status" "$ram" "$ram_status" "$cpu" "$cpu_status" "$nuc"
}

is_stressed() {
  local temp; temp=$(get_temp_c)
  local ram;  ram=$(get_ram_pct)
  local cpu;  cpu=$(get_cpu_pct)

  [ "$temp" -ge "$MAX_TEMP" ] && return 0
  [ "$ram"  -ge "$MAX_RAM"  ] && return 0
  [ "$cpu"  -ge "$MAX_CPU"  ] && return 0
  return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if $REPORT_ONLY; then
  print_stats
  is_stressed && exit 1 || exit 0
fi

if $WAIT_MODE; then
  local_pass=0
  while is_stressed; do
    print_stats
    local temp; temp=$(get_temp_c)
    local ram;  ram=$(get_ram_pct)
    local cpu;  cpu=$(get_cpu_pct)

    local delay=30
    [ "$temp" -ge "$MAX_TEMP" ] && delay=120
    [ "$ram"  -ge "$MAX_RAM"  ] && delay=60

    echo "[pi-resource-guard] Resources stressed — waiting ${delay}s" >&2
    sleep "$delay"
    local_pass=$((local_pass + 1))
    [ "$local_pass" -gt 20 ] && { echo "[pi-resource-guard] Waited too long, proceeding anyway" >&2; break; }
  done
  print_stats
  exit 0
fi

# Default: check once, exit code reflects state
print_stats
is_stressed && exit 1 || exit 0
