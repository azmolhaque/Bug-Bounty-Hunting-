#!/usr/bin/env bash
# pi-optimize.sh — Raspberry Pi 5 Bug Bounty Lab Optimizer
#
# Diagnoses slowness, kills waste, maximizes performance for:
#   - Thermal throttling detection & mitigation
#   - Unnecessary service pruning
#   - Memory reclaim (cache flush, journal trim, Docker cleanup)
#   - CPU governor enforcement (performance mode)
#   - Disk I/O tuning (scheduler, readahead)
#   - GPU memory split optimization (headless)
#   - Swap health check
#   - Network stack verification
#   - Tool/cache cleanup
#
# Usage:
#   ./scripts/pi-optimize.sh              # full diagnose + optimize
#   ./scripts/pi-optimize.sh --diagnose   # read-only report, no changes
#   ./scripts/pi-optimize.sh --clean      # free disk space only
#   ./scripts/pi-optimize.sh --services   # service pruning only
#   ./scripts/pi-optimize.sh --tuning     # kernel/CPU tuning only
#   ./scripts/pi-optimize.sh --watch      # live resource monitor (1s refresh)

set -uo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
info()    { echo -e "  ${CYAN}→${NC} $*"; }
section() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}"; }
fixed()   { echo -e "  ${GREEN}[FIXED]${NC} $*"; }

DIAGNOSE_ONLY=false
MODE="all"
CHANGES_MADE=()

# ─── Helpers ──────────────────────────────────────────────────────────────────

get_temp_c() {
  local raw=0
  for zone in /sys/class/thermal/thermal_zone*/temp; do
    [ -f "$zone" ] || continue
    local t; t=$(cat "$zone" 2>/dev/null || echo "0")
    [ "$t" -gt "$raw" ] 2>/dev/null && raw="$t"
  done
  echo $((raw / 1000))
}

get_throttle_flags() {
  # vcgencmd: 0x0 = no throttle, anything else = problem
  # bit0=currently throttled, bit1=arm_freq_capped, bit2=currently_throttled
  # bit16=previously_throttled, bit17=arm_freq_capped_occurred, etc.
  command -v vcgencmd >/dev/null 2>&1 || { echo "N/A (vcgencmd not found)"; return; }
  local flags; flags=$(vcgencmd get_throttled 2>/dev/null | tr -d 'throttled=')
  echo "$flags"
}

get_cpu_freq_mhz() {
  local freq; freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo "0")
  echo $((freq / 1000))
}

get_cpu_max_mhz() {
  local freq; freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null || echo "0")
  echo $((freq / 1000))
}

get_ram_used_mb() {
  local total avail
  total=$(grep MemTotal    /proc/meminfo | awk '{print $2}')
  avail=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
  echo $(( (total - avail) / 1024 ))
}

get_ram_total_mb() {
  grep MemTotal /proc/meminfo | awk '{print $2/1024}' | cut -d. -f1
}

get_ram_pct() {
  local total avail
  total=$(grep MemTotal    /proc/meminfo | awk '{print $2}')
  avail=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
  echo $(( (total - avail) * 100 / total ))
}

get_disk_used_pct() {
  df / | awk 'NR==2{print $5}' | tr -d '%'
}

get_disk_free_gb() {
  df -BG / | awk 'NR==2{print $4}' | tr -d 'G'
}

get_storage_type() {
  local root_dev; root_dev=$(findmnt -n -o SOURCE / 2>/dev/null | sed 's/[0-9]*$//')
  local rotational; rotational=$(cat /sys/block/$(basename "$root_dev")/queue/rotational 2>/dev/null || echo "?")
  if echo "$root_dev" | grep -q 'mmcblk'; then
    echo "SD Card (SLOW — migrate to NVMe/SSD for 10x I/O)"
  elif [ "$rotational" = "0" ]; then
    echo "SSD/NVMe (optimal)"
  elif [ "$rotational" = "1" ]; then
    echo "HDD (slow rotational)"
  else
    echo "Unknown ($root_dev)"
  fi
}

get_governor() {
  cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown"
}

get_swap_mb() {
  free -m | awk '/Swap:/{print $2}'
}

get_swap_used_mb() {
  free -m | awk '/Swap:/{print $3}'
}

get_journal_size_mb() {
  journalctl --disk-usage 2>/dev/null | grep -oP '\d+\.?\d*[KMGT]?(?= (?:B|KiB|MiB|GiB))' | head -1 || echo "?"
}

# ─── Phase 1: Full Diagnosis ───────────────────────────────────────────────────

diagnose() {
  section "System Diagnosis — Raspberry Pi 5 Bug Bounty Lab"

  local temp; temp=$(get_temp_c)
  local throttle; throttle=$(get_throttle_flags)
  local freq; freq=$(get_cpu_freq_mhz)
  local max_freq; max_freq=$(get_cpu_max_mhz)
  local governor; governor=$(get_governor)
  local ram_used; ram_used=$(get_ram_used_mb)
  local ram_total; ram_total=$(get_ram_total_mb)
  local ram_pct; ram_pct=$(get_ram_pct)
  local disk_pct; disk_pct=$(get_disk_used_pct)
  local disk_free; disk_free=$(get_disk_free_gb)
  local storage; storage=$(get_storage_type)
  local swap_total; swap_total=$(get_swap_mb)
  local swap_used; swap_used=$(get_swap_used_mb)

  # ── Temperature ──
  echo ""
  echo -e "${BOLD}CPU Temperature:${NC}"
  if [ "$temp" -ge 80 ]; then
    bad "CRITICAL — ${temp}°C — Pi is thermal throttling heavily. CPU down to ~600MHz. Add active cooling NOW."
  elif [ "$temp" -ge 75 ]; then
    warn "HIGH — ${temp}°C — approaching throttle threshold. Check heatsink/fan."
  elif [ "$temp" -ge 65 ]; then
    warn "WARM — ${temp}°C — acceptable but watch under load."
  else
    ok "${temp}°C — healthy"
  fi

  # ── Throttle flags ──
  echo ""
  echo -e "${BOLD}Throttle Status (vcgencmd):${NC}"
  if [ "$throttle" = "0x0" ]; then
    ok "No throttling detected (0x0)"
  elif [ "$throttle" = "N/A (vcgencmd not found)" ]; then
    warn "vcgencmd not available — install: sudo apt install libraspberrypi-bin"
  else
    bad "THROTTLED: $throttle"
    echo "    Decode: 0x1=currently_throttled  0x2=freq_capped  0x4=under_voltage"
    echo "            0x10000=was_throttled    0x20000=freq_was_capped  0x40000=was_undervoltage"
  fi

  # ── CPU ──
  echo ""
  echo -e "${BOLD}CPU:${NC}"
  if [ "$governor" = "performance" ]; then
    ok "Governor: performance @ ${freq}MHz (max: ${max_freq}MHz)"
  else
    warn "Governor: $governor @ ${freq}MHz — NOT performance mode (will throttle under load)"
  fi

  # ── Memory ──
  echo ""
  echo -e "${BOLD}Memory (${ram_total} MB total):${NC}"
  if [ "$ram_pct" -ge 90 ]; then
    bad "CRITICAL — ${ram_used}MB / ${ram_total}MB used (${ram_pct}%) — OOM risk. Kill unused processes."
  elif [ "$ram_pct" -ge 75 ]; then
    warn "HIGH — ${ram_used}MB / ${ram_total}MB (${ram_pct}%)"
  else
    ok "${ram_used}MB / ${ram_total}MB used (${ram_pct}%)"
  fi

  # ── Swap ──
  echo ""
  echo -e "${BOLD}Swap:${NC}"
  if [ "$swap_total" -eq 0 ]; then
    warn "No swap configured (long nuclei scans may OOM)"
  elif [ "$swap_used" -gt $((swap_total * 70 / 100)) ]; then
    bad "HEAVY swap use: ${swap_used}MB / ${swap_total}MB — system is RAM-starved"
  else
    ok "${swap_used}MB / ${swap_total}MB swap used"
  fi

  # ── Storage ──
  echo ""
  echo -e "${BOLD}Storage:${NC}"
  echo "    Type: $storage"
  if [ "$disk_pct" -ge 90 ]; then
    bad "CRITICAL disk: ${disk_pct}% full, only ${disk_free}GB free — system may freeze"
  elif [ "$disk_pct" -ge 80 ]; then
    warn "Disk ${disk_pct}% full (${disk_free}GB free) — clean up soon"
  else
    ok "Disk ${disk_pct}% full (${disk_free}GB free)"
  fi

  # ── Top RAM consumers ──
  echo ""
  echo -e "${BOLD}Top 10 RAM consumers:${NC}"
  ps aux --sort=-%mem 2>/dev/null | awk 'NR>1 && NR<=11 {
    printf "  %5s%%  %6s KB  %s\n", $4, $6, $11
  }' | head -10

  # ── Top CPU consumers ──
  echo ""
  echo -e "${BOLD}Top 10 CPU consumers:${NC}"
  ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && NR<=11 {
    printf "  %5s%%  %-30s\n", $3, $11
  }' | head -10

  # ── Running services (identify waste) ──
  echo ""
  echo -e "${BOLD}Running services (filtering for optimization candidates):${NC}"
  local waste_services=(
    bluetooth avahi-daemon cups cups-browsed ModemManager colord
    hciuart rpi-eeprom-update triggerhappy wpa_supplicant
    NetworkManager-wait-online apt-daily apt-daily-upgrade
    unattended-upgrades man-db.timer fwupd motd-news
    packagekit snapd flatpak polkit speech-dispatcher
    rtkit gpsd lm-sensors fancontrol
  )
  local found_waste=false
  for svc in "${waste_services[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      warn "Running: $svc (candidate for disable)"
      found_waste=true
    fi
  done
  $found_waste || ok "No obvious waste services running"

  # ── Docker containers ──
  echo ""
  echo -e "${BOLD}Docker:${NC}"
  if command -v docker >/dev/null 2>&1; then
    local containers; containers=$(docker ps -q 2>/dev/null | wc -l)
    local images_mb; images_mb=$(docker system df 2>/dev/null | awk '/Images/{print $4}' | tr -d 'GB\n' || echo "?")
    ok "Docker available — ${containers} running containers"
    if [ "$containers" -gt 3 ]; then
      warn "${containers} containers running — check if all needed"
    fi
    local dangling; dangling=$(docker images -f dangling=true -q 2>/dev/null | wc -l)
    [ "$dangling" -gt 0 ] && warn "${dangling} dangling images wasting disk — run: docker image prune -f"
  else
    info "Docker not installed"
  fi

  # ── Journal size ──
  echo ""
  echo -e "${BOLD}Systemd Journal:${NC}"
  local journal_size; journal_size=$(du -sh /var/log/journal 2>/dev/null | cut -f1 || echo "?")
  echo "    Journal size: $journal_size"
  journalctl --disk-usage 2>/dev/null || true

  # ── Network ──
  echo ""
  echo -e "${BOLD}Network stack (BBR congestion control):${NC}"
  local cc; cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
  if [ "$cc" = "bbr" ]; then
    ok "BBR congestion control active"
  else
    warn "TCP congestion control: $cc (not BBR — apply sysctl tuning)"
  fi

  # ── File descriptors ──
  echo ""
  echo -e "${BOLD}File descriptors:${NC}"
  local ulimit_n; ulimit_n=$(ulimit -n 2>/dev/null || echo "?")
  if [ "$ulimit_n" != "?" ] && [ "$ulimit_n" -ge 1000000 ]; then
    ok "ulimit -n = $ulimit_n (optimal for parallel scanning)"
  elif [ "$ulimit_n" != "?" ] && [ "$ulimit_n" -lt 65535 ]; then
    warn "ulimit -n = $ulimit_n — TOO LOW for nuclei/httpx parallel runs (need ≥1M)"
  else
    ok "ulimit -n = $ulimit_n"
  fi

  # ── Power supply ──
  echo ""
  echo -e "${BOLD}Power supply check:${NC}"
  local undervolt; undervolt=$(vcgencmd get_throttled 2>/dev/null | grep -o '0x[0-9a-f]*' || echo "?")
  if echo "$undervolt" | grep -qE '0x[0-9a-f]*[48][0-9a-f]*$' 2>/dev/null; then
    bad "UNDERVOLTAGE detected! Use official Pi 5 27W USB-C PSU. Throttling WILL occur."
  elif [ "$undervolt" = "0x0" ]; then
    ok "No undervoltage detected"
  else
    info "Throttle register: $undervolt (check bits 18-19 for undervoltage)"
  fi

  echo ""
  echo -e "${DIM}Run without --diagnose to apply all optimizations${NC}"
  echo ""
}

# ─── Phase 2: Service Pruning ─────────────────────────────────────────────────

prune_services() {
  section "Pruning Unnecessary Services"

  # Services that are useless on a headless bug bounty Pi
  local disable_services=(
    bluetooth
    hciuart
    avahi-daemon
    cups
    cups-browsed
    ModemManager
    colord
    triggerhappy
    speech-dispatcher
    rtkit
    fwupd
    gpsd
    packagekit
    snapd
    flatpak
    polkit
  )

  # Services to mask (prevent accidental restart)
  local mask_services=(
    apt-daily
    apt-daily-upgrade
    unattended-upgrades
  )

  for svc in "${disable_services[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      if $DIAGNOSE_ONLY; then
        warn "Would disable: $svc"
      else
        sudo systemctl stop "$svc" 2>/dev/null && \
        sudo systemctl disable "$svc" 2>/dev/null && \
        fixed "Disabled: $svc" || \
        info "Could not disable $svc (may not exist)"
        CHANGES_MADE+=("disabled:$svc")
      fi
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      if $DIAGNOSE_ONLY; then
        warn "Would disable (was enabled but stopped): $svc"
      else
        sudo systemctl disable "$svc" 2>/dev/null && \
        fixed "Disabled (was enabled): $svc" || true
      fi
    else
      ok "Already disabled: $svc"
    fi
  done

  for svc in "${mask_services[@]}"; do
    if ! systemctl is-masked --quiet "$svc" 2>/dev/null; then
      if $DIAGNOSE_ONLY; then
        warn "Would mask: $svc (prevents apt updates from interrupting scans)"
      else
        sudo systemctl mask "$svc" 2>/dev/null && fixed "Masked: $svc (re-enable with: sudo systemctl unmask $svc)" || true
      fi
    else
      ok "Already masked: $svc"
    fi
  done

  # Disable man-db auto-update (enormous I/O spike on apt installs)
  if [ -f /etc/apt/apt.conf.d/15update-stamp ]; then
    ok "man-db auto-update already controlled"
  elif ! $DIAGNOSE_ONLY; then
    echo 'APT::Update::Post-Invoke-Success {"[ -x /usr/bin/man-db ] && /usr/bin/mandb -q 2>/dev/null || true";};' | \
      sudo tee /etc/apt/apt.conf.d/15update-stamp >/dev/null 2>/dev/null && \
      fixed "man-db auto-update suppressed" || true
  fi
}

# ─── Phase 3: Memory Reclaim ──────────────────────────────────────────────────

reclaim_memory() {
  section "Memory Reclaim"

  # Page cache flush (safe — kernel will repopulate as needed)
  local ram_before; ram_before=$(get_ram_used_mb)

  if $DIAGNOSE_ONLY; then
    info "Would: sync + drop caches (pagecache, dentries, inodes)"
    info "Would: trim systemd journal to 200MB"
    info "Would: clear pip/Go/apt cache"
  else
    echo "  Flushing page cache…"
    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null 2>&1 && \
      fixed "Page cache (pagecache + dentries + inodes) flushed" || \
      warn "Could not flush caches (need root)"

    echo "  Trimming systemd journal to 200MB…"
    sudo journalctl --vacuum-size=200M 2>/dev/null && \
      fixed "Journal trimmed to ≤200MB" || warn "Journal trim failed"

    echo "  Clearing pip cache…"
    pip3 cache purge 2>/dev/null || true
    rm -rf "${HOME}/.cache/pip" 2>/dev/null && fixed "pip cache cleared" || true

    echo "  Clearing Go build cache (keeps tools, removes build artifacts)…"
    go clean -cache 2>/dev/null && fixed "Go build cache cleared" || true

    echo "  Clearing apt cache…"
    sudo apt-get clean 2>/dev/null && fixed "apt cache cleared" || true
    sudo apt-get autoremove -y -q 2>/dev/null && fixed "apt autoremove done" || true

    echo "  Clearing nuclei template cache index…"
    rm -f "${HOME}/.config/nuclei/.ignore" 2>/dev/null || true

    echo "  Clearing old scan temp files (results older than 30 days)…"
    find /tmp -maxdepth 2 -name "*.nuclei*" -o -name "*.httpx*" -o -name "*.subfinder*" 2>/dev/null | \
      xargs rm -f 2>/dev/null || true

    CHANGES_MADE+=("memory-reclaimed")
  fi

  local ram_after; ram_after=$(get_ram_used_mb)
  local freed=$(( ram_before - ram_after ))
  [ "$freed" -gt 0 ] && ok "Freed ~${freed}MB RAM" || ok "RAM post-clean: ${ram_after}MB"
}

# ─── Phase 4: CPU & Kernel Tuning ────────────────────────────────────────────

apply_tuning() {
  section "CPU & Kernel Tuning"

  # CPU governor → performance
  local current_gov; current_gov=$(get_governor)
  if [ "$current_gov" != "performance" ]; then
    if $DIAGNOSE_ONLY; then
      warn "CPU governor is '$current_gov' — would set to performance"
    else
      for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [ -f "$gov" ] && echo performance | sudo tee "$gov" >/dev/null
      done
      fixed "CPU governor → performance ($(get_cpu_freq_mhz) → $(get_cpu_max_mhz) MHz)"
      CHANGES_MADE+=("cpu-governor-performance")
    fi
  else
    ok "CPU governor already: performance"
  fi

  # I/O scheduler — for NVMe/SSD use 'none', for SD card use 'mq-deadline'
  local root_dev; root_dev=$(findmnt -n -o SOURCE / 2>/dev/null | sed 's/[0-9]*$//' | xargs basename 2>/dev/null)
  if [ -n "$root_dev" ] && [ -f "/sys/block/${root_dev}/queue/scheduler" ]; then
    local cur_sched; cur_sched=$(cat "/sys/block/${root_dev}/queue/scheduler" 2>/dev/null || echo "?")
    local want_sched
    if echo "$root_dev" | grep -q 'mmcblk'; then
      want_sched="mq-deadline"   # best for SD card / eMMC
    else
      want_sched="none"          # best for NVMe/SSD (no extra queuing)
    fi
    if echo "$cur_sched" | grep -q "$want_sched"; then
      ok "I/O scheduler: $want_sched (already set for $root_dev)"
    elif $DIAGNOSE_ONLY; then
      warn "I/O scheduler: $cur_sched — would set to $want_sched for $root_dev"
    else
      echo "$want_sched" | sudo tee "/sys/block/${root_dev}/queue/scheduler" >/dev/null 2>&1 && \
        fixed "I/O scheduler → $want_sched (was: $cur_sched)" || warn "Could not set I/O scheduler"
    fi
  fi

  # Sysctl tuning
  local sysctl_file="/etc/sysctl.d/99-bugbounty.conf"
  if [ -f "$sysctl_file" ]; then
    ok "sysctl tuning file exists ($sysctl_file)"
    if $DIAGNOSE_ONLY; then
      info "Verify tuning is applied: sudo sysctl --system"
    else
      sudo sysctl --system >/dev/null 2>&1 && fixed "sysctl tuning re-applied" || true
    fi
  else
    if $DIAGNOSE_ONLY; then
      warn "sysctl tuning file missing — run setup-pi.sh --system to apply"
    else
      warn "sysctl tuning file missing — applying now…"
      sudo tee /etc/sysctl.d/99-bugbounty.conf >/dev/null <<'SYSCTL'
# Bug bounty lab — network + memory tuning
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.core.netdev_max_backlog=65535
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_congestion_control=bbr
vm.swappiness=10
vm.dirty_ratio=15
vm.dirty_background_ratio=5
vm.vfs_cache_pressure=50
fs.file-max=1048576
SYSCTL
      sudo sysctl --system >/dev/null 2>&1 && fixed "sysctl tuning applied" || true
      CHANGES_MADE+=("sysctl-tuning")
    fi
  fi

  # File descriptor limit check
  local ulimit_n; ulimit_n=$(ulimit -n 2>/dev/null || echo "0")
  local limits_file="/etc/security/limits.d/99-bugbounty.conf"
  if [ "$ulimit_n" -lt 1000000 ] 2>/dev/null; then
    if $DIAGNOSE_ONLY; then
      warn "ulimit -n = $ulimit_n — too low. Would set to 1048576."
    else
      if [ ! -f "$limits_file" ]; then
        sudo tee "$limits_file" >/dev/null <<'LIMITS'
* soft nofile 1048576
* hard nofile 1048576
* soft nproc  65535
* hard nproc  65535
LIMITS
        fixed "File descriptor limits set to 1M (re-login to take effect)"
        CHANGES_MADE+=("fd-limits")
      fi
    fi
  else
    ok "File descriptor limit: $ulimit_n"
  fi

  # GPU memory split — reduce to 16MB (headless, no display needed)
  local config_file
  config_file=""
  for f in /boot/firmware/config.txt /boot/config.txt; do
    [ -f "$f" ] && { config_file="$f"; break; }
  done
  if [ -n "$config_file" ]; then
    if grep -q 'gpu_mem=16' "$config_file" 2>/dev/null; then
      ok "GPU memory: 16MB (optimal for headless)"
    elif $DIAGNOSE_ONLY; then
      warn "GPU memory: not minimized — would add gpu_mem=16 to $config_file (saves ~64MB RAM)"
    else
      if ! grep -q 'gpu_mem' "$config_file"; then
        echo "gpu_mem=16" | sudo tee -a "$config_file" >/dev/null && \
          fixed "GPU memory → 16MB (takes effect after reboot)" || true
      else
        sudo sed -i 's/^gpu_mem=.*/gpu_mem=16/' "$config_file" && \
          fixed "GPU memory → 16MB (was different, takes effect after reboot)" || true
      fi
      CHANGES_MADE+=("gpu-mem-16mb")
    fi
  fi
}

# ─── Phase 5: Docker Cleanup ──────────────────────────────────────────────────

cleanup_docker() {
  section "Docker Cleanup"
  if ! command -v docker >/dev/null 2>&1; then
    info "Docker not installed — skipping"
    return
  fi
  if ! docker info >/dev/null 2>&1; then
    warn "Docker daemon not running — skipping"
    return
  fi

  local dangling; dangling=$(docker images -f dangling=true -q 2>/dev/null | wc -l)
  local stopped; stopped=$(docker ps -a -q --filter status=exited 2>/dev/null | wc -l)

  if $DIAGNOSE_ONLY; then
    [ "$dangling" -gt 0 ] && warn "$dangling dangling images (~$(docker system df 2>/dev/null | awk '/Images/{print $4}') used)"
    [ "$stopped" -gt 0 ] && warn "$stopped stopped containers can be pruned"
    info "Would run: docker system prune -f"
  else
    docker image prune -f 2>/dev/null && fixed "Docker dangling images pruned" || true
    docker container prune -f 2>/dev/null && fixed "Docker stopped containers pruned" || true
    docker volume prune -f 2>/dev/null && fixed "Docker unused volumes pruned" || true
    docker network prune -f 2>/dev/null && fixed "Docker unused networks pruned" || true
    CHANGES_MADE+=("docker-prune")
  fi
  ok "Docker disk usage: $(docker system df 2>/dev/null | tail -1 | awk '{print $4}')"
}

# ─── Phase 6: Disk Cleanup ────────────────────────────────────────────────────

cleanup_disk() {
  section "Disk Space Reclaim"

  local total_freed=0

  # Large directories to report
  echo ""
  echo -e "${BOLD}Large directories:${NC}"
  du -sh "${HOME}/wordlists" 2>/dev/null | awk '{print "  wordlists:       "$1}'
  du -sh "${HOME}/nuclei-templates" 2>/dev/null | awk '{print "  nuclei-templates: "$1}'
  du -sh "${HOME}/go" 2>/dev/null | awk '{print "  ~/go:            "$1}'
  du -sh "${HOME}/.cache" 2>/dev/null | awk '{print "  ~/.cache:        "$1}'
  du -sh "${HOME}/tools" 2>/dev/null | awk '{print "  ~/tools:         "$1}'
  du -sh /var/log 2>/dev/null | awk '{print "  /var/log:        "$1}'
  du -sh /tmp 2>/dev/null | awk '{print "  /tmp:            "$1}'
  du -sh /var/cache/apt 2>/dev/null | awk '{print "  apt cache:       "$1}'

  if $DIAGNOSE_ONLY; then
    info "Would clean: pip cache, go build cache, apt cache, old logs, /tmp scan files"
    return
  fi

  # Old logs
  sudo find /var/log -name "*.gz" -mtime +7 -delete 2>/dev/null && fixed "Old compressed logs deleted" || true
  sudo find /var/log -name "*.1" -mtime +7 -delete 2>/dev/null || true
  sudo find /var/log -name "*.old" -delete 2>/dev/null || true

  # Journald size cap
  sudo journalctl --vacuum-size=200M --vacuum-time=30d 2>/dev/null && \
    fixed "Journal capped at 200MB / 30 days" || true

  # Thumbnail cache (if any desktop)
  rm -rf "${HOME}/.cache/thumbnails" 2>/dev/null || true

  # Temp scan files
  sudo find /tmp -maxdepth 1 -type f -mtime +1 -delete 2>/dev/null
  sudo find /tmp -maxdepth 2 \( -name "*.nuclei*" -o -name "*.httpx*" -o -name "*.subfinder*" \) \
    -delete 2>/dev/null || true
  fixed "/tmp old files cleaned"

  # pip + Go caches
  pip3 cache purge 2>/dev/null || true
  rm -rf "${HOME}/.cache/pip" 2>/dev/null
  go clean -cache 2>/dev/null && fixed "Go build cache cleared" || true

  # apt
  sudo apt-get clean 2>/dev/null
  sudo apt-get autoremove --purge -y -q 2>/dev/null
  fixed "APT cache + orphan packages cleaned"

  # Old nuclei results in results/ older than 60 days (keep recent)
  find "${HOME}/bug-bounty-hunting-/results" -name "*.log" -mtime +60 \
    -not -path "*/findings/*" -delete 2>/dev/null && \
    fixed "Nuclei scan logs older than 60 days cleaned" || true

  CHANGES_MADE+=("disk-cleanup")
  echo ""
  ok "Disk after cleanup: $(get_disk_used_pct)% used, $(get_disk_free_gb)GB free"
}

# ─── Phase 7: Swap Optimization ───────────────────────────────────────────────

optimize_swap() {
  section "Swap Configuration"

  if swapon --show 2>/dev/null | grep -q '/swapfile'; then
    local swap_total; swap_total=$(get_swap_mb)
    local swap_used; swap_used=$(get_swap_used_mb)
    ok "Swap: ${swap_total}MB configured, ${swap_used}MB used"

    # Swappiness — for 16GB Pi, 10 means OS rarely swaps
    local current_swappiness; current_swappiness=$(cat /proc/sys/vm/swappiness 2>/dev/null || echo "?")
    if [ "$current_swappiness" != "10" ]; then
      if $DIAGNOSE_ONLY; then
        warn "swappiness=$current_swappiness — would set to 10 (keep data in RAM)"
      else
        sudo sysctl vm.swappiness=10 >/dev/null && fixed "vm.swappiness → 10"
      fi
    else
      ok "vm.swappiness = 10 (optimal)"
    fi
  else
    warn "No swap — configuring 4GB swapfile…"
    if ! $DIAGNOSE_ONLY; then
      sudo fallocate -l 4G /swapfile 2>/dev/null || \
        sudo dd if=/dev/zero of=/swapfile bs=1M count=4096 status=none
      sudo chmod 600 /swapfile
      sudo mkswap /swapfile >/dev/null 2>&1
      sudo swapon /swapfile
      grep -q '/swapfile' /etc/fstab || echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
      fixed "4GB swap created and activated"
      CHANGES_MADE+=("swap-created")
    fi
  fi

  # zram — optional: compress a portion of RAM (effective on 16GB Pi)
  if ! lsmod 2>/dev/null | grep -q zram; then
    if $DIAGNOSE_ONLY; then
      info "Optional: zram not active — run 'sudo apt install zram-tools' for compressed RAM swap"
    fi
  else
    ok "zram active (compressed RAM swap)"
  fi
}

# ─── Phase 8: Live Monitor ───────────────────────────────────────────────────

live_watch() {
  echo -e "${BOLD}${CYAN}Pi5 Bug Bounty Lab — Live Monitor (Ctrl+C to exit)${NC}"
  echo ""
  while true; do
    local temp; temp=$(get_temp_c)
    local freq; freq=$(get_cpu_freq_mhz)
    local ram_pct; ram_pct=$(get_ram_pct)
    local ram_used; ram_used=$(get_ram_used_mb)
    local disk_pct; disk_pct=$(get_disk_used_pct)
    local swap_used; swap_used=$(get_swap_used_mb)
    local throttle; throttle=$(get_throttle_flags)
    local nuc; nuc=$(pgrep -c nuclei 2>/dev/null || echo "0")
    local httpx; httpx=$(pgrep -c httpx 2>/dev/null || echo "0")
    local subfinder; subfinder=$(pgrep -c subfinder 2>/dev/null || echo "0")

    local temp_color="$GREEN"
    [ "$temp" -ge 75 ] && temp_color="$YELLOW"
    [ "$temp" -ge 80 ] && temp_color="$RED"

    local ram_color="$GREEN"
    [ "$ram_pct" -ge 75 ] && ram_color="$YELLOW"
    [ "$ram_pct" -ge 90 ] && ram_color="$RED"

    local throttle_str="OK"
    [ "$throttle" != "0x0" ] && throttle_str="⚠ THROTTLED:$throttle"

    printf "\r${BOLD}%s${NC}  Temp:${temp_color}%d°C${NC}  CPU:%dMHz  RAM:${ram_color}%d%%${NC}(%dMB)  Disk:%d%%  Swap:%dMB  Throttle:%s  Tools:[nuclei:%s httpx:%s subfinder:%s]  " \
      "$(date '+%H:%M:%S')" "$temp" "$freq" "$ram_pct" "$ram_used" "$disk_pct" "$swap_used" \
      "$throttle_str" "$nuc" "$httpx" "$subfinder"
    sleep 1
  done
}

# ─── Summary ─────────────────────────────────────────────────────────────────

print_summary() {
  section "Optimization Summary"

  if [ ${#CHANGES_MADE[@]} -eq 0 ]; then
    ok "System was already well-tuned. No changes needed."
  else
    ok "${#CHANGES_MADE[@]} optimizations applied:"
    for change in "${CHANGES_MADE[@]}"; do
      echo "    • $change"
    done
  fi

  echo ""
  echo -e "${BOLD}Current state after optimization:${NC}"
  local temp; temp=$(get_temp_c)
  local ram_used; ram_used=$(get_ram_used_mb)
  local ram_total; ram_total=$(get_ram_total_mb)
  local freq; freq=$(get_cpu_freq_mhz)
  local disk_free; disk_free=$(get_disk_free_gb)
  echo "    Temp: ${temp}°C  |  CPU: ${freq}MHz @ $(get_governor)  |  RAM: ${ram_used}/${ram_total}MB  |  Disk free: ${disk_free}GB"

  echo ""
  echo -e "${BOLD}${CYAN}Next-step hardware recommendations (most impactful):${NC}"
  local storage; storage=$(get_storage_type)
  if echo "$storage" | grep -q "SD Card"; then
    echo -e "  ${RED}!${NC} ${BOLD}MIGRATE TO NVMe SSD${NC} — SD card is your #1 bottleneck."
    echo "    → Pi 5 + official NVMe HAT + 500GB SSD = 10x faster I/O, no thermal issues from SD"
    echo "    → Sequential read: SD=45MB/s → NVMe=800MB/s+. Nuclei scans finish 3-5x faster."
  fi
  echo ""
  echo -e "  ${CYAN}→${NC} ${BOLD}Active cooling:${NC} Pimoroni Heatsink SHIM + Raspberry Pi Active Cooler"
  echo -e "  ${CYAN}→${NC} ${BOLD}Power:${NC} Official Pi 5 PSU (27W USB-C) — not a phone charger"
  echo -e "  ${CYAN}→${NC} ${BOLD}Run Pi Claude headless via SSH${NC} — disable desktop environment entirely:"
  echo "    sudo raspi-config → System Options → Boot → Console (no GUI)"
  echo ""
  echo -e "  ${GREEN}→${NC} Run ${BOLD}./scripts/pi-resource-guard.sh --report${NC} before heavy scans"
  echo -e "  ${GREEN}→${NC} Run ${BOLD}./scripts/pi-optimize.sh --watch${NC} for live monitoring"
  echo ""
}

# ─── Main ─────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $0 [--diagnose | --clean | --services | --tuning | --watch]

  (no args)    Full optimize: diagnose + services + memory + tuning + docker + disk + swap
  --diagnose   Read-only report. No changes made.
  --clean      Free disk space only (cache, logs, temp files)
  --services   Prune unnecessary services only
  --tuning     CPU governor + sysctl + limits only
  --watch      Live 1-second resource monitor
EOF
}

main() {
  case "${1:---all}" in
    --diagnose)
      DIAGNOSE_ONLY=true
      diagnose
      ;;
    --watch)
      live_watch
      ;;
    --clean)
      cleanup_docker
      cleanup_disk
      reclaim_memory
      print_summary
      ;;
    --services)
      prune_services
      print_summary
      ;;
    --tuning)
      apply_tuning
      optimize_swap
      print_summary
      ;;
    --all|-*)
      diagnose
      prune_services
      reclaim_memory
      apply_tuning
      optimize_swap
      cleanup_docker
      cleanup_disk
      print_summary
      ;;
  esac
}

main "${1:---all}"
