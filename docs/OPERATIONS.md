# Pi 5 Bug Bounty Lab — Operations Guide

## 1. SSH Into the Pi

```bash
ssh gorib@192.168.10.118
```

The shell loads automatically. You will see a banner like:
```
Pi5 Bug Bounty Lab | 47.7°C | RAM: 913Mi/15Gi | Branch: claude/... | tmux: 2 sessions
```

---

## 2. First Thing After Login — Check Status

```bash
bb-status
```

Output shows:
- Active hunt sessions (if any)
- Pi temperature, RAM, CPU, nuclei count

---

## 3. Resume or Start a Hunt Session

### A. Resume an existing session (most common)

```bash
tmux ls                              # list all sessions
tmux attach -t hunt-photomath-net    # attach to a specific target
# OR just attach to most recent:
tmux attach
```

### B. Start a NEW hunt on a target

```bash
bash ~/bug-bounty-hunting-/scripts/hunt-workspace.sh photomath.net
```

This will:
1. Scope-check the target (stops if out of scope)
2. Check Pi resources
3. Create result directories
4. Open a 4-window tmux workspace
5. Attach you automatically

### C. Quick one-off hunt session (no full workspace)

```bash
hunt photomath.net
```

---

## 4. Inside the Workspace — Window Layout

```
Window 1: recon     — your main shell + notes + OOB listener
Window 2: scan      — nuclei / httpx / ffuf
Window 3: monitor   — Pi resource watch
Window 4: results   — tail finding logs
```

**Switch between windows:** `Shift + ←` / `Shift + →`

**Switch between panes in a window:** `Alt + ←` / `Alt + →` / `Alt + ↑` / `Alt + ↓`

---

## 5. Essential Keybindings (all use `Ctrl-a` prefix)

| Keys | Action |
|------|--------|
| `Ctrl-a + d` | **Detach** (session keeps running in background) |
| `Ctrl-a + \|` | Split pane vertically |
| `Ctrl-a + -` | Split pane horizontally |
| `Ctrl-a + r` | Reload tmux config |
| `Ctrl-a + H` | Add 3-pane hunt layout to current window |
| `Ctrl-a + M` | Open resource monitor window |
| `Ctrl-a + [` | Enter scroll/copy mode (use arrow keys, `q` to exit) |
| `Ctrl-a + z` | Zoom current pane fullscreen (again to unzoom) |
| `Shift + ←/→` | Switch windows |
| `Alt + arrows` | Switch panes |

---

## 6. Standard Hunt Workflow (Phase by Phase)

### Phase 0 — Scope Check (MANDATORY before any testing)

```bash
scope photomath.net          # must return IN-SCOPE
scope api.photomath.net      # check subdomains too
```

### Phase 1 — Asset Discovery (Window 2: scan)

```bash
# Subdomain enumeration
subfinder -d photomath.net -silent -all \
  | tee ~/bug-bounty-hunting-/results/photomath.net/recon/subdomains/current.txt

# CT log search
cert photomath.net

# Probe which subdomains are live
httpx -l ~/bug-bounty-hunting-/results/photomath.net/recon/subdomains/current.txt \
  -silent -title -status-code -tech-detect \
  -o ~/bug-bounty-hunting-/results/photomath.net/recon/ports/http-services.txt

# View results
cat ~/bug-bounty-hunting-/results/photomath.net/recon/ports/http-services.txt
```

### Phase 2 — Subdomain Takeover Check

```bash
subzy run \
  --targets ~/bug-bounty-hunting-/results/photomath.net/recon/subdomains/current.txt \
  --concurrency 20 --https
```

### Phase 3 — Vulnerability Scan (Window 2)

```bash
# Nuclei on all live hosts (config auto-loaded from ~/.config/nuclei/config.yaml)
nuclei \
  -l ~/bug-bounty-hunting-/results/photomath.net/recon/ports/http-services.txt \
  -severity medium,high,critical \
  -o ~/bug-bounty-hunting-/results/photomath.net/findings/nuclei-$(date +%Y%m%d).txt

# Watch results in Window 4
tail -f ~/bug-bounty-hunting-/results/photomath.net/findings/nuclei-*.txt
```

### Phase 4 — OOB / SSRF Testing (Window 1, bottom pane)

```bash
oob photomath.net       # starts interactsh, prints your OOB URL
lastoob                 # print the last OOB URL again
```

Use the printed URL in any SSRF/XXE/webhook test field.

### Phase 5 — JS Analysis

```bash
# Extract endpoints and secrets from JS bundles
katana -u https://photomath.net -jc -silent \
  | grep '\.js' \
  | httpx -silent \
  | jsluice urls \
  | tee ~/bug-bounty-hunting-/results/photomath.net/recon/urls/js-endpoints.txt

# Scan for secrets
trufflehog filesystem ~/bug-bounty-hunting-/results/photomath.net/ 2>/dev/null
```

### Phase 6 — Parameter Discovery

```bash
# Historical URLs from Wayback + Common Crawl
gau photomath.net | tee ~/bug-bounty-hunting-/results/photomath.net/recon/urls/gau.txt

# Find interesting params
cat ~/bug-bounty-hunting-/results/photomath.net/recon/urls/gau.txt | gf ssrf
cat ~/bug-bounty-hunting-/results/photomath.net/recon/urls/gau.txt | gf redirect
cat ~/bug-bounty-hunting-/results/photomath.net/recon/urls/gau.txt | gf xss
```

---

## 7. Useful Lab Commands (available anywhere after SSH)

| Command | What it does |
|---------|-------------|
| `bb-status` | Active sessions + Pi health |
| `picheck` | Pi temp / RAM / CPU snapshot |
| `optimize` | Run full Pi optimizer |
| `optimize --diagnose` | Read-only health report |
| `scope <host>` | Check if a target is in scope |
| `cert <domain>` | CT log subdomain search |
| `oob [tag]` | Start interactsh OOB listener |
| `lastoob` | Print last OOB URL |
| `notify "message"` | Send Discord ping |
| `shodan-ip <ip>` | Quick Shodan host lookup |
| `bb-update` | Update tools + templates + pull repo |
| `bb-clean` | Clear temp scan files + caches |
| `temp` | Print CPU temperature |
| `topcpu` | Top 12 CPU-consuming processes |
| `topmem` | Top 12 RAM-consuming processes |
| `nuclei-update` | Pull latest nuclei templates |

---

## 8. Notification Setup (Discord)

Alerts are sent to your Discord channel automatically when:
- Subdomain monitor (03:00 nightly) finds new assets
- Subdomain takeover candidates detected

Manual ping:
```bash
notify "Found IDOR on photomath.net — investigating"
```

---

## 9. Automated Nightly Jobs (already configured)

| Time | Job |
|------|-----|
| 02:00 daily | Update nuclei templates |
| 03:00 daily | Subdomain monitor → Discord alert if new assets |
| 04:00 daily | Pi cleanup (cache, logs, temp files) |
| 06:00 Sunday | Full tool upgrade |

Logs: `~/bug-bounty-hunting-/results/cron-logs/`

---

## 10. End of Session

```bash
# Detach (session survives, continues running)
Ctrl-a + d

# OR close everything for this target
bash ~/bug-bounty-hunting-/scripts/hunt-workspace.sh --kill photomath.net

# Commit your findings before disconnecting
cd ~/bug-bounty-hunting-
git add results/photomath.net/
git commit -m "photomath recon session $(date +%Y-%m-%d)"
git push origin claude/appsheet-vrp-submission-vq80t5
```

---

## 11. Result Directory Structure

```
results/
└── photomath.net/
    ├── findings/          ← confirmed vulns + nuclei output
    ├── evidence/          ← screenshots, HTTP logs, OOB proofs
    ├── recon/
    │   ├── subdomains/    ← current.txt, previous.txt, new-YYYY-MM-DD.txt
    │   ├── ports/         ← http-services.txt
    │   └── urls/          ← js-endpoints.txt, gau.txt
    └── notes.md           ← your manual notes (open in recon window pane 2)
```

---

## 12. Quick Reference Card

```
SSH LOGIN:     ssh gorib@192.168.10.118
CHECK:         bb-status
NEW HUNT:      bash ~/bug-bounty-hunting-/scripts/hunt-workspace.sh <target>
RESUME:        tmux attach   (or: tmux attach -t hunt-<target>)
DETACH:        Ctrl-a + d
WINDOWS:       Shift+←/→
PANES:         Alt+arrows
SCROLL:        Ctrl-a + [   (q to exit)
ZOOM PANE:     Ctrl-a + z
OOB:           oob <target>
SCOPE CHECK:   scope <host>
NOTIFY:        notify "message"
STATUS:        picheck
```
