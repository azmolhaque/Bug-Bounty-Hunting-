# Quick Start — Deploying the Bug Bounty Agent on Raspberry Pi 5

This guide gets you from a fresh Pi 5 (Raspberry Pi OS 64-bit or Ubuntu 24.04
arm64) to a running autonomous hunt.

---

## Fix 0 — GitHub authentication (password login is dead, use SSH)

GitHub disabled HTTPS password auth in 2021. Use SSH instead — it's one-time
setup and works forever.

```bash
# 1. Generate an SSH key (accept defaults, add a passphrase)
ssh-keygen -t ed25519 -C "your-github-email@example.com"

# 2. Print your public key and copy it
cat ~/.ssh/id_ed25519.pub

# 3. Add it to GitHub:
#    github.com → Settings → SSH and GPG keys → New SSH key → paste

# 4. Test it
ssh -T git@github.com
# Expected: "Hi azmolhaque! You've successfully authenticated..."
```

**Alternative — Personal Access Token (PAT) for HTTPS users:**
```bash
# github.com → Settings → Developer settings → Personal access tokens → Fine-grained
# Scope: Contents (read) on the repo, then use the token as the password when prompted.
# Or store it permanently:
git config --global credential.helper store
# Then clone once with your username + PAT as password; it saves it.
```

---

## Step 1 — Clone and provision the toolchain

```bash
# SSH clone (recommended — works after Fix 0 above)
git clone git@github.com:azmolhaque/bug-bounty-hunting-.git ~/bug-bounty-hunting-

# OR HTTPS with PAT
git clone https://github.com/azmolhaque/bug-bounty-hunting-.git ~/bug-bounty-hunting-

cd ~/bug-bounty-hunting-
chmod +x scripts/*.sh
./scripts/setup-pi.sh
source ~/.bashrc

# Verify the toolchain:
./scripts/setup-pi.sh --check
```

Installs Go, the ProjectDiscovery suite (subfinder, httpx, dnsx, naabu, nuclei,
katana, asnmap), gau, waybackurls, ffuf, dalfox, arjun, SecLists.
All tools compile/run natively on arm64. Estimated time: 10–20 min on Pi 5.

---

## Step 2 — Install Claude Code CLI

Claude Code is a Node.js app. Install Node first, then Claude Code:

```bash
# Install nvm (Node Version Manager — most reliable on Pi arm64)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
source ~/.bashrc   # (or open a new terminal)

# Install Node.js LTS
nvm install --lts
nvm use --lts
node --version     # should print v22.x.x or similar

# Install Claude Code CLI globally
npm install -g @anthropic-ai/claude-code

# Verify
claude --version
```

First run will ask you to log in with your Anthropic account:
```bash
cd ~/bug-bounty-hunting-
claude          # opens browser for auth on first run
```

---

## Step 3 — Configure your scope

**The agent refuses to hunt with an empty scope file — this is intentional.**

```bash
nano config/scope.yaml
```

Minimum required fields:
```yaml
program: "Example Corp Bug Bounty (HackerOne)"
handle: "your-h1-handle"
in_scope:
  - "*.example.com"
  - "api.example.com"
out_of_scope:
  - "blog.example.com"
rules:
  max_requests_per_second: 50
```

Test the scope gate:
```bash
./scripts/scope-check.sh api.example.com
# → IN-SCOPE: api.example.com matches '*.example.com'

./scripts/scope-check.sh evil.com
# → OUT-OF-SCOPE: evil.com matches no in_scope entry (default-deny)
```

---

## Step 4 — Hunt

```bash
cd ~/bug-bounty-hunting-
claude
```

Inside Claude Code:
```
/methodology              → study the playbook, form a hunt thesis
/workflow example.com     → run the full automated + agentic pipeline
```

Phased (recommended for first run):
```
/recon example.com        → Phases 1+2: asset discovery + surface mapping
/hunt example.com         → Phases 3+4: discovery + verification
/triage example.com       → Phase 5:   score, dedup, prioritize
/report example.com --all → Phase 6:   generate triager-grade reports
```

---

## Results layout

```
results/example.com/
  00-plan.md        → hunt thesis and action plan
  HUNT-LOG.md       → running decision log (survives context resets + reboots)
  01-assets/        → subdomains, resolved hosts, CIDRs, cloud assets
  02-surface/       → live hosts, tech map, endpoints, JS findings, priority.md
  03-candidates/    → candidates.jsonl (unverified leads)
  04-verified/      → confirmed bugs with minimal PoCs
  05-triage/        → ranked, dedup'd findings table
  findings/         → sanitized reports ready for submission
```

---

## Pi 5 performance tips

- Active cooling is recommended. Nuclei + amass loads all 4 cores.
- For large programs (`*.big.com`): run `./scripts/recon.sh example.com --passive-only`
  first, then `/hunt` on high-priority subsets.
- Long scans survive reboots: the agent writes `HUNT-LOG.md` as a checkpoint and
  resumes from the last completed phase on next run.
- Raw evidence stays local; `.gitignore` hard-blocks secrets from git.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Authentication failed` for git clone | Use SSH (Fix 0) or a PAT |
| `claude: command not found` | Run Step 2 — Node + npm install |
| `nvm: command not found` after install | `source ~/.bashrc` or open new terminal |
| `AMBIGUOUS: in_scope is empty` | Edit `config/scope.yaml` (Step 3) |
| `go install` tool fails | `source ~/.bashrc` so `$GOPATH/bin` is on `$PATH` |
| Nuclei templates missing | `nuclei -update-templates` |
| Pi overheats / throttles | Add active cooling; lower `THREADS=10 RATE=50` in env |
