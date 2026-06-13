# Hunt Log — virustotal.com (Google VRP TIER1)
Started: 2026-06-13

| Time | Phase | Action | Finding |
|------|-------|---------|---------|
| 2026-06-13 | 0 | Scope confirmed | `virustotal.com`, `www.virustotal.com`, `virustotal-plugins.com`, `gtidocs.virustotal.com` IN-SCOPE TIER1 |
| 2026-06-13 | 0 | Plan written | See `00-plan.md` — 5 hypotheses, H1 (SSRF→IMDS) is CRITICAL priority |
| 2026-06-13 | 1-2 | Scripts ready | `scripts/vt-recon.sh` — run on Pi |
| 2026-06-13 | 3 | Attack scripts ready | `scripts/vt-attack.sh` — needs VT_API_KEY |

## Key Hypotheses

### [CRITICAL — H1] SSRF via URL Submission
VirusTotal scans submitted URLs by fetching them server-side from GCP infrastructure.
Submitting `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`
could yield a GCP service account token if VT's scanner doesn't block metadata requests.
Script: `vt-attack.sh` Phase H1.

**Chain:** URL submission → VT scanner fetches URL → GCP IMDS response in analysis result → service account token

**SSRF bypass techniques to test:**
1. Direct metadata URL
2. AWS IMDS (169.254.169.254) — in case VT runs on hybrid
3. IPv6 link-local (fe80::1)
4. Octal IP encoding (0251.0376.0251.0376)
5. Hex IP encoding (0xa9fea9fe)
6. Redirect chain: external URL → 302 → IMDS
7. Alt schemes: gopher://, file://, ftp://

### [HIGH — H2] Analysis Object IDOR
VT analysis IDs encode `base64(hash:timestamp)`. Private analyses may be
enumerable if timestamp is guessable. Test: decode own analysis ID structure → test
adjacent IDs.

### [MEDIUM — H3] Premium Endpoint Error Differential
Enterprise-only endpoints (/intelligence/search, /retrohunt_jobs, /hunting_rulesets)
might return different 403 error codes for "no permission" vs "not found",
leaking existence of enterprise objects to free users.

### [MEDIUM — H4] User/Group IDOR
`/api/v3/users/{id}/relationships/{rel}` — if user IDs are enumerable and access
control only checks the top-level object (not relationships), another user's
comments/votes/files might be readable.

## Next Actions — Run on Pi

### Step 1: Account setup (2 minutes)
1. Go to https://www.virustotal.com/gui/sign-in
2. Sign up (or log in with Google account)
3. Go to profile → API Key tab → copy the Community API key

### Step 2: Phase 1+2 recon (10 minutes)
```zsh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd ~/bug-bounty-hunting-
bash scripts/vt-recon.sh 2>&1 | tee ~/vt-recon-output.txt
```

### Step 3: Phase 3 attack (20 minutes)
```zsh
export VT_API_KEY="<your_community_api_key>"
bash scripts/vt-attack.sh 2>&1 | tee ~/vt-attack-output.txt
```

### Step 4: OOB SSRF (needs webhook.site)
```zsh
export VT_API_KEY="<key>"
export COLLAB_URL="https://webhook.site/<your-uuid>"
bash scripts/vt-ssrf-oob.sh 2>&1 | tee ~/vt-ssrf-oob-output.txt
```
Then check webhook.site for incoming requests from VT's scanner.

## Decision Log
- Chose VirusTotal: TIER1, explicitly in scope (no VERIFY caveat), rich documented API v3
- SSRF via URL scanner is the primary attack vector — VT's own product fetches arbitrary URLs
- Free community API key gives immediate access to full API surface
- Premium endpoint error differentials could leak enterprise intel without auth
