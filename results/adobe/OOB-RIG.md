# Adobe hunt — OOB rig (Raspberry Pi 5, ARM64)

Two distinct capabilities are needed and are frequently conflated:

| Need | Why | Tool |
|---|---|---|
| **Content host** | The injected instructions live *inside* the page Adobe's fetcher retrieves. Must serve arbitrary bytes | `simplehttpserver` + **Tailscale Funnel** |
| **Callback sink** | Records *who* fetched what, with full headers | the same server's log, plus `interactsh` for DNS-level hits |

`interactsh` alone is insufficient — it returns a fixed response and cannot carry a payload.
`simplehttpserver` alone is insufficient — the Pi is behind NAT (`wlan0 192.168.10.118/24`,
no public address).

---

## Primary — Tailscale Funnel + simplehttpserver

Tailscale is already up (`tailscale0 100.118.254.108`). Funnel publishes a local port on a
**stable public HTTPS hostname** at no cost, and every request lands in a log we own.

```bash
mkdir -p ~/adobe-oob/www && cd ~/adobe-oob

# probe content, one file per probe so a hit is attributable to exactly one hypothesis
echo 'P1-IMG'   > www/p1.png       # markdown-image render probe
echo 'P2-LINK'  > www/p2.txt       # link render / unfurl probe
echo 'P3-FETCH' > www/p3.txt       # server-vs-browser fetch probe

# serve with full request logging
simplehttpserver -listen 127.0.0.1:8000 -path ~/adobe-oob/www -verbose
```

In a second shell:

```bash
tailscale funnel --bg 8000
tailscale funnel status          # prints the public https://<machine>.<tailnet>.ts.net URL
```

Funnel needs **HTTPS certificates** and the **Funnel** node attribute enabled for the tailnet
(Tailscale admin console → DNS → enable HTTPS; Access Controls → `nodeAttrs` → `funnel`).
One-time setup.

**Verify from outside the network before trusting it** — phone on mobile data, not Wi-Fi:

```
https://<machine>.<tailnet>.ts.net/p1.png
```

The request must appear in the `simplehttpserver` output. If it does not, the rig is broken and
every later negative is meaningless — the same Gate 0A discipline as Exoscale.

## Secondary — interactsh, for DNS-level hits

Catches server-side **DNS resolution** even when HTTP egress is blocked, which distinguishes
"fetch attempted and blocked" from "never attempted at all".

```bash
interactsh-client -v
```

Payloads are encrypted to a per-client key, so the public servers cannot read interaction
contents. Note that `oast.*` domains are widely blocklisted — **a silent interactsh is not
evidence of no fetch.** The Funnel host is the primary; interactsh is corroboration.

## Fallbacks

- **Cloudflare Tunnel** — `cloudflared tunnel --url http://localhost:8000`, no account needed,
  random `*.trycloudflare.com` hostname. Use if Funnel setup stalls.
- **GitHub Pages** — free static hosting on a domain unlikely to be blocklisted. Serves content
  but gives **no request log**, so pair it with interactsh.

---

## Evidence hygiene

- **One unique path per probe.** `/p1.png`, `/p2.txt` … never reuse a path across hypotheses —
  attribution is the whole point.
- **Log everything to disk**, not scrollback:
  `simplehttpserver … -verbose 2>&1 | tee -a ~/adobe-oob/oob-$(date +%F).log`
  (pass the date in from the shell; do not rely on the tool for it)
- Record **our own external IP** at session start — `curl ifconfig.me`. Adobe **requires** a
  testing IP address for bounty payment and Safe Harbour coverage.
- Capture, for every inbound hit: **timestamp · source IP · User-Agent · full headers · path**.
  The User-Agent and IP are what prove a *server-side* fetch rather than the victim's browser.

## Safety

- Serve **benign canaries only**. No exploit code, no redirect chains into Adobe infrastructure,
  no content that would harm a user who visited by accident.
- The Funnel hostname is public. Assume anything placed there is world-readable — never host
  another party's data, session material, or anything captured during testing.
- Take the Funnel down between sessions: `tailscale funnel --bg off`.

## Housekeeping

`dnsx` is outdated (1.2.3 → 1.3.0); `pdtm` itself is 0.1.3 → 0.1.5. Neither blocks this hunt.
`pdtm -ua` when convenient.
