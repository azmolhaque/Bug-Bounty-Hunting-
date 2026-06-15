# F001 — Google VRP Submission Guide
# win-test.wiz.io Subdomain Takeover
# Reporter: zahinshahriar3@gmail.com

---

## Files in This Package

```
F001-SUBMIT-PACKAGE/
├── README-DO-THIS-FIRST.md     ← You are here
├── 1-REPORT.md                 ← Paste this into the Google VRP form
├── 2-POC.md                    ← Attach this OR paste key sections
├── 3-verify.sh                 ← Run from Termux to confirm bug is still live
├── 4-extension-proof.sh        ← Run from Pi/Termux to download Wiz CRX + extract proof
├── 5-cookie-server.py          ← Attacker cookie capture server (for triager reference)
└── 6-attacker-page.html        ← Attacker phishing payload (for triager reference)
```

**Cert file (NOT in this package — stays local per security policy):**
```
Pi: /tmp/wintest.wiz.io.crt     ← Attach this to the VRP form as evidence
    Serial: 06:D3:55:B9:15:21:BA:DC:B0:6B:BE:B4:09:F2:90:FC:50:94
```

---

## Step 0 — Run Verification from Termux First

```bash
# Install deps if not done yet
pkg install dnsutils openssl-tool curl

# Run the verification script
bash 3-verify.sh
```

All 3 checks must show [PASS] before submitting. If any fail, the bug may
have been fixed — do not submit.

---

## Step 1 — Go to Google VRP

Open in your Android browser:
```
https://bughunters.google.com/report
```

---

## Step 2 — Fill the Form

| Field | Value |
|-------|-------|
| **Found in Google product?** | Yes |
| **Product** | Type "Wiz" → select Wiz (Google Cloud Security) |
| **URL / Endpoint** | `https://win-test.wiz.io/` |
| **Vulnerability type** | Subdomain Takeover |
| **Severity** | High |
| **Description** | Paste entire contents of `1-REPORT.md` |

---

## Step 3 — Attachments

Attach these files:
1. `wintest.wiz.io.crt` (from your Pi — the expired TLS certificate PEM)
2. `2-POC.md` (the full PoC document)

If the form only allows images, take screenshots of:
- `dig CNAME win-test.wiz.io +short` output
- `curl -sk https://win-test.wiz.io/` output (shows DEPLOYMENT_NOT_FOUND)
- `openssl` cert dates output

---

## Step 4 — Submit and Note the Report ID

After submitting, Google VRP gives you a report ID (e.g., `bughunters.google.com/report/12345678`).
Save this ID.

Expected triage timeline: 1–14 days for initial response on High severity.

---

## Key Facts to Remember If Triager Asks

- **Cert serial:** `06:D3:55:B9:15:21:BA:DC:B0:6B:BE:B4:09:F2:90:FC:50:94`
- **Vercel project response:** `{"error":{"code":"DEPLOYMENT_NOT_FOUND"}}`
- **Cookie name source:** `LT = \`wiz-app\`` in background.js of Chrome extension `koellablckildiakdjcchdfnagjfbpbh`
- **Domain=.wiz.io proof:** `e.domain.startsWith('.') && r.endsWith(e.domain.slice(1))` filter in same file
- **DNS updated:** WHOIS shows wiz.io last-modified `2026-03-14` — CNAME survived active review
- **CVSS:** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` = **8.2 High**
- **If OAuth chain confirmed internally:** escalates to **9.3 Critical**

---

## Transfer to Termux

From your Pi, run:
```bash
# Option A — via SSH to phone (if Termux SSH is running)
scp -r F001-SUBMIT-PACKAGE/ user@phone-ip:~/storage/downloads/

# Option B — zip and send via any file transfer
zip -r F001-submission.zip F001-SUBMIT-PACKAGE/
# Then AirDrop / Bluetooth / Google Drive / Telegram Saved Messages
```

From Termux on your Motorola:
```bash
# If received in Downloads
cp -r ~/storage/downloads/F001-SUBMIT-PACKAGE ~/
cd ~/F001-SUBMIT-PACKAGE
bash 3-verify.sh
```
