# F001 Submission Guide — bughunters.google.com

**Status:** READY TO SUBMIT  
**Report:** `findings/F001-win-test-subdomain-takeover.md`

---

## Before You Submit

1. **Fill in your handle** in `config/scope.yaml` line 26:
   ```yaml
   handle: "YOUR_BUGHUNTERS_HANDLE"
   ```

2. **Verify the finding is still live** (run from Pi):
   ```zsh
   dig CNAME win-test.wiz.io +short
   curl -sk https://win-test.wiz.io/ | head -5
   ```
   Expected: `37e7f43d8158e70f.vercel-dns-013.com.` and `DEPLOYMENT_NOT_FOUND`

---

## Submission Steps

1. Go to: **https://bughunters.google.com/report/**
2. Log in with your Google account
3. Click **"Submit a vulnerability"**
4. **Target:** Search for "wiz.io" → select the Wiz entry (TIER1)

### Form Fields

**Title:**
```
Subdomain Takeover on win-test.wiz.io via Dangling Vercel CNAME
```

**Severity:** High

**Vulnerability type:**
- Subdomain Takeover (or: Misconfiguration → Subdomain Takeover)

**Affected URL:**
```
https://win-test.wiz.io
```

**Description (paste this):**
> `win-test.wiz.io` has a live DNS CNAME record pointing to `37e7f43d8158e70f.vercel-dns-013.com`, but the corresponding Vercel project has been deleted. Any Vercel account holder can claim this subdomain and serve arbitrary content under the `wiz.io` brand, enabling phishing, cookie theft (Domain=.wiz.io cookies), and potential OAuth redirect hijacking if the subdomain appears in any redirect_uri allowlist.

**Steps to reproduce (paste exactly):**

Step 1 — Confirm live CNAME:
```
dig CNAME win-test.wiz.io +short
# Returns: 37e7f43d8158e70f.vercel-dns-013.com.
```

Step 2 — Confirm resolves to Vercel IPs:
```
dig A win-test.wiz.io +short
# Returns: 64.239.109.193 / 64.239.123.193
```

Step 3 — Confirm DEPLOYMENT_NOT_FOUND:
```
curl -sk https://win-test.wiz.io/
# Returns: DEPLOYMENT_NOT_FOUND
```

Step 4 — Confirm expired TLS cert (unrenewed = project deleted):
```
echo | openssl s_client -connect win-test.wiz.io:443 -servername win-test.wiz.io 2>/dev/null \
  | openssl x509 -noout -issuer -dates
# issuer=O=Let's Encrypt, CN=R13
# notAfter=Dec 16 2025  ← EXPIRED
```

**Impact:**
> An attacker who claims this subdomain can: (1) host phishing pages under the wiz.io brand, (2) steal Domain=.wiz.io cookies from victims, (3) potentially intercept OAuth authorization codes if win-test.wiz.io is in any Auth0 redirect_uri allowlist. Wiz customers are enterprise security teams with broad cloud permissions — account compromise is exceptionally high-consequence.

**CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` → **8.2**

---

## Evidence to Attach

- Screenshot of `dig CNAME win-test.wiz.io +short` output
- Screenshot of `curl -sk https://win-test.wiz.io/` showing `DEPLOYMENT_NOT_FOUND`
- Screenshot of expired TLS cert (issued 2025-09-17, expired 2025-12-16)
- HTTP response headers showing `x-vercel-error: DEPLOYMENT_NOT_FOUND`

---

## After Submission

- Note the report ID bughunters assigns
- Monitor for triager response (typically 1-2 weeks for Google VRP)
- While waiting: run Pi scripts, continue phase 3 hunting
- If triager asks for more evidence: run `curl -v https://win-test.wiz.io/` from Pi and attach full output
