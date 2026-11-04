#!/bin/bash
# Fetch /saml_error and extract meaningful text from the HTML.
# Strips style blocks, script blocks, and base64 image data before parsing text.
# Run after apigee_saml_sso.sh redirects to /saml_error.
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L005-saml-error-text.txt"

echo "=== Fetching /saml_error page ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo | tee -a "$OUT"

/usr/bin/curl -skL --max-time 15 \
  "https://login.apigee.com/saml_error" \
  -o /tmp/saml_error_raw.html
echo "Raw page size: $(wc -c < /tmp/saml_error_raw.html) bytes" | tee -a "$OUT"
echo | tee -a "$OUT"

# Extract text: remove <style>, <script>, base64 blobs, then strip all tags
python3 << 'PYEOF' 2>/dev/null | tee -a "$OUT"
import re

with open('/tmp/saml_error_raw.html', 'r', errors='replace') as f:
    html = f.read()

# Remove <style> and <script> blocks entirely
html = re.sub(r'<style[^>]*>.*?</style>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
html = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL | re.IGNORECASE)

# Remove base64 data URIs
html = re.sub(r'data:[a-z/]+;base64,[A-Za-z0-9+/=]+', '[BASE64]', html)

# Remove all remaining tags
text = re.sub(r'<[^>]+>', ' ', html)

# Collapse whitespace
text = re.sub(r'\s+', ' ', text).strip()

print("=== Extracted text (first 3000 chars) ===")
print(text[:3000])
print()
print("=== Lines containing 'error', 'saml', 'invalid', 'issuer', 'signature' ===")
for line in text.split('.'):
    if re.search(r'error|saml|invalid|issuer|signature|idp|registered|unknown', line, re.IGNORECASE):
        print(line.strip())
PYEOF

echo
echo "Done. Full output: $OUT"
echo "Raw HTML: /tmp/saml_error_raw.html"
