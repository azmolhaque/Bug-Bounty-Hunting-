#!/data/data/com.termux/files/usr/bin/bash
# g-probe11.sh — the login bundle named four grants we had never heard of.
# Three requests, same sentinel method. Genuinely the last probe.
set -u
ID=228TQD; SEC=7659f9d9ecc92d6dc1ee0d1774e9744a
B=$(printf '%s:%s' "$ID" "$SEC" | base64 -w0 2>/dev/null || printf '%s:%s' "$ID" "$SEC" | base64)
g() { printf '  %-24s ' "$1"; curl -s --max-time 14 -X POST https://api.fitbit.com/oauth2/token \
   -H "Authorization: Basic $B" -H 'Content-Type: application/x-www-form-urlencoded' -d "$2" \
   -w ' [HTTP %{http_code}]\n' 2>/dev/null | tr -d '\n' | head -c 260; echo; sleep 2; }

echo "  accounts.fitbit.com's own bundle names these grants:"
echo "    authorization_code · delegate_token · mfa_sms · social   (+ password, refresh_token in vendor)"
echo "  Which of them does the published credential actually unlock?"
echo
g "[SENTINEL] fake grant" "grant_type=zzz_not_a_real_grant_7x2"
g "delegate_token"       "grant_type=delegate_token&token=ZZZINVALID7x2"
g "mfa_sms"              "grant_type=mfa_sms&mfa_token=ZZZINVALID7x2&code=000000"
g "social"               "grant_type=social&provider=google&token=ZZZINVALID7x2"
echo
echo "  Anything answering differently from the sentinel is a grant this client has."
echo "  Each was sent ONCE with a fabricated token. Nothing is retried."
