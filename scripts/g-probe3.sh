#!/data/data/com.termux/files/usr/bin/bash
# g-probe3.sh — the Fitbit OAuth client credential, plus three fixes.
set -u
T="$HOME/.gprobe"; mkdir -p "$T"

echo "######################################################################"
echo "# 1. THE ONE THAT MATTERS — is 458dd4...196d a live client secret?   #"
echo "######################################################################"
cat <<'TXT'
  feed-moderation.fitbit.com ships this in a PUBLIC meta tag:

      "clientId": "227ZG3:458dd4f32a9db4957cf15fd464be196d"
      "serverTokenEndpoint": "https://api.fitbit.com/oauth2/token"

  Fitbit's token endpoint authenticates with HTTP Basic, base64(id:secret).
  The 6-char id is public by design. The 32-hex half is shaped exactly like a
  client secret, and a client secret in a public file is a different thing
  entirely from an API key.

  DO NOT assume it. Google's own article says key reports are "frequently false
  positives", and the Tesla report died in that exact class. So this asks the
  endpoint a question it cannot answer wrongly:

      send a DELIBERATELY INVALID authorization code with each credential.

      wrong secret -> "invalid_client"  (authentication failed, never got to the code)
      right secret -> "invalid_grant"   (authenticated fine, the CODE is what is bad)

  That differential proves the credential is live WITHOUT obtaining a token,
  without touching any user, and without using the access for anything.
TXT
echo
ID=227ZG3
SEC=458dd4f32a9db4957cf15fd464be196d
try() { # try <label> <clientid> <secret>
  b=$(printf '%s:%s' "$2" "$3" | base64 -w0 2>/dev/null || printf '%s:%s' "$2" "$3" | base64)
  printf '  %-34s ' "$1"
  curl -s --max-time 12 -X POST "https://api.fitbit.com/oauth2/token" \
    -H "Authorization: Basic $b" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'grant_type=authorization_code&code=ZZZINVALIDCODE7x2&redirect_uri=https://example.com/' \
    -w ' [HTTP %{http_code}]\n' 2>/dev/null | tr -d '\n' | head -c 400; echo
  sleep 1.5
}
try "[TEST]     real id + real secret" "$ID" "$SEC"
try "[CONTROL]  real id + WRONG secret" "$ID" "0000000000000000000000000000dead"
try "[SENTINEL] fake id + fake secret"  "ZZZZZZ" "0000000000000000000000000000dead"
echo
echo "  READ IT LIKE THIS:"
echo "    TEST says invalid_grant while both others say invalid_client  -> SECRET IS LIVE"
echo "    all three say invalid_client                                  -> not a secret, drop it"
echo "    all three say the same thing                                  -> endpoint is not differentiating, inconclusive"

echo
echo "######################################################################"
echo "# 2. bucket ACL, redone — /tmp is not writable in Termux             #"
echo "######################################################################"
B=https://looker-opensource-components.looker.com
for q in acl policy cors website versioning logging; do
  printf '  ?%-11s ' "$q"
  code=$(curl -s --max-time 8 -o "$T/s3.$q" -w '%{http_code}' "$B/?$q" 2>/dev/null)
  printf '%s  %s\n' "$code" "$(head -c 170 "$T/s3.$q" 2>/dev/null | tr -d '\n')"
  sleep 0.6
done
echo "  --- real key count (the XML is one line, so grep -c counted 1) ---"
curl -s --max-time 12 "$B/?list-type=2" -o "$T/s3.list"
printf '  keys: %s   bytes: %s\n' "$(grep -o '<Key>' "$T/s3.list" | wc -l)" "$(wc -c < "$T/s3.list")"

echo
echo "######################################################################"
echo "# 3. a hostname the CSP handed us, not in Google's published list    #"
echo "######################################################################"
echo "  connect-src named  feed-moderation.site-ops.fitbit.com  over BOTH http and"
echo "  https. site-ops is an internal ops domain — the tier list has"
echo "  customersupport-tableau.site-ops.fitbit.com at TIER1."
for h in feed-moderation.site-ops.fitbit.com site-ops.fitbit.com zzz-canary-7x2.site-ops.fitbit.com; do
  ip=$(dig +short +time=2 "$h" | grep -E '^[0-9.]+$' | head -1)
  printf '  %-44s %-16s ' "$h" "${ip:--}"
  [ -z "$ip" ] && { echo NO-DNS; continue; }
  curl -s -o /dev/null --max-time 8 -w '%{http_code} %{size_download}b %{redirect_url}\n' "https://$h/"
  sleep 0.6
done

echo
echo "######################################################################"
echo "# 4. two cheap loose ends                                            #"
echo "######################################################################"
echo "  dfa.nestlabs.com/api/login_config.js — a config endpoint names its own backend"
curl -s --max-time 8 "https://dfa.nestlabs.com/api/login_config.js" | head -c 500; echo
echo
echo "  cameyo: /public was identical on the canary, so compare /login instead"
for u in "https://online.cameyo.com/login" "https://zzz-canary-7x2.cameyo.com/login"; do
  printf '  %-48s ' "$u"
  curl -s -o /dev/null --max-time 8 -w '%{http_code} %{size_download}b\n' "$u"
  sleep 0.6
done
