#!/data/data/com.termux/files/usr/bin/bash
# g-captcha.sh — prove, or disprove, the one impact claim the report rests on.
#
# THE CLAIM SO FAR, UNPROVEN:
#   "the token endpoint reached with the published secret is a credential-check
#    without the reCAPTCHA that guards the sign-in page."
#
# We inferred that from a feature flag. That is not evidence, and a reviewer will
# say so. It CAN be proved by static analysis, with no brute force and no extra
# requests: read accounts.fitbit.com's own bundle and find out whether its login
# code attaches a reCAPTCHA token to the credential submission.
#
#   it does   -> the page sends a captcha token, our curl sent none and was still
#                processed. The bypass is demonstrated, not asserted. This is the
#                impact the report has been missing.
#   it does not -> there is no captcha on that path at all, the claim is wrong, and
#                it comes OUT of the report. Better found now than by a reviewer.
set -u
T="$HOME/.gcap"; mkdir -p "$T"
echo "Fetching accounts.fitbit.com and its bundles..."
curl -s --max-time 15 https://accounts.fitbit.com/ -o "$T/index.html"
grep -oE 'src="[^"]+\.js[^"]*"' "$T/index.html" | sed 's/src="//;s/"$//' | sort -u > "$T/js.txt"
: > "$T/all.js"
while read -r j; do
  [ -z "$j" ] && continue
  case "$j" in http*) u="$j" ;; /*) u="https://accounts.fitbit.com$j" ;; *) u="https://accounts.fitbit.com/$j" ;; esac
  printf '  %s\n' "$(basename "$j")"
  curl -s --max-time 40 --max-filesize 4000000 "$u" >> "$T/all.js"
  sleep 0.5
done < "$T/js.txt"
printf '  total %s bytes of JS\n\n' "$(wc -c < "$T/all.js")"

echo "######################################################################"
echo "# 1. Is reCAPTCHA wired into the LOGIN request, or only loaded?      #"
echo "######################################################################"
echo "  Loading the library proves nothing. What matters is whether a captcha"
echo "  token is put INTO the credential request."
grep -oE '.{90}(recaptcha|reCaptcha|captchaToken|grecaptcha)[A-Za-z]{0,20}.{90}' "$T/all.js" \
  | sort -u | head -14 | sed 's/^/    /'

echo
echo "######################################################################"
echo "# 2. How does the page submit a username and password?               #"
echo "######################################################################"
grep -oE '.{110}grant_type:"password".{150}' "$T/all.js" | head -4 | sed 's/^/    /'
echo
echo "    --- and which parameters travel with it ---"
grep -oE 'grant_type:"password"[^}]{0,320}' "$T/all.js" | head -3 | sed 's/^/    /'

echo
echo "######################################################################"
echo "# 3. Does any captcha value get attached to a token request?         #"
echo "######################################################################"
grep -oE '[A-Za-z_]{0,18}(captcha|Captcha)[A-Za-z_]{0,18}\s*[:=]\s*[A-Za-z_$][A-Za-z0-9_$.]{0,40}' "$T/all.js" \
  | sort -u | head -20 | sed 's/^/    /'

echo
echo "######################################################################"
echo "# 4. Which endpoints does the login code actually call?              #"
echo "######################################################################"
grep -oE '"(/[a-zA-Z0-9_/.-]{3,60})"|https://[a-zA-Z0-9.-]+/[a-zA-Z0-9_/.-]{0,40}' "$T/all.js" \
  | grep -iE 'oauth2|token|login|signin|session|authenticate|captcha' | sort -u | head -25 | sed 's/^/    /'

echo
cat <<'TXT'

  READ IT LIKE THIS

    Section 2 or 3 shows a captcha value travelling WITH the password request
        -> the sign-in path requires a captcha token. Our curl sent none and the
           endpoint still validated the credentials. That is a demonstrated
           protection bypass, and it is the impact the report needs. Capture the
           exact code snippet - it is the evidence.

    No captcha anywhere near the credential submission
        -> the claim was wrong. reCAPTCHA guards signup or some other flow, not
           this one. The sentence comes OUT of the report. Finding that ourselves
           is worth more than having a reviewer find it.
TXT
