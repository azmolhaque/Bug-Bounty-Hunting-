#!/data/data/com.termux/files/usr/bin/bash
# g-verify.sh — attack our own central claim before a reviewer does.
#
# THE CLAIM: "the token endpoint performs the credential check without the
# reCAPTCHA token Fitbit's own client attaches."
#
# THE DANGER: their bundle also contains
#     loginWhenRecaptchaFails:function
#     recaptchaFail:function
#     checkUnrecoverableErrorAndRetryGetRecaptchaToken
# and loads reCAPTCHA **v3** (api.js?render=<sitekey>), which is score-based and
# frequently advisory rather than blocking.
#
# If their own client deliberately logs in WITHOUT a captcha token when reCAPTCHA
# fails, then the server not requiring one is the DESIGN, our "bypass" is intended
# behaviour, and the impact claim has to come out. Better we find that than a
# reviewer. If instead the fallback is narrow or still carries a token, the claim
# survives and is much stronger for having been attacked.
set -u
T="$HOME/.gcap"; mkdir -p "$T"
[ -s "$T/all.js" ] || { echo "run scripts/g-captcha.sh first (it caches the bundles)"; exit 1; }
printf 'bundle cache: %s bytes\n\n' "$(wc -c < "$T/all.js")"

show() { echo "=== $1 ==="; grep -oE "$2" "$T/all.js" | sort -u | head -"${3:-6}" | sed 's/^/  /'; echo; }

echo "######################################################################"
echo "# 1. What happens when reCAPTCHA FAILS? (the claim lives or dies here)#"
echo "######################################################################"
show "loginWhenRecaptchaFails — the whole function" 'loginWhenRecaptchaFails:function[^}]{0,400}' 4
show "recaptchaFail" 'recaptchaFail:function[^}]{0,400}' 4
show "handleRecaptchaError" 'handleRecaptchaError:function[^}]{0,350}' 3

echo "######################################################################"
echo "# 2. Is the token ever OMITTED on purpose?                            #"
echo "######################################################################"
show "calls to fitbitPasswordOauth2Login" 'fitbitPasswordOauth2Login\([^)]{0,160}' 8
show "the login function signature" 'fitbitPasswordOauth2Login:function\([^)]{0,80}' 3

echo "######################################################################"
echo "# 3. Is the captcha advisory (v3 assessment) or blocking?             #"
echo "######################################################################"
show "makeRecaptchaAssessment" 'makeRecaptchaAssessment:function[^}]{0,400}' 3
show "where recaptchaEnabled is tested" '.{80}recaptchaEnabled.{120}' 6
show "the recaptcha-blocked route — does anything navigate to it?" '.{100}recaptcha-blocked.{80}|transitionTo\("recaptcha[^"]*"\)|"recaptcha-blocked"' 6

echo "######################################################################"
echo "# 4. v2 or v3? and is a score ever acted on client-side?              #"
echo "######################################################################"
show "recaptcha script URL (render= means v3)" 'recaptcha[^"]{0,40}api\.js[^"]{0,60}' 4
show "any score handling" '.{60}(score|assessment|riskAnalysis).{80}' 6
