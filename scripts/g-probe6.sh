#!/data/data/com.termux/files/usr/bin/bash
# g-probe6.sh — THE CHAIN. This single question decides whether G-F001 is a
# credential-exposure report or an account-takeover report.
#
# A client secret alone does not take over accounts: to exchange an authorization
# code you also need the code, and codes are delivered to the REGISTERED
# redirect_uri. So the whole severity of this finding turns on one thing:
#
#     will Fitbit's authorize endpoint send a code to a URI we control?
#
# If redirect_uri validation is strict, the finding stands as credential exposure
# and we report exactly that. If it is loose, then:
#
#     loose redirect_uri  ->  attacker receives a victim's code
#     + published secret  ->  attacker exchanges it for a USER access token
#     = account takeover over scopes incl. heartrate, location, sleep
#
# and the published secret is the link that makes the chain work, because a
# confidential client's code cannot be exchanged without it.
#
# Nothing here involves a victim. No session, no consent, no code is ever issued.
set -u
A=https://www.fitbit.com/oauth2/authorize
ID=227ZG3

t() { # t <label> <client_id> <redirect_uri>
  printf '  %-42s ' "$1"
  u="$A?response_type=code&client_id=$2&scope=profile"
  [ -n "$3" ] && u="$u&redirect_uri=$(printf '%s' "$3" | sed 's/:/%3A/g;s|/|%2F|g;s/@/%40/g;s/?/%3F/g')"
  out=$(curl -s -D - -o "$HOME/.gprobe/auth.body" --max-time 12 "$u" 2>/dev/null)
  code=$(printf '%s' "$out" | head -1 | awk '{print $2}')
  loc=$(printf '%s' "$out" | awk 'BEGIN{IGNORECASE=1}/^location:/{sub(/^[^:]*: */,"");gsub(/\r/,"");print;exit}')
  err=$(grep -oiE 'redirect[_ ]?uri[^<&"]{0,70}|invalid_request[^<&"]{0,60}|error=[a-z_]+' "$HOME/.gprobe/auth.body" 2>/dev/null | head -1)
  printf '%-4s %s %s\n' "${code:-ERR}" "$(printf '%s' "${loc:--}" | cut -c1-90)" "${err:+| $err}"
  sleep 1.2
}
mkdir -p "$HOME/.gprobe"

echo "######################################################################"
echo "# What does ACCEPTANCE look like, and what does REJECTION look like? #"
echo "######################################################################"
t "[no redirect_uri at all]"        "$ID" ""
t "[CONTROL] obviously wrong URI"   "$ID" "https://example.com/"
t "[SENTINEL] fabricated client_id" "ZZZZZZ" "https://example.com/"
echo
echo "  If the CONTROL and the SENTINEL look different from each other, the endpoint"
echo "  is telling us which part it rejected, and every row below is readable."

echo
echo "######################################################################"
echo "# The host's own origin, then the classic validation mistakes        #"
echo "######################################################################"
t "exact own origin"               "$ID" "https://feed-moderation.fitbit.com/"
t "own origin + extra path"        "$ID" "https://feed-moderation.fitbit.com/zzz-canary-7x2"
t "SUFFIX attack  (.example.com)"  "$ID" "https://feed-moderation.fitbit.com.example.com/"
t "USERINFO attack (@example.com)" "$ID" "https://feed-moderation.fitbit.com@example.com/"
t "SUBDOMAIN  zzz.<host>"          "$ID" "https://zzz-canary-7x2.feed-moderation.fitbit.com/"
t "apex fitbit.com"                "$ID" "https://fitbit.com/"
t "loopback http://localhost"      "$ID" "http://localhost:8080/"
t "loopback 127.0.0.1"             "$ID" "http://127.0.0.1:8080/"

echo
echo "######################################################################"
echo "# Same question for the sign-in host's client, 228TQD                #"
echo "######################################################################"
t "[CONTROL] wrong URI"            "228TQD" "https://example.com/"
t "exact accounts origin"          "228TQD" "https://accounts.fitbit.com/"
t "SUFFIX attack"                  "228TQD" "https://accounts.fitbit.com.example.com/"
t "USERINFO attack"                "228TQD" "https://accounts.fitbit.com@example.com/"
t "loopback"                       "228TQD" "http://localhost:8080/"

echo
echo "######################################################################"
echo "# HOW TO READ THIS                                                   #"
echo "######################################################################"
cat <<'TXT'
  Every attack row behaves like the CONTROL      -> validation is strict.
      The chain is dead. Report G-F001 as written: credential exposure, and say
      plainly that redirect_uri validation was tested and holds. Saying so makes
      the report stronger, not weaker - it shows the impact was bounded, not guessed.

  Any attack row behaves like the EXACT OWN ORIGIN row instead
      -> that URI is accepted, a code would be delivered there, and with the
      published secret it can be exchanged for a user token. STOP IMMEDIATELY.
      Do not complete a flow, do not sign in, do not obtain a code. The accepted
      redirect_uri IS the proof; a real code would mean touching a real account.
TXT
