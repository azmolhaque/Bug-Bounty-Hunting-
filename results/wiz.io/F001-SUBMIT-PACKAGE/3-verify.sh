#!/usr/bin/env bash
# 3-verify.sh — F001 live verification
# Run from Termux: bash 3-verify.sh
# All 3 checks must PASS before submitting to Google VRP.
#
# Termux setup (first time only):
#   pkg install dnsutils openssl-tool curl

set -euo pipefail

TARGET="win-test.wiz.io"
EXPECTED_CNAME="37e7f43d8158e70f.vercel-dns-013.com."
BOLD='\033[1m'; RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
PASS=0; FAIL=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  F001 — win-test.wiz.io Subdomain Takeover          ║${NC}"
echo -e "${BOLD}║  Live Verification  •  $(date -u '+%Y-%m-%d %H:%M UTC')       ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── CHECK 1: CNAME IS LIVE AND POINTS TO VERCEL ───────────────────────────
echo -e "${BOLD}[1/3] DNS CNAME check${NC}"
CNAME=$(dig CNAME "$TARGET" +short 2>/dev/null | head -1)
if [[ -z "$CNAME" ]]; then
    # Termux fallback using nslookup if dig not available
    CNAME=$(nslookup -type=CNAME "$TARGET" 2>/dev/null | grep "canonical name" | awk '{print $NF}')
fi

echo "      → $TARGET CNAME = ${CNAME:-'(no result)'}"
if [[ "$CNAME" == "$EXPECTED_CNAME" ]]; then
    pass "Dangling CNAME confirmed: $CNAME"
    A_RECORDS=$(dig A "$TARGET" +short 2>/dev/null | tr '\n' ' ')
    info "A records (Vercel/Fastly edges): ${A_RECORDS:-'see nslookup'}"
else
    fail "CNAME mismatch. Got: '$CNAME' — bug may be fixed or DNS changed."
fi
echo ""

# ─── CHECK 2: VERCEL RETURNS DEPLOYMENT_NOT_FOUND ──────────────────────────
echo -e "${BOLD}[2/3] Vercel project status check${NC}"
BODY=$(curl -sk --max-time 15 "https://$TARGET/" 2>/dev/null || echo "CURL_FAILED")
echo "      → HTTP response body (first 120 chars):"
echo "        $(echo "$BODY" | head -c 120)"

if echo "$BODY" | grep -qi "DEPLOYMENT_NOT_FOUND\|deployment-not-found\|deployment_not_found"; then
    pass "Vercel project is DELETED — DEPLOYMENT_NOT_FOUND confirmed"
elif echo "$BODY" | grep -qi "CURL_FAILED"; then
    fail "curl failed — check network connection"
else
    fail "Unexpected response — bug may be fixed or already claimed by another party"
    info "Full response: $BODY"
fi
echo ""

# ─── CHECK 3: TLS CERTIFICATE IS EXPIRED ───────────────────────────────────
echo -e "${BOLD}[3/3] TLS certificate expiry check${NC}"
CERT_OUTPUT=$(echo | openssl s_client \
    -connect "${TARGET}:443" \
    -servername "$TARGET" \
    -timeout 10 2>/dev/null)

SERIAL=$(echo "$CERT_OUTPUT" | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)
NOT_BEFORE=$(echo "$CERT_OUTPUT" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2-)
NOT_AFTER=$(echo "$CERT_OUTPUT" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2-)
ISSUER=$(echo "$CERT_OUTPUT" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
SUBJECT=$(echo "$CERT_OUTPUT" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')

echo "      → Subject:    ${SUBJECT:-'(unavailable)'}"
echo "      → Issuer:     ${ISSUER:-'(unavailable)'}"
echo "      → Serial:     ${SERIAL:-'(unavailable)'}"
echo "      → Not Before: ${NOT_BEFORE:-'(unavailable)'}"
echo "      → Not After:  ${NOT_AFTER:-'(unavailable)'}"

EXPECTED_SERIAL="06D355B91521BADCB06BBEB409F290FC5094"
if [[ -n "$SERIAL" ]]; then
    SERIAL_CLEAN=$(echo "$SERIAL" | tr -d ':' | tr '[:lower:]' '[:upper:]')
    if [[ "$SERIAL_CLEAN" == "$EXPECTED_SERIAL" ]]; then
        pass "Certificate serial matches known abandoned cert: $SERIAL"
    else
        info "Different cert serial: $SERIAL — may have been claimed already!"
    fi
fi

if [[ -n "$NOT_AFTER" ]]; then
    # Try GNU date first, then BSD date (macOS)
    EXPIRY_EPOCH=$(date -d "$NOT_AFTER" +%s 2>/dev/null || \
                   date -j -f "%b %e %H:%M:%S %Y %Z" "$NOT_AFTER" +%s 2>/dev/null || echo 0)
    NOW_EPOCH=$(date +%s)
    if [[ $EXPIRY_EPOCH -gt 0 && $EXPIRY_EPOCH -lt $NOW_EPOCH ]]; then
        DAYS_AGO=$(( (NOW_EPOCH - EXPIRY_EPOCH) / 86400 ))
        pass "Certificate EXPIRED ${DAYS_AGO} days ago (${NOT_AFTER})"
        pass "  → Confirms abandoned Vercel project; fresh cert issued on claim"
    elif [[ $EXPIRY_EPOCH -gt $NOW_EPOCH ]]; then
        fail "Certificate is VALID — domain may have been claimed already! Do not submit."
    fi
else
    fail "Could not retrieve certificate — check openssl/network"
fi
echo ""

# ─── SUMMARY ────────────────────────────────────────────────────────────────
echo -e "${BOLD}════════════════════ RESULT ════════════════════${NC}"
if [[ $FAIL -eq 0 && $PASS -eq 3 ]]; then
    echo -e "${GREEN}${BOLD}✓ ALL 3 CHECKS PASSED — Vulnerability is LIVE${NC}"
    echo ""
    echo "  Submit to: https://bughunters.google.com/report"
    echo "  Use file:  1-REPORT.md  (paste into description field)"
    echo "  Attach:    wintest.wiz.io.crt  +  2-POC.md"
    echo "  Severity:  High (CVSS 8.2)"
elif [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}${BOLD}✗ $FAIL CHECK(S) FAILED — Verify manually before submitting${NC}"
    echo "  The bug may have been fixed or already claimed."
fi
echo ""
