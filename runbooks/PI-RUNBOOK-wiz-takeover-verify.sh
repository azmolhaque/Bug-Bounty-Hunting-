#!/usr/bin/env bash
# =============================================================================
# Google VRP — Wiz F001 (win-test.wiz.io) SUBDOMAIN-TAKEOVER **CLAIMABILITY** TEST
# Report: IssueTracker #524181553 (currently P2, status New, Wiz prodsec queue)
# Portable: Termux / Linux / Pi.
#
# WHY THIS RUN EXISTS (METHODOLOGY FO-9 — Boundary-Cross Proof Gate):
#   The submitted report ASSERTS win-test.wiz.io is claimable on a free Vercel
#   account. It never PROVED it. `DEPLOYMENT_NOT_FOUND` is only the PRECONDITION
#   (dangling CNAME), NOT proof of takeover. Modern Vercel BLOCKS claiming a
#   domain that is still bound to another team, and the persistent EXPIRED Wiz
#   TLS cert (Dec 2025) is a strong tell the domain is STILL bound to Wiz's
#   Vercel team → likely NOT claimable. FO-9 says: prove the cross or drop the
#   claim. This run settles it either way:
#     * claim SUCCEEDS + our canary served under a FRESH cert = takeover PROVEN
#       → the P2 report is confirmed with self-made, in-hand evidence.
#     * claim is REFUSED ("assigned to another team") = takeover NOT exploitable
#       → be honest: the report is precondition-only, do not defend it (FO-12).
#
# ETHICS / SAFETY (NON-NEGOTIABLE):
#   * In scope: win-test.wiz.io matches *.wiz.io (TIER1, blackout-exempt).
#   * BENIGN CANARY ONLY. The page says exactly: "PoC 524181553 — authorized
#     Google VRP test — no data collected". NO cookie capture, NO JS that reads
#     document.cookie, NO redirect, NO phishing, NO logging of any visitor.
#   * We NEVER capture a real Wiz user's cookie/session. The whole point is to
#     prove *claimability*, not to harvest anything.
#   * RELEASE the domain immediately after the screenshot (remove it from the
#     Vercel project / delete the project). Hold time = minutes.
#   * GET/read-only against wiz.io DNS. We change NOTHING in wiz.io's zone.
#
# USAGE:
#   Phase A (pre-check, run now):     bash runbooks/PI-RUNBOOK-wiz-takeover-verify.sh pre
#   Phase B (the claim itself):       follow the printed browser steps
#   Phase C (post-check, after claim):CANARY_TOKEN=524181553 \
#                                       bash runbooks/PI-RUNBOOK-wiz-takeover-verify.sh post
#   Phase D (confirm release):        bash runbooks/PI-RUNBOOK-wiz-takeover-verify.sh release
# =============================================================================
set -o pipefail
TARGET="win-test.wiz.io"
OUTDIR="${OUTDIR:-$HOME/wiz-takeover}"; mkdir -p "$OUTDIR"
PHASE="${1:-pre}"
STAMP(){ date -u '+%Y-%m-%dT%H:%M:%SZ'; }
# Reference cert serial from the submitted report (Wiz's own expired cert).
# If the CURRENT serial still equals this, the domain is still bound to Wiz's
# Vercel team (Vercel keeps serving the old cert) → un-claimable signal.
REPORT_CERT_SERIAL="06D355B91521BADCB06BBEB409F290FC5094"
REPORT_CERT_NOTAFTER="Dec 16 11:19:36 2025 GMT"

banner(){ echo "============================================================";
  echo "WIZ F001 CLAIMABILITY TEST — phase:$PHASE  $(STAMP)";
  echo "target=$TARGET   IP=$(curl -s --max-time 8 ifconfig.me)";
  echo "report=#524181553   BENIGN CANARY ONLY — no cookie capture, release after";
  echo "============================================================"; echo ""; }

fingerprint(){ # writes a full state snapshot to $1
  local out="$1"
  {
    echo "### snapshot $(STAMP)"
    echo "--- dig CNAME ---";      dig CNAME "$TARGET" +short 2>/dev/null
    echo "--- dig A ---";          dig A     "$TARGET" +short 2>/dev/null
    echo "--- HTTP status + vercel-error header ---"
    curl -sI --max-time 15 "https://$TARGET/" 2>/dev/null \
      | grep -iE 'HTTP/|x-vercel-error|x-vercel-id|server:|location:'
    echo "--- body (first 200 bytes) ---"
    curl -sk --max-time 15 "https://$TARGET/" 2>/dev/null | head -c 200; echo ""
    echo "--- TLS cert (dates / serial / issuer / SAN) ---"
    echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
      | openssl x509 -noout -dates -serial -issuer 2>/dev/null
    echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
      | openssl x509 -noout -ext subjectAltName 2>/dev/null
  } | tee "$out"
}

case "$PHASE" in
# ---------------------------------------------------------------------------
pre)
  banner
  echo "═══ PRE-CLAIM STATE (must still be dangling to proceed) ═══"
  fingerprint "$OUTDIR/pre.txt"; echo ""
  echo "─── interpretation ───"
  cur_serial=$(grep -o 'serial=[0-9A-Fa-f]*' "$OUTDIR/pre.txt" | head -1 | cut -d= -f2)
  if grep -qi 'DEPLOYMENT_NOT_FOUND' "$OUTDIR/pre.txt"; then
    echo "  [ok] Still DEPLOYMENT_NOT_FOUND — dangling precondition holds."
  else
    echo "  [STOP] No DEPLOYMENT_NOT_FOUND — state changed. Re-read pre.txt before"
    echo "         doing anything else; the CNAME may have been fixed or reclaimed."
  fi
  if [ "$cur_serial" = "$REPORT_CERT_SERIAL" ]; then
    echo "  [signal: LIKELY NOT CLAIMABLE] Current cert serial == the report's"
    echo "     Wiz cert ($REPORT_CERT_SERIAL, expired $REPORT_CERT_NOTAFTER)."
    echo "     Vercel is still serving Wiz's OLD cert => domain likely STILL bound"
    echo "     to Wiz's Vercel team => the free-account claim will probably be"
    echo "     REFUSED. That would make the report precondition-only (FO-9)."
  elif [ -n "$cur_serial" ]; then
    echo "  [signal] Cert serial changed ($cur_serial). Domain may be released or"
    echo "     re-provisioned — the claim test below is decisive."
  fi
  echo ""
  echo "═══ NEXT: attempt the actual claim (this is the FO-9 boundary cross) ═══"
  cat <<'STEPS'
  1. https://vercel.com → sign up FREE (throwaway is fine).
  2. Add New → Project → deploy a blank/"Hello World" static page.
  3. Project → Settings → Domains → Add Domain → enter:  win-test.wiz.io
  4. WATCH VERCEL'S RESPONSE AND SCREENSHOT IT — this is the whole finding:
       (a) "Valid Configuration" / domain attaches / TLS provisions
             => CLAIM SUCCEEDED → takeover CONFIRMED. Go to phase `post`.
       (b) "This domain is already in use by another team / project" (or any
           refusal to attach) => CLAIM REFUSED → takeover NOT exploitable.
           Screenshot the exact message, then STOP. Update the report honestly.
  5. If (a): replace the page body with EXACTLY the benign canary (below), redeploy,
     THEN run:  CANARY_TOKEN=524181553 bash runbooks/PI-RUNBOOK-wiz-takeover-verify.sh post
STEPS
  echo ""
  echo "  Benign canary page (index.html) — copy verbatim, NOTHING else:"
  cat > "$OUTDIR/index.html" <<'HTML'
<!doctype html><meta charset="utf-8">
<title>PoC 524181553</title>
<h1>PoC 524181553 — authorized Google VRP subdomain-takeover test</h1>
<p>This page proves win-test.wiz.io was claimable by an unauthorized party.
No data is collected. No cookies are read. Reported to Google VRP / Wiz.
This page will be removed immediately after verification.</p>
HTML
  echo "  (written to $OUTDIR/index.html — deploy this exact file, no JS)"
  ;;
# ---------------------------------------------------------------------------
post)
  : "${CANARY_TOKEN:?set CANARY_TOKEN=524181553 (the string that must appear in the served page)}"
  banner
  echo "═══ POST-CLAIM VERIFICATION (only meaningful if the claim SUCCEEDED) ═══"
  fingerprint "$OUTDIR/post.txt"; echo ""
  echo "─── decisive checks ───"
  ok=1
  if curl -sk --max-time 15 "https://$TARGET/" 2>/dev/null | grep -qF "$CANARY_TOKEN"; then
    echo "  [PROVEN] Our canary token '$CANARY_TOKEN' is served from https://$TARGET/"
  else
    echo "  [not served] Canary token not found in the live body — claim not in"
    echo "     effect yet (Vercel TLS can take a few min) or claim did not succeed."
    ok=0
  fi
  post_serial=$(grep -o 'serial=[0-9A-Fa-f]*' "$OUTDIR/post.txt" | head -1 | cut -d= -f2)
  if [ -n "$post_serial" ] && [ "$post_serial" != "$REPORT_CERT_SERIAL" ]; then
    echo "  [PROVEN] Fresh TLS cert (serial=$post_serial != old $REPORT_CERT_SERIAL)"
    echo "     — Vercel re-provisioned the domain under OUR project."
  else
    echo "  [check] Cert serial still == Wiz's old cert — no fresh provisioning yet."
    ok=0
  fi
  echo ""
  if [ "$ok" = 1 ]; then
    echo "  *** TAKEOVER CONFIRMED — self-made proof in hand. ***"
    echo "  Now: SCREENSHOT the browser at https://$TARGET/ showing the canary +"
    echo "  the padlock (valid TLS). Save it to $OUTDIR/. Then RELEASE immediately:"
  else
    echo "  Not yet proven. If Vercel refused the domain, the takeover is NOT"
    echo "  exploitable — say so honestly in the report (FO-9/FO-12). If it just"
    echo "  needs TLS time, wait 2-3 min and re-run `post`."
  fi
  echo "     -> Vercel: Project → Settings → Domains → Remove win-test.wiz.io"
  echo "     -> then delete the project. Then run the `release` phase to confirm."
  ;;
# ---------------------------------------------------------------------------
release)
  banner
  echo "═══ RELEASE CONFIRMATION (domain must be handed back / no longer ours) ═══"
  fingerprint "$OUTDIR/release.txt"; echo ""
  if curl -sk --max-time 15 "https://$TARGET/" 2>/dev/null | grep -qi 'DEPLOYMENT_NOT_FOUND'; then
    echo "  [ok] Back to DEPLOYMENT_NOT_FOUND — our project is removed. Clean."
  elif curl -sk --max-time 15 "https://$TARGET/" 2>/dev/null | grep -qF '524181553'; then
    echo "  [STILL LIVE] Our canary is STILL served — REMOVE the domain from Vercel"
    echo "     now. Do not leave the takeover standing."
  else
    echo "  [inspect] Neither our canary nor DEPLOYMENT_NOT_FOUND — read release.txt."
  fi
  echo ""
  echo "Evidence dir: $OUTDIR (pre.txt / post.txt / release.txt + screenshots)"
  ;;
*) echo "usage: $0 {pre|post|release}"; exit 2;;
esac
echo ""
echo "phase '$PHASE' complete: $(STAMP)"
