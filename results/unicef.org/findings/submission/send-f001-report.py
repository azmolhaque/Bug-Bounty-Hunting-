#!/usr/bin/env python3
"""
send-f001-report.py  —  Send F001 UNICEF vulnerability report

Sends from azmolhaque95@gmail.com to infosecurity@unicef.org via Gmail SMTP.
The PoC script is attached as .py.txt (Gmail blocks .py attachments).

Prerequisites for azmolhaque95@gmail.com:
  1. Enable 2-Step Verification: https://myaccount.google.com/security
  2. Create an App Password:     https://myaccount.google.com/apppasswords
     Category: Mail / Device: Other  →  name it "Bug Bounty Pi"
  3. Run:  python3 send-f001-report.py
     Paste the 16-character App Password when prompted.
"""

import os
import sys
import getpass
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

# ── Paths ──────────────────────────────────────────────────────────────────────

HERE       = os.path.dirname(os.path.abspath(__file__))
REPORT_MD  = os.path.join(HERE, "F001-unicef-email-report.md")
POC_PY     = os.path.join(HERE, "..", "poc-F001-unicef-jsonapi-disclosure.py")

# ── Email config ───────────────────────────────────────────────────────────────

FROM    = "azmolhaque95@gmail.com"
TO      = "infosecurity@unicef.org"
SUBJECT = (
    "Vulnerability Report: Unauthenticated Bulk Disclosure of 13,112 "
    "Staff Email Addresses via Drupal JSON:API on ram.unicef.org"
)
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

# ── Helpers ────────────────────────────────────────────────────────────────────

DELIM = "==========================================================================="


def read_email_body(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    start = content.find(DELIM)
    end   = content.rfind(DELIM)
    if start == -1 or start == end:
        raise ValueError(f"Could not find === delimiters in {path}")
    return content[start + len(DELIM):end].strip()


def check_files():
    missing = []
    for path, label in [(REPORT_MD, "email report"), (POC_PY, "PoC script")]:
        if not os.path.exists(path):
            missing.append(f"  {label}: {path}")
    if missing:
        print("ERROR — required files not found:")
        print("\n".join(missing))
        sys.exit(1)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    check_files()

    body    = read_email_body(REPORT_MD)
    poc_src = open(POC_PY, "r", encoding="utf-8").read()

    # Add attachment note to body (Gmail renames .py → .py.txt)
    body += (
        "\n\n"
        "─────────────────────────────────────────────────────────────────────────\n"
        "NOTE ON ATTACHMENT\n"
        "─────────────────────────────────────────────────────────────────────────\n"
        "The PoC script is attached as poc-F001-unicef-jsonapi-disclosure.py.txt\n"
        "(Gmail blocks .py attachments; rename to .py to run it directly).\n"
        "Requirements: Python 3.6+ stdlib only — no pip installs.\n"
        "Run: python3 poc-F001-unicef-jsonapi-disclosure.py --sample-only\n"
    )

    # Build MIME message
    msg = MIMEMultipart()
    msg["From"]    = FROM
    msg["To"]      = TO
    msg["Subject"] = SUBJECT

    msg.attach(MIMEText(body, "plain", "utf-8"))

    attach_name = "poc-F001-unicef-jsonapi-disclosure.py.txt"
    part = MIMEApplication(poc_src.encode("utf-8"), Name=attach_name)
    part["Content-Disposition"] = f'attachment; filename="{attach_name}"'
    msg.attach(part)

    # Preview
    print()
    print("─" * 70)
    print("  F001 — UNICEF Vulnerability Report")
    print("─" * 70)
    print(f"  From   : {FROM}")
    print(f"  To     : {TO}")
    print(f"  Subject: {SUBJECT[:65]}...")
    print(f"  Body   : {len(body):,} characters")
    print(f"  Attach : {attach_name} ({len(poc_src):,} bytes)")
    print("─" * 70)
    print()
    print("You need a Gmail App Password (not your regular password).")
    print("  → https://myaccount.google.com/apppasswords")
    print("  → 2-Step Verification must be enabled first")
    print()

    password = getpass.getpass(f"App Password for {FROM}: ").strip()
    if not password:
        print("Aborted.")
        sys.exit(0)

    print()
    print(f"Connecting to {SMTP_HOST}:{SMTP_PORT} ...")

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(FROM, password)
            smtp.sendmail(FROM, [TO], msg.as_bytes())

        print()
        print("✓ SUCCESS — email sent to infosecurity@unicef.org")
        print("  Check Sent folder in azmolhaque95@gmail.com to confirm.")
        print()

    except smtplib.SMTPAuthenticationError:
        print()
        print("✗ ERROR: Authentication failed.")
        print("  Make sure you used the App Password, not your regular Gmail password.")
        print("  App Passwords: https://myaccount.google.com/apppasswords")
        sys.exit(1)

    except smtplib.SMTPException as e:
        print(f"\n✗ SMTP error: {e}")
        sys.exit(1)

    except OSError as e:
        print(f"\n✗ Network error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
