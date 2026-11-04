#!/usr/bin/env python3
"""
exo-req — issue a single EXO2-signed request to the Exoscale API and print it verbatim.

The workhorse for every remaining session. Unlike the `exo` CLI it lets us choose the
method, path and body freely, and it always sends the programme's required identifying
header. Prints the full request and response so the output *is* the evidence.

    export EXO_KEY=... EXO_SECRET=... [EXO_ZONE=ch-gva-2]

    ./exo-req.py GET  /v2/dns-domain
    ./exo-req.py POST /v2/iam-role/<uuid>/assume '{"ttl": 3600}'

Signing follows egoscale v3 api.go signRequest():
    sigParts = ["<METHOD> <path>", <body>, <signed query params>, "", "<expires>"]
    HMAC-SHA256 over "\\n".join(sigParts), base64, in the Authorization header.

Query parameters are deliberately unsupported: they must be sorted and declared in a
`signed-query-args=` pragma, and a silently wrong signature looks like an authorisation
result when it is not one. Add them properly when a test needs them.
"""

import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ZONE = os.environ.get("EXO_ZONE", "ch-gva-2")
HOST = f"api-{ZONE}.exoscale.com"
KEY = os.environ.get("EXO_KEY")
SECRET = os.environ.get("EXO_SECRET")
INTIGRITI_USER = os.environ.get("INTIGRITI_USER", "gorib")


def sign(method, path, body):
    expires = int(time.time()) + 600
    msg = "\n".join([f"{method} {path}", body, "", "", str(expires)])
    sig = hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).digest()
    return (f"EXO2-HMAC-SHA256 credential={KEY},expires={expires},"
            f"signature={base64.b64encode(sig).decode()}")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    if not KEY or not SECRET:
        sys.exit("set EXO_KEY and EXO_SECRET in the environment first")

    method, path = sys.argv[1].upper(), sys.argv[2]
    body = sys.argv[3] if len(sys.argv) > 3 else ""
    if "?" in path:
        sys.exit("query parameters need signed-query-args handling — see the docstring")

    url = f"https://{HOST}{path}"
    req = urllib.request.Request(
        url, method=method, data=body.encode() if body else None
    )
    req.add_header("Authorization", sign(method, path, body))
    req.add_header("X-Intigriti-Username", INTIGRITI_USER)
    req.add_header("Accept", "application/json")
    if body:
        req.add_header("Content-Type", "application/json")

    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"# {stamp}  key={KEY[:8]}...{KEY[-4:]}  zone={ZONE}")
    print(f"> {method} {url}")
    print(f"> X-Intigriti-Username: {INTIGRITI_USER}")
    if body:
        print(f"> {body}")
    print()

    try:
        with urllib.request.urlopen(
            req, timeout=30, context=ssl.create_default_context()
        ) as r:
            status, hdrs, raw = r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        status, hdrs, raw = e.code, dict(e.headers), e.read()
    except Exception as e:                      # noqa: BLE001 — fail loud, never silent
        sys.exit(f"TRANSPORT-ERROR (rig failure, not a result): {e!r}")

    text = raw.decode("utf-8", "replace")
    print(f"< HTTP {status}  {len(raw)} bytes")
    for h in ("content-type", "date", "x-request-id", "www-authenticate"):
        for k, v in hdrs.items():
            if k.lower() == h:
                print(f"< {k}: {v}")
    print()
    try:
        print(json.dumps(json.loads(text), indent=2))
    except Exception:                           # noqa: BLE001 — non-JSON is fine
        print(text)

    # Loud, because this is the response that would matter.
    if status == 200 and '"secret"' in text:
        print("\n*** RESPONSE CONTAINS A SECRET — credentials were issued. ***")
        print("*** Capture this, then stop. Do not use them for anything else. ***")


if __name__ == "__main__":
    main()
