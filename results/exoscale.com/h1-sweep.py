#!/usr/bin/env python3
"""
H1 sweep — does a policy-restricted Exoscale key reach services its policy denies?

Reads credentials from the environment. NEVER hardcode them, never commit them:

    export EXO_KEY="EXO..."
    export EXO_SECRET="..."
    ./h1-sweep.py

Only issues GET requests, and only to *collection* endpoints that take no path
parameter — so no resource ID is ever guessed or enumerated and no Exoscale
customer's resource can be touched (program rule + FO-14).

Rate limited well under the program's 10 req/s ceiling.
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

REQ_INTERVAL = 0.35  # ~3 req/s — program ceiling is 10

if not KEY or not SECRET:
    sys.exit("set EXO_KEY and EXO_SECRET in the environment first")

# GET endpoints taking no path parameter, from egoscale v3 operations.go.
# Grouped by the service class we expect to gate them.
ENDPOINTS = [
    # --- allowed by our policy: the positive control ---
    ("dns",          "/v2/dns-domain"),
    # --- high value: a hit here is a real finding ---
    ("iam",          "/v2/api-key"),
    ("iam",          "/v2/iam-role"),
    ("iam",          "/v2/iam-organization-policy"),
    ("iam",          "/v2/user"),
    ("ai",           "/v2/ai/api-key"),
    ("kms",          "/v2/kms-key"),
    ("organization", "/v2/organization"),
    ("organization", "/v2/event"),
    ("organization", "/v2/live-balance"),
    ("organization", "/v2/usage-report"),
    ("organization", "/v2/quota"),
    ("sos",          "/v2/sos-buckets-usage"),
    # --- customer resource inventories ---
    ("compute",      "/v2/instance"),
    ("compute",      "/v2/instance-pool"),
    ("compute",      "/v2/snapshot"),
    ("compute",      "/v2/ssh-key"),
    ("compute",      "/v2/elastic-ip"),
    ("compute",      "/v2/security-group"),
    ("compute",      "/v2/anti-affinity-group"),
    ("compute",      "/v2/private-network"),
    ("compute",      "/v2/vpc"),
    ("compute",      "/v2/load-balancer"),
    ("compute",      "/v2/sks-cluster"),
    ("compute",      "/v2/deploy-target"),
    ("block-storage", "/v2/block-storage"),
    ("block-storage", "/v2/block-storage-snapshot"),
    ("dbaas",        "/v2/dbaas-service"),
    ("dbaas",        "/v2/dbaas-external-endpoints"),
    ("dbaas",        "/v2/dbaas-ca-certificate"),
    ("ai",           "/v2/ai/deployment"),
    ("ai",           "/v2/ai/quota"),
    # --- catalogue / static: expected public, included as calibration ---
    ("catalogue",    "/v2/zone"),
    ("catalogue",    "/v2/instance-type"),
    ("catalogue",    "/v2/template"),
    ("catalogue",    "/v2/sks-cluster-version"),
    ("catalogue",    "/v2/ai/model"),
    ("catalogue",    "/v2/ai/instance-type"),
    ("catalogue",    "/v2/dbaas-service-type"),
    ("catalogue",    "/v2/dbaas-integration-types"),
    ("catalogue",    "/v2/dbaas-external-endpoint-types"),
    ("catalogue",    "/v2/environmental-impact/report"),
]


def sign(method, path):
    """EXO2-HMAC-SHA256, per egoscale v3 api.go signRequest().

    Signed message for a GET with no body and no query params:
        "<METHOD> <path>", "", "", "", "<expires>"   joined with "\\n"
    """
    expires = int(time.time()) + 600
    msg = "\n".join([f"{method} {path}", "", "", "", str(expires)])
    sig = hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).digest()
    return (
        f"EXO2-HMAC-SHA256 credential={KEY},"
        f"expires={expires},"
        f"signature={base64.b64encode(sig).decode()}"
    )


def call(path):
    req = urllib.request.Request(f"https://{HOST}{path}", method="GET")
    req.add_header("Authorization", sign("GET", path))
    req.add_header("X-Intigriti-Username", INTIGRITI_USER)
    req.add_header("Accept", "application/json")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                      # noqa: BLE001 - fail loud, never silent
        return None, f"TRANSPORT-ERROR: {e!r}"


def main():
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out = f"h1-sweep-{ZONE}.jsonl"
    print(f"zone={ZONE}  host={HOST}  started={stamp}")
    print(f"{len(ENDPOINTS)} GET collection endpoints, ~{REQ_INTERVAL}s apart\n")

    hits = []
    with open(out, "w") as fh:
        for svc, path in ENDPOINTS:
            status, body = call(path)
            snippet = body[:220].replace("\n", " ")
            fh.write(json.dumps({
                "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "zone": ZONE, "service": svc, "path": path,
                "status": status, "bytes": len(body), "body": body[:4000],
            }) + "\n")

            if status is None:
                mark = "ERR "                    # rig problem, NOT a result
            elif status == 200 and svc == "dns":
                mark = "ctrl"                    # positive control
            elif status == 200 and svc == "catalogue":
                mark = "pub "                    # expected-public calibration
            elif status == 200:
                mark = "HIT!"                    # denied service answered
                hits.append((svc, path, len(body)))
            else:
                mark = "deny"

            print(f"  [{mark}] {status!s:>4} {len(body):>7}b  {path:<42} ({svc})")
            if mark in ("HIT!", "ERR "):
                print(f"          {snippet}")
            time.sleep(REQ_INTERVAL)

    print(f"\nfull responses -> {out}")
    if hits:
        print("\n*** denied services that answered 200 ***")
        for svc, path, n in hits:
            print(f"    {path}  ({svc})  {n} bytes")
        print("\nNext: does the body contain real org data, or is it empty/public?")
        print("An empty 200 is not a finding. Read the bodies in the jsonl.")
    else:
        print("\nNo denied service returned 200. Enforcement holds on this axis.")


if __name__ == "__main__":
    main()
