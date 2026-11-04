#!/usr/bin/env python3
"""
H1 follow-up — which endpoints answer with NO credentials at all?

Motivation: `exo` CLI got 200 on GET /v2/zone with our dns-only key, while the same
request signed by hand got 403 ("compute" denial). If egoscale discovers zones with an
unauthenticated client, then unauthenticated requests bypass the policy engine entirely
— and the question becomes what *else* is reachable that way.

Reuses the endpoint list from the authenticated sweep's jsonl, so the two runs are
directly comparable. Sends no Authorization header. GET only, collection endpoints
only, no resource IDs (FO-14).
"""

import json
import os
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ZONE = os.environ.get("EXO_ZONE", "ch-gva-2")
HOST = f"api-{ZONE}.exoscale.com"
INTIGRITI_USER = os.environ.get("INTIGRITI_USER", "gorib")
REQ_INTERVAL = 0.35

prior = f"h1-sweep-{ZONE}.jsonl"
if not os.path.exists(prior):
    raise SystemExit(f"run h1-sweep.py first — {prior} not found")

rows = [json.loads(line) for line in open(prior)]
authed = {r["path"]: (r["status"], r["bytes"]) for r in rows}


def call(path):
    req = urllib.request.Request(f"https://{HOST}{path}", method="GET")
    req.add_header("X-Intigriti-Username", INTIGRITI_USER)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(
            req, timeout=25, context=ssl.create_default_context()
        ) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:                      # noqa: BLE001 — fail loud
        return None, f"TRANSPORT-ERROR: {e!r}"


def main():
    print(f"zone={ZONE}  host={HOST}  NO Authorization header")
    print(f"{len(rows)} endpoints, ~{REQ_INTERVAL}s apart\n")
    print(f"  {'':6} {'noauth':>10}   {'authed':>10}   path")

    out, opens = f"h1-noauth-{ZONE}.jsonl", []
    with open(out, "w") as fh:
        for r in rows:
            path = r["path"]
            status, body = call(path)
            fh.write(json.dumps({
                "utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "zone": ZONE, "path": path, "status": status,
                "bytes": len(body), "body": body[:4000],
            }) + "\n")

            a_status, a_bytes = authed[path]
            if status == 200:
                mark = "OPEN"
                opens.append((path, len(body), a_status))
            elif status is None:
                mark = "ERR "
            else:
                mark = "    "

            print(f"  [{mark}] {status!s:>4} {len(body):>5}b   "
                  f"{a_status!s:>4} {a_bytes:>5}b   {path}")
            if mark in ("OPEN", "ERR "):
                print(f"          {body[:220]}".replace("\n", " "))
            time.sleep(REQ_INTERVAL)

    print(f"\nfull responses -> {out}")
    if opens:
        print("\n*** answered with NO credentials ***")
        for path, n, a in opens:
            flag = "  <-- and DENIED to our authenticated key" if a == 403 else ""
            for_ = f"    {path}  {n} bytes (authed: {a}){flag}"
            print(for_)
        print("\nA 200 here only matters if the body holds non-public data.")
        print("Zone lists, templates and instance types are public — those are calibration.")
    else:
        print("\nNothing answers unauthenticated. Hypothesis dead; the CLI's 200 has")
        print("another cause — capture the CLI's actual request headers and diff them.")


if __name__ == "__main__":
    main()
