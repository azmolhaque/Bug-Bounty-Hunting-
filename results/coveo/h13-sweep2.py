#!/usr/bin/env python3
"""
H13 re-sweep — phase 1, redone with a PER-ENDPOINT positive control.

Why this exists
---------------
The original phase 1 sweep used an API key holding only ORGANIZATION:VIEW. When it
got 403 against org B on /sources, /fields, /catalogs and the rest, that key would
have got 403 against org A too — it had no privilege for those domains at all.

The only positive control I ran was on /rest/organizations/{id}. So most of those
196 "correct denials" were PRIVILEGE denials, not ORG-SCOPE denials, and recording
them as evidence that org scoping holds was wrong.

This version calls org A AND org B for every path, with a 137-privilege key, so the
control is per-endpoint:

  A=200, B=200           -> CROSS-ORG READ. The finding.
  A=200, B denied        -> genuinely enforced. Counts as evidence.
  A != 200               -> no privilege / not GETable. Proves nothing, DISCARDED.

The third bucket is the point. Those were previously being counted as wins.

READ ONLY. GET only.

usage:
  export KEYADM='<137-privilege key minted in ORG A>'
  export ORGA='...'  ORGB='...'
  python3 h13-sweep2.py
"""
import os, sys, time, json, urllib.request, urllib.error

OUT = os.environ.get("OUT", os.path.expanduser("~/h13"))
PATHS = os.path.join(OUT, "paths.txt")
DENY = ("ACCESS_DENIED", "MissingPrivileges", "AccessDenied", "Forbidden",
        "UnauthorizedOrg", "DOES_NOT_EXIST", "INVALID_TOKEN")


def get(url, key):
    r = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {key}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=25) as x:
            return x.status, x.read(600).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(600).decode("utf-8", "replace")
    except Exception as e:
        return 0, f"ERR {e}"


def main():
    key = os.environ.get("KEYADM")
    orga, orgb = os.environ.get("ORGA"), os.environ.get("ORGB")
    if not (key and orga and orgb):
        sys.exit("export KEYADM, ORGA and ORGB first")
    rows = [l.rstrip("\n").split("\t") for l in open(PATHS) if "\t" in l]

    base = "https://platform.cloud.coveo.com"
    findings, enforced, discarded = [], 0, 0
    log = open(os.path.join(OUT, "resweep.txt"), "w")

    for i, (group, path) in enumerate(rows, 1):
        ca, ba = get(base + path.replace("{organizationId}", orga), key)
        time.sleep(0.3)
        if ca != 200:
            discarded += 1                      # no access in our OWN org: proves nothing
            time.sleep(0.05)
            continue
        cb, bb = get(base + path.replace("{organizationId}", orgb), key)
        time.sleep(0.3)

        if cb == 200:
            msg = (f"*** CROSS-ORG READ  {group}  {path}\n"
                   f"    ORG A [{ca}] {ba[:200]}\n"
                   f"    ORG B [{cb}] {bb[:200]}\n")
            print(msg); log.write(msg); log.flush()
            findings.append((group, path))
        else:
            enforced += 1
            marker = "denied" if any(m in bb for m in DENY) else f"other({cb})"
            log.write(f"[ok:{marker}] {group} {path}\n")
        if i % 25 == 0:
            print(f"   ...{i}/{len(rows)}  enforced={enforced} discarded={discarded} findings={len(findings)}")

    log.close()
    print(f"\n=== re-sweep complete over {len(rows)} paths")
    print(f"  ENFORCED  (200 in org A, denied in org B) : {enforced}   <- real evidence")
    print(f"  DISCARDED (no access in org A either)     : {discarded}  <- proves nothing")
    print(f"  CROSS-ORG READS                           : {len(findings)}")
    for g, p in findings:
        print(f"     {g}  {p}")
    print(f"\n  detail -> {OUT}/resweep.txt")


if __name__ == "__main__":
    main()
