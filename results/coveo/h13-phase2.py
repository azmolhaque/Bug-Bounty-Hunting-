#!/usr/bin/env python3
"""
H13 phase 2 — Coveo cross-organization sweep, QUERY-PARAMETER surface.

Phase 1 swept endpoints carrying the org as a PATH segment: 196 paths,
25 services, clean negative. When the tenant id is a path segment the router
sees it and one framework-level check can cover every route at once.

This phase sweeps the org carried as a QUERY PARAMETER, which is the weaker
shape: the check has to be written by hand in each handler, so a missed
handler is the expected failure mode rather than an unlikely one.

READ ONLY. GET only. No writes against any organization.

Each candidate is called TWICE — once with org B's id, once with an org id
that cannot exist. Identical responses mean the handler discriminates nothing
(correct). A DIFFERENCE is the signal, whether or not the status is 200,
because phase 1 established Coveo deliberately offers no existence oracle.

usage:
  export KEYA='<api key minted in ORG A>'
  export ORGB='bugbountygoribbcsq3h50g'
  python3 h13-phase2.py extract
  python3 h13-phase2.py sweep
"""
import json, os, sys, glob, time, urllib.parse, urllib.request, urllib.error

OUT = os.environ.get("OUT", os.path.expanduser("~/h13"))
CAND = os.path.join(OUT, "phase2-candidates.tsv")
FAKE = "zzznotarealorgzzz999"
ORG_NAMES = {"organizationid", "org", "orgid", "organization"}
DENY_MARKERS = ("ACCESS_DENIED", "MissingPrivileges", "AccessDenied",
                "Forbidden", "INVALID_TOKEN", "UnauthorizedOrg")


def resolve(spec, node):
    """Follow a local $ref one hop."""
    if isinstance(node, dict) and "$ref" in node:
        parts = node["$ref"].lstrip("#/").split("/")
        cur = spec
        for p in parts:
            if not isinstance(cur, dict) or p not in cur:
                return {}
            cur = cur[p]
        return cur
    return node


def extract():
    rows = []
    for f in sorted(glob.glob(os.path.join(OUT, "spec-*.json"))):
        group = os.path.basename(f)[5:-5]
        try:
            spec = json.load(open(f))
        except Exception:
            continue

        # Base URL: specs declare their own server, which is how the
        # non-platform hosts (search / analytics / api .cloud) surface.
        base = ""
        for s in spec.get("servers") or []:
            u = s.get("url", "")
            if u.startswith("http"):
                base = u.rstrip("/")
                break

        for path, item in (spec.get("paths") or {}).items():
            if "{organizationId}" in path:
                continue                      # phase 1 covered these
            if not isinstance(item, dict):
                continue
            op = item.get("get")
            if not isinstance(op, dict):
                continue                      # GET only

            params = list(item.get("parameters") or []) + list(op.get("parameters") or [])
            orgparam, required = None, []
            for p in params:
                p = resolve(spec, p)
                if not isinstance(p, dict):
                    continue
                name = str(p.get("name", ""))
                if p.get("in") != "query":
                    continue
                if name.lower() in ORG_NAMES:
                    orgparam = name
                elif p.get("required"):
                    required.append(name)
            if orgparam and "{" not in path:
                rows.append((group, base, path, orgparam, ",".join(required)))

    rows = sorted(set(rows))
    with open(CAND, "w") as fh:
        for r in rows:
            fh.write("\t".join(r) + "\n")

    print(f"== candidates (org as QUERY param, GET): {len(rows)} -> {CAND}")
    by_group, by_host = {}, {}
    for g, base, *_ in rows:
        by_group[g] = by_group.get(g, 0) + 1
        host = urllib.parse.urlparse(base).netloc or "(spec declares no server)"
        by_host[host] = by_host.get(host, 0) + 1
    print("\n-- by service:")
    for g, c in sorted(by_group.items(), key=lambda kv: -kv[1]):
        print(f"   {c:4d}  {g}")
    print("\n-- by host:")
    for h, c in sorted(by_host.items(), key=lambda kv: -kv[1]):
        print(f"   {c:4d}  {h}")


def fetch(url, key):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {key}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(400).decode("utf-8", "replace")
    except Exception as e:
        return 0, f"ERR {e}"


def denied(code, body):
    # Coveo denies with 401, 403 AND 400 (UnauthorizedOrg on the analytics API).
    return code in (400, 401, 403) and any(m in body for m in DENY_MARKERS)


def sweep():
    key = os.environ.get("KEYA")
    orgb = os.environ.get("ORGB")
    if not key or not orgb:
        sys.exit("export KEYA and ORGB first")
    if not os.path.exists(CAND):
        sys.exit("run 'extract' first")

    rows = [l.rstrip("\n").split("\t") for l in open(CAND)]
    print(f"== sweeping {len(rows)} candidates, each against ORG B and a fake org\n")
    hits = n = 0
    log = open(os.path.join(OUT, "phase2-hits.txt"), "w")

    for group, base, path, orgparam, required in rows:
        n += 1
        host = base or "https://platform.cloud.coveo.com"
        c1, b1 = fetch(f"{host}{path}?{urllib.parse.urlencode({orgparam: orgb})}", key)
        if denied(c1, b1):
            time.sleep(0.3)
            continue                              # correct denial, silent
        time.sleep(0.3)
        c2, b2 = fetch(f"{host}{path}?{urllib.parse.urlencode({orgparam: FAKE})}", key)
        time.sleep(0.3)

        # Normalise the echoed org id out before comparing, otherwise every
        # response that quotes its input looks like a difference.
        n1 = b1.replace(orgb, "<ORG>")
        n2 = b2.replace(FAKE, "<ORG>")
        same = (c1 == c2 and n1[:200] == n2[:200])
        # Not denied AND behaves differently for a real vs imaginary org.
        flag = "DIFFERS" if not same else "same-as-fake"
        if not same or c1 == 200:
            hits += 1
            msg = (f"[{flag}] {group}  {path}?{orgparam}=\n"
                   f"    ORG B [{c1}] {b1[:200]}\n"
                   f"    FAKE  [{c2}] {b2[:200]}\n")
            print(msg)
            log.write(msg)
            log.flush()
        if n % 25 == 0:
            print(f"   ...{n}/{len(rows)} checked, {hits} flagged")

    log.close()
    print(f"\n== swept {n}  flagged {hits}  -> {OUT}/phase2-hits.txt")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "extract":
        extract()
    elif cmd == "sweep":
        sweep()
    else:
        print("usage: python3 h13-phase2.py {extract|sweep}")
