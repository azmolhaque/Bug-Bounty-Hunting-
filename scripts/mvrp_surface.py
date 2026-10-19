#!/usr/bin/env python3
"""
mvrp_surface.py — decoded AndroidManifest.xml থেকে আক্রমণ-তল বের করো, ranked.

ব্যবহার:  python3 -I mvrp_surface.py <AndroidManifest.xml> [...]

CONTROL নীতি (CLAUDE.md §8, probe7-এর শিক্ষা):
  parser নিজেই নিজের ভাঙা অবস্থা ঘোষণা করে। package নাম না পেলে, বা শূন্য
  component পেলে, বা android: namespace না পেলে — FAIL LOUD, চুপচাপ "clean" না।

যা খোঁজে, payout-per-effort অনুসারে:
  P1 exported provider, permission নেই          -> file read / theft
  P1 exported provider, grantUriPermissions     -> path traversal -> arbitrary read
  P1 exported activity/service যার নাম intent/uri/file/import/export ইঙ্গিত করে
  P2 deeplink (scheme/host) -> WebView token theft-এর প্রবেশপথ
  P2 exported receiver, permission নেই          -> untrusted extras
  P3 allowBackup / debuggable / cleartext       -> একা দামি না, chain-এ লাগে
"""
import sys, os, re
import xml.etree.ElementTree as ET

AND = "http://schemas.android.com/apk/res/android"
def a(el, name, default=None):
    return el.get(f"{{{AND}}}{name}", default)

# component-এর নামে এই শব্দগুলো থাকলে সেটা ফাইল/intent হাতায় — আগে দেখো
HOT = re.compile(r"(file|path|uri|intent|proxy|redirect|deeplink|link|import|export|"
                 r"share|attach|download|upload|backup|restore|update|web|browser|"
                 r"oauth|auth|token|login|sso|account|sync)", re.I)

class Finding:
    def __init__(s, pri, kind, name, why, extra=""):
        s.pri, s.kind, s.name, s.why, s.extra = pri, kind, name, why, extra

def analyse(path):
    try:
        root = ET.parse(path).getroot()
    except Exception as e:
        print(f"!! PARSE FAIL {path}: {e}")
        return None

    pkg = root.get("package") or ""
    app = root.find("application")
    if app is None:
        print(f"!! CONTROL FAIL: <application> নেই — {path}")
        return None

    sdk = root.find("uses-sdk")
    tgt = a(sdk, "targetSdkVersion", "?") if sdk is not None else "?"

    counts, findings = {}, []
    perms_declared = {a(p, "name") for p in root.findall("permission")}

    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        els = app.findall(kind)
        counts[kind] = len(els)
        for el in els:
            name = a(el, "name") or "?"
            exp  = a(el, "exported")
            perm = a(el, "permission") or a(el, "readPermission") or a(el, "writePermission")
            ifs  = el.findall("intent-filter")

            # exported নির্ণয়: explicit true, অথবা explicit না কিন্তু intent-filter আছে
            if exp == "true":
                is_exp, how = True, "exported=true"
            elif exp is None and ifs:
                is_exp, how = True, "implicit (intent-filter, exported অনুপস্থিত)"
            else:
                continue

            hot = bool(HOT.search(name))

            if kind == "provider":
                auth  = a(el, "authorities") or "?"
                grant = a(el, "grantUriPermissions") == "true"
                paths = [a(pp, "name") or a(pp, "path") or a(pp, "pathPrefix") or "*"
                         for pp in el.findall("grant-uri-permission")]
                if not perm:
                    findings.append(Finding(
                        1, "provider", name,
                        "exported, কোনো permission নেই -> যেকোনো app query করতে পারে",
                        f"authority={auth}" + (f" grantUri={paths or 'true'}" if grant else "")))
                elif grant:
                    findings.append(Finding(
                        1, "provider", name,
                        f"permission={perm} কিন্তু grantUriPermissions -> Uri grant দিয়ে বাইপাস দেখো",
                        f"authority={auth} grantUri={paths or 'true'}"))
                else:
                    findings.append(Finding(
                        3, "provider", name, f"exported কিন্তু permission={perm}",
                        f"authority={auth}"))
                continue

            # deeplink
            schemes = set()
            for f in ifs:
                for d in f.findall("data"):
                    sch, host = a(d, "scheme"), a(d, "host")
                    if sch:
                        schemes.add(sch + ("://" + host if host else ""))

            if not perm:
                pri = 1 if hot else 2
                why = "exported, permission নেই"
                if hot: why += " + নামেই file/intent/auth হ্যান্ডলিং ইঙ্গিত"
                findings.append(Finding(pri, kind, name, why,
                                        (f"{how}; deeplink={sorted(schemes)}" if schemes else how)))
            elif perm not in perms_declared and perm and not perm.startswith("android.permission"):
                findings.append(Finding(
                    2, kind, name,
                    f"permission={perm} — এই app নিজে declare করে না (orphaned permission?)", how))
            elif schemes:
                findings.append(Finding(2, kind, name,
                                        f"exported, permission={perm}", f"deeplink={sorted(schemes)}"))

    flags = []
    for f in ("allowBackup", "debuggable", "usesCleartextTraffic"):
        if a(app, f) == "true":
            flags.append(f)
    netcfg = a(app, "networkSecurityConfig")

    total = sum(counts.values())
    # ---- CONTROL ----
    if not pkg:
        print(f"!! CONTROL FAIL: package নাম খালি — namespace ভাঙা? {path}")
        return None
    if total == 0:
        print(f"!! CONTROL FAIL: {pkg} — শূন্য component parse হলো। manifest binary?")
        return None

    print(f"\n{'='*78}\n{pkg}   targetSdk={tgt}   [{path}]")
    print("  components: " + "  ".join(f"{k}={v}" for k, v in counts.items()) +
          f"   (মোট {total})")
    if flags:   print(f"  flags: {' '.join(flags)}")
    if netcfg:  print(f"  networkSecurityConfig: {netcfg}  <- cleartext/trust-anchor দেখো")

    if not findings:
        print("  -> কোনো exported component নেই। (এটাই সত্যি হলে এই app বাদ।)")
        return pkg

    for pri in (1, 2, 3):
        rows = [f for f in findings if f.pri == pri]
        if not rows: continue
        print(f"\n  --- P{pri} ({len(rows)}) ---")
        for f in sorted(rows, key=lambda x: x.kind):
            print(f"  [{f.kind:14}] {f.name}")
            print(f"       {f.why}")
            if f.extra: print(f"       {f.extra}")
    return pkg

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    ok = 0
    for p in sys.argv[1:]:
        if not os.path.isfile(p):
            print(f"!! নেই: {p}"); continue
        if analyse(p): ok += 1
    print(f"\n{'='*78}\n{ok}/{len(sys.argv)-1} manifest সফলভাবে parse হয়েছে।")
    if ok != len(sys.argv) - 1:
        print("!! সবগুলো হয়নি — উপরের CONTROL FAIL লাইনগুলো দেখো, ফলাফল অসম্পূর্ণ।")
        sys.exit(2)
