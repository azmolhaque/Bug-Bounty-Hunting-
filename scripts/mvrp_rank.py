#!/usr/bin/env python3
"""
mvrp_rank.py — decode করা সব app জুড়ে একটা ক্রমতালিকা। কোনটা আগে খুলবে, সেটা বলে দেয়।

ব্যবহার:  python3 -I mvrp_rank.py ~/mvrp/decoded

৫০টা আলাদা রিপোর্ট চোখে পড়া যায় না। এটা প্রতিটা app-কে একটা স্কোর দেয়
(payout-per-effort অনুসারে), তারপর উপরের দিকেরগুলোর P1 component দেখায়।

স্কোর কেন এভাবে:
  provider, permission নেই          12  সরাসরি ডেটা, ঘুরপথ নেই। সবচেয়ে দামি।
  provider, grantUriPermissions      8  path traversal-এর প্রবেশপথ
  exported service, permission নেই   4  bound হলে IPC surface, প্রায়ই অরক্ষিত
  hot-named activity (file/intent/   3  intent redirection / arbitrary file
    uri/auth/import/export...)
  exported receiver, permission নেই  2  untrusted extras
  অন্য exported, permission নেই      1

CONTROL: কোনো manifest parse না হলে বা শূন্য app পেলে exit 2। চুপচাপ খালি
তালিকা দেখিয়ে "কিছু নেই" বলবে না।
"""
import sys, os, re
import xml.etree.ElementTree as ET

AND = "http://schemas.android.com/apk/res/android"
def a(el, n, d=None): return el.get(f"{{{AND}}}{n}", d)

HOT = re.compile(r"(file|path|uri|intent|proxy|redirect|deeplink|import|export|"
                 r"share|attach|download|upload|backup|restore|update|web|browser|"
                 r"oauth|auth|token|login|sso|account|sync)", re.I)

# ভিড় বেশি — একই পরিশ্রমে duplicate-এর ঝুঁকি বেশি
TIER1 = {"com.google.android.gms", "com.google.android.googlequicksearchbox",
         "com.google.android.apps.cloudconsole", "com.google.android.gm"}

def scan(path):
    try:
        root = ET.parse(path).getroot()
    except Exception as e:
        return None, f"PARSE FAIL: {e}"
    pkg = root.get("package") or ""
    app = root.find("application")
    if app is None or not pkg:
        return None, "no <application> or no package"

    score, rows, total = 0, [], 0
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in app.findall(kind):
            total += 1
            if a(el, "enabled") == "false":
                continue
            name = a(el, "name") or "?"
            exp  = a(el, "exported")
            ifs  = el.findall("intent-filter")
            if exp != "true" and not (exp is None and ifs):
                continue
            perm = a(el, "permission") or a(el, "readPermission") or a(el, "writePermission")
            grant = a(el, "grantUriPermissions") == "true"

            if kind == "provider":
                auth = a(el, "authorities") or "?"
                if not perm:
                    score += 12; rows.append((12, kind, name, f"no permission | {auth}"))
                elif grant:
                    score += 8;  rows.append((8, kind, name, f"grantUri, perm={perm} | {auth}"))
                continue
            if perm:
                continue
            if kind == "service":
                score += 4; rows.append((4, kind, name, "exported service, no permission"))
            elif HOT.search(name):
                score += 3; rows.append((3, kind, name, "hot name, no permission"))
            elif kind == "receiver":
                score += 2; rows.append((2, kind, name, "exported receiver, no permission"))
            else:
                score += 1; rows.append((1, kind, name, "exported, no permission"))

    if total == 0:
        return None, "zero components parsed"
    return (pkg, score, sorted(rows, reverse=True), total), None

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/mvrp/decoded")
    apps, bad = [], []
    for d in sorted(os.listdir(base)):
        m = os.path.join(base, d, "resources", "AndroidManifest.xml")
        if not os.path.isfile(m):
            continue
        res, err = scan(m)
        (apps.append(res) if res else bad.append((d, err)))

    if not apps:
        print("!! CONTROL FAIL: একটাও manifest পড়া গেল না।"); sys.exit(2)

    apps.sort(key=lambda t: -t[1])
    print(f"{'score':>6}  {'components':>10}  package")
    print("-" * 78)
    for pkg, score, rows, total in apps:
        mark = "  [TIER1 - ভিড়]" if pkg in TIER1 else ""
        print(f"{score:>6}  {total:>10}  {pkg}{mark}")

    print("\n" + "=" * 78)
    print("শীর্ষ app-গুলোর P1 component (provider আগে)\n")
    shown = 0
    for pkg, score, rows, total in apps:
        if pkg in TIER1 or score == 0:
            continue
        top = [r for r in rows if r[0] >= 3]
        if not top:
            continue
        print(f"--- {pkg}  (score {score}) ---")
        for w, kind, name, why in top[:8]:
            print(f"  {w:>2} [{kind:14}] {name}")
            print(f"       {why}")
        print()
        shown += 1
        if shown >= 12:
            print("... (বাকিগুলো উপরের তালিকায়)")
            break

    if bad:
        print("\n!! পড়া যায়নি:")
        for d, err in bad:
            print(f"   {d}: {err}")
        print("!! ফলাফল অসম্পূর্ণ — এগুলো হাতে দেখো।")
        sys.exit(2)
