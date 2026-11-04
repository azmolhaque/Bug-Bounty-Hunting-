# mitmproxy addon — live-extract Nest web-session auth token + bucket/object IDs.
# Run in Termux:  mitmdump -s tools/nest_mitm.py -p 8080
# Then browse home.nest.com through the proxy; watch this output.
# The token printed is YOUR OWN session — keep it private, never commit it.
import re

WANT = re.compile(r'(structure|device|shared|user|quartz|topaz|kryptonite|where|message|link|track|widget)\.[A-Za-z0-9_\-]{6,}')

def _host(flow):
    try: return flow.request.pretty_host
    except Exception: return ""

def request(flow):
    h = _host(flow)
    if "nest.com" not in h and "nestlabs" not in h:
        return
    auth = flow.request.headers.get("Authorization", "")
    if auth:
        print("\n========== NEST AUTH TOKEN (keep private) ==========")
        print(auth)
        print("====================================================\n")
    print(f"[REQ] {flow.request.method:5} {flow.request.pretty_url[:130]}")
    body = flow.request.get_text() or ""
    uid = re.search(r'/api/0\.1/user/(\w+)', flow.request.pretty_url) or re.search(r'"userid"\s*:\s*"?(\w+)"?', body)
    if uid:
        print(f"   userid: {uid.group(1)}")

def response(flow):
    h = _host(flow)
    if "nest.com" not in h and "nestlabs" not in h:
        return
    try:
        body = flow.response.get_text() or ""
    except Exception:
        body = ""
    found = sorted(set(m.group(0) for m in WANT.finditer(body[:20000])))
    if found:
        print(f"[BUCKETS in resp of {flow.request.path[:40]}]:")
        for b in found[:30]:
            print("   " + b)
    for u in set(re.findall(r'"(transport_url|czfe_url|rubyapi_url|weather_url)"\s*:\s*"([^"]+)"', body)):
        print(f"   {u[0]}: {u[1]}")
