#!/usr/bin/env python3
"""H5 phase 2 — operations the GetObject matrix never touched.

Every call tries to reach BRAVO, which the key's policy explicitly denies.
The prize is CopyObject (bravo as SOURCE) and presigned-URL redemption.
"""
import os, sys, urllib.request, boto3, botocore

KEY, SECRET = os.environ.get("SOS_KEY"), os.environ.get("SOS_SECRET")
if not KEY or not SECRET:
    sys.exit("export SOS_KEY and SOS_SECRET first")

ALPHA, A_OBJ = "zt-alpha-ipvfmx1q", "alpha-canary.txt"
BRAVO, B_OBJ = "zt-bravo-ipvfmx1q", "bravo-canary.txt"
CANARY = "BRAVO-ipvfmx1q-SECRET"

def hdr(request, **kw):
    try:    request.headers.add_header("X-Intigriti-Username", "gorib")
    except Exception: request.headers["X-Intigriti-Username"] = "gorib"

c = boto3.client("s3", endpoint_url="https://sos-ch-gva-2.exo.io",
    region_name="ch-gva-2", aws_access_key_id=KEY, aws_secret_access_key=SECRET,
    config=botocore.config.Config(s3={"addressing_style": "path"},
                                  signature_version="s3v4"))
c.meta.events.register("before-send.s3.*", hdr)

def probe(label, fn):
    try:
        r = fn()
        print(f"  [{label:<26}] 200  {str(r)[:90]}")
        return r
    except botocore.exceptions.ClientError as e:
        code = e.response["ResponseMetadata"]["HTTPStatusCode"]
        print(f"  [{label:<26}] {code}  {e.response['Error'].get('Code','?')}")
    except Exception as e:
        print(f"  [{label:<26}] RIG  {type(e).__name__}: {e}")

print("THE BIG ONE — CopyObject with bravo as source:")
probe("copy bravo -> alpha", lambda: c.copy_object(
    Bucket=ALPHA, Key="zt-copied.txt",
    CopySource={"Bucket": BRAVO, "Key": B_OBJ}))
try:
    body = c.get_object(Bucket=ALPHA, Key="zt-copied.txt")["Body"].read().decode().strip()
    print(f"        -> alpha/zt-copied.txt = {body!r}")
    if CANARY in body:
        print("\n  *** BRAVO'S CONTENT REACHED AN ALLOWED BUCKET. STOP AND COLLECT EVIDENCE. ***\n")
except Exception as e:
    print(f"        -> copy did not land ({type(e).__name__})")

print("\nPresigned URL — is the policy enforced at redemption?")
url = c.generate_presigned_url("get_object",
        Params={"Bucket": BRAVO, "Key": B_OBJ}, ExpiresIn=300)
print(f"  minted: {url[:96]}...")
try:
    with urllib.request.urlopen(url, timeout=20) as r:
        body = r.read().decode("utf-8", "replace").strip()
    print(f"  [redeem presigned         ] {r.status}  {body!r}")
    if CANARY in body:
        print("\n  *** PRESIGNED URL SERVED A DENIED BUCKET. STOP AND COLLECT EVIDENCE. ***\n")
except urllib.error.HTTPError as e:
    print(f"  [redeem presigned         ] {e.code}  {e.read()[:70]}")

print("\nOther operations on bravo:")
probe("list objects",     lambda: c.list_objects_v2(Bucket=BRAVO).get("Contents"))
probe("head object",      lambda: c.head_object(Bucket=BRAVO, Key=B_OBJ)["ContentLength"])
probe("head bucket",      lambda: c.head_bucket(Bucket=BRAVO))
probe("get bucket acl",   lambda: c.get_bucket_acl(Bucket=BRAVO).get("Grants"))
probe("get bucket policy",lambda: c.get_bucket_policy(Bucket=BRAVO).get("Policy"))
probe("get location",     lambda: c.get_bucket_location(Bucket=BRAVO))
probe("get versioning",   lambda: c.get_bucket_versioning(Bucket=BRAVO).get("Status"))
probe("get tagging",      lambda: c.get_bucket_tagging(Bucket=BRAVO).get("TagSet"))
probe("get cors",         lambda: c.get_bucket_cors(Bucket=BRAVO).get("CORSRules"))
probe("list mpu",         lambda: c.list_multipart_uploads(Bucket=BRAVO).get("Uploads"))
probe("create mpu",       lambda: c.create_multipart_upload(Bucket=BRAVO, Key="zt-mpu.txt")["UploadId"])
