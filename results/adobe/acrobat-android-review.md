# Adobe Acrobat Reader (Android) — static review for the Adobe program (Intigriti)

**Date:** 2026-11-03
**Researcher:** Md. Azmol Haque Rony (`cindrasec`)
**Target:** `com.adobe.reader` (Acrobat Reader), pulled from a physical device,
decompiled with apktool 2.9.3 + jadx. Tier 2 mobile asset.
**Method:** manifest triage → trace exported components / deep links to their sinks.

## Bottom line

**No finding in the two highest-value surfaces examined.** Both were traced to
their sinks and confirmed safe *with evidence*, not assumed. Recorded so the
ground isn't re-walked.

## Surface 1 — cross-app auth content provider — SAFE (signature-gated)

`<provider android:authorities="com.adobe.reader.commonid" android:exported="true"
android:grantUriPermissions="true"
android:name="…auth.crossapp.CrossAppContentProvider"/>`

An exported provider that *does* hold SSO device credentials — but the sensitive
path is caller-signature gated:

```java
// CrossAppContentProvider.queryMAM()
if (i(uri)) {                                  // path "/device_credentials"
    if (!CROSS_APP_SSO enabled) return null;
    if (j.b(getContext())) return f();         // j.b() = caller SIGNATURE check
    // "Invalid caller signature for device credentials request"
    return null;
}
```

- Credentials (`f()`) only released if `j.b(getContext())` (signature verify) passes.
- Live probe `adb shell content query --uri content://com.adobe.reader.commonid`
  → **"No result found"** (shell isn't Adobe-signed).
- `f()`'s output is additionally encrypted with a `NativeKeyProvider` key.
- Footnote: the `/common_id_key` path (`g()`) has no signature check but returns
  a native-key-encrypted blob, and the thing it would help decrypt is itself
  signature-gated → no demonstrable cross-user impact → dropped per §6.

**Verdict: intended cross-app SSO design, not a leak.**

## Surface 2 — deep-link review/durable-link handling — SAFE (ID-based)

Finding worth noting for *method*: Acrobat's link classifiers are inconsistent.
Good ones parse the host —
`AdobeReader.f4()` (`TextUtils.equals(host, …)`) and `C9287k0.G()`
(`host.equalsIgnoreCase(DOCUMENT_CLOUD_NEW_HOST_NAME)`). But the review /
send-and-track / durable classifiers validate by **substring on the whole URL**:

```java
// C9287k0.m()/H()/l() — no getHost(), just contains()
return str.contains(EUREKA_REVIEW_SERVER_API_COMMENTING_PROD) || …;
```

`String.contains()` on the raw URL is the classic deep-link-classification
weakness (`https://evil.com/?x=<host-constant>` passes). **But it was traced to
its sinks and reaches nothing dangerous:**

- The `M` dispatcher (`C9306u0`) that review links route through is a
  **First-Time-Experience / sign-in handler** — `h()`→`i()`→`e()`→ shows
  `ARFTEParentFragment` or a callback. It never parses or fetches the URL.
- The actual review-document load operates on an **`invitationURI` /
  `invitationUrn` / `invitationOrAssetId`** (an Adobe invitation identifier):
  `ARFileLoaderFragment.getDownloadLiveData(this.invitationURI)`,
  `ARShareLoaderRepository.getBootstrapInfo(invitationOrAssetId, …)` → all
  against Adobe's own DC service (`DCHTTPError`). The link's host never becomes
  a request destination.

**Verdict: the loose `contains()` is a code smell with no reachable impact.**
The boundary is never crossed → not a finding (§6).

## Network security config — not reportable

`base-config cleartextTrafficPermitted="true"`, but every sensitive Adobe domain
is explicitly `cleartext=false`, and **user-CA trust is only inside
`<debug-overrides>`** (release builds don't trust user CAs → casual MITM blocked).
The global cleartext default is a TLS-best-practice nit → explicitly out of scope.

## Not yet examined (if this app is revisited)

Exported receivers (`ARInstallReferrerBroadcastReceiver`,
`ARAppUpdateBroadcastReceiver`, `PackageInstallNotificationBroadcast`), the
`ICAppLinkReceiverActivity` (`icmobilelib://iam-action`), and WebView usage
(`addJavascriptInterface`) — none traced yet. Lower prior than the two above.

## Honest assessment

Acrobat is a mature, heavily-audited app. The two highest-value surfaces are
correctly implemented. This is what thorough mobile review mostly looks like:
confirming, with evidence, that things are safe. No submission from this pass.
