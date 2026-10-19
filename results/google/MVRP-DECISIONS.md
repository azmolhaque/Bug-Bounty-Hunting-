
## 2026-10-19 — Mobile VRP, Android 15 / SDK 35, moto g stylus 5G 2024

| # | surface | verdict | why |
|---|---|---|---|
| S24 | `fitbit-stage.com` in Fitbit's production intent-filter | DROP | MarkMonitor registrar, googledomains NS. Google's own domain, not claimable. 10s to kill. |
| S25 | safetyhub `DEVICE_SUPERVISION` orphaned permission | DROP | Guard permission genuinely undeclared on device — but the component is `android:enabled="false"` and names the abstract `android.content.BroadcastReceiver`. A disabled stub; no app can enable another app's component. Tool gap found and fixed (`mvrp_surface.py` now skips `enabled=false`). |
| S26 | tycho `CarrierServicesHvContentProvider`, guard `...ACCESS_DATA` declared with no `protectionLevel` (= `normal`, auto-granted) | DROP | Real weak-guard config, but Google Fi is unavailable in BD, the app ships `enabled=2` (disabled) and `pm enable` is refused to shell. Sentinel and target returned the SAME result (`Could not find provider`), so the run proves nothing about the guard. Even enabled, a non-Fi account yields an empty provider — that is a precondition, not a crossing. Mobile VRP pays on actual, not potential, impact. |

**Live lead:** `fitbit://webview` → `com.fitbit.webview.deeplink.WebviewGateway` →
`com.google.apps.tiktok.nav.gateway.GatewayActivity`. All 31 Fitbit deeplink gateways
are aliases onto that one activity, so the question is Fitbit's own routing config:
does the WebView destination take its URL from the deeplink, and is the host validated?

**Structural note:** exported providers are essentially closed across these apps
(Fitbit: 6 providers, 0 flagged). The surface has moved to deeplinks.

| S27 | Fitbit `fitbit://webview?authenticated=&url=` → `WebFrameActivity` | DROP | Correctly built. `UrlValidator.isTrusted` is an exact `Set.contains(host)` plus an https check — no `endsWith`/`contains` bypass. `WebFrameActivity:221` applies it precisely when `AUTHENTICATED` is set, and `slw` registers the `WebViewJsInterface` bridge *and* constructs `DelegateTokenGenerator` only on that same flag. So: unauthenticated → arbitrary URL but no bridge and no credentials; authenticated → bridge and credentials but Fitbit hosts only. Credentials, bridge and validation are all gated on one flag, consistently. |

**Strategic update after S27.** Fitbit's webview stack is well maintained — the
obvious deeplink/WebView classes are handled correctly. Depth-first on a flagship
app is unlikely to pay. Switch to breadth: only 16 of the 50 pulled in-scope
packages have been swept. The remaining 34 include the low-attention ones
(labs.whisk, labs.language.tailwind, scone, cbrsnetworkmonitor, carrier.carrierwifi,
mapslite, photosgo, cultural), which is where a first-party app is likelier to
have an unguarded component than Gmail or Fitbit.
