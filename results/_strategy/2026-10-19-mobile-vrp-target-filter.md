# Mobile VRP — কেন এখানে, আর কোন app-এ

তারিখ: 2026-10-19 · scope পড়া: `google/bughunters@ab9de14`

---

## ১. চারটা দেয়াল — Mobile VRP চারটাই ভাঙে

গত ২৩টা বন্ধ surface-এর প্রতিটা এই চারটার কোনো একটায় মরেছে। এইবার মিলিয়ে দেখি:

| দেয়াল | web surface-এ | Mobile VRP-তে |
|---|---|---|
| **identity-gated** — দ্বিতীয় শিকার লাগে | Shopify, Marriott এখানে মরেছে | **ভাঙে।** আক্রমণকারী = একই ডিভাইসে বসা একটা malicious app। দুটো app-ই তুমি নিজে install করবে। কারও অ্যাকাউন্ট লাগে না |
| **Boq / কোনো REST object id নেই** | Google-এর সব first-party web app | **ভাঙে।** এটা local IPC — exported activity, provider, receiver, deeplink। সব manifest-এ লেখা, আর manifest APK-এর ভেতরেই |
| **users একে অন্যের সাথে share করে না** | Google-এর অধিকাংশ surface | **প্রযোজ্যই না।** সীমানাটা tenant না, **app sandbox**। প্রতিটা app-এর আলাদা uid — সেটাই crossing |
| **অনুমান-অযোগ্য identifier লাগে** | **G-F002 এখানেই মরেছে** (২০৫ অক্ষরের token) | **ভাঙে, চূড়ান্তভাবে।** অনুমান করার মতো কিছুই নেই। manifest পাবলিক, তুমি শুধু একটা Intent পাঠাও |

> এটাই প্রথম Google surface যেটা চারটাই পার হয়। কথার কথা না — গঠনগতভাবে সত্যি।

আর program নিজেই লিখে রেখেছে:

> *"in cases that the vulnerability can be fully triggered by using ADB,
> that is also acceptable"*

মানে PoC-র জন্য malicious APK লেখাও বাধ্যতামূলক না — `adb shell` থেকেই চলে।

---

## ২. টাকার অঙ্ক — বাস্তব পরিস্থিতি

আমাদের বাস্তব scenario হলো **কলাম ৩: "User must install malicious app"**।
কলাম ১ (remote, no interaction) পেশাদার দলের এলাকা, ওদিকে তাকাবো না।

| | ACE | Theft of Sensitive Data | Other (intent redirect, path traversal, PendingIntent) |
|---|---|---|---|
| **Tier 1** (GMS, AGSA, Gmail, Cloud) | $15,000 | $9,000 | $4,500 |
| **Tier 2** (user data / Google services ছোঁয়) | **$7,500** | **$4,500** | **$2,250** |
| Tier 3 (user data ছোঁয় না) | $2,250 | $1,350 | $675 |

**গুণক:** root cause analysis + proposed patch দিলে **×1.5**।
root cause লেখা তোমার শক্তি — ২৩টা surface-এ তুমি ঠিক এটাই করেছ।
তাই Tier 2 theft = $4,500 × 1.5 = **$6,750**, আর novel হলে +$1,000।

---

## ৩. app ছাঁকনি — ছয়টা মাপকাঠি, সস্তাটা আগে

| # | প্রশ্ন | কেন |
|---|---|---|
| 1 | in-scope developer-এর কি? | ৯টা developer। বাইরে হলে Play SRP, এই program না |
| 2 | **High Impact Data ছোঁয়?** (credential, auth token, govt ID, **medical**, payment) | এটাই theft category-র ছাদ ঠিক করে |
| 3 | Tier কত? | Tier 3-এ ৬৭৫ ডলার, Tier 2-এ ৪,৫০০। একই পরিশ্রম |
| 4 | **ভিড় কত?** install সংখ্যা ≈ কতজন hunter দেখছে | Tier 1 মানে ফুলটাইম পেশাদাররা আছে |
| 5 | exported component কয়টা? | surface যত বড়, সুযোগ তত |
| 6 | **আমার আগের জ্ঞান আছে?** | সপ্তাহখানেক context বিনামূল্যে পাওয়া |

### ফলাফল — এই ক্রমে

**১ম — Fitbit (`com.fitbit.FitbitMobile`)**
- মাপকাঠি ২: **medical data**, rules-এ আক্ষরিক লেখা High Impact — ছাদ সর্বোচ্চ
- মাপকাঠি ৬: **তুমি Fitbit-এর OAuth, client id, token introspection আচরণ ইতিমধ্যে ম্যাপ করেছ** (G-F001/F002)। app ওই একই endpoint-এ কথা বলে। app-এ token কোথায় রাখে, কে পড়তে পারে — এই প্রশ্নটা তোমার কাছে সস্তা
- Tier 2। theft @ scenario 3 = $4,500 (×1.5 = $6,750)
- আলাদা developer (Fitbit LLC), core Google app-এর তুলনায় কম ভিড়

**২য় — Nest / Google Home** (`com.nest.android`, `com.google.android.apps.chromecast.app`)
ক্যামেরা, ঘরের ভিডিও, ডিভাইস token। sensitivity সর্বোচ্চ।

**৩য় — "Research at Google" + "Google Samples"-এর app গুলো**
কম install, প্রায় কেউ দেখে না। সম্ভবত Tier 3 ($675–$1,350) — কিন্তু **পাইপলাইনটা শেখার
সবচেয়ে সস্তা জায়গা**, আর প্রথম valid report-টা এখান থেকেই আসা বেশি সম্ভব।

**৪র্থ — Waze** — message আর contact আছে। (location একা qualify করে না, rules-এ স্পষ্ট।)

**এখন এড়িয়ে চলো — Tier 1:** GMS, AGSA, Gmail, Cloud Console।
টাকা বেশি, কিন্তু ওখানে ফুলটাইম দল বসে আছে। duplicate নিয়মে প্রথম রিপোর্টই পায়।

---

## ৪. probe লেখার আগে kill list (`config/scope-mobile-vrp.yaml`)

G-F002 মরেছিল কারণ আমি scope ফাইল লিখে সেটা নিজের finding-এ চালাইনি।
এইবার প্রতিটা hypothesis এখানে ফেলে তবে কমান্ড:

- Hardcoded API key → বাদ (**G-F001 এই নিয়মেই মরত**)
- root লাগে → বাদ (frida দিয়ে *খুঁজতে* পারো, কিন্তু **PoC unrooted-এ চলতে হবে**)
- Strandhogg / Tapjacking variant → বাদ
- external storage-এর non-sensitive media → বাদ
- **অন্য app-এর non-sensitive internal file** → বাদ ← provider খুলে গেলেই উৎসব কোরো না,
  আগে দেখো ভেতরে কী
- location একা → বাদ
- latest OS-এ চলে না → বাদ
- third-party app / AOSP / Chrome → অন্য program

**impact নিয়ে program-এর নিজের লাইন:**
> *"Impact is judged based on the ACTUAL reported impact, and not on a POTENTIAL
> impact... arbitrary file write... if you do not demonstrate this in your report,
> the reward amount will not reflect this."*

এটাই CLAUDE.md FO-8/9/11, Google-এর ভাষায়। **arbitrary file write পেলে থেমো না** —
`.so` overwrite করে ACE দেখাও। ওখানেই $2,250 থেকে $7,500।
