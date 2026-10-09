# Meta Business Manager Security Audit — Operator Checklist

**এটা তোমার product।** ক্লায়েন্টের Business Manager-এ Employee/Admin হিসেবে যোগ হয়ে
এই ১৮টা চেক চালাবে, তারপর `REPORT-TEMPLATE.md` ভরে হস্তান্তর করবে।

সময়: প্রথমবার ~৯০ মিনিট। তৃতীয় ক্লায়েন্টের পরে ~৪০ মিনিট।

---

## নিয়ম — এগুলো ভাঙবে না

1. **কখনো ক্লায়েন্টের পাসওয়ার্ড বা 2FA কোড চাইবে না।** কেউ চাইলে সেটাই scam-এর সংজ্ঞা।
   তুমি স্বাভাবিক invite flow-তে যোগ হবে: Business settings → People → Add → তোমার ইমেইল।
2. **recovery-র গ্যারান্টি দেবে না।** হারানো page/business ফেরত দেওয়ার সিদ্ধান্ত Meta-র, তোমার না।
   তুমি যেটা গ্যারান্টি দিতে পারো সেটা হলো audit + hardening + recovery-readiness।
3. **কাজ শেষে নিজেকে সরিয়ে নেবে।** রিপোর্টে লিখে দেবে কবে সরেছ।
4. **ক্লায়েন্টের কোনো data কপি করবে না** — audience, customer list, ad spend। শুধু
   configuration দেখবে। রিপোর্টে কোনো PII থাকবে না।
5. এটা bug bounty না। এখানে তুমি **রক্ষক**, আক্রমণকারী না।

---

## A. Access inventory — কার হাতে চাবি আছে

| # | চেক | কোথায় | লাল পতাকা |
|---|---|---|---|
| A1 | **People** — প্রতিটি ইউজার, role, শেষ কার্যকলাপ | Business settings → Users → People | অচেনা মানুষ; প্রাক্তন কর্মী এখনো আছে; ২-এর বেশি Admin |
| A2 | **Partners** — প্রতিটি partner business, কোন asset, কোন level | Business settings → Users → Partners | যে এজেন্সির সাথে কাজ শেষ, সে এখনো আছে; partner-এর হাতে Admin |
| A3 | **System Users** — token-ধারী non-human অ্যাকাউন্ট | Business settings → Users → System users | **অচেনা system user = ঢুকে পড়া আক্রমণকারীর রেখে যাওয়া দরজা।** অধিকাংশ মালিক এই স্ক্রিনটা জীবনে খোলেনি |
| A4 | **Page roles (legacy)** — Business Manager-এর বাইরের আলাদা admin তালিকা | Page → Settings → Page roles | BM-এ নেই কিন্তু page-এ Admin — এটাই সবচেয়ে বেশি মিস হয় |
| A5 | **Connected apps** | Business settings → Accounts → Apps | অচেনা app |
| A6 | **Ad accounts + payment methods** | Business settings → Accounts → Ad accounts / Payments | অচেনা ad account; অচেনা কার্ড; খরচের হঠাৎ লাফ |

## B. Authentication — দরজার তালা

| # | চেক | কোথায় | কী হওয়া উচিত |
|---|---|---|---|
| B1 | Business-wide 2FA বাধ্যতামূলক? | Business settings → Security Center | **Required for everyone** |
| B2 | প্রতিটি Admin-এর ব্যক্তিগত অ্যাকাউন্টে 2FA | প্রতিটি admin নিজে দেখাবে | authenticator app, **SMS না** (SIM swap) |
| B3 | Admin-দের ইমেইল | — | যে ইমেইল নিয়ন্ত্রণে নেই (প্রাক্তন কর্মীর Gmail) = business হারানোর পথ |
| B4 | **দুইজন Admin, আলাদা ডিভাইস, আলাদা ইমেইল** | Business settings → People | একজন Admin = একটা ফোন হারালে পুরো business শেষ |

## C. Persistence hunt — এখানেই তুমি অন্যদের থেকে আলাদা

> যারা "page recovery" বেচে তারা A আর B দেখে থেমে যায়। ফলে তিন সপ্তাহ পরে page আবার hack হয়।
> C-অংশটাই তোমার security background, আর এটাই তোমার দাম।

| # | চেক | কোথায় | কেন |
|---|---|---|---|
| C1 | **ইমেইলে forwarding / filter rule** | Gmail → Settings → Forwarding; Filters | আক্রমণকারীর ক্লাসিক কৌশল: একটা filter বানিয়ে রাখে যাতে Facebook-এর security মেইল auto-delete হয়। এটা না সরালে recovery-র পরেও সে ফিরে আসে |
| C2 | **Active sessions** | FB → Settings → Security and Login → Where you're logged in | অচেনা device/দেশ → সব logout |
| C3 | **Apps and Websites** ব্যক্তিগত প্রোফাইলে | FB → Settings → Apps and Websites | অচেনা app = token নিয়ে বসে আছে |
| C4 | **Recovery methods** — backup email, ফোন নম্বর | FB → Settings → Personal details / Contact | আক্রমণকারীর যোগ করা নম্বর/ইমেইল থাকলে সে যেকোনো সময় reset করতে পারে |
| C5 | **Trusted contacts / Login alerts** | FB → Settings → Security and Login | alert চালু আছে কি |
| C6 | Business-এর restriction / quarantine অবস্থা | Business settings → Security Center | policy violation থাকলে recovery জটিল হয় |

## D. Blast-radius কমানো — hack হলে ক্ষতি কতটুকু

| # | কাজ | কেন |
|---|---|---|
| D1 | **Role right-sizing** — যে শুধু রিপোর্ট দেখে, সে Admin না; Analyst | একজনের অ্যাকাউন্ট গেলে পুরো business যায় না |
| D2 | Payment method আলাদা করা, দৈনন্দিন ইউজারের হাত থেকে | ad fraud-এর সীমা বাঁধা |
| D3 | **Asset inventory নথিভুক্ত করা** — Business ID, Page ID, Ad account ID, pixel ID, তৈরির তারিখ | Meta-র recovery form ঠিক এই তথ্যগুলো চায়। **এটা না থাকলে হারানো business ফেরত পাওয়ার সম্ভাবনা প্রায় শূন্য।** এই এক পাতাই তোমার audit-এর সবচেয়ে দামি deliverable |
| D4 | Break-glass plan — কে কাকে ফোন করবে, কোন অ্যাকাউন্ট backup Admin | ঘটনার দিন কেউ ভাবতে পারে না |

---

## কাজের ক্রম

```
১. invite গ্রহণ → স্ক্রিনশট নাও (তারিখ-সময় সহ) যে তুমি কোন role-এ ঢুকলে
২. A1–A6  পড়ো, কিছু বদলাবে না — শুধু লিখে রাখো
৩. C1–C6  পড়ো (ক্লায়েন্ট নিজে স্ক্রিন শেয়ার করে দেখাবে, তুমি তার অ্যাকাউন্টে ঢুকবে না)
৪. রিপোর্ট লেখো — কী পেলে, কতটা জরুরি
৫. ক্লায়েন্টের অনুমতি নিয়ে তবেই B আর D-র পরিবর্তনগুলো করো
৬. নিজেকে People থেকে সরাও → স্ক্রিনশট
৭. রিপোর্ট + inventory শিট হস্তান্তর
```

**কিছু বদলানোর আগে সবসময় অনুমতি।** লিখিত (WhatsApp/মেসেঞ্জারই যথেষ্ট)।
