# mvrp-probe — permission-বিহীন probe app

## কেন

আজ রাতে বারবার একই দেয়ালে আটকেছি: **`adb shell` একটা malicious app নয়।**
shell-এর uid 2000, আর কিছু জায়গায় সে বাড়তি সুবিধা পায়। তাই shell থেকে পাওয়া
ফল দিয়ে "একটা সাধারণ app এটা পারবে" বলা যায় না।

এই app-এ **একটাও `<uses-permission>` নেই**। এটা যা পারে, যেকোনো malicious app
তাই পারে। Mobile VRP-ও good-quality রিপোর্টে APK চায়:

> *"An example application in the form of an APK, in cases that the
> vulnerability can be fully triggered by using ADB, that is also acceptable"*

এটা তিনটে জিনিস খোলে যা adb দিয়ে হয় না:

1. **exported service-এ bind** — `CredentialRecoveryService`, `OemCommandEndpointService`,
   `HealthDataSdkService`, `LocalPolicyHandlerEndpointService` …
2. **intent redirection** — shell যেহেতু non-exported component নিজেই চালু করতে
   পারে, differential-টা shell থেকে অর্থহীন। app থেকে অর্থপূর্ণ।
3. **package-name দখল** — Wellbeing-এর allowlist-এ থাকা
   `com.google.android.apps.search.assistant.surfaces.voice.devapp` ইনস্টল নেই।
   allowlist শুধু নাম মেলায় নাকি signature-ও — পরীক্ষা করতে ওই নামে আসল APK লাগে।

## বানানো

```
./build.sh
adb install -r out/mvrp-probe.apk
```

`javac -> d8 -> aapt2 -> zipalign -> apksigner`। Gradle লাগে না।

### android.jar

`aapt2 link -I` এর জন্য **আসল platform android.jar** লাগে, যাতে `resources.arsc`
আছে। Maven-এর `com.google.android:android:4.1.1.4` classes-only stub — চলবে না,
আর `build.sh` শুরুতেই সেটা ধরে ফেলে স্পষ্ট বার্তা দেয়।

Google-এর `platform-34_r03.zip` এখন 404 (ওরা extension-level নামকরণে সরেছে)।
আসল নামটা ওদের রিপোজিটরি সূচি থেকেই বের করো:

```
curl -s https://dl.google.com/android/repository/repository2-3.xml \
  | grep -oE 'platform-3[4-6][^<"]*\.zip' | sort -u
```

তারপর যেটা পেলে:

```
cd ~/tools
curl -L -O https://dl.google.com/android/repository/<যে নামটা পেলে>
unzip -q <ওই ফাইল>
find . -name android.jar
cp <পাওয়া পথ> ~/tools/android.jar
```

## চালানো

```
adb logcat -c
adb logcat -s MVRP &
```

**service-এ bind:**
```
adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action bind \
  --es pkg com.google.android.apps.restore \
  --es cls com.google.android.apps.restore.osmigration.data.credentials.importer.recovery.CredentialRecoveryService
```

**provider call:**
```
adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action call \
  --es uri content://com.google.android.apps.wellbeing.api --es method get_wind_down_status
```

**provider query:**
```
adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action query \
  --es uri content://com.google.android.apps.docs.storage.legacy/root
```

## পড়ার নিয়ম

| logcat | অর্থ |
|---|---|
| `bindService() returned false` | system চেষ্টাও করতে দেয়নি — component নেই, exported নয়, বা visibility নেই |
| `bindService() returned true` + কিছুই না | অনুরোধ গেছে, কিন্তু connect হয়নি |
| `BOUND ... descriptor = X` | **একটা permission-বিহীন app অন্য app-এর service-এ যুক্ত হয়েছে** |
| `NULL BINDING` | service-এ পৌঁছেছে, কিন্তু `onBind` null দিয়েছে |
| `THROWN SecurityException` | সীমানা ধরে আছে |
| `THROWN <অন্য কিছু>` | সীমানা ধরেনি — অন্য কারণে ব্যর্থ। এটাই আলাদা করে দেখার জিনিস |

**bind হওয়া মানেই finding নয়** (CLAUDE.md FO-8)। পরের প্রশ্ন সবসময় একটাই:
ওই binder দিয়ে attacker আসলে **কী পায়**? descriptor জানা = precondition।
AIDL-এ ডাক দিয়ে ডেটা বা ক্ষমতা বের করা = crossing।

## নিয়ম

- এই app কখনো সিদ্ধান্ত ছাপে না, শুধু যা ঘটেছে তাই ছাপে। রায় আমরা বাইরে দেবো —
  FileProvider-এর NPE-কে "পৌঁছেছে" পড়ার ভুলটা ঠিক ব্যাখ্যা-মেশানো থেকেই হয়েছিল।
- `query` সর্বোচ্চ ২০ সারি পড়ে, তারপর বাকি কত আছে তা শুধু গোনে। অন্যের ডেটা
  গণহারে টানা নিষেধ (CLAUDE.md §7), আর নিজের অ্যাকাউন্ট ছাড়া কিছু ছোঁয়া নিষেধ
  (Google VRP: *"only ever target your own accounts"*)।
