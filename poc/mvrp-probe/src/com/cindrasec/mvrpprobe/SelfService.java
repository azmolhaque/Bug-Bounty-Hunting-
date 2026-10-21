package com.cindrasec.mvrpprobe;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;

/**
 * bindtest-এর positive control — আমাদের নিজের service।
 *
 * কেন দরকার হলো: আগে control ছিল AGSA-র OneSearchSuggestService, "ওটা তো
 * connect হয়"। হতো, কিন্তু তখনকার probe `QSB` permission ঘোষণা করত। আজকের
 * permission-হীন probe-এ ওটা manifest-এর পাহারাতেই আটকে যায়, আর control
 * মিথ্যা করে "probe ভাঙা" বলে।
 *
 * অর্থাৎ control-টা probe-এর পাইপলাইন মাপছিল না, অন্য কারো নীতি মাপছিল।
 * নিজের service-এ bind করলে সেটা শুধু আমাদের যন্ত্রটাই মাপে — am start চলে
 * কিনা, onServiceConnected আসে কিনা, logcat ধরা পড়ে কিনা।
 */
public class SelfService extends Service {
    public static final String DESCRIPTOR = "com.cindrasec.mvrpprobe.SelfService";

    @Override
    public IBinder onBind(Intent intent) {
        Binder b = new Binder();
        b.attachInterface(null, DESCRIPTOR);
        return b;
    }
}
