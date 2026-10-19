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
            else if ("start".equals(action))  doStart(in);
            else Log.i(TAG, "actions: call | query | bind | start");
        } catch (Throwable t) {
            // শ্রেণির নামই প্রায়ই আসল উত্তর:
            // SecurityException = সীমানা ধরেছে। অন্য কিছু = অন্য কারণে ব্যর্থ।
            Log.i(TAG, "THROWN " + t.getClass().getName() + ": " + t.getMessage());
        }

        if (keepAlive) handler.postDelayed(this, 4000);
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
