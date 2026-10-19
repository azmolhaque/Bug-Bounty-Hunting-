package com.cindrasec.mvrpprobe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.ContentResolver;
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
 * সব ফলাফল logcat-এ TAG=MVRP দিয়ে যায়:   adb logcat -s MVRP
 *
 * চালানো:
 *   am start -n com.cindrasec.mvrpprobe/.MainActivity --es action call \
 *       --es uri content://AUTH --es method NAME [--es arg VALUE]
 *   am start -n ... --es action query --es uri content://AUTH/path
 *   am start -n ... --es action bind  --es pkg PKG --es cls FQCN
 *   am start -n ... --es action start --es pkg PKG --es cls FQCN
 *
 * নকশার নিয়ম: এই app কখনো সিদ্ধান্ত ছাপে না, শুধু যা ঘটেছে তাই ছাপে।
 * "DENIED" বনাম "ফেরত এল" — সেই রায় আমরা বাইরে বসে দেবো, কারণ এখানে
 * নিজের ব্যাখ্যা ঢোকালে ঠিক সেই ভুলটা হয় যেটা FileProvider-এর NPE-তে হয়েছিল।
 */
public class MainActivity extends Activity {

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
            else usage();
        } catch (Throwable t) {
            // throwable-টা পুরো ছাপি: শ্রেণির নামই প্রায়ই আসল উত্তর
            // (SecurityException = সীমানা ধরেছে, বাকি সব = অন্য কিছু)
            Log.i(TAG, "THROWN " + t.getClass().getName() + ": " + t.getMessage());
        }

        if (keepAlive) {
            handler.postDelayed(new Runnable() {
                public void run() { Log.i(TAG, "---- end ----"); finish(); }
            }, 4000);
        } else {
            Log.i(TAG, "---- end ----");
            finish();
        }
    }

    private void usage() {
        Log.i(TAG, "actions: call | query | bind | start");
    }

    // ---------- ContentProvider.call() ----------
    private void doCall(Intent in) {
        String uri    = req(in, "uri");
        String method = req(in, "method");
        String arg    = in.getStringExtra("arg");
        Log.i(TAG, "CALL uri=" + uri + " method=" + method + " arg=" + arg);

        Bundle extras = new Bundle();
        String ek = in.getStringExtra("extraKey");
        String ev = in.getStringExtra("extraVal");
        if (ek != null) extras.putString(ek, ev);

        Bundle out = getContentResolver().call(Uri.parse(uri), method, arg, extras);
        if (out == null) { Log.i(TAG, "RESULT null"); return; }
        Log.i(TAG, "RESULT Bundle keys=" + out.keySet());
        for (String k : out.keySet()) {
            Object v = out.get(k);
            Log.i(TAG, "  " + k + " = " + render(v));
        }
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
            for (String n : names) hdr.append(n).append(" | ");
            Log.i(TAG, "  cols: " + hdr);
            int row = 0;
            while (c.moveToNext() && row < 20) {        // ২০ সারির বেশি নয়:
                StringBuilder sb = new StringBuilder(); // অন্যের ডেটা গণহারে টানা
                for (int i = 0; i < c.getColumnCount(); i++) {   // নিষেধ (CLAUDE.md §7)
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
        final String pkg = req(in, "pkg");
        final String cls = req(in, "cls");
        Log.i(TAG, "BIND " + pkg + "/" + cls);

        Intent svc = new Intent();
        svc.setComponent(new ComponentName(pkg, cls));
        String act = in.getStringExtra("svcAction");
        if (act != null) svc.setAction(act);

        ServiceConnection conn = new ServiceConnection() {
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
                        + "  (service এ পৌঁছেছে, কিন্তু onBind null দিয়েছে)");
            }
        };

        boolean ok = bindService(svc, conn, Context.BIND_AUTO_CREATE);
        // bindService false = system এমনকি চেষ্টাও করতে দেয়নি (component নেই,
        // exported নয়, বা visibility নেই)। true = অনুরোধ গেছে; আসল উত্তর callback-এ।
        Log.i(TAG, "bindService() returned " + ok);
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
            for (byte x : b) sb.append((x >= 32 && x < 127) ? (char) x : '.');
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
