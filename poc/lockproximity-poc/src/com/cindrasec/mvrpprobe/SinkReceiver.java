package com.cindrasec.mvrpprobe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

/**
 * Where anything Google Home sends to our IntentSender arrives.
 *
 * This receiver is not exported. It is reached only through the
 * PendingIntent this app created, which carries this app's identity, so
 * nothing else on the device can deliver to it.
 *
 * Values are masked before logging. The point to establish is that a
 * sensitive key arrives with a real value attached, not to print the value
 * into a screenshot that goes to a bug report — it is my own test account,
 * but a report is not the place for it either way. Short strings are shown
 * whole because wizard extras like the theme name carry nothing personal;
 * anything that looks like an address or a long identifier is masked down
 * to its first and last character and its length.
 */
public class SinkReceiver extends BroadcastReceiver {

    private static final String TAG = "MVRP";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(TAG, "SINK got a delivery, action=" + intent.getAction());

        Bundle b = intent.getExtras();
        if (b == null) {
            Log.i(TAG, "SINK no extras at all");
            return;
        }

        Log.i(TAG, "SINK " + b.keySet().size() + " extras:");
        for (String key : b.keySet()) {
            Object v;
            try {
                v = b.get(key);
            } catch (Throwable t) {
                Log.i(TAG, "  " + key + " = <unreadable: " + t.getClass().getSimpleName() + ">");
                continue;
            }
            Log.i(TAG, "  " + key + " = " + describe(v));
        }
    }

    private static String describe(Object v) {
        if (v == null) return "null";
        if (v instanceof String) {
            String s = (String) v;
            if (s.isEmpty()) return "\"\" (empty)";
            if (s.length() <= 12 && s.indexOf('@') < 0) return "\"" + s + "\"";
            return "\"" + s.charAt(0) + "…" + s.charAt(s.length() - 1)
                   + "\" (String, len=" + s.length() + ")";
        }
        if (v instanceof Bundle) {
            Bundle inner = (Bundle) v;
            return "Bundle[" + inner.keySet().size() + " keys: " + inner.keySet() + "]";
        }
        return v.getClass().getSimpleName() + "(" + v + ")";
    }
}
