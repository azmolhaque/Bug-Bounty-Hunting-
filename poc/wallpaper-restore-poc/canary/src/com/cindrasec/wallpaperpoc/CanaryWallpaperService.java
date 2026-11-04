package com.cindrasec.wallpaperpoc;

import android.os.Process;
import android.service.wallpaper.WallpaperService;
import android.util.Log;

/**
 * The canary.
 *
 * Its only job is to log once when the system starts it. That line is the
 * evidence for the second half of the claim: this process is not running
 * because the user picked a wallpaper and not because this app started
 * anything, it is running because the system bound it after a permissionless
 * app asked a privileged app to select it.
 *
 * The engine lives in its own top-level class rather than as a nested one.
 * d8 8.2.2-dev crashes with an internal NullPointerException on a nested
 * subclass of WallpaperService.Engine here, and the finding must not depend on
 * working around a toolchain bug.
 */
public class CanaryWallpaperService extends WallpaperService {

    static final String TAG = "WPPOC";

    @Override
    public Engine onCreateEngine() {
        Log.i(TAG, "canary engine created by the system: uid=" + Process.myUid()
                + " pid=" + Process.myPid());
        return new CanaryEngine(this);
    }
}
