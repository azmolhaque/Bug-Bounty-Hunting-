package com.cindrasec.wallpaperpoc;

import android.graphics.Canvas;
import android.graphics.Color;
import android.os.Process;
import android.service.wallpaper.WallpaperService;
import android.util.Log;
import android.view.SurfaceHolder;

/**
 * The canary.
 *
 * It paints one flat colour and logs once when the system starts it. That log
 * line is the evidence: this process is not running because the user chose a
 * wallpaper or because this app started anything, it is running because the
 * system bound it after a permissionless app asked a privileged app to select
 * it.
 *
 * Deliberately inert otherwise — no network, no files, no reading of anything.
 */
public class CanaryWallpaperService extends WallpaperService {

    private static final String TAG = "WPPOC";

    @Override
    public Engine onCreateEngine() {
        Log.i(TAG, "canary engine created by the system: uid=" + Process.myUid()
                + " pid=" + Process.myPid());
        return new CanaryEngine();
    }

    private class CanaryEngine extends Engine {

        @Override
        public void onVisibilityChanged(boolean visible) {
            if (visible) {
                draw();
            }
        }

        @Override
        public void onSurfaceRedrawNeeded(SurfaceHolder holder) {
            draw();
        }

        private void draw() {
            SurfaceHolder holder = getSurfaceHolder();
            Canvas c = null;
            try {
                c = holder.lockCanvas();
                if (c != null) {
                    c.drawColor(Color.rgb(0x1f, 0x4f, 0x2f));
                }
            } catch (Exception e) {
                Log.w(TAG, "draw failed: " + e);
            } finally {
                if (c != null) {
                    try {
                        holder.unlockCanvasAndPost(c);
                    } catch (Exception ignored) {
                        // The surface can go away between lock and post; that is
                        // not interesting here and must not crash the canary.
                    }
                }
            }
        }
    }
}
