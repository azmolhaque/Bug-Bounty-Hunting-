package com.cindrasec.wallpaperpoc;

import android.graphics.Canvas;
import android.graphics.Color;
import android.service.wallpaper.WallpaperService;
import android.util.Log;
import android.view.SurfaceHolder;

/**
 * Paints one flat colour, and nothing else. No network, no files, no reading of
 * anything belonging to any other app.
 *
 * WallpaperService.Engine is an inner class, so a top-level subclass has to be
 * given its enclosing instance explicitly — that is what {@code s.super()} is.
 */
public class CanaryEngine extends WallpaperService.Engine {

    CanaryEngine(WallpaperService s) {
        s.super();
    }

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
            Log.w(CanaryWallpaperService.TAG, "draw failed: " + e);
        } finally {
            if (c != null) {
                try {
                    holder.unlockCanvasAndPost(c);
                } catch (Exception ignored) {
                    // The surface can go away between lock and post; that must
                    // not crash the canary.
                }
            }
        }
    }
}
