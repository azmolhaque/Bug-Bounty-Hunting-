package com.cindrasec.mvrpprobe;

import android.os.Binder;
import android.os.Parcel;
import android.util.Log;

/**
 * যে binder-টা আমরা service-কে দিই, যাতে উত্তরটা ফেরত পাই।
 *
 * IWellbeingCallback-এর asInterface সার্ভারের দিকে proxy বানায় (queryLocalInterface
 * প্রক্রিয়ার সীমানা পেরিয়ে মেলে না), তাই আমাদের descriptor মেলানোর দরকার নেই —
 * যা আসে তার কাঁচা বাইট ছাপলেই চলে।
 *
 * আলাদা top-level ফাইল, nested নয়: build-tools 34-এর d8 JDK 21-এর তৈরি
 * anonymous class-এ ভেঙে পড়ে, আর সেই ঝুঁকি একেবারে এড়ানোই ভালো।
 */
public class CallbackBinder extends Binder {

    @Override
    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
        Log.i(MainActivity.TAG, "CALLBACK code=" + code + " size=" + data.dataSize());
        try {
            data.setDataPosition(0);
            byte[] raw = data.marshall();
            StringBuilder ascii = new StringBuilder();
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < raw.length && i < 192; i++) {
                ascii.append((raw[i] >= 32 && raw[i] < 127) ? (char) raw[i] : '.');
                hex.append(String.format("%02x ", raw[i]));
            }
            Log.i(MainActivity.TAG, "  ascii = " + ascii);
            Log.i(MainActivity.TAG, "  hex   = " + hex);
        } catch (Throwable t) {
            Log.i(MainActivity.TAG, "  dump THREW " + t.getClass().getName() + ": " + t.getMessage());
        }
        if (reply != null) reply.writeNoException();
        return true;
    }
}
