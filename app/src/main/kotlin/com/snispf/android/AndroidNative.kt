package com.snispf.android

import android.content.Context
import android.util.Log

object AndroidNative {
    private val TAG = "AndroidNative"
    private var loaded = false

    fun init(context: Context): Boolean {
        if (loaded) return true
        try {
            // Load the native library (androidnative.so) which provides
            // the JNI bridge for android.system.Os.setsocknetwork
            System.loadLibrary("androidnative")
            loaded = true
            Log.d(TAG, "Android native library (androidnative.so) loaded successfully")
            return true
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load androidnative library: ${e.message}", e)
            return false
        }
    }

    fun isLoaded(): Boolean = loaded
}