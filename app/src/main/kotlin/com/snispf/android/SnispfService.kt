package com.snispf.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

class SnispfService : Service() {

    // Termux holds a CPU wake lock by default, which is why the backend
    // behaves there: no Doze freeze/unfreeze cycles of the proxy process.
    // Doze freezing a backend with live sockets is exactly what causes
    // connection blackholes, retry storms (CPU spikes) and battery drain —
    // and Android's phantom-process management then kills the backend.
    // Hold the same locks while the proxy is running.
    private var cpuWakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    private fun acquireLocks() {
        if (cpuWakeLock == null) {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            cpuWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "snispf:backend").apply {
                setReferenceCounted(false)
                acquire()
            }
        }
        if (wifiLock == null) {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "snispf:wifi").apply {
                setReferenceCounted(false)
                acquire()
            }
        }
    }

    private fun releaseLocks() {
        try { cpuWakeLock?.release() } catch (_: Exception) {}
        cpuWakeLock = null
        try { wifiLock?.release() } catch (_: Exception) {}
        wifiLock = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                // Stop the actual backend process first — the old code only
                // stopped the foreground service and left the Go backend
                // running as an orphan (orphan churn is a battery drain and
                // keeps port 40443 bound so the next start fails).
                GoBridgeSingleton.existing?.stop()
                releaseLocks()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> {
                createNotificationChannel()
                startForeground(NOTIFICATION_ID, buildNotification())
                acquireLocks()
            }
        }
        // START_STICKY: if killed, restart without intent — keeps service alive
        return START_STICKY
    }

    override fun onDestroy() {
        releaseLocks()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onTaskRemoved(rootIntent: Intent?) {
        // User swiped app from recents — keep service running
        super.onTaskRemoved(rootIntent)
    }

    private fun buildNotification(): Notification {
        // Tap notification → open app
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE
        )

        // Stop action inside notification
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, SnispfService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SNISPF-HJ")
            .setContentText("Proxy is running")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setOngoing(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_media_pause, "Stop", stopIntent)
            .build()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "SNISPF Proxy",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Keeps proxy running in background"
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(channel)
    }

    companion object {
        const val CHANNEL_ID      = "snispf_channel"
        const val NOTIFICATION_ID = 1
        const val ACTION_STOP     = "com.snispf.android.STOP"

        fun start(context: Context) {
            val intent = Intent(context, SnispfService::class.java)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, SnispfService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
