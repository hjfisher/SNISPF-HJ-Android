package com.snispf.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat

class SnispfService : Service() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> {
                createNotificationChannel()
                startForeground(NOTIFICATION_ID, buildNotification())
            }
        }
        // START_STICKY: if killed, restart without intent — keeps service alive
        return START_STICKY
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
