package com.example.demo.features.network

import android.content.Context
import java.util.UUID

/**
 * Per-install identity and a strictly increasing request counter.
 * The backend rejects a counter that does not increase (replay / cloned state).
 * Stored in app-private prefs; allowBackup is off so it is not restored onto another device.
 */
object DeviceIdentity {
    private const val PREFS = "trust_identity"
    private const val KEY_INSTALL_ID = "install_id"
    private const val KEY_COUNTER = "counter"

    @Synchronized
    fun installId(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.getString(KEY_INSTALL_ID, null)?.let { return it }
        val id = "i_" + UUID.randomUUID().toString().replace("-", "")
        prefs.edit().putString(KEY_INSTALL_ID, id).commit()
        return id
    }

    @Synchronized
    fun nextCounter(context: Context): Long {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val next = prefs.getLong(KEY_COUNTER, 0L) + 1
        prefs.edit().putLong(KEY_COUNTER, next).commit()
        return next
    }
}
