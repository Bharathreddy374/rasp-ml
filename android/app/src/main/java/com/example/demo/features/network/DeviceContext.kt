package com.example.demo.features.network

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import android.provider.Settings
import android.telephony.TelephonyManager
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Locale
import java.util.TimeZone

/**
 * The optional "device_context" block of rasp_collect_v2: facts the backend needs to compute
 * server-side signals, none of which needs a runtime permission.
 *
 *   sim_country, network_country   ISO codes from TelephonyManager       (F289 IP vs SIM country)
 *   timezone, locale               device settings                       (F290 / F291 vs IP country)
 *   network_type                   wifi | cellular | ethernet | vpn | none   (F301, F303)
 *   boot_count, uptime_ms          Settings.Global.BOOT_COUNT, elapsedRealtime  (F310, F311)
 *   android_id_hash                SHA-256 of a fixed salt + ANDROID_ID   (F326 reinstalls)
 *
 * ANDROID_ID is never sent: only a salted hash, stable for this app on this device and user.
 * Every field is best effort; a value that cannot be read is left out.
 */
object DeviceContext {

    private const val SALT = "rasp-ml/android-id/v1:"

    @SuppressLint("HardwareIds")
    fun collect(context: Context): JSONObject {
        val out = JSONObject()
        fun put(key: String, value: () -> Any?) {
            try {
                value()?.let { v -> if (v !is String || v.isNotBlank()) out.put(key, v) }
            } catch (_: Exception) {
            }
        }
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        put("sim_country") { tm?.simCountryIso?.lowercase(Locale.US) }
        put("network_country") { tm?.networkCountryIso?.lowercase(Locale.US) }
        put("timezone") { TimeZone.getDefault().id }
        put("locale") { Locale.getDefault().toLanguageTag() }
        put("network_type") { networkType(context) }
        put("boot_count") { Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT) }
        put("uptime_ms") { SystemClock.elapsedRealtime() }
        put("android_id_hash") {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)?.let { id ->
                MessageDigest.getInstance("SHA-256").digest((SALT + id).toByteArray()).joinToString("") { "%02x".format(it) }
            }
        }
        return out
    }

    private fun networkType(context: Context): String {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return "none"
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return "none"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "other"
        }
    }
}
