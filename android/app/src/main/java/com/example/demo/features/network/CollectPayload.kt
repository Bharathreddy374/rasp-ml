package com.example.demo.features.network

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.example.demo.features.model.CollectionSource
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult
import com.example.demo.features.scanner.ScanSummary
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Builds the "rasp_collect_v2" payload for the external data collector:
 *
 * {
 *   "schema": "rasp_collect_v2", "action": "transfer",
 *   "context_keys": { "install_id", "session_id" },
 *   "device": { "manufacturer", "model", "android_release", "sdk_int", "fingerprint",
 *               "security_patch", "scan_timestamp" },
 *   "app": { "version_code" },
 *   "device_context": { "sim_country", "network_country", "timezone", "locale", "network_type",
 *                       "boot_count", "uptime_ms", "android_id_hash" },     optional, see DeviceContext
 *   "signals": { "F016": 0, "F018": ["release-keys", 0], ..., "battery_temp_c": 28.2 },
 *   "unknown": [ ... ], "failed_groups": [ ... ],
 *   "attestation": { "nonce", "chain": [leaf, ..., root] }       optional, see InstallKey
 * }
 *
 * Signals listed in [PAIR_IDS] are sent as [value, risk] (risk 0 SAFE, 1 INFO, 2 SUSPICIOUS,
 * 3 ALERT); all others as the bare value. Placeholder probes go to "unknown".
 *
 * When the keystore can make an attested key, the body also carries the server nonce and the
 * install key's certificate chain, and is signed with that key (header X-Rasp-Signature), so the
 * backend can tell a real device and app from a forged or replayed request. Without it the
 * backend marks the session "unverified".
 */
object CollectPayload {

    const val SCHEMA = "rasp_collect_v2"
    private const val MAX_TEXT = 64
    private val NUMBER = Regex("^-?\\d+(\\.\\d+)?$")

    /** Signals sent as [value, risk]; matches the agreed rasp_collect_v2 sample. */
    private val PAIR_IDS = setOf(
        "F018", "F019", "F020", "F021", "F028", "F031", "F037", "F038", "F039", "F040", "F041",
        "F043", "F045", "F046", "F047", "F050", "F051", "F053", "F055", "F057", "F058", "F059",
        "F060", "F063", "F065", "F098", "F099", "F108", "F109", "F113", "F117", "F118", "F121",
        "F124", "F125", "F126", "F127", "F128", "F129", "F130", "F131", "F132", "F137", "F138",
        "F139", "F140", "F141", "F142", "F143", "F166", "F257", "F278", "F279", "F280", "F282",
    )

    fun build(context: Context, summary: ScanSummary, action: String, attestation: JSONObject? = null): String {
        val signals = JSONObject()
        val unknown = JSONArray()
        for (s in summary.signals) {
            if (!isSent(s)) continue
            if (!s.implemented) {
                unknown.put(s.id)
                continue
            }
            val v = wireValue(s)
            signals.put(s.id, if (s.id in PAIR_IDS) JSONArray().put(v).put(s.riskLevel.ordinal) else v)
        }
        summary.signals.firstOrNull { it.id == "F268" && it.implemented }?.raw?.let { t ->
            (t as? Number)?.toDouble()?.takeIf { it.isFinite() }?.let { signals.put("battery_temp_c", it) }
        }

        return JSONObject()
            .put("schema", SCHEMA)
            .put("action", action)
            .put("context_keys", JSONObject()
                .put("install_id", DeviceIdentity.installId(context))
                .put("session_id", "session-" + UUID.randomUUID()))
            .put("device", JSONObject()
                .put("manufacturer", Build.MANUFACTURER)
                .put("model", Build.MODEL)
                .put("android_release", Build.VERSION.RELEASE)
                .put("sdk_int", Build.VERSION.SDK_INT)
                .put("fingerprint", Build.FINGERPRINT)
                .put("security_patch", Build.VERSION.SECURITY_PATCH)
                .put("scan_timestamp", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date())))
            .put("app", JSONObject().put("version_code", versionCode(context)))
            .put("device_context", DeviceContext.collect(context))
            .put("signals", signals)
            .put("unknown", unknown)
            .put("failed_groups", JSONArray(summary.failedGroups))
            .apply { attestation?.let { put("attestation", it) } }
            .toString()
    }

    /** Same signal set as the signed payload: device-observed only (no attestation rows, no server-side rows). */
    private fun isSent(s: SignalResult): Boolean =
        s.category != SignalCategory.ATTESTATION && s.source != CollectionSource.SERVER_ONLY

    private fun wireValue(s: SignalResult): Any = when (val r = s.raw) {
        is Boolean, is Int, is Long -> r
        is Float -> if (r.isFinite()) r.toDouble() else JSONObject.NULL
        is Double -> if (r.isFinite()) r else JSONObject.NULL
        is String -> r.take(MAX_TEXT)
        null -> {
            val text = s.value.trim()
            when {
                NUMBER.matches(text) -> text.toLongOrNull() ?: text.toDouble()
                text.equals("true", true) -> true
                text.equals("false", true) -> false
                else -> text.take(MAX_TEXT)
            }
        }
        else -> r.toString().take(MAX_TEXT)
    }

    @Suppress("DEPRECATION")
    private fun versionCode(context: Context): Long = try {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else info.versionCode.toLong()
    } catch (_: PackageManager.NameNotFoundException) {
        0L
    }
}
