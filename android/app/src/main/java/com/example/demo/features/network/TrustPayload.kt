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
import java.security.MessageDigest

/**
 * Builds the schema-2 payload: compact, typed, device-observed signals only.
 *
 * {
 *   "schema": 2, "install_id", "action", "nonce", "counter", "ts", "scan_ms",
 *   "app":    { "package", "version_code", "cert_sha256": [hex] },
 *   "device": { "manufacturer", "brand", "model", "device", "hardware", "board",
 *               "release", "sdk_int", "security_patch", "fingerprint" },
 *   "signals": { "F016": [value, risk], ... },   risk: 0 SAFE, 1 INFO, 2 SUSPICIOUS, 3 ALERT
 *   "unknown": [ "F025", ... ],                   placeholder probes: unknown, not clean
 *   "failed_groups": [ ... ]
 * }
 *
 * Not sent: attestation rows (the certificate chain is sent instead and verified by the
 * backend) and server-side rows F286 - F350 / F363 - F365 (the backend computes those).
 * Names, categories and descriptions are not sent: the backend has the catalogue.
 */
object TrustPayload {

    const val SCHEMA = 2
    private const val MAX_TEXT = 64
    private val NUMBER = Regex("^-?\\d+(\\.\\d+)?$")

    fun build(
        context: Context,
        summary: ScanSummary,
        installId: String,
        action: String,
        nonce: String,
        counter: Long,
    ): String {
        val signals = JSONObject()
        val unknown = JSONArray()
        for (s in summary.signals) {
            if (!isSent(s)) continue
            if (!s.implemented) {
                unknown.put(s.id)
                continue
            }
            signals.put(s.id, JSONArray().put(wireValue(s)).put(s.riskLevel.ordinal))
        }

        return JSONObject()
            .put("schema", SCHEMA)
            .put("install_id", installId)
            .put("action", action)
            .put("nonce", nonce)
            .put("counter", counter)
            .put("ts", System.currentTimeMillis())
            .put("scan_ms", summary.scanDurationMs)
            .put("app", appInfo(context))
            .put("device", deviceInfo())
            .put("signals", signals)
            .put("unknown", unknown)
            .put("failed_groups", JSONArray(summary.failedGroups))
            .toString()
    }

    private fun isSent(s: SignalResult): Boolean =
        s.category != SignalCategory.ATTESTATION && s.source != CollectionSource.SERVER_ONLY

    /** Typed value: the probe's raw value when it set one, else a number or short text from the UI string. */
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

    private fun deviceInfo(): JSONObject = JSONObject()
        .put("manufacturer", Build.MANUFACTURER)
        .put("brand", Build.BRAND)
        .put("model", Build.MODEL)
        .put("device", Build.DEVICE)
        .put("hardware", Build.HARDWARE)
        .put("board", Build.BOARD)
        .put("release", Build.VERSION.RELEASE)
        .put("sdk_int", Build.VERSION.SDK_INT)
        .put("security_patch", Build.VERSION.SECURITY_PATCH)
        .put("fingerprint", Build.FINGERPRINT)

    @Suppress("DEPRECATION")
    private fun appInfo(context: Context): JSONObject {
        val pm = context.packageManager
        val pkg = context.packageName
        val digests = JSONArray()
        var versionCode = 0L
        try {
            val sigs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                versionCode = info.longVersionCode
                info.signingInfo?.let {
                    if (it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory
                } ?: emptyArray()
            } else {
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
                versionCode = info.versionCode.toLong()
                info.signatures ?: emptyArray()
            }
            val md = MessageDigest.getInstance("SHA-256")
            for (sig in sigs) {
                digests.put(md.digest(sig.toByteArray()).joinToString("") { "%02x".format(it) })
            }
        } catch (_: Exception) {
        }
        return JSONObject()
            .put("package", pkg)
            .put("version_code", versionCode)
            .put("cert_sha256", digests)
    }
}
