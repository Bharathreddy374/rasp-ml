package com.example.demo.features.network

import android.content.Context
import android.util.Base64
import com.example.demo.features.attestation.AttestationSession
import com.example.demo.features.scanner.FeatureCatalogueScanner
import com.example.demo.features.scanner.ScanSummary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPOutputStream

data class Reason(val code: String, val tier: String, val text: String)

data class ModelResult(
    val level: Int,
    val label: String,
    val outcome: String,
    val rulesLevel: Int,
    val mlLevel: Int?,
    val reasons: List<Reason>,
    val decisionId: String,
    /** Backend's verdict on the hardware attestation chain (null if none was sent). */
    val attestation: JSONObject?,
    /** Server-side signals the backend computed for this request (F286 - F350 subset). */
    val serverSignals: JSONObject?,
    val coverage: JSONObject?,
    val serverMs: Double,
)

data class ApiResponse(
    val isSuccess: Boolean,
    val statusCode: Int,
    val responseBody: String,
    val result: ModelResult? = null,
    val errorMessage: String? = null,
    val durationMs: Long = 0L,
    /** Payload JSON size before and after gzip, to show what is actually on the wire. */
    val payloadBytes: Int = 0,
    val wireBytes: Int = 0,
    /** False when the device could not create an attested key; the request then has reduced assurance. */
    val attested: Boolean = false,
)

/**
 * Signed assessment flow (backend /v1/nonce then /v2/assess):
 *  1. get a one-time nonce bound to this install and action
 *  2. create a hardware-attested key with that nonce as the challenge
 *  3. scan, build the compact schema-2 payload, sign it with the attested key
 *  4. gzip and POST payload + signature + certificate chain
 */
object BackendApiClient {

    private const val PREFS_NAME = "telemetry_backend_prefs"
    private const val KEY_API_URL = "backend_base_url"
    private const val LEGACY_KEY_API_URL = "last_backend_url"

    const val DEFAULT_BASE_URL = "http://192.168.1.5:8000"
    const val EMULATOR_BASE_URL = "http://10.0.2.2:8000"

    fun getSavedBaseUrl(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.getString(KEY_API_URL, null)?.let { return it }
        // Older builds saved the full /v1/features URL; keep the host the user typed.
        val legacy = prefs.getString(LEGACY_KEY_API_URL, null) ?: return DEFAULT_BASE_URL
        return normalizeBaseUrl(legacy)
    }

    fun saveBaseUrl(context: Context, url: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putString(KEY_API_URL, normalizeBaseUrl(url)).apply()
    }

    private const val KEY_COLLECTOR_URL = "collector_url"

    /** Full URL of the external collector that receives rasp_collect_v2 payloads. */
    fun getCollectorUrl(context: Context): String =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getString(KEY_COLLECTOR_URL, "") ?: ""

    fun saveCollectorUrl(context: Context, url: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putString(KEY_COLLECTOR_URL, url.trim()).apply()
    }

    /**
     * Scans and POSTs a rasp_collect_v2 payload (plain JSON, unsigned) to [url].
     * Returns the fresh scan together with the collector's answer.
     */
    suspend fun sendCollect(
        context: Context,
        url: String,
        action: String = "transfer",
    ): Pair<ScanSummary?, ApiResponse> = withContext(Dispatchers.IO) {
        val t0 = System.currentTimeMillis()
        try {
            val summary = FeatureCatalogueScanner.scanAll(context)
            val body = CollectPayload.build(context, summary, action).toByteArray(Charsets.UTF_8)
            val (code, text) = postJson(url.trim(), body, gzip = false)
            val ok = code in 200..299
            summary to ApiResponse(
                isSuccess = ok, statusCode = code, responseBody = text,
                result = if (ok) parseResult(text)?.takeIf { it.level in 1..5 } else null,
                errorMessage = if (ok) null else "Collector returned HTTP $code: ${detailOf(text)}",
                durationMs = System.currentTimeMillis() - t0,
                payloadBytes = body.size, wireBytes = body.size, attested = false,
            )
        } catch (e: Exception) {
            null to ApiResponse(
                isSuccess = false, statusCode = -1, responseBody = "",
                errorMessage = "Connection error: ${e.localizedMessage ?: e.javaClass.simpleName}. " +
                    "Check the collector URL and that this device can reach it.",
                durationMs = System.currentTimeMillis() - t0
            )
        }
    }

    fun normalizeBaseUrl(url: String): String =
        url.trim().removeSuffix("/").removeSuffix("/v1/features").removeSuffix("/v2/assess").removeSuffix("/")

    /**
     * Runs the full signed flow. Returns the fresh scan (taken under this request's
     * attestation key) together with the backend's answer.
     */
    suspend fun assess(
        context: Context,
        baseUrl: String,
        action: String = "login",
    ): Pair<ScanSummary?, ApiResponse> = withContext(Dispatchers.IO) {
        val t0 = System.currentTimeMillis()
        val base = normalizeBaseUrl(baseUrl)
        val installId = DeviceIdentity.installId(context)
        var session: AttestationSession? = null
        try {
            // 1. nonce
            val nonceRes = postJson(
                "$base/v1/nonce",
                JSONObject().put("install_id", installId).put("action", action).toString().toByteArray(),
                gzip = false
            )
            if (nonceRes.first !in 200..299) {
                return@withContext null to failure(nonceRes.first, nonceRes.second, "Nonce request failed", t0)
            }
            val nonce = JSONObject(nonceRes.second).getString("nonce")

            // 2. attested key bound to the nonce (absent on devices without a working keystore)
            session = try {
                AttestationSession.create(Base64.decode(nonce, Base64.DEFAULT))
            } catch (_: Exception) {
                null
            }

            // 3. scan + payload + signature
            val summary = FeatureCatalogueScanner.scanAll(context, session)
            val payload = TrustPayload.build(
                context, summary, installId, action, nonce, DeviceIdentity.nextCounter(context)
            )
            val payloadBytes = payload.toByteArray(Charsets.UTF_8)
            val body = JSONObject()
                .put("payload", payload)
                .put("signature", session?.let { b64(it.sign(payloadBytes)) } ?: "")
                .put("chain", JSONArray().apply { session?.chain?.forEach { put(b64(it)) } })
                .toString()
                .toByteArray(Charsets.UTF_8)

            // 4. send
            val wire = gzip(body)
            val (code, text) = postJson("$base/v2/assess", wire, gzip = true)
            val elapsed = System.currentTimeMillis() - t0
            val response = if (code in 200..299) {
                ApiResponse(
                    isSuccess = true, statusCode = code, responseBody = text,
                    result = parseResult(text), durationMs = elapsed,
                    payloadBytes = payloadBytes.size, wireBytes = wire.size, attested = session != null
                )
            } else {
                failure(code, text, "Assessment failed", t0)
                    .copy(payloadBytes = payloadBytes.size, wireBytes = wire.size, attested = session != null)
            }
            summary to response
        } catch (e: Exception) {
            null to ApiResponse(
                isSuccess = false, statusCode = -1, responseBody = "",
                errorMessage = "Connection error: ${e.localizedMessage ?: e.javaClass.simpleName}. " +
                    "Check the backend is running and reachable from this device.",
                durationMs = System.currentTimeMillis() - t0
            )
        } finally {
            session?.close()
        }
    }

    private fun postJson(url: String, body: ByteArray, gzip: Boolean): Pair<Int, String> {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = 15000
            readTimeout = 20000
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setRequestProperty("Accept", "application/json")
            if (gzip) setRequestProperty("Content-Encoding", "gzip")
            setFixedLengthStreamingMode(body.size)
        }
        try {
            conn.outputStream.use { it.write(body) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else (conn.errorStream ?: conn.inputStream)
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            return code to text
        } finally {
            conn.disconnect()
        }
    }

    private fun failure(code: Int, body: String, what: String, t0: Long) = ApiResponse(
        isSuccess = false, statusCode = code, responseBody = body,
        errorMessage = "$what (HTTP $code): ${detailOf(body)}",
        durationMs = System.currentTimeMillis() - t0
    )

    private fun gzip(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(data) }
        return out.toByteArray()
    }

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun parseResult(text: String): ModelResult? = try {
        val json = JSONObject(text)
        val reasons = mutableListOf<Reason>()
        json.optJSONArray("reasons")?.let { arr ->
            for (i in 0 until arr.length()) {
                val r = arr.optJSONObject(i) ?: continue
                reasons.add(Reason(r.optString("code"), r.optString("tier"), r.optString("text")))
            }
        }
        ModelResult(
            level = json.optInt("trust_level", 0),
            label = json.optString("label", "UNKNOWN"),
            outcome = json.optString("outcome", ""),
            rulesLevel = json.optInt("rules_level", 0),
            mlLevel = if (json.isNull("ml_level")) null else json.optInt("ml_level"),
            reasons = reasons,
            decisionId = json.optString("decision_id", ""),
            attestation = json.optJSONObject("attestation"),
            serverSignals = json.optJSONObject("server_signals"),
            coverage = json.optJSONObject("coverage"),
            serverMs = json.optDouble("server_ms", 0.0),
        )
    } catch (_: Exception) {
        null
    }

    private fun detailOf(body: String): String = try {
        JSONObject(body).optString("detail", body.take(150))
    } catch (_: Exception) {
        body.take(150)
    }
}
