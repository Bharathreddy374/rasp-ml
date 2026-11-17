package com.example.demo.features.scanner

import android.content.Context
import com.example.demo.features.attestation.AttestationSession
import com.example.demo.features.model.CollectionSource
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalResult
import com.example.demo.features.probes.AppIntegrityProbe
import com.example.demo.features.probes.AttestationProbe
import com.example.demo.features.probes.DeviceStaticProbe
import com.example.demo.features.probes.MemoryProcfsProbe
import com.example.demo.features.probes.NativeProbes
import com.example.demo.features.probes.ProbeHealthProbe
import com.example.demo.features.probes.RiskyContextProbe
import com.example.demo.features.probes.RuntimeHookingProbe
import com.example.demo.features.probes.SensorTouchProbe
import com.example.demo.features.probes.ServerTeleProbe
import com.example.demo.features.probes.TimingProbes
import com.example.demo.features.probes.support.Proc
import com.example.demo.features.probes.support.measured
import com.example.demo.features.probes.support.unknown
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

data class ScanSummary(
    val signals: List<SignalResult>,
    val scanDurationMs: Long,
    val safeCount: Int,
    val infoCount: Int,
    val suspiciousCount: Int,
    val alertCount: Int,
    val deviceOnlyCount: Int,
    val hybridCount: Int,
    val serverOnlyCount: Int,
    /** Probe groups that threw; their signals are missing and count as unknown. */
    val failedGroups: List<String> = emptyList(),
    /** Signals whose probe is still a constant placeholder. */
    val notImplementedCount: Int = 0
)

object FeatureCatalogueScanner {

    /**
     * Runs every probe group. Pass the request's [session] when the scan will be sent,
     * so the attestation rows describe the key that signs this payload.
     */
    suspend fun scanAll(context: Context, session: AttestationSession? = null): ScanSummary =
        withContext(Dispatchers.IO) {
            val t0 = System.currentTimeMillis()
            Proc.resetCounters()
            try { NativeProbes.begin(context) } catch (_: Throwable) {}  // native report for this scan
            val allResults = mutableListOf<SignalResult>()
            val failed = mutableListOf<String>()

            fun group(name: String, block: () -> List<SignalResult>) {
                try {
                    allResults.addAll(block())
                } catch (_: Exception) {
                    failed.add(name)
                }
            }

            group("attestation") { AttestationProbe.collect(session) }              // F001 - F015
            group("device_static") { DeviceStaticProbe.collect(context) }           // F016 - F075
            group("app_integrity") { AppIntegrityProbe.collect(context) }           // F076 - F115
            group("runtime_hooking") { RuntimeHookingProbe.collect(context) }       // F116 - F175
            group("memory_procfs") { MemoryProcfsProbe.collect() }                  // F176 - F205
            group("timing") { TimingProbes.collect() }                              // F206 - F230
            group("sensor_touch") { SensorTouchProbe.collect(context) }             // F231 - F270
            group("risky_context") { RiskyContextProbe.collect(context) }           // F271 - F285
            group("server_side") { ServerTeleProbe.collect() }                      // F286 - F350 (labels only)

            // Timings the scanner owns: F221 total scan, F223 / F224 attestation (when sending).
            val scanMs = System.currentTimeMillis() - t0
            allResults.add(measured("F221", "probe_total_duration_ms", "$scanMs ms", scanMs,
                details = "Wall time of all probe groups in this scan."))
            if (session != null) {
                allResults.add(measured("F223", "attestation_latency_ms", "${session.attestationMs} ms", session.attestationMs,
                    details = "Attested key generation plus certificate chain retrieval."))
                allResults.add(measured("F224", "key_gen_latency_ms", "${session.keyGenMs} ms", session.keyGenMs,
                    details = "Key pair generation inside the keystore (TEE / StrongBox)."))
            } else {
                allResults.add(unknown("F223", "attestation_latency_ms", "measured when sending to the backend"))
                allResults.add(unknown("F224", "key_gen_latency_ms", "measured when sending to the backend"))
            }

            val present = allResults.map { it.id }.toSet()
            val missing = (1..350).count { "F%03d".format(it) !in present }
            group("probe_health") { ProbeHealthProbe.collect(failed.size, Proc.blockedReads(), missing) } // F351 - F370

            allResults.sortBy { it.id }

            val elapsed = System.currentTimeMillis() - t0
            ScanSummary(
                signals = allResults,
                scanDurationMs = elapsed,
                safeCount = allResults.count { it.riskLevel == RiskLevel.SAFE },
                infoCount = allResults.count { it.riskLevel == RiskLevel.INFO },
                suspiciousCount = allResults.count { it.riskLevel == RiskLevel.SUSPICIOUS },
                alertCount = allResults.count { it.riskLevel == RiskLevel.ALERT },
                deviceOnlyCount = allResults.count { it.source == CollectionSource.DEVICE_ONLY },
                hybridCount = allResults.count { it.source == CollectionSource.HYBRID },
                serverOnlyCount = allResults.count { it.source == CollectionSource.SERVER_ONLY },
                failedGroups = failed.toList(),
                notImplementedCount = allResults.count { !it.implemented }
            )
        }

    /** Human-readable export for sharing and debugging. Not what is sent to the backend. */
    fun exportToJson(summary: ScanSummary): String {
        val root = JSONObject()
        root.put("total_signals", summary.signals.size)
        root.put("safe_count", summary.safeCount)
        root.put("info_count", summary.infoCount)
        root.put("suspicious_count", summary.suspiciousCount)
        root.put("alert_count", summary.alertCount)
        root.put("not_implemented_count", summary.notImplementedCount)
        root.put("failed_groups", JSONArray(summary.failedGroups))

        val array = JSONArray()
        for (s in summary.signals) {
            val item = JSONObject()
            item.put("id", s.id)
            item.put("name", s.name)
            item.put("value", s.value)
            item.put("category", s.category.displayName)
            item.put("risk_level", s.riskLevel.name)
            item.put("implemented", s.implemented)
            item.put("details", s.details)
            array.put(item)
        }
        root.put("signals", array)
        return root.toString(2)
    }
}
