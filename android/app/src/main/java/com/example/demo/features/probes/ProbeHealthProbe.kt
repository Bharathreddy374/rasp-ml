package com.example.demo.features.probes

import com.example.demo.features.model.CollectionSource
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult

/**
 * Catalogue group 12 (F351 - F370).
 *
 * F351 is measured here. F363 - F365 (counter, signature, payload age) are checked by the
 * backend on every request, so the phone does not claim them. The rest need native canary
 * probes and SDK self-hashing that do not exist yet, so they are reported as unknown.
 */
object ProbeHealthProbe {

    private val BACKEND_CHECKED = mapOf(
        "F363" to "payload_counter_monotonic",
        "F364" to "payload_signature_valid",
        "F365" to "payload_age_ms",
    )

    private val NOT_IMPLEMENTED = listOf(
        "F352" to "probe_timeout_count",
        "F354" to "probe_crash_count", "F355" to "probe_path_disagreement_total",
        "F357" to "canary_probe_failed",
        "F358" to "canary_decoy_visible", "F359" to "sdk_self_hash_match",
        "F361" to "sdk_version_expected",
        "F362" to "probe_order_matches_nonce", "F366" to "cert_pinning_failure",
        "F367" to "jni_registered_natives_ok",
        "F369" to "probe_variance_too_low", "F370" to "vector_matches_cohort_median_exactly",
    )

    /**
     * [blockedReads]: /proc and file reads the OS refused this scan.
     * [missingSignals]: catalogue IDs F001 - F350 that no probe produced (failed groups).
     */
    fun collect(failedGroupCount: Int = 0, blockedReads: Int = 0, missingSignals: Int = 0): List<SignalResult> {
        val list = mutableListOf<SignalResult>()
        list.add(
            SignalResult(
                id = "F353",
                name = "probe_blocked_count",
                category = SignalCategory.PROBE_HEALTH,
                value = "$blockedReads reads refused",
                raw = blockedReads,
                riskLevel = RiskLevel.INFO,
                source = CollectionSource.DEVICE_ONLY,
                details = "File and /proc reads the OS refused during this scan (SELinux, hooks); compared per device model."
            )
        )
        list.add(
            SignalResult(
                id = "F356",
                name = "probe_missing_count",
                category = SignalCategory.PROBE_HEALTH,
                value = "$missingSignals signals missing",
                raw = missingSignals,
                riskLevel = if (missingSignals > 0) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                source = CollectionSource.DEVICE_ONLY,
                details = "Catalogue signals F001 - F350 that no probe produced in this scan."
            )
        )
        list.add(
            SignalResult(
                id = "F351",
                name = "probe_error_count",
                category = SignalCategory.PROBE_HEALTH,
                value = "$failedGroupCount probe groups failed",
                raw = failedGroupCount,
                riskLevel = if (failedGroupCount > 0) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                source = CollectionSource.DEVICE_ONLY,
                details = "Probe groups that threw during the scan. A failed probe is unknown, never clean."
            )
        )
        // Native code integrity and load path (libtrustprobe)
        for ((id, name) in listOf("F360" to "sdk_text_integrity", "F368" to "native_lib_load_path_ok")) {
            list.add(NativeProbes.signal(id, name) ?: SignalResult(id, name, SignalCategory.PROBE_HEALTH,
                "Not measured", details = "native probe library", implemented = false))
        }
        for ((id, name) in BACKEND_CHECKED) {
            list.add(
                SignalResult(
                    id = id,
                    name = name,
                    category = SignalCategory.PROBE_HEALTH,
                    value = "Checked by backend on every request",
                    riskLevel = RiskLevel.INFO,
                    source = CollectionSource.SERVER_ONLY,
                    details = "Verified server-side from the signed payload envelope."
                )
            )
        }
        for ((id, name) in NOT_IMPLEMENTED) {
            list.add(
                SignalResult(
                    id = id,
                    name = name,
                    category = SignalCategory.PROBE_HEALTH,
                    value = "Not implemented",
                    riskLevel = RiskLevel.INFO,
                    details = "Needs native canary probes / SDK self-hashing.",
                    implemented = false
                )
            )
        }
        return list.sortedBy { it.id }
    }
}
