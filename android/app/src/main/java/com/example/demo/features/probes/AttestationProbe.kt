package com.example.demo.features.probes

import com.example.demo.features.attestation.AttestationSession
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult

/**
 * Catalogue group 1 (F001 - F015).
 *
 * Key Attestation facts (F001 - F010) live inside the certificate chain and can only be
 * trusted after the backend verifies that chain against Google's roots. The phone therefore
 * reports no verdicts here: it sends the chain itself (see TrustPayload) and shows the
 * backend's answer after a send. Only the key's storage level is read locally, for display.
 *
 * Play Integrity (F011 - F015) needs the Play Integrity API, a Google Cloud project and
 * server-side token decryption. That is not integrated yet, so those signals are unknown.
 */
object AttestationProbe {

    private val KEY_ATTESTATION = listOf(
        "F001" to "attest_chain_valid", "F002" to "attest_cert_revoked",
        "F003" to "attest_security_level", "F004" to "attest_verified_boot_state",
        "F005" to "attest_device_locked", "F006" to "attest_os_patch_level",
        "F007" to "attest_vendor_patch_level", "F008" to "attest_app_cert_digest_match",
        "F009" to "attest_package_name_match", "F010" to "attest_nonce_valid",
    )

    private val PLAY_INTEGRITY = listOf(
        "F011" to "pi_device_verdict", "F012" to "pi_app_verdict", "F013" to "pi_licensing",
        "F014" to "pi_recent_device_activity", "F015" to "pi_app_access_risk",
    )

    fun collect(session: AttestationSession?): List<SignalResult> {
        val list = mutableListOf<SignalResult>()
        for ((id, name) in KEY_ATTESTATION) {
            val value = when {
                session == null -> "Created when you send to the backend"
                id == "F001" -> "${session.chain.size} certificates sent; backend verifies"
                id == "F003" -> "Key stored in ${session.securityLevel} (device view)"
                else -> "Read by backend from the signed certificate"
            }
            list.add(
                SignalResult(
                    id = id,
                    name = name,
                    category = SignalCategory.ATTESTATION,
                    value = value,
                    riskLevel = if (id == "F003" && session?.securityLevel == "Software") RiskLevel.SUSPICIOUS else RiskLevel.INFO,
                    details = "Hardware key attestation. The certificate chain is generated with the server's " +
                        "one-time nonce and verified on the backend against Google's attestation roots."
                )
            )
        }
        for ((id, name) in PLAY_INTEGRITY) {
            list.add(
                SignalResult(
                    id = id,
                    name = name,
                    category = SignalCategory.ATTESTATION,
                    value = "Play Integrity not integrated",
                    riskLevel = RiskLevel.INFO,
                    details = "Needs the Play Integrity API, a Google Cloud project and server-side token decryption.",
                    implemented = false
                )
            )
        }
        return list
    }
}
