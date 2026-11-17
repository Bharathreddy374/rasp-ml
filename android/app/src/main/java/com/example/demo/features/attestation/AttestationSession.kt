package com.example.demo.features.attestation

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * One hardware-attested signing key per request.
 *
 * The key is created in AndroidKeyStore with the server's nonce as the attestation
 * challenge, so its certificate chain proves (to the backend, not to us) which device,
 * boot state and app produced the request. The same key signs the payload, binding the
 * telemetry to that chain. The phone never judges its own attestation: the backend does.
 */
class AttestationSession private constructor(
    private val alias: String,
    /** DER certificates, leaf first. */
    val chain: List<ByteArray>,
    /** Where the key lives, as the OS reports it: "StrongBox", "TEE", "Software" or "Unknown". */
    val securityLevel: String,
    /** Time to generate the key pair inside the keystore (catalogue F224). */
    val keyGenMs: Long,
    /** Key generation plus fetching the attestation certificate chain (catalogue F223). */
    val attestationMs: Long,
) : AutoCloseable {

    fun sign(data: ByteArray): ByteArray {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val key = ks.getKey(alias, null) as PrivateKey
        return Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(data)
            sign()
        }
    }

    override fun close() {
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias)
        } catch (_: Exception) {
        }
    }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"

        /** Throws if the device cannot create an attested key; the caller then sends without attestation. */
        fun create(challenge: ByteArray): AttestationSession {
            val alias = "trust_req_" + UUID.randomUUID().toString()
            val t0 = System.nanoTime()
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
            kpg.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build()
            )
            val pair = kpg.generateKeyPair()
            val keyGenMs = (System.nanoTime() - t0) / 1_000_000
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val certs = ks.getCertificateChain(alias)
                ?: throw IllegalStateException("keystore returned no certificate chain")
            val attestationMs = (System.nanoTime() - t0) / 1_000_000
            return AttestationSession(alias, certs.map { it.encoded }, securityLevelOf(pair.private), keyGenMs, attestationMs)
        }

        @Suppress("DEPRECATION")
        private fun securityLevelOf(key: PrivateKey): String = try {
            val info = KeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Software"
                    else -> "Unknown"
                }
            } else if (info.isInsideSecureHardware) "TEE" else "Software"
        } catch (_: Exception) {
            "Unknown"
        }
    }
}
