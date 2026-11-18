package com.example.demo.features.attestation

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * ONE hardware-attested signing key per install (and per collector host), kept in AndroidKeyStore.
 *
 * It is created the first time the app sends, with that request's server nonce as the attestation
 * challenge, so the certificate chain proves the key was made on this device's keystore for this
 * server. Every later request is signed with the same key (header X-Rasp-Signature), which lets the
 * backend follow the key across sessions: key age, key changes, keys shared between installs.
 * The phone never judges its own attestation: the backend does.
 */
object InstallKey {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val PREFIX = "rasp_install_key_v1_"

    class Material internal constructor(
        private val alias: String,
        /** DER certificates, leaf first. */
        val chain: List<ByteArray>,
        /** True when the key was created for this request (its challenge is this request's nonce). */
        val created: Boolean,
        /** Key generation plus chain retrieval, when [created] (catalogue F223). */
        val createMs: Long?,
    ) {
        fun sign(data: ByteArray): ByteArray {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val key = ks.getKey(alias, null) as PrivateKey
            return Signature.getInstance("SHA256withECDSA").run {
                initSign(key)
                update(data)
                sign()
            }
        }
    }

    /** The install key for [host]; creates it with [challenge] if there is none. Throws if the keystore cannot. */
    fun get(host: String, challenge: ByteArray): Material {
        val alias = aliasFor(host)
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(alias)) {
            val chain = ks.getCertificateChain(alias)
            if (chain != null && chain.isNotEmpty()) return Material(alias, chain.map { it.encoded }, false, null)
            ks.deleteEntry(alias)
        }
        val t0 = System.nanoTime()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).apply {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build()
            )
        }.generateKeyPair()
        val chain = ks.getCertificateChain(alias) ?: throw IllegalStateException("keystore returned no certificate chain")
        return Material(alias, chain.map { it.encoded }, true, (System.nanoTime() - t0) / 1_000_000)
    }

    /** Forget the key for [host], e.g. when the server no longer recognises the challenge it was made with. */
    fun reset(host: String) {
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(aliasFor(host))
        } catch (_: Exception) {
        }
    }

    private fun aliasFor(host: String): String =
        PREFIX + MessageDigest.getInstance("SHA-256").digest(host.lowercase().toByteArray())
            .take(6).joinToString("") { "%02x".format(it) }
}
