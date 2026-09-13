package com.aidotvpn.client.core

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * CsrBuilder generates an ECDSA P-256 keypair *inside Android Keystore*
 * and produces a PKCS#10 CSR (PEM) that the AidotVpn controller signs.
 *
 * Why Android Keystore: the matching private key never leaves the
 * keystore daemon's address space (and on devices with StrongBox, never
 * leaves the secure element). When the device-attached app needs to
 * authenticate over mTLS to the controller, it asks Keystore to perform
 * the signature operation; the raw key bytes are inaccessible to the
 * app process.
 *
 * Lifecycle:
 *
 *   1. [generate] creates a fresh key under [keyAlias] and returns the
 *      CSR PEM bytes the caller should send to the controller.
 *
 *   2. After [generate], the key remains in the Keystore until [delete]
 *      is called or [generate] is called again with the same alias
 *      (which overwrites). The [RegistrationFlow] manages the alias
 *      lifecycle as part of its rotation logic.
 *
 *   3. [getSignerForAlias] returns a configured [Signature] object the
 *      mTLS handshake code uses for the cert verification step.
 *
 * Why hand-rolled ASN.1: see DerEncoder.kt rationale.
 */
class CsrBuilder {

    /**
     * Generates a fresh EC P-256 keypair under [keyAlias] inside Android
     * Keystore and builds a PKCS#10 CSR around it. Returns CSR bytes
     * (PEM) plus the attestation cert chain Keystore emitted (PEM).
     *
     * The attestation chain is non-empty when the device supports key
     * attestation (Android 7+) AND the caller passed [attestationChallenge].
     * The chain ends at Google's hardware-attestation root and proves the
     * private key really lives in TEE/StrongBox. Server-side verification
     * lives in [com.aidotvpn.server.internal.attestation.Verifier] in Go.
     *
     * If [keyAlias] already exists, the old key is replaced — callers
     * that need atomic rotation should generate to a new alias first
     * and only delete the old alias after the new cert is in hand.
     */
    fun generate(
        keyAlias: String,
        requireStrongBox: Boolean = false,
        attestationChallenge: ByteArray? = null,
    ): GenerateResult {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        // Drop existing entry if any.
        if (ks.containsAlias(keyAlias)) ks.deleteEntry(keyAlias)

        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val specBuilder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            // We use this key as a TLS client identity. No user-auth gate
            // because the standalone app drives mTLS in the background to
            // refresh peer config.
            .setUserAuthenticationRequired(false)
        if (requireStrongBox && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            specBuilder.setIsStrongBoxBacked(true)
        }
        // Phase 5b+: bind a server-issued nonce so the resulting attestation
        // cert chain can be replay-protected. Older devices (API <= 23)
        // ignore this field; the chain in that case is software-only and
        // the server's allowlist mode will reject it (good — we want
        // hardware attestation as the gate).
        if (attestationChallenge != null) {
            specBuilder.setAttestationChallenge(attestationChallenge)
        }
        gen.initialize(specBuilder.build())
        val keyPair = gen.generateKeyPair()

        val csrDer = buildCsrDer(keyPair.public, keyPair.private)
        val chainPem = readChain(ks, keyAlias)
        return GenerateResult(
            csrPem = pemWrap(csrDer, "CERTIFICATE REQUEST"),
            attestationChainPem = chainPem,
        )
    }

    /**
     * Result of [generate]: the CSR plus (when supported) a hardware
     * attestation cert chain.
     */
    data class GenerateResult(
        val csrPem: ByteArray,
        /** Empty when the device doesn't support key attestation OR when
         *  the caller didn't pass an [attestationChallenge]. */
        val attestationChainPem: ByteArray,
    )

    /**
     * Reads the X.509 cert chain Keystore generated for this key entry
     * and PEM-encodes it. Returns empty bytes when no chain is present
     * (typical on emulators / very old devices).
     */
    private fun readChain(ks: KeyStore, alias: String): ByteArray {
        val chain = ks.getCertificateChain(alias) ?: return ByteArray(0)
        if (chain.isEmpty()) return ByteArray(0)
        val sb = StringBuilder()
        for (cert in chain) {
            val der = cert.encoded
            val b64 = android.util.Base64.encode(der, android.util.Base64.NO_WRAP)
            sb.append("-----BEGIN CERTIFICATE-----\n")
            var i = 0
            while (i < b64.size) {
                val end = (i + 64).coerceAtMost(b64.size)
                sb.append(String(b64, i, end - i)).append('\n')
                i = end
            }
            sb.append("-----END CERTIFICATE-----\n")
        }
        return sb.toString().toByteArray()
    }

    /** Returns the PrivateKey reference for [keyAlias] suitable for passing
     *  to a [java.security.KeyStore.PrivateKeyEntry] consumer (e.g. JSSE
     *  client cert auth). */
    fun privateKey(keyAlias: String): PrivateKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry ?: return null
        return entry.privateKey
    }

    fun delete(keyAlias: String) {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(keyAlias)) ks.deleteEntry(keyAlias)
    }

    // --- internals ----------------------------------------------------

    private fun buildCsrDer(publicKey: PublicKey, privateKey: PrivateKey): ByteArray {
        // The X.509 SubjectPublicKeyInfo is exactly what getEncoded()
        // returns for KeyPairGenerator-produced EC keys.
        val spki = publicKey.encoded

        // CertificationRequestInfo
        val tbs = DerEncoder.sequence(
            DerEncoder.integer(0),                     // version v1
            DerEncoder.emptySequence(),                // empty subject Name
            spki,                                      // already DER
            DerEncoder.implicitSet(0),                 // empty attributes [0]
        )

        // Sign the TBS bytes.
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(tbs)
            sign()
        }

        // Final CertificationRequest
        val ecdsaWithSha256 = DerEncoder.sequence(
            DerEncoder.oid(1, 2, 840, 10045, 4, 3, 2),  // ecdsaWithSHA256
        )
        return DerEncoder.sequence(
            tbs,
            ecdsaWithSha256,
            DerEncoder.bitString(signature),
        )
    }

    private fun pemWrap(der: ByteArray, label: String): ByteArray {
        val b64 = android.util.Base64.encode(der, android.util.Base64.NO_WRAP)
        val sb = StringBuilder()
        sb.append("-----BEGIN ").append(label).append("-----\n")
        // 64-char wrap per RFC 7468 §2.
        var i = 0
        while (i < b64.size) {
            val end = (i + 64).coerceAtMost(b64.size)
            sb.append(String(b64, i, end - i))
            sb.append('\n')
            i = end
        }
        sb.append("-----END ").append(label).append("-----\n")
        return sb.toString().toByteArray()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /** Convenience: alias for the *current* mTLS key. */
        const val CURRENT_ALIAS = "aidotvpn.mtls.current"

        /** Convenience: alias used during rotation handoff. */
        const val PENDING_ALIAS = "aidotvpn.mtls.pending"
    }
}
