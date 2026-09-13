package com.aidotvpn.client.core

import android.util.Base64
import android.util.Log
import org.bouncycastle.crypto.SecretWithEncapsulation
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.SecureRandom

/**
 * Client half of the hybrid post-quantum PSK: ML-KEM-768 encapsulation.
 *
 * This is the file `internal/pqc`'s package comment claimed existed since
 * Phase 6. It did not. The server half was complete and tested the whole
 * time; nothing on Android could produce a ciphertext for it, so every
 * device fell back to the classical PSK — correctly, but permanently.
 *
 * ## What it does
 *
 * The controller hands each device its tenant's 1184-byte encapsulation
 * key at registration. We encapsulate against it, which yields a 32-byte
 * shared secret (kept locally) and a 1088-byte ciphertext (sent back).
 * The server decapsulates to the same secret, and both ends fold it into
 * the WireGuard PSK via HKDF. Neither side transmits the secret.
 *
 * ## Why BouncyCastle
 *
 * Android has no ML-KEM. `javax.crypto.KEM` needs JDK 21 and Android
 * targets 17 here, so we use BouncyCastle's low-level
 * `pqc.crypto.mlkem` classes directly.
 *
 * Deliberately **not** registered as a JCE provider. Registering a second
 * BouncyCastle alongside the platform's bundled
 * `com.android.org.bouncycastle` is a long-standing source of provider
 * conflicts, and we need exactly one algorithm — going through the
 * provider machinery would buy nothing and cost that risk.
 *
 * ## Wire compatibility
 *
 * The server uses Go's `crypto/mlkem`. Both implement FIPS 203 final, so
 * the encodings match — but only for BouncyCastle 1.78+. Earlier releases
 * implement the round-3 Kyber draft, and mixing them fails in the worst
 * available way: encapsulation succeeds, the server decapsulates
 * successfully, and the two ends derive **different** secrets. The result
 * is a tunnel that completes its handshake and drops every packet. The
 * version floor in `libs.versions.toml` is load-bearing.
 */
object PqcKemClient {

    private const val TAG = "PqcKemClient"

    /** ML-KEM-768 encapsulation key size, per FIPS 203. */
    const val ENCAP_KEY_SIZE = 1184

    /** ML-KEM-768 ciphertext size. */
    const val CIPHERTEXT_SIZE = 1088

    /** Shared secret size. */
    const val SHARED_SECRET_SIZE = 32

    /** Algorithm identifier the controller sends alongside the key. */
    const val ALGORITHM = "ml-kem-768"

    /**
     * Result of one encapsulation.
     *
     * [sharedSecret] never leaves the device; [ciphertextB64] is what the
     * controller needs to derive the same value.
     */
    data class Encapsulation(
        val sharedSecret: ByteArray,
        val ciphertextB64: String,
    ) {
        // ByteArray gives reference equality by default, which makes an
        // accidental `==` comparison silently wrong for a value that is
        // cryptographic material.
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Encapsulation) return false
            return sharedSecret.contentEquals(other.sharedSecret) &&
                ciphertextB64 == other.ciphertextB64
        }

        override fun hashCode(): Int =
            31 * sharedSecret.contentHashCode() + ciphertextB64.hashCode()
    }

    /**
     * Encapsulate against the tenant's key.
     *
     * Returns null — rather than throwing — when the input is unusable or
     * BouncyCastle is unavailable. A device that cannot do ML-KEM must
     * still be able to register: the classical PSK is secure today, and
     * refusing enrolment over an unavailable enhancement would trade a
     * real outage for a hypothetical future one. Callers treat null as
     * "no ciphertext to send".
     *
     * @param algorithm the identifier the controller reported
     * @param encapKeyB64 base64 of the 1184-byte encapsulation key
     */
    @JvmStatic
    fun encapsulate(algorithm: String, encapKeyB64: String): Encapsulation? {
        if (algorithm.isBlank() || encapKeyB64.isBlank()) {
            // Controller has PQC disabled. Not an error.
            return null
        }
        if (algorithm != ALGORITHM) {
            // A future server offering a different KEM. Refusing beats
            // guessing: encapsulating with the wrong parameter set
            // produces a ciphertext the server decapsulates to a
            // different secret, and the tunnel then drops every packet
            // with no error anywhere.
            Log.w(TAG, "controller offered unsupported KEM '$algorithm'; using classical PSK")
            return null
        }

        val encapKey = try {
            Base64.decode(encapKeyB64, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            Log.w(TAG, "encapsulation key is not valid base64: ${e.message}")
            return null
        }
        if (encapKey.size != ENCAP_KEY_SIZE) {
            Log.w(TAG, "encapsulation key is ${encapKey.size} bytes, want $ENCAP_KEY_SIZE")
            return null
        }

        return try {
            val params = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, encapKey)
            val generator = MLKEMGenerator(SecureRandom())
            val result: SecretWithEncapsulation = generator.generateEncapsulated(params)

            val secret = result.secret
            val ciphertext = result.encapsulation

            // Size checks against the constants rather than trusting the
            // library: a version mismatch that changed either size would
            // otherwise surface as a broken tunnel, not a log line.
            if (secret.size != SHARED_SECRET_SIZE || ciphertext.size != CIPHERTEXT_SIZE) {
                Log.e(
                    TAG,
                    "unexpected ML-KEM sizes (secret=${secret.size}, " +
                        "ciphertext=${ciphertext.size}); is bcprov older than 1.79?",
                )
                return null
            }

            Log.i(TAG, "ML-KEM-768 encapsulation succeeded")
            Encapsulation(
                sharedSecret = secret,
                ciphertextB64 = Base64.encodeToString(ciphertext, Base64.NO_WRAP),
            )
        } catch (e: NoClassDefFoundError) {
            // BouncyCastle stripped by an over-aggressive R8 config. Worth
            // its own branch: the symptom is otherwise indistinguishable
            // from "the server has PQC off".
            Log.e(TAG, "BouncyCastle ML-KEM classes are missing — check consumer-rules.pro", e)
            null
        } catch (e: Exception) {
            Log.e(TAG, "ML-KEM encapsulation failed; falling back to the classical PSK", e)
            null
        }
    }
}
