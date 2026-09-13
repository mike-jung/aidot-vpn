package com.aidotvpn.client.core

import android.util.Base64
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair

/**
 * WireGuard key utilities.
 *
 * The Curve25519 keypair the device uses for WG handshakes is generated
 * **client-side** so the private key never leaves the device. The
 * public key is sent to the controller during Register/RotateKey and
 * forwarded to data nodes via NodeService.SyncPeers.
 *
 * In Phase 6 we'll wrap the private key inside Android Keystore with
 * StrongBox attestation; for Phase 5 we keep it in the same encrypted
 * preferences blob as the rest of the allocation. That blob is itself
 * sealed by an Android-Keystore-backed AES key, so the private key
 * never sits on disk in the clear — the storage trust model is
 * roughly equivalent to using Keystore directly, just with a coarser
 * granularity that we'll tighten later.
 */
object KeyUtils {

    /** Base64 (standard, no wrap) encoding used by the controller wire. */
    private const val B64_FLAGS = Base64.NO_WRAP

    fun newKeyPair(): KeyPair = KeyPair()

    /** 44-char base64 string the controller expects (32 raw bytes -> 44 chars). */
    fun publicKeyB64(kp: KeyPair): String =
        Base64.encodeToString(kp.publicKey.bytes, B64_FLAGS)

    fun privateKeyB64(kp: KeyPair): String =
        Base64.encodeToString(kp.privateKey.bytes, B64_FLAGS)

    fun privateKeyFromB64(b64: String): Key =
        Key.fromBytes(Base64.decode(b64, B64_FLAGS))

    fun publicKeyFromB64(b64: String): Key =
        Key.fromBytes(Base64.decode(b64, B64_FLAGS))

    /**
     * Convenience: render a 32-byte WG/PSK byte array as the 44-char
     * base64 string the proto expects.
     */
    fun bytesToB64(b: ByteArray): String = Base64.encodeToString(b, B64_FLAGS)

    fun b64ToBytes(s: String): ByteArray = Base64.decode(s, B64_FLAGS)
}
