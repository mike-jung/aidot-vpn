package com.aidotvpn.client.core

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Encrypted persistence for the device's registration material.
 *
 * Backed by AndroidX Security Crypto's [EncryptedSharedPreferences] which
 * AES-GCM-encrypts both keys and values with a master key kept in the
 * Android Keystore. The Keystore-backed key never leaves the secure
 * environment (StrongBox if available, otherwise TEE/Software Keymaster).
 *
 * What we store:
 *   - The device-side WireGuard private key
 *   - The PSK paired with that key
 *   - Allocated VPN addresses (v4 + v6)
 *   - The mTLS client cert + CA chain we use to talk to the controller
 *   - The list of authorised nodes + their endpoints
 *
 * What we deliberately do NOT store:
 *   - OIDC access/refresh tokens. AppAuth manages those in its own
 *     Keystore-backed vault and they're cheaper to re-acquire (silent
 *     SSO on Keycloak) than recovering from a key compromise.
 *
 * Threat model assumption: an attacker with root on the unlocked device
 * can extract the cleartext blob, but the same attacker could read raw
 * memory anyway. The encryption protects against:
 *   - Lost-device, screen-locked threat (boot-time key derivation needs
 *     hardware Keystore unlock)
 *   - Backup leakage (this prefs file is excluded from auto-backup; see
 *     :app's data_extraction_rules.xml)
 */
class CoreStorage private constructor(private val context: Context) {

    private val masterKey: MasterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        // Use StrongBox when available (Pixel + recent Samsung). The
        // builder transparently falls back if the device lacks it.
        .setRequestStrongBoxBacked(true)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        FILE_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = false
    }

    fun loadAllocation(): StoredAllocation? {
        val raw = prefs.getString(KEY_ALLOCATION, null) ?: return null
        return runCatching { json.decodeFromString<StoredAllocation>(raw) }
            .getOrNull()
    }

    fun saveAllocation(allocation: StoredAllocation) {
        prefs.edit()
            .putString(KEY_ALLOCATION, json.encodeToString(allocation))
            .apply()
    }

    fun clearAllocation() {
        prefs.edit().remove(KEY_ALLOCATION).apply()
    }

    /**
     * The controller URL this install was configured with.
     *
     * Persisted (0.28.2) because the engine is a process-wide singleton
     * that the host app initialises with a URL, and the VpnService is
     * `START_STICKY` — so Android restarts the service into a *fresh
     * process* after a reboot or a low-memory kill, with no Activity
     * having run.
     *
     * In that process the singleton is null and the service's
     * `AidotVpnEngine.get(applicationContext)` had nothing to fall back
     * on. It called `error()`, which crashes the service on the exact
     * path START_STICKY exists to support.
     *
     * Stored alongside the allocation rather than in a separate file:
     * they have the same lifetime, and a URL without an allocation is
     * useless anyway.
     */
    fun loadControllerUrl(): String? = prefs.getString(KEY_CONTROLLER_URL, null)

    /**
     * Whether the user currently wants the tunnel up.
     *
     * Android restarts a START_STICKY service after the app is closed or
     * killed, and the recreated service has to decide whether to dial
     * out again. Without this it either always did — reconnecting a
     * tunnel the user had just disconnected — or never did, dropping an
     * always-on connection on the first low-memory kill. The user's last
     * intent is the only thing that answers it.
     */
    fun loadTunnelWanted(): Boolean = prefs.getBoolean(KEY_TUNNEL_WANTED, false)

    fun saveTunnelWanted(wanted: Boolean) {
        prefs.edit().putBoolean(KEY_TUNNEL_WANTED, wanted).apply()
    }

    /**
     * Which controller address to use right now.
     *
     * The tunnel address once a tunnel is up, the bootstrap address
     * otherwise. Callers do not choose — asking each caller to decide
     * would mean each one could get it wrong.
     */
    fun controllerUrlFor(tunnelUp: Boolean): String? =
        if (tunnelUp) prefs.getString(KEY_TUNNEL_CONTROLLER, null) ?: loadControllerUrl()
        else loadControllerUrl()

    fun saveTunnelControllerUrl(url: String) {
        prefs.edit().putString(KEY_TUNNEL_CONTROLLER, url).apply()
    }

    /** An admin switched the policy back to 그대로 사용. */
    fun clearTunnelControllerUrl() {
        prefs.edit().remove(KEY_TUNNEL_CONTROLLER).apply()
    }

    fun saveControllerUrl(url: String) {
        prefs.edit().putString(KEY_CONTROLLER_URL, url).apply()
    }

    /** Stable per-install UUID. Survives app updates, rotates on uninstall. */
    fun installId(): String {
        val existing = prefs.getString(KEY_INSTALL_ID, null)
        if (existing != null) return existing
        val fresh = java.util.UUID.randomUUID().toString()
        prefs.edit().putString(KEY_INSTALL_ID, fresh).apply()
        return fresh
    }

    companion object {
        private const val FILE_NAME = "aidotvpn_secure"
        private const val KEY_TUNNEL_WANTED = "tunnel_wanted"
        private const val KEY_CONTROLLER_URL = "controller_url"

        /**
         * The controller as seen from inside the tunnel.
         *
         * Registration has to happen before a tunnel exists, so the
         * bootstrap address stays compiled in. Everything afterwards
         * can go over the tunnel to an address that means nothing
         * outside it — which is how an .ovpn deployment keeps internal
         * hosts out of the client.
         */
        private const val KEY_TUNNEL_CONTROLLER = "tunnel_controller_url"
        private const val KEY_ALLOCATION = "allocation_v1"
        private const val KEY_INSTALL_ID = "install_id_v1"

        @Volatile
        private var instance: CoreStorage? = null

        fun get(context: Context): CoreStorage {
            return instance ?: synchronized(this) {
                instance ?: CoreStorage(context.applicationContext).also { instance = it }
            }
        }
    }
}
