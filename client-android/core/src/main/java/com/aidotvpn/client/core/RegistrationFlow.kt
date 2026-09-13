package com.aidotvpn.client.core

import android.content.Context
import android.os.Build
import com.wireguard.crypto.KeyPair

/**
 * RegistrationFlow ties everything in :core together: it takes an
 * authenticated [Authenticator], generates a device keypair (Phase 5b:
 * Android Keystore-backed for mTLS, software-backed for WG since
 * Curve25519 isn't a Keystore-supported algorithm), calls Register on
 * the controller, and persists the result.
 *
 * Phase 5b adds:
 *   - CSR-based mTLS issuance — the device builds a PKCS#10 CSR around
 *     a hardware-bound EC key and the controller signs it. Server never
 *     sees the matching private key.
 *   - [rotateKey] — refreshes both the WG keypair and the mTLS cert
 *     under cover of the existing cert (mTLS-authenticated request).
 *     Allocated VPN addresses are preserved; the controller revokes
 *     the old keys server-side.
 */
class RegistrationFlow(
    private val context: Context,
    /**
     * Which shell this is. Defaults to standalone; :vpnlib's
     * AidotVpnEngine passes "embedded" when a business app hosts the
     * tunnel itself.
     */
    private val deploymentMode: String = "standalone",
    /**
     * Source of access tokens. [Authenticator] in standalone mode,
     * [DelegatedTokenSource] when a host app supplies its own token
     * (see :vpnlib AidotVpnEngine).
     */
    private val authenticator: TokenSource,
    private val controllerBaseUrl: String,
    private val storage: CoreStorage = CoreStorage.get(context),
    private val csrBuilder: CsrBuilder = CsrBuilder(),
) {
    private val controller = ControllerClient(controllerBaseUrl)

    /**
     * Register this device with the controller. Idempotent on the
     * (user, install_id) tuple — re-running it after a fresh install
     * registers a new device row, but re-running it on the same
     * install re-issues a new key + cert for the existing device.
     *
     * Phase 7 flow:
     *   1. Fetch a fresh attestation challenge from the controller.
     *   2. Generate hardware-backed mTLS keypair with that challenge baked
     *      in via [KeyGenParameterSpec.Builder.setAttestationChallenge].
     *   3. Read the resulting cert chain (Keystore proves the key lives
     *      in TEE/StrongBox via the chain rooted at Google's hardware
     *      attestation root).
     *   4. Send CSR + chain + WG pubkey alongside Register.
     *   5. Server verifies the chain, checks the challenge match, and
     *      (when allowlist mode is on for the tenant) checks the device's
     *      hardware fingerprint against device_attestations_allowlist.
     */
    suspend fun register(displayName: String): StoredAllocation {
        val token = authenticator.getAccessToken()

        // 1. Fetch attestation challenge (best-effort — older deployments
        //    that haven't deployed Phase 7 yet just return empty).
        val challenge = fetchAttestationChallenge(token)

        // Generate a fresh WireGuard keypair (Curve25519, software-backed).
        val keypair: KeyPair = KeyUtils.newKeyPair()

        // 2-3. Generate Keystore EC key + CSR + cert chain.
        val csr = csrBuilder.generate(
            keyAlias = CsrBuilder.CURRENT_ALIAS,
            attestationChallenge = challenge,
        )

        // Hybrid post-quantum PSK (0.21.0).
        //
        // We encapsulate against the tenant key received in a PREVIOUS
        // allocation — on the very first registration there is none yet,
        // so the first device-key uses the classical PSK and every
        // subsequent one is hybrid. Avoiding that would need an extra
        // round trip before registration, which is a poor trade for one
        // key generation's worth of delay.
        val kem = cached()?.let {
            PqcKemClient.encapsulate(it.kemAlgorithm, it.kemEncapKey)
        }

        val req = RegisterRequest(
            installId = storage.installId(),
            displayName = displayName,
            platform = "android",
            osVersion = "Android ${Build.VERSION.RELEASE} (sdk ${Build.VERSION.SDK_INT})",
            appVersion = appVersion(context),
            // Manufacturer and model, so an admin can tell one 검증 폰
            // from another. A MAC address would be the obvious choice
            // and is not available: Android 10+ returns
            // 02:00:00:00:00:00 to apps and randomises the real one per
            // network, so it identifies nothing and changes when the
            // nurse walks to another floor.
            model = "${Build.MANUFACTURER} ${Build.MODEL}".trim(),
            osSdk = Build.VERSION.SDK_INT,
            deploymentMode = deploymentMode,
            // The host package is always us: whoever owns this process
            // owns the VpnService. Reading it from the context rather
            // than hardcoding means the embedded case reports the
            // business app without the SDK having to be told its name.
            hostPackage = context.packageName,
            kemCiphertext = kem?.ciphertextB64 ?: "",
            devicePublicKey = KeyUtils.publicKeyB64(keypair),
            attestationToken = "",            // Phase 7: Play Integrity token wires here
            clientCertCsrPem = String(csr.csrPem),
            attestationChainPem = String(csr.attestationChainPem),
        )

        val client = controller.bearerClient(token)
        val resp: RegisterResponse = controller.rpc(client, "Register", req)
        // Status and policy reads require this credential. Do not persist an
        // unusable allocation when an older server omits it from the response.
        check(resp.allocation.stateToken.isNotBlank()) {
            "서버 등록 응답에 상태 인증 정보가 없습니다. 서버를 업데이트한 뒤 다시 등록하세요."
        }

        val stored = StoredAllocation(
            deviceId = resp.device.id,
            installId = req.installId,
            ipv4Addr = resp.allocation.ipv4Addr,
            ipv6Addr = resp.allocation.ipv6Addr,
            devicePublicKeyB64 = KeyUtils.publicKeyB64(keypair),
            devicePrivateKeyB64 = KeyUtils.privateKeyB64(keypair),
            pskB64 = resp.allocation.psk,
            stateToken = resp.allocation.stateToken,
            clientCertPem = resp.allocation.clientCertPem,
            clientCertKeyAlias = CsrBuilder.CURRENT_ALIAS,
            caCertPem = resp.allocation.caCertPem,
            clientCertExpiresAt = resp.allocation.clientCertExpiresAt,
            nodes = resp.nodes,
            // Forward the server's split-tunnel policy. Empty list = full
            // tunnel (safe default if the controller predates Phase 6b).
            allowedIps = resp.allocation.allowedIps,
            // 0.10.0: whether an admin actually bound this device to a
            // policy. Drives the deny-by-default check in TunnelManager.
            policyBound = resp.allocation.policyBound,
            routeScope = resp.allocation.routeScope,
            dnsServers = resp.allocation.dnsServers,
            dnsSearchDomains = resp.allocation.dnsSearchDomains,
            kemEncapKey = resp.allocation.kemEncapKey,
            kemAlgorithm = resp.allocation.kemAlgorithm,
            // Phase 8 per-app split tunnel snapshot. Pre-Phase-8 servers
            // omit these fields → empty defaults → no per-app filtering.
            appFilterMode = resp.allocation.appFilterMode,
            appFilterPackages = resp.allocation.appFilterPackages,
        )
        storage.saveAllocation(stored)

        // The tunnel-side controller address, if the policy provided one.
        //
        // Saved separately from the allocation because it is consulted
        // from a different question: "how do I reach the controller
        // right now", which depends on whether the tunnel is up.
        if (resp.allocation.controllerTunnelUrl.isNotBlank()) {
            storage.saveTunnelControllerUrl(resp.allocation.controllerTunnelUrl)
        } else {
            storage.clearTunnelControllerUrl()
        }
        return stored
    }

    /**
     * Pull a fresh attestation challenge. Returns null when the controller
     * doesn't expose this endpoint (pre-Phase-7 deployments) — callers
     * fall through to non-attested CSR generation in that case.
     */
    private suspend fun fetchAttestationChallenge(token: String): ByteArray? {
        return try {
            val client = controller.bearerClient(token)
            val resp: GetAttestationChallengeResponse = controller.rpc(
                client, "GetAttestationChallenge",
                GetAttestationChallengeRequest(),
            )
            // Hex-decode (32 bytes -> 64 hex chars).
            val out = ByteArray(resp.challengeHex.length / 2)
            for (i in out.indices) {
                out[i] = resp.challengeHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
            out
        } catch (e: ControllerException) {
            // 404 / 501 => endpoint not deployed; degrade gracefully.
            if (e.httpStatus in setOf(404, 405, 501)) null else throw e
        }
    }

    /**
     * Rotate the device's WireGuard keypair AND mTLS keypair atomically.
     *
     * Sequence:
     *   1. Generate fresh WG keypair (software).
     *   2. Generate fresh mTLS keypair under [CsrBuilder.PENDING_ALIAS]
     *      and build CSR.
     *   3. Call RotateKey using the *current* mTLS key for transport auth.
     *   4. On success: promote PENDING -> CURRENT in Keystore, persist
     *      the new allocation, delete the old key.
     *   5. On failure: keep CURRENT alive, delete PENDING; the caller
     *      can retry safely.
     *
     * Allocated VPN IPs are preserved across rotation by the controller
     * (it copies them from the old device_keys row).
     */
    suspend fun rotateKey(): StoredAllocation {
        val current = storage.loadAllocation()
            ?: throw IllegalStateException("rotateKey called before initial register")

        val token = authenticator.getAccessToken()
        val challenge = fetchAttestationChallenge(token)

        // 1+2. Build the new credentials.
        val newWgKeypair = KeyUtils.newKeyPair()
        val newCsr = csrBuilder.generate(
            keyAlias = CsrBuilder.PENDING_ALIAS,
            attestationChallenge = challenge,
        )

        // 3. Send RotateKey under cover of the existing mTLS cert.
        val rotateKem = PqcKemClient.encapsulate(current.kemAlgorithm, current.kemEncapKey)

        val req = RotateKeyRequest(
            newDevicePublicKey = KeyUtils.publicKeyB64(newWgKeypair),
            attestationToken = "",
            clientCertCsrPem = String(newCsr.csrPem),
            kemCiphertext = rotateKem?.ciphertextB64 ?: "",
        )

        val client = try {
            // Phase 5b path: Keystore-bound private key + CSR-issued cert.
            controller.mtlsClientFromKeystore(
                clientCertPem = current.clientCertPem,
                keystoreAlias = current.clientCertKeyAlias,
                caCertPem = current.caCertPem,
            )
        } catch (e: Throwable) {
            csrBuilder.delete(CsrBuilder.PENDING_ALIAS)
            throw e
        }

        val resp: RotateKeyResponse = try {
            controller.rpc(client, "RotateKey", req)
        } catch (e: Throwable) {
            csrBuilder.delete(CsrBuilder.PENDING_ALIAS)
            throw e
        }

        // 4. Promote PENDING -> CURRENT atomically.
        //    First swap the alias, then delete the old key (or vice versa
        //    on failure — see the comment block at the top).
        csrBuilder.delete(CsrBuilder.CURRENT_ALIAS)
        // Android Keystore doesn't expose rename; we re-import isn't safe
        // because the private key is non-extractable. Instead we rebuild
        // CURRENT by generating a *replacement* on the next call. For
        // now we accept that "current alias" can point at PENDING when
        // we update StoredAllocation to track that.
        val updated = current.copy(
            devicePublicKeyB64 = KeyUtils.publicKeyB64(newWgKeypair),
            devicePrivateKeyB64 = KeyUtils.privateKeyB64(newWgKeypair),
            pskB64 = resp.allocation.psk,
            clientCertPem = resp.allocation.clientCertPem,
            clientCertKeyAlias = CsrBuilder.PENDING_ALIAS, // promote
            caCertPem = resp.allocation.caCertPem,
            clientCertExpiresAt = resp.allocation.clientCertExpiresAt,
            // Phase 8: pick up any admin-side app-filter changes that
            // happened between the last register and this rotation.
            // Server-side normalisation guarantees mode is "off" when
            // packages is empty.
            appFilterMode = resp.allocation.appFilterMode,
            appFilterPackages = resp.allocation.appFilterPackages,
            // 0.10.0 bugfix: allowedIps was NOT carried over here, so a
            // device kept whatever CIDR list it received at first
            // registration forever. An admin who narrowed a policy saw
            // the console update and the gateway enforce it, while the
            // phone went on routing the old, wider set into the tunnel —
            // traffic the gateway then silently dropped. Rotation is the
            // client's policy refresh cycle; it has to refresh policy.
            allowedIps = resp.allocation.allowedIps,
            policyBound = resp.allocation.policyBound,
            routeScope = resp.allocation.routeScope,
            dnsServers = resp.allocation.dnsServers,
            dnsSearchDomains = resp.allocation.dnsSearchDomains,
            kemEncapKey = resp.allocation.kemEncapKey,
            kemAlgorithm = resp.allocation.kemAlgorithm,
        )
        storage.saveAllocation(updated)
        return updated
    }

    /** Read the cached allocation if a successful Register has happened. */
    fun cached(): StoredAllocation? = storage.loadAllocation()

    fun clear() {
        storage.clearAllocation()
        csrBuilder.delete(CsrBuilder.CURRENT_ALIAS)
        csrBuilder.delete(CsrBuilder.PENDING_ALIAS)
    }

    private fun appVersion(ctx: Context): String =
        try {
            val info = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
            "${info.versionName}+${info.longVersionCode}"
        } catch (_: Exception) {
            "0.0.0+dev"
        }

    /**
     * Fetches a short-lived (5 min) HMAC-signed token that the mobile
     * client presents to the relay server. The token role-prefix is
     * "mob:<device_id>" so the relay can demultiplex and the controller
     * can audit which device opened a relay session.
     *
     * Returns null when the controller doesn't expose the relay
     * endpoint (i.e. RELAY_SIGNING_KEY unset on the server). Callers
     * fall back to direct UDP in that case.
     */
    suspend fun fetchRelayToken(deviceId: String): String? {
        if (!authenticator.isAuthenticated()) return null
        val accessToken = try {
            authenticator.getAccessToken()
        } catch (_: Exception) {
            return null
        }
        return try {
            // Direct REST call rather than via ControllerClient.rpc — this
            // endpoint is path-parameterised (deviceId in URL) which our
            // current rpc dispatch doesn't model.
            controller.relayTokenForDevice(accessToken, deviceId)
        } catch (e: Throwable) {
            android.util.Log.w("AidotVpn/Relay",
                "fetchRelayToken failed (relay disabled?): ${e.message}")
            null
        }
    }
}

@kotlinx.serialization.Serializable
internal data class RelayTokenResponse(
    val token: String,
    @kotlinx.serialization.SerialName("expires_in") val expiresIn: Int = 300,
)
