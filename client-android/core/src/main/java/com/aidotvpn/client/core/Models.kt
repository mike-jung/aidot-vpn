package com.aidotvpn.client.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Wire-shape of the responses we get back from the AidotVpn controller.
//
// We hand-write these instead of generating from the proto schema for
// three reasons:
//
//   1. The controller serves Connect-Web JSON when called from a
//      browser-equivalent client. The wire keys here are snake_case to
//      match that.
//   2. Pulling protoc + the Connect-Go-Kotlin stack into a mobile build
//      adds 1-2 MB of binary size and a long compile dependency for
//      modest payoff at this scale (a handful of RPCs).
//   3. Hand-written models give us room to evolve the wire format
//      without re-running codegen across two languages.
//
// Keep these in sync with proto/aidotvpn/controller/v1/*.proto.

@Serializable
data class RegisterRequest(
    @SerialName("install_id") val installId: String,
    @SerialName("display_name") val displayName: String,
    @SerialName("platform") val platform: String,
    @SerialName("os_version") val osVersion: String = "",
    @SerialName("app_version") val appVersion: String = "",
    @SerialName("model") val model: String = "",
    // Android API level as a number, for the controller's posture check.
    // os_version is a display string and the wrong thing to compare
    // against — a phrasing change here would silently disable the rule.
    @SerialName("os_sdk") val osSdk: Int = 0,
    @SerialName("device_public_key") val devicePublicKey: String,
    @SerialName("attestation_token") val attestationToken: String = "",
    // PEM-encoded PKCS#10 CSR. Phase 5b: every Android client sends this
    // so the controller never needs to generate the mTLS keypair itself.
    @SerialName("client_cert_csr_pem") val clientCertCsrPem: String = "",
    // PEM-encoded Android Key Attestation cert chain. Phase 7+: required
    // when the tenant has require_device_attestation enabled. Empty
    // otherwise (the controller's verifier rejects empty chains in
    // allowlist mode).
    @SerialName("attestation_chain_pem") val attestationChainPem: String = "",
    /**
     * Which shell is registering: "standalone" or "embedded" (0.17.0).
     *
     * A phone running both shells registers twice — install_id is
     * generated per app storage, so the controller sees two devices with
     * the same display name and no way to tell them apart. This field is
     * what makes the duplicate attributable in the console.
     */
    @SerialName("deployment_mode") val deploymentMode: String = "standalone",
    /**
     * The package that hosts the VpnService. In embedded mode that is the
     * business app, not com.aidotvpn.client.app — which also determines
     * which package an MDM Always-on VPN policy must target.
     */
    @SerialName("host_package") val hostPackage: String = "",
    /**
     * Base64 ML-KEM-768 ciphertext, when this device could encapsulate
     * against the tenant key it received last time. Empty means the
     * classical PSK.
     */
    @SerialName("kem_ciphertext") val kemCiphertext: String = "",
)

@Serializable
data class GetAttestationChallengeRequest(val unused: Boolean = true)

@Serializable
data class GetAttestationChallengeResponse(
    /** Hex-encoded 32-byte challenge to bake into KeyGenParameterSpec. */
    @SerialName("challenge_hex") val challengeHex: String,
)

@Serializable
data class RegisterResponse(
    val device: DeviceModel,
    val allocation: AllocationModel,
    val nodes: List<NodeModel> = emptyList(),
)

@Serializable
data class RotateKeyRequest(
    @SerialName("new_device_public_key") val newDevicePublicKey: String,
    @SerialName("attestation_token") val attestationToken: String = "",
    @SerialName("client_cert_csr_pem") val clientCertCsrPem: String = "",
    /**
     * Carried on rotation as well as registration. The hybrid PSK is
     * derived per device-key, so a rotation that omitted this would
     * quietly downgrade a PQ-protected device to the classical PSK at
     * its next 12-hour cycle.
     */
    @SerialName("kem_ciphertext") val kemCiphertext: String = "",
)

@Serializable
data class RotateKeyResponse(
    val allocation: AllocationModel,
)

@Serializable
data class DeviceModel(
    val id: String,
    @SerialName("display_name") val displayName: String,
    val platform: String = "",
    val status: String = "",
    @SerialName("os_version") val osVersion: String = "",
    @SerialName("app_version") val appVersion: String = "",
    @SerialName("created_at") val createdAt: String = "",
    @SerialName("last_seen_at") val lastSeenAt: String? = null,
)

@Serializable
data class AllocationModel(
    @SerialName("device_public_key") val devicePublicKey: String,
    val psk: String,
    @SerialName("psk_source") val pskSource: String = "",
    @SerialName("ipv4_addr") val ipv4Addr: String = "",
    @SerialName("ipv6_addr") val ipv6Addr: String = "",
    @SerialName("client_cert_pem") val clientCertPem: String = "",
    @SerialName("ca_cert_pem") val caCertPem: String = "",
    @SerialName("client_cert_expires_at") val clientCertExpiresAt: String = "",
    /**
     * AllowedIPs for the WireGuard peer. This is the SERVER-SIDE policy
     * decision: which destination CIDRs should the client route through
     * the tunnel?
     *
     *   - For full tunnel: ["0.0.0.0/0", "::/0"]  (default)
     *   - For split tunnel: e.g. ["10.10.0.0/16", "192.168.20.0/24"]
     *     — only those CIDRs route via wg0; everything else uses the
     *     normal default route.
     *
     * Empty list is interpreted as full tunnel for backward compat with
     * pre-Phase-6b servers that don't return this field.
     */
    @SerialName("allowed_ips") val allowedIps: List<String> = emptyList(),
    /**
     * Whether an administrator has actually bound this device to a
     * policy (0.10.0).
     *
     * This exists because "allowedIps is empty" is ambiguous and the two
     * cases need opposite handling:
     *
     *   - Pre-0.10.0 server, field absent → defaults to true, and the
     *     empty allowedIps list keeps its old full-tunnel meaning. An
     *     older controller keeps working exactly as before.
     *
     *   - 0.10.0+ server says false → the device is NOT provisioned.
     *     Falling back to a full tunnel here would be actively harmful:
     *     the gateway's nftables ruleset drops every packet from an
     *     unbound peer, so routing 0.0.0.0/0 into the tunnel would take
     *     the user's entire network connection down rather than just
     *     failing to reach the hospital. The client refuses to connect
     *     instead and says why.
     */
    @SerialName("policy_bound") val policyBound: Boolean = true,
    /**
     * What happens to traffic the policy does not permit (0.12.0).
     *
     *   "policy" (default) — split tunnel. Only [allowedIps] are routed;
     *     other traffic uses the normal network.
     *   "full" — lockdown. Everything is routed into the tunnel and the
     *     gateway drops what the policy disallows, so the tunnelled apps
     *     reach the permitted servers and nothing else.
     *
     * This is orthogonal to [appFilterMode]: that decides WHICH APPS
     * enter the tunnel, this decides what those apps can do once inside.
     * Older servers omit the field and get "policy", which is the
     * pre-0.12.0 behaviour.
     */
    @SerialName("route_scope") val routeScope: String = "policy",
    /**
     * Resolver addresses to use inside the tunnel (0.15.0).
     *
     * The server folds each of these into [allowedIps], so the tunnel
     * always has a route to them. A pushed resolver the tunnel cannot
     * reach produces a device where every lookup times out — which looks
     * like a total outage rather than a misconfiguration.
     *
     * Empty means "leave system DNS alone", the pre-0.15.0 behaviour.
     */
    @SerialName("dns_servers") val dnsServers: List<String> = emptyList(),

    /**
     * Where to reach the controller once the tunnel is up.
     *
     * Present only when the policy says 감추기. Absent means keep using
     * the compiled-in address, which is what an app from before this
     * field does anyway.
     */
    @SerialName("controller_tunnel_url") val controllerTunnelUrl: String = "",
    /** Search domains appended to short names, e.g. ["hospital.local"]. */
    @SerialName("dns_search_domains") val dnsSearchDomains: List<String> = emptyList(),
    /**
     * The tenant's ML-KEM-768 encapsulation key, base64 (0.21.0).
     *
     * Public by construction. Empty when the controller has PQC off, in
     * which case the device keeps the classical PSK.
     *
     * Note the timing: encapsulating against this key affects the NEXT
     * register or rotate, not the allocation it arrived with — that
     * allocation's PSK is already issued.
     */
    @SerialName("kem_encap_key") val kemEncapKey: String = "",
    @SerialName("kem_algorithm") val kemAlgorithm: String = "",
    /**
     * Per-app split tunnel mode (Phase 8). Driven by the admin from
     * the console; snapshot at register/rotate time.
     *
     * Values: "off" (or empty) | "include" | "exclude"
     *   - off     → no per-app filtering
     *   - include → only [appFilterPackages] route through the tunnel
     *   - exclude → all apps EXCEPT [appFilterPackages] route through
     *
     * Pre-Phase-8 servers omit this field; the empty default means
     * "off" so the client behaviour is unchanged.
     */
    @SerialName("app_filter_mode") val appFilterMode: String = "",
    @SerialName("app_filter_packages") val appFilterPackages: List<String> = emptyList(),
    @SerialName("state_token") val stateToken: String = "",
)

@Serializable
data class NodeModel(
    val id: String,
    val region: String,
    @SerialName("public_key") val publicKey: String,
    val endpoints: List<EndpointModel> = emptyList(),
)

@Serializable
data class EndpointModel(
    val id: String,
    val mode: String,
    @SerialName("public_host") val publicHost: String,
    @SerialName("public_port") val publicPort: Int,
    @SerialName("params_json") val paramsJson: String = "",
)

/**
 * Local snapshot of the most-recent registration. We persist this in
 * EncryptedSharedPreferences (see CoreStorage) so the user doesn't have
 * to re-authenticate every time they open the app.
 *
 * What's persisted vs hardware-bound (Phase 5b):
 *   - WG private key: persisted (Curve25519 isn't a Keystore-supported
 *     algorithm; the prefs blob is itself AES-GCM encrypted with a
 *     Keystore-bound master key)
 *   - mTLS private key: NOT persisted. The Keystore alias name is stored
 *     here; the actual key never leaves the Keystore daemon.
 */
@Serializable
data class StoredAllocation(
    /** "virtual=real" pairs, from the policy. Empty for most devices. */
    val virtualHosts: List<String> = emptyList(),
    val deviceId: String,
    val installId: String,
    val ipv4Addr: String,
    val ipv6Addr: String,
    val devicePublicKeyB64: String,
    val devicePrivateKeyB64: String, // Curve25519 32-byte private key
    val pskB64: String,
    val clientCertPem: String,
    /** Alias of the Keystore entry holding the matching private key. */
    val clientCertKeyAlias: String = CsrBuilder.CURRENT_ALIAS,
    val caCertPem: String,
    val clientCertExpiresAt: String,
    val nodes: List<NodeModel>,
    /**
     * Server-driven AllowedIPs (split-tunnel policy). See AllocationModel
     * for the format. Empty list means full tunnel.
     */
    val allowedIps: List<String> = emptyList(),
    /**
     * Whether an admin has bound this device to a policy. See
     * AllocationModel.policyBound. Defaults to true so an allocation
     * persisted by a pre-0.10.0 build keeps working after an app
     * upgrade instead of locking the user out until the next key
     * rotation.
     */
    val policyBound: Boolean = true,
    /** See AllocationModel.routeScope. "policy" (split) or "full" (lockdown). */
    val routeScope: String = "policy",
    /** See AllocationModel.dnsServers. */
    val dnsServers: List<String> = emptyList(),
    val dnsSearchDomains: List<String> = emptyList(),
    /**
     * Tenant encapsulation key from the last allocation, so the next
     * register/rotate can encapsulate without an extra round trip.
     */
    val kemEncapKey: String = "",
    val kemAlgorithm: String = "",
    /**
     * Per-app split tunnel mode (Phase 8). See AllocationModel for the
     * full description. Empty/"off" means no per-app filtering.
     */
    val appFilterMode: String = "",
    val appFilterPackages: List<String> = emptyList(),
    val stateToken: String = "",
)
