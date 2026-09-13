package com.aidotvpn.client.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * HTTP client to the AidotVpn controller.
 *
 * Two flavours:
 *
 *   * Bearer-token client (used during Register, before we have an mTLS
 *     cert). Authenticates with the OIDC access token only.
 *
 *   * mTLS client (used by RotateKey / ListMyDevices / Revoke after the
 *     initial Register). The client cert + key were issued by the
 *     controller and live in CoreStorage.
 *
 * The controller speaks Connect-Web JSON (gRPC over HTTP/1.1 with JSON
 * bodies). We POST to the RPC URL with the request message as JSON
 * and read the JSON response back. This mirrors what the admin console
 * does in the browser.
 *
 * If the user runs `buf generate --template buf.gen.connect-kotlin.yaml`
 * later, we can swap this hand-rolled client for the generated stubs.
 */
class ControllerClient(
    // @PublishedApi internal — these are referenced by the public `inline
    // fun rpc(...)` below, so Kotlin 2.0+ requires they be at least
    // `internal` (private would leak into callers' bytecode). The
    // @PublishedApi annotation tells the compiler we accept that
    // tradeoff intentionally; the practical visibility stays
    // module-internal because nothing outside `:core` references them.
    @PublishedApi internal val baseUrl: String,
) {
    @PublishedApi internal val json = Json {
        ignoreUnknownKeys = true
        // A null where a List is declared falls back to the default
        // instead of throwing.
        //
        // Go serialises a nil slice as `null`, and 1.4.2 fixed the
        // server to send [] — but a client that dies on a null array is
        // one bad deploy away from unusable, and the failure it produces
        // names an offset rather than a cause:
        //
        //   Expected start of the array '[', but had 'n' instead
        //   at path: $.allocation.dns_search_domains
        //
        // Belt and braces on purpose: the server should not send null,
        // and the app should survive it.
        coerceInputValues = true
    }

    /** Bearer-token client — used pre-Register only. */
    fun bearerClient(accessToken: String): OkHttpClient =
        baseClientBuilder()
            .addInterceptor { chain ->
                val req = chain.request().newBuilder()
                    .header("Authorization", "Bearer $accessToken")
                    .build()
                chain.proceed(req)
            }
            .build()

    /**
     * Calls POST /devices/{id}/relay-token with the user's bearer
     * token. Returns the relay JWT-like token, or throws on HTTP errors.
     *
     * Lives outside the generic `rpc()` helper because the path is
     * parameterised (no static method-name mapping), and because the
     * request body is empty — the deviceId is in the URL.
     */
    suspend fun relayTokenForDevice(accessToken: String, deviceId: String): String =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            val client = bearerClient(accessToken)
            val httpReq = okhttp3.Request.Builder()
                .url("${baseUrl.trimEnd('/')}/devices/$deviceId/relay-token")
                .post(okhttp3.RequestBody.create(JSON_MEDIA_TYPE, ByteArray(0)))
                .build()
            client.newCall(httpReq).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                if (!resp.isSuccessful) {
                    throw ControllerException(resp.code, text)
                }
                json.decodeFromString<com.aidotvpn.client.core.RelayTokenResponse>(text).token
            }
        }

    /**
     * mTLS client — used after Register. The client cert + private key
     * were issued by the controller's CA and are paired with the same
     * device key the WireGuard tunnel uses. The CA cert pins the
     * controller end of the connection.
     */
    fun mtlsClient(
        clientCertPem: String,
        clientKeyPem: String,
        caCertPem: String,
    ): OkHttpClient {
        val cf = CertificateFactory.getInstance("X.509")
        val clientCert = cf.generateCertificate(
            ByteArrayInputStream(clientCertPem.toByteArray()),
        ) as X509Certificate
        val caCert = cf.generateCertificate(
            ByteArrayInputStream(caCertPem.toByteArray()),
        ) as X509Certificate

        val privateKey = parsePkcs8PrivateKey(clientKeyPem)

        return mtlsClientWithKey(clientCert, privateKey, caCert)
    }

    /**
     * Phase 5b mTLS client. The private key lives inside Android Keystore
     * (alias [keystoreAlias]); we never see the key bytes. The cert was
     * minted by the controller from a CSR we built earlier.
     */
    fun mtlsClientFromKeystore(
        clientCertPem: String,
        keystoreAlias: String,
        caCertPem: String,
    ): OkHttpClient {
        val cf = CertificateFactory.getInstance("X.509")
        val clientCert = cf.generateCertificate(
            ByteArrayInputStream(clientCertPem.toByteArray()),
        ) as X509Certificate
        val caCert = cf.generateCertificate(
            ByteArrayInputStream(caCertPem.toByteArray()),
        ) as X509Certificate

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = ks.getEntry(keystoreAlias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("no Keystore entry under $keystoreAlias")
        return mtlsClientWithKey(clientCert, entry.privateKey, caCert)
    }

    private fun mtlsClientWithKey(
        clientCert: X509Certificate,
        privateKey: java.security.PrivateKey,
        caCert: X509Certificate,
    ): OkHttpClient {
        // Trust store: the AidotVpn CA only.
        val trustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("aidotvpn-ca", caCert)
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(trustStore) }
        val trustManager = tmf.trustManagers.first { it is X509TrustManager } as X509TrustManager

        // Key store: the client cert + private key.
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry(
                "aidotvpn-client",
                privateKey,
                CHAR_ARRAY_EMPTY,
                arrayOf<java.security.cert.Certificate>(clientCert),
            )
        }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            .apply { init(keyStore, CHAR_ARRAY_EMPTY) }

        val sslContext = SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, arrayOf(trustManager), java.security.SecureRandom())
        }

        return baseClientBuilder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .build()
    }

    suspend inline fun <reified Req, reified Res> rpc(
        client: OkHttpClient,
        method: String,
        request: Req,
    ): Res = withContext(Dispatchers.IO) {
        // Map the legacy gRPC-style method name to its REST path on the
        // controller. The controller exposes a hand-rolled REST API
        // (internal/httpapi) rather than Connect-RPC because the admin
        // console is plain fetch and the Android client is small enough
        // to not need typed protobuf stubs. The method name → path
        // mapping kept here keeps callers (RegistrationFlow) ergonomic
        // — they still write rpc("Register", ...) — while the wire
        // format is REST.
        val path = when (method) {
            "Register"                -> "/devices/register"
            "RotateKey"               -> "/devices/rotate-key"
            "GetAttestationChallenge" -> "/devices/attestation-challenge"
            else -> error("ControllerClient: unknown RPC method '$method'")
        }
        val body = json.encodeToString(request).toRequestBody(JSON_MEDIA_TYPE)
        val httpReq = Request.Builder()
            .url("${baseUrl.trimEnd('/')}$path")
            .post(body)
            .build()
        client.newCall(httpReq).execute().use { resp ->
            val text = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) {
                throw ControllerException(resp.code, text)
            }
            json.decodeFromString<Res>(text)
        }
    }

    private fun baseClientBuilder(): OkHttpClient.Builder =
        OkHttpClient.Builder()
            // Route every controller socket around an active wg0 tunnel
            // via VpnService.protect(). When no VpnService is registered
            // (register-time RPCs, or non-VPN consumers of :core), this
            // is a no-op — sockets use the default network normally.
            // See SocketProtector.kt for the full rationale.
            .socketFactory(ProtectingSocketFactory())
            .connectTimeout(java.time.Duration.ofSeconds(15))
            .readTimeout(java.time.Duration.ofSeconds(30))
            .callTimeout(java.time.Duration.ofSeconds(45))

    companion object {
        val JSON_MEDIA_TYPE = "application/json".toMediaType()
        val CHAR_ARRAY_EMPTY = CharArray(0)
    }
}

class ControllerException(
    val httpStatus: Int,
    val responseBody: String,
) : Exception("controller HTTP $httpStatus: ${responseBody.take(500)}")

/**
 * Decode a PEM-wrapped PKCS#8 private key (the format the controller
 * issues). Returns a [java.security.PrivateKey] suitable for use with
 * KeyManagerFactory.
 */
internal fun parsePkcs8PrivateKey(pem: String): java.security.PrivateKey {
    val b64 = pem
        .lineSequence()
        .filterNot { it.startsWith("-----") }
        .joinToString("")
    val der = android.util.Base64.decode(b64, android.util.Base64.DEFAULT)
    val keySpec = java.security.spec.PKCS8EncodedKeySpec(der)
    // The controller currently issues ECDSA P-256 keys. If the format
    // changes we'll inspect the PEM header instead of hard-coding "EC".
    return java.security.KeyFactory.getInstance("EC").generatePrivate(keySpec)
}
