package com.aidotvpn.client.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

/**
 * Device-initiated enrolment.
 *
 * The app used to ask for an access token pasted in by hand — 38
 * characters with no way to get them onto a phone. Now it asks the
 * controller to enrol, shows six digits, and waits for an admin to
 * confirm those digits against the handset.
 *
 * ## Unauthenticated, necessarily
 *
 * A phone being enrolled has no session yet; that is the situation. The
 * shared password on the way in keeps a stranger on the wifi out of the
 * queue, and the admin's comparison on the way out is the actual
 * authorisation. Only the second is load-bearing, which is why this
 * client holds no credential and returns none.
 */
class EnrollmentRequestClient(
    private val baseUrl: String,
    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        // Longer than the longest long poll (30s) plus slack. Too short
        // and the client aborts its own wait, which looks like the server
        // failing to answer.
        .readTimeout(45, TimeUnit.SECONDS)
        .socketFactory(ProtectingSocketFactory())
        .build(),
) {
    private val json = Json {
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
    private val jsonType = "application/json".toMediaType()

    @Serializable
    private data class CreateReq(
        val password: String,
        @SerialName("install_id") val installId: String,
        @SerialName("display_name") val displayName: String,
        val platform: String = "android",
        @SerialName("device_public_key") val devicePublicKey: String,
    )

    @Serializable
    data class Created(
        val id: String,
        @SerialName("verification_code") val verificationCode: String,
        @SerialName("expires_at") val expiresAt: String = "",
    )

    @Serializable
    data class Status(
        val status: String,
        /**
         * The one-time grant, present exactly once after approval.
         *
         * The device registers with it through the normal path. Approval
         * decides; it does not become a second way to get an allocation.
         */
        @SerialName("enrollment_token") val enrollmentToken: String = "",
    )

    /** Ask to enrol. Returns the request id and the code to display. */
    suspend fun request(
        password: String,
        installId: String,
        displayName: String,
        devicePublicKeyB64: String,
    ): Result<Created> = withContext(Dispatchers.IO) {
        runCatching {
            val body = json.encodeToString(
                CreateReq(
                    password = password,
                    installId = installId,
                    displayName = displayName,
                    devicePublicKey = devicePublicKeyB64,
                ),
            ).toRequestBody(jsonType)

            val req = Request.Builder()
                .url("$baseUrl/enrollment-requests")
                .post(body)
                .build()

            http.newCall(req).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                if (!resp.isSuccessful) {
                    // Show what the controller said.
                    //
                    // It answers in Korean and names the cause — "등록
                    // 비밀번호가 올바르지 않습니다", "install_id 와
                    // device_public_key 가 필요합니다". Replacing that with
                    // "등록 요청 실패 (400)" throws away the only part an
                    // operator can act on, which is what this did.
                    error(errorMessage(text) ?: "등록 요청 실패 (${resp.code})")
                }
                json.decodeFromString<Created>(text)
            }
        }
    }

    /**
     * The controller's `{"error": "…"}`, when there is one.
     *
     * Parsed leniently: a proxy or a crash can return HTML, and failing
     * to read an error body should not replace the error with a parse
     * error.
     */
    private fun errorMessage(body: String): String? = runCatching {
        json.decodeFromString<ErrorBody>(body).error.takeIf { it.isNotBlank() }
    }.getOrNull()

    @Serializable
    private data class ErrorBody(val error: String = "")

    /**
     * Ask for the decision, optionally holding the connection open.
     *
     * `waitSeconds` turns this into a long poll: the controller answers
     * the moment an admin decides — measured at 8ms after the click —
     * instead of on this side's next tick. Both people are watching the
     * phone at that moment, which is the one situation where three
     * seconds is noticed.
     *
     * Zero means answer immediately, which is what a one-off status check
     * wants.
     */
    suspend fun status(requestId: String, waitSeconds: Int = 0): Result<Status> = withContext(Dispatchers.IO) {
        runCatching {
            val url = if (waitSeconds > 0) {
                "$baseUrl/enrollment-requests/$requestId/status?wait=$waitSeconds"
            } else {
                "$baseUrl/enrollment-requests/$requestId/status"
            }
            val req = Request.Builder()
                .url(url)
                .get()
                .build()
            http.newCall(req).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                if (!resp.isSuccessful) error("상태 확인 실패 (${resp.code})")
                json.decodeFromString<Status>(text)
            }
        }
    }

    /**
     * Poll until the request is decided or the window closes.
     *
     * Three seconds, because an admin approving while the operator
     * watches should see the phone change within a breath — and the
     * server side of this is a single indexed row read, so the cost is
     * not the concern. Stops on any terminal state rather than only on
     * approval, so a rejection surfaces instead of spinning for ten
     * minutes.
     */
    suspend fun awaitDecision(
        requestId: String,
        timeoutMs: Long = 10 * 60 * 1000,
        // Only used after a failure. A successful call already waited on
        // the server, so there is nothing to sleep off.
        intervalMs: Long = 3_000,
        onTick: (String) -> Unit = {},
        onError: (String, Int) -> Unit = { _, _ -> },
    ): Result<Status> {
        val deadline = System.currentTimeMillis() + timeoutMs
        var failures = 0
        while (System.currentTimeMillis() < deadline) {
            // getOrNull, not getOrElse { … continue }.
            //
            // `continue` inside an inline lambda needs Kotlin 2.2; this
            // project is on 2.1.20, and the error only appears at build
            // time in Gradle:
            //
            //   The feature "break continue in inline lambdas" is only
            //   available since language version 2.2
            //
            // A transient network failure mid-wait is not a decision, so
            // the loop keeps going and the deadline is the exit.
            // 30s per call: long enough that an approval arrives on the
            // open connection, short enough that proxies and mobile
            // networks do not drop it as idle.
            val attempt = status(requestId, waitSeconds = 30)
            val s = attempt.getOrNull()
            if (s == null) {
                // Report the failure rather than swallowing it.
                //
                // The first version kept polling and said nothing, so a
                // controller that had become unreachable looked identical
                // to an admin who had not decided yet — for ten minutes.
                // The caller decides whether one failed poll matters;
                // this loop only decides whether to keep trying.
                failures += 1
                onError(attempt.exceptionOrNull()?.message ?: "서버에 연결할 수 없습니다", failures)
                delay(intervalMs)
                continue
            }
            failures = 0
            onTick(s.status)
            if (s.status != "pending") return Result.success(s)
            delay(intervalMs)
        }
        return Result.failure(IllegalStateException("시간이 초과되었습니다. 다시 요청하세요."))
    }
}

class StateAuthenticationException(message: String) : IllegalStateException(message)

/**
 * Device-local state authenticated with the dedicated registration credential.
 * Approval-enrolled devices do not need an OIDC session for this read.
 * Missing or rejected credentials are distinct from network failures.
 */
class DeviceStateClient(
    private val baseUrl: String,
    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .socketFactory(ProtectingSocketFactory())
        .build(),
    private val stateToken: String = "",
) {
    private val json = Json {
        ignoreUnknownKeys = true
        coerceInputValues = true
    }

    @Serializable
    data class State(
        val status: String = "",
        @SerialName("policy_bound") val policyBound: Boolean = false,
        /**
         * Where this device may go, as the controller sees it now.
         *
         * The stored allocation holds the list from registration. An
         * admin editing a policy afterwards changes this and not that,
         * so a refresh has to ask rather than re-read.
         */
        @SerialName("allowed_ips") val allowedIps: List<String> = emptyList(),
        @SerialName("route_scope") val routeScope: String = "policy",
        @SerialName("dns_servers") val dnsServers: List<String>? = null,
        @SerialName("dns_search_domains") val dnsSearchDomains: List<String>? = null,
        @SerialName("app_filter_mode") val appFilterMode: String? = null,
        @SerialName("app_filter_packages") val appFilterPackages: List<String>? = null,

        /**
         * Where the gateway is now. Empty from an older controller.
         *
         * Stored at registration and never re-read until 1.7.24, which
         * left every enrolled phone knocking on the address it had first
         * been told — including a seed address that exists only inside
         * the Android emulator.
         */
        @SerialName("nodes") val nodes: List<NodeModel> = emptyList(),

        /** Virtual → real, for explaining a probe against a virtual address. */
        @SerialName("virtual_hosts") val virtualHosts: List<VirtualHost> = emptyList(),
    )

    @Serializable
    data class VirtualHost(
        @SerialName("virtual") val virtual: String,
        @SerialName("real") val real: String,
    )

    /**
     * Returns null when the controller could not be reached.
     *
     * Null and "revoked" must stay distinguishable: treating an
     * unreachable server as a revocation would wipe a working device's
     * stage every time the wifi dropped.
     */
    suspend fun fetch(deviceId: String): State? = fetchResult(deviceId).getOrNull()

    /**
     * Same call, with the reason on failure.
     *
     * fetch() returned null for every failure — a 404, a refused
     * connection, a JSON mismatch — and the app then said "서버에 연결할
     * 수 없어" for all of them. A user reading that with the controller
     * plainly up had no way to learn which it was, and neither did I
     * reading the code. The reason has to survive to the screen.
     */
    suspend fun fetchResult(deviceId: String): Result<State> = withContext(Dispatchers.IO) {
        runCatching {
            if (stateToken.isBlank()) throw StateAuthenticationException("저장된 등록 정보에 상태 인증 정보가 없습니다. '다시 등록하기'로 관리자 승인을 받아주세요.")
            val req = Request.Builder()
                .url("$baseUrl/devices/$deviceId/state")
                .header("Authorization", "Bearer $stateToken")
                .get()
                .build()
            http.newCall(req).execute().use { resp ->
                val text = resp.body?.string().orEmpty()
                if (resp.code == 401 || resp.code == 403) throw StateAuthenticationException("상태 API 인증이 거부되었습니다. 다시 등록하세요.")
                if (!resp.isSuccessful) {
                    error("HTTP ${resp.code} from $baseUrl (devices/state)")
                }
                json.decodeFromString<State>(text)
            }
        }.recoverCatching { e ->
            if (e is kotlinx.coroutines.CancellationException || e is StateAuthenticationException) throw e
            // Name the failure class, because "connection refused" and
            // "unknown host" call for different fixes.
            throw IllegalStateException(
                "${e::class.simpleName}: ${e.message ?: "(no message)"}", e,
            )
        }
    }
}
