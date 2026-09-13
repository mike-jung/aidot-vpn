package com.aidotvpn.client.vpnlib

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.net.VpnService
import android.util.Log
import com.aidotvpn.client.core.CoreStorage
import com.aidotvpn.client.core.EnrollmentRequestClient
import com.aidotvpn.client.core.DelegatedTokenSource
import com.aidotvpn.client.core.RegistrationFlow
import com.aidotvpn.client.core.StoredAllocation
import kotlinx.coroutines.flow.StateFlow

/**
 * Public entry point for apps that embed the VPN engine directly
 * (single-APK deployment).
 *
 * This is the embedded-mode counterpart to [com.aidotvpn.client.sdk.AidotVpnSDK],
 * which drives a separately-installed standalone app over AIDL. Same
 * engine underneath; the difference is who hosts the VpnService.
 *
 * Typical integration — the business app already signed the user in
 * against the same Keycloak realm and holds an access token:
 *
 * ```kotlin
 * val engine = AidotVpnEngine.get(context, "https://vpn.example.com")
 *
 * // 1. Once per install (and after a token refresh), register the device.
 * engine.registerWithToken(accessToken)
 *
 * // 2. First run only: the OS consent dialog.
 * engine.prepareIntent()?.let { startActivityForResult(it, RC_VPN) }
 *
 * // 3. Connect. Safe to call on every login.
 * engine.connect()
 * ```
 *
 * ### Why token delegation exists
 *
 * In standalone mode the user signs in twice: once in the business app,
 * once in the AidotVpn app's own OIDC flow. There was no way to hand a
 * token across — the SDK exposed only `connect()`. Embedding removes the
 * second login entirely, because the engine runs inside the app that
 * already has the token.
 *
 * The token is used immediately to call the controller and is never
 * persisted by this class; what gets stored is the resulting allocation
 * (in the Keystore-backed encrypted prefs that [CoreStorage] owns).
 *
 * ### What this class does NOT do
 *
 * It does not sign the user in. The host app owns authentication. If you
 * want the engine to run its own OIDC flow, use the standalone app.
 */
class AidotVpnEngine private constructor(
    private val appContext: Context,
    private val controllerUrl: String,
) {

    /**
     * The tunnel engine.
     *
     * Internal rather than private: AidotVpnService needs it, and it
     * previously reached for `AidotVpnApplication.get().tunnelManager`
     * — a class in :app. That made :vpnlib compile only when :app was in
     * the build, which is the opposite of what a library module is for
     * and would fail outright in an embedding business app.
     */
    internal val tunnelManager: TunnelManager by lazy { TunnelManager(appContext) }

    /**
     * Apply the stored allocation to a running tunnel.
     *
     * For a policy that changed while connected. The interface stays up
     * and no handshake repeats — the alternative was disconnecting and
     * connecting again, which is how 연결 quietly became the way to
     * apply a policy change, a job that button should never have had.
     *
     * Does nothing when no tunnel is up; the next connect reads the
     * stored allocation anyway.
     */
    suspend fun applyStoredConfig(): Result<Unit> = tunnelManager.applyConfig()

    /**
     * A condition the tunnel worked around, for the host app to show.
     *
     * Exposed here rather than through [tunnelManager], which is
     * internal on purpose — a consumer of this library should not reach
     * into the manager to read one field, and doing so compiled only
     * because the check harness builds all three modules together where
     * `internal` does not apply.
     */
    val tunnelWarning: StateFlow<String?> get() = tunnelManager.lastWarning

    /**
     * Bytes (received, sent) on the tunnel, or null when the backend
     * cannot say. Received == 0 with sent > 0 is a handshake nobody
     * answered — the one fact 연결됨 cannot convey.
     */
    fun statistics(): Pair<Long, Long>? = tunnelManager.statistics()

    /**
     * Bytes (received, sent) on the tunnel, or null when unavailable.
     *
     * Public so a host app can tell "interface up" from "peer answered":
     * sent > 0 with received == 0 is a handshake nobody replied to,
     * which 연결됨 does not distinguish.
     */
    fun tunnelStatistics(): Pair<Long, Long>? = tunnelManager.statistics()

    /**
     * The host app's token provider, remembered from registration.
     *
     * Key rotation runs on a WorkManager schedule with no UI and no way
     * to ask the host for a token at that moment, so the callback given
     * at registration is kept and reused.
     *
     * Held in memory only. After a process restart it is null and
     * rotation is skipped until the host registers again — deliberate:
     * persisting a token-minting callback is not something a library
     * should do on an app's behalf, and the host is the only party that
     * knows whether its session is still valid.
     */
    @Volatile
    private var tokenProvider: (suspend () -> String?)? = null

    /**
     * Supply a token provider outside of registration.
     *
     * Necessary because key rotation runs on a WorkManager schedule that
     * wakes a **dead process**: nothing has called [register] in it, so
     * the provider captured there is null and rotation silently does
     * nothing. Every 12 hours, forever — the failure is invisible
     * because `Result.success()` is the honest answer to "was there
     * anything to do".
     *
     * A host that wants rotation to keep working across process death
     * calls this from `Application.onCreate`:
     *
     * ```kotlin
     * class MyApp : Application() {
     *     override fun onCreate() {
     *         super.onCreate()
     *         AidotVpnEngine.get(this, BuildConfig.CONTROLLER_URL)
     *             .setTokenProvider { myAuth.currentAccessTokenOrNull() }
     *     }
     * }
     * ```
     *
     * The callback must tolerate being invoked with no user present and
     * return null when the session is gone — rotation then skips, which
     * is correct. Persisting the token itself is deliberately not offered:
     * a library storing a credential on an app's behalf is the app's
     * decision to make, not ours.
     */
    fun setTokenProvider(provider: suspend () -> String?) {
        tokenProvider = provider
    }

    /** Current tunnel state. Safe to collect from the UI. */
    val state: StateFlow<TunnelState> get() = tunnelManager.state

    /** The saved allocation, or null when this device has never registered. */
    fun allocation(): StoredAllocation? = CoreStorage.get(appContext).loadAllocation()

    /**
     * Discard this device's registration.
     *
     * For the case where the controller has revoked it: the allocation
     * is dead, the app cannot use it, and keeping it leaves the UI on a
     * stage it has no way to leave. Disconnects first — a tunnel running
     * on credentials the server has revoked is worse than no tunnel.
     */
    fun forgetAllocation() {
        disconnect()
        CoreStorage.get(appContext).clearAllocation()
    }

    /** True once the device has an allocation and an admin has bound a policy. */
    fun isProvisioned(): Boolean = allocation()?.policyBound == true

    /**
     * Register (or re-register) this device using an access token the
     * host app already holds.
     *
     * Call this after your own sign-in completes. It is idempotent in
     * practice: re-registering an existing install_id returns the same
     * device with a refreshed allocation, which is also how a device
     * picks up policy changes between key rotations.
     */
    @JvmOverloads
    suspend fun registerWithToken(
        accessToken: String,
        displayName: String = android.os.Build.MODEL ?: "Android device",
    ): Result<StoredAllocation> = runCatching {
        require(accessToken.isNotBlank()) { "accessToken must not be blank" }
        registrationFlow { accessToken }.register(displayName)
    }

    /**
     * Register using a callback the engine can re-invoke later.
     *
     * Prefer this over [registerWithToken] when your app refreshes
     * tokens: a captured string goes stale, whereas the callback is
     * asked again each time a token is needed — including by the
     * background key-rotation worker hours later.
     */
    @JvmOverloads
    suspend fun register(
        tokenProvider: suspend () -> String?,
        displayName: String = android.os.Build.MODEL ?: "Android device",
    ): Result<StoredAllocation> = runCatching {
        this.tokenProvider = tokenProvider
        registrationFlow(tokenProvider).register(displayName)
    }

    /**
     * Register with a one-time grant from an approved enrollment request.
     *
     * The grant is exchanged for a short-lived access token, then
     * registration runs on exactly the path [registerWithToken] uses.
     * Approval decides whether a device may register; it does not become
     * a second way to obtain an allocation.
     */
    suspend fun registerWithEnrollmentToken(
        grant: String,
        displayName: String = android.os.Build.MODEL ?: "Android device",
    ): Result<StoredAllocation> = runCatching {
        require(grant.isNotBlank()) { "grant must not be blank" }
        // The exchange endpoint validates and burns the grant, returning
        // the tenant and policy it carried. The registration that follows
        // is ordinary.
        registrationFlow { grant }.register(displayName)
    }

    /**
     * A well-formed public key for the enrollment request.
     *
     * The request records intent, not key material: the real keypair is
     * generated during registration, after approval. The controller
     * validates the field is base64 of the right length, so this supplies
     * something that parses rather than leaving it empty and teaching the
     * server to accept blanks.
     */
    fun placeholderPublicKeyB64(): String {
        val b = ByteArray(32)
        java.security.SecureRandom().nextBytes(b)
        return android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP)
    }

    private fun registrationFlow(tokenProvider: suspend () -> String?) =
        RegistrationFlow(
            context = appContext,
            // This class only ever runs inside a host app that embeds the
            // engine, so the mode is fixed here rather than passed in —
            // an integrator cannot get it wrong.
            deploymentMode = "embedded",
            authenticator = DelegatedTokenSource(tokenProvider),
            // Settings may change after this process-wide engine was created.
            // Enrollment and the final Register must use the saved address.
            controllerBaseUrl = CoreStorage.get(appContext).loadControllerUrl() ?: controllerUrl,
        )

    /**
     * Returns the OS consent Intent, or null when consent was already
     * granted.
     *
     * This cannot be avoided or automated: Android requires a
     * user-visible confirmation before any app may hold a VpnService, and
     * it must be launched from an Activity. Call it once, right after
     * login; subsequent connects return null here.
     *
     * For fleet deployments, provisioning the app as an Always-on VPN
     * through Android Enterprise removes the prompt entirely and is the
     * better answer for a hospital.
     */
    fun prepareIntent(): Intent? = VpnService.prepare(appContext)

    /**
     * Enrol this device: request, wait for an admin, register.
     *
     * The three steps have always existed and every caller had to
     * assemble them — demo-app does it across fifty lines of its
     * ViewModel, and sample-app was written against an `enroll` that
     * did not exist because that is the shape a caller expects. An app
     * that only needs "get me registered" should not have to know that
     * approval is a separate round trip.
     *
     * Suspends until an admin decides or the wait times out.
     * [onWaiting] is called once the request is in, with the code the
     * console shows, so a caller can put it on screen while waiting.
     */
    suspend fun enroll(
        displayName: String,
        password: String,
        onWaiting: (String) -> Unit = {},
    ): Result<StoredAllocation> {
        val base = CoreStorage.get(appContext).loadControllerUrl() ?: controllerUrl
        val client = EnrollmentRequestClient(base)
        val installId = CoreStorage.get(appContext).installId()
        val created = client
            .request(password, installId, displayName, placeholderPublicKeyB64())
            .getOrElse { return Result.failure(it) }

        onWaiting(created.verificationCode)

        val decided = client.awaitDecision(created.id).getOrElse {
            return Result.failure(it)
        }
        return when (decided.status) {
            "approved" ->
                registerWithEnrollmentToken(decided.enrollmentToken, displayName)
            "rejected" ->
                Result.failure(IllegalStateException("관리자가 등록을 거절했습니다."))
            else ->
                Result.failure(IllegalStateException("승인을 받지 못했습니다: ${decided.status}"))
        }
    }

    /**
     * Bring the tunnel up.
     *
     * Fails fast when the device has no policy bound — see
     * [TunnelManager.start]. Connecting an unprovisioned device would
     * produce a tunnel the gateway drops everything from.
     */
    fun connect(): Result<Unit> {
        val prepare = prepareIntent()
        if (prepare != null) {
            Log.w(TAG, "connect() called before VPN consent was granted")
            return Result.failure(
                VpnConsentRequiredException(
                    "VPN consent not granted; launch prepareIntent() from an Activity first"
                )
            )
        }
        // Refuse before starting anything when there is nothing to
        // connect with.
        //
        // TunnelManager already handles this, but by then the service is
        // running and the failure surfaces as a notification that appears
        // and vanishes. Checking here means the caller gets a Result it
        // can show.
        if (allocation() == null) {
            return Result.failure(
                IllegalStateException("아직 등록되지 않았습니다. 먼저 기기를 등록하세요."),
            )
        }

        // startForegroundService, not startService.
        //
        // Since API 26 a backgrounded app cannot start a service the old
        // way. The VPN consent dialog backgrounds the activity, so the
        // call that follows the user tapping 확인 lands in exactly that
        // state and throws:
        //
        //   IllegalStateException: Not allowed to start service …
        //   app is in background
        //
        // which killed the app — screen gone, no notification, nothing to
        // read. The service then has five seconds to call startForeground,
        // which onStartCommand does first thing.
        val intent = Intent(appContext, AidotVpnService::class.java)
            .setAction(AidotVpnService.ACTION_CONNECT)
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                appContext.startForegroundService(intent)
            } else {
                appContext.startService(intent)
            }
            Unit
        }
    }

    /** Tear the tunnel down. */
    fun disconnect(): Result<Unit> {
        appContext.startService(
            Intent(appContext, AidotVpnService::class.java)
                .setAction(AidotVpnService.ACTION_DISCONNECT)
        )
        return Result.success(Unit)
    }

    /**
     * Start the background key-rotation worker.
     *
     * Rotation is also the client's policy refresh cycle — each rotation
     * pulls a fresh allocation, so an admin's policy change reaches the
     * device here. Call once from your Application.onCreate.
     */
    fun startKeyRotation() = KeyRotationWorker.schedule(appContext)

    /**
     * Rotate the device key if a token provider is available.
     *
     * Returns false when there is nothing to do — no provider, or the
     * host's session has expired and the callback returns null. Both are
     * ordinary states, not errors: the schedule tries again later, and
     * the classical/hybrid PSK in force stays valid until it does.
     */
    internal suspend fun rotateKeyIfPossible(): Boolean {
        val provider = tokenProvider ?: return false
        if (provider() == null) return false
        registrationFlow(provider).rotateKey()
        return true
    }

    /** Raised by [connect] when OS consent has not been granted yet. */
    class VpnConsentRequiredException(message: String) : IllegalStateException(message)

    companion object {
        private const val TAG = "AidotVpnEngine"

        @Volatile
        private var instance: AidotVpnEngine? = null

        /**
         * Returns the process-wide engine.
         *
         * A singleton because the underlying VpnService is: two engine
         * instances would fight over one tunnel, and the second
         * connect() would revoke the first.
         *
         * [controllerUrl] is read on first call and ignored afterwards.
         * Pass it from your own BuildConfig — :vpnlib deliberately has no
         * buildConfigField of its own so that the embedding app controls
         * which controller it talks to.
         */
        @JvmStatic
        fun get(context: Context, controllerUrl: String? = null): AidotVpnEngine =
            instance ?: synchronized(this) {
                instance ?: run {
                    val app = context.applicationContext

                    // Resolve the URL: caller's value first, then the one
                    // persisted at first initialisation.
                    //
                    // The fallback exists because the VpnService is
                    // START_STICKY. Android restarts it into a FRESH
                    // PROCESS after a reboot or a low-memory kill, with
                    // no Activity having run — so the singleton is null
                    // and the service's `get(applicationContext)` has no
                    // URL to offer. Before 0.28.2 that hit `error()` and
                    // crashed the service on the exact path START_STICKY
                    // exists to support.
                    //
                    // The URL is written on the first successful
                    // initialisation, so the only case that still throws
                    // is a genuinely first-ever call with no argument —
                    // which is an integration mistake and should throw.
                    val url = controllerUrl
                        ?: CoreStorage.get(app).loadControllerUrl()
                        ?: error(
                            "AidotVpnEngine.get() needs controllerUrl on first call " +
                                "(none was passed and none is stored)",
                        )

                    AidotVpnEngine(app, url).also {
                        instance = it
                        if (controllerUrl != null) {
                            CoreStorage.get(app).saveControllerUrl(url)
                        }
                    }
                }
            }

        /**
         * Convenience for an Activity result callback.
         *
         * ```kotlin
         * override fun onActivityResult(rc: Int, result: Int, data: Intent?) {
         *     if (rc == RC_VPN && AidotVpnEngine.isConsentGranted(result)) {
         *         AidotVpnEngine.get(this).connect()
         *     }
         * }
         * ```
         */
        @JvmStatic
        fun isConsentGranted(resultCode: Int): Boolean = resultCode == Activity.RESULT_OK
    }
}
