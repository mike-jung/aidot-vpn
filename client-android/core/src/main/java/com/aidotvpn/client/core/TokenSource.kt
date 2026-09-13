package com.aidotvpn.client.core

/**
 * Supplies access tokens to [RegistrationFlow].
 *
 * Extracted in 0.11.0 so the registration flow no longer depends on
 * [Authenticator] concretely. That coupling was what made single-APK
 * embedding impossible in practice: `Authenticator` owns an AppAuth
 * `AuthorizationService` and runs its own OIDC browser flow, so an app
 * that had *already* signed the user in had no way to reuse that
 * session. The user signed in twice — once in the business app, once in
 * the VPN app.
 *
 * Two implementations exist:
 *
 *   - [Authenticator] — standalone mode. Runs the full OIDC flow and
 *     refreshes tokens itself.
 *   - [DelegatedTokenSource] — embedded mode. Asks the host app for the
 *     token it already holds.
 */
interface TokenSource {
    /**
     * Returns a currently-valid access token, refreshing if necessary.
     *
     * Implementations must not return an expired token; the controller
     * rejects it and registration surfaces as a generic auth failure
     * that is painful to diagnose from a phone.
     */
    suspend fun getAccessToken(): String

    /**
     * Whether a token is obtainable right now without user interaction.
     *
     * Used by the background key-rotation worker, which must not trigger
     * a sign-in prompt from a WorkManager job — waking a user at 3am with
     * a login screen is not acceptable behaviour, so rotation simply
     * skips a cycle when this is false and retries on the next one.
     */
    fun isAuthenticated(): Boolean
}

/**
 * A [TokenSource] backed by a callback into the host application.
 *
 * The host owns authentication entirely. This class holds no token of
 * its own and persists nothing — every call goes back to [provider], so
 * a host that refreshes its token transparently gets the fresh one
 * without any coordination.
 *
 * ```kotlin
 * val source = DelegatedTokenSource { myAuthManager.currentAccessToken() }
 * ```
 *
 * Return null from [provider] when the user is signed out. Registration
 * then fails with a clear error rather than sending an empty bearer
 * token the controller would reject as malformed.
 */
class DelegatedTokenSource(
    private val provider: suspend () -> String?,
) : TokenSource {

    override suspend fun getAccessToken(): String =
        provider()?.takeIf { it.isNotBlank() }
            ?: throw IllegalStateException(
                "host application returned no access token; is the user signed in?"
            )

    /**
     * Optimistic by design.
     *
     * We cannot inspect the host's session without calling [provider],
     * and [provider] is a suspend function while this is not. Returning
     * true means key rotation will attempt a refresh and fail cleanly if
     * the user is signed out — which is the right trade, because the
     * alternative (returning false) would silently stop rotating keys
     * and let the device's certificate expire.
     */
    override fun isAuthenticated(): Boolean = true
}
