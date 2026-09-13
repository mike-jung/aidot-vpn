package com.aidotvpn.demo

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aidotvpn.client.core.CoreStorage
import com.aidotvpn.client.core.DeviceStateClient
import com.aidotvpn.client.core.EnrollmentRequestClient
import com.aidotvpn.client.vpnlib.AidotVpnEngine
import com.aidotvpn.client.vpnlib.TunnelState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn

/**
 * State for the demo app.
 *
 * The app has one job beyond connecting: show the reader *why* the tunnel
 * behaves the way it does. So alongside the connection state it carries
 * the server's own account of this device's configuration — the
 * `/devices/{id}/effective` response — and pairs it with live reachability
 * results.
 *
 * Seeing "route_scope: full" next to "바깥 인터넷 → 응답 없음" is what
 * turns a confusing failure into an understood one.
 */
class DemoViewModel(app: Application) : AndroidViewModel(app) {

    /**
     * The controller's address, editable.
     *
     * Compiled in from gradle.properties, which meant every move of the
     * controller needed a rebuild — and a phone with the old address
     * connected on its stored policy and warned, correctly, that it
     * could not ask the server. The stored value wins; the build
     * constant is what a fresh install starts with.
     */
    private val _controllerUrl = MutableStateFlow(
        CoreStorage.get(app).loadControllerUrl() ?: BuildConfig.CONTROLLER_URL,
    )
    val controllerUrl: StateFlow<String> = _controllerUrl.asStateFlow()

    /** Every controller call goes through here, so a change lands everywhere. */
    private val ctl: String get() = _controllerUrl.value

    fun setControllerUrl(url: String) {
        val trimmed = url.trim().trimEnd('/')
        if (trimmed.isBlank()) return
        CoreStorage.get(getApplication()).saveControllerUrl(trimmed)
        _controllerUrl.value = trimmed
        _addressMismatch.value = null
        invalidateServerState()
        // It applies now, not next time. The old wording was written when
        // the address was only read at startup; since 1.10.0 every call
        // goes through `ctl`, so the next poll — seconds away — uses it.
        // Telling someone to restart for a change that already happened
        // sends them to do something pointless and doubt the one thing
        // that did work.
        say("서버 주소를 $trimmed 로 바꿨습니다. 바로 적용됩니다.")
        refreshServerState()
    }

    /**
     * The address the app was built with, and the one it is using.
     *
     * There are two, and nothing on screen ever said so. An operator who
     * edits gradle.properties, rebuilds, and still cannot connect has no
     * way to learn that a value saved on the phone is winning — the app
     * simply says 서버에 연결할 수 없습니다 and leaves them to guess.
     *
     * Non-null when they differ and the controller is unreachable: the
     * only moment the difference matters, and the moment it explains
     * what the operator is looking at.
     */
    private val _addressMismatch = MutableStateFlow<Pair<String, String>?>(null)
    val addressMismatch: StateFlow<Pair<String, String>?> = _addressMismatch.asStateFlow()

    /** Use the address compiled into this build. */
    fun useBuiltInAddress() {
        setControllerUrl(BuildConfig.CONTROLLER_URL)
    }

    fun dismissAddressMismatch() { _addressMismatch.value = null }

    private val engine by lazy { AidotVpnEngine.get(app, ctl) }

    /**
     * Dark or light, remembered.
     *
     * Read synchronously at construction so the first frame is already
     * the chosen mood — a flash of the wrong theme on every launch is
     * the thing aidot-delivery's users noticed first.
     */
    private val prefs = app.getSharedPreferences("aidot_ui", android.content.Context.MODE_PRIVATE)
    private val _darkTheme = MutableStateFlow(prefs.getBoolean("dark", true))
    val darkTheme: StateFlow<Boolean> = _darkTheme.asStateFlow()

    fun setDarkTheme(dark: Boolean) {
        prefs.edit().putBoolean("dark", dark).apply()
        _darkTheme.value = dark
    }

    val tunnelState: StateFlow<TunnelState> get() = engine.state

    private val _effective = MutableStateFlow<Effective?>(null)
    val effective: StateFlow<Effective?> = _effective.asStateFlow()

    private val _probeResults = MutableStateFlow<Map<String, Reachability.Result>>(emptyMap())
    val probeResults: StateFlow<Map<String, Reachability.Result>> = _probeResults.asStateFlow()

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    // 연결 and 끊기 are deliberately not gated on [busy]. They are
    // connection-layer actions; [busy] belongs to application-layer work
    // like 세 곳 모두 확인하기, and sharing the flag let a probe lock the
    // controls that hang up a call. See the buttons in MainActivity.

    // A counter rides with the text.
    //
    // StateFlow drops a value equal to the one it already holds, so
    // pressing 등록 요청 twice with the same wrong password produced one
    // snackbar and then silence — indistinguishable from the button not
    // working, which is what was reported.
    data class Msg(val text: String, val seq: Long)

    /** What kind of thing happened, so the list can be read at a glance. */
    enum class LogKind { INFO, OK, WARN, ERROR }

    /**
     * One line of history.
     *
     * The screen used to hold a single message that each new one
     * overwrote, so pressing 끊기 erased the record of connecting and
     * everything before it. "기록" means history; this is that.
     */
    data class LogEntry(
        val at: Long,
        val kind: LogKind,
        val text: String,
        /** Extra lines shown when the entry is expanded, if any. */
        val detail: String? = null,
    )

    private var msgSeq = 0L
    private val _message = MutableStateFlow<Msg?>(null)
    val message: StateFlow<Msg?> = _message.asStateFlow()

    /**
     * Newest first, capped.
     *
     * Two hundred lines is more than a session produces and small
     * enough to keep in memory; nothing here is worth persisting across
     * launches, since the controller's 감사 로그 is the durable record
     * and this is the operator's view of what just happened on the
     * phone in front of them.
     */
    private val _log = MutableStateFlow<List<LogEntry>>(emptyList())
    val log: StateFlow<List<LogEntry>> = _log.asStateFlow()

    fun clearLog() { _log.value = emptyList() }

    private fun logIt(kind: LogKind, text: String, detail: String? = null) {
        _log.value = (listOf(LogEntry(System.currentTimeMillis(), kind, text, detail)) + _log.value)
            .take(200)
    }

    private fun say(text: String, detail: String? = null) {
        logIt(LogKind.INFO, text, detail)
        msgSeq += 1
        _message.value = Msg(text, msgSeq)
    }

    // Enrollment: the six digits to show, and whether we are waiting.
    //
    // The code is the whole interaction. An admin has to see it on this
    // screen, so it stays visible until the request is decided rather
    // than flashing in a toast.
    private val _enrollCode = MutableStateFlow<String?>(null)
    val enrollCode: StateFlow<String?> = _enrollCode.asStateFlow()

    private val _enrollWaiting = MutableStateFlow(false)
    val enrollWaiting: StateFlow<Boolean> = _enrollWaiting.asStateFlow()

    // Errors get a dialog, not just a snackbar.
    //
    // A snackbar is right for "등록 요청을 보냈습니다" — it appears, it
    // goes away, nothing is lost. A failure is different: the operator
    // has to read it, and often has to read it to somebody else. A
    // message that disappears on its own is one they have to reproduce
    // the failure to see again.
    /**
     * Where this device is in its lifecycle.
     *
     * The screen showed every control at once — 등록 요청 stayed live
     * after registering, 연결/끊기 sat there before there was anything
     * to connect. Nothing said whether the device was registered, and
     * nothing said whether a policy had been applied, so the two states
     * that decide whether connecting can work were both invisible.
     *
     * Derived, never stored. Each value is a fact the app can check:
     * an allocation exists, that allocation has a policy, the tunnel is
     * up. A stored copy would be a second source of truth to drift from.
     */
    enum class Stage {
        /** No allocation. The phone has not enrolled. */
        UNREGISTERED,

        /** A request is out; the code is on screen. */
        AWAITING_APPROVAL,

        /** Registration succeeded; the first status response is pending. */
        CHECKING,

        /** Registered, but no policy — connecting is refused. */
        NO_POLICY,

        /** Registered and governed. Ready to connect. */
        READY,

        /** Tunnel up. */
        CONNECTED,

        /** The controller revoked this device. */
        REVOKED,

        /**
         * The controller cannot be reached.
         *
         * Not a stage in the enrolment sequence — a statement that we do
         * not know which stage we are in. Until 1.9.0 an unreachable
         * controller fell through to the stored allocation, so a phone
         * whose device had been revoked, or whose server had moved,
         * announced 등록 완료 · 연결할 수 있습니다 and offered a 연결
         * button that could not work. Nothing can be judged without the
         * server, so nothing is.
         */
        UNREACHABLE,
        AUTH_REQUIRED,
    }

    /**
     * The controller's last word on this device, or null if never asked.
     *
     * 1.5.0 derived the stage from local storage alone, so an admin
     * revoking a handset changed nothing on the handset: it sat on
     * 정책 적용 forever with no route back to 등록 요청 short of clearing
     * app data. Local state says what this device was told; only the
     * server says what is true now.
     */
    private val _serverState = MutableStateFlow<DeviceStateClient.State?>(null)

    /**
     * A fallback the tunnel took, surfaced so the user can judge it.
     *
     * Connecting on a stored policy because the controller was
     * unreachable works and might be wrong — only the person who knows
     * whether an admin changed something can tell. Hiding it would make
     * "it connected but cannot reach the EMR" unexplainable.
     */
    val tunnelWarning: StateFlow<String?> get() = engine.tunnelWarning

    /**
     * Whether the controller answered the last time we asked.
     *
     * null before the first attempt — the app has not tried yet, so
     * neither "reachable" nor "unreachable" is true.
     */
    /**
     * Whether this phone holds an allocation — the plain fact of having
     * enrolled, independent of anything the controller says right now.
     *
     * Screens that ask "is there anything to enrol?" ask this. Deciding
     * it from the stage instead meant every new stage had to be added
     * to a list, and 1.9.0's UNREACHABLE was not, so a phone that had
     * just enrolled was shown the enrolment form again.
     */
    private val _registered = MutableStateFlow(engine.allocation() != null)
    val registered: StateFlow<Boolean> = _registered.asStateFlow()

    private val _stateAuthRequired = MutableStateFlow(false)
    private val _stateFailure = MutableStateFlow<String?>(null)
    val stateFailure: StateFlow<String?> = _stateFailure.asStateFlow()
    private val _serverReachable = MutableStateFlow<Boolean?>(null)
    val serverReachable: StateFlow<Boolean?> = _serverReachable.asStateFlow()
    private var stateRevision = 0L

    private fun invalidateServerState() {
        stateRevision++
        _serverState.value = null
        _serverReachable.value = null
        _stateAuthRequired.value = false
        _stateFailure.value = null
        _effective.value = null
    }

    /**
     * Which stage this phone is in, decided in the order the answers
     * actually arrive.
     *
     *   1. Have we ever enrolled?      no  → UNREGISTERED
     *   2. Waiting for approval?       yes → AWAITING_APPROVAL
     *   3. Can we reach the server?    no  → UNREACHABLE
     *   4. Does the server still know us? no → REVOKED
     *   5. Then, and only then, the rest.
     *
     * The order is the fix. It used to fall back to the stored
     * allocation whenever the server was silent, which meant "the wifi
     * changed" and "an admin revoked this phone" and "the server moved"
     * all produced the same cheerful 등록 완료 · 연결할 수 있습니다. The
     * old comment argued those two must not look the same — true, and
     * the answer is a third state for "we do not know", not guessing
     * from stale data.
     *
     * A live tunnel is the one thing that outranks an unreachable
     * controller: packets are flowing, so whatever the control channel
     * is doing, the phone is genuinely connected.
     */
    val stage: StateFlow<Stage> = combine(
        _enrollWaiting, engine.state, _serverState, _serverReachable, _stateAuthRequired,
    ) { waiting, tunnel, server, reachable, authRequired ->
        val alloc = engine.allocation()
        when {
            alloc == null && !waiting -> Stage.UNREGISTERED
            waiting -> Stage.AWAITING_APPROVAL
            authRequired -> Stage.AUTH_REQUIRED

            // Traffic beats the control channel: if the tunnel is up we
            // are connected whatever /devices/{id}/state has to say.
            tunnel is TunnelState.Connected -> Stage.CONNECTED

            // No server, no judgement.
            reachable == false -> Stage.UNREACHABLE
            server == null -> Stage.CHECKING

            server.status == "revoked" -> Stage.REVOKED
            !server.policyBound -> Stage.NO_POLICY
            else -> Stage.READY
        }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, Stage.UNREGISTERED)

    /**
     * Whether [connect] can succeed right now.
     *
     * Derived here rather than listed at the button, because a list of
     * stages at a call site has to be revisited every time a stage is
     * added and nothing makes anyone do it: 1.9.0 added UNREACHABLE and
     * the enrolment card missed it; the same list at the 연결 button
     * missed NO_POLICY, so a phone with no policy offered a button whose
     * connection the gateway refuses. Only READY can connect — that is
     * what READY means — and CONNECTED keeps it live for a reconnect.
     */
    init {
        // Log every stage change, so the history shows the sequence the
        // operator actually walked: 등록 요청 → 승인 → 정책 → 연결. The
        // old single-message field could not: each new message erased
        // the one before, and pressing 끊기 wiped the whole session.
        viewModelScope.launch {
            var previous: Stage? = null
            stage.collect { st ->
                if (previous != null && previous != st) {
                    val (kind, text) = when (st) {
                        Stage.UNREGISTERED -> LogKind.INFO to "등록 정보가 없습니다"
                        Stage.AWAITING_APPROVAL -> LogKind.INFO to "관리자 승인 대기"
                        Stage.CHECKING -> LogKind.INFO to "등록 완료 — 서버 상태를 확인하는 중입니다"
                        Stage.NO_POLICY -> LogKind.WARN to "정책 적용 대기 — 관리자가 정책을 지정해야 연결됩니다"
                        Stage.READY -> LogKind.OK to "정책 적용됨 — 연결할 수 있습니다"
                        Stage.CONNECTED -> LogKind.OK to "연결됨"
                        Stage.REVOKED -> LogKind.ERROR to "관리자가 이 단말을 폐기했습니다"
                        Stage.UNREACHABLE -> LogKind.ERROR to "서버에 연결할 수 없습니다"
                        Stage.AUTH_REQUIRED -> LogKind.ERROR to "상태 API 인증이 필요합니다. 앱 업데이트 후 다시 등록하세요."
                    }
                    logIt(kind, text)
                    Log.i("AidotVpn/Control", "Client stage: ${st.name}")
                }
                previous = st
            }
        }
    }

    val canConnect: StateFlow<Boolean> = stage
        // READY only.
        //
        // CONNECTED was on this list so a reconnect stayed available, and
        // that was wrong twice over: pressing 연결 while connected tore
        // the tunnel down (1.13.8), and once that was fixed the button
        // did nothing at all — which is worse, because a button that
        // looks pressable and is not lies about what it offers. Already
        // connected means there is nothing to connect; 끊기 is the action
        // that applies, and it is enabled.
        .map { it == Stage.READY }
        .stateIn(viewModelScope, SharingStarted.Eagerly, false)

    /**
     * Ask the controller what this device's status is.
     *
     * Called on every resume, so returning to the app after an admin
     * revokes shows the change without the operator doing anything. A
     * failure sets [serverReachable] to false, which puts [stage] in
     * UNREACHABLE — the app says it cannot tell, rather than repeating
     * a stale answer.
     */
    private suspend fun fetchAuthenticatedState(base: String, id: String, token: String): DeviceStateClient.State? {
        val revision = stateRevision
        val result = DeviceStateClient(base, stateToken = token).fetchResult(id)
        val current = engine.allocation()
        if (revision != stateRevision || current?.deviceId != id || current.stateToken != token) {
            throw CancellationException("Registration or server address changed during status read")
        }
        val failure = result.exceptionOrNull()
        val detail = failure?.let { "서버: $base\n${it.message ?: it.javaClass.simpleName}" }
        val newFailure = detail != null && detail != _stateFailure.value
        if (newFailure) {
            logIt(LogKind.ERROR, "서버 상태 조회 실패", detail)
            if (failure is com.aidotvpn.client.core.StateAuthenticationException) {
                val reason = if (token.isBlank()) "credential missing locally; request not sent" else "authentication rejected"
                Log.w("AidotVpn/Control", "Device status $reason at $base")
            } else {
                Log.w("AidotVpn/Control", "Device status request failed at $base: ${failure?.message}")
            }
        }
        _stateFailure.value = detail
        _stateAuthRequired.value = failure is com.aidotvpn.client.core.StateAuthenticationException
        if (failure is com.aidotvpn.client.core.StateAuthenticationException && newFailure) {
            engine.disconnect()
            say(failure.message ?: "상태 API 인증이 필요합니다")
        }
        return result.getOrNull()
    }

    fun refreshServerState() {
        val allocation = engine.allocation() ?: return
        viewModelScope.launch {
            // The tunnel address when connected and the policy gave one;
            // the compiled-in address otherwise. CoreStorage decides, so
            // this call and the others cannot each choose differently.
            val up = engine.state.value is TunnelState.Connected
            val base = CoreStorage.get(getApplication()).controllerUrlFor(up)
                ?: ctl
            val st = fetchAuthenticatedState(base, allocation.deviceId, allocation.stateToken)
            // Record whether the controller answered at all, separately
            // from what it said. A failed fetch used to leave the last
            // answer standing and the screen carried on as if nothing
            // had changed; the stage now shows UNREACHABLE instead of
            // guessing from an answer that may be days old.
            _serverReachable.value = st != null
            if (st == null && !_stateAuthRequired.value) {
                val built = BuildConfig.CONTROLLER_URL.trim().trimEnd('/')
                val inUse = _controllerUrl.value.trim().trimEnd('/')
                if (built.isNotBlank() && built != inUse) {
                    _addressMismatch.value = inUse to built
                }
            } else {
                _addressMismatch.value = null
            }
            if (st != null) {
                _serverState.value = st
            } else {
                // Drop the last answer too, not just the reachability.
                //
                // Keeping it meant a stale "revoked" survived the server
                // going away, and the moment reachability flipped back to
                // true — before a fresh answer had landed — the stage read
                // that old value and announced 이 단말은 폐기되었습니다
                // about a device that was fine. "We do not know" is not
                // the same as holding on to what we last knew, and the
                // whole point of UNREACHABLE was to stop conflating them.
                _serverState.value = null
            }
        }
    }

    /**
     * Forget this device's registration and start over.
     *
     * Recover a revoked registration or one saved by an older app without a
     * state credential. Keep the install identity and configured server URL.
     */
    fun resetRegistration() {
        engine.forgetAllocation()
        _registered.value = false
        invalidateServerState()
        _addressMismatch.value = null
        say("서버 주소는 유지했습니다. 등록 요청 후 관리자 승인을 받아주세요.")
    }

    private val _errorDialog = MutableStateFlow<String?>(null)
    val errorDialog: StateFlow<String?> = _errorDialog.asStateFlow()

    fun dismissError() { _errorDialog.value = null }

    private fun fail(text: String) {
        // Same line the dialog shows, kept in the history as an error so
        // the list reads as a sequence of what worked and what did not.
        logIt(LogKind.ERROR, text)
        _message.value = Msg(text, ++msgSeq)
        _errorDialog.value = text
    }

    /** Editable so the tutorial works against any deployment's addresses. */
    /**
     * Default probe targets, on the tunnel.
     *
     * 10.78.0.1 is the address the tunnel gives the gateway, and the
     * controller runs on that machine — so the permitted probe reaches
     * something real without anyone looking up a LAN address, and the
     * value is the same on every network.
     *
     * These were 10.10.5.20/.99, numbers standing in for a hospital EMR
     * server. Nothing answers at either on a home LAN, so the permitted
     * probe failed exactly like the blocked one: two identical silences,
     * one of which is supposed to prove the policy works.
     *
     * The blocked target is inside the tunnel pool and unassigned, so a
     * refusal there is the policy rather than a missing route.
     */
    /**
     * Probe targets that the policy actually governs.
     *
     * The permitted one was 10.78.0.1 — the gateway's own tunnel
     * address. That reported 연결됨 whether or not the policy allowed
     * it, because the phone's interface is 10.78.0.2 and the two are
     * adjacent: the packet reaches wg0 by proximity rather than by
     * routing. A test that passes when the policy forbids the target is
     * not testing the policy.
     *
     * 8080 on the gateway is a responder placed there for this, and it
     * is a normal destination: reachable only when the policy lists it.
     * Put 10.78.0.1/32 in the policy and this succeeds; remove it and
     * this fails. That is what the test is for.
     */
    private val _permitted = MutableStateFlow("http://10.78.0.1:8080")
    val permitted: StateFlow<String> = _permitted.asStateFlow()

    // Inside the tunnel pool and unassigned, so a refusal here is the
    // policy rather than a missing route.
    private val _blocked = MutableStateFlow("http://10.78.9.9")
    val blocked: StateFlow<String> = _blocked.asStateFlow()

    fun setPermitted(v: String) { _permitted.value = v }
    fun setBlocked(v: String) { _blocked.value = v }
    fun clearMessage() { _message.value = null }

    /**
     * What the controller says this device has.
     *
     * Deliberately the server's view rather than the client's stored copy.
     * The two can differ — an admin changes a policy and the phone does
     * not see it until its next registration or key rotation — and that
     * gap is itself a thing the tutorial teaches. Showing the client's
     * cache here would hide it.
     */
    data class Effective(
        val policyBound: Boolean,
        val policyName: String,
        val allowedIps: List<String>,
        val routeScope: String,
        val routeScopeMeans: String,
        val appFilterMode: String,
        val appFilterMeans: String,
        val dnsServers: List<String>,
        val warnings: List<String>,
    )

    /**
     * Ask the controller to enrol this device.
     *
     * Replaces the pasted access token. The phone shows six digits, an
     * admin confirms they match this screen, and the allocation arrives
     * without anything being typed across.
     */
    fun requestEnrollment(displayName: String, password: String) {
        viewModelScope.launch {
            _busy.value = true
            _message.value = null
            try {
                val client = EnrollmentRequestClient(ctl)
                // The public key the request carries is a placeholder: the
                // real keypair is generated during registration, after
                // approval. The controller only needs a well-formed value
                // here to record the request.
                // getApplication(), not `app`.
                //
                // `app` is a constructor parameter without `val`, so it is
                // only in scope for initialisers — which is why line 35's
                // `by lazy` compiles and this did not. AndroidViewModel
                // exists to hold the reference for exactly this.
                val installId = CoreStorage.get(getApplication()).installId()
                val pubKey = engine.placeholderPublicKeyB64()

                val created = client.request(password, installId, displayName, pubKey)
                    .getOrElse {
                        fail(it.message ?: "등록 요청에 실패했습니다")
                        return@launch
                    }

                _enrollCode.value = created.verificationCode
                _enrollWaiting.value = true
                // The request went through, so the controller is reachable
                // whatever an earlier check concluded.
                _serverReachable.value = true
                say("등록 요청을 보냈습니다. 관리자 승인을 기다리는 중…")

                val decided = client.awaitDecision(
                    created.id,
                    onError = { msg, n ->
                        // Say it once, then stay quiet. A controller that
                        // is down would otherwise produce a message every
                        // three seconds for ten minutes.
                        if (n == 1) say("서버 응답 없음: $msg (계속 시도합니다)")
                    },
                ).getOrElse {
                    fail(it.message ?: "승인을 받지 못했습니다")
                    _enrollWaiting.value = false
                    return@launch
                }

                when (decided.status) {
                    "approved" -> {
                        // Approval handed us a one-time grant; registration
                        // itself is the path it always was.
                        val alloc = engine
                            .registerWithEnrollmentToken(decided.enrollmentToken, displayName)
                            .getOrElse {
                                fail(it.message ?: "등록에 실패했습니다")
                                _enrollWaiting.value = false
                                return@launch
                            }
                        _enrollWaiting.value = false
                        _enrollCode.value = null
                        invalidateServerState()
                        // We just talked to the controller, twice. Say so:
                        // an earlier failed status check had left
                        // serverReachable false, which put the stage in
                        // UNREACHABLE right after a successful enrolment.
                        _serverReachable.value = true
                        _registered.value = true
                        say("등록 완료 — 정책 " + if (alloc.policyBound) "적용됨" else "없음")
                        // And ask for the status now rather than waiting
                        // for the next resume, so the screen moves on by
                        // itself.
                        refreshServerState()
                    }
                    "rejected" -> {
                        _enrollWaiting.value = false
                        _enrollCode.value = null
                        fail("관리자가 등록을 거절했습니다.")
                    }
                    else -> {
                        _enrollWaiting.value = false
                        _enrollCode.value = null
                        fail("시간이 초과되었습니다. 다시 요청하세요.")
                    }
                }
            } catch (e: Exception) {
                // try/finally with no catch was the bug.
                //
                // Anything thrown outside the Result-returning calls —
                // the client constructor, CoreStorage, a blocked
                // cleartext connection — cancelled the coroutine
                // silently. `finally` reset busy, so the button flickered
                // and nothing else happened, and nothing reached the
                // server. There was no message because no code ran to
                // produce one.
                _enrollWaiting.value = false
                _enrollCode.value = null
                fail(e.message?.takeIf { it.isNotBlank() } ?: e.toString())
            } finally {
                _busy.value = false
            }
        }
    }

    fun cancelEnrollment() {
        _enrollWaiting.value = false
        _enrollCode.value = null
        _message.value = null
    }

    fun connect() {
        val prepare = engine.prepareIntent()
        if (prepare != null) {
            say("먼저 VPN 사용 동의가 필요합니다. '동의하기' 를 누르세요.")
            return
        }
        engine.connect()
            .onSuccess { say("연결을 시작했습니다.") }
            .onFailure { say("연결 실패: ${it.message}") }
    }

    fun disconnect() {
        engine.disconnect()
        say("연결을 끊었습니다.")
        _probeResults.value = emptyMap()
    }

    fun consentIntent() = engine.prepareIntent()

    fun reportConsentDenied() {
        say("VPN 사용을 허용하지 않으면 연결할 수 없습니다. " +
            "'연결' 을 다시 눌러 허용해 주세요.")
    }

    fun reportNotificationsDenied() {
        // Not fatal — the tunnel works. But the user loses the only
        // always-visible indication of which policy is in force, and the
        // disconnect shortcut with it, so it is worth saying once.
        say("알림 권한이 없어 상단 알림에 VPN 상태가 표시되지 않습니다. " +
            "설정 → 앱 → 알림 에서 켤 수 있습니다.")
    }

    /**
     * Run all three probes.
     *
     * Sequential rather than parallel on purpose. Three simultaneous
     * connects through one tunnel produce timings that say more about
     * contention than about policy, and the timing is part of what the
     * reader is being asked to notice — a block times out slowly, a
     * success returns fast.
     */
    fun runProbes() = launchBusy {
        val probes = Reachability.defaults(_permitted.value, _blocked.value)
        val out = mutableMapOf<String, Reachability.Result>()
        for (p in probes) {
            _probeResults.value = out.toMap() + (p.id to
                Reachability.Result(Reachability.Outcome.ERROR, 0, "확인 중…"))
            out[p.id] = explainAgainstPolicy(p.target, Reachability.probe(p.target))
            _probeResults.value = out.toMap()
        }
    }

    /**
     * Say whether the policy even sends this address into the tunnel.
     *
     * "응답 없음" on its own could mean the address is not in the policy,
     * or the server behind it is down, or the gateway dropped it. A user
     * probing 10.78.0.1:8080 with no 10.78.0.1/32 in their policy saw
     * the first and read it as the second — the tunnel was fine, the
     * policy was doing its job, and nothing on screen said so.
     *
     * The stored allocation holds the list the tunnel was built from,
     * so the check is local and exact.
     */
    private fun explainAgainstPolicy(
        target: String,
        result: Reachability.Result,
    ): Reachability.Result {
        // The tunnel first. Every other explanation assumes one is up.
        //
        // A user probed with the tunnel down — the screen said
        // "등록 완료. 연결할 수 있습니다", which is the state *before*
        // connecting — and this told them the policy lacked the address.
        // The policy had it. The packet never went near the tunnel
        // because there was no tunnel, and the stored copy it compared
        // against predated the admin's change. Both true, both beside
        // the point.
        if (engine.state.value !is TunnelState.Connected) {
            return result.copy(
                detail = "터널이 연결되어 있지 않습니다. 먼저 [연결] 을 누른 뒤 시험하세요.",
            )
        }

        // Has the far end ever answered?
        //
        // 연결됨 means the phone's interface is up — WireGuard brings it
        // up whether or not a peer exists. The counters tell the rest:
        // bytes sent with nothing received is a handshake nobody
        // answered. A user with the tunnel "connected" and every probe
        // timing out had exactly this, and the screen could not say so.
        val stats = engine.tunnelStatistics()
        if (stats != null && stats.second > 0 && stats.first == 0L) {
            return result.copy(
                detail = "문지기가 답하지 않습니다 (보낸 ${stats.second}B, 받은 0B). " +
                    "서버에서 npm start 를 다시 하고, 폰에서 끊었다 다시 연결하세요. " +
                    "그래도 안 되면 Windows 방화벽의 UDP 52840 을 확인하세요.",
            )
        }

        val host = runCatching { java.net.URI(target).host }.getOrNull() ?: return result
        val alloc = engine.allocation() ?: return result
        val routed = alloc.routeScope == "full" ||
            alloc.allowedIps.any { cidrContains(it, host) }

        return when {
            result.ok && !routed ->
                // Reached, but not through the tunnel: the address is
                // on the phone's normal network. True and misleading.
                result.copy(detail = "정책에 없는 주소라 터널을 거치지 않고 평소 망으로 닿았습니다")
            !result.ok && !routed ->
                result.copy(detail = "정책에 이 주소가 없어 터널로 보내지 않았습니다 — 콘솔 정책에 추가하세요")
            !result.ok && routed -> {
                // A virtual address: name the real one, with the port the
                // probe used. "The server behind the gateway is down" is
                // true of 10.79.0.11:8080 but sends the user to look at
                // 10.79.0.11 — there is nothing to look at there. The
                // question is what listens on 192.168.0.11:8080.
                val real = alloc.virtualHosts
                    .map { it.split("=", limit = 2) }
                    .firstOrNull { it.size == 2 && it[0] == host }?.get(1)
                val port = runCatching { java.net.URI(target).port }.getOrNull()?.takeIf { it > 0 } ?: 80
                if (real != null) {
                    result.copy(detail = "가상 주소 $host → 진짜 $real. 문지기가 바꿔 보냈는데 " +
                        "$real:$port 에서 답이 없습니다 — 그 서버의 $port 포트에 서비스가 있는지, " +
                        "정책의 '주소 바꿔서 보내기' 가 켜져 있는지 확인하세요.")
                } else {
                    result.copy(detail = "정책에는 있습니다. 문지기 뒤의 서버가 꺼져 있거나 답신 경로가 없습니다")
                }
            }
            else -> result
        }
    }

    /** IPv4 only, which is all the probe targets use. */
    private fun cidrContains(cidr: String, ip: String): Boolean {
        val (net, bitsStr) = cidr.split("/").let { it[0] to (it.getOrNull(1) ?: "32") }
        val bits = bitsStr.toIntOrNull() ?: return false
        fun toInt(a: String): Int? = a.split(".").takeIf { it.size == 4 }
            ?.mapNotNull { it.toIntOrNull() }?.takeIf { it.size == 4 }
            ?.fold(0) { acc, o -> (acc shl 8) or o }
        val n = toInt(net) ?: return false
        val i = toInt(ip) ?: return false
        if (bits == 0) return true
        val mask = (-1 shl (32 - bits))
        return (n and mask) == (i and mask)
    }

    /** Fetch /devices/{id}/effective for the registered device. */
    /**
     * Show what the controller handed this device at registration.
     *
     * Reads the stored allocation rather than calling /effective. A
     * device enrolled by approval has no OIDC session — that is the
     * point of the flow — so there is no credential to make that call
     * with, and the allocation already contains everything the screen
     * shows.
     *
     * The cost is that a policy changed after registration is not
     * reflected until the tunnel reconnects and the engine refreshes.
     * Worth naming rather than hiding behind a button that would need
     * an authentication the app does not have.
     */
    /**
     * Ask the controller what this device may reach now.
     *
     * 1.2.8 made this read the stored allocation instead — the copy
     * handed over at registration — so an admin changing a policy never
     * showed up here. The button re-read a snapshot and presented it as
     * current, which is worse than not having the button: it answers the
     * question wrongly rather than not at all.
     *
     * Falls back to the stored copy when the controller is unreachable,
     * and says so, because "we could not ask" and "you may go nowhere"
     * are different answers.
     */
    fun refreshEffective() = launchBusy {
        val alloc = engine.allocation()
        if (alloc == null || alloc.deviceId.isBlank()) {
            say("아직 등록되지 않았습니다. 먼저 '등록 요청' 을 누르세요.")
            return@launchBusy
        }

        val up = engine.state.value is TunnelState.Connected
        val base = CoreStorage.get(getApplication()).controllerUrlFor(up)
            ?: ctl
        val st = fetchAuthenticatedState(base, alloc.deviceId, alloc.stateToken)
        if (st == null && _stateAuthRequired.value) {
            _effective.value = effectiveFrom(false, emptyList(), alloc.routeScope, alloc.appFilterMode,
                listOf("상태 API 인증이 필요합니다. 다시 등록하세요."))
            return@launchBusy
        }
        if (st == null) {
            _effective.value = effectiveFrom(
                alloc.policyBound, alloc.allowedIps, alloc.routeScope, alloc.appFilterMode,
                listOf("서버에 연결할 수 없어 마지막으로 받은 설정을 보여줍니다."),
            )
            say("서버에 연결할 수 없습니다. 화면은 마지막으로 받은 설정입니다.")
            return@launchBusy
        }

        _serverState.value = st

        // Save what the server said, not only display it.
        //
        // 1.6.5 made this button ask the server and show the answer,
        // and left the stored allocation untouched — so the screen
        // showed the new policy while the probe explainer, reading the
        // stored copy, said the address was not in it. Two parts of one
        // app disagreeing about one fact.
        // The engine checks the actual backend state. An Error UI state can
        // still have an active interface that needs policy updates or revocation.
        CoreStorage.get(getApplication()).saveAllocation(
            alloc.copy(
                policyBound = st.policyBound, allowedIps = st.allowedIps, routeScope = st.routeScope,
                dnsServers = st.dnsServers ?: alloc.dnsServers,
                dnsSearchDomains = st.dnsSearchDomains ?: alloc.dnsSearchDomains,
                appFilterMode = st.appFilterMode ?: alloc.appFilterMode,
                appFilterPackages = st.appFilterPackages ?: alloc.appFilterPackages,
                nodes = if (st.nodes.isNotEmpty()) st.nodes else alloc.nodes,
                virtualHosts = st.virtualHosts.map { "${it.virtual}=${it.real}" },
            ),
        )

        engine.applyStoredConfig()
            .onFailure { say("새 설정을 터널에 적용하지 못했습니다: ${it.message}") }

        _effective.value = effectiveFrom(
            st.policyBound, st.allowedIps, st.routeScope, st.appFilterMode ?: alloc.appFilterMode,
            if (!st.policyBound) {
                listOf("정책이 지정되지 않았습니다. 이 단말은 연결 자체가 거부됩니다.")
            } else {
                emptyList()
            },
        )
        say(
            if (st.policyBound) "설정을 새로 받았습니다. 갈 수 있는 곳 ${st.allowedIps.size}개."
            else "정책이 없습니다. 관리자가 지정해야 연결됩니다.",
        )
    }

    private fun effectiveFrom(
        bound: Boolean,
        ips: List<String>,
        scope: String,
        filterMode: String,
        warnings: List<String>,
    ) = Effective(
        policyBound = bound,
        policyName = "",
        allowedIps = ips,
        routeScope = scope,
        routeScopeMeans = when (scope) {
            "full" -> "모든 트래픽이 터널로 갑니다"
            else -> "허용 목록만 터널로 가고, 나머지는 평소 네트워크를 씁니다"
        },
        appFilterMode = filterMode,
        appFilterMeans = when (filterMode) {
            "include" -> "지정한 앱만 터널을 씁니다"
            "exclude" -> "지정한 앱을 뺀 나머지가 터널을 씁니다"
            else -> "모든 앱이 터널을 씁니다"
        },
        dnsServers = emptyList(),
        warnings = warnings,
    )

    private suspend fun fetchEffective(deviceId: String, token: String): Effective? =
        withContext(Dispatchers.IO) {
            runCatching {
                val url = URL("$ctl/devices/$deviceId/effective")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    setRequestProperty("Authorization", "Bearer $token")
                    connectTimeout = 8000
                    readTimeout = 8000
                }
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                conn.disconnect()
                val j = JSONObject(body)
                Effective(
                    policyBound = j.optBoolean("policy_bound"),
                    policyName = j.optString("policy_name", "(없음)"),
                    allowedIps = j.optJSONArray("allowed_ips").toList(),
                    routeScope = j.optString("route_scope"),
                    routeScopeMeans = j.optString("route_scope_means"),
                    appFilterMode = j.optString("app_filter_mode"),
                    appFilterMeans = j.optString("app_filter_means"),
                    dnsServers = j.optJSONArray("dns_servers").toList(),
                    warnings = j.optJSONArray("warnings").toList(),
                )
            }.onFailure {
                Log.w("AidotDemo", "effective 조회 실패", it)
                say("설정 조회 실패: ${it.message}")
            }.getOrNull()
        }

    private fun org.json.JSONArray?.toList(): List<String> {
        if (this == null) return emptyList()
        return (0 until length()).map { optString(it) }
    }

    private fun launchBusy(block: suspend () -> Unit) {
        viewModelScope.launch {
            _busy.value = true
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                say("오류: ${e.message}")
            } finally {
                _busy.value = false
            }
        }
    }
}
