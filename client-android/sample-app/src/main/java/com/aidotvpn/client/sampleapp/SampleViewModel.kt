package com.aidotvpn.client.sampleapp

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aidotvpn.client.core.CoreStorage
import com.aidotvpn.client.core.DeviceStateClient
import com.aidotvpn.client.vpnlib.AidotVpnEngine
import com.aidotvpn.client.vpnlib.TunnelState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

internal data class SampleUiState(
    val controllerUrl: String = "",
    val registered: Boolean = false,
    val policyBound: Boolean = false,
    val serverStatus: String? = null,
    val tunnel: TunnelState = TunnelState.Disconnected,
    val busy: Boolean = false,
    val code: String? = null,
    val message: String? = null,
    val probes: List<ProbeRowState> = List(3) { ProbeRowState() },
    val probing: Boolean = false,
    val probeRoute: String? = null,
)

/** Owns initialization and enrollment independently of Activity recreation. */
class SampleViewModel(app: Application) : AndroidViewModel(app) {
    private val storage = CoreStorage.get(app)
    private val preferences = app.getSharedPreferences("sample-ui", android.content.Context.MODE_PRIVATE)
    private var engine: AidotVpnEngine? = null
    private val initial = storage.loadAllocation()
    private val mutable = MutableStateFlow(SampleUiState(
        controllerUrl = storage.loadControllerUrl().orEmpty(),
        registered = initial != null,
        policyBound = initial?.policyBound == true,
        probes = List(3) { ProbeRowState(preferences.getString("probe-$it", "").orEmpty()) },
    ))
    internal val ui = mutable.asStateFlow()

    init {
        // A fresh installation has no URL. Render onboarding without an engine.
        // Do not invent a default server or require a different app's settings.
        if (mutable.value.controllerUrl.isNotBlank()) {
            runCatching { configure(serverAddress(mutable.value.controllerUrl, !BuildConfig.DEBUG)) }
                .onFailure { showMessage(it.message ?: "서버 주소를 다시 설정하세요.") }
        }
    }

    private fun configure(url: String): AidotVpnEngine {
        if (storage.loadControllerUrl() != url) {
            storage.saveControllerUrl(url)
            storage.clearTunnelControllerUrl()
        }
        mutable.update { it.copy(controllerUrl = url) }
        return engine ?: AidotVpnEngine.get(getApplication(), url).also { current ->
            engine = current
            viewModelScope.launch {
                current.state.collect { state -> mutable.update { previous ->
                    previous.copy(tunnel = state, message = when {
                        state == previous.tunnel -> previous.message
                        state is TunnelState.Connected -> "VPN에 연결됐습니다. 아래에서 서버 접속을 확인하세요."
                        state is TunnelState.Connecting -> "VPN 연결을 준비하고 있습니다."
                        state is TunnelState.Handshaking -> "서버와 보안 연결을 확인하고 있습니다."
                        state is TunnelState.Error -> "연결하지 못했습니다: ${state.message}"
                        else -> "VPN 연결이 해제됐습니다."
                    })
                } }
            }
        }
    }

    internal fun showMessage(message: String) { mutable.update { it.copy(message = message) } }

    internal fun saveServer(raw: String): Boolean {
        if (mutable.value.busy || mutable.value.probing || storage.loadTunnelWanted()) {
            showMessage("진행 중인 작업을 마치고 VPN 연결을 끊은 뒤 주소를 변경하세요.")
            return false
        }
        return runCatching {
            configure(serverAddress(raw, !BuildConfig.DEBUG))
            mutable.update { it.copy(serverStatus = null, message = "서버 주소를 저장했습니다. 등록 정보는 유지됩니다.") }
            refresh()
        }.fold(onSuccess = { true }, onFailure = { showMessage(it.message ?: "주소를 저장하지 못했습니다."); false })
    }

    internal fun enroll(name: String, password: String, raw: String) {
        if (mutable.value.busy || mutable.value.registered) return
        val current = runCatching {
            require(name.isNotBlank() && password.isNotBlank()) { "기기 이름과 등록 비밀번호를 입력하세요." }
            configure(serverAddress(raw, !BuildConfig.DEBUG))
        }.getOrElse { showMessage(it.message ?: "입력 내용을 확인하세요."); return }
        mutable.update { it.copy(busy = true, code = null, message = "등록을 요청하는 중입니다.") }
        viewModelScope.launch {
            try {
                val result = current.enroll(name.trim(), password) { code ->
                    mutable.update { it.copy(code = code, message = "관리자 승인을 기다립니다.") }
                }
                ensureActive()
                val allocation = result.getOrThrow()
                mutable.update { it.copy(registered = true, policyBound = allocation.policyBound,
                    serverStatus = "active", code = null, message = if (allocation.policyBound)
                        "등록이 완료됐습니다. 연결 버튼을 누르세요." else "등록됐지만 정책이 없습니다. 관리자에게 정책 할당을 요청하세요.") }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                mutable.update { it.copy(code = null, message = "등록하지 못했습니다: ${error.message}") }
            } finally {
                mutable.update { it.copy(busy = false) }
            }
        }
    }

    internal fun refresh() {
        val allocation = storage.loadAllocation() ?: return
        if (mutable.value.busy) return
        val url = runCatching { serverAddress(mutable.value.controllerUrl, !BuildConfig.DEBUG) }
            .getOrElse { showMessage(it.message ?: "서버 주소를 확인하세요."); return }
        mutable.update { it.copy(busy = true) }
        viewModelScope.launch {
            try {
                val result = DeviceStateClient(url, stateToken = allocation.stateToken).fetchResult(allocation.deviceId)
                ensureActive()
                val state = result.getOrThrow()
                mutable.update { it.copy(serverStatus = state.status, policyBound = state.policyBound,
                    message = when {
                        state.status == "revoked" -> "등록이 해제됐습니다. 관리자에게 문의하세요."
                        !state.policyBound -> "등록됐지만 정책이 없습니다. 관리자에게 정책 할당을 요청하세요."
                        it.tunnel is TunnelState.Connected -> "VPN에 연결됐습니다. 아래에서 서버 접속을 확인하세요."
                        else -> "등록과 정책을 확인했습니다."
                    }) }
                if ((state.status == "revoked" || !state.policyBound) && storage.loadTunnelWanted()) {
                    engine?.disconnect()?.getOrThrow()
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                showMessage("상태를 확인하지 못했습니다: ${error.message}")
            } finally {
                mutable.update { it.copy(busy = false) }
            }
        }
    }

    internal fun connect() {
        if (mutable.value.busy || !mutable.value.registered) return
        val current = runCatching { configure(serverAddress(mutable.value.controllerUrl, !BuildConfig.DEBUG)) }
            .getOrElse { showMessage(it.message ?: "서버 주소를 확인하세요."); return }
        mutable.update { it.copy(busy = true, message = "연결을 요청했습니다.") }
        viewModelScope.launch {
            try {
                // TunnelManager authenticates and refreshes the effective policy
                // before connecting. The UI's cached policy is never authority.
                current.connect().getOrThrow()
                withTimeout(15_000) { current.state.first { it !is TunnelState.Disconnected } }
            } catch (cancelled: CancellationException) {
                if (!kotlinx.coroutines.currentCoroutineContext().isActive) throw cancelled
                showMessage("연결 시작을 확인하지 못했습니다. 다시 시도하세요.")
            } catch (error: Exception) {
                showMessage("연결하지 못했습니다: ${error.message}")
            } finally {
                mutable.update { it.copy(busy = false) }
            }
        }
    }

    internal fun disconnect() {
        runCatching { engine?.disconnect()?.getOrThrow() }
            .onSuccess { showMessage("연결을 끊는 중입니다.") }
            .onFailure { showMessage("연결을 끊지 못했습니다: ${it.message}") }
    }

    internal fun editProbe(index: Int, target: String) {
        if (mutable.value.probing || index !in 0..2) return
        preferences.edit().putString("probe-$index", target).apply()
        mutable.update { current -> current.copy(probes = current.probes.mapIndexed { i, row ->
            if (i == index) ProbeRowState(target) else row
        }) }
    }

    internal fun runProbes() {
        if (mutable.value.probing || mutable.value.busy) return
        val targets = mutable.value.probes.map { it.target }
        if (targets.any { it.isBlank() }) { showMessage("시험할 서버 주소 세 곳을 모두 입력하세요."); return }
        val cm = getApplication<Application>().getSystemService(ConnectivityManager::class.java)
        val network = cm.activeNetwork
        val vpn = cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        mutable.update { it.copy(probing = true, probeRoute = if (vpn) "이 앱의 VPN 경로에서 시험합니다."
            else "이 앱의 일반 네트워크에서 시험합니다. VPN·앱별 허용 설정을 확인하세요.",
            probes = it.probes.map { row -> row.copy(result = "확인 중…") }) }
        viewModelScope.launch {
            try {
                coroutineScope {
                    targets.mapIndexed { index, target -> async {
                        val result = PolicyProbe.run(target)
                        mutable.update { current -> current.copy(probes = current.probes.mapIndexed { i, row ->
                            if (i == index) row.copy(result = result) else row
                        }) }
                    } }.awaitAll()
                }
                if (cm.activeNetwork != network) mutable.update { it.copy(probeRoute = "시험 중 네트워크가 바뀌었습니다. 결과를 다시 확인하세요.") }
            } finally { mutable.update { it.copy(probing = false) } }
        }
    }
}
