package com.aidotvpn.client.vpnlib

import android.content.Context
import android.util.Log
import java.net.InetAddress
import com.aidotvpn.client.core.CoreStorage
import com.aidotvpn.client.core.DeviceStateClient
import com.aidotvpn.client.core.EndpointModel
import com.aidotvpn.client.core.KeyUtils
import com.aidotvpn.client.core.NodeModel
import com.aidotvpn.client.core.StoredAllocation
import com.aidotvpn.client.core.relay.RelayClient
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.InetEndpoint
import com.wireguard.config.InetNetwork
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/**
 * TunnelManager wraps the wireguard-android `GoBackend` — the userspace
 * WireGuard implementation that ships embedded in the AAR — and exposes
 * a small, status-flow-driven API to the rest of :app.
 *
 * Why userspace and not kernel mode? Android's mainline kernel doesn't
 * include WireGuard, so we use the bundled Go-userspace tunnel. On
 * recent Pixels and on devices running KernelSU/Magisk the kernel mode
 * is sometimes available; if the user really wants it they can swap
 * GoBackend for WgQuickBackend, but the userspace path works on every
 * Android 8+ device.
 *
 * The tunnel lifecycle is:
 *
 *   start()  -> derive Config from StoredAllocation -> setState(UP)
 *   stop()   -> setState(DOWN)
 *   getStats() (best-effort, periodic) -> emit telemetry
 *
 * Tunnel state is a StateFlow so the AIDL service and UI both observe
 * the same source of truth.
 */
class TunnelManager(
    private val context: Context,
    /**
     * Optional callback that returns a fresh relay token for the given
     * device_id. Set by AidotVpnApplication when wiring TunnelManager
     * up. Returning null means "I cannot get a relay token right now",
     * which makes Connect fall back to direct UDP if the chosen
     * endpoint mode is wss_relay.
     */
    private val relayTokenProvider: (suspend (deviceId: String) -> String?)? = null,
) {

    private val backend: GoBackend = GoBackend(context)
    /**
     * The tunnel name, which is also what the system shows.
     *
     * GoBackend passes this to VpnService.Builder.setSession(), and
     * Android puts it in 빠른설정 › VPN and in the dialog that opens when
     * a user taps the key icon. It was "aidotvpn0" — an interface name,
     * meaningless to whoever is checking whether their phone is
     * protected.
     *
     * WireGuard requires the name to match [a-zA-Z0-9_=+.-]{1,15}, so
     * this cannot be Korean and cannot be long. "AidotVPN" is what a
     * user would recognise inside those limits.
     */
    private val tunnel = AidotTunnel("AidotVPN", ::onTunnelStateChanged)

    /**
     * Bytes moved through the tunnel, or null when it is not up.
     *
     * The status notification says "보호 중", which is a claim. Counters
     * that climb are the evidence — the difference between a tunnel that
     * is established and one that is actually carrying the app's
     * traffic. Someone checking whether their phone is protected can see
     * the number move.
     */
    /**
     * Ask the controller for this device's current policy and persist it.
     *
     * Returns null when the controller cannot be reached, which the
     * caller reads as "keep using what we have" rather than "you have
     * nothing".
     *
     * Persisting matters as much as returning: the tunnel config is
     * built from the stored allocation, so a policy fetched and not
     * saved would pass the check above and then bring up a tunnel with
     * the old AllowedIPs.
     */
    private suspend fun refreshPolicyFromController(stored: StoredAllocation): StoredAllocation? {
        if (stored.deviceId.isBlank()) return null
        // The URL the device registered against, not a build constant:
        // vpnlib is a library and the host app decides where the
        // controller is.
        // Before the tunnel is up, so the bootstrap address. The tunnel
        // address only works once the tunnel exists, and this runs to
        // decide whether to bring it up.
        val url = CoreStorage.get(context).controllerUrlFor(tunnelUp = false)
        if (url == null) {
            lastRefreshFailure = "저장된 컨트롤러 주소가 없습니다"
            return null
        }
        val result = DeviceStateClient(url, stateToken = stored.stateToken).fetchResult(stored.deviceId)
        val st = result.getOrElse { e ->
            if (e is com.aidotvpn.client.core.StateAuthenticationException) {
                stop().getOrThrow()
                throw e
            }
            // Keep the reason for the warning the caller will show.
            lastRefreshFailure = e.message ?: "알 수 없는 오류"
            Log.w(TAG, "policy refresh failed: ${e.message}")
            return null
        }
        lastRefreshFailure = null
        if (st.status == "revoked") {
            // Throw, not return null.
            //
            // Returning null made the caller fall back to the stored
            // allocation and connect — so a device the admin had just
            // revoked brought its tunnel up anyway, with a warning about
            // the server being unreachable. Revocation is the one answer
            // that must stop the connect, not soften it.
            throw RevokedException()
        }
        val updated = stored.copy(
            policyBound = st.policyBound,
            allowedIps = st.allowedIps,
            routeScope = st.routeScope,
            dnsServers = st.dnsServers ?: stored.dnsServers,
            dnsSearchDomains = st.dnsSearchDomains ?: stored.dnsSearchDomains,
            appFilterMode = st.appFilterMode ?: stored.appFilterMode,
            appFilterPackages = st.appFilterPackages ?: stored.appFilterPackages,
            // Where to connect, as well as what may be reached. An empty
            // list means an older controller that did not send it; keep
            // what we have rather than forgetting the gateway entirely.
            nodes = if (st.nodes.isNotEmpty()) st.nodes else stored.nodes,
            virtualHosts = st.virtualHosts.map { "${it.virtual}=${it.real}" },
        )
        if (st.nodes.isNotEmpty() && st.nodes != stored.nodes) {
            Log.i(TAG, "gateway endpoint updated from controller")
        }
        CoreStorage.get(context).saveAllocation(updated)
        return updated
    }

    /**
     * Wait for the gateway to answer, then say so.
     *
     * WireGuard's handshake retries for about five seconds per attempt.
     * We poll the received-byte counter: anything above zero means a
     * response was decrypted, which is the only proof the far end holds
     * the matching keys and is reachable. Twelve seconds covers two
     * attempts on a slow link.
     *
     * On failure the interface stays up — a later handshake may still
     * succeed, and tearing it down would lose that — but the state says
     * Error so no screen can claim 연결됨 over a tunnel nothing came
     * back through.
     */
    private suspend fun awaitHandshake(timeoutMs: Long = 12_000) {
        val started = System.currentTimeMillis()
        while (System.currentTimeMillis() - started < timeoutMs) {
            val stats = statistics()
            Log.d(TAG, "handshake wait: rx=${stats?.first} tx=${stats?.second} state=${_state.value}")
            if (stats != null && stats.first > 0) {
                _state.value = TunnelState.Connected
                return
            }
            delay(500)
        }
        val sent = statistics()?.second ?: 0
        Log.w(TAG, "handshake did not complete within ${timeoutMs}ms (sent=$sent, received=0)")
        _state.value = TunnelState.Error(
            "문지기가 답하지 않습니다 (보낸 ${sent}B, 받은 0B). " +
                "서버 주소가 맞는지, 서버가 켜져 있는지 확인하세요.",
        )
    }

    fun statistics(): Pair<Long, Long>? = try {
        val s = backend.getStatistics(tunnel)
        if (s == null) {
            Log.w(TAG, "statistics: backend returned null — counters unavailable")
            null
        } else {
            s.totalRx() to s.totalTx()
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        // Log it. The bytes vanishing from the notification with no
        // reason anywhere is the fallback problem in miniature: a
        // display that silently stops updating looks the same as one
        // that has nothing to show.
        Log.w(TAG, "statistics unavailable: ${e.message}", e)
        null
    }

    /**
     * Active relay client when the chosen endpoint is wss_relay.
     * Null when running in direct-UDP mode (Scenarios A/B). Stop()
     * tears it down alongside the tunnel itself.
     */
    private var relayClient: RelayClient? = null

    /**
     * The last config we passed to GoBackend. Saved so [rebind] can
     * re-apply it after a network roam without rerunning registration
     * lookups. Cleared on [stop].
     */
    @Volatile
    private var lastConfig: Config? = null

    /**
     * Set to true during the brief DOWN→UP cycle in [rebind]. While
     * true, `onTunnelStateChanged` ignores callback-driven state
     * transitions — the rebind path manages [_state] explicitly so
     * downstream collectors (notably `AidotVpnService.bringTunnelUp`'s
     * `stopSelf`-on-Disconnected handler) don't see a transient
     * Disconnected and tear the service down before the UP completes.
     */
    @Volatile
    private var inRebind: Boolean = false

    /**
     * A condition the tunnel worked around rather than failed on.
     *
     * Distinct from TunnelState.Error, which means the tunnel is not up.
     * This is for the case where it *is* up but on information that
     * might be stale — a fallback the user should know happened, since
     * they are the only one who can tell whether it matters.
     */
    /** Set by refreshPolicyFromController when it returns null. */
    private var lastRefreshFailure: String? = null

    private val _lastWarning = MutableStateFlow<String?>(null)
    val lastWarning: StateFlow<String?> = _lastWarning.asStateFlow()

    private val _state = MutableStateFlow<TunnelState>(TunnelState.Disconnected)
    val state: StateFlow<TunnelState> = _state.asStateFlow()

    suspend fun start(): Result<Unit> = withContext(Dispatchers.IO) {
        // Record the intent before attempting, not after: a phone killed
        // mid-connect should come back trying, and the flag is what the
        // restarted service reads to decide.
        CoreStorage.get(context).saveTunnelWanted(true)
        try {
            val stored = CoreStorage.get(context).loadAllocation()
            if (stored == null) {
                // Distinct error so the UI can prompt re-registration.
                _state.value = TunnelState.Error("not registered — tap '디바이스 등록' first")
                return@withContext Result.failure(IllegalStateException("not registered"))
            }
            // Deny-by-default (0.10.0). A device the admin never bound to
            // a policy must not connect.
            //
            // Refusing here is friendlier than it sounds. The gateway
            // drops every packet from an unbound peer, so "connecting"
            // would produce a tunnel that silently eats all traffic —
            // and because the pre-0.10.0 client widened an empty policy
            // to 0.0.0.0/0, that meant the phone lost its internet
            // connection entirely with no indication why. Failing fast
            // with a message an admin can act on is the better outcome.
            // Refresh the policy from the controller before deciding.
            //
            // The stored allocation is what the controller said at
            // registration. An admin binding a policy afterwards changes
            // the controller and not this copy, so connecting kept
            // refusing with "접근 정책이 지정되지 않은 단말입니다" while
            // 설정 새로고침 — which does ask the controller — showed the
            // policy plainly. Screen and behaviour disagreed because they
            // read different things.
            //
            // Connect time is the only point where the answer has to be
            // current, so it is the point that has to ask.
            //
            // A failed fetch still connects on the stored copy — a phone
            // that cannot reach the controller should raise a tunnel it
            // was already granted. But it must not do so *silently*:
            // "the controller is unreachable" and "your policy is
            // current" are different situations, and a fallback that
            // conflates them leaves the user with no way to tell why
            // something later does not work.
            val fresh = try {
                refreshPolicyFromController(stored)
            } catch (e: RevokedException) {
                _state.value = TunnelState.Error(e.message ?: "폐기됨")
                return@withContext Result.failure(e)
            }
            val allocation = fresh ?: stored
            if (fresh == null) {
                // Say what failed. "서버에 연결할 수 없어" on its own sent
                // someone to check a controller that was up; the actual
                // reason was in an exception nobody printed.
                val why = lastRefreshFailure ?: "알 수 없는 이유"
                Log.w(TAG, "policy refresh failed ($why); connecting on the stored copy")
                _lastWarning.value = "정책을 새로 받지 못해 마지막으로 받은 설정으로 연결합니다.\n" +
                    "이유: $why\n" +
                    "관리자가 정책을 바꿨다면 반영되지 않았을 수 있습니다."
            } else {
                _lastWarning.value = null
            }

            if (!allocation.policyBound) {
                _state.value = TunnelState.Error(
                    "접근 정책이 지정되지 않은 단말입니다. 관리자에게 문의하세요."
                )
                Log.w(TAG, "refusing to connect: device is not bound to a policy")
                return@withContext Result.failure(
                    IllegalStateException("device is not policy-bound")
                )
            }

            val node = pickNode(allocation)
            if (node == null) {
                // The allocation predates the controller's peer-list
                // population (Phase 8.14). Stale-cache recovery is the
                // user clearing app data + re-registering; we surface
                // that hint here rather than crashing silently.
                _state.value = TunnelState.Error(
                    "no peer in saved allocation — clear app data and re-register"
                )
                return@withContext Result.failure(IllegalStateException("no node available"))
            }

            _state.value = TunnelState.Connecting

            // For relay-mode endpoints we have to spin up the WS bridge
            // BEFORE wireguard-go opens its socket — wg-go will start
            // dialing 127.0.0.1:51821 immediately, and if nothing is
            // listening there yet the first handshake initiation drops
            // on the floor and the user sees a 5-second stall before
            // the second attempt succeeds.
            if (!ensureRelayIfNeeded(allocation.deviceId, node)) {
                _state.value = TunnelState.Error(
                    "relay setup failed — controller relay disabled or VPS unreachable")
                return@withContext Result.failure(
                    IllegalStateException("relay setup failed"))
            }

            val cfg = buildConfig(allocation, node)
            // Pressing 연결 while connected must not break the connection.
            //
            // setState(UP) on a tunnel that is already up tears it down
            // and brings it back, so the handshake starts over — and
            // awaitHandshake then reported failure and the screen showed
            // 연결 안 됨, having destroyed a working tunnel to do it.
            //
            // What the button means is "I want to be connected". When
            // that is already true there is nothing to do; when the
            // config has changed since — a new policy — the new one is
            // applied without dropping the tunnel, which is what
            // WireGuard's own reconfiguration is for.
            if (_state.value is TunnelState.Connected && lastConfig != null) {
                if (lastConfig == cfg) {
                    Log.i(TAG, "already connected with this configuration; leaving it alone")
                    return@withContext Result.success(Unit)
                }
                Log.i(TAG, "connected with an older configuration; applying the new one")
                backend.setState(tunnel, Tunnel.State.UP, cfg)
                lastConfig = cfg
                return@withContext Result.success(Unit)
            }

            // Already up? Do not take it down to put it back.
            //
            // setState(UP) on a live tunnel tears the interface down and
            // raises it again, so the handshake starts over and
            // awaitHandshake's twelve seconds begin from zero — press
            // 연결 while connected and a working tunnel became 연결 안 됨.
            //
            // Pressing 연결 means "I want to be connected". If that is
            // already true there is nothing to do; if only the config has
            // changed — a new policy — rebind applies it without dropping
            // the interface. Neither path risks a working connection.
            // Already up? Leave it alone.
            //
            // The 연결 button is disabled while connected, so this is a
            // guard rather than a path the UI takes — Always-on VPN and
            // a system restart both come through start() too. Config
            // changes arrive via applyStoredConfig, which rebinds
            // without dropping the interface.
            if (_state.value is TunnelState.Connected && lastConfig != null) {
                // Say so plainly. buildConfig has already logged
                // "selected endpoint" by this point, so without this
                // line a press that changed nothing looks identical in
                // logcat to one that raised a tunnel — and reading a
                // logcat is how the last four faults were found.
                Log.i(TAG, "connect requested but already connected; tunnel untouched")
                return@withContext Result.success(Unit)
            }

            Log.i(TAG, "bringing the tunnel up")
            backend.setState(tunnel, Tunnel.State.UP, cfg)
            lastConfig = cfg
            // Up, not yet answered. awaitHandshake flips this to
            // Connected when the gateway replies, or to Error when it
            // does not.
            _state.value = TunnelState.Handshaking
            awaitHandshake()
            Result.success(Unit)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            stopRelayIfRunning()
            _state.value = TunnelState.Error(e.message ?: "tunnel up failed")
            Result.failure(e)
        }
    }

    suspend fun stop(): Result<Unit> = withContext(Dispatchers.IO) {
        CoreStorage.get(context).saveTunnelWanted(false)
        try {
            backend.setState(tunnel, Tunnel.State.DOWN, null)
            stopRelayIfRunning()
            lastConfig = null
            _state.value = TunnelState.Disconnected
            Result.success(Unit)
        } catch (e: CancellationException) {
            // Cancellation is not a failure — see the note above.
            throw e
        } catch (e: Throwable) {
            stopRelayIfRunning()
            _state.value = TunnelState.Error(e.message ?: "tunnel down failed")
            Result.failure(e)
        }
    }

    /**
     * Force a fresh handshake without changing the saved allocation.
     * Called by [com.aidotvpn.client.vpnlib.NetworkMonitor] when the
     * default network changes.
     *
     * If the tunnel isn't currently connected we return success quietly
     * — there is nothing to rebind, and a `lastConfig`-less start would
     * have to recompute from scratch which the user-driven Connect
     * button does already.
     *
     * The DOWN→UP cycle here is sub-second on Android 13+ devices we've
     * profiled (Pixel 7, S23, A54). It does cause a brief gap in
     * inbound packets — we mark the StateFlow as Connecting during
     * the cycle so the UI can show "재연결 중..." instead of the
     * misleading "Connected".
     */
    /**
     * When the last rebind ran, and how many have run in a row.
     *
     * A second line of defence. The NOT_VPN filter should stop the
     * monitor seeing our own interface, but a rebind loop takes the
     * tunnel down and up repeatedly and the user watches it flap — so a
     * cheap ceiling is worth having even if the cause is fixed.
     *
     * Three within ten seconds is not roaming. A handset changing
     * networks that fast has a bigger problem than a stale tunnel, and
     * rebinding through it makes that problem worse.
     */

    /** The controller says this device is revoked. Connecting must stop. */
    class RevokedException : Exception("이 단말은 폐기되었습니다. 다시 등록하세요.")

    private var lastRebindAt = 0L
    private var rebindBurst = 0

    private fun rebindAllowed(): Boolean {
        val now = System.currentTimeMillis()
        if (now - lastRebindAt > 10_000) {
            rebindBurst = 0
        }
        lastRebindAt = now
        rebindBurst += 1
        if (rebindBurst > 3) {
            Log.w(TAG, "rebind suppressed: $rebindBurst in 10s — treating as a loop, not a roam")
            return false
        }
        return true
    }

    /**
     * Apply the stored policy to an active tunnel.
     * GoBackend 1.0.20250531 internally performs DOWN/UP for a changed
     * config and attempts to restore the previous config on failure.
     * Suppress those intermediate callbacks while the operation runs;
     * this is a tunnel recreation, not a zero-downtime update.
     */
    suspend fun applyConfig(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            // A handshake timeout reports Error while GoBackend remains UP.
            // Policy changes and revocation must follow the actual interface,
            // not the presentation state.
            if (backend.getState(tunnel) != Tunnel.State.UP) {
                Log.i(TAG, "applyConfig: no tunnel up; nothing to update")
                return@withContext Result.success(Unit)
            }
            val allocation = CoreStorage.get(context).loadAllocation()
                ?: error("저장된 VPN 설정이 없습니다")
            if (!allocation.policyBound) {
                stop().getOrThrow()
                error("접근 정책이 해제되어 VPN 연결을 종료했습니다")
            }
            val node = pickNode(allocation) ?: error("VPN 게이트웨이 설정이 없습니다")
            val cfg = buildConfig(allocation, node)
            if (lastConfig == cfg) return@withContext Result.success(Unit)
            inRebind = true
            backend.setState(tunnel, Tunnel.State.UP, cfg)
            lastConfig = cfg
            Log.i(TAG, "applyConfig: refreshed stored configuration applied")
            Result.success(Unit)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            Log.w(TAG, "applyConfig failed: ${e.message}", e)
            Result.failure(e)
        } finally {
            inRebind = false
        }
    }


    // rebind() was removed in 1.14.7.
    //
    // It took the interface down and back up on every network change,
    // which is the one thing WireGuard is designed to make unnecessary:
    // the protocol roams by itself, and the Linux client — which does
    // nothing at all on a network change — has never had the fault this
    // caused. Anyone reaching for it again should read that release
    // note first. applyConfig() is what updates a running tunnel.

    private fun onTunnelStateChanged(newState: Tunnel.State) {
        if (inRebind) {
            // Suppressed: the rebind() path drives _state explicitly.
            // Letting GoBackend's DOWN callback through here would
            // surface a transient Disconnected to subscribers like
            // AidotVpnService.bringTunnelUp, which would then call
            // stopSelf() — killing the service mid-rebind.
            return
        }
        // Log every backend transition, with a stack for DOWN.
        //
        // A tunnel that drops five seconds after connecting has exactly
        // one observable cause — the backend reporting DOWN — and no way
        // to tell who asked. Five rounds of reading this file did not
        // find it; the stack will say in one run.
        if (newState == Tunnel.State.DOWN) {
            Log.w(TAG, "backend reported DOWN", Throwable("who took the tunnel down"))
        } else {
            Log.i(TAG, "backend state -> $newState")
        }
        _state.value = when (newState) {
            Tunnel.State.UP -> TunnelState.Connected
            Tunnel.State.DOWN -> TunnelState.Disconnected
            Tunnel.State.TOGGLE -> TunnelState.Connecting
        }
    }

    /**
     * Pick a node. Phase 5 keeps it dumb: take the first one in the
     * allocation. Phase 6 will add latency probing + sticky preferences
     * + the obfuscation-mode fallback chain.
     */
    private fun pickNode(allocation: StoredAllocation): NodeModel? =
        allocation.nodes.firstOrNull()

    private fun buildConfig(alloc: StoredAllocation, node: NodeModel): Config {
        val privateKey = KeyUtils.privateKeyFromB64(alloc.devicePrivateKeyB64)
        val keyPair = KeyPair(privateKey)
        val nodePub = Key.fromBase64(node.publicKey)
        val psk = Key.fromBase64(alloc.pskB64)

        // Endpoint mode selection priority:
        //   1. Direct WG (UDP) — lowest latency, used in Scenarios A/B
        //   2. Relay (wss_relay) — for clients behind CGNAT (Scenario C);
        //      requires relayTokenProvider to mint a session token first
        //   3. Anything else as a last resort, won't currently work
        //      because we don't speak obfuscation modes yet
        //
        // Once the chosen endpoint is a relay, buildConfig switches the
        // wireguard-go peer endpoint to a loopback socket that the
        // RelayClient terminates locally. This lets wireguard-go think
        // it's talking direct UDP while the actual transport is the
        // WebSocket bridge to a public-IP VPS.
        val endpoint = pickEndpoint(node)
            ?: error("node ${node.id} has no usable endpoint")

        Log.i("AidotVpn/Tunnel", "selected endpoint mode=${endpoint.mode} host=${endpoint.publicHost}:${endpoint.publicPort}")

        val (peerHost, peerPort) = when (endpoint.mode) {
            ENDPOINT_MODE_WG -> endpoint.publicHost to endpoint.publicPort
            ENDPOINT_MODE_WSS_RELAY -> {
                // RelayClient binds a loopback DatagramSocket. wireguard-go
                // is told to dial that, so traffic flows wg-go ←→ relay
                // client ←→ WebSocket ←→ VPS ←→ wg-data-node.
                "127.0.0.1" to RelayClient.DEFAULT_WG_LOOPBACK_PORT + 1
            }
            else -> {
                Log.w("AidotVpn/Tunnel",
                    "unsupported endpoint mode '${endpoint.mode}' — falling back to direct host:port")
                endpoint.publicHost to endpoint.publicPort
            }
        }

        val ifaceBuilder = Interface.Builder()
            .setKeyPair(keyPair)
        if (alloc.ipv4Addr.isNotEmpty()) {
            ifaceBuilder.addAddress(InetNetwork.parse("${alloc.ipv4Addr}/32"))
        }
        if (alloc.ipv6Addr.isNotEmpty()) {
            ifaceBuilder.addAddress(InetNetwork.parse("${alloc.ipv6Addr}/128"))
        }
        // DNS push (0.15.0). Empty list leaves the system resolver alone,
        // which is what every pre-0.15.0 deployment does.
        //
        // The controller guarantees each of these addresses is also in
        // allowedIps, so the tunnel can reach them. Without that the
        // device sends every query into a tunnel with no matching route
        // and each lookup times out — a failure that presents as "the
        // internet is broken" rather than "DNS is misconfigured".
        //
        // Scope caveat worth knowing when reading a bug report: Android
        // applies a VPN's DNS servers to every app on the VPN network,
        // not only to traffic matching the tunnel's routes. With
        // appFilterMode = "off" and a split tunnel, an internal-only
        // resolver therefore captures ALL device DNS, and public names
        // stop resolving unless that resolver forwards upstream. Using
        // appFilterMode = "include" confines the effect to the listed
        // apps. The controller warns on the risky combination.
        alloc.dnsServers.forEach { server ->
            runCatching { ifaceBuilder.addDnsServer(InetAddress.getByName(server)) }
                .onFailure { Log.w(TAG, "skipping unparseable DNS server '$server'") }
        }
        alloc.dnsSearchDomains.forEach { domain ->
            runCatching { ifaceBuilder.addDnsSearchDomain(domain) }
                .onFailure { Log.w(TAG, "skipping invalid search domain '$domain'") }
        }
        if (alloc.dnsServers.isNotEmpty()) {
            Log.i(TAG, "DNS pushed: ${alloc.dnsServers.size} server(s), " +
                "${alloc.dnsSearchDomains.size} search domain(s)")
        }

        // Phase 8: per-app split tunnel.
        //
        // wireguard-android's Interface.Builder.includeApplication /
        // excludeApplication ultimately call VpnService.Builder.add{Allowed,
        // Disallowed}Application — and **those throw NameNotFoundException
        // if the package isn't installed**, which would crash the tunnel
        // start. So we filter the server-pushed list against actually-
        // installed packages before handing it to the builder. Packages
        // missing locally are logged but not fatal — the admin can still
        // queue a future install via MDM and it picks up at the next
        // rotateKey cycle.
        applyAppFilter(ifaceBuilder, alloc.appFilterMode, alloc.appFilterPackages)

        val peerBuilder = Peer.Builder()
            .setPublicKey(nodePub)
            .setPreSharedKey(psk)
            .setEndpoint(InetEndpoint.parse("$peerHost:$peerPort"))
            .setPersistentKeepalive(25)

        // Server-driven split tunnel. The controller returns the CIDRs
        // this device's policy permits; we route only those through wg0.
        //
        // 0.10.0 changed what an EMPTY list means, and the distinction is
        // the whole point of the release:
        //
        //   policyBound = true, list non-empty
        //       → normal case. Route exactly these CIDRs.
        //
        //   policyBound = true, list empty
        //       → the admin bound a policy but it currently has no
        //         destinations (mid-edit). Bring the tunnel up with no
        //         routes rather than falling back to 0.0.0.0/0.
        //
        //   policyBound = false
        //       → not provisioned. buildConfig is never reached; connect()
        //         rejects earlier with a message the user can act on.
        //
        // The pre-0.10.0 behaviour — empty list means full tunnel — was
        // exactly backwards for a hospital deployment. It granted the
        // widest possible access precisely when the server had said
        // nothing about what this device should reach.
        // 0.12.0 — route scope (axis 2: WHAT HAPPENS TO NON-PERMITTED
        // TRAFFIC). Independent of the per-app filter above.
        //
        //   "policy" (default)  Split tunnel. Route only the policy's
        //                       CIDRs. Anything else never enters the
        //                       tunnel and uses the normal network, so
        //                       the device keeps working internet.
        //
        //   "full"              Lockdown. Route everything. The gateway's
        //                       default-drop chain then discards whatever
        //                       the policy doesn't permit, so the
        //                       tunnelled apps reach the permitted
        //                       servers and nothing else — not even the
        //                       public internet.
        //
        // Note that "full" is NOT a return of the pre-0.10.0 fallback.
        // That was 0.0.0.0/0 applied because the server had said nothing;
        // this is 0.0.0.0/0 applied because an admin explicitly chose
        // lockdown, on top of a gateway that permits only the policy.
        if (alloc.routeScope == ROUTE_SCOPE_FULL) {
            peerBuilder.addAllowedIp(InetNetwork.parse("0.0.0.0/0"))
            peerBuilder.addAllowedIp(InetNetwork.parse("::/0"))
            Log.i(TAG, "route scope=full (lockdown): all traffic enters the tunnel")
        } else if (alloc.allowedIps.isNotEmpty()) {
            // The controller's own address stays out of the tunnel.
            //
            // The app talks to the controller to refresh its policy and
            // to learn it has been revoked. Routing that through the
            // tunnel makes it depend on the thing it is supposed to
            // manage: when the tunnel is down or the gateway is
            // unreachable, the app cannot ask why, and every call times
            // out with "서버에 연결할 수 없습니다".
            //
            // SDK control sockets are also protected in full-route mode:
            // bind -> protect -> connect creates a valid native descriptor.
            // Protection belongs to the prepared app UID, not a particular
            // VpnService instance. Keep the split-route exclusion for
            // compatibility with existing policy routing behavior.
            val controlHost = runCatching {
                CoreStorage.get(context).loadControllerUrl()?.let { java.net.URI(it).host }
            }.getOrNull()

            alloc.allowedIps.forEach { cidr ->
                if (controlHost != null && cidr.substringBefore('/') == controlHost) {
                    Log.i(TAG, "excluding controller $cidr from the tunnel")
                    return@forEach
                }
                peerBuilder.addAllowedIp(InetNetwork.parse(cidr))
            }
        } else {
            Log.w(TAG, "allocation has no AllowedIPs; tunnel will carry no traffic")
        }

        val peer = peerBuilder.build()

        return Config.Builder()
            .setInterface(ifaceBuilder.build())
            .addPeer(peer)
            .build()
    }

    /**
     * Apply the per-app tunnel rule (axis 1: WHICH APPS enter the
     * tunnel).
     *
     * Maps onto `VpnService.Builder.addAllowedApplication` /
     * `addDisallowedApplication`. Android enforces these by UID, and a
     * Builder may hold an allow set OR a deny set but never both —
     * calling one after the other throws `UnsupportedOperationException`,
     * which is why the modes are exclusive here too.
     *
     * Packages that aren't installed are filtered out first, because the
     * platform API throws `NameNotFoundException` on a missing package
     * and that would abort tunnel start entirely.
     *
     * Edge cases:
     *   - Mode "off"/blank → no-op. All apps enter the tunnel, subject
     *     only to the AllowedIPs from axis 2.
     *   - Mode "exclude" with nothing installed → equivalent to "off".
     *     Excluding no apps means everything tunnels, which is exactly
     *     what an empty exclude set means. Safe.
     *   - Mode "include" with nothing installed → THROWS. See below.
     *   - Including the host app itself is correct in embedded mode (the
     *     business app's traffic is the traffic you want tunnelled). The
     *     WireGuard socket is exempt regardless via SocketProtector, so
     *     there is no routing loop.
     */
    private fun applyAppFilter(
        builder: Interface.Builder,
        mode: String,
        packages: List<String>,
    ) {
        if (mode.isBlank() || mode == APP_FILTER_OFF) return
        require(mode == APP_FILTER_INCLUDE || mode == APP_FILTER_EXCLUDE) {
            "지원하지 않는 앱 VPN 정책입니다: $mode. 관리자에게 정책을 확인하세요."
        }

        // Filter to installed packages only. PackageManager.getPackageInfo
        // is the lightweight existence check; we don't actually need the
        // returned info.
        val pm = context.packageManager
        val installed = packages.filter { pkg ->
            try {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, 0)
                true
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                Log.w("AidotVpn/Tunnel", "app filter: package '$pkg' not installed; skipped")
                false
            }
        }

        if (installed.isEmpty()) {
            if (mode == APP_FILTER_INCLUDE) {
                // FAIL CLOSED (fixed in 0.12.0).
                //
                // This previously fell back to mode=off, which inverted
                // the admin's intent in the worst possible direction: a
                // policy saying "only the EMR app may use this tunnel"
                // became "every app on the phone uses this tunnel" the
                // moment the EMR app was uninstalled, renamed, or hidden
                // from us by package-visibility rules.
                //
                // It is the same class of bug as the pre-0.10.0 empty
                // AllowedIPs → 0.0.0.0/0 fallback, on the other axis:
                // treating "the server told me nothing" as "allow the
                // widest thing". Refusing to build the tunnel is the
                // only correct answer.
                throw IllegalStateException(
                    "app filter is include-only but none of the listed packages " +
                        "(${packages.joinToString()}) are installed or visible; " +
                        "refusing to tunnel every app instead"
                )
            }
            // Exclude mode: an empty exclude set genuinely means "tunnel
            // everything", so this is not an error.
            Log.i(
                "AidotVpn/Tunnel",
                "app filter mode=exclude but no listed packages are installed; all apps tunnel",
            )
            return
        }

        when (mode) {
            APP_FILTER_INCLUDE -> {
                installed.forEach { builder.includeApplication(it) }
                Log.i(
                    "AidotVpn/Tunnel",
                    "app filter: include-only ${installed.size} package(s)",
                )
            }
            APP_FILTER_EXCLUDE -> {
                installed.forEach { builder.excludeApplication(it) }
                Log.i(
                    "AidotVpn/Tunnel",
                    "app filter: exclude ${installed.size} package(s)",
                )
            }
            else -> {
                // Forward-compat: unknown mode from a newer server.
                // Refuse to apply rather than guessing.
                Log.w("AidotVpn/Tunnel", "app filter: unknown mode '$mode'; ignoring")
            }
        }
    }

    /**
     * Pick the best available endpoint for [node]. Preference order:
     * direct WG → relay → other (best effort, may not work).
     */
    private fun pickEndpoint(node: NodeModel): EndpointModel? =
        node.endpoints.firstOrNull { it.mode == ENDPOINT_MODE_WG }
            ?: node.endpoints.firstOrNull { it.mode == ENDPOINT_MODE_WSS_RELAY }
            ?: node.endpoints.firstOrNull()

    /**
     * If the chosen endpoint requires a relay, fetch a token, open the
     * WS bridge, and wait for the relay to acknowledge our hello frame.
     * Returns true on success or when no relay was needed; false on
     * hard error so callers can surface a clear message.
     */
    private suspend fun ensureRelayIfNeeded(
        deviceId: String,
        node: NodeModel,
    ): Boolean {
        val endpoint = pickEndpoint(node) ?: return false
        if (endpoint.mode != ENDPOINT_MODE_WSS_RELAY) return true

        val provider = relayTokenProvider
        if (provider == null) {
            Log.w("AidotVpn/Tunnel",
                "endpoint requires relay but no relayTokenProvider was wired in")
            return false
        }
        val token = provider(deviceId) ?: run {
            Log.w("AidotVpn/Tunnel", "failed to fetch relay token from controller")
            return false
        }
        // Build wss:// URL from the endpoint's host/port.
        val scheme = if (endpoint.publicPort == 443) "wss" else "ws"
        val url = "$scheme://${endpoint.publicHost}:${endpoint.publicPort}/ws/mobile"
        val client = RelayClient(
            relayUrl = url,
            relayToken = token,
            targetNodeId = node.id,
            wgLoopbackPort = RelayClient.DEFAULT_WG_LOOPBACK_PORT,
        )
        return withContext(Dispatchers.IO) {
            val ok = client.start()
            if (ok) {
                relayClient = client
                Log.i("AidotVpn/Tunnel", "relay client ready: $url")
            } else {
                Log.w("AidotVpn/Tunnel", "relay client failed to start")
            }
            ok
        }
    }

    /** Tear down the relay client if one was started. Safe to call repeatedly. */
    private fun stopRelayIfRunning() {
        relayClient?.stop()
        relayClient = null
    }

    companion object {
        private const val TAG = "TunnelManager"
        private const val ENDPOINT_MODE_WG = "wg"
        private const val ENDPOINT_MODE_WSS_RELAY = "wss_relay"
        private const val APP_FILTER_OFF = "off"
        private const val ROUTE_SCOPE_FULL = "full"
        private const val APP_FILTER_INCLUDE = "include"
        private const val APP_FILTER_EXCLUDE = "exclude"
    }
}

sealed class TunnelState {
    data object Disconnected : TunnelState()
    data object Connecting : TunnelState()

    /**
     * The interface is up and initiations are going out, but the
     * gateway has not answered yet.
     *
     * WireGuard raises the interface whether or not a peer exists, so
     * "the interface is up" says nothing about reachability. Reporting
     * Connected there told a user their phone was on the hospital
     * network while every probe timed out — on a screen that showed
     * SocketTimeoutException right below the green text. Handshaking is
     * the honest state until bytes come back.
     */
    data object Handshaking : TunnelState()
    data object Connected : TunnelState()
    data class Error(val message: String) : TunnelState()
}

/**
 * Concrete Tunnel impl wireguard-android needs. Just a name + a state
 * change callback the backend uses to notify us of background changes
 * (e.g. user toggled VPN off in system Settings).
 */
private class AidotTunnel(
    private val tunName: String,
    private val stateChangeCallback: (Tunnel.State) -> Unit,
) : Tunnel {
    override fun getName(): String = tunName
    override fun onStateChange(newState: Tunnel.State) {
        stateChangeCallback(newState)
    }
}
