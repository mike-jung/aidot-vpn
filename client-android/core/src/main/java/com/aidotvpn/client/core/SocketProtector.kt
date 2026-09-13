package com.aidotvpn.client.core

import java.net.DatagramSocket
import java.net.Socket

/**
 * Bridges :core's HTTP / WebSocket / UDP-bridge sockets to the live
 * `VpnService.protect()` call provided by :app's AidotVpnService.
 *
 * # Why this exists
 *
 * When the AidotVpn tunnel is up with `AllowedIPs = 0.0.0.0/0` (full
 * tunnel), an unprotected outbound TCP socket from inside our own
 * process — for example, the controller HTTP call that fetches a fresh
 * relay token, or the WebSocket carrying relay traffic when in
 * Scenario C — is itself routed through wg0. The packet leaves the
 * device on wg0, hits the data-node, exits to the public internet,
 * arrives at the controller, and the response retraces the same path.
 * In the best case this works but doubles latency. In the more common
 * case, the controller hostname's resolved IP isn't in `AllowedIPs`
 * (we resolved it on the underlying network *before* the tunnel came
 * up, then the resolution cache outlives the routing change), and the
 * SYN never makes it back to us — the user sees a 30s call timeout.
 *
 * `VpnService.protect(socket)` binds the socket to the system default
 * network at the OS level, bypassing wg0 unconditionally. The platform
 * documents this is the supported way for a VPN app's own infra
 * sockets (callbacks, control channel, attestation server) to escape
 * the tunnel they themselves operate.
 *
 * # Lifecycle
 *
 * The :vpnlib module's [com.aidotvpn.client.vpnlib.AidotVpnService]
 * registers itself as the [strategy] in `onCreate()` and unregisters
 * in `onDestroy()`. While unregistered (tunnel down, or the SDK
 * consumer using us at register-time only), `protect()` is a no-op —
 * sockets simply use the default network, which is what we want at
 * that point anyway.
 *
 * # Thread safety
 *
 * `strategy` is `@Volatile`; reads from arbitrary OkHttp socket-creation
 * threads are safe. The unbind path uses `synchronized` to avoid a race
 * where a newer service's [bind] is overwritten by the older service's
 * delayed [unbind].
 */
object SocketProtector {

    /**
     * Capability provided by the active VpnService. Each method returns
     * `true` on success, `false` if the platform refused (rare; usually
     * means the service is being destroyed mid-call).
     */
    interface Strategy {
        fun protectSocket(socket: Socket): Boolean
        fun protectDatagramSocket(socket: DatagramSocket): Boolean
        fun protectFd(fd: Int): Boolean
    }

    @Volatile
    private var strategy: Strategy? = null

    /** Called by AidotVpnService.onCreate(). */
    fun bind(s: Strategy) {
        strategy = s
    }

    /**
     * Called by AidotVpnService.onDestroy(). Only clears the slot if
     * [s] is still the registered instance — when the system tears down
     * an old service after a new one is already up, the old's onDestroy
     * arrives later and would otherwise wipe the live registration.
     */
    fun unbind(s: Strategy) {
        synchronized(this) {
            if (strategy === s) strategy = null
        }
    }

    /** True iff a VpnService is currently registered. */
    val isActive: Boolean get() = strategy != null

    fun protect(socket: Socket): Boolean =
        strategy?.protectSocket(socket) ?: false

    fun protect(socket: DatagramSocket): Boolean =
        strategy?.protectDatagramSocket(socket) ?: false

    fun protect(fd: Int): Boolean =
        strategy?.protectFd(fd) ?: false
}
