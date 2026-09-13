package com.aidotvpn.client.vpnlib

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.SystemClock
import android.util.Log

/**
 * NetworkMonitor watches the **default network** (the network that
 * non-VPN traffic would use — Wi-Fi, cellular, ethernet, …) and fires
 * [onRoamed] when it switches transports.
 *
 * # Why we need this even with persistent_keepalive=25s
 *
 * WireGuard tracks endpoint IP at the wire layer, so a Wi-Fi → LTE
 * handover usually recovers within one keepalive cycle (~25s). For
 * a user who just walked into the parking lot, that 25s is felt as
 * "the app froze, then unfroze". Forcing a fresh handshake the moment
 * the OS tells us the default network changed cuts that to ~1s.
 *
 * # What "roamed" means
 *
 * `ConnectivityManager.registerDefaultNetworkCallback` fires:
 *
 *   - `onAvailable(net)` when a default network exists (initial bind,
 *     or recovery after `onLost`).
 *   - `onLost(net)` when the default network goes away with no
 *     replacement.
 *   - `onCapabilitiesChanged(net, caps)` for transport changes.
 *
 * "Roamed" is specifically: a *new* default network became available
 * after we already had one (i.e. the underlying transport changed).
 * Pure availability transitions (`onLost` followed by `onAvailable` of
 * the same network handle) shouldn't fire — those are momentary
 * blips that WireGuard's keepalive handles fine.
 *
 * # Lifecycle
 *
 * Owned by [com.aidotvpn.client.vpnlib.AidotVpnService] — start in
 * `onCreate`, stop in `onDestroy`. `unregisterNetworkCallback` is
 * idempotent-safe via the [registered] flag.
 */
class NetworkMonitor(
    private val context: Context,
    private val onRoamed: () -> Unit,
    /**
     * The real network now carrying the tunnel, or null when there is
     * none.
     *
     * Handed to `VpnService.setUnderlyingNetworks`. Without it the
     * framework infers which network the VPN runs over, and that
     * inference is part of what re-announces networks after a VPN comes
     * up — the churn that made a tunnel rebind itself two seconds into
     * its own handshake. Saying it outright replaces a guess with a
     * fact, on both sides: the system stops guessing, and we stop having
     * to guess whether an event was ours.
     */
    private val onUnderlyingNetwork: (Network?) -> Unit = {},
) {

    private val cm: ConnectivityManager? =
        context.getSystemService(ConnectivityManager::class.java)

    @Volatile
    private var registered = false

    @Volatile
    private var lastNetwork: Network? = null

    @Volatile
    private var lastTransport: Int = TRANSPORT_UNKNOWN

    private val callback = object : ConnectivityManager.NetworkCallback() {

        override fun onAvailable(network: Network) {
            val previous = lastNetwork
            lastNetwork = network

            // Bringing the tunnel up re-announces the underlying network.
            //
            // Establishing a VPN makes the framework re-evaluate every
            // network, and the Wi-Fi we are running over comes back with
            // a fresh Network handle — which is indistinguishable, here,
            // from the user walking between access points. The logcat
            // shows it plainly: "selected endpoint" at 07:40:36 and
            // "rebinding tunnel after network change" at 07:40:38, twice
            // in a row, each right after a connect.
            //
            // A rebind two seconds into a handshake is what made the
            // second connect fail while the first and third held. So a
            // roam that lands within the settling window is ignored: the
            // tunnel we would rebind is the one that just caused it.
            // Whatever else we decide about this event, the framework
            // should be told which network carries the tunnel now.
            onUnderlyingNetwork(network)

            // The settling window used to live here, suppressing events
            // for five seconds after the tunnel came up. It went because
            // the framework produced events at nine seconds too, and
            // widening a window to cover what you last observed is how
            // you get a number that is wrong next time. The decision
            // moved to TunnelManager.rebind, which asks whether the
            // tunnel is still carrying traffic — a question about now,
            // not about how long ago something happened.
            val sinceTunnelUp = SystemClock.elapsedRealtime() - tunnelUpAt
            Log.i(TAG, "network re-announced ${sinceTunnelUp}ms after the tunnel came up")
            if (previous == null) {
                // First default network we've ever seen — initial bind.
                Log.i(TAG, "default network available: $network (initial)")
                return
            }
            if (previous == network) {
                // Same Network handle re-announced; not a real roam.
                return
            }
            Log.i(TAG, "default network changed: $previous -> $network — triggering rebind")
            onRoamed()
        }

        override fun onLost(network: Network) {
            if (network == lastNetwork) onUnderlyingNetwork(null)
            // Don't clear lastNetwork yet — onAvailable on the
            // replacement transport will tell us the new identity. If
            // there is no replacement (airplane mode), the next
            // onAvailable after the user reconnects is correctly seen
            // as "first default network we've ever seen" and skips
            // the rebind path. Either is right.
            Log.i(TAG, "default network lost: $network")
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            // Transport-class changes (Wi-Fi metered → not, VPN added,
            // etc.) without a Network identity change. We log but
            // don't rebind on these — the wg-go socket survives
            // capability flips.
            val newTransport = transportOf(caps)
            if (newTransport != lastTransport) {
                Log.i(
                    TAG,
                    "transport changed on $network: ${transportLabel(lastTransport)} -> ${transportLabel(newTransport)}",
                )
                lastTransport = newTransport
            }
        }
    }

    /**
     * When the tunnel last came up, so [onAvailable] can tell a real
     * roam from the framework re-announcing networks because of us.
     *
     * A timestamp rather than a flag: a flag has to be cleared, and
     * whatever clears it becomes another thing that can be wrong. This
     * cannot get stuck — it simply stops mattering.
     */
    @Volatile
    private var tunnelUpAt: Long = 0

    fun noteTunnelUp() {
        tunnelUpAt = SystemClock.elapsedRealtime()
    }

    fun start() {
        if (registered) return
        val mgr = cm ?: run {
            Log.w(TAG, "ConnectivityManager unavailable; roaming monitor disabled")
            return
        }
        try {
            // NOT_VPN, and a request rather than the default callback.
            //
            // registerDefaultNetworkCallback reports the VPN itself once
            // the tunnel is up, because a VPN becomes the default
            // network. That produced a loop:
            //
            //   터널 섬 → 기본망이 VPN 으로 바뀜 → onAvailable(VPN)
            //   → 로밍으로 오인 → rebind → 터널 내려감
            //   → 기본망이 CELLULAR 로 → onAvailable → 다시 rebind → …
            //
            // A logcat from a real handset shows the result: VPN state
            // CONNECTED five times and DISCONNECTED six, alternating,
            // ending disconnected.
            //
            // NET_CAPABILITY_NOT_VPN excludes our own interface, so the
            // monitor watches what it was written to watch — the
            // underlying transport the tunnel runs over.
            mgr.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build(),
                callback,
            )
            registered = true
            Log.i(TAG, "default network callback registered")
        } catch (e: SecurityException) {
            // Some restricted profiles deny the callback. Not fatal.
            Log.w(TAG, "registerDefaultNetworkCallback denied", e)
        }
    }

    fun stop() {
        if (!registered) return
        runCatching { cm?.unregisterNetworkCallback(callback) }
        registered = false
        lastNetwork = null
        lastTransport = TRANSPORT_UNKNOWN
        Log.i(TAG, "default network callback unregistered")
    }

    private fun transportOf(caps: NetworkCapabilities): Int = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> TRANSPORT_WIFI
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> TRANSPORT_CELLULAR
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> TRANSPORT_ETHERNET
        caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> TRANSPORT_BLUETOOTH
        else -> TRANSPORT_UNKNOWN
    }

    private fun transportLabel(t: Int): String = when (t) {
        TRANSPORT_WIFI -> "wifi"
        TRANSPORT_CELLULAR -> "cellular"
        TRANSPORT_ETHERNET -> "ethernet"
        TRANSPORT_BLUETOOTH -> "bluetooth"
        else -> "unknown"
    }

    companion object {
        private const val TAG = "AidotVpn/NetMon"

        /**
         * How long after the tunnel comes up a network re-announcement is
         * attributed to the tunnel itself.
         *
         * Five seconds covers the framework's re-evaluation. A real roam
         * inside that window costs one missed rebind — and the tunnel
         * repairs itself on the next handshake anyway — while acting on a
         * false one costs the connection outright.
         */
        private const val SETTLING_MS = 5_000L

        private const val TRANSPORT_UNKNOWN = -1
        private const val TRANSPORT_WIFI = 1
        private const val TRANSPORT_CELLULAR = 2
        private const val TRANSPORT_ETHERNET = 3
        private const val TRANSPORT_BLUETOOTH = 4
    }
}
