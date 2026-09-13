package com.aidotvpn.client.vpnlib

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Network
import android.net.VpnService
import android.os.Build
import androidx.core.app.NotificationCompat
import com.aidotvpn.client.core.CoreStorage
import com.aidotvpn.client.core.StoredAllocation
import com.aidotvpn.client.core.SocketProtector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay

/**
 * AidotVpnService is the system-blessed [VpnService]. The kernel hands
 * us the routing socket only after the user accepts the VPN consent
 * dialog (`VpnService.prepare()` flow).
 *
 * Note: the WireGuard tunnel itself is started by [TunnelManager], not
 * here. The VpnService.Builder we expose is consumed by GoBackend to
 * establish the routing fd. We keep this thin so the heavy lifting
 * lives in TunnelManager where it's testable.
 */
class AidotVpnService : VpnService() {

    private val supervisor = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.Default + supervisor)

    /**
     * Forwards the four `VpnService.protect()` overloads :core needs for
     * its OkHttp / WebSocket / DatagramSocket plumbing. We have to wrap
     * because :core can't depend on android.net.VpnService directly —
     * see SocketProtector.kt for the rationale.
     */
    private val protectStrategy = object : SocketProtector.Strategy {
        override fun protectSocket(socket: java.net.Socket): Boolean =
            this@AidotVpnService.protect(socket)

        override fun protectDatagramSocket(socket: java.net.DatagramSocket): Boolean =
            this@AidotVpnService.protect(socket)

        override fun protectFd(fd: Int): Boolean =
            this@AidotVpnService.protect(fd)
    }

    /**
     * Watches default-network roams (Wi-Fi ↔ LTE) and asks
     * TunnelManager to bounce the WireGuard interface so the user
     * doesn't wait the full 25-second keepalive cycle for traffic to
     * resume.
     */
    private val networkMonitor by lazy {
        NetworkMonitor(
            context = this,
            // A network change is not something to act on.
            //
            // WireGuard roams by design: the client keeps sending from
            // whatever address it now has, and the peer updates its
            // endpoint from the first authenticated packet. The session
            // keys are untouched — no renegotiation, no reconnection.
            // wg-quick on Linux brings the interface up and never
            // touches it again, which is exactly why the Linux client
            // never had this bug.
            //
            // Rebinding was this app re-implementing roaming with a far
            // more destructive tool, and three releases of settling
            // windows and liveness checks were attempts to make a
            // mechanism that should not exist behave. What Android
            // genuinely needs — a protected socket, and
            // setUnderlyingNetworks so the framework knows what carries
            // the tunnel — is already in place.
            onRoamed = {
                android.util.Log.i(TAG, "network changed; WireGuard handles roaming, leaving the tunnel alone")
            },
            onUnderlyingNetwork = { network -> publishUnderlying(network) },
        )
    }

    /**
     * Tell the framework which real network carries the tunnel.
     *
     * `setUnderlyingNetworks` only takes effect while the VPN is
     * established, and throws if it is not — so a failure here is
     * ordinary (we are between tunnels) and logged rather than raised.
     *
     * With this set, the system knows the answer instead of inferring
     * it, which is what stops it re-evaluating every network each time a
     * VPN appears. The five-second settling window in NetworkMonitor
     * covers the case where it still does; this is what makes that
     * window rarely matter.
     */
    private fun publishUnderlying(network: Network?) {
        try {
            setUnderlyingNetworks(network?.let { arrayOf(it) })
            android.util.Log.i(TAG, "underlying network -> ${network ?: "(none)"}")
        } catch (e: Exception) {
            android.util.Log.d(TAG, "setUnderlyingNetworks skipped: ${e.message}")
        }
    }

    override fun onCreate() {
        super.onCreate()
        // Mirror status into the notification, once, for the life of
        // the service.
        //
        // This used to live inside bringTunnelUp(), so a collector was
        // attached on every 연결 press and none on 끊기. Two presses
        // meant two collectors writing the same notification, and the
        // disconnect path had nobody watching at all — which is why the
        // notification froze on "연결하는 중…" and stayed there through
        // both connect and disconnect.
        //
        // onCreate runs once per service instance, which is the lifetime
        // this collector should have.
        //
        // wasConnected tracks the transition, not the state: an outage
        // is Connected → Error, and Error on the first attempt is a
        // failed connect the user is already watching for.
        var wasConnected = false

        // Whether a tunnel has ever been up or coming up in this
        // service's lifetime. See the Disconnected branch below.

        val tm = AidotVpnEngine.get(applicationContext).tunnelManager
        scope.launch {
            tm.state.collectLatest { state ->
                val text = when (state) {
                    is TunnelState.Disconnected -> getString(R.string.aidotvpn_notif_disconnected)
                    is TunnelState.Connecting   -> getString(R.string.aidotvpn_notif_connecting)
                    is TunnelState.Handshaking  -> getString(R.string.aidotvpn_notif_handshaking)
                    is TunnelState.Connected    -> getString(R.string.aidotvpn_notif_connected)
                    is TunnelState.Error        -> getString(R.string.aidotvpn_notif_error, state.message)
                }
                updateNotification(text)

                // Alert only when a working tunnel breaks by itself.
                //
                // Disconnected is not included: that is what tapping
                // 끊기 produces, and warning someone about the thing
                // they just asked for teaches them to swipe these away
                // — taking the one that matters with it.
                if (state is TunnelState.Error && wasConnected) {
                    notifyDropped()
                }
                wasConnected = state is TunnelState.Connected

                // While connected, refresh the counters so the
                // notification shows traffic moving rather than only
                // claiming "보호 중". A claim and a number that climbs
                // are different kinds of evidence to someone checking
                // whether their phone is really protected.
                // The framework re-announces every network when a VPN is
                // established, so the monitor needs to know when that was
                // — otherwise it reads our own tunnel coming up as the
                // user roaming to a new access point and rebinds two
                // seconds into the handshake.
                if (state is TunnelState.Connecting || state is TunnelState.Handshaking) {
                    networkMonitor.noteTunnelUp()
                }
                if (state is TunnelState.Connected) {
                    startTrafficUpdates(text)
                } else {
                    stopTrafficUpdates()
                }

                // The service does not decide when to stop.
                //
                // It used to: any Disconnected after a tunnel had been up
                // meant stopSelf(). That reads as tidy and is a trap —
                // the rule depends on a list of states that "count", and
                // 1.13.8 added Error to that list, so a handshake that
                // timed out and then settled killed the service under a
                // live connection. The notification vanished and the
                // tunnel went with it, five seconds after connecting.
                //
                // Stopping is a decision, and every way to make it is
                // already explicit and already handled:
                //   끊기            → bringTunnelDown
                //   app closed      → onTaskRemoved
                //   VPN revoked     → onRevoke
                //   nothing to hold → the restart path in onStartCommand
                //
                // While the service runs the notification stays, which is
                // also what a foreground service is required to do.
            }
        }
        SocketProtector.bind(protectStrategy)
        networkMonitor.start()
        android.util.Log.i(TAG, "VpnService created (protect+roam wired)")
    }

    /** The most recent start command, so a deferred stop can defer to it. */
    @Volatile
    private var latestStartId: Int = -1

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // A null intent means the system recreated us under START_STICKY.
        //
        // There is no action to dispatch on, and falling through to the
        // when below would do nothing while leaving the service running
        // without a foreground notification — which Android kills after
        // a few seconds, with an ANR-shaped crash rather than anything
        // that names the cause.
        if (intent?.action == null) {
            android.util.Log.i(TAG, "restarted by the system; restoring the tunnel")
            startForegroundIfNeeded()
            // Only restore a tunnel the user had running. Coming back
            // after the app was closed — or after a disconnect — and
            // dialling out again is the service deciding something the
            // user already decided.
            val wanted = CoreStorage.get(applicationContext).loadTunnelWanted()
            if (wanted && AidotVpnEngine.get(applicationContext).allocation() != null) {
                bringTunnelUp()
            } else {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf(startId)
            }
            return START_STICKY
        }

        // Always-on VPN entry path: when the user enables AidotVpn under
        // Settings → Network & Internet → VPN → Always-on VPN, the system
        // launches us with `intent == null` after every reboot and
        // whenever it kills+restarts the service. Default to CONNECT in
        // that case so the tunnel comes up automatically.
        val action = intent?.action ?: ACTION_CONNECT
        android.util.Log.i(TAG, "onStartCommand action=$action id=$startId intent=${intent != null}")
        // Remember which start command we are serving.
        //
        // A deferred stopSelf() with no argument kills the service even
        // when a newer start is waiting — so 끊기 followed quickly by
        // 연결 tore down the connection that had just been made, and the
        // third attempt worked only because the stale coroutine had
        // finished by then. stopSelf(startId) is exactly the guard
        // Android provides for this: it is ignored once a newer command
        // has arrived.
        latestStartId = startId

        when (action) {
            ACTION_CONNECT -> {
                startForegroundIfNeeded()
                bringTunnelUp()
            }
            ACTION_DISCONNECT -> {
                bringTunnelDown()
            }
        }
        return START_STICKY
    }

    private fun bringTunnelUp() {
        val tm = AidotVpnEngine.get(applicationContext).tunnelManager
        scope.launch {
            tm.start().onFailure { err ->
                // Log the actual reason — without this, an "no node available"
                // failure looks identical to "user clicked Disconnect" from
                // the UI. With logcat tag `AidotVpn/Tunnel`, an operator can
                // diagnose without rebuilding.
                android.util.Log.w(
                    "AidotVpn/Tunnel",
                    "bringTunnelUp failed: ${err.message}",
                    err,
                )
                // Defer stopSelf by 6 seconds so the Compose UI's
                // WhileSubscribed(5s) collector has time to observe the
                // Error state set by TunnelManager.start() before we
                // tear down. Otherwise the StateFlow snaps back to its
                // initialValue (Disconnected) and the user sees "연결
                // 안 됨" with no hint of what went wrong.
                val id = latestStartId
                kotlinx.coroutines.delay(6_000)
                if (latestStartId != id) {
                    android.util.Log.i(TAG, "a newer start arrived while failing; staying up")
                    return@onFailure
                }
                stopSelf(id)
            }
        }
    }

    private fun bringTunnelDown() {
        val tm = AidotVpnEngine.get(applicationContext).tunnelManager
        // Capture the id now: by the time stop() returns, a 연결 may have
        // arrived and moved it on, and that is precisely when this stop
        // must not take effect.
        val id = latestStartId
        scope.launch {
            tm.stop()
            if (latestStartId != id) {
                android.util.Log.i(TAG, "a newer start arrived while stopping; staying up")
                return@launch
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf(id)
        }
    }

    private fun startForegroundIfNeeded() {
        ensureChannel()
        val notification = buildNotification(getString(R.string.aidotvpn_notif_connecting))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // MUST match android:foregroundServiceType in the manifest.
            //
            // The comment here has said that since 0.12.0, while the two
            // sides pointed at different types the whole time: manifest
            // systemExempted, call SPECIAL_USE. Writing the rule down did
            // not keep them in step — check-gradle now compares them.
            //
            // Both are specialUse as of 1.3.2, because systemExempted is
            // reserved for VPNs registered as always-on in Settings and
            // throws ForegroundServiceTypeNotAllowedException for anything
            // else.
            startForeground(
                NOTIF_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    /**
     * Update the foreground notification — through startForeground, not
     * NotificationManager.notify.
     *
     * They look interchangeable and are not. `notify` posts a standalone
     * notification that happens to share an id; it belongs to the app,
     * not to the service, so it survives the process being killed. With
     * setOngoing(true) the user cannot even swipe it away. That is why
     * AidotVpn stayed in the shade reading 연결 안 됨 after a force
     * stop: the service was long gone and its notification was not,
     * because it had stopped being its notification the first time the
     * state changed.
     *
     * Re-calling startForeground with the same id replaces the content
     * and keeps the binding, so the system removes it with the service.
     */
    private fun updateNotification(text: String) {
        val notification = buildNotification(text, modeSummary())
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIF_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } else {
                startForeground(NOTIF_ID, notification)
            }
        } catch (e: Exception) {
            // The service may already be stopping, in which case there is
            // nothing to update and nothing to report.
            android.util.Log.d(TAG, "notification update skipped: ${e.message}")
        }
    }

    /**
     * Build the persistent notification.
     *
     * Android shows a VPN key icon in the status bar on its own whenever
     * a VpnService holds a tunnel — that part is the OS and we cannot
     * change it. What we control is this notification, and until 0.28.0
     * it said only "VPN 활성", which answers the least interesting
     * question. The user can already see the key icon.
     *
     * What they cannot see is WHICH policy is in force. "보호 중" plus
     * "잠금 — 허용된 곳 외 차단" explains why the browser stopped
     * working; "보호 중" alone makes that look like a fault.
     *
     * The disconnect action is here for the same reason: a lockdown
     * tunnel cuts general internet, and requiring the user to find the
     * app to undo that is a poor trade when the notification is already
     * on screen.
     */
    private fun buildNotification(text: String, mode: String? = null): Notification {
        ensureChannel()

        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, AidotVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        // Tapping the notification opens the host app's launcher activity.
        //
        // Resolved rather than hardcoded: :vpnlib has no idea what the
        // embedding app's entry point is called, and the previous version
        // referenced com.aidotvpn.client.app.ui.MainActivity by name —
        // which does not exist in a business app.
        val open = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(
                this, 0, it,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.aidotvpn_notif_title))
            .setContentText(text)
            .setSubText(mode)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .apply {
                open?.let { setContentIntent(it) }
                addAction(0, getString(R.string.aidotvpn_notif_disconnect), stopIntent)
                // Two lines when a mode is known, so the policy is
                // readable without expanding.
                if (mode != null) {
                    setStyle(NotificationCompat.BigTextStyle().bigText("$text\n$mode"))
                }
            }
            .build()
    }

    /**
     * A one-line summary of the two axes, for the notification subtext.
     *
     * Reads from the stored allocation rather than from the tunnel,
     * because these are the values the server sent and the ones an admin
     * would recognise when the user reads the notification aloud over the
     * phone.
     */
    private fun modeSummary(): String? {
        val alloc: StoredAllocation = runCatching {
            AidotVpnEngine.get(applicationContext).allocation()
        }.getOrNull() ?: return null

        val scope = if (alloc.routeScope == "full") {
            getString(R.string.aidotvpn_notif_scope_full)
        } else {
            getString(R.string.aidotvpn_notif_scope_policy)
        }
        val apps = when (alloc.appFilterMode) {
            "include" -> getString(R.string.aidotvpn_notif_apps_include)
            "exclude" -> getString(R.string.aidotvpn_notif_apps_exclude)
            else -> getString(R.string.aidotvpn_notif_apps_all)
        }
        return "$apps · $scope"
    }

    /**
     * Warn when the tunnel drops without being asked to.
     *
     * Only for an unrequested drop. Tapping 끊기 is not news, and a
     * notification for it trains people to swipe these away — at which
     * point the one that matters goes with them.
     *
     * Its own channel so a user can silence outage alerts without
     * silencing the status line, or the reverse. IMPORTANCE_DEFAULT:
     * this is the case where a sound is right, because the phone keeps
     * working and quietly stops reaching the EMR.
     */
    private fun notifyDropped() {
        ensureAlertChannel()
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val open = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(
                this, 1, it,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        }
        val n = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setContentTitle(getString(R.string.aidotvpn_alert_dropped_title))
            .setContentText(getString(R.string.aidotvpn_alert_dropped_text))
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .apply { open?.let { setContentIntent(it) } }
            .build()
        nm.notify(ALERT_NOTIF_ID, n)
    }

    private var trafficJob: Job? = null

    /**
     * Rewrite the notification every few seconds with byte counts.
     *
     * Five seconds: fast enough that opening the shade after loading a
     * chart shows a number that moved, slow enough that it is not a
     * wakelock. Cancelled the moment the tunnel is not Connected, so a
     * dropped tunnel does not keep showing stale totals as if it were
     * still carrying traffic.
     */
    private fun startTrafficUpdates(baseText: String) {
        stopTrafficUpdates()
        trafficJob = scope.launch {
            while (true) {
                val s = AidotVpnEngine.get(applicationContext).tunnelManager.statistics()
                if (s != null) {
                    // Zero is a real reading and worth showing: it means
                    // the interface is up and nothing has crossed it,
                    // which is exactly the state after a gateway restart
                    // with no fresh handshake.
                    updateNotification("$baseText · ${formatBytes(s.first + s.second)}")
                } else {
                    // Say the counters are missing rather than leaving
                    // the line looking like it did before the tunnel came
                    // up. A number that quietly stops updating reads as
                    // "no traffic", which is a different claim.
                    updateNotification("$baseText · 사용량 확인 불가")
                }
                delay(5_000)
            }
        }
    }

    private fun stopTrafficUpdates() {
        trafficJob?.cancel()
        trafficJob = null
    }

    /** Short enough for a notification line: 1.2 MB, not 1234567 B. */
    private fun formatBytes(n: Long): String = when {
        n >= 1_000_000_000 -> String.format("%.1f GB", n / 1_000_000_000.0)
        n >= 1_000_000 -> String.format("%.1f MB", n / 1_000_000.0)
        n >= 1_000 -> String.format("%.0f KB", n / 1_000.0)
        else -> "$n B"
    }

    private fun ensureAlertChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(ALERT_CHANNEL_ID) != null) return
        nm.createNotificationChannel(
            NotificationChannel(
                ALERT_CHANNEL_ID,
                getString(R.string.aidotvpn_alert_channel),
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = getString(R.string.aidotvpn_alert_channel_desc)
            },
        )
    }

    private fun ensureChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.aidotvpn_notif_channel),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.aidotvpn_notif_channel_desc)
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    /**
     * Called by the system when the user picks a different VPN app, or
     * when an admin app revokes our VPN privileges. Once this fires,
     * our wg0 fd has already been ripped out of the kernel — there's
     * nothing we can route any more.
     *
     * The default `VpnService.onRevoke` calls `stopSelf()`; we add the
     * tunnel teardown so TunnelManager's StateFlow flips to
     * Disconnected and the AIDL callbacks fan out to SDK consumers
     * (otherwise their UIs would still show "Connected" while no
     * traffic flows).
     */
    /**
     * The user swiped the app away.
     *
     * Android keeps a START_STICKY service alive and restarts it, which
     * is right for a tunnel the user meant to leave running — but the
     * notification then sits in the shade reading 연결 끊어짐, because
     * the recreated service has no tunnel and its state starts at
     * Disconnected. That is what you saw.
     *
     * Closing the app is a statement: stop. A tunnel that should survive
     * it is what Android's own Always-on VPN is for, and that path does
     * not come through here.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        android.util.Log.i(TAG, "app closed; tearing the tunnel down")
        scope.launch {
            runCatching { AidotVpnEngine.get(applicationContext).tunnelManager.stop() }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onRevoke() {
        android.util.Log.w(TAG, "VPN revoked by system or another VPN app")
        val tm = AidotVpnEngine.get(applicationContext).tunnelManager
        scope.launch {
            runCatching { tm.stop() }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        // Belt and braces. startForeground binds the notification to the
        // service so the system removes it, but a notification left over
        // from an earlier build — or from the notify() path this used to
        // take — would otherwise stay in the shade forever, since it is
        // ongoing and cannot be swiped away.
        runCatching {
            getSystemService(NotificationManager::class.java)?.cancel(NOTIF_ID)
        }
        super.onDestroy()
        networkMonitor.stop()
        SocketProtector.unbind(protectStrategy)
        // The message is internal, so keep it internal.
        //
        // TunnelManager now rethrows CancellationException rather than
        // writing it into TunnelState, but a message that reads like a
        // user-facing error is a trap for the next person to add a
        // catch. Naming it after the mechanism removes the temptation.
        scope.cancel(java.util.concurrent.CancellationException("vpnlib: service scope cancelled"))
        android.util.Log.i(TAG, "VpnService destroyed")
    }

    companion object {
        const val ACTION_CONNECT = "com.aidotvpn.client.action.CONNECT"
        const val ACTION_DISCONNECT = "com.aidotvpn.client.action.DISCONNECT"

        private const val TAG = "AidotVpn/Service"
        private const val CHANNEL_ID = "aidotvpn_status"
        private const val NOTIF_ID = 1101

        // Separate channel and id: the outage alert must be dismissable
        // and silenceable on its own, and it must not replace the
        // ongoing status line.
        private const val ALERT_CHANNEL_ID = "aidotvpn_alert"
        private const val ALERT_NOTIF_ID = 1102

        @Suppress("unused") // referenced from XML in future phases
        private val keepRef: Job = Job()
    }
}
