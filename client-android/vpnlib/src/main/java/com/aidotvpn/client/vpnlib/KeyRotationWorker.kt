package com.aidotvpn.client.vpnlib

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.time.Duration

/**
 * KeyRotationWorker rotates the device's mTLS keypair + WireGuard
 * keypair on a 12-hour cadence (best-effort; the OS may delay or batch
 * with other periodic work).
 *
 * Why automatically rotate:
 *
 *   - Tightens blast radius if a private key is somehow exfiltrated.
 *     With a 12h rotation cadence, even a successful key compromise
 *     gives the attacker at most 12h of authenticated access before
 *     the cert + WG peer are no longer accepted by the controller.
 *
 *   - The mTLS cert lifetime is capped at 24h server-side. Rotating
 *     every 12h keeps us comfortably ahead of expiry.
 *
 * Why best-effort:
 *
 *   - WorkManager schedules to network-available + battery-not-critical
 *     windows. If the device has been offline for >24h the cert will
 *     have expired; the user opens the app and the standalone client
 *     re-runs Register from scratch. We tolerate the gap.
 *
 *   - Failures here don't crash anything. The user-visible symptom of
 *     skipped rotations is "tunnel won't connect" once the cert
 *     expires; the standalone client surfaces that as an error and
 *     prompts the user to sign in again.
 */
class KeyRotationWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        // Runs against the engine, not against a specific Application
        // subclass.
        //
        // This used to be `applicationContext as? AidotVpnApplication`,
        // which is a class in :app. In the standalone client that cast
        // succeeds; in an embedding business app it is always null and
        // the worker returned success without rotating anything — so key
        // rotation silently did not happen, on the deployment mode the
        // library exists to support.
        val engine = AidotVpnEngine.get(applicationContext)

        // Nothing registered yet, so nothing to rotate.
        engine.allocation() ?: return Result.success()

        // The token provider is supplied by the host app at registration
        // time and cannot be recovered here, so rotation is delegated to
        // the engine, which holds it.
        return try {
            val rotated = engine.rotateKeyIfPossible()
            if (!rotated) {
                // Not an error, but not nothing either. WorkManager wakes
                // a dead process, so unless the host called
                // setTokenProvider from Application.onCreate there is no
                // way to mint a token here — and rotation then never
                // happens, every 12 hours, with success reported each
                // time. Say so, or the silence is indistinguishable from
                // working.
                android.util.Log.w(
                    "AidotVpn/Rotate",
                    "key rotation skipped: no token provider in this process. " +
                        "Call AidotVpnEngine.setTokenProvider() from Application.onCreate " +
                        "if rotation should survive process death.",
                )
            }
            Result.success()
        } catch (e: Throwable) {
            // WorkManager retries with exponential backoff. After enough
            // failures it gives up and Result.failure() pulls the worker
            // out of the queue; we use Result.retry() so the schedule
            // keeps trying through transient outages.
            Result.retry()
        }
    }

    companion object {
        private const val UNIQUE_NAME = "aidotvpn.key-rotation"
        private val INTERVAL = Duration.ofHours(12)

        /**
         * Schedule (or reschedule) the rotation worker. Idempotent —
         * calling repeatedly with the same schedule is a no-op.
         */
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()
            val req = PeriodicWorkRequestBuilder<KeyRotationWorker>(INTERVAL)
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(UNIQUE_NAME, ExistingPeriodicWorkPolicy.KEEP, req)
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(UNIQUE_NAME)
        }
    }
}
