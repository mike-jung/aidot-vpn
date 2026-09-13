package com.aidotvpn.demo

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import kotlin.system.measureTimeMillis

/**
 * Reachability probes — the part of this app that makes the VPN visible.
 *
 * A tunnel that works and a tunnel that does nothing look identical from
 * the outside: the phone still has network, apps still open. The only way
 * to *see* an access policy is to try reaching things and observe which
 * ones answer.
 *
 * So the demo app is built around three probes:
 *
 *   permitted    a server the policy allows      → should succeed
 *   blocked      a server on the same LAN        → should fail
 *   internet     something outside entirely      → depends on route scope
 *
 * The third one is what teaches route scope. Under a split tunnel it
 * succeeds; under lockdown it fails, and that failure is the feature
 * rather than a fault.
 *
 * ## Why the failure mode matters more than the success
 *
 * A blocked destination does not answer "no" — nothing answers at all,
 * because the gateway drops the packet silently. So the observable
 * difference between "blocked" and "the server is down" is only the
 * shape of the failure: a timeout rather than a refusal.
 *
 * That distinction is the single most confusing thing about testing a
 * VPN policy, so [Probe] reports it explicitly instead of collapsing
 * everything into "failed".
 */
object Reachability {

    private const val TAG = "AidotDemo/Reach"

    /** How a probe ended. The distinction is the point — see the class doc. */
    enum class Outcome {
        /** Something answered. The destination is reachable. */
        REACHED,

        /** Nothing answered before the deadline.
         *
         *  This is what a dropped packet looks like from the client, and
         *  therefore what a working block looks like. It is also what a
         *  powered-off server looks like, which is why the app shows the
         *  target address next to the result. */
        TIMEOUT,

        /** Actively refused — something is there and said no.
         *
         *  Notably NOT what the gateway does: nftables `drop` is silent.
         *  A refusal usually means you reached a host that has nothing
         *  listening on that port, so the tunnel is carrying traffic. */
        REFUSED,

        /** DNS could not resolve the name.
         *
         *  Separated out because it is the symptom of the DNS footgun:
         *  a pushed internal resolver that cannot answer public names
         *  breaks lookups while connectivity is fine. */
        DNS_FAILED,

        /** Something else. The message carries the detail. */
        ERROR,
    }

    data class Result(
        val outcome: Outcome,
        val millis: Long,
        val detail: String = "",
        /** HTTP status when one was received. */
        val httpStatus: Int? = null,
    ) {
        val ok: Boolean get() = outcome == Outcome.REACHED

        /** One short line for the UI, in plain Korean. */
        fun describe(): String = when (outcome) {
            // Any HTTP response means the packet made it there and back.
            //
            // "연결됨 (HTTP 404)" read as a failure — the number looks
            // like an error even though it is the proof. A 404 is the
            // server saying it does not have that path, which it can
            // only say after receiving the request.
            //
            // What this test asks is whether the address is reachable,
            // not whether a path exists at it.
            Outcome.REACHED -> buildString {
                append("연결됨 · ${millis}ms")
                httpStatus?.let { code ->
                    if (code in 200..299) {
                        append("  (HTTP $code · 서버가 정상 응답)")
                    } else {
                        append("  (서버가 HTTP $code 로 응답 — 닿았다는 뜻입니다)")
                    }
                }
            }
            Outcome.TIMEOUT -> "응답 없음 · ${millis}ms — 막혔거나 서버가 꺼져 있습니다"
            Outcome.REFUSED -> "거부됨 · ${millis}ms — 통로는 열렸고 그 포트에 서버가 없습니다"
            Outcome.DNS_FAILED -> "이름을 못 찾음 — DNS 설정을 확인하세요"
            Outcome.ERROR -> "오류: $detail"
        }
    }

    /**
     * A single thing to try reaching.
     *
     * [expectation] is what the *current* policy should produce. The UI
     * compares it against the actual result so the reader sees 예상대로
     * or 예상과 다름 rather than having to remember what should happen.
     */
    data class Probe(
        val id: String,
        val label: String,
        val target: String,
        val hint: String,
        val expectation: Outcome? = null,
    )

    /**
     * Try a TCP connect, then an HTTP GET if it is an http(s) URL.
     *
     * TCP first on purpose: it separates "the packet got through" from
     * "the server answered my request". A policy question is about the
     * former, and an HTTP-only probe would report a 500 as a failure when
     * the tunnel is working perfectly.
     */
    suspend fun probe(
        target: String,
        timeoutMs: Int = 4000,
        logger: (String) -> Unit = { Log.i(TAG, it) },
    ): Result = withContext(Dispatchers.IO) {
        val isHttp = target.startsWith("http://") || target.startsWith("https://")
        val url = runCatching { if (isHttp) URL(target) else URL("http://$target") }.getOrNull()
            ?: return@withContext Result(Outcome.ERROR, 0, "주소 형식이 올바르지 않습니다")

        val host = url.host
        val port = if (url.port != -1) url.port else if (url.protocol == "https") 443 else 80

        var status: Int? = null
        var outcome = Outcome.ERROR
        var detail = ""

        val elapsed = measureTimeMillis {
            val r = withTimeoutOrNull(timeoutMs.toLong() + 1000) {
                runCatching {
                    Socket().use { s ->
                        s.connect(InetSocketAddress(host, port), timeoutMs)
                    }
                    // The packet got through. Now see if it speaks HTTP.
                    if (isHttp) {
                        val conn = (url.openConnection() as HttpURLConnection).apply {
                            connectTimeout = timeoutMs
                            readTimeout = timeoutMs
                            requestMethod = "GET"
                            instanceFollowRedirects = false
                        }
                        try {
                            status = conn.responseCode
                        } finally {
                            conn.disconnect()
                        }
                    }
                    Outcome.REACHED
                }.getOrElse { e ->
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    when {
                        e is java.net.UnknownHostException -> Outcome.DNS_FAILED
                        e is java.net.SocketTimeoutException -> Outcome.TIMEOUT
                        e is java.net.ConnectException &&
                            (e.message?.contains("refused", true) == true) -> Outcome.REFUSED
                        else -> {
                            detail = e.message ?: e::class.java.simpleName
                            // A connect that fails without a refusal is,
                            // in practice, a drop — which is what the
                            // gateway does. Report it as such rather than
                            // as a generic error the reader cannot act on.
                            if (e is java.net.ConnectException) Outcome.TIMEOUT else Outcome.ERROR
                        }
                    }
                }
            }
            outcome = r ?: Outcome.TIMEOUT
        }

        logger("probe $target → $outcome in ${elapsed}ms" + (status?.let { " http=$it" } ?: ""))
        Result(outcome, elapsed, detail, status)
    }

    /**
     * The default probe set, sized to the tutorial.
     *
     * Addresses are editable in the app because every deployment's
     * internal range differs — hard-coding them would make the first
     * screen wrong for everyone.
     */
    fun defaults(permitted: String, blocked: String): List<Probe> = listOf(
        Probe(
            id = "permitted",
            label = "허용된 병원 서버",
            target = permitted,
            hint = "정책에서 허락한 곳입니다. 연결되어야 정상입니다.",
            expectation = Outcome.REACHED,
        ),
        Probe(
            id = "blocked",
            label = "허용 안 된 병원 서버",
            target = blocked,
            hint = "같은 병원망이지만 정책에 없습니다. 막혀야 정상입니다.",
            expectation = Outcome.TIMEOUT,
        ),
        Probe(
            id = "internet",
            label = "바깥 인터넷",
            target = "https://www.google.com",
            hint = "스플릿이면 연결되고, 잠금이면 막힙니다. 경로 범위를 확인하는 곳입니다.",
            expectation = null, // depends on route scope; the UI says so
        ),
    )
}
