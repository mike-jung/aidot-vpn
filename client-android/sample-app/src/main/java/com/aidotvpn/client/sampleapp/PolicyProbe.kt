package com.aidotvpn.client.sampleapp

import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException
import kotlin.coroutines.resume

/** Uses ordinary app sockets: never protect/bind these probes outside the VPN. */
internal object PolicyProbe {
    internal fun address(raw: String): HttpUrl {
        val text = raw.trim()
        val url = (if ("://" in text) text else "http://$text").toHttpUrlOrNull()
        require(url != null && text.isNotEmpty() && url.username.isEmpty() && url.password.isEmpty()) {
            "http:// 또는 https:// 서버 주소를 입력하세요. 계정 정보는 주소에 넣지 마세요."
        }
        return url
    }

    suspend fun run(raw: String): String {
        val url = try { address(raw) } catch (e: IllegalArgumentException) { return e.message.orEmpty() }
        // A fresh pool and no redirects prevent a prior connection/other host
        // from being mistaken for a fresh policy decision at this destination.
        val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
            .retryOnConnectionFailure(false).connectionPool(ConnectionPool(0, 1, TimeUnit.SECONDS))
            .callTimeout(6, TimeUnit.SECONDS).connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(4, TimeUnit.SECONDS).build()
        val started = System.nanoTime()
        return try {
            suspendCancellableCoroutine { continuation ->
                val call = client.newCall(Request.Builder().url(url).header("Cache-Control", "no-cache").get().build())
                continuation.invokeOnCancellation { call.cancel() }
                call.enqueue(object : Callback {
                    override fun onResponse(call: Call, response: Response) {
                        response.use {
                            val elapsed = (System.nanoTime() - started) / 1_000_000
                            continuation.resume("응답 받음 · HTTP ${it.code} · ${elapsed}ms")
                        }
                    }
                    override fun onFailure(call: Call, e: IOException) {
                        val detail = when (e) {
                            is UnknownHostException -> "DNS 실패 · 서버 이름을 확인하세요."
                            is SocketTimeoutException -> "시간 초과 · 정책 차단 또는 서버·망 장애일 수 있습니다."
                            is SSLException -> "TLS 오류 · 인증서와 HTTPS 설정을 확인하세요."
                            is ConnectException -> "연결 실패 · 서버 포트 또는 방화벽을 확인하세요."
                            else -> if (e.message?.contains("CLEARTEXT", true) == true)
                                "HTTP 제한 · 이 빌드에서는 HTTPS 주소를 사용하세요."
                            else "응답 실패 · 주소, 정책 또는 네트워크를 확인하세요."
                        }
                        continuation.resume(detail)
                    }
                })
            }
        } finally {
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
        }
    }
}

internal data class ProbeRowState(val target: String = "", val result: String? = null)
