package com.aidotvpn.demo

import com.aidotvpn.client.core.DeviceStateClient
import com.aidotvpn.client.core.StateAuthenticationException
import java.net.ServerSocket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.Assert.*
import org.junit.Test

class DeviceStateClientTest {
    private fun request(code: Int): Pair<Result<DeviceStateClient.State>, List<String>> = runBlocking {
        ServerSocket(0).use { server ->
            server.soTimeout = 5000
            val executor = Executors.newSingleThreadExecutor()
            try {
                val headers = executor.submit<List<String>> {
                    server.accept().use { socket ->
                        socket.soTimeout = 5000
                        val reader = socket.getInputStream().bufferedReader()
                        val lines = mutableListOf<String>()
                        while (true) {
                            val line = reader.readLine() ?: break
                            if (line.isEmpty()) break
                            lines.add(line)
                        }
                        val body = """{"status":"active","policy_bound":true,"allowed_ips":["10.78.0.1/32"]}"""
                        val response = "HTTP/1.1 $code Test\r\nContent-Type: application/json\r\nContent-Length: ${body.toByteArray().size}\r\nConnection: close\r\n\r\n$body"
                        socket.getOutputStream().write(response.toByteArray())
                        lines
                    }
                }
                val result = DeviceStateClient("http://127.0.0.1:${server.localPort}", http = OkHttpClient(), stateToken = "test-token").fetchResult("test")
                result to headers.get(5, TimeUnit.SECONDS)
            } finally { executor.shutdownNow() }
        }
    }
    @Test fun sendsCredentialAndDecodesState() {
        val (result, headers) = request(200)
        assertTrue(headers.contains("Authorization: Bearer test-token"))
        val state = result.getOrThrow()
        assertTrue(state.policyBound)
        assertEquals(listOf("10.78.0.1/32"), state.allowedIps)
    }
    @Test fun authenticationFailureDiffersFromUnavailableController() {
        assertTrue(request(401).first.exceptionOrNull() is StateAuthenticationException)
        val failure = request(503).first.exceptionOrNull()
        assertNotNull(failure)
        assertFalse(failure is StateAuthenticationException)
    }
    @Test fun missingTokenFailsBeforeNetwork() = runBlocking {
        val result = DeviceStateClient("http://127.0.0.1:1", http = OkHttpClient(), stateToken = "").fetchResult("test")
        assertTrue(result.exceptionOrNull() is StateAuthenticationException)
    }
}
