package com.aidotvpn.client.sampleapp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.net.ServerSocket
import kotlin.concurrent.thread

class PolicyProbeTest {
    @Test fun addressesRejectCredentialsAndUnsupportedSchemes() {
        assertEquals("http://10.0.0.1:8080/", PolicyProbe.address("10.0.0.1:8080").toString())
        listOf("", "ftp://example.com", "https://user:secret@example.com").forEach {
            assertThrows(IllegalArgumentException::class.java) { PolicyProbe.address(it) }
        }
    }
    @Test fun responseCodesProveReachabilityWithoutFollowingRedirects() = runBlocking {
        for (status in listOf(404, 302)) ServerSocket(0).use { server ->
            server.soTimeout = 5000
            val responder = thread {
                server.accept().use { socket ->
                    socket.getInputStream().bufferedReader().let { input -> while (!input.readLine().isNullOrEmpty()) {} }
                    socket.getOutputStream().write("HTTP/1.1 $status Test\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
                }
            }
            assertTrue(PolicyProbe.run("http://127.0.0.1:${server.localPort}").contains("HTTP $status"))
            responder.join(6000)
            assertFalse(responder.isAlive)
        }
    }
}
