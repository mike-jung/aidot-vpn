package com.aidotvpn.client.core

import java.io.IOException
import java.net.*
import org.junit.Assert.*
import org.junit.Test

class ProtectingSocketFactoryTest {
    private fun strategy(check: (Socket) -> Boolean) = object : SocketProtector.Strategy {
        override fun protectSocket(socket: Socket) = check(socket)
        override fun protectDatagramSocket(socket: DatagramSocket) = false
        override fun protectFd(fd: Int) = false
    }

    @Test fun allOverloadsBindBeforeProtectionAndConnection() {
        var calls = 0
        val guard = strategy { socket ->
            assertTrue("native socket must exist before protect", socket.isBound)
            assertFalse("must protect before connect", socket.isConnected)
            calls++
            true
        }
        SocketProtector.bind(guard)
        try {
            val factory = ProtectingSocketFactory()
            factory.createSocket().use { assertFalse(it.isConnected) }
            val loopback = InetAddress.getByName("127.0.0.1")
            ServerSocket(0, 10, loopback).use { server ->
                factory.createSocket("127.0.0.1", server.localPort).use { server.accept().close() }
                factory.createSocket(loopback, server.localPort).use { server.accept().close() }
                factory.createSocket("127.0.0.1", server.localPort, loopback, 0).use {
                    assertEquals(loopback, it.localAddress); server.accept().close()
                }
                factory.createSocket(loopback, server.localPort, loopback, 0).use {
                    assertEquals(loopback, it.localAddress); server.accept().close()
                }
            }
            assertEquals(5, calls)
        } finally { SocketProtector.unbind(guard) }
    }

    @Test fun rejectedProtectionClosesSocketAndDoesNotConnect() {
        var attempted: Socket? = null
        val guard = strategy { attempted = it; false }
        SocketProtector.bind(guard)
        try {
            try { ProtectingSocketFactory().createSocket("127.0.0.1", 9); fail("protection failure must propagate") }
            catch (e: IOException) { assertEquals("VPN control socket protection failed", e.message) }
            assertTrue(attempted!!.isClosed)
            assertFalse(attempted!!.isConnected)
        } finally { SocketProtector.unbind(guard) }
    }

    @Test fun registrationWithoutVpnServiceStillConnects() {
        assertFalse(SocketProtector.isActive)
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            ProtectingSocketFactory().createSocket("127.0.0.1", server.localPort).use {
                assertTrue(it.isConnected); server.accept().close()
            }
        }
    }
}
