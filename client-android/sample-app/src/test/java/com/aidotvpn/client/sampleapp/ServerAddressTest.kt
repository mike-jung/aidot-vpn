package com.aidotvpn.client.sampleapp

import org.junit.Assert.*
import org.junit.Test

class ServerAddressTest {
    @Test fun acceptsLabIpv4AndCanonicalizesTrailingSlash() {
        assertEquals("http://192.168.0.11:10030", serverAddress("  http://192.168.0.11:10030/  "))
    }
    @Test fun acceptsHttpsDnsAndIpv6() {
        assertEquals("https://vpn.example.com", serverAddress("https://VPN.EXAMPLE.COM/", true))
        assertEquals("http://[::1]:10030", serverAddress("http://[::1]:10030"))
    }
    @Test fun rejectsMissingAndUnsupportedSchemes() {
        for (value in listOf("", "192.168.0.11:10030", "ftp://vpn.example.com", "http://")) {
            assertTrue(value, runCatching { serverAddress(value) }.isFailure)
        }
    }
    @Test fun rejectsEmbeddedCredentialsAndQueryOrFragment() {
        for (value in listOf("https://user:pass@vpn.example.com", "https://vpn.example.com?token=a", "https://vpn.example.com/#test")) {
            assertTrue(value, runCatching { serverAddress(value) }.isFailure)
        }
    }
    @Test fun releaseRequiresHttps() {
        assertTrue(runCatching { serverAddress("http://192.168.0.11:10030", true) }.isFailure)
        assertEquals("https://192.168.0.11:10030", serverAddress("https://192.168.0.11:10030", true))
    }
}
