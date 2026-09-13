package com.aidotvpn.demo

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The probe outcomes, which are the app's whole vocabulary for
 * explaining a policy.
 *
 * The distinction that matters and is easy to get wrong: a blocked
 * destination TIMES OUT, it is not REFUSED. nftables `drop` is silent, so
 * nothing answers at all. A refusal means something *did* answer — the
 * packet arrived and the port was closed — which tells you the tunnel is
 * carrying traffic. Collapsing the two into "failed" would throw away the
 * most useful diagnostic the app has.
 */
class ReachabilityTest {

    @Test
    fun `bare host and port only require TCP, not an HTTP server`() = runBlocking {
        java.net.ServerSocket(0).use { server ->
            val result = Reachability.probe("127.0.0.1:${server.localPort}", 500, logger = {})
            assertEquals(Reachability.Outcome.REACHED, result.outcome)
            assertNull(result.httpStatus)
        }
    }

    @Test
    fun `closed port on loopback is refused, not timed out`() = runBlocking {
        val r = Reachability.probe("http://127.0.0.1:1", 1500, logger = {})
        assertEquals(
            "loopback rejects immediately; that is a refusal, not a drop",
            Reachability.Outcome.REFUSED, r.outcome,
        )
    }

    @Test
    fun `unresolvable name reports DNS rather than a generic error`() = runBlocking {
        val r = Reachability.probe("http://this-name-does-not-exist.invalid", 1500, logger = {})
        assertEquals(Reachability.Outcome.DNS_FAILED, r.outcome)
    }

    @Test
    fun `descriptions name the ambiguity instead of hiding it`() {
        val timeout = Reachability.Result(Reachability.Outcome.TIMEOUT, 4000)
        // A timeout cannot distinguish "blocked" from "server is off", so
        // the text must say both rather than assert one.
        assertTrue(timeout.describe().contains("막혔거나"))

        val refused = Reachability.Result(Reachability.Outcome.REFUSED, 12)
        assertTrue(refused.describe().contains("통로는 열렸고"))
    }

    @Test
    fun `reached carries the http status when there was one`() {
        val r = Reachability.Result(Reachability.Outcome.REACHED, 30, httpStatus = 200)
        assertTrue(r.ok)
        assertTrue(r.describe().contains("200"))
    }

    @Test
    fun `default probes encode the expected outcome for each`() {
        val probes = Reachability.defaults("http://10.10.5.20", "http://10.10.5.99")
        assertEquals(3, probes.size)
        assertEquals(Reachability.Outcome.REACHED, probes[0].expectation)
        assertEquals(Reachability.Outcome.TIMEOUT, probes[1].expectation)
        // The internet probe has no fixed expectation: split tunnel
        // reaches it, lockdown does not, and that is the lesson rather
        // than a bug. Asserting either would make the app tell the reader
        // the wrong thing under one of the two policies.
        assertNull(probes[2].expectation)
    }
}
