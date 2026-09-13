package com.aidotvpn.client.sampleapp

import com.aidotvpn.client.vpnlib.TunnelState
import org.junit.Assert.*
import org.junit.Test

class SampleStageTest {
    @Test fun onboardingApprovalAndPolicyHaveSeparateHints() {
        assertEquals(0, sampleStage(SampleUiState()).index)
        assertTrue(sampleStage(SampleUiState(code = "123456")).title.contains("승인"))
        assertTrue(sampleStage(SampleUiState(registered = true)).title.contains("정책"))
        assertEquals(2, sampleStage(SampleUiState(registered = true, policyBound = true)).index)
    }
    @Test fun actualTunnelOverridesOldRequestMessage() {
        val connected = SampleUiState(registered = true, policyBound = true,
            tunnel = TunnelState.Connected, message = "연결을 요청했습니다.")
        assertEquals(3, sampleStage(connected).index)
        assertTrue(sampleStage(connected).title.contains("연결됐습니다"))
        assertEquals(0, sampleStage(connected.copy(serverStatus = "revoked")).index)
    }
}
