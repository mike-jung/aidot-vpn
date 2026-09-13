package com.aidotvpn.client.sampleapp

import com.aidotvpn.client.vpnlib.TunnelState

internal data class SampleStage(val index: Int, val title: String, val hint: String)

internal fun sampleStage(state: SampleUiState): SampleStage = when {
    state.serverStatus == "revoked" -> SampleStage(0, "등록 확인이 필요합니다", "관리자에게 기기 등록 상태를 확인해 주세요.")
    !state.registered && state.code != null -> SampleStage(1, "관리자 승인을 기다립니다", "아래 확인 번호를 관리자에게 알려주세요. 화면을 다시 열어도 승인 대기는 유지됩니다.")
    !state.registered -> SampleStage(0, "먼저 기기를 등록하세요", "서버 주소, 기기 이름과 등록 비밀번호를 입력해 등록을 요청하세요.")
    !state.policyBound -> SampleStage(1, "업무 정책을 기다립니다", "등록은 완료됐습니다. 관리자가 정책을 할당하면 상태 새로고침을 눌러주세요.")
    state.tunnel is TunnelState.Connected -> SampleStage(3, "VPN에 연결됐습니다", "아래 세 주소 접속 확인으로 업무 서버에 닿는지 시험해 보세요.")
    state.tunnel is TunnelState.Connecting || state.tunnel is TunnelState.Handshaking -> SampleStage(2, "VPN에 연결하는 중입니다", "서버와 안전한 통신 경로를 만드는 중입니다. 잠시 기다려 주세요.")
    state.tunnel is TunnelState.Error -> SampleStage(2, "연결을 확인해 주세요", state.tunnel.message)
    else -> SampleStage(2, "이제 VPN에 연결하세요", "등록과 정책이 준비됐습니다. 연결 버튼을 누르고 Android의 VPN 사용을 허용하세요.")
}
