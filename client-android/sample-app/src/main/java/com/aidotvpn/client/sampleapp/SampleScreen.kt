package com.aidotvpn.client.sampleapp

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.*
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aidotvpn.client.vpnlib.TunnelState

@Composable
internal fun Screen(
    state: SampleUiState, consentPending: Boolean,
    onEnroll: (String, String, String) -> Unit, onSaveServer: (String) -> Boolean,
    onConnect: () -> Unit, onDisconnect: () -> Unit, onRefresh: () -> Unit,
    onProbeChange: (Int, String) -> Unit, onRunProbes: () -> Unit,
) {
    var name by rememberSaveable { mutableStateOf(Build.MODEL) }
    var password by remember { mutableStateOf("") }
    var visible by remember { mutableStateOf(false) }
    var server by rememberSaveable(state.controllerUrl) { mutableStateOf(state.controllerUrl) }
    var settings by rememberSaveable { mutableStateOf(false) }
    val busy = state.busy || consentPending
    val disconnected = state.tunnel is TunnelState.Disconnected || state.tunnel is TunnelState.Error
    val stage = sampleStage(state)
    val navy = Color(0xFF10283F)
    Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).imePadding()
        .background(Color(0xFFF4F7FB)).testTag("sample-screen")) {
        Surface(color = navy, contentColor = Color.White) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Icon(painterResource(R.drawable.ic_sample_mark), null, Modifier.size(30.dp), tint = Color(0xFF32D3CF))
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text("AidotVpn", fontSize = 23.sp, fontWeight = FontWeight.Bold)
                        Text("단독 VPN · ${BuildConfig.VERSION_NAME}", fontSize = 12.sp, color = Color(0xFFBDD0E0))
                    }
                    IconButton(onClick = { settings = !settings }, modifier = Modifier.testTag("open-settings")) {
                        Icon(painterResource(if (settings) R.drawable.ic_close else R.drawable.ic_settings),
                            if (settings) "설정 닫기" else "설정 열기", tint = Color.White)
                    }
                }
                Row(Modifier.fillMaxWidth().padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("기기 등록", "승인·정책", "VPN 연결", "접속 확인").forEachIndexed { i, label ->
                        Column(Modifier.weight(1f), horizontalAlignment = Alignment.CenterHorizontally) {
                            Surface(shape = CircleShape, color = if (i <= stage.index) Color(0xFF32D3CF) else Color(0xFF30465A)) {
                                Box(Modifier.size(26.dp), contentAlignment = Alignment.Center) {
                                    Text(if (i < stage.index) "✓" else "${i + 1}", color = if (i <= stage.index) navy else Color.White, fontSize = 13.sp)
                                }
                            }
                            Text(label, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp))
                        }
                    }
                }
                Text(if (consentPending) "Android의 VPN 사용 승인을 확인하세요" else stage.title,
                    fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 12.dp).testTag("stage-title"))
                Text(if (consentPending) "동의 창에서 허용하면 연결을 시작합니다." else stage.hint,
                    fontSize = 12.sp, lineHeight = 17.sp, color = Color(0xFFBDD0E0), modifier = Modifier.testTag("stage-hint"))
            }
        }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            if (settings) {
                Text("설정", fontSize = 22.sp, fontWeight = FontWeight.Bold)
                Text("서버 주소를 바꿔도 이 앱의 등록 정보는 유지됩니다. VPN을 끊은 상태에서 저장하세요.")
                ServerField(server, { server = it }, !busy && disconnected && !state.probing)
                Text("예: http://192.168.0.11:10030\n운영: https://vpn.example.com:10030", style = MaterialTheme.typography.bodySmall)
                Button(onClick = { if (onSaveServer(server)) settings = false }, enabled = !busy && disconnected && !state.probing,
                    modifier = Modifier.fillMaxWidth().testTag("save-server")) { Text("주소 저장") }
                TextButton(onClick = { server = state.controllerUrl; settings = false }) { Text("돌아가기") }
            } else {
                SampleCard {
                    Text(if (!state.registered) "기기 등록이 필요합니다" else connectionText(state.tunnel),
                        style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold,
                        modifier = Modifier.testTag("connection-state"))
                    if (state.registered) {
                        Text(state.controllerUrl, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("saved-server"))
                        TextButton(onClick = { settings = true }, modifier = Modifier.testTag("edit-server")) { Text("서버 주소 변경 · 설정") }
                    } else {
                        ServerField(server, { server = it }, !busy)
                        OutlinedTextField(name, { name = it }, label = { Text("기기 이름") }, enabled = !busy,
                            singleLine = true, modifier = Modifier.fillMaxWidth().testTag("enroll-name"))
                        OutlinedTextField(password, { password = it }, label = { Text("등록 비밀번호") }, enabled = !busy,
                            singleLine = true, visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            trailingIcon = {
                                IconButton(onClick = { visible = !visible }, modifier = Modifier.testTag("toggle-password")) {
                                    Icon(painterResource(if (visible) R.drawable.ic_visibility_off else R.drawable.ic_visibility),
                                        if (visible) "비밀번호 숨기기" else "비밀번호 보기")
                                }
                            }, modifier = Modifier.fillMaxWidth().testTag("enroll-password"))
                        Button(onClick = { visible = false; onEnroll(name, password, server) },
                            enabled = !busy && name.isNotBlank() && password.isNotBlank() && server.isNotBlank(),
                            modifier = Modifier.fillMaxWidth().testTag("enroll-submit")) { Text(if (busy) "등록 진행 중…" else "등록 요청") }
                        state.code?.let { Text("확인 번호  $it", fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.testTag("approval-code")) }
                    }
                    if (state.controllerUrl.startsWith("http://") || (!state.registered && server.startsWith("http://")))
                        Text("HTTP는 시험용입니다. 운영 서버에서는 HTTPS를 사용하세요.", style = MaterialTheme.typography.bodySmall)
                }
                if (state.registered) {
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(onClick = onConnect, enabled = !busy && !state.probing && disconnected && state.policyBound && state.serverStatus != "revoked",
                            modifier = Modifier.weight(1f).testTag("connect")) { Text("연결") }
                        OutlinedButton(onClick = onDisconnect, enabled = !consentPending && state.tunnel !is TunnelState.Disconnected,
                            modifier = Modifier.weight(1f).testTag("disconnect")) { Text("끊기") }
                    }
                    OutlinedButton(onClick = onRefresh, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("refresh-state")) { Text("상태 새로고침") }
                }
            }
            state.message?.let { message ->
                Card(colors = CardDefaults.cardColors(containerColor = Color(0xFFE7F1F7))) {
                    Text(message, Modifier.fillMaxWidth().padding(14.dp).testTag("result-message"))
                }
            }
            if (!settings && state.registered) SampleCard {
                Text("정책 접속 테스트", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text("세 서버 주소를 직접 입력하세요. 각 주소에 새 연결로 HTTP 응답을 요청합니다.", style = MaterialTheme.typography.bodyMedium)
                val labels = listOf("허용할 업무 서버", "차단할 업무 서버", "외부 서버")
                val hints = listOf("http://10.20.0.10:8080", "http://10.20.0.20:8080", "https://www.example.com")
                state.probes.forEachIndexed { i, row ->
                    OutlinedTextField(row.target, { onProbeChange(i, it) }, label = { Text(labels[i]) },
                        placeholder = { Text(hints[i]) }, singleLine = true, enabled = !state.probing,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        modifier = Modifier.fillMaxWidth().testTag("probe-target-$i"))
                    row.result?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("probe-result-$i")) }
                }
                Button(onClick = onRunProbes, enabled = !busy && !state.probing && state.probes.all { it.target.isNotBlank() },
                    modifier = Modifier.fillMaxWidth().testTag("run-probes")) { Text(if (state.probing) "세 곳 확인 중…" else "세 주소 접속 확인") }
                state.probeRoute?.let { Text(it, fontWeight = FontWeight.SemiBold, modifier = Modifier.testTag("probe-route")) }
                Text("HTTP 오류 코드도 서버가 응답한 결과입니다. 응답이 없다는 사실만으로 정책 차단을 확정할 수는 없습니다. 외부 서버 결과는 전체·분할 경로와 앱별 정책에 따라 다릅니다.", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable private fun ServerField(value: String, change: (String) -> Unit, enabled: Boolean) {
    OutlinedTextField(value, change, label = { Text("서버 주소") },
        placeholder = { Text("예: http://192.168.0.11:10030") },
        supportingText = { Text("예: http://192.168.0.11:10030\n앱 제어 API 주소입니다. 콘솔의 6193 포트와 구분하세요.") },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), enabled = enabled, singleLine = true,
        modifier = Modifier.fillMaxWidth().testTag("server-address"))
}

@Composable private fun SampleCard(content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Color.White)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp), content = content)
    }
}

private fun connectionText(state: TunnelState) = when (state) {
    is TunnelState.Disconnected -> "연결 안 됨"
    is TunnelState.Connecting -> "연결하는 중"
    is TunnelState.Handshaking -> "서버 응답 확인 중"
    is TunnelState.Connected -> "연결됨"
    is TunnelState.Error -> "연결 확인 필요"
}
