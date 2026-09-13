package com.aidotvpn.demo

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aidotvpn.client.vpnlib.TunnelState
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.material3.Surface
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.IconButton
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.withResumed
import kotlinx.coroutines.launch
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.Lifecycle

/**
 * The demo app's single screen.
 *
 * Laid out as four sections in the order a reader works through them, so
 * the screen doubles as the instructions:
 *
 *   ① 연결        state, and the two buttons that change it
 *   ② 지금 설정    what the SERVER says this device has
 *   ③ 도달성 시험  what the device can actually reach
 *   ④ 기록        recent messages
 *
 * Sections ② and ③ side by side are the whole point. A policy value on
 * its own is abstract; a policy value next to "바깥 인터넷 → 응답 없음"
 * is an explanation.
 */
class MainActivity : ComponentActivity() {

    private val vm: DemoViewModel by viewModels()

    /**
     * The Android VPN consent dialog.
     *
     * This is the "이 앱이 VPN 연결을 설정하도록 허용하시겠습니까?" prompt
     * that every VPN app shows once. It is not ours to draw — the system
     * puts it up in response to the Intent from `VpnService.prepare()`,
     * and no tunnel can be established until the user accepts.
     *
     * `prepare()` returns null once consent has been given, which is why
     * a second run shows no dialog. That is the platform remembering, not
     * the app skipping a step.
     */
    private val consent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            // Wait for RESUMED before starting the service.
            //
            // This callback runs while the activity is coming back from
            // the consent dialog, before onResume completes — so the
            // process can still count as background. Starting a
            // foreground service there throws
            // ForegroundServiceStartNotAllowedException on Android 12+,
            // which killed the app: screen gone, no notification.
            //
            // withResumed defers to the moment the activity is
            // definitively in the foreground, where the start is always
            // permitted. Milliseconds later, and correct.
            lifecycleScope.launch {
                lifecycle.withResumed { vm.connect() }
            }
        } else {
            vm.reportConsentDenied()
        }
    }

    /**
     * POST_NOTIFICATIONS, Android 13+.
     *
     * Without it the foreground service still runs — but its notification
     * is never shown, so the user sees no state and no disconnect button.
     * Declaring the permission in the manifest is not enough on 13+; it
     * has to be requested, and a library cannot request it on the host
     * app's behalf.
     *
     * Asked for at startup rather than at connect time so the dialog does
     * not land on top of the VPN consent dialog, which is confusing and
     * makes people dismiss both.
     */
    private val notifPerm = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (!granted) vm.reportNotificationsDenied()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        askNotificationPermission()
        setContent {
            // The mood is read from the ViewModel, which read it from
            // SharedPreferences synchronously — so this first frame is
            // already right and there is no flash of the other theme.
            val dark by vm.darkTheme.collectAsState()
            val palette = if (dark) DarkPalette else LightPalette
            CompositionLocalProvider(LocalPalette provides palette) {
                MaterialTheme(
                    colorScheme = if (dark) darkColorScheme(
                        primary = palette.accent, background = palette.bgTop,
                        surface = Color.Transparent, onSurface = palette.text,
                    ) else lightColorScheme(
                        primary = palette.accent, background = palette.bgTop,
                        surface = Color.Transparent, onSurface = palette.text,
                    ),
                ) {
                    DemoScreen(
                    vm = vm,
                    onAskConsent = { vm.consentIntent()?.let { consent.launch(it) } ?: vm.connect() },
                )
                }
            }
        }
    }

    private fun askNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(
            this, Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
}

// Colours now come from the palette in Theme.kt. These names are kept so
// the call sites below read unchanged; each resolves against whichever
// mood is active.
private val Navy: Color @Composable get() = LocalPalette.current.text
private val Mint: Color @Composable get() = LocalPalette.current.goodSoft
private val Teal: Color @Composable get() = LocalPalette.current.accent
private val Good: Color @Composable get() = LocalPalette.current.good
private val Warn: Color @Composable get() = LocalPalette.current.warn
private val Stop: Color @Composable get() = LocalPalette.current.bad
private val Cream: Color @Composable get() = LocalPalette.current.glass
private val Grey: Color @Composable get() = LocalPalette.current.text2

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DemoScreen(vm: DemoViewModel, onAskConsent: () -> Unit) {
    val state by vm.tunnelState.collectAsState()
    val eff by vm.effective.collectAsState()
    val probes by vm.probeResults.collectAsState()
    val busy by vm.busy.collectAsState()
    val message by vm.message.collectAsState()
    val permitted by vm.permitted.collectAsState()
    val blocked by vm.blocked.collectAsState()

    // Enrollment: a device name and the shared password, which is what
    // the operator actually has in hand. The access token this replaced
    // was 38 characters with no way to get them onto a phone.
    // Model alone is not a name.
    //
    // Ten identical handsets all enrolled as SM-F721N, and 디바이스 —
    // and every screen that lists devices by name — could not tell them
    // apart. The model is reported separately (1.9.0) and shown in the
    // detail dialog, so the name field is free to be what an admin
    // actually needs: something they chose. The suffix makes the
    // default unique; the operator is expected to replace it.
    // The phone's own name first.
    //
    // Model plus a suffix is unique but unreadable: 디바이스 showed
    // SM-F721N-A3C1 and an admin still could not tell whose phone it
    // was. Settings.Global.DEVICE_NAME is what the owner called it
    // ("마이크의 Galaxy Z Flip4"), needs no permission, and is the same
    // key Unity and others read. The model form remains the fallback
    // for a phone whose owner never named it.
    val appCtx = LocalContext.current
    var deviceName by remember { mutableStateOf(defaultDeviceName(appCtx)) }
    var enrollPassword by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    val enrollCode by vm.enrollCode.collectAsState()
    val enrollWaiting by vm.enrollWaiting.collectAsState()
    val errorDialog by vm.errorDialog.collectAsState()
    val stage by vm.stage.collectAsState()
    val registered by vm.registered.collectAsState()
    val canConnect by vm.canConnect.collectAsState()
    val log by vm.log.collectAsState()
    val mismatch by vm.addressMismatch.collectAsState()
    val stateFailure by vm.stateFailure.collectAsState()
    var logPage by remember { mutableStateOf(0) }
    // A new line means something just happened; that is what the reader
    // wants to see, not page four of what happened before it.
    LaunchedEffect(log.size) { logPage = 0 }
    val tunnelWarning by vm.tunnelWarning.collectAsState()
    val controllerUrl by vm.controllerUrl.collectAsState()
    var urlDraft by remember(controllerUrl) { mutableStateOf(controllerUrl) }

    // Messages surface here, not only in ④ 기록 at the bottom of a
    // scrolling column. A failed 등록 요청 wrote its reason into a section
    // the operator had to scroll past the whole screen to reach, which is
    // indistinguishable from nothing happening.
    val snackbar = remember { SnackbarHostState() }
    // Keyed on seq, not on the text: the same message twice in a row
    // must show twice, because to the operator those are two attempts.
    // Ask the controller on every resume.
    //
    // An admin can revoke while the app sits in the background, and the
    // phone has no other way to find out. Coming back to the app is the
    // moment the operator is looking, so it is the moment to check.
    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(lifecycleOwner) {
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            // Poll while the screen is up, not just once on resume.
            //
            // An admin assigns a policy with the phone in front of them
            // and nothing happens until someone presses 설정 새로고침 —
            // which the operator has no reason to know about. Five
            // seconds is cheap (one small GET) and stops the moment the
            // app goes to the background, so nothing polls in a pocket.
            while (true) {
                vm.refreshServerState()
                kotlinx.coroutines.delay(5_000)
            }
        }
    }

    LaunchedEffect(message?.seq) {
        message?.let { snackbar.showSnackbar(it.text) }
    }

    // Failures get a dialog the operator dismisses, on top of the
    // snackbar. A snackbar that vanishes is fine for progress and wrong
    // for an error somebody has to read out to whoever set up the server.
    // Address mismatch comes first: when it applies it is the reason for
    // whatever error is behind it, and answering it usually clears both.
    mismatch?.let { (inUse, built) ->
        AddressMismatchDialog(
            inUse = inUse,
            built = built,
            onUseBuilt = vm::useBuiltInAddress,
            onKeep = vm::dismissAddressMismatch,
        )
    }


    errorDialog?.let { text ->
        AlertDialog(
            onDismissRequest = vm::dismissError,
            title = { Text("문제가 생겼습니다") },
            text = { Text(text) },
            confirmButton = {
                TextButton(onClick = vm::dismissError) { Text("확인") }
            },
        )
    }

    val p = LocalPalette.current
    var showSettings by remember { mutableStateOf(false) }
    Scaffold(
        containerColor = Color.Transparent,
        modifier = Modifier.auroraBackground(p),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("AidotVpn 시험 앱", fontWeight = FontWeight.Bold) },
                // The mood switch, in the bar where aidot-delivery keeps
                // it. One tap, remembered, no restart.
                actions = {
                    val dark by vm.darkTheme.collectAsState()
                    TextButton(onClick = { vm.setDarkTheme(!dark) }) {
                        Text(if (dark) "☀ 라이트" else "☾ 다크", color = p.headerText, fontSize = 12.sp)
                    }
                    // Settings, reachable at any stage.
                    //
                    // The server address could only be edited inside the
                    // registration card, so once a phone was registered
                    // there was no way to point it at a different server
                    // — moving to another site meant rebuilding the app
                    // with a new gradle.properties. It lives here now.
                    var menuOpen by remember { mutableStateOf(false) }
                    IconButton(onClick = { menuOpen = true }) {
                        Text("⚙", color = p.headerText, fontSize = 18.sp)
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text("설정") },
                            onClick = { menuOpen = false; showSettings = true },
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = p.headerBg, titleContentColor = p.headerText,
                ),
            )
        },
    ) { pad ->
        if (showSettings) {
            SettingsSheet(vm = vm, onClose = { showSettings = false })
            return@Scaffold
        }
        Column(Modifier.padding(pad).fillMaxSize()) {
            // The stage bar is outside the scroll, so it is always on
            // screen.
            //
            // It describes the whole page — every card below is one step
            // of it — and it is the answer to "where am I", which is the
            // question someone has when they open the app and again
            // after every action. Inside the scroll it disappeared as
            // soon as they read anything.
            //
            // Surface rather than a bare Column: it needs to sit on top
            // of the scrolling content, and a shared background is what
            // makes that read as a header rather than as a card that
            // failed to scroll.
            Surface(
                color = Color.Transparent,
                modifier = Modifier.fillMaxWidth().glassCard(p, radius = 0),
            ) {
                Column(Modifier.padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 10.dp)) {
                    StageBar(stage)
                    StageHint(stage, stateFailure)
                }
            }

            Column(
                Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {

            // Registration and connection are separate cards.
            //
            // They answer different questions — "is this phone enrolled"
            // and "is the tunnel up" — and only one of them is ever the
            // live one. A single card holding both meant the controls
            // for a step the user had finished sat beside the ones for
            // the step they were on.
            Section("① 등록") {

                // One stage, one set of controls.
                //
                // Every button used to be visible at once, so the screen
                // said the same thing whatever the device was doing.
                // Showing only what applies now means the operator never
                // has to work out which control is the live one.
                if (stage == DemoViewModel.Stage.REVOKED || stage == DemoViewModel.Stage.AUTH_REQUIRED) {
                    val needsAuthentication = stage == DemoViewModel.Stage.AUTH_REQUIRED
                    Text(
                        if (needsAuthentication) "등록 인증 정보를 갱신해야 합니다." else "관리자가 이 단말을 폐기했습니다.",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = Stop,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        if (needsAuthentication) "아래 버튼을 누른 뒤 등록을 요청하고 관리자 승인을 받아주세요. 서버 주소는 유지되며 앱을 삭제할 필요가 없습니다."
                        else "다시 쓰려면 등록 정보를 지우고 처음부터 등록하세요.",
                        fontSize = 12.sp,
                        color = Grey,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = { vm.resetRegistration() },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !busy,
                    ) { Text(if (needsAuthentication) "다시 등록하기" else "등록 정보 지우고 다시 시작") }
                } else if (registered) {
                    // Registered — whatever the controller is saying right
                    // now. This used to list the stages that hide the
                    // enrolment form (READY, CONNECTED, NO_POLICY); adding
                    // UNREACHABLE in 1.9.0 left it out, so a phone that
                    // enrolled while the last status check had failed was
                    // shown the enrolment form again, on top of a
                    // registration that had just succeeded. Asking whether
                    // an allocation exists cannot go stale that way.
                } else if (enrollCode != null) {
                    // Waiting for approval. The code is the interaction —
                    // an admin has to read it off this screen — so it is
                    // the largest thing here and stays put until decided.
                    Text(
                        "관리자에게 이 숫자를 보여주세요",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.fillMaxWidth(),
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.height(8.dp))
                    Surface(
                        color = Color.Transparent,
                        shape = RoundedCornerShape(18.dp),
                        modifier = Modifier.fillMaxWidth().glassCard(p),
                    ) {
                        Text(
                            enrollCode!!,
                            style = MaterialTheme.typography.displaySmall,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 6.sp,
                            color = Navy,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth().padding(vertical = 14.dp),
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        if (enrollWaiting) "승인을 기다리는 중…\n10분 안에 승인받으세요" else "",
                        style = MaterialTheme.typography.bodySmall,
                        color = Grey,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = { vm.cancelEnrollment() },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("취소") }
                } else {
                    OutlinedTextField(
                        value = deviceName,
                        onValueChange = { deviceName = it },
                        label = { Text("기기 이름") },
                        supportingText = { Text("관리자가 목록에서 알아볼 이름") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = enrollPassword,
                        onValueChange = { enrollPassword = it },
                        label = { Text("등록 비밀번호") },
                        supportingText = { Text("관리자가 관리실 화면에서 알려줍니다") },
                        singleLine = true,
                        // Revealable. This is a shared password read aloud
                        // across a room and typed on a phone keypad —
                        // masking it protects nothing and mistyping it is
                        // the most likely reason a request fails.
                        visualTransformation =
                            if (showPassword) VisualTransformation.None
                            else PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { showPassword = !showPassword }) {
                                Text(
                                    if (showPassword) "숨김" else "보기",
                                    fontSize = 12.sp,
                                    color = Navy,
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    // The address this app was built with.
                    //
                    // "the password was right and the console showed
                    // nothing" is almost always a phone talking to a
                    // different controller — usually localhost, which on a
                    // handset means the handset. The app cannot detect
                    // that, but it can stop the operator from having to
                    // guess: the value is baked in at build time and
                    // shown here.
                    // Editable. It used to be a read-only line showing the
                    // build constant, and a controller that moved meant a
                    // rebuild for every phone. Now the value on screen is
                    // the value in use, and changing it here is enough.
                    OutlinedTextField(
                        value = urlDraft,
                        onValueChange = { urlDraft = it },
                        label = { Text("서버 주소") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        trailingIcon = {
                            if (urlDraft.trim().trimEnd('/') != controllerUrl) {
                                TextButton(onClick = { vm.setControllerUrl(urlDraft) }) {
                                    Text("적용", fontSize = 12.sp)
                                }
                            }
                        },
                    )
                    Text(
                        "http://컨트롤러IP:10030 — 서버를 옮기면 여기만 바꾸면 됩니다",
                        fontSize = 10.sp,
                        color = Grey,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(8.dp))
                    Button(
                        onClick = { vm.requestEnrollment(deviceName, enrollPassword) },
                        enabled = !busy && deviceName.isNotBlank() && enrollPassword.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("등록 요청") }
                }

            }

            Section("② 연결") {
                // Status directly above the buttons that change it.
                //
                // 연결 안 됨 used to sit at the top of the card with the
                // registration form between it and the 연결 button —
                // cause and effect separated by an unrelated form, so
                // pressing the button meant scrolling back to see
                // whether it had done anything.
                StatusPill(state)

                // A fallback that happened, said out loud.
                //
                // Connecting on a stored policy is better than refusing
                // to connect, and it is not the same as connecting on a
                // current one. Saying so is what lets the user act on it.
                tunnelWarning?.let { w ->
                    Spacer(Modifier.height(8.dp))
                    Surface(
                        color = p.warnSoft,
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            w,
                            fontSize = 11.5.sp,
                            color = Warn,
                            modifier = Modifier.padding(10.dp),
                        )
                    }
                }

                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onAskConsent,
                        // Not gated on `busy`.
                        //
                        // `busy` is shared by every operation, so 세 곳 모두
                        // 확인하기 — an application-level probe — used to
                        // lock the connection controls until its results
                        // arrived. Whether a probe is running has nothing
                        // to do with whether the user may connect: they
                        // are different layers and must not share a lock.
                        enabled = canConnect,
                        modifier = Modifier.weight(1f),
                    ) { Text("연결") }
                    OutlinedButton(
                        onClick = { vm.disconnect() },
                        // Same reasoning as 연결: hanging up is a connection
                    // action and stays available while the app is doing
                    // something else.
                    enabled = state !is TunnelState.Disconnected,
                        modifier = Modifier.weight(1f),
                    ) { Text("끊기") }
                }
                if (stage == DemoViewModel.Stage.UNREGISTERED) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "먼저 위에서 등록을 마쳐야 연결할 수 있습니다.",
                        fontSize = 11.5.sp, color = Grey,
                    )
                }
            }

            // ------------------------------------------------ ② 지금 설정
            Section("③ 지금 내 폰에 적용된 설정") {
                if (eff == null) {
                    Text(
                        "아직 불러오지 않았습니다. 등록 후 아래 버튼을 누르세요.",
                        fontSize = 13.sp, color = Grey,
                    )
                } else {
                    val e = eff!!
                    KV("정책", if (e.policyBound) e.policyName else "없음 — 연결되지 않습니다",
                        if (e.policyBound) Good else Stop)
                    KV("갈 수 있는 곳", e.allowedIps.joinToString(", ").ifBlank { "없음" }, Navy)
                    KV("경로 범위", e.routeScopeMeans, if (e.routeScope == "full") Warn else Navy)
                    KV("앱 필터", e.appFilterMeans, Navy)
                    if (e.dnsServers.isNotEmpty()) KV("DNS", e.dnsServers.joinToString(", "), Navy)
                    e.warnings.forEach { w ->
                        if (w != "특이사항 없습니다.") {
                            Spacer(Modifier.height(6.dp))
                            Callout(w, Warn)
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = { vm.refreshEffective() },
                    enabled = !busy,
                ) { Text("설정 새로고침") }
            }

            // --------------------------------------------- ③ 도달성 시험
            Section("④ 어디에 갈 수 있는지 시험") {
                OutlinedTextField(
                    value = permitted, onValueChange = vm::setPermitted,
                    label = { Text("허용된 서버") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = blocked, onValueChange = vm::setBlocked,
                    label = { Text("허용 안 된 서버") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = { vm.runProbes() },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (busy) "확인 중…" else "세 곳 모두 확인하기") }

                Spacer(Modifier.height(10.dp))
                Reachability.defaults(permitted, blocked).forEach { p ->
                    ProbeRow(p, probes[p.id])
                    Spacer(Modifier.height(6.dp))
                }
            }

            // ------------------------------------------------------ ④ 기록
            if (log.isNotEmpty()) {
                Section("⑤ 기록") {
                    Text(
                        "최근에 일어난 일이 위에서부터 쌓입니다.",
                        fontSize = 11.5.sp, color = Grey,
                    )
                    Spacer(Modifier.height(8.dp))
                    // A page at a time.
                    //
                    // Thirty lines and a "… 그 밖에 N줄" note meant the
                    // card grew to a screenful and the rest was
                    // unreachable — the older entries are exactly the
                    // ones worth reading when something has just gone
                    // wrong. Ten per page, newest first, with the page
                    // reset whenever a new line arrives so the operator
                    // is looking at what just happened.
                    val pageSize = 10
                    val pages = maxOf(1, (log.size + pageSize - 1) / pageSize)
                    val page = logPage.coerceIn(0, pages - 1)
                    log.drop(page * pageSize).take(pageSize).forEach { e -> LogRow(e) }

                    if (pages > 1) {
                        Spacer(Modifier.height(6.dp))
                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            TextButton(
                                onClick = { logPage = page - 1 },
                                enabled = page > 0,
                            ) { Text("← 최근") }
                            Text(
                                "${page + 1} / $pages 쪽 · 전체 ${log.size}줄",
                                fontSize = 11.sp, color = p.text3,
                            )
                            TextButton(
                                onClick = { logPage = page + 1 },
                                enabled = page < pages - 1,
                            ) { Text("이전 →") }
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    TextButton(onClick = vm::clearLog) { Text("기록 지우기") }
                }
            }
            }
        }
    }
}

/**
 * One line of history: time, a coloured dot for the kind, the text.
 *
 * Newest at the top, because the thing that just happened is the thing
 * being looked for. Time in HH:mm:ss and nothing else — a session lasts
 * minutes, and a date on every line would be noise.
 */
@Composable
private fun LogRow(e: DemoViewModel.LogEntry) {
    val p = LocalPalette.current
    val colour = when (e.kind) {
        DemoViewModel.LogKind.OK -> p.good
        DemoViewModel.LogKind.WARN -> p.warn
        DemoViewModel.LogKind.ERROR -> p.bad
        DemoViewModel.LogKind.INFO -> p.text3
    }
    Row(
        Modifier.fillMaxWidth().padding(vertical = 3.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            timeOf(e.at),
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            color = p.text3,
            modifier = Modifier.width(58.dp),
        )
        Box(
            Modifier.padding(top = 5.dp, end = 8.dp).size(7.dp)
                .background(colour, CircleShape),
        )
        Column(Modifier.weight(1f)) {
            Text(e.text, fontSize = 12.5.sp, color = p.text)
            e.detail?.let {
                Text(it, fontSize = 11.sp, color = p.text3)
            }
        }
    }
}

/** What the owner called this phone, falling back to its model. */
private fun defaultDeviceName(ctx: android.content.Context): String {
    val cr = ctx.contentResolver
    val named = runCatching {
        android.provider.Settings.Global.getString(cr, "device_name")
            ?: android.provider.Settings.Secure.getString(cr, "bluetooth_name")
    }.getOrNull()
    named?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
    // Nobody named this phone: model plus a suffix, so at least two of
    // the same handset are two rows.
    val suffix = android.os.Build.ID.takeLast(4).ifBlank {
        (System.currentTimeMillis() % 10000).toString()
    }
    return (android.os.Build.MODEL ?: "단말") + "-" + suffix
}

private fun timeOf(ms: Long): String {
    val c = java.util.Calendar.getInstance().apply { timeInMillis = ms }
    return "%02d:%02d:%02d".format(
        c.get(java.util.Calendar.HOUR_OF_DAY),
        c.get(java.util.Calendar.MINUTE),
        c.get(java.util.Calendar.SECOND),
    )
}

@Composable
private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Cream),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(title, fontWeight = FontWeight.Bold, fontSize = 16.sp, color = Navy)
            Spacer(Modifier.height(10.dp))
            content()
        }
    }
}

/**
 * 설정 — the server address, editable at any time.
 *
 * One field, because one thing here actually changes between sites: the
 * controller's address. Changing it clears nothing; the phone stays
 * registered, and the next connect uses the new address. If the new
 * server does not know this phone, 등록 부터 다시 하라고 화면이 말합니다.
 */
@Composable
private fun SettingsSheet(vm: DemoViewModel, onClose: () -> Unit) {
    val p = LocalPalette.current
    val current by vm.controllerUrl.collectAsState()
    var draft by remember(current) { mutableStateOf(current) }
    Column(
        Modifier.fillMaxSize().auroraBackground(p).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("설정", fontSize = 22.sp, fontWeight = FontWeight.Bold, color = p.text)
        Text(
            "다른 곳에서 쓰려면 서버 주소만 바꾸면 됩니다. 앱을 다시 만들 필요 없습니다.",
            fontSize = 13.sp, color = p.text2,
        )
        Column(Modifier.fillMaxWidth().glassCard(p).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("서버 주소 (관리실)", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = p.text2)
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                "예: http://192.168.0.11:10030\n" +
                    "서버를 켠 컴퓨터의 주소입니다. npm start 가 화면에 찍어줍니다.",
                fontSize = 11.sp, color = p.text3,
            )
            Button(
                onClick = { vm.setControllerUrl(draft); onClose() },
                enabled = draft.isNotBlank() && draft != current,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("저장") }
        }
        Column(Modifier.fillMaxWidth().glassCard(p).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("지금 이 폰", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = p.text2)
            Text("주소를 바꿔도 등록은 그대로 남습니다.", fontSize = 11.5.sp, color = p.text3)
            Text(
                "새 서버가 이 폰을 모르면 [등록] 부터 다시 하면 됩니다.",
                fontSize = 11.5.sp, color = p.text3,
            )
        }
        Spacer(Modifier.weight(1f))
        OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("닫기") }
    }
}

/**
 * 서버 주소가 둘일 때.
 *
 * The app was built with one address and is using another, and the
 * controller is not answering. Nothing else on screen can explain that:
 * 서버에 연결할 수 없습니다 is true and useless. Naming both values and
 * asking which one to keep turns a dead end into a choice.
 */
@Composable
private fun AddressMismatchDialog(
    inUse: String,
    built: String,
    onUseBuilt: () -> Unit,
    onKeep: () -> Unit,
) {
    val p = LocalPalette.current
    AlertDialog(
        onDismissRequest = onKeep,
        title = { Text("서버 주소가 두 개입니다") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "서버에 연결되지 않습니다. 이 앱이 쓰는 주소와 앱을 만들 때 넣은 주소가 다릅니다.",
                    fontSize = 13.sp, color = p.text,
                )
                Text("지금 쓰는 주소 (설정에서 저장한 값)", fontSize = 11.sp, color = p.text3)
                Text(inUse, fontSize = 13.sp, fontFamily = FontFamily.Monospace, color = p.text)
                Text("앱을 만들 때 넣은 주소 (gradle.properties)", fontSize = 11.sp, color = p.text3)
                Text(built, fontSize = 13.sp, fontFamily = FontFamily.Monospace, color = p.text)
                Text(
                    "설정에 저장한 값이 우선합니다. 앱을 새로 만들어도 이 값이 남아 있어서 바뀌지 않습니다.",
                    fontSize = 11.5.sp, color = p.text3,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onUseBuilt) { Text("만들 때 넣은 주소 쓰기") }
        },
        dismissButton = {
            TextButton(onClick = onKeep) { Text("지금 주소 그대로") }
        },
    )
}

@Composable
private fun StatusPill(state: TunnelState) {
    val (text, color) = when (state) {
        is TunnelState.Connected -> "연결됨" to Good
        is TunnelState.Connecting -> "연결 중…" to Teal
        // Amber, not green: the interface is up but nothing has come
        // back yet. Green here is what made a phone claim 연결됨 next to
        // a SocketTimeoutException.
        is TunnelState.Handshaking -> "문지기 응답 대기 중…" to Warn
        is TunnelState.Disconnected -> "연결 안 됨" to Grey
        is TunnelState.Error -> state.message to Stop
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(12.dp)
                .background(color, RoundedCornerShape(6.dp)),
        )
        Spacer(Modifier.width(8.dp))
        Text(text, fontWeight = FontWeight.Bold, color = color, fontSize = 15.sp)
    }
}

@Composable
private fun KV(key: String, value: String, color: Color) {
    Row(Modifier.padding(vertical = 3.dp)) {
        Text(key, fontSize = 13.sp, color = Grey, modifier = Modifier.width(96.dp))
        Text(value, fontSize = 13.sp, color = color, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun Callout(text: String, color: Color) {
    Box(
        Modifier
            .fillMaxWidth()
            .background(color.copy(alpha = 0.10f), RoundedCornerShape(8.dp))
            .padding(10.dp),
    ) {
        Text(text, fontSize = 12.sp, color = color)
    }
}

/**
 * One probe and its result.
 *
 * Shows expected vs actual rather than only actual. "응답 없음" on its own
 * reads as a fault; "응답 없음 · 예상대로" reads as the policy working,
 * and that difference is most of what this app exists to teach.
 */
@Composable
private fun ProbeRow(p: Reachability.Probe, r: Reachability.Result?) {
    val matched = r != null && p.expectation != null && r.outcome == p.expectation
    val mismatched = r != null && p.expectation != null && r.outcome != p.expectation
    val dot = when {
        r == null -> Color.LightGray
        matched -> Good
        mismatched -> Stop
        else -> Teal   // no expectation — depends on route scope
    }
    Column(
        Modifier
            .fillMaxWidth()
            .glassCard(LocalPalette.current, radius = 12)
            .padding(10.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(10.dp).background(dot, RoundedCornerShape(5.dp)))
            Spacer(Modifier.width(8.dp))
            Text(p.label, fontWeight = FontWeight.Bold, fontSize = 14.sp, color = Navy)
        }
        Text(p.target, fontSize = 11.sp, color = Grey, fontFamily = FontFamily.Monospace)
        Spacer(Modifier.height(4.dp))
        Text(r?.describe() ?: "아직 확인하지 않음", fontSize = 13.sp, color = dot)
        // Why, when the app can tell. "응답 없음" is the same two words
        // for a policy that excludes the address and a server that is
        // down; the line below is what separates them.
        if (!r?.detail.isNullOrBlank() && r?.detail != "확인 중…") {
            Text(r.detail, fontSize = 11.sp, color = Warn)
        }
        if (matched) Text("예상대로입니다", fontSize = 11.sp, color = Good)
        if (mismatched) Text("예상과 다릅니다 — 정책을 확인하세요", fontSize = 11.sp, color = Stop)
        Spacer(Modifier.height(3.dp))
        Text(p.hint, fontSize = 11.sp, color = Grey)
    }
}

/**
 * The four things that have to happen, and where this device is.
 *
 * A progress row rather than prose because the question — "did my
 * registration go through?" — is positional. The screen previously
 * showed 등록 요청, 연결 and 끊기 simultaneously and in the same
 * weight, so a registered device looked exactly like an unregistered
 * one.
 *
 * Four steps, not six: the enum has states for waiting and revoked, but
 * those are conditions of a step rather than steps of their own, and a
 * bar that grows when something goes wrong reads as progress.
 */
@Composable
private fun StageBar(stage: DemoViewModel.Stage) {
    val steps = listOf("등록 요청", "관리자 승인", "정책 적용", "연결")
    val reached = when (stage) {
        DemoViewModel.Stage.UNREGISTERED -> 0
        DemoViewModel.Stage.AWAITING_APPROVAL -> 1
        DemoViewModel.Stage.CHECKING -> 2
        DemoViewModel.Stage.NO_POLICY -> 2
        DemoViewModel.Stage.READY -> 3
        DemoViewModel.Stage.CONNECTED -> 4
        DemoViewModel.Stage.REVOKED -> 0
        // No lit steps: the bar shows progress through enrolment, and
        // without the server we do not know how far along we are.
        DemoViewModel.Stage.UNREACHABLE -> 0
        DemoViewModel.Stage.AUTH_REQUIRED -> 0
    }

    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        steps.forEachIndexed { i, label ->
            val done = i < reached
            val current = i == reached
            Column(
                modifier = Modifier.weight(1f),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Surface(
                    color = when {
                        done -> Mint
                        current -> Navy
                        else -> Color.LightGray
                    },
                    shape = RoundedCornerShape(2.dp),
                    modifier = Modifier.fillMaxWidth().height(4.dp),
                ) {}
                Spacer(Modifier.height(5.dp))
                Text(
                    label,
                    fontSize = 10.sp,
                    // The current step is the one to read; the rest are
                    // context. Colour carries that, not size — a bar
                    // whose labels change size shifts on every transition.
                    color = if (done || current) Navy else Grey,
                    fontWeight = if (current) FontWeight.Bold else FontWeight.Normal,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

/** One line saying what the device is waiting for, in plain terms. */
@Composable
private fun StageHint(stage: DemoViewModel.Stage, stateFailure: String? = null) {
    val (text, color) = when (stage) {
        DemoViewModel.Stage.UNREGISTERED ->
            "아직 등록되지 않았습니다." to Grey
        DemoViewModel.Stage.AWAITING_APPROVAL ->
            "관리자 승인을 기다리는 중입니다." to Navy
        DemoViewModel.Stage.CHECKING ->
            "등록 완료. 서버 상태와 정책을 확인하고 있습니다." to Navy
        DemoViewModel.Stage.NO_POLICY ->
            "등록됐지만 정책이 없습니다. 관리자가 정책을 지정해야 연결됩니다." to Warn
        DemoViewModel.Stage.READY ->
            "등록 완료. 연결할 수 있습니다." to Good
        DemoViewModel.Stage.CONNECTED ->
            "연결됨." to Good
        DemoViewModel.Stage.AUTH_REQUIRED ->
            "등록 인증 정보를 사용할 수 없습니다. 아래 '다시 등록하기'로 복구하세요." to Stop
        DemoViewModel.Stage.UNREACHABLE ->
            (stateFailure ?: "서버 상태를 확인하지 못했습니다. 잠시 후 다시 시도하세요.") to Stop
        DemoViewModel.Stage.REVOKED ->
            "이 단말은 폐기되었습니다. 다시 등록해야 합니다." to Stop
    }
    Text(text, fontSize = 12.sp, color = color, modifier = Modifier.fillMaxWidth())
}
