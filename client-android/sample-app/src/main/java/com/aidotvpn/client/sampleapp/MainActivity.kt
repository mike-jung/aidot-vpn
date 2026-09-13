package com.aidotvpn.client.sampleapp

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.core.view.WindowCompat
import com.aidotvpn.client.vpnlib.TunnelState

/** Standalone VPN shell; has its own settings and registration, separate from demo-app. */
class MainActivity : ComponentActivity() {
    private val model: SampleViewModel by viewModels()
    private var consentPending by mutableStateOf(false)
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        consentPending = false
        if (it.resultCode == RESULT_OK) model.connect()
        else model.showMessage("VPN 사용을 허용해야 연결할 수 있습니다.")
    }
    private val notifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        requestVpnConsent()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // safeDrawing leaves a light system-bar background. Android 15+ can
        // ignore statusBarColor, so use dark icons instead of relying on it.
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = true
            isAppearanceLightNavigationBars = true
        }
        consentPending = savedInstanceState?.getBoolean("consentPending") ?: false
        setContent {
            val state by model.ui.collectAsStateWithLifecycle()
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) {
                    Screen(state, consentPending, model::enroll, model::saveServer,
                        ::requestConnection, model::disconnect, model::refresh, model::editProbe, model::runProbes)
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        if (!consentPending) model.refresh()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean("consentPending", consentPending)
        super.onSaveInstanceState(outState)
    }

    private fun requestConnection() {
        if (consentPending) return
        consentPending = true
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else requestVpnConsent()
    }

    private fun requestVpnConsent() {
        runCatching {
            val intent = VpnService.prepare(this)
            if (intent != null) vpnConsent.launch(intent)
            else { consentPending = false; model.connect() }
        }.onFailure {
            consentPending = false
            model.showMessage("VPN 사용 승인을 열지 못했습니다: ${it.message}")
        }
    }
}
