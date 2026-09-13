// :vpnlib — the VPN engine, as an embeddable Android library.
//
// Extracted from :app in 0.11.0. Before that the engine (TunnelManager,
// AidotVpnService, NetworkMonitor, KeyRotationWorker) lived inside an
// `application` module, which meant no other app could use it. The only
// integration path was AIDL to a separately-installed standalone app —
// two APKs, two logins, and a device that had to have both.
//
// The split is one engine, two shells:
//
//   :core    ──▶ :vpnlib ──┬──▶ :app        standalone shell (UI + AIDL)
//                          └──▶ <업무앱>     embedded, single APK
//
// Both shells run identical tunnel code, registration protocol, and
// policy handling. They differ only in who hosts the VpnService and how
// the user signs in.
//
// IMPORTANT — the two modes cannot both be active on one device.
// Android permits exactly one VpnService at a time; whichever connects
// second revokes the first (see AidotVpnService.onRevoke). Choosing a
// mode is a deployment decision per site, not a runtime toggle.
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.aidotvpn.client.vpnlib"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    packaging {
        // The wireguard-tunnel AAR carries native .so files. Consumers
        // inherit them transitively through :core's api(...) dependency.
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}


// Pin the JDK the compiler runs against.
//
// Without this, the toolchain is whatever JDK Gradle happens to run on —
// which is Android Studio's bundled one, and Studio changes it between
// feature drops. A project that built yesterday then fails after an IDE
// update, with an error about class file versions that names the JDK and
// not the cause.
//
// 17 because AGP 8.x and 9.x both require exactly that as a minimum, and
// because `compileOptions` below already targets it. Declaring the
// toolchain makes the two agree by construction rather than by
// coincidence: Gradle downloads a matching JDK if the local one differs.
kotlin {
    jvmToolchain(17)
}

dependencies {
    // api, not implementation: an embedding app needs StoredAllocation,
    // CoreStorage and the controller client to drive registration before
    // it can ask for a tunnel.
    api(project(":core"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime)

    // WorkManager backs the 12-hour key rotation. An embedding app that
    // already uses WorkManager shares the same instance — hence
    // implementation rather than a bundled initializer we control.
    implementation(libs.androidx.work.runtime)
    implementation(libs.androidx.datastore.preferences)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation("androidx.test:runner:1.6.2")
}
