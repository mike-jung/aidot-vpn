// :demo-app — a business app that embeds the VPN engine.
//
// This is the whole point of the module: it shows what integrating
// AidotVpn actually costs a product team. The answer is the one line
// marked below plus about four calls.
//
// demo-app and sample-app each embed :vpnlib, but have separate app data.
// demo-app provides diagnostic UI; sample-app is the standalone VPN shell.
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.aidotvpn.demo"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.aidotvpn.demo"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        minSdk = 26
        targetSdk = 36
        versionCode = 12002
        versionName = "1.20.2"

        // Where the controller lives, as seen FROM THE PHONE.
        //
        // Not localhost: on a handset that means the handset. The phone
        // has to reach the machine running `npm start`, so this is that
        // machine's LAN address. 10.0.2.2 is the emulator's alias for the
        // host, which is why it is the default — the emulator path works
        // with no edit, and a real device needs one.
        // providers.gradleProperty, not project.findProperty.
        //
        // `org.gradle.configuration-cache=true` caches the configuration
        // phase wholesale. A value read with findProperty is not a tracked
        // input, so editing gradle.properties left the cached entry —
        // and the previous value — in place:
        //
        //   1st build   no property → default 10.0.2.2 baked in
        //   edit gradle.properties
        //   2nd build   "Configuration cache entry reused" → still 10.0.2.2
        //
        // providers.gradleProperty IS tracked, so a change invalidates the
        // entry and the new address reaches BuildConfig.
        val controllerUrl = providers.gradleProperty("aidot.controllerUrl")
            .orElse("http://10.0.2.2:10030")
        buildConfigField("String", "CONTROLLER_URL", "\"${controllerUrl.get()}\"")

        // Printed at configure time, so the address that was actually
        // baked in is visible in the build output rather than only on the
        // phone after installing.
        logger.lifecycle("aidot: demo-app CONTROLLER_URL = ${controllerUrl.get()}")
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    buildTypes {
        debug {
            // The tutorial connects to a controller over plain HTTP on a
            // lab network. Android blocks cleartext by default, and the
            // failure is an opaque IOException rather than anything that
            // names the policy — see network_security_config.xml, which
            // permits it for private ranges only.
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
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
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation("androidx.test:runner:1.6.2")
    // ─────────────────────────────────────────────────────────────
    // This is the integration. One line.
    //
    // It brings the tunnel engine, the VpnService declaration and the
    // VPN permissions (through manifest merge), and :core transitively.
    implementation(project(":vpnlib"))
    // ─────────────────────────────────────────────────────────────

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.material3)
    debugImplementation(libs.compose.ui.tooling)
    implementation(libs.compose.ui.tooling.preview)
}
