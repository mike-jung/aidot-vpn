// Standalone VPN app that embeds :vpnlib and owns its enrollment/settings.
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.aidotvpn.client.sampleapp"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.aidotvpn.client.sampleapp"
        minSdk = 26
        targetSdk = 36
        versionCode = 12002
        versionName = "1.20.2"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures { compose = true; buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildTypes {
        release { isMinifyEnabled = false }
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
    // vpnlib directly, not :sdk.
    //
    // :sdk binds over AIDL to com.aidotvpn.client.app, which stopped
    // shipping in 1.8.0 when 방법 A was withdrawn — so this app was
    // binding to something that no longer exists and sending the user
    // to onboarding forever. A standalone VPN app has no second app to
    // talk to; it embeds the tunnel and runs it.
    implementation(project(":vpnlib"))
    implementation(project(":core"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    debugImplementation(libs.compose.ui.tooling)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
