// :core — pure-Kotlin shared layer for AidotVpn Android client.
//
// Both :app and :sdk depend on :core for:
//   - Network client to the AidotVpn controller (registration, key
//     rotation, listing devices)
//   - Models (DeviceRegistration, Allocation, Endpoint) that mirror the
//     proto messages but are hand-written so we don't pull a gRPC
//     stack into a mobile binary
//   - OIDC wrapper around AppAuth-Android
//   - Crypto primitives (Curve25519 keypair, base64 helpers)
//
// This module is an Android library (not a pure JVM library) because
// AppAuth and Android Keystore both require an Android runtime.
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.aidotvpn.client.core"
    compileSdk = 36

    defaultConfig {
        minSdk = 26   // Android 8.0; matches the wider VPN client floor
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
    api(libs.androidx.core.ktx)
    api(libs.androidx.lifecycle.runtime)

    api(libs.okhttp)
    api(libs.okhttp.logging)

    // compileOnly, not api.
    //
    // AppAuth is used by exactly one class — Authenticator — and that
    // class is only reachable in standalone mode, where :app runs the
    // OIDC flow itself. The embedded path (demo-app) supplies its own
    // token through DelegatedTokenSource and never touches it.
    //
    // Exposing it with api() pulled AppAuth's AndroidManifest into every
    // consumer, and that manifest declares:
    //
    //     <data android:scheme="${appAuthRedirectScheme}" />
    //
    // …a placeholder each application module then has to fill in. Only
    // :app had it, so :demo-app failed at processDebugMainManifest for a
    // dependency it does not use:
    //
    //     Attribute data@scheme requires a placeholder substitution but
    //     no value for <appAuthRedirectScheme> is provided.
    //
    // compileOnly keeps Authenticator compiling here while leaving the
    // AAR — and its manifest — out of anything that does not ask for it.
    // :app declares it directly, along with the placeholder.
    compileOnly(libs.appauth)

    api(libs.androidx.datastore.preferences)
    api(libs.androidx.security.crypto)

    api(libs.kotlinx.serialization.json)

    // BouncyCastle, for ML-KEM-768 only (PqcKemClient).
    //
    // `implementation`, not `api`: nothing outside :core touches a
    // BouncyCastle type, and exposing it transitively would make an
    // embedding business app inherit a second crypto provider on its
    // compile classpath for no reason.
    //
    // Size: bcprov is ~8MB unshrunk. We use the low-level
    // pqc.crypto.mlkem classes directly and never register a JCE
    // provider, so R8 strips the rest — see consumer-rules.pro. Not
    // registering a provider also sidesteps the classic Android
    // headache of a second BouncyCastle colliding with the platform's
    // bundled com.android.org.bouncycastle.
    implementation(libs.bouncycastle)

    // Exposed as `api` (not `implementation`) because KeyUtils returns
    // com.wireguard.crypto.{Key, KeyPair} as part of its public surface.
    // `:app` and `:sdk` both rely on this transitive — the WG tunnel
    // AAR also ships the native .so libs they need at runtime.
    api(libs.wireguard.tunnel)

    testImplementation(libs.junit)
}
