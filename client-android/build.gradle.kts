// Root build script. We declare plugins as `apply false` so each module
// chooses which to apply, but the version is pinned here through the
// version catalog.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}

// Force-clean the top-level build dir along with module ones.
tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
