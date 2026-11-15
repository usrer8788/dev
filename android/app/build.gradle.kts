plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.chalklog"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.chalklog"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    // The tracker UI is the single web page kept at the repo root; it ships inside the APK as an asset.
    sourceSets["main"].assets.srcDir("../../workout-tracker")
}
