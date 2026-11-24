import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.maven.publish)
}

android {
    namespace = "io.github.brennocm.iris"
    compileSdk = 35
    // Pinned so local and CI builds use the same toolchain; see docs/adr/0001-stack.md.
    ndkVersion = "27.0.12077973"

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
        warningsAsErrors = true
        // These depend on what is published upstream today, which would make check
        // non-deterministic. Dependency updates are handled separately.
        disable += setOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion")
    }
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    api(project(":core"))

    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}

// AGP 8.7 generates the AAR's javadoc with a bundled Dokka whose ASM cannot read the sealed
// types of :core (PermittedSubclasses needs ASM 9), so the javadoc jar holds a README instead.
// Maven Central requires the jar, not its contents; the sources jar carries the KDoc.
mavenPublishing {
    configure(
        com.vanniktech.maven.publish.AndroidSingleVariantLibrary(
            variant = "release",
            sourcesJar = true,
            publishJavadocJar = false,
        ),
    )
}

val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    from(rootProject.file("docs/javadoc-readme.md")) { rename { "README.md" } }
}

afterEvaluate {
    extensions.configure<PublishingExtension> {
        publications.named<MavenPublication>("maven") { artifact(javadocJar) }
    }
}
