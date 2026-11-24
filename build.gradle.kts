plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.maven.publish) apply false
}

// Publishing to Maven Central (docs/releasing.md). Coordinates and POM metadata come from
// gradle.properties; credentials and the signing key only from the environment, never a file.
subprojects {
    plugins.withId("com.vanniktech.maven.publish") {
        extensions.configure<com.vanniktech.maven.publish.MavenPublishBaseExtension> {
            publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL, automaticRelease = false)
            // Signing needs the key, which only the release workflow has; local and CI
            // builds can still publish to the staging repository below to inspect the output.
            if (providers.gradleProperty("signingInMemoryKey").isPresent) signAllPublications()
        }
        extensions.configure<PublishingExtension> {
            repositories {
                maven {
                    name = "staging"
                    url = uri(rootProject.layout.buildDirectory.dir("staging-repo"))
                }
            }
        }
    }
}
