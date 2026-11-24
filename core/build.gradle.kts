import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    // Shared report examples (see ContractTest); declared as an input so edits rerun the test.
    val schemaDir = rootProject.layout.projectDirectory.dir("schema")
    inputs.dir(schemaDir)
    systemProperty("iris.schemaDir", schemaDir.asFile.path)
}
