package io.github.brennocm.iris.core

/**
 * Traces of an emulator (the Android emulator, Genymotion, common gaming emulators).
 *
 * An emulator is not root, so these are ENV signals: most backends send them to review, and a
 * backend for a game or a bank may refuse them. Build properties are trivial to change on a
 * rooted image, so the device files are checked too; neither is proof on its own.
 */
public object Emulator {
    /** The android.os.Build fields this check reads, so it can run on the JVM in tests. */
    public data class BuildInfo(
        val fingerprint: String,
        val model: String,
        val manufacturer: String,
        val brand: String,
        val device: String,
        val product: String,
        val hardware: String,
    )

    /** Files that only exist on emulated hardware (QEMU pipes and the goldfish devices). */
    public val DEVICE_FILES: List<String> = listOf(
        "/dev/qemu_pipe",
        "/dev/goldfish_pipe",
        "/dev/goldfish_address_space",
        "/dev/socket/qemud",
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        "/system/bin/qemu-props",
        "/system/lib/libc_malloc_debug_qemu.so",
    )

    private val HARDWARE = setOf("goldfish", "ranchu", "vbox86", "nox", "ttvm_x86", "android_x86")
    private val PRODUCT_MARKERS =
        listOf("sdk_gphone", "sdk_google", "google_sdk", "sdk_x86", "vbox86p", "emulator", "simulator")
    private val MODEL_MARKERS = listOf("android sdk built for", "emulator", "sdk_gphone")

    public fun evaluate(build: BuildInfo, stat: (String) -> PathState): ProbeResult {
        val evidence = mutableListOf<String>()
        if (build.hardware.lowercase() in HARDWARE) evidence += "hardware=${build.hardware}"
        if (PRODUCT_MARKERS.any { build.product.lowercase().contains(it) }) evidence += "product=${build.product}"
        if (MODEL_MARKERS.any { build.model.lowercase().contains(it) }) evidence += "model=${build.model}"
        if (build.manufacturer.equals("Genymotion", ignoreCase = true)) evidence += "manufacturer=${build.manufacturer}"
        if (build.fingerprint.startsWith("generic") || build.fingerprint.contains("/sdk_")) {
            evidence += "fingerprint=${build.fingerprint}"
        }
        if (build.brand.startsWith("generic") && build.device.startsWith("generic")) {
            evidence += "brand=${build.brand} device=${build.device}"
        }
        val signals = evidence.map { Signal.of(SignalId.EMULATOR_BUILD, it) } +
            DEVICE_FILES.filter { stat(it) == PathState.PRESENT }.map { Signal.of(SignalId.EMULATOR_DEVICE_FILE, it) }
        return ProbeResult.Completed(signals)
    }
}
