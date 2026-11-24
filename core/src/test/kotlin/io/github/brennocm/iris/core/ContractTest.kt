package io.github.brennocm.iris.core

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The report format is shared with the verifier through schema/examples. Each example here is
 * built from real types and must match its file byte for byte; the Go side parses the same
 * files. Set IRIS_UPDATE_CONTRACT=1 to rewrite the files after a deliberate format change.
 */
class ContractTest {
    private val dir = File(System.getProperty("iris.schemaDir")!!, "examples")

    private fun check(name: String, report: Report) {
        val file = File(dir, "$name.json")
        val json = report.toJson() + "\n"
        if (System.getenv("IRIS_UPDATE_CONTRACT") == "1") file.writeText(json)
        assertEquals(file.readText(), json, "schema/examples/$name.json is out of date")
    }

    @Test
    fun clean() = check("clean", Report(Probe.entries.associateWith { ProbeResult.Completed(emptyList()) }))

    @Test
    fun instrumented() = check(
        "instrumented",
        Report(
            mapOf(
                Probe.MAPS to ProbeResult.Completed(
                    listOf(Signal.of(SignalId.INSTRUMENTATION_LIBRARY, "/memfd:frida-agent-64.so (deleted)")),
                ),
                Probe.THREADS to ProbeResult.Completed(
                    listOf("gmain", "gdbus", "gum-js-loop").map { Signal.of(SignalId.INSTRUMENTATION_THREAD, it) },
                ),
                Probe.SU_PATHS to ProbeResult.Completed(listOf(Signal.of(SignalId.SU_BINARY, "/system/xbin/su"))),
                Probe.TRACER to ProbeResult.Completed(emptyList()),
            ),
        ),
    )

    @Test
    fun blinded() = check(
        "blinded",
        Report(
            mapOf(
                Probe.MAPS to ProbeResult.Unavailable("/proc/self/maps is larger than 4194304 bytes"),
                Probe.TRACER to ProbeResult.Unavailable("native library unavailable"),
                Probe.MOUNTS to ProbeResult.Completed(
                    listOf(Signal.of(SignalId.MAGISK_MOUNT, "magisk on /debug_ramdisk \"quoted\"\ttab")),
                ),
            ),
        ),
    )
}
