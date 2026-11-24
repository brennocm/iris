package io.github.brennocm.iris.core

import kotlin.test.Test
import kotlin.test.assertEquals

class ReportTest {
    @Test
    fun `serializes signals and unavailable probes deterministically`() {
        val report = Report(
            mapOf(
                Probe.TRACER to ProbeResult.Unavailable("could not read /proc/self/status"),
                Probe.MAPS to
                    ProbeResult.Completed(
                        listOf(Signal(SignalId.INSTRUMENTATION_LIBRARY, "/tmp/frida-agent \"64\".so")),
                    ),
                Probe.BUILD_TAGS to ProbeResult.Completed(emptyList()),
            ),
        )
        assertEquals(
            """{"schema":1,"signals":[{"id":"HOOK-001","probe":"maps","evidence":"/tmp/frida-agent \"64\".so"}],""" +
                """"unavailable":[{"probe":"tracer","reason":"could not read /proc/self/status"}]}""",
            report.toJson(),
        )
    }

    @Test
    fun `escapes control characters`() {
        val r =
            Report(
                mapOf(
                    Probe.THREADS to ProbeResult.Completed(
                        listOf(Signal(SignalId.INSTRUMENTATION_THREAD, "a\u0001\nb")),
                    ),
                ),
            )
        assertEquals(true, r.toJson().contains("\"a\\u0001\\nb\""))
    }

    @Test
    fun `long evidence is truncated by Signal of`() {
        val s = Signal.of(SignalId.MAGISK_MOUNT, "x".repeat(1000))
        assertEquals(Signal.MAX_EVIDENCE, s.evidence.length)
    }
}
