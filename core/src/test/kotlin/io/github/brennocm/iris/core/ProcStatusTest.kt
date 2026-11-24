package io.github.brennocm.iris.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class ProcStatusTest {
    private fun status(tracer: String) = "Name:\tcom.example\nState:\tS (sleeping)\nTgid:\t4242\nTracerPid:\t$tracer\nUid:\t10123\n"

    @Test
    fun `no tracer`() {
        assertEquals(emptyList(), assertIs<ProbeResult.Completed>(ProcStatus.evaluate(status("0"))).signals)
    }

    @Test
    fun `a ptrace-attached process is reported with the tracer pid`() {
        val r = assertIs<ProbeResult.Completed>(ProcStatus.evaluate(status("4250")))
        assertEquals(listOf(Signal(SignalId.TRACER_ATTACHED, "TracerPid=4250")), r.signals)
    }

    @Test
    fun `missing or malformed status is unavailable`() {
        assertIs<ProbeResult.Unavailable>(ProcStatus.evaluate(null))
        assertIs<ProbeResult.Unavailable>(ProcStatus.evaluate("Name:\tx\n"))
        assertIs<ProbeResult.Unavailable>(ProcStatus.evaluate(status("abc")))
    }
}
