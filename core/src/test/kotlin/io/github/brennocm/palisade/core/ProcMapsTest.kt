package io.github.brennocm.palisade.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class ProcMapsTest {
    private val clean = """
        12c00000-12e00000 rw-p 00000000 00:00 0                                  [anon:dalvik-main space]
        7a1b2c3000-7a1b2c5000 r-xp 00000000 fd:05 1843                           /system/lib64/libc.so
        7a1b400000-7a1b401000 r--p 00000000 fd:05 22                             /data/app/~~x==/com.example-y==/base.apk
        7fd3a00000-7fd3a21000 rw-p 00000000 00:00 0                              [stack]
    """.trimIndent()

    @Test
    fun `parses the path, including paths with spaces, and anonymous mappings`() {
        val m = ProcMaps.parse("7a00-7b00 r-xp 00000000 fd:05 12   /data/local/tmp/my lib.so\n7c00-7d00 rw-p 00000000 00:00 0")
        assertEquals(listOf(ProcMaps.Mapping("r-xp", "/data/local/tmp/my lib.so"), ProcMaps.Mapping("rw-p", "")), m)
    }

    @Test
    fun `a clean process has no signals`() {
        val r = assertIs<ProbeResult.Completed>(ProcMaps.evaluate(clean))
        assertEquals(emptyList(), r.signals)
    }

    @Test
    fun `finds a frida agent once even when it is mapped several times`() {
        val agent = "/data/local/tmp/re.frida.server/frida-agent-64.so"
        val maps = clean + "\n7a20000000-7a20100000 r--p 00000000 fd:21 99 $agent" +
            "\n7a20100000-7a20800000 r-xp 00100000 fd:21 99 $agent"
        val r = assertIs<ProbeResult.Completed>(ProcMaps.evaluate(maps))
        assertEquals(listOf(Signal(SignalId.INSTRUMENTATION_LIBRARY, agent)), r.signals)
    }

    @Test
    fun `matches markers case-insensitively and covers xposed`() {
        val maps = "7a00-7b00 r-xp 0 fd:05 1 /system/framework/XposedBridge.jar"
        val r = assertIs<ProbeResult.Completed>(ProcMaps.evaluate(maps))
        assertEquals(1, r.signals.size)
    }

    @Test
    fun `unreadable maps are unavailable, not clean`() {
        assertIs<ProbeResult.Unavailable>(ProcMaps.evaluate(null))
    }
}
