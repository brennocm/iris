package io.github.brennocm.iris.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class MountsAndThreadsTest {
    @Test
    fun `stock mounts are clean`() {
        val mounts = "/dev/block/dm-0 / ext4 ro,seclabel,relatime 0 0\ntmpfs /dev tmpfs rw,seclabel,nosuid 0 0\n"
        assertEquals(emptyList(), assertIs<ProbeResult.Completed>(Mounts.evaluate(mounts)).signals)
    }

    @Test
    fun `magisk mounts are reported`() {
        val mounts = "magisk /system/bin tmpfs rw,seclabel 0 0\n" +
            "/dev/block/sda1 /debug_ramdisk ext4 ro 0 0\n"
        val r = assertIs<ProbeResult.Completed>(Mounts.evaluate(mounts))
        assertEquals(
            listOf("magisk on /system/bin", "/dev/block/sda1 on /debug_ramdisk"),
            r.signals.map(Signal::evidence),
        )
    }

    @Test
    fun `frida thread names are reported once`() {
        val r =
            assertIs<ProbeResult.Completed>(
                Threads.evaluate(listOf("main", "RenderThread", "gum-js-loop", "gmain", "gmain")),
            )
        assertEquals(listOf("gum-js-loop", "gmain"), r.signals.map { it.evidence })
    }

    @Test
    fun `unreadable inputs are unavailable`() {
        assertIs<ProbeResult.Unavailable>(Mounts.evaluate(null))
        assertIs<ProbeResult.Unavailable>(Threads.evaluate(null))
    }
}
