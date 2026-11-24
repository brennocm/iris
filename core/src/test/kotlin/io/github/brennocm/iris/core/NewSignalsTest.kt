package io.github.brennocm.iris.core

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class EmulatorTest {
    private val pixel = Emulator.BuildInfo(
        fingerprint = "google/husky/husky:15/AP4A.250105.002/12701944:user/release-keys",
        model = "Pixel 8 Pro",
        manufacturer = "Google",
        brand = "google",
        device = "husky",
        product = "husky",
        hardware = "husky",
    )
    private val avd = Emulator.BuildInfo(
        fingerprint = "google/sdk_gphone64_x86_64/emu64xa:14/UE1A.230829.036/10956411:userdebug/dev-keys",
        model = "sdk_gphone64_x86_64",
        manufacturer = "Google",
        brand = "google",
        device = "emu64xa",
        product = "sdk_gphone64_x86_64",
        hardware = "ranchu",
    )

    @Test
    fun `a phone shows nothing`() {
        val r = assertIs<ProbeResult.Completed>(Emulator.evaluate(pixel) { PathState.ABSENT })
        assertEquals(emptyList(), r.signals)
    }

    @Test
    fun `the android emulator is recognised by build and device files`() {
        val r = assertIs<ProbeResult.Completed>(
            Emulator.evaluate(avd) { if (it == "/dev/goldfish_pipe") PathState.PRESENT else PathState.UNKNOWN },
        )
        assertEquals(
            listOf(
                "hardware=ranchu",
                "product=sdk_gphone64_x86_64",
                "model=sdk_gphone64_x86_64",
                "fingerprint=${avd.fingerprint}",
                "/dev/goldfish_pipe",
            ),
            r.signals.map(Signal::evidence),
        )
        assertEquals(setOf(SignalId.EMULATOR_BUILD, SignalId.EMULATOR_DEVICE_FILE), r.signals.map(Signal::id).toSet())
        assertEquals(Category.ENV, SignalId.EMULATOR_BUILD.category)
    }
}

class FridaPortsTest {
    // 27042 = 0x69A2; 8080 = 0x1F90. State 0A is LISTEN, 01 is ESTABLISHED.
    private val tcp = """
          sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
           0: 00000000:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1
           1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10123        0 4243 1
           2: 0100007F:9C40 0100007F:69A2 01 00000000:00000000 00:00000000 00000000 10123        0 4244 1
    """.trimIndent()

    @Test
    fun `listening sockets are parsed from proc net tcp`() {
        assertEquals(listOf(27042, 8080), FridaPorts.listening(tcp))
    }

    @Test
    fun `frida-server in listen is reported, an established peer connection is not`() {
        val r = assertIs<ProbeResult.Completed>(
            FridaPorts.evaluate(mapOf("tcp" to tcp, "tcp6" to null)) { error("must not connect") },
        )
        assertEquals(listOf("tcp port 27042 in LISTEN"), r.signals.map(Signal::evidence))
    }

    @Test
    fun `when proc net is denied a loopback connect decides`() {
        val denied = mapOf("tcp" to null, "tcp6" to null)
        assertEquals(1, assertIs<ProbeResult.Completed>(FridaPorts.evaluate(denied) { 0 }).signals.size)
        assertEquals(0, assertIs<ProbeResult.Completed>(FridaPorts.evaluate(denied) { -111 }).signals.size)
        assertIs<ProbeResult.Unavailable>(FridaPorts.evaluate(denied) { -13 })
    }
}

class ArtHooksTest {
    @Test
    fun `native flags on java methods and hooker frames are reported`() {
        val r = assertIs<ProbeResult.Completed>(
            ArtHooks.evaluate(
                nativeJavaMethods = listOf("java.io.File.exists"),
                stackClasses = listOf("android.app.ActivityThread", "LSPHooker_.exists"),
                loadableClasses = listOf("de.robv.android.xposed.XposedBridge"),
            ),
        )
        assertEquals(
            listOf("java.io.File.exists", "stack: LSPHooker_.exists", "class: de.robv.android.xposed.XposedBridge"),
            r.signals.map(Signal::evidence),
        )
    }

    @Test
    fun `clean and blind are different`() {
        assertEquals(
            emptyList(),
            assertIs<ProbeResult.Completed>(
                ArtHooks.evaluate(emptyList(), listOf("android.os.Looper"), emptyList()),
            ).signals,
        )
        assertIs<ProbeResult.Unavailable>(ArtHooks.evaluate(null, emptyList(), emptyList()))
    }
}

class InlineHooksTest {
    private val linux = File("/proc/self/maps").canRead()

    private fun readMemory(address: Long, length: Int): ByteArray? = try {
        RandomAccessFile("/proc/self/mem", "r").use { f ->
            f.seek(address)
            ByteArray(length).also { f.readFully(it) }
        }
    } catch (_: Exception) {
        null
    }

    @Test
    fun `the libc of this JVM matches its file`() {
        if (!linux) return
        val maps = File("/proc/self/maps").readText()
        val r = InlineHooks.evaluate(maps, { File(it).readBytes() }, ::readMemory)
        assertEquals(ProbeResult.Completed(emptyList()), r, "host libc compared clean")
    }

    @Test
    fun `a patched prologue in the real libc is reported`() {
        if (!linux) return
        val maps = File("/proc/self/maps").readText()
        val libc = InlineHooks.findLibc(maps)!!
        val elf = Elf.parse(File(libc.path).readBytes())!!
        val open = libc.base + elf.functions.getValue("open").value - elf.loads.first { it.offset == 0L }.vaddr
        val r = InlineHooks.evaluate(maps, { File(it).readBytes() }) { addr, len ->
            readMemory(addr, len)?.also { if (addr == open) it[0] = 0xe9.toByte() } // jmp rel32
        }
        val signals = assertIs<ProbeResult.Completed>(r).signals
        assertEquals(listOf("open"), signals.map { it.evidence.substringBefore(':') })
        assertTrue(signals.single().evidence.startsWith("open: e9"))
    }

    /** A minimal ELF32 with one Thumb function named open at 0x100, as on armeabi-v7a. */
    private fun elf32(): ByteArray {
        val b = ByteBuffer.allocate(0x1B8).order(ByteOrder.LITTLE_ENDIAN)
        b.put(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 1, 1, 1))
        b.putInt(0x1C, 52).putInt(0x20, 0x140) // e_phoff, e_shoff
        b.putShort(0x2A, 32).putShort(0x2C, 1).putShort(0x2E, 40).putShort(0x30, 3)
        b.putInt(52, 1).putInt(56, 0).putInt(60, 0).putInt(68, 0x1B8) // PT_LOAD, offset 0, vaddr 0
        for (i in 0 until 16) b.put(0x100 + i, (0x10 + i).toByte())
        b.position(0x110)
        b.put("\u0000open\u0000".toByteArray())
        b.putInt(0x130, 1).putInt(0x134, 0x101).putInt(0x138, 16) // name, value (Thumb), size
        b.put(0x13C, 0x12).putShort(0x13E, 1) // GLOBAL FUNC, section 1
        // section headers: null, .dynstr (type 3), .dynsym (type 11, link 1)
        b.putInt(0x140 + 40 + 4, 3).putInt(0x140 + 40 + 16, 0x110).putInt(0x140 + 40 + 20, 6)
        b.putInt(0x140 + 80 + 4, 11).putInt(0x140 + 80 + 16, 0x120).putInt(0x140 + 80 + 20, 32)
        b.putInt(0x140 + 80 + 24, 1).putInt(0x140 + 80 + 36, 16)
        return b.array()
    }

    @Test
    fun `32-bit thumb functions are compared at the even address`() {
        val file = elf32()
        val maps = "a0000000-a0001000 r-xp 00000000 fd:00 1   /apex/com.android.runtime/lib/bionic/libc.so\n"
        val clean = InlineHooks.evaluate(maps, { file }) { addr, len ->
            assertEquals(0xa0000100, addr)
            file.copyOfRange(0x100, 0x100 + len)
        }
        assertEquals(ProbeResult.Completed(emptyList()), clean)
        val hooked = InlineHooks.evaluate(maps, { file }) { _, len -> ByteArray(len) { 0xdf.toByte() } }
        assertEquals(1, assertIs<ProbeResult.Completed>(hooked).signals.size)
    }

    @Test
    fun `unreadable or unparseable libc is unavailable, not clean`() {
        val maps = "a0000000-a0001000 r-xp 00000000 fd:00 1 /system/lib64/libc.so\n"
        assertIs<ProbeResult.Unavailable>(InlineHooks.evaluate(maps, { null }) { _, _ -> null })
        assertIs<ProbeResult.Unavailable>(InlineHooks.evaluate(maps, { ByteArray(100) }) { _, _ -> null })
        assertIs<ProbeResult.Unavailable>(InlineHooks.evaluate(maps, { elf32() }) { _, _ -> null })
        assertIs<ProbeResult.Unavailable>(InlineHooks.evaluate("", { null }) { _, _ -> null })
        assertEquals(null, Elf.parse(elf32().copyOf(200)))
    }
}
