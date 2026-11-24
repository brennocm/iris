package io.github.brennocm.iris.core

/**
 * Looks for inline hooks in libc: functions whose first instructions in memory differ from the
 * same bytes in the libc file on disk.
 *
 * Frida's Interceptor, and most native hooking libraries, overwrite a function's prologue with
 * a jump to their trampoline. libc's code pages are mapped read-only from the file and never
 * relocated, so any difference in the first bytes of a function means someone wrote to them.
 * The functions checked are the ones anti-detection scripts hook to hide files, maps and
 * threads. Reading the memory and the file goes through direct syscalls in the native layer.
 */
public object InlineHooks {
    public val FUNCTIONS: List<String> = listOf(
        "open", "openat", "__openat", "read", "close", "access", "faccessat", "stat", "fopen",
        "opendir", "readdir", "strstr", "strcmp", "ptrace", "syscall", "connect", "kill",
        "pthread_create", "__system_property_get", "__system_property_read_callback",
    )

    /** Bytes compared per function: enough to cover any hook's branch sequence. */
    public const val PROLOGUE: Int = 16

    /** libc as the process mapped it: the file and the address its first segment is at. */
    public data class Library(val path: String, val base: Long)

    private val LIBC = Regex("/libc\\.so(\\.\\d+)?$")

    /** Finds libc in the text of `/proc/self/maps`. */
    public fun findLibc(maps: String): Library? = maps.lineSequence().mapNotNull { line ->
        val f = line.trim().split(WHITESPACE, limit = 6)
        if (f.size < 6 || !LIBC.containsMatchIn(f[5].trim()) || f[2].toLongOrNull(16) != 0L) return@mapNotNull null
        val start = f[0].substringBefore('-').toULongOrNull(16)?.toLong() ?: return@mapNotNull null
        Library(f[5].trim(), start)
    }.firstOrNull()

    /**
     * [readFile] returns the whole libc file; [readMemory] returns bytes of this process's
     * memory, or null when the address cannot be read.
     */
    public fun evaluate(
        maps: String?,
        readFile: (String) -> ByteArray?,
        readMemory: (address: Long, length: Int) -> ByteArray?,
    ): ProbeResult {
        if (maps == null) return ProbeResult.Unavailable("could not read /proc/self/maps")
        val lib = findLibc(maps) ?: return ProbeResult.Unavailable("libc not found in /proc/self/maps")
        val file = readFile(lib.path) ?: return ProbeResult.Unavailable("could not read ${lib.path}")
        val elf = Elf.parse(file) ?: return ProbeResult.Unavailable("could not parse ${lib.path}")
        // The mapping at file offset 0 is the segment loaded from offset 0.
        val first = elf.loads.firstOrNull { it.offset == 0L }
            ?: return ProbeResult.Unavailable("unexpected segment layout in ${lib.path}")

        var compared = 0
        val signals = mutableListOf<Signal>()
        for (name in FUNCTIONS) {
            val sym = elf.functions[name] ?: continue
            val vaddr = sym.value and 1L.inv() // bit 0 marks Thumb code on 32-bit ARM
            val length = if (sym.size in 1 until PROLOGUE) sym.size.toInt() else PROLOGUE
            val disk = elf.bytesAt(vaddr, length) ?: continue
            val memory = readMemory(lib.base + vaddr - first.vaddr, length) ?: continue
            compared++
            if (!disk.contentEquals(memory)) {
                signals += Signal.of(SignalId.INLINE_HOOK, "$name: ${hex(memory)} (file ${hex(disk)})")
            }
        }
        if (compared == 0) return ProbeResult.Unavailable("no libc function could be compared")
        return ProbeResult.Completed(signals)
    }

    private fun hex(b: ByteArray): String = b.take(8).joinToString(" ") { "%02x".format(it) }

    private val WHITESPACE = Regex("\\s+")
}
