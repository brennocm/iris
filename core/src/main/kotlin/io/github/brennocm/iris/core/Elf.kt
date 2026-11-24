package io.github.brennocm.iris.core

/**
 * The few parts of a little-endian ELF shared object the inline hook check needs: loadable
 * segments and the dynamic symbol table. Every read is bounds-checked; [parse] returns null for
 * anything it does not understand instead of throwing.
 */
internal class Elf private constructor(
    private val b: ByteArray,
    private val is64: Boolean,
    val loads: List<Segment>,
    val functions: Map<String, Symbol>,
) {
    data class Segment(val offset: Long, val vaddr: Long, val fileSize: Long)

    data class Symbol(val value: Long, val size: Long)

    /** File offset of virtual address [vaddr], or null when no loaded segment holds it. */
    fun fileOffset(vaddr: Long): Long? =
        loads.firstOrNull { vaddr >= it.vaddr && vaddr < it.vaddr + it.fileSize }?.let { vaddr - it.vaddr + it.offset }

    /** [length] bytes of the file at the offset of [vaddr], or null when out of range. */
    fun bytesAt(vaddr: Long, length: Int): ByteArray? {
        val off = fileOffset(vaddr) ?: return null
        if (off < 0 || off + length > b.size) return null
        return b.copyOfRange(off.toInt(), off.toInt() + length)
    }

    companion object {
        private const val PT_LOAD = 1
        private const val SHT_DYNSYM = 11
        private const val STT_FUNC = 2

        fun parse(b: ByteArray): Elf? = try {
            parseOrThrow(b)
        } catch (_: IndexOutOfBoundsException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }

        private fun parseOrThrow(b: ByteArray): Elf? {
            if (b.size < 52 || b[0] != 0x7f.toByte() || b[1] != 'E'.code.toByte() || b[2] != 'L'.code.toByte() ||
                b[3] != 'F'.code.toByte()
            ) {
                return null
            }
            val is64 = when (b[4].toInt()) {
                1 -> false
                2 -> true
                else -> return null
            }
            if (b[5].toInt() != 1) return null // little endian only; every Android ABI is
            val r = Reader(b)
            val phoff = if (is64) r.u64(0x20) else r.u32(0x1C)
            val shoff = if (is64) r.u64(0x28) else r.u32(0x20)
            val phentsize = r.u16(if (is64) 0x36 else 0x2A)
            val phnum = r.u16(if (is64) 0x38 else 0x2C)
            val shentsize = r.u16(if (is64) 0x3A else 0x2E)
            val shnum = r.u16(if (is64) 0x3C else 0x30)

            val loads = (0 until phnum).mapNotNull { i ->
                val p = phoff + i.toLong() * phentsize
                if (r.u32(p) != PT_LOAD.toLong()) return@mapNotNull null
                if (is64) {
                    Segment(offset = r.u64(p + 8), vaddr = r.u64(p + 16), fileSize = r.u64(p + 32))
                } else {
                    Segment(offset = r.u32(p + 4), vaddr = r.u32(p + 8), fileSize = r.u32(p + 16))
                }
            }

            data class Section(val type: Long, val offset: Long, val size: Long, val link: Long, val entsize: Long)
            val sections = (0 until shnum).map { i ->
                val s = shoff + i.toLong() * shentsize
                if (is64) {
                    Section(r.u32(s + 4), r.u64(s + 24), r.u64(s + 32), r.u32(s + 40), r.u64(s + 56))
                } else {
                    Section(r.u32(s + 4), r.u32(s + 16), r.u32(s + 20), r.u32(s + 24), r.u32(s + 36))
                }
            }
            val dynsym = sections.firstOrNull { it.type == SHT_DYNSYM.toLong() } ?: return null
            val strtab = sections.getOrNull(dynsym.link.toInt()) ?: return null
            val entsize = if (dynsym.entsize > 0) {
                dynsym.entsize
            } else if (is64) {
                24L
            } else {
                16L
            }

            val functions = linkedMapOf<String, Symbol>()
            for (i in 0 until (dynsym.size / entsize)) {
                val e = dynsym.offset + i * entsize
                val name: Long
                val info: Int
                val shndx: Int
                val value: Long
                val size: Long
                if (is64) {
                    name = r.u32(e)
                    info = r.u8(e + 4)
                    shndx = r.u16(e + 6)
                    value = r.u64(e + 8)
                    size = r.u64(e + 16)
                } else {
                    name = r.u32(e)
                    value = r.u32(e + 4)
                    size = r.u32(e + 8)
                    info = r.u8(e + 12)
                    shndx = r.u16(e + 14)
                }
                if (info and 0xf != STT_FUNC || shndx == 0 || value == 0L) continue
                functions.putIfAbsent(r.cString(strtab.offset + name), Symbol(value, size))
            }
            return Elf(b, is64, loads, functions)
        }
    }

    private class Reader(private val b: ByteArray) {
        private fun at(o: Long): Int {
            require(o >= 0 && o < b.size) { "offset $o out of range" }
            return o.toInt()
        }

        fun u8(o: Long): Int = b[at(o)].toInt() and 0xff

        fun u16(o: Long): Int = u8(o) or (u8(o + 1) shl 8)

        fun u32(o: Long): Long = (u16(o).toLong() or (u16(o + 2).toLong() shl 16))

        fun u64(o: Long): Long = u32(o) or (u32(o + 4) shl 32)

        fun cString(o: Long): String {
            val start = at(o)
            var end = start
            while (end < b.size && b[end] != 0.toByte() && end - start < 256) end++
            return String(b, start, end - start, Charsets.US_ASCII)
        }
    }
}
