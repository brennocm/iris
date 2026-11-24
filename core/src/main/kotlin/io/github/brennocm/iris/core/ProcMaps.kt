package io.github.brennocm.iris.core

/**
 * Looks for instrumentation frameworks loaded into the process, from the text of
 * `/proc/self/maps`.
 *
 * Name matching is the weakest form of this check: a renamed Frida gadget or agent does not
 * match. It is still worth running because default setups use these names, and because
 * reading the maps through direct syscalls (see the native layer) defeats the cheap bypass of
 * hooking libc's string functions.
 */
public object ProcMaps {
    /** Lowercase substrings of mapped file paths that indicate an instrumentation framework. */
    public val MARKERS: List<String> = listOf(
        "frida-agent", "frida-gadget", "libgadget", "frida-helper",
        "libxposed", "xposedbridge", "liblspd", "lspatch",
        "libsubstrate", "libriru",
    )

    /** One parsed line of `/proc/<pid>/maps`. [path] is empty for anonymous mappings. */
    public data class Mapping(val perms: String, val path: String)

    public fun parse(text: String): List<Mapping> = text.lineSequence().mapNotNull { line ->
        // address perms offset dev inode [path]; the path itself may contain spaces
        val parts = line.trim().split(WHITESPACE, limit = 6)
        if (parts.size < 5) null else Mapping(parts[1], parts.getOrElse(5) { "" }.trim())
    }.toList()

    public fun evaluate(maps: String?): ProbeResult {
        if (maps == null) return ProbeResult.Unavailable("could not read /proc/self/maps")
        val hits = parse(maps).map { it.path }
            .filter { path -> MARKERS.any { path.lowercase().contains(it) } }
            .distinct()
        return ProbeResult.Completed(hits.map { Signal.of(SignalId.INSTRUMENTATION_LIBRARY, it) })
    }

    private val WHITESPACE = Regex("\\s+")
}
