package io.github.brennocm.iris.core

/**
 * Looks for frida-server listening on its default port.
 *
 * frida-server runs as root and listens on 27042 until told otherwise. A renamed or moved
 * server does not match; like the name checks, this catches default setups cheaply.
 *
 * The listening sockets are read from `/proc/net/tcp` and `tcp6`. Android 10 and later deny
 * apps those files, so the fallback is a TCP connect to the loopback port.
 */
public object FridaPorts {
    public val PORTS: List<Int> = listOf(27042)

    private const val LISTEN = "0A"
    private const val ECONNREFUSED = 111

    /**
     * [tables] are the texts of `/proc/net/tcp` and `/proc/net/tcp6` (null when unreadable).
     * [connect] returns 0 when a loopback connection to the port succeeds, or a negated errno;
     * it is only called when no table could be read.
     */
    public fun evaluate(tables: Map<String, String?>, connect: (Int) -> Int): ProbeResult {
        val readable = tables.filterValues { it != null }
        if (readable.isNotEmpty()) {
            val hits = readable.flatMap { (name, text) ->
                listening(text!!).filter { it in PORTS }.map { "$name port $it in LISTEN" }
            }.distinct()
            return ProbeResult.Completed(hits.map { Signal.of(SignalId.FRIDA_SERVER_PORT, it) })
        }
        val signals = mutableListOf<Signal>()
        for (port in PORTS) {
            when (val r = connect(port)) {
                0 -> signals += Signal.of(SignalId.FRIDA_SERVER_PORT, "127.0.0.1:$port accepts connections")

                -ECONNREFUSED -> Unit

                // EACCES without the INTERNET permission, or a sandbox without loopback.
                else -> return ProbeResult.Unavailable("/proc/net/tcp unreadable and connect failed (errno ${-r})")
            }
        }
        return ProbeResult.Completed(signals)
    }

    /** Local ports of the sockets in LISTEN state in one `/proc/net/tcp*` table. */
    public fun listening(table: String): List<Int> = table.lineSequence().drop(1).mapNotNull { line ->
        // sl local_address rem_address st ...; local_address is HEXIP:HEXPORT
        val f = line.trim().split(WHITESPACE)
        if (f.size < 4 || f[3] != LISTEN) return@mapNotNull null
        f[1].substringAfterLast(':', "").toIntOrNull(16)
    }.toList()

    private val WHITESPACE = Regex("\\s+")
}
