package io.github.brennocm.iris

/**
 * Reads that must not go through libc, so that hooking `open`, `read` or `strstr` in libc
 * does not blind them. Implemented in src/main/cpp/iris.c.
 */
internal object NativeProbes {
    private val loaded: Boolean by lazy {
        try {
            System.loadLibrary("iris")
            true
        } catch (_: UnsatisfiedLinkError) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    /** Loads libiris.so once. False when it is missing or cannot be loaded on this device. */
    fun load(): Boolean = loaded

    /** Contents of [path], at most [maxBytes] bytes, or null if it could not be opened. */
    @JvmStatic
    external fun readFile(path: String, maxBytes: Int): ByteArray?

    /** 0 when [path] exists, otherwise the negated errno from `faccessat(F_OK)`. */
    @JvmStatic
    external fun access(path: String): Int

    /** The `comm` name of every thread in this process, or null if the task list is unreadable. */
    @JvmStatic
    external fun threadNames(): Array<String>?

    /** 0 when a TCP connect to 127.0.0.1:[port] succeeds, otherwise the negated errno. */
    @JvmStatic
    external fun connectLoopback(port: Int): Int

    /** [length] bytes of this process's memory at [address], or null if it cannot be read. */
    @JvmStatic
    external fun readMemory(address: Long, length: Int): ByteArray?
}
