package io.github.brennocm.iris.core

/**
 * Looks for Magisk in `/proc/self/mounts`. Magisk's DenyList unmounts its files for apps on
 * the list, so an empty result does not mean the device is not rooted.
 */
public object Mounts {
    private val TARGET_PREFIXES = listOf("/sbin/.magisk", "/debug_ramdisk", "/data/adb")

    public fun evaluate(mounts: String?): ProbeResult {
        if (mounts == null) return ProbeResult.Unavailable("could not read /proc/self/mounts")
        val hits = mounts.lineSequence().mapNotNull { line ->
            val parts = line.trim().split(' ')
            if (parts.size < 3) return@mapNotNull null
            val (source, target) = parts
            val magisk = source.contains("magisk", ignoreCase = true) ||
                target.contains("magisk", ignoreCase = true) ||
                TARGET_PREFIXES.any { target.startsWith(it) }
            if (magisk) "$source on $target" else null
        }.distinct().toList()
        return ProbeResult.Completed(hits.map { Signal.of(SignalId.MAGISK_MOUNT, it) })
    }
}
