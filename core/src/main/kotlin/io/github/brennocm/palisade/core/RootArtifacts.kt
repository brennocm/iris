package io.github.brennocm.palisade.core

/** Result of checking whether a path exists. */
public enum class PathState { PRESENT, ABSENT, UNKNOWN }

/** File-system and build-property traces of root. */
public object RootArtifacts {
    public val SU_PATHS: List<String> = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
        "/data/local/bin/su", "/data/local/xbin/su", "/system/app/Superuser.apk",
        "/system/xbin/daemonsu", "/system/bin/magisk", "/sbin/magisk",
    )

    /**
     * [stat] reports whether a path exists. When every path comes back [PathState.UNKNOWN]
     * (for example, all denied by SELinux), the probe is unavailable rather than clean.
     */
    public fun evaluateSuPaths(stat: (String) -> PathState): ProbeResult {
        val states = SU_PATHS.associateWith(stat)
        if (states.values.all { it == PathState.UNKNOWN }) {
            return ProbeResult.Unavailable("no su path could be checked")
        }
        return ProbeResult.Completed(
            states.filterValues { it == PathState.PRESENT }.keys.map { Signal.of(SignalId.SU_BINARY, it) },
        )
    }

    /** `Build.TAGS` containing `test-keys` means the system image was signed with test keys. */
    public fun evaluateBuildTags(tags: String?): ProbeResult = ProbeResult.Completed(
        if (tags?.contains("test-keys") == true) listOf(Signal.of(SignalId.TEST_KEYS, tags)) else emptyList(),
    )
}
