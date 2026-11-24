package io.github.brennocm.iris.core

/** Result of checking whether a path exists. */
public enum class PathState {
    PRESENT,
    ABSENT,
    UNKNOWN,
    ;

    public companion object {
        // Linux errno values; identical on every Android ABI.
        private const val ENOENT = 2
        private const val EACCES = 13
        private const val ENOTDIR = 20

        /**
         * Classifies the result of `faccessat(path, F_OK)` (0 or a negated errno).
         *
         * SELinux answers EACCES for a file the app may not look at, such as `su` labelled
         * `su_exec` on emulator and userdebug images. EACCES alone is ambiguous: an unsearchable
         * directory gives the same answer whether or not the file exists. [control] checks a name
         * that cannot exist in the same directory; if that answers ENOENT the directory was
         * searched, so the EACCES came from the file itself and the file is there.
         */
        public fun fromAccess(result: Int, control: () -> Int): PathState = when (result) {
            0 -> PRESENT
            -ENOENT, -ENOTDIR -> ABSENT
            -EACCES -> if (control() == -ENOENT) PRESENT else UNKNOWN
            else -> UNKNOWN
        }
    }
}

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
