package io.github.brennocm.iris.core

/** Reads `TracerPid` from `/proc/self/status`: non-zero means a process is ptrace-attached. */
public object ProcStatus {
    public fun tracerPid(status: String): Int? = status.lineSequence()
        .firstOrNull { it.startsWith("TracerPid:") }
        ?.substringAfter(':')?.trim()?.toIntOrNull()

    public fun evaluate(status: String?): ProbeResult {
        if (status == null) return ProbeResult.Unavailable("could not read /proc/self/status")
        val pid = tracerPid(status) ?: return ProbeResult.Unavailable("no TracerPid line")
        return ProbeResult.Completed(
            if (pid == 0) emptyList() else listOf(Signal.of(SignalId.TRACER_ATTACHED, "TracerPid=$pid")),
        )
    }
}
