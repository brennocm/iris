package io.github.brennocm.iris.core

/** Looks for thread names that Frida's agent creates inside the instrumented process. */
public object Threads {
    /** Exact thread names (`/proc/self/task/<tid>/comm`, at most 15 characters). */
    public val MARKERS: Set<String> = setOf("gum-js-loop", "gmain", "gdbus", "pool-frida", "frida-main")

    public fun evaluate(names: List<String>?): ProbeResult {
        if (names == null) return ProbeResult.Unavailable("could not list /proc/self/task")
        val hits = names.map { it.trim() }.filter { it in MARKERS }.distinct()
        return ProbeResult.Completed(hits.map { Signal.of(SignalId.INSTRUMENTATION_THREAD, it) })
    }
}
