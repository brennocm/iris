package io.github.brennocm.iris.core

/** Each independent check the SDK runs. */
public enum class Probe(public val key: String) {
    SU_PATHS("su_paths"),
    BUILD_TAGS("build_tags"),
    MOUNTS("mounts"),
    MAPS("maps"),
    THREADS("threads"),
    TRACER("tracer"),
    DEBUGGABLE("debuggable"),
    JAVA_DEBUGGER("java_debugger"),
    SIGNING_CERT("signing_cert"),
}

/**
 * The outcome of one probe. A probe that could not run is [Unavailable], never an empty
 * [Completed]: "I could not look" and "I looked and saw nothing" must stay distinguishable.
 */
public sealed interface ProbeResult {
    public data class Completed(val signals: List<Signal>) : ProbeResult
    public data class Unavailable(val reason: String) : ProbeResult
}

/**
 * Everything one inspection observed. The report carries signals, not a verdict: the app's
 * backend decides what to do with them (see docs/adr/0002-signals-not-verdicts.md).
 */
public class Report(results: Map<Probe, ProbeResult>) {
    public val results: Map<Probe, ProbeResult> = results.toSortedMap()

    public val signals: List<Signal>
        get() = results.values.filterIsInstance<ProbeResult.Completed>().flatMap { it.signals }

    public val unavailable: Map<Probe, String>
        get() = results.mapNotNull { (p, r) -> (r as? ProbeResult.Unavailable)?.let { p to it.reason } }.toMap()

    /** Deterministic JSON, meant to be sent to the backend alongside a Play Integrity token. */
    public fun toJson(): String = buildString {
        append("{\"schema\":").append(SCHEMA_VERSION)
        append(",\"signals\":[")
        results.entries.flatMap { (probe, r) ->
            (r as? ProbeResult.Completed)?.signals.orEmpty().map { probe to it }
        }.forEachIndexed { i, (probe, s) ->
            if (i > 0) append(',')
            append("{\"id\":").appendJson(s.id.code)
            append(",\"probe\":").appendJson(probe.key)
            append(",\"evidence\":").appendJson(s.evidence).append('}')
        }
        append("],\"unavailable\":[")
        unavailable.entries.forEachIndexed { i, (probe, reason) ->
            if (i > 0) append(',')
            append("{\"probe\":").appendJson(probe.key)
            append(",\"reason\":").appendJson(reason).append('}')
        }
        append("]}")
    }

    public companion object {
        public const val SCHEMA_VERSION: Int = 1
    }
}

private fun StringBuilder.appendJson(s: String): StringBuilder {
    append('"')
    for (c in s) {
        when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c == '\n' -> append("\\n")
            c == '\r' -> append("\\r")
            c == '\t' -> append("\\t")
            c < ' ' -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
    }
    return append('"')
}
