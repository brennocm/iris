package io.github.brennocm.iris.core

/** What a signal is evidence of. */
public enum class Category { ROOT, HOOK, DEBUG, TAMPER }

/**
 * Stable identifiers. The code is part of the report format: a backend matches on it,
 * so a code is never reused for a different meaning.
 */
public enum class SignalId(public val code: String, public val category: Category) {
    SU_BINARY("ROOT-001", Category.ROOT),
    TEST_KEYS("ROOT-002", Category.ROOT),
    MAGISK_MOUNT("ROOT-003", Category.ROOT),
    INSTRUMENTATION_LIBRARY("HOOK-001", Category.HOOK),
    INSTRUMENTATION_THREAD("HOOK-002", Category.HOOK),
    TRACER_ATTACHED("DEBUG-001", Category.DEBUG),
    DEBUGGABLE_BUILD("DEBUG-002", Category.DEBUG),
    JAVA_DEBUGGER("DEBUG-003", Category.DEBUG),
    SIGNING_CERT_MISMATCH("TAMPER-001", Category.TAMPER),
}

/** One observation. [evidence] is what was seen (a path, a thread name), capped in length. */
public data class Signal(val id: SignalId, val evidence: String) {
    init {
        require(evidence.length <= MAX_EVIDENCE) { "evidence longer than $MAX_EVIDENCE chars" }
    }

    public companion object {
        public const val MAX_EVIDENCE: Int = 256

        /** Builds a signal, truncating evidence that would exceed [MAX_EVIDENCE]. */
        public fun of(id: SignalId, evidence: String): Signal =
            Signal(id, if (evidence.length <= MAX_EVIDENCE) evidence else evidence.take(MAX_EVIDENCE - 1) + "…")
    }
}
