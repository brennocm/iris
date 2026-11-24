package io.github.brennocm.iris.core

/**
 * Looks for Java methods replaced at runtime by Frida or an Xposed-style framework.
 *
 * Frida's Java bridge replaces a method by turning its ArtMethod into a native one: the
 * access flags gain ACC_NATIVE, which `Method.getModifiers()` then reports for a method that
 * was compiled from Java. [nativeJavaMethods] are such methods, found by the caller among
 * classes known to have no native methods (this SDK's own probes and framework methods that
 * anti-detection scripts hook).
 *
 * Xposed, LSPosed and their forks leave class names in stack traces (hooked calls go through a
 * generated hooker class, and classic Xposed wraps zygote's entry point). [stackClasses] are the
 * classes on the caller's and the main thread's stacks; [loadableClasses] are framework classes
 * that the app's class loader could load.
 */
public object ArtHooks {
    /** Lowercase prefixes or substrings of class names that belong to hooking frameworks. */
    public val FRAMEWORK_MARKERS: List<String> = listOf(
        "de.robv.android.xposed",
        "lsphooker",
        "edhooker",
        "org.lsposed",
        "com.elderdrivers.riru",
        "me.weishu.epic",
        "top.canyie.pine",
        "com.saurik.substrate",
    )

    public fun evaluate(
        nativeJavaMethods: List<String>?,
        stackClasses: List<String>,
        loadableClasses: List<String>,
    ): ProbeResult {
        if (nativeJavaMethods == null) return ProbeResult.Unavailable("reflection unavailable")
        val framework = (stackClasses.map { "stack: $it" } + loadableClasses.map { "class: $it" })
            .filter { entry -> FRAMEWORK_MARKERS.any { entry.lowercase().contains(it) } }
            .distinct()
        return ProbeResult.Completed(
            nativeJavaMethods.distinct().map { Signal.of(SignalId.ART_METHOD_HOOK, it) } +
                framework.map { Signal.of(SignalId.XPOSED_FRAMEWORK, it) },
        )
    }
}
