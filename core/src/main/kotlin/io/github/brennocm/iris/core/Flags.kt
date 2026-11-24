package io.github.brennocm.iris.core

/** Probes that reduce to a boolean the platform reports directly. */
public object Flags {
    public fun debuggable(flag: Boolean): ProbeResult = ProbeResult.Completed(
        if (flag) listOf(Signal.of(SignalId.DEBUGGABLE_BUILD, "FLAG_DEBUGGABLE")) else emptyList(),
    )

    public fun javaDebugger(connected: Boolean): ProbeResult = ProbeResult.Completed(
        if (connected) listOf(Signal.of(SignalId.JAVA_DEBUGGER, "Debug.isDebuggerConnected")) else emptyList(),
    )
}
