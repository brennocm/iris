# 0004. Bind JNI functions by exported name

## Status
Accepted, 2026-11-24.

## Decision
Native methods use the standard `Java_<package>_<class>_<method>` exports instead of
`RegisterNatives` with hidden names. Hiding names is obfuscation (a non-goal) and only costs
an analyst minutes; standard binding keeps the code simple to review. The consumer ProGuard
rule keeps `NativeProbes` and its native methods from being renamed.
