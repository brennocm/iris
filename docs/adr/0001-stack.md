# 0001. Stack: Kotlin core on the JVM, Android library, C for native probes

## Status
Accepted, 2026-11-24.

## Decision
- Detection rules and the report format live in `core`, a pure Kotlin/JVM module with no
  Android dependency, so they are unit-tested on any machine in seconds.
- The Android library (`iris`, minSdk 24, compileSdk 35) only gathers raw inputs.
- Native code is C (not C++), built with CMake and NDK 27.0.12077973, with `-Werror`, stack
  protector, full RELRO and 16 KB page alignment (required for Android 15+ devices with
  16 KB pages; NDK r27 does not apply it by default).
- Gradle 8.11.1 (wrapper with checksum), AGP 8.7.3, Kotlin 2.1.0, JDK 17 pinned through mise.
- `explicitApi()` and warnings-as-errors in both modules.
- License: Apache-2.0, so commercial apps can embed the SDK (GPL would rule them out).

## Alternatives rejected
- Kotlin Multiplatform with an iOS target: no iOS work planned yet; it adds build complexity
  now for no user.
- Rust for the native part: safer, but the native surface is ~200 lines of syscalls and string
  copying, and C keeps the NDK toolchain the only native dependency.
