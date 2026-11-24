# 0003. Read /proc with direct syscalls

## Status
Accepted, 2026-11-24.

## Context
The cheapest bypass of file-based detection is hooking libc: make `open` fail for
`/proc/self/maps`, or make `strstr` never find "frida". UnCrackable Level 3 falls exactly
this way.

## Decision
`iris.c` issues `openat`, `read`, `close`, `faccessat` and `getdents64` with an inline
`svc #0` (arm64) or `syscall` (x86_64) instruction. String matching happens in Kotlin, not in
libc. On 32-bit ABIs (armeabi-v7a, x86) it falls back to libc's `syscall()` wrapper, which is
hookable; those ABIs are a small and shrinking share of devices.

Verified on the release AAR: the 64-bit libraries import no libc file functions.

## Consequences
- Hooking libc no longer changes what the probes read. Hooking `NativeProbes` in ART, or
  patching the library, still does (see the threat model).
- Adding a new native file access means adding a raw syscall wrapper, not calling libc.
