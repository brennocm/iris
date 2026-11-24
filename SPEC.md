# palisade: specification

## Problem

Mobile apps that move money or hold personal data want to know when they run on a rooted
device, under Frida or Xposed, under a debugger, or after being repackaged. Client-side checks
alone are easy to bypass: each one ends in a boolean that whoever controls the device can flip.

## What palisade is

An Android library that collects evidence (signals) about the runtime environment and returns
a report for the app's backend, which combines it with a Play Integrity verdict and decides.
The SDK raises the cost of tampering and feeds server-side decisions; it does not try to be
unbreakable.

## Users

Android developers and the security team behind them. The report is designed to be logged,
correlated and acted on by a backend.

## Scope of v0.1

| Probe | Signal | How |
| --- | --- | --- |
| su paths | ROOT-001 | `faccessat` by direct syscall on known su/Magisk paths |
| Build tags | ROOT-002 | `Build.TAGS` contains `test-keys` |
| Mounts | ROOT-003 | Magisk entries in `/proc/self/mounts` |
| Maps | HOOK-001 | Frida/Xposed/LSPosed/Substrate libraries in `/proc/self/maps` |
| Threads | HOOK-002 | Frida thread names in `/proc/self/task/*/comm` |
| Tracer | DEBUG-001 | `TracerPid` in `/proc/self/status` |
| Debuggable | DEBUG-002 | `FLAG_DEBUGGABLE` |
| Java debugger | DEBUG-003 | `Debug.isDebuggerConnected()` |
| Signing cert | TAMPER-001 | APK signer SHA-256 against developer pins |

## Non-goals

- Deciding, blocking or killing the app on the client.
- Obfuscation, packing or anti-disassembly of the SDK itself.
- Stopping an attacker with root and full instrumentation. Nothing on the device can.
- Collecting device identifiers or personal data.

## Roadmap

1. Sample app and instrumented tests on an emulator (clean, rooted, Frida attached).
2. Server-side reference verifier (Go): checks the Play Integrity token, binds it to the
   report through the request hash, and returns a decision.
3. Report binding: sign the report with a hardware-backed Android Keystore key, using key
   attestation, so a hooked SDK cannot forge a clean report without the backend noticing.
4. More signals: emulator traits, Frida ports, inline-hook checks on libc prologues, ART method
   hook detection.
5. Formatter/linter (ktlint) in `mise run check`; Maven Central publishing.
